#include "sinkhole/log_buffer.hpp"

#include <array>
#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstring>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "sinkhole/memory.hpp"

namespace sinkhole {

namespace {
constexpr size_t kPsramBytes = 64 * 1024;
constexpr size_t kInternalBytes = 4 * 1024;
constexpr size_t kLineMax = 192;  // longer log lines are cut in the buffer (not on serial)

char* sBuf = nullptr;
size_t sCap = 0;
bool sPsram = false;
uint32_t sTotal = 0;  // bytes ever written; the newest is at (sTotal - 1) % sCap
portMUX_TYPE sLock = portMUX_INITIALIZER_UNLOCKED;
vprintf_like_t sSerial = nullptr;

void append(const char* s, size_t n)
{
    taskENTER_CRITICAL(&sLock);
    for (size_t i = 0; i < n; i++) {
        sBuf[sTotal % sCap] = s[i];
        sTotal++;
    }
    taskEXIT_CRITICAL(&sLock);
}

// Formats into one static line instead of the caller's stack: ESP_LOGx runs on
// every task, some with little stack to spare (Wi-Fi start-up on the main task).
// If two tasks log at the same instant, the second line still goes to the
// serial port but is skipped here.
std::array<char, kLineMax> sLine;
std::atomic_flag sLineBusy = ATOMIC_FLAG_INIT;

int hook(const char* fmt, va_list args)
{
    if (!sLineBusy.test_and_set(std::memory_order_acquire)) {
        va_list copy;
        va_copy(copy, args);
        const int n = vsnprintf(sLine.data(), sLine.size(), fmt, copy);
        va_end(copy);
        if (n > 0) {
            const size_t len = static_cast<size_t>(n) < sLine.size() ? static_cast<size_t>(n) : sLine.size() - 1;
            if (static_cast<size_t>(n) >= sLine.size()) sLine[len - 1] = '\n';  // cut: keep lines whole
            append(sLine.data(), len);
        }
        sLineBusy.clear(std::memory_order_release);
    }
    return sSerial ? sSerial(fmt, args) : 0;
}
}  // namespace

void LogBuffer::begin()
{
    if (sBuf) return;
    const Region r = allocTable(1, kPsramBytes, kInternalBytes);
    if (!r.ptr) return;
    sBuf = static_cast<char*>(r.ptr);
    sCap = r.count;
    sPsram = r.psram;
    sSerial = esp_log_set_vprintf(&hook);
}

LogBuffer::Chunk LogBuffer::read(uint32_t from, char* out, size_t cap)
{
    Chunk c{from, from, 0};
    if (!sBuf || !cap) return c;
    taskENTER_CRITICAL(&sLock);
    const uint32_t oldest = sTotal > sCap ? sTotal - static_cast<uint32_t>(sCap) : 0;
    uint32_t pos = from;
    bool resync = false;
    if (pos < oldest || pos > sTotal) {  // overwritten (or a position from before a restart)
        pos = oldest;
        resync = oldest > 0;
    }
    if (resync) {  // start at the next whole line
        while (pos < sTotal && sBuf[pos % sCap] != '\n') pos++;
        if (pos < sTotal) pos++;
    }
    c.start = pos;
    while (pos < sTotal && c.len < cap) out[c.len++] = sBuf[pos++ % sCap];
    c.next = pos;
    taskEXIT_CRITICAL(&sLock);
    return c;
}

uint32_t LogBuffer::end()
{
    taskENTER_CRITICAL(&sLock);
    const uint32_t t = sTotal;
    taskEXIT_CRITICAL(&sLock);
    return t;
}

size_t LogBuffer::capacity()
{
    return sCap;
}

bool LogBuffer::inPsram()
{
    return sPsram;
}

}  // namespace sinkhole
