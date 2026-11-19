#include "sinkhole/log_buffer.hpp"

#include <algorithm>
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

struct Ring {
    char* buf = nullptr;
    size_t cap = 0;
    bool psram = false;
    uint32_t total = 0;  // bytes ever written; the newest is at (total - 1) % cap
    portMUX_TYPE lock = portMUX_INITIALIZER_UNLOCKED;
    vprintf_like_t serial = nullptr;
    // One static line instead of the caller's stack: ESP_LOGx runs on every
    // task, some with little stack to spare (Wi-Fi start-up on the main task).
    // If two tasks log at the same instant, the second line still goes to the
    // serial port but is skipped here.
    std::array<char, kLineMax> line{};
    std::atomic_flag lineBusy = ATOMIC_FLAG_INIT;
};

Ring& ring()
{
    static Ring r;
    return r;
}

void append(Ring& r, const char* s, size_t n)
{
    taskENTER_CRITICAL(&r.lock);
    for (size_t i = 0; i < n; i++) {
        r.buf[r.total % r.cap] = s[i];
        r.total++;
    }
    taskEXIT_CRITICAL(&r.lock);
}

int hook(const char* fmt, va_list args)
{
    Ring& r = ring();
    if (!r.lineBusy.test_and_set()) {
        va_list copy;
        va_copy(copy, args);
        const int n = vsnprintf(r.line.data(), r.line.size(), fmt, copy);  // NOSONAR vprintf hook: esp_log passes the format
        va_end(copy);
        if (n > 0) {
            const auto full = static_cast<size_t>(n);
            const size_t len = full < r.line.size() ? full : r.line.size() - 1;
            if (full >= r.line.size()) r.line[len - 1] = '\n';  // cut: keep lines whole
            append(r, r.line.data(), len);
        }
        r.lineBusy.clear();
    }
    return r.serial ? r.serial(fmt, args) : 0;
}
}  // namespace

void LogBuffer::begin()
{
    Ring& r = ring();
    if (r.buf) return;
    const Region mem = allocTable(1, kPsramBytes, kInternalBytes);
    if (!mem.ptr) return;
    r.buf = static_cast<char*>(mem.ptr);
    r.cap = mem.count;
    r.psram = mem.psram;
    r.serial = esp_log_set_vprintf(&hook);
}

LogBuffer::Chunk LogBuffer::read(uint32_t from, char* out, size_t cap)
{
    // Copied in short slices: a critical section turns interrupts off on this
    // core, and a 2 KB copy (from PSRAM on Pro) is too long for that.
    constexpr size_t kSlice = 256;
    Ring& r = ring();
    Chunk c{from, from, 0};
    if (!r.buf || !cap) return c;
    uint32_t pos = from;
    for (bool first = true; c.len < cap; first = false) {
        taskENTER_CRITICAL(&r.lock);
        const uint32_t oldest = r.total > r.cap ? r.total - static_cast<uint32_t>(r.cap) : 0;
        if (pos < oldest || pos > r.total) {
            if (!first) {  // the writer lapped this read: stop here, the next one resyncs
                taskEXIT_CRITICAL(&r.lock);
                break;
            }
            pos = oldest;  // overwritten (or a position from before a restart)
            if (oldest > 0) {  // start at the next whole line
                const uint32_t stop = r.total - pos > kSlice ? pos + kSlice : r.total;
                while (pos < stop && r.buf[pos % r.cap] != '\n') pos++;
                if (pos < r.total) pos++;
            }
            c.start = pos;
        }
        const size_t before = c.len;
        const size_t limit = std::min(cap, c.len + kSlice);
        while (pos < r.total && c.len < limit) out[c.len++] = r.buf[pos++ % r.cap];
        taskEXIT_CRITICAL(&r.lock);
        if (c.len == before) break;  // caught up
    }
    c.next = pos;
    return c;
}

uint32_t LogBuffer::end()
{
    Ring& r = ring();
    taskENTER_CRITICAL(&r.lock);
    const uint32_t t = r.total;
    taskEXIT_CRITICAL(&r.lock);
    return t;
}

size_t LogBuffer::capacity()
{
    return ring().cap;
}

bool LogBuffer::inPsram()
{
    return ring().psram;
}

}  // namespace sinkhole
