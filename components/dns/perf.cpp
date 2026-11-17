#include "sinkhole/perf.hpp"

#if CONFIG_SINKHOLE_PERF

#include <cstring>

#include "esp_cpu.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

namespace sinkhole::perf {

namespace {
constexpr const char* kNames[kStages] = {"recv",      "parse",   "client",     "rules",  "filter",
                                         "log",       "cache",   "cname",      "forward", "send",
                                         "qBlocked",  "qCached", "qForwarded", "qOther", "uRecv",
                                         "uMatch",    "uCname",  "uSend",      "uStore", "uTotal"};
constexpr uint32_t kMhz = CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ;

int bucketOf(uint32_t c)
{
    if (c < 4) return static_cast<int>(c);
    const int msb = 31 - __builtin_clz(c);
    const int idx = 4 * msb + static_cast<int>((c >> (msb - 2)) & 3);
    return idx < kBuckets ? idx : kBuckets - 1;
}

uint32_t bucketTop(int idx)  // upper bound of a bucket, in cycles
{
    if (idx < 4) return static_cast<uint32_t>(idx);
    const int msb = idx / 4, q = idx % 4;
    return (1u << msb) + ((q + 1u) << (msb - 2)) - 1;
}
}  // namespace

Recorder& Recorder::instance()
{
    static Recorder r;
    return r;
}

void Recorder::add(Stage s, uint32_t cycles)
{
    StageStats& st = s_[s];
    if (!st.n || cycles < st.min) st.min = cycles;
    if (cycles > st.max) st.max = cycles;
    st.n++;
    st.sum += cycles;
    st.hist[bucketOf(cycles)]++;
}

void Recorder::applyReset()
{
    if (!reset_.exchange(false)) return;
    memset(s_, 0, sizeof(s_));
    since_ = esp_timer_get_time();
}

void Recorder::snapshot(StageStats out[kStages], int64_t& windowUs) const
{
    memcpy(out, s_, sizeof(s_));
    windowUs = esp_timer_get_time() - since_;
}

Lap::Lap() : core_(xPortGetCoreID()), total_(QOther)
{
    Recorder::instance().applyReset();
    t0_ = last_ = esp_cpu_get_cycle_count();
}

void Lap::mark(Stage s)
{
    const uint32_t now = esp_cpu_get_cycle_count();
    acc_[s] += now - last_;
    last_ = now;
}

void Lap::finish(Stage total)
{
    if (done_) return;
    done_ = true;
    const uint32_t end = esp_cpu_get_cycle_count();
    if (xPortGetCoreID() != core_) return;  // cycle counters are per core
    Recorder& r = Recorder::instance();
    for (int i = 0; i < kStages; i++)
        if (acc_[i]) r.add(static_cast<Stage>(i), acc_[i]);
    r.add(total, end - t0_);
}

uint32_t cyclesToNs(uint64_t cycles) { return static_cast<uint32_t>(cycles * 1000 / kMhz); }

uint32_t quantileNs(const StageStats& s, float q)
{
    if (!s.n) return 0;
    const uint32_t want = static_cast<uint32_t>(q * s.n);
    uint32_t seen = 0;
    for (int i = 0; i < kBuckets; i++) {
        seen += s.hist[i];
        if (seen > want) return cyclesToNs(bucketTop(i) < s.max ? bucketTop(i) : s.max);
    }
    return cyclesToNs(s.max);
}

const char* name(Stage s) { return kNames[s]; }

}  // namespace sinkhole::perf

#endif
