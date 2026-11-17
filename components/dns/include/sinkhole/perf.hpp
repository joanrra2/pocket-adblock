#pragma once
// Per-stage timing of the DNS task (CONFIG_SINKHOLE_PERF, a development aid,
// off in every release build). Each client query or upstream reply is timed
// with the CPU cycle counter as laps: mark(stage) charges the time since the
// previous mark to that stage, so preemption by Wi-Fi / lwIP lands in the
// stage it interrupted, as it would for a real client. A query seen on the
// other core at any mark is dropped (the counters are per core).
// GET /api/perf returns the stats in ns; ?reset=1 starts a new window.

#include <atomic>
#include <cstddef>
#include <cstdint>

#include "sdkconfig.h"

namespace sinkhole::perf {

enum Stage : uint8_t {
    Recv,       // recvfrom of the client query
    Parse,      // question parsing
    Client,     // per-client rate limit + per-client counters
    Rules,      // captive portal, local names, SafeSearch, bypass guard
    Filter,     // allow / custom / blocklist decision
    Log,        // query log (+ top domains)
    Cache,      // answer cache lookup
    Cname,      // CNAME re-check of a cached answer
    Forward,    // pending slot + txid for an uncached query
    Send,       // sendto (reply or upstream)
    QBlocked,   // whole query, answered as blocked
    QCached,    // whole query, answered from the cache
    QForwarded, // whole query, until sent upstream
    QOther,     // rate limited, local name, SafeSearch, guard, dropped
    URecv,      // recvfrom of an upstream reply
    UMatch,     // pending-slot match
    UCname,     // CNAME check of the reply
    USend,      // relay to the client
    UStore,     // answer cache store
    UTotal,     // whole upstream reply
    kStages
};

#if CONFIG_SINKHOLE_PERF

constexpr int kBuckets = 80;  // quarter-octave buckets up to 2^20 cycles

struct StageStats {
    uint32_t n, min, max;
    uint64_t sum;
    uint32_t hist[kBuckets];
};

class Recorder {
public:
    static Recorder& instance();
    void add(Stage s, uint32_t cycles);
    void requestReset() { reset_ = true; }
    void applyReset();  // DNS task only
    // Copy for the web server (racy by design: a stats view, not a ledger).
    void snapshot(StageStats out[kStages], int64_t& windowUs) const;

private:
    StageStats s_[kStages]{};
    int64_t since_ = 0;
    std::atomic<bool> reset_{true};
};

class Lap {
public:
    Lap();
    ~Lap() { finish(total_); }
    void mark(Stage s);
    void total(Stage s) { total_ = s; }  // which whole-query bucket on exit
    void finish(Stage total);

private:
    uint32_t acc_[kStages]{};
    uint32_t t0_, last_;
    int core_;
    Stage total_;
    bool done_ = false;
    bool moved_ = false;  // ran on the other core at some point: dropped
};

uint32_t cyclesToNs(uint64_t cycles);
uint32_t quantileNs(const StageStats& s, float q);
const char* name(Stage s);

#define SINKHOLE_PERF_LAP(var, totalStage) \
    ::sinkhole::perf::Lap var;             \
    var.total(totalStage)
#define SINKHOLE_PERF_MARK(var, stage) (var).mark(stage)
#define SINKHOLE_PERF_TOTAL(var, stage) (var).total(stage)

#else

#define SINKHOLE_PERF_LAP(var, totalStage) \
    do {                                   \
    } while (0)
#define SINKHOLE_PERF_MARK(var, stage) \
    do {                               \
    } while (0)
#define SINKHOLE_PERF_TOTAL(var, stage) \
    do {                                \
    } while (0)

#endif

}  // namespace sinkhole::perf
