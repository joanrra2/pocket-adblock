#pragma once
// Answer cache for forwarded queries. A hit is answered locally in microseconds
// instead of waiting for an upstream round trip, which is the one place where
// PSRAM clearly improves latency: big cache in PSRAM when present, small one in
// internal RAM otherwise (sized once at boot, see memory.hpp).
//
// Only touched by the DNS task, so it needs no locking.

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace sinkhole {

class DnsCache {
public:
    static constexpr size_t kMaxResponse = 512;

    void begin();

    // query: client packet, qend: end of its question. Writes the cached reply
    // (with the client's txid and aged TTLs) into out; returns 0 on a miss.
    size_t lookup(uint32_t key, const uint8_t* query, size_t qend, uint8_t* out, size_t cap);
    void store(uint32_t key, const uint8_t* resp, size_t len);
    void clear();

    // Separate keys for EDNS / non-EDNS queries: an OPT record must only go
    // back to clients that sent one.
    static uint32_t keyFor(uint32_t questionKey, bool edns)
    {
        uint32_t k = edns ? questionKey ^ 0x5bd1e995u : questionKey;
        return k ? k : 1;  // 0 marks an empty slot
    }

    size_t capacity() const { return sets_ * 2; }
    bool inPsram() const { return psram_; }
    uint32_t hits() const { return hits_; }
    uint32_t misses() const { return misses_; }

private:
    struct Entry {
        uint32_t key;
        uint32_t storedAt;  // uptime seconds
        uint32_t ttl;       // seconds
        uint16_t len;
        uint16_t qend;
        uint8_t data[kMaxResponse];
    };

    Entry* entries_ = nullptr;
    size_t sets_ = 0;  // 2-way set associative
    bool psram_ = false;
    std::atomic<uint32_t> hits_{0};
    std::atomic<uint32_t> misses_{0};
};

}  // namespace sinkhole
