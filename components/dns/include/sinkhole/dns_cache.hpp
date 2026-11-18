#pragma once
// Answer cache for forwarded queries. A hit is answered locally in microseconds
// instead of waiting for an upstream round trip.
//
// With PSRAM: one big table of full-size (512 B) slots in PSRAM. Without it the
// same internal-RAM budget is split into two tables, because 97% of real
// answers are <= 160 bytes: many small slots plus a few full-size ones, about
// 2.8x more answers than equal 512-byte slots would hold.
//
// Only touched by the DNS task, so it needs no locking.

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace sinkhole {

class DnsCache {
public:
    static constexpr size_t kMaxResponse = 512;
    static constexpr size_t kSmallResponse = 160;

    void begin();

    // query: client packet, qend: end of its question. Writes the cached reply
    // (with the client's txid and aged TTLs) into out; returns 0 on a miss.
    // refresh: set when the caller should ask the upstream again in the
    // background: the answer expired less than kStaleS ago (served with a 30 s
    // TTL, RFC 8767) or has less than a tenth of its lifetime left (prefetch).
    size_t lookup(uint32_t key, const uint8_t* query, size_t qend, uint8_t* out, size_t cap, bool* refresh = nullptr);
    static constexpr uint32_t kStaleS = 3600;
    void store(uint32_t key, const uint8_t* resp, size_t len);
    void clear();

    // Separate keys for EDNS / non-EDNS queries: an OPT record must only go
    // back to clients that sent one.
    static uint32_t keyFor(uint32_t questionKey, bool edns)
    {
        uint32_t k = edns ? questionKey ^ 0x5bd1e995u : questionKey;
        return k ? k : 1;  // 0 marks an empty slot
    }

    size_t capacity() const { return small_.sets * small_.ways + large_.sets * large_.ways; }
    bool inPsram() const { return psram_; }
    uint32_t hits() const { return hits_; }
    uint32_t misses() const { return misses_; }

private:
    struct Hdr {
        uint32_t key;
        uint32_t storedAt;  // uptime seconds
        uint32_t ttl;       // seconds
        uint32_t refreshed; // uptime of the last background refresh request
        uint16_t len;
        uint16_t qend;
    };
    // Set-associative table of Hdr + `room` bytes of answer: 2-way for the big
    // PSRAM table, fully associative (one set) for the small internal ones,
    // where scanning ~90 headers is cheap and no two names fight for a slot.
    struct Table {
        uint8_t* mem = nullptr;
        size_t stride = 0;
        size_t room = 0;
        size_t sets = 0;
        size_t ways = 2;
        Hdr* way(uint32_t key, size_t w) const
        {
            return reinterpret_cast<Hdr*>(mem + ((key % sets) * ways + w) * stride);
        }
        static uint8_t* data(Hdr* h) { return reinterpret_cast<uint8_t*>(h + 1); }
    };

    bool setup(Table& t, size_t room, size_t entries, bool psram, bool fullyAssociative);
    size_t lookupIn(Table& t, uint32_t key, const uint8_t* query, size_t qend, uint8_t* out, size_t cap,
                    uint32_t now, bool* refresh);
    static void forget(Table& t, uint32_t key);

    Table small_;
    Table large_;
    bool psram_ = false;
    std::atomic<uint32_t> hits_{0};
    std::atomic<uint32_t> misses_{0};
};

}  // namespace sinkhole
