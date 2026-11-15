#pragma once
// Per-client counters, ban list, global counters and a ring buffer of recent
// queries. All fixed-size.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "esp_err.h"
#include "sdkconfig.h"
#include "sinkhole/rtos.hpp"

namespace sinkhole {

// A DNS client: IPv4 (address in a[0..3], network order) or IPv6.
struct ClientAddr {
    uint8_t v6;
    uint8_t a[16];

    static ClientAddr fromV4(uint32_t ip)
    {
        ClientAddr c{};
        memcpy(c.a, &ip, 4);
        return c;
    }
    static ClientAddr fromV6(const uint8_t addr[16])
    {
        ClientAddr c{};
        c.v6 = 1;
        memcpy(c.a, addr, 16);
        return c;
    }
    uint32_t v4() const
    {
        uint32_t ip = 0;
        if (!v6) memcpy(&ip, a, 4);
        return ip;
    }
    bool operator==(const ClientAddr& o) const { return v6 == o.v6 && memcmp(a, o.a, v6 ? 16 : 4) == 0; }
    void format(char out[46]) const;
};

struct ClientInfo {
    ClientAddr addr;
    uint8_t mac[6];
    uint32_t blocked;
    uint32_t allowed;
    uint32_t lastSeen;  // uptime seconds
    bool banned;
    uint32_t rateStart;  // rate-limit window start (uptime s)
    uint16_t rateCount;  // queries in that window
    uint32_t refused;    // queries refused by the rate limit
    bool noFilter;       // per-device rule: never blocked
};

class ClientTable {
public:
    static constexpr size_t kCapacity = CONFIG_SINKHOLE_MAX_CLIENTS;
    static constexpr size_t kMaxBanned = 32;

    esp_err_t load();  // ban list from NVS

    // Counts one query; returns true if the client is banned (IPv4 clients only).
    bool record(const ClientAddr& addr, bool blocked);
    // Counts one query against the client's per-minute budget; false when
    // over `perMinute` (the query should be refused). 0 = no limit.
    bool withinRate(const ClientAddr& addr, uint16_t perMinute, bool* noFilter = nullptr);
    // Per-device rule (IPv4): queries from this device are never blocked.
    esp_err_t setNoFilter(uint32_t ip, bool on);
    bool isBanned(uint32_t ip);
    esp_err_t setBanned(uint32_t ip, bool banned);

    // Snapshot for the UI. Resolves missing MACs from the ARP table first.
    size_t snapshot(ClientInfo* out, size_t max);
    // Clients seen within the last `seconds`.
    size_t activeCount(uint32_t seconds);

private:
    ClientInfo* findLocked(const ClientAddr& addr);
    ClientInfo* findOrAddLocked(const ClientAddr& addr);
    esp_err_t saveBannedLocked();
    static esp_err_t setInList(uint32_t* list, size_t& count, uint32_t ip, bool on, const char* key);

    Mutex mu_;
    ClientInfo clients_[kCapacity]{};
    size_t count_ = 0;
    uint32_t banned_[kMaxBanned]{};
    size_t bannedCount_ = 0;
    uint32_t noFilter_[kMaxBanned]{};
    size_t noFilterCount_ = 0;
};

struct QueryEntry {
    uint32_t uptime;
    ClientAddr addr;
    bool blocked;
    char domain[64];
};

struct QueryFilter {
    uint32_t ip = 0;          // IPv4 client, 0 = any client
    bool blockedOnly = false;
    const char* text = nullptr;  // substring of the domain, nullptr = any
};

// Most-queried domains since boot (CONFIG_SINKHOLE_TOP_DOMAINS, PSRAM only).
// 4-way set-associative counters: a new name replaces the smallest count in
// its set, so frequent names stay and one-off names churn. Approximate, O(1).
class TopDomains {
public:
    struct Item {
        char name[52];
        uint32_t count;
    };
    void begin();
    bool enabled() const { return sets_ != 0; }
    size_t capacity() const { return sets_ * kWays; }
    void recordLocked(const char* name, bool blocked);              // caller holds the log lock
    size_t topLocked(bool blocked, Item* out, size_t max) const;   // highest first

private:
    static constexpr size_t kWays = 4;
    struct Entry {
        uint32_t key;    // FNV-1a of the name, low bit = blocked
        uint32_t count;  // 0 = empty
        char name[52];
    };
    Entry* e_ = nullptr;
    size_t sets_ = 0;
};

class QueryLog {
public:
    static constexpr size_t kSmall = 32;

    // Allocates the long history when CONFIG_SINKHOLE_QUERY_HISTORY_EXTENDED.
    void begin();
    void add(const ClientAddr& addr, const char* domain, bool blocked);
    // Flips the newest matching allowed entry to blocked (decided after the
    // upstream answered, e.g. CNAME cloaking). Only looks at recent entries.
    void markBlocked(const ClientAddr& addr, const char* domain);

    // Paged, newest first. `cursor` counts entries already scanned (start at 0);
    // copies up to `max` matches and returns how many. The lock is held only per
    // page, so the DNS task is never stuck behind a slow HTTP client.
    size_t page(size_t& cursor, const QueryFilter& f, QueryEntry* out, size_t max);
    size_t capacity() const { return cap_; }
    bool inPsram() const { return psram_; }
    bool topEnabled() const { return top_.enabled(); }
    // 0 = record everything, 1 = hide domains ("(hidden)", no top domains),
    // 2 = also hide clients (no addresses in the log or the client views).
    void setPrivacy(uint8_t level) { privacy_ = level; }
    uint8_t privacy() const { return privacy_; }
    size_t top(bool blocked, TopDomains::Item* out, size_t max)
    {
        LockGuard g(mu_);
        return top_.topLocked(blocked, out, max);
    }

private:
    Mutex mu_;
    QueryEntry small_[kSmall]{};
    QueryEntry* ring_ = small_;
    size_t cap_ = kSmall;
    bool psram_ = false;
    size_t head_ = 0;
    size_t count_ = 0;
    TopDomains top_;
    std::atomic<uint8_t> privacy_{0};
};

struct Counters {
    std::atomic<uint32_t> blocked{0};
    std::atomic<uint32_t> allowed{0};
    std::atomic<uint32_t> upstreamTimeouts{0};
    std::atomic<uint32_t> dropped{0};  // pending table full / malformed
    std::atomic<uint32_t> bypassBlocked{0};  // canary / encrypted-DNS lookups answered NXDOMAIN
    std::atomic<uint32_t> cnameBlocked{0};   // allowed names that were aliases of blocked ones
    std::atomic<uint32_t> rateLimited{0};    // queries refused by the per-client rate limit
};

}  // namespace sinkhole
