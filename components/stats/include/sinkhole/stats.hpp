#pragma once
// Per-client counters, ban list, global counters and a ring buffer of recent
// queries. All fixed-size.

#include <atomic>
#include <cstddef>
#include <cstdint>

#include "esp_err.h"
#include "sdkconfig.h"
#include "sinkhole/rtos.hpp"

namespace sinkhole {

struct ClientInfo {
    uint32_t ip;  // network byte order
    uint8_t mac[6];
    uint32_t blocked;
    uint32_t allowed;
    uint32_t lastSeen;  // uptime seconds
    bool banned;
};

class ClientTable {
public:
    static constexpr size_t kCapacity = CONFIG_SINKHOLE_MAX_CLIENTS;
    static constexpr size_t kMaxBanned = 32;

    esp_err_t load();  // ban list from NVS

    // Counts one query; returns true if the client is banned.
    bool record(uint32_t ip, bool blocked);
    bool isBanned(uint32_t ip);
    esp_err_t setBanned(uint32_t ip, bool banned);

    // Snapshot for the UI. Resolves missing MACs from the ARP table first.
    size_t snapshot(ClientInfo* out, size_t max);

private:
    ClientInfo* findLocked(uint32_t ip);
    esp_err_t saveBannedLocked();

    Mutex mu_;
    ClientInfo clients_[kCapacity]{};
    size_t count_ = 0;
    uint32_t banned_[kMaxBanned]{};
    size_t bannedCount_ = 0;
};

struct QueryEntry {
    uint32_t uptime;
    uint32_t ip;
    bool blocked;
    char domain[64];
};

class QueryLog {
public:
    static constexpr size_t kCapacity = 32;
    void add(uint32_t ip, const char* domain, bool blocked);
    // Newest first.
    size_t snapshot(QueryEntry* out, size_t max);

private:
    Mutex mu_;
    QueryEntry ring_[kCapacity]{};
    size_t head_ = 0;
    size_t count_ = 0;
};

struct Counters {
    std::atomic<uint32_t> blocked{0};
    std::atomic<uint32_t> allowed{0};
    std::atomic<uint32_t> upstreamTimeouts{0};
    std::atomic<uint32_t> dropped{0};  // pending table full / malformed
};

}  // namespace sinkhole
