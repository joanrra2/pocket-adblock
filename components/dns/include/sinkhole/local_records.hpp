#pragma once
// User-defined local DNS: fixed addresses (nas.home -> 192.168.1.10) and
// forward rules (names under "lan" -> the router's DNS). Persisted as one NVS
// blob; checked before blocking on every query, lock-free while empty.

#include <atomic>
#include <cstddef>
#include <cstdint>

#include "esp_err.h"
#include "sdkconfig.h"
#include "sinkhole/rtos.hpp"

namespace sinkhole {

class LocalRecords {
public:
    static constexpr size_t kCapacity = CONFIG_SINKHOLE_MAX_LOCAL_RECORDS;
    static constexpr size_t kMaxName = 48;
    enum class Kind : uint8_t { Address = 0, Forward = 1 };

    struct Record {
        char name[kMaxName];
        uint32_t ip;  // network byte order: the address, or the DNS server to forward to
        Kind kind;
    };

    esp_err_t load();
    // ESP_ERR_INVALID_ARG (bad name) / ESP_ERR_NO_MEM (full). Re-adding a name
    // of the same kind replaces its address.
    esp_err_t add(const char* name, uint32_t ip, Kind kind);
    esp_err_t remove(const char* name, Kind kind);
    bool at(size_t i, Record& out);

    // name: lower-case query name. An Address must match exactly; a Forward
    // rule matches the name or any subdomain (longest suffix wins).
    bool lookup(const char* name, size_t len, Kind& kind, uint32_t& ip);

    // Lower-case, trims, strips a trailing dot. Single labels ("printer",
    // "lan") are fine here, unlike the block lists.
    static bool normalize(const char* in, char out[kMaxName]);

private:
    esp_err_t saveLocked();

    Mutex mu_;
    Record records_[kCapacity]{};
    size_t count_ = 0;
    std::atomic<size_t> published_{0};
};

}  // namespace sinkhole
