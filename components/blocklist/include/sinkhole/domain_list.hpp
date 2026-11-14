#pragma once
// Fixed-capacity list of user-managed domains (custom block list / allow list),
// persisted as one NVS blob.

#include <cstddef>
#include <cstdint>

#include "esp_err.h"
#include "sdkconfig.h"
#include "sinkhole/rtos.hpp"

namespace sinkhole {

class DomainList {
public:
    static constexpr size_t kCapacity = CONFIG_SINKHOLE_MAX_CUSTOM_DOMAINS;
    static constexpr size_t kMaxLen = 64;

    explicit DomainList(const char* nvsKey) : key_(nvsKey) {}

    esp_err_t load();
    esp_err_t add(const char* domain);  // ESP_ERR_INVALID_ARG / ESP_ERR_NO_MEM / ESP_ERR_INVALID_STATE (dup)
    esp_err_t remove(const char* domain);
    bool containsHash(uint64_t h);
    size_t count();

    // Copies entry i into out (thread-safe iteration for the web UI).
    bool at(size_t i, char out[kMaxLen]);

    // Lower-cases, trims, strips "www." and trailing dot. False if not a domain.
    static bool normalize(const char* in, char out[kMaxLen]);

private:
    struct Entry {
        char name[kMaxLen];
    };
    esp_err_t saveLocked();
    void rehashLocked();

    const char* key_;
    Mutex mu_;
    Entry entries_[kCapacity]{};
    uint64_t hashes_[kCapacity]{};
    size_t count_ = 0;
};

}  // namespace sinkhole
