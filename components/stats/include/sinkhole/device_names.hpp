#pragma once
// Names you give devices on the network, by MAC address (so a name stays with
// the device when its IP changes). Shown in the device list, the query log and
// the top clients. 32 names, 32 bytes each, in one NVS blob.

#include <array>
#include <cstddef>
#include <cstdint>

#include "esp_err.h"
#include "sinkhole/rtos.hpp"

namespace sinkhole {

class DeviceNames {
public:
    static constexpr size_t kCapacity = 32;
    static constexpr size_t kMaxName = 26;  // with the terminator

    struct Entry {
        std::array<uint8_t, 6> mac;
        std::array<char, kMaxName> name;
    };
    static_assert(sizeof(Entry) == 32, "stored in NVS");

    esp_err_t load();
    // Empty name = forget it. ESP_ERR_INVALID_ARG: bad name; ESP_ERR_NO_MEM: full.
    esp_err_t set(const uint8_t* mac, const char* name);
    bool find(const uint8_t* mac, char* out, size_t cap);
    static bool validName(const char* name);

private:
    esp_err_t saveLocked();

    Mutex mu_;
    std::array<Entry, kCapacity> entries_{};
    size_t count_ = 0;
};

}  // namespace sinkhole
