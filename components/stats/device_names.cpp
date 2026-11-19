#include "sinkhole/device_names.hpp"

#include <cstring>

#include "sinkhole/config.hpp"
#include "sinkhole/text.hpp"

namespace sinkhole {

namespace {
constexpr const char* kKey = "dev_names";
}

esp_err_t DeviceNames::load()
{
    LockGuard g(mu_);
    size_t n = 0;
    if (nvs::loadBlob(kKey, entries_.data(), sizeof(entries_), &n) != ESP_OK) n = 0;
    count_ = n / sizeof(Entry);
    for (size_t i = 0; i < count_; i++) entries_[i].name.back() = '\0';
    return ESP_OK;
}

bool DeviceNames::validName(const char* name)
{
    const size_t n = strnlen(name, kMaxName);
    if (n == 0 || n >= kMaxName) return false;
    for (size_t i = 0; i < n; i++) {
        const auto c = static_cast<unsigned char>(name[i]);
        if (c < 0x20 || c == 0x7f || c == '<' || c == '>' || c == '"' || c == '&') return false;
    }
    return true;
}

esp_err_t DeviceNames::set(const uint8_t* mac, const char* name)
{
    if (name[0] && !validName(name)) return ESP_ERR_INVALID_ARG;
    LockGuard g(mu_);
    size_t i = 0;
    while (i < count_ && memcmp(entries_[i].mac.data(), mac, 6) != 0) i++;
    if (!name[0]) {  // forget
        if (i == count_) return ESP_OK;
        for (size_t j = i + 1; j < count_; j++) entries_[j - 1] = entries_[j];
        count_--;
        return saveLocked();
    }
    if (i == count_) {
        if (count_ == kCapacity) return ESP_ERR_NO_MEM;
        count_++;
        memcpy(entries_[i].mac.data(), mac, 6);
    }
    copyStr(entries_[i].name.data(), entries_[i].name.size(), name);
    return saveLocked();
}

bool DeviceNames::find(const uint8_t* mac, char* out, size_t cap)
{
    LockGuard g(mu_);
    for (size_t i = 0; i < count_; i++) {
        if (memcmp(entries_[i].mac.data(), mac, 6) == 0) {
            copyStr(out, cap, entries_[i].name.data());
            return true;
        }
    }
    return false;
}

esp_err_t DeviceNames::saveLocked()
{
    return nvs::saveBlob(kKey, entries_.data(), count_ * sizeof(Entry));
}

}  // namespace sinkhole
