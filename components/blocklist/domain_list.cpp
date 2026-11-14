#include "sinkhole/domain_list.hpp"

#include <cctype>
#include <cstring>

#include "esp_log.h"
#include "nvs.h"
#include "sinkhole/config.hpp"
#include "sinkhole/hash_table.hpp"

namespace sinkhole {

namespace {
constexpr const char* TAG = "domains";
}

bool DomainList::normalize(const char* in, char out[kMaxLen])
{
    while (*in == ' ' || *in == '\t' || *in == '*' || *in == '.') in++;
    size_t n = 0;
    for (; *in && n < kMaxLen - 1; in++) {
        char c = static_cast<char>(tolower(static_cast<unsigned char>(*in)));
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') break;
        if (!(isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '.' || c == '_'))
            return false;
        out[n++] = c;
    }
    if (*in && *in != ' ' && *in != '\t' && *in != '\r' && *in != '\n') return false;  // too long
    while (n && out[n - 1] == '.') n--;
    out[n] = '\0';
    if (n > 4 && strncmp(out, "www.", 4) == 0) {
        memmove(out, out + 4, n - 3);
        n -= 4;
    }
    return n >= 3 && strchr(out, '.') != nullptr;
}

esp_err_t DomainList::load()
{
    LockGuard g(mu_);
    size_t n = 0;
    esp_err_t err = nvs::loadBlob(key_, entries_, sizeof(entries_), &n);
    if (err == ESP_ERR_NVS_INVALID_LENGTH) {
        ESP_LOGW(TAG, "%s: stored list larger than capacity, ignoring", key_);
        n = 0;
    }
    count_ = n / sizeof(Entry);
    for (size_t i = 0; i < count_; i++) entries_[i].name[kMaxLen - 1] = '\0';
    rehashLocked();
    return ESP_OK;
}

void DomainList::rehashLocked()
{
    for (size_t i = 0; i < count_; i++)
        hashes_[i] = fnv1a40(entries_[i].name, strlen(entries_[i].name));
}

esp_err_t DomainList::saveLocked()
{
    return nvs::saveBlob(key_, entries_, count_ * sizeof(Entry));
}

esp_err_t DomainList::add(const char* domain)
{
    char norm[kMaxLen];
    if (!normalize(domain, norm)) return ESP_ERR_INVALID_ARG;
    LockGuard g(mu_);
    for (size_t i = 0; i < count_; i++)
        if (strcmp(entries_[i].name, norm) == 0) return ESP_ERR_INVALID_STATE;
    if (count_ >= kCapacity) return ESP_ERR_NO_MEM;
    memcpy(entries_[count_].name, norm, kMaxLen);
    hashes_[count_] = fnv1a40(norm, strlen(norm));
    count_++;
    return saveLocked();
}

esp_err_t DomainList::remove(const char* domain)
{
    char norm[kMaxLen];
    if (!normalize(domain, norm)) return ESP_ERR_INVALID_ARG;
    LockGuard g(mu_);
    for (size_t i = 0; i < count_; i++) {
        if (strcmp(entries_[i].name, norm) != 0) continue;
        for (size_t j = i + 1; j < count_; j++) {
            entries_[j - 1] = entries_[j];
            hashes_[j - 1] = hashes_[j];
        }
        count_--;
        return saveLocked();
    }
    return ESP_ERR_NOT_FOUND;
}

bool DomainList::containsHash(uint64_t h)
{
    LockGuard g(mu_);
    for (size_t i = 0; i < count_; i++)
        if (hashes_[i] == h) return true;
    return false;
}

size_t DomainList::count()
{
    LockGuard g(mu_);
    return count_;
}

bool DomainList::at(size_t i, char out[kMaxLen])
{
    LockGuard g(mu_);
    if (i >= count_) return false;
    memcpy(out, entries_[i].name, kMaxLen);
    return true;
}

}  // namespace sinkhole
