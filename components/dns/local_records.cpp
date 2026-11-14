#include "sinkhole/local_records.hpp"

#include <cctype>
#include <cstring>

#include "esp_log.h"
#include "sinkhole/config.hpp"

namespace sinkhole {

namespace {
constexpr const char* TAG = "local-dns";
constexpr const char* kKey = "local_dns";
}  // namespace

bool LocalRecords::normalize(const char* in, char out[kMaxName])
{
    while (*in == ' ' || *in == '\t' || *in == '.') in++;
    size_t n = 0;
    for (; *in && *in != ' ' && *in != '\t' && *in != '\r' && *in != '\n'; in++) {
        const char c = static_cast<char>(tolower(static_cast<unsigned char>(*in)));
        if (!(isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '.' || c == '_')) return false;
        if (n >= kMaxName - 1) return false;
        out[n++] = c;
    }
    while (*in == ' ' || *in == '\t' || *in == '\r' || *in == '\n') in++;
    if (*in) return false;  // "bad name": a space inside the name
    while (n && out[n - 1] == '.') n--;
    out[n] = '\0';
    return n > 0 && strstr(out, "..") == nullptr;
}

esp_err_t LocalRecords::load()
{
    LockGuard g(mu_);
    size_t n = 0;
    if (nvs::loadBlob(kKey, records_, sizeof(records_), &n) != ESP_OK) n = 0;
    count_ = n / sizeof(Record);
    for (size_t i = 0; i < count_; i++) records_[i].name[kMaxName - 1] = '\0';
    published_ = count_;
    if (count_) ESP_LOGI(TAG, "%u local records", static_cast<unsigned>(count_));
    return ESP_OK;
}

esp_err_t LocalRecords::saveLocked()
{
    published_ = count_;
    return nvs::saveBlob(kKey, records_, count_ * sizeof(Record));
}

esp_err_t LocalRecords::add(const char* name, uint32_t ip, Kind kind)
{
    char norm[kMaxName];
    if (!normalize(name, norm) || !ip) return ESP_ERR_INVALID_ARG;
    LockGuard g(mu_);
    for (size_t i = 0; i < count_; i++) {
        if (records_[i].kind == kind && strcmp(records_[i].name, norm) == 0) {
            records_[i].ip = ip;
            return saveLocked();
        }
    }
    if (count_ >= kCapacity) return ESP_ERR_NO_MEM;
    Record& r = records_[count_++];
    memcpy(r.name, norm, kMaxName);
    r.ip = ip;
    r.kind = kind;
    return saveLocked();
}

esp_err_t LocalRecords::remove(const char* name, Kind kind)
{
    char norm[kMaxName];
    if (!normalize(name, norm)) return ESP_ERR_INVALID_ARG;
    LockGuard g(mu_);
    for (size_t i = 0; i < count_; i++) {
        if (records_[i].kind != kind || strcmp(records_[i].name, norm) != 0) continue;
        for (size_t j = i + 1; j < count_; j++) records_[j - 1] = records_[j];
        count_--;
        return saveLocked();
    }
    return ESP_ERR_NOT_FOUND;
}

bool LocalRecords::at(size_t i, Record& out)
{
    LockGuard g(mu_);
    if (i >= count_) return false;
    out = records_[i];
    return true;
}

bool LocalRecords::lookup(const char* name, size_t len, Kind& kind, uint32_t& ip)
{
    if (published_ == 0) return false;  // the common case: nothing configured
    LockGuard g(mu_);
    size_t best = 0;
    for (size_t i = 0; i < count_; i++) {
        const Record& r = records_[i];
        const size_t n = strlen(r.name);
        if (r.kind == Kind::Address) {
            if (n == len && memcmp(r.name, name, len) == 0) {
                kind = Kind::Address;
                ip = r.ip;
                return true;
            }
        } else if (n > best && n <= len && memcmp(name + len - n, r.name, n) == 0 &&
                   (n == len || name[len - n - 1] == '.')) {
            best = n;
            kind = Kind::Forward;
            ip = r.ip;
        }
    }
    return best > 0;
}

}  // namespace sinkhole
