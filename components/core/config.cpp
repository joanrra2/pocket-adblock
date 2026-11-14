#include "sinkhole/config.hpp"

#include <cstddef>
#include <cstring>

#include "esp_log.h"
#include "lwip/inet.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "sdkconfig.h"
#include "sinkhole/text.hpp"

namespace sinkhole {

namespace {
constexpr const char* TAG = "config";
constexpr const char* kNamespace = "sinkhole";
constexpr const char* kSettingsKey = "settings";
}  // namespace

// ---------------------------------------------------------------- text helpers

bool parseIp4(const char* s, uint32_t& out)
{
    in_addr a{};
    if (!s || inet_aton(s, &a) == 0) return false;
    if (a.s_addr == 0 || a.s_addr == 0xFFFFFFFFu) return false;
    out = a.s_addr;
    return true;
}

void formatIp4(uint32_t ip, char out[16])
{
    in_addr a{};
    a.s_addr = ip;
    inet_ntoa_r(a, out, 16);
}

// ---------------------------------------------------------------- NVS helpers

namespace nvs {

esp_err_t init()
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS partition reset (%s)", esp_err_to_name(err));
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    return err;
}

esp_err_t loadBlob(const char* key, void* data, size_t len, size_t* outLen)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(kNamespace, NVS_READONLY, &h);
    if (err != ESP_OK) return err;
    size_t n = len;
    err = nvs_get_blob(h, key, data, &n);
    nvs_close(h);
    if (outLen) *outLen = (err == ESP_OK) ? n : 0;
    return err;
}

esp_err_t saveBlob(const char* key, const void* data, size_t len)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(kNamespace, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(h, key, data, len);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

esp_err_t loadU8(const char* key, uint8_t& out)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(kNamespace, NVS_READONLY, &h);
    if (err != ESP_OK) return err;
    err = nvs_get_u8(h, key, &out);
    nvs_close(h);
    return err;
}

esp_err_t saveU8(const char* key, uint8_t v)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(kNamespace, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_set_u8(h, key, v);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

}  // namespace nvs

// ---------------------------------------------------------------- Config

void Config::applyDefaults(Settings& s)
{
    memset(&s, 0, sizeof(s));
    s.version = kVersion;
    copyStr(s.hostname, CONFIG_SINKHOLE_HOSTNAME);
    copyStr(s.apPass, CONFIG_SINKHOLE_AP_PASSWORD);
    s.apAlways = false;  // AP only while no uplink is configured / reachable
    copyStr(s.adminUser, CONFIG_SINKHOLE_ADMIN_USER);
    copyStr(s.adminPass, CONFIG_SINKHOLE_ADMIN_PASSWORD);
    s.upstreamMode = UpstreamMode::Builtin;
    s.blocking = true;
    copyStr(s.blocklistUrl, CONFIG_SINKHOLE_BLOCKLIST_URL);
    s.updateHours = CONFIG_SINKHOLE_BLOCKLIST_UPDATE_HOURS;
    copyStr(s.mqttPrefix, "sinkhole");
}

// Bytes of Settings that were meaningful in a given stored version. Fields are
// only ever appended, so an older blob is a valid prefix of the current struct.
size_t Config::validBytes(uint16_t version)
{
    switch (version) {
        case 2: return offsetof(Settings, staticIp);
        case 3: return offsetof(Settings, txPower);
        case 4: return offsetof(Settings, upstreamIp2);
        case kVersion: return sizeof(Settings);
        default: return 0;  // unknown / too old: start from defaults
    }
}

esp_err_t Config::load()
{
    LockGuard g(mu_);
    static Settings stored;  // only used here, under mu_; keeps 1 KB off the stack
    memset(&stored, 0, sizeof(stored));
    size_t n = 0;
    esp_err_t err = nvs::loadBlob(kSettingsKey, &stored, sizeof(stored), &n);
    const size_t valid = (err == ESP_OK && n >= sizeof(uint16_t)) ? validBytes(stored.version) : 0;
    applyDefaults(s_);
    if (!valid || n < valid) {
        ESP_LOGI(TAG, "no usable stored settings (%s), using defaults", esp_err_to_name(err));
        return saveLocked();
    }
    if (stored.version != kVersion) {
        memcpy(&s_, &stored, valid);  // keep everything the old version knew
        s_.version = kVersion;
        ESP_LOGI(TAG, "settings migrated from v%u to v%u", stored.version, kVersion);
        saveLocked();
    } else {
        s_ = stored;
    }
    // Defensive: blobs from a buggy build could miss terminators.
    s_.hostname[sizeof(s_.hostname) - 1] = '\0';
    s_.staSsid[sizeof(s_.staSsid) - 1] = '\0';
    s_.staPass[sizeof(s_.staPass) - 1] = '\0';
    s_.apSsid[sizeof(s_.apSsid) - 1] = '\0';
    s_.apPass[sizeof(s_.apPass) - 1] = '\0';
    s_.adminUser[sizeof(s_.adminUser) - 1] = '\0';
    s_.adminPass[sizeof(s_.adminPass) - 1] = '\0';
    s_.blocklistUrl[sizeof(s_.blocklistUrl) - 1] = '\0';
    s_.mqttUri[sizeof(s_.mqttUri) - 1] = '\0';
    s_.mqttUser[sizeof(s_.mqttUser) - 1] = '\0';
    s_.mqttPass[sizeof(s_.mqttPass) - 1] = '\0';
    s_.mqttPrefix[sizeof(s_.mqttPrefix) - 1] = '\0';
    return ESP_OK;
}

Settings Config::get()
{
    LockGuard g(mu_);
    return s_;
}

bool Config::usingDefaultAdminPassword()
{
    LockGuard g(mu_);
    return strcmp(s_.adminPass, CONFIG_SINKHOLE_ADMIN_PASSWORD) == 0;
}

esp_err_t Config::saveLocked()
{
    esp_err_t err = nvs::saveBlob(kSettingsKey, &s_, sizeof(s_));
    if (err != ESP_OK) ESP_LOGE(TAG, "save failed: %s", esp_err_to_name(err));
    return err;
}

}  // namespace sinkhole
