#include "sinkhole/config.hpp"

#include <cstddef>
#include <cstring>

#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "lwip/inet.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "psa/crypto.h"
#include "sdkconfig.h"
#include "sinkhole/text.hpp"

namespace sinkhole {

namespace {
constexpr const char* TAG = "config";
constexpr const char* kNamespace = "sinkhole";
constexpr const char* kSettingsKey = "settings";
// PBKDF2 work factor for the admin password. Each login check costs this many
// HMAC-SHA256 rounds (cached after a success); stored per password, so it can
// be raised later without breaking existing ones.
constexpr uint32_t kAdminIter = 10000;
constexpr char kScrubbed = '\x7f';  // first byte of a cleared adminPass

esp_err_t pbkdf2(const char* pass, const uint8_t* salt, size_t saltLen, uint32_t iter, uint8_t out[32])
{
    psa_crypto_init();  // idempotent
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_status_t st = psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
    if (st == PSA_SUCCESS) st = psa_key_derivation_input_integer(&op, PSA_KEY_DERIVATION_INPUT_COST, iter);
    if (st == PSA_SUCCESS) st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, salt, saltLen);
    if (st == PSA_SUCCESS)
        st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD,
                                            reinterpret_cast<const uint8_t*>(pass), strlen(pass));
    if (st == PSA_SUCCESS) st = psa_key_derivation_output_bytes(&op, out, 32);
    psa_key_derivation_abort(&op);
    if (st != PSA_SUCCESS) ESP_LOGE(TAG, "PBKDF2 failed (%d)", static_cast<int>(st));
    return st == PSA_SUCCESS ? ESP_OK : ESP_FAIL;
}

// Constant time, for credentials.
bool sameBytes(const uint8_t* a, const uint8_t* b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    return diff == 0;
}

bool sameText(const char* a, const char* b)
{
    const size_t la = strlen(a), lb = strlen(b);
    uint8_t diff = static_cast<uint8_t>(la != lb);
    for (size_t i = 0; i < la; i++) diff |= static_cast<uint8_t>(a[i] ^ b[i % (lb ? lb : 1)]);
    return diff == 0;
}

// Overwrite adminPass with random letters behind kScrubbed: older firmware
// (rollback or manual downgrade) then matches no password at all.
void scrub(char (&pass)[64])
{
    uint8_t rnd[16];
    esp_fill_random(rnd, sizeof(rnd));
    memset(pass, 0, sizeof(pass));
    pass[0] = kScrubbed;
    for (size_t i = 0; i < sizeof(rnd); i++) pass[i + 1] = static_cast<char>('a' + rnd[i] % 26);
}
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

esp_err_t eraseKey(const char* key)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(kNamespace, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_erase_key(h, key);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

size_t blobSize(const char* key)
{
    nvs_handle_t h;
    if (nvs_open(kNamespace, NVS_READONLY, &h) != ESP_OK) return 0;
    size_t n = 0;
    if (nvs_get_blob(h, key, nullptr, &n) != ESP_OK) n = 0;
    nvs_close(h);
    return n;
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
    copyStr(s.fwManifestUrl, CONFIG_SINKHOLE_FW_MANIFEST_URL);
    s.bypassGuard = 1;  // canary domains on, encrypted-DNS list off (see bypass_guard.hpp)
    s.cnameCheck = true;
    s.haDiscovery = true;
    copyStr(s.dotHost, "dns.quad9.net");
    s.ledPin = -1;
    s.ledBrightness = 24;
    s.rateLimit = 1000;  // Pi-hole's default: 1000 queries per minute per client
    s.dhcpLeaseMinutes = 720;
}

// Bytes of Settings that were meaningful in a given stored version. Fields are
// only ever appended, so an older blob is a valid prefix of the current struct.
size_t Config::validBytes(uint16_t version)
{
    switch (version) {
        case 2: return offsetof(Settings, staticIp);
        case 3: return offsetof(Settings, txPower);
        case 4: return offsetof(Settings, upstreamIp2);
        case 5: return offsetof(Settings, fwManifestUrl);
        case 6: return offsetof(Settings, bypassGuard);
        case 7: return offsetof(Settings, cnameCheck);
        case 8: return offsetof(Settings, haDiscovery);
        case 9: return offsetof(Settings, safeSearch);
        case 10: return offsetof(Settings, dot);
        case 11: return offsetof(Settings, ledKind);
        case 12: return offsetof(Settings, privacy);
        case 13: return offsetof(Settings, dhcpServer);
        case 14: return offsetof(Settings, adminHash);
        case kVersion: return sizeof(Settings);
        default:
            // Newer firmware wrote it (rollback / downgrade): fields are only ever
            // appended, so everything this version knows is still a valid prefix.
            // Keeps Wi-Fi and the rest instead of resetting to defaults.
            if (version > kVersion && version < 1000) return sizeof(Settings);
            return 0;  // unknown / too old: start from defaults
    }
}

bool Config::upgrade(const uint8_t* raw, size_t n, Settings& out)
{
    static Settings stored;  // under mu_ in load(); httpd task in restore (one at a time)
    memset(&stored, 0, sizeof(stored));
    memcpy(&stored, raw, n < sizeof(stored) ? n : sizeof(stored));
    if (n > sizeof(stored)) n = sizeof(stored);
    const size_t valid = n >= sizeof(uint16_t) ? validBytes(stored.version) : 0;
    applyDefaults(out);
    if (!valid || n < valid) return false;
    memcpy(&out, &stored, valid);  // keep everything the stored version knew
    out.version = kVersion;
    if (stored.version < 6) copyStr(out.fwManifestUrl, CONFIG_SINKHOLE_FW_MANIFEST_URL);
    // Defensive: blobs from a buggy build could miss terminators.
    out.hostname[sizeof(out.hostname) - 1] = '\0';
    out.staSsid[sizeof(out.staSsid) - 1] = '\0';
    out.staPass[sizeof(out.staPass) - 1] = '\0';
    out.apSsid[sizeof(out.apSsid) - 1] = '\0';
    out.apPass[sizeof(out.apPass) - 1] = '\0';
    out.adminUser[sizeof(out.adminUser) - 1] = '\0';
    out.adminPass[sizeof(out.adminPass) - 1] = '\0';
    out.blocklistUrl[sizeof(out.blocklistUrl) - 1] = '\0';
    out.mqttUri[sizeof(out.mqttUri) - 1] = '\0';
    out.mqttUser[sizeof(out.mqttUser) - 1] = '\0';
    out.mqttPass[sizeof(out.mqttPass) - 1] = '\0';
    out.mqttPrefix[sizeof(out.mqttPrefix) - 1] = '\0';
    out.dotHost[sizeof(out.dotHost) - 1] = '\0';
    // Older firmware kept the admin password in plain text: hash it. The plain
    // copy stays until the firmware is confirmed (scrubLegacyAdminPassword), so
    // a rollback to the previous image still accepts it. The default password
    // and an empty one (a backup without passwords) stay as they are.
    if (stored.version < 15 && out.adminPass[0] && strcmp(out.adminPass, CONFIG_SINKHOLE_ADMIN_PASSWORD) != 0)
        hashAdmin(out, out.adminPass);
    return true;
}

esp_err_t Config::load()
{
    LockGuard g(mu_);
    // Only used here, under mu_ (keeps ~1 KB off the stack). Room for fields a
    // newer firmware appended, so a rollback keeps the settings.
    static uint8_t raw[sizeof(Settings) + 256];
    memset(raw, 0, sizeof(raw));
    size_t n = 0;
    esp_err_t err = nvs::loadBlob(kSettingsKey, raw, sizeof(raw), &n);
    uint16_t version = 0;
    if (n >= sizeof(version)) memcpy(&version, raw, sizeof(version));
    if (err != ESP_OK || !upgrade(raw, n, s_)) {
        ESP_LOGI(TAG, "no usable stored settings (%s), using defaults", esp_err_to_name(err));
        return saveLocked();
    }
    if (version != kVersion) {
        ESP_LOGI(TAG, "settings migrated from v%u to v%u", version, kVersion);
        saveLocked();
    }
    // Early builds defaulted to the upstream project's list; follow the new
    // default (this project's weekly list) unless the user picked another URL.
    static constexpr const char* kOldDefaultList =
        "https://github.com/M-Abozaid/esp32-c3-adblock/releases/download/blocklist/blocklist.bin";
    if (strcmp(s_.blocklistUrl, kOldDefaultList) == 0 && strcmp(CONFIG_SINKHOLE_BLOCKLIST_URL, kOldDefaultList) != 0) {
        copyStr(s_.blocklistUrl, CONFIG_SINKHOLE_BLOCKLIST_URL);
        saveLocked();
    }
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
    return s_.adminIter == 0 && strcmp(s_.adminPass, CONFIG_SINKHOLE_ADMIN_PASSWORD) == 0;
}

esp_err_t Config::hashAdmin(Settings& s, const char* pass)
{
    uint8_t salt[sizeof(s.adminSalt)], hash[sizeof(s.adminHash)];
    esp_fill_random(salt, sizeof(salt));
    const int64_t t0 = esp_timer_get_time();
    if (pbkdf2(pass, salt, sizeof(salt), kAdminIter, hash) != ESP_OK) return ESP_FAIL;
    ESP_LOGI(TAG, "admin password hashed (%lu rounds, %d ms)", static_cast<unsigned long>(kAdminIter),
             static_cast<int>((esp_timer_get_time() - t0) / 1000));
    memcpy(s.adminSalt, salt, sizeof(salt));
    memcpy(s.adminHash, hash, sizeof(hash));
    s.adminIter = kAdminIter;
    return ESP_OK;
}

bool Config::checkAdmin(const char* user, const char* pass)
{
    char u[sizeof(Settings::adminUser)], plain[sizeof(Settings::adminPass)];
    uint8_t salt[sizeof(Settings::adminSalt)], hash[sizeof(Settings::adminHash)];
    uint32_t iter;
    {
        LockGuard g(mu_);
        memcpy(u, s_.adminUser, sizeof(u));
        memcpy(plain, s_.adminPass, sizeof(plain));
        memcpy(salt, s_.adminSalt, sizeof(salt));
        memcpy(hash, s_.adminHash, sizeof(hash));
        iter = s_.adminIter;
    }
    bool ok = sameText(user, u);
    if (iter == 0) {
        ok &= sameText(pass, plain);
    } else {
        uint8_t got[sizeof(hash)];
        ok &= pbkdf2(pass, salt, sizeof(salt), iter, got) == ESP_OK && sameBytes(got, hash, sizeof(hash));
        memset(got, 0, sizeof(got));
    }
    memset(plain, 0, sizeof(plain));
    return ok;
}

esp_err_t Config::setAdmin(const char* user, const char* pass)
{
    if (strcmp(pass, CONFIG_SINKHOLE_ADMIN_PASSWORD) == 0) {
        // Back to the published default: nothing to hide, and the UI keeps warning.
        LockGuard g(mu_);
        copyStr(s_.adminUser, user);
        copyStr(s_.adminPass, pass);
        s_.adminIter = 0;
        memset(s_.adminHash, 0, sizeof(s_.adminHash));
        return saveLocked();
    }
    static Settings next;  // httpd task only; keeps the slow PBKDF2 outside the lock
    applyDefaults(next);
    if (hashAdmin(next, pass) != ESP_OK) return ESP_FAIL;
    LockGuard g(mu_);
    copyStr(s_.adminUser, user);
    memcpy(s_.adminSalt, next.adminSalt, sizeof(s_.adminSalt));
    memcpy(s_.adminHash, next.adminHash, sizeof(s_.adminHash));
    s_.adminIter = next.adminIter;
    scrub(s_.adminPass);
    return saveLocked();
}

void Config::scrubLegacyAdminPassword()
{
    LockGuard g(mu_);
    if (s_.adminIter == 0 || s_.adminPass[0] == kScrubbed) return;
    scrub(s_.adminPass);
    if (saveLocked() == ESP_OK) ESP_LOGI(TAG, "plain admin password removed");
}

esp_err_t Config::saveLocked()
{
    esp_err_t err = nvs::saveBlob(kSettingsKey, &s_, sizeof(s_));
    if (err != ESP_OK) ESP_LOGE(TAG, "save failed: %s", esp_err_to_name(err));
    return err;
}

}  // namespace sinkhole
