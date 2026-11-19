#include "sinkhole/config.hpp"

#include <array>
#include <cstddef>
#include <cstring>
#include <memory>
#include <new>

#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "lwip/inet.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "psa/crypto.h"
#include "sdkconfig.h"
#include "sinkhole/events.hpp"
#include "sinkhole/secret.hpp"
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
constexpr char kScrubbed = 0x7f;  // first byte of a cleared adminPass (DEL: never typed)
constexpr size_t kPassMax = sizeof(Settings::adminPass);

using Hash = std::array<uint8_t, sizeof(Settings::adminHash)>;
using Salt = std::array<uint8_t, sizeof(Settings::adminSalt)>;

esp_err_t pbkdf2(const char* pass, const Salt& salt, uint32_t iter, Hash& out)
{
    psa_crypto_init();  // idempotent
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_status_t st = psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
    if (st == PSA_SUCCESS) st = psa_key_derivation_input_integer(&op, PSA_KEY_DERIVATION_INPUT_COST, iter);
    if (st == PSA_SUCCESS)
        st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, salt.data(), salt.size());
    if (st == PSA_SUCCESS)
        st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD,
                                            reinterpret_cast<const uint8_t*>(pass), strnlen(pass, kPassMax));
    if (st == PSA_SUCCESS) st = psa_key_derivation_output_bytes(&op, out.data(), out.size());
    psa_key_derivation_abort(&op);
    if (st != PSA_SUCCESS) ESP_LOGE(TAG, "PBKDF2 failed (%d)", static_cast<int>(st));
    return st == PSA_SUCCESS ? ESP_OK : ESP_FAIL;
}

// Overwrite adminPass with random letters behind kScrubbed: older firmware
// (rollback or manual downgrade) then matches no password at all.
void scrub(char (&pass)[kPassMax])
{
    std::array<uint8_t, 16> rnd;
    esp_fill_random(rnd.data(), rnd.size());
    secureWipe(pass, sizeof(pass));
    pass[0] = kScrubbed;
    for (size_t i = 0; i < rnd.size(); i++) pass[i + 1] = static_cast<char>('a' + rnd[i] % 26);
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

void Config::applyNotifyDefaults(NotifySettings& n)
{
    memset(&n, 0, sizeof(n));
    n.version = kNotifyVersion;
    copyStr(n.ntfyServer, "https://ntfy.sh");
    // Host online/offline is opt-in: a wake already reports when the PC answers.
    n.notifyEvents = events::kAllKinds & ~events::HostState;
}

bool Config::upgradeNotify(const uint8_t* raw, size_t len, NotifySettings& out)
{
    applyNotifyDefaults(out);
    uint16_t version = 0;
    if (len < sizeof(version)) return false;
    memcpy(&version, raw, sizeof(version));
    if (version == 0 || version >= 1000) return false;
    // Version 1 is the first layout; a newer one only appended fields.
    memcpy(&out, raw, len < sizeof(out) ? len : sizeof(out));
    // Alerts for watched hosts came with version 2: on unless turned off since.
    if (version < 2) out.notifyEvents |= events::Watch;
    out.version = kNotifyVersion;
    out.ntfyServer[sizeof(out.ntfyServer) - 1] = '\0';
    out.ntfyTopic[sizeof(out.ntfyTopic) - 1] = '\0';
    out.ntfyToken[sizeof(out.ntfyToken) - 1] = '\0';
    out.tgToken[sizeof(out.tgToken) - 1] = '\0';
    out.tgChat[sizeof(out.tgChat) - 1] = '\0';
    return true;
}

void Config::loadNotifyLocked()
{
    static constexpr const char* kKey = "notify";
    // Room for fields a newer firmware appended (a bigger blob is not read,
    // and stays stored until the notification settings are changed here).
    std::array<uint8_t, sizeof(NotifySettings) + 256> raw{};  // ~0.5 KB, boot only
    size_t got = 0;
    if (nvs::loadBlob(kKey, raw.data(), raw.size(), &got) != ESP_OK || !upgradeNotify(raw.data(), got, n_))
        applyNotifyDefaults(n_);  // nothing stored yet: saved on the first change
    secureWipe(raw.data(), raw.size());  // tokens
}

esp_err_t Config::saveNotifyLocked()
{
    return nvs::saveBlob("notify", &n_, sizeof(n_));
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
    out.fwManifestUrl[sizeof(out.fwManifestUrl) - 1] = '\0';
    // Older firmware kept the admin password in plain text: hash it. The plain
    // copy stays until the firmware is confirmed (scrubLegacyAdminPassword), so
    // a rollback to the previous image still accepts it. The default password
    // and an empty one (a backup without passwords) stay as they are.
    if (stored.version < 15 && out.adminPass[0] && strcmp(out.adminPass, CONFIG_SINKHOLE_ADMIN_PASSWORD) != 0)
        hashAdmin(out, out.adminPass);
    return true;
}

// A blob from a much newer firmware (downgrade): read it whole from the heap and
// keep the prefix this version knows. Fields are only ever appended.
esp_err_t Config::loadOversized(uint8_t* raw, size_t cap, size_t& n)
{
    n = 0;
    const size_t full = nvs::blobSize(kSettingsKey);
    if (full <= cap || full > 16 * 1024) return ESP_ERR_NVS_INVALID_LENGTH;
    // Not std::vector: on the 4 MB boards every KB of flash counts.
    std::unique_ptr<uint8_t[]> big(new (std::nothrow) uint8_t[full]);  // NOSONAR owned by unique_ptr; nothrow, no exceptions here
    if (!big) return ESP_ERR_NO_MEM;
    size_t got = 0;
    const esp_err_t err = nvs::loadBlob(kSettingsKey, big.get(), full, &got);
    if (err == ESP_OK) {
        memcpy(raw, big.get(), cap);
        n = cap;
    }
    secureWipe(big.get(), full);  // passwords
    if (err != ESP_OK) return err;
    return ESP_OK;
}

namespace {
// Stored-settings buffer for load() and revertLocked(), only used under mu_
// (keeps ~1.5 KB off the stack). Room for fields a newer firmware appended,
// so a rollback keeps the settings.
std::array<uint8_t, sizeof(Settings) + 256> gRaw;  // NOSONAR a scratch buffer, written on every load: const is not possible
}  // namespace

esp_err_t Config::load()
{
    LockGuard g(mu_);
    loadNotifyLocked();
    uint8_t* raw = gRaw.data();
    memset(raw, 0, sizeof(gRaw));
    size_t n = 0;
    esp_err_t err = nvs::loadBlob(kSettingsKey, raw, sizeof(gRaw), &n);
    if (err == ESP_ERR_NVS_INVALID_LENGTH) err = loadOversized(raw, sizeof(gRaw), n);
    uint16_t version = 0;
    if (n >= sizeof(version)) memcpy(&version, raw, sizeof(version));
    if (err != ESP_OK || !upgrade(raw, n, s_)) {
        ESP_LOGW(TAG, "no usable stored settings (%s), using defaults", esp_err_to_name(err));
        // Only a missing blob is replaced. One this build cannot read stays as
        // it is until settings are changed here, so flashing the newer firmware
        // back still finds it.
        return err == ESP_ERR_NVS_NOT_FOUND ? saveLocked() : ESP_OK;
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
    Salt salt;
    Hash hash;
    esp_fill_random(salt.data(), salt.size());
    const int64_t t0 = esp_timer_get_time();
    if (pbkdf2(pass, salt, kAdminIter, hash) != ESP_OK) return ESP_FAIL;
    ESP_LOGI(TAG, "admin password hashed (%lu rounds, %d ms)", static_cast<unsigned long>(kAdminIter),
             static_cast<int>((esp_timer_get_time() - t0) / 1000));
    memcpy(s.adminSalt, salt.data(), salt.size());
    memcpy(s.adminHash, hash.data(), hash.size());
    s.adminIter = kAdminIter;
    return ESP_OK;
}

bool Config::checkAdmin(const char* user, const char* pass)
{
    // Copies, so the slow PBKDF2 runs outside the lock.
    struct Stored {
        char user[sizeof(Settings::adminUser)];
        char plain[sizeof(Settings::adminPass)];
        Salt salt;
        Hash hash;
        uint32_t iter;
    };
    static Stored c;  // httpd task only
    {
        LockGuard g(mu_);
        memcpy(c.user, s_.adminUser, sizeof(c.user));
        memcpy(c.plain, s_.adminPass, sizeof(c.plain));
        memcpy(c.salt.data(), s_.adminSalt, c.salt.size());
        memcpy(c.hash.data(), s_.adminHash, c.hash.size());
        c.iter = s_.adminIter;
    }
    bool ok = sameText(user, c.user, sizeof(c.user));
    if (c.iter == 0) {
        ok &= sameText(pass, c.plain, sizeof(c.plain));
    } else {
        Hash got;
        ok &= pbkdf2(pass, c.salt, c.iter, got) == ESP_OK && sameBytes(got.data(), c.hash.data(), got.size());
        secureWipe(got.data(), got.size());
    }
    secureWipe(&c, sizeof(c));
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
        secureWipe(s_.adminHash, sizeof(s_.adminHash));
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

// A save failed (flash full or worn): put RAM back to the stored settings.
// If they can't be read either, RAM keeps the change until the restart.
void Config::revertLocked()
{
    size_t n = 0;
    uint16_t version = 0;
    if (nvs::loadBlob(kSettingsKey, gRaw.data(), gRaw.size(), &n) == ESP_OK && n >= sizeof(version)) {
        memcpy(&version, gRaw.data(), sizeof(version));
        const size_t valid = validBytes(version);
        // Checked first: upgrade() resets its output to defaults on a bad blob.
        if (valid && n >= valid && upgrade(gRaw.data(), n, s_))
            ESP_LOGW(TAG, "change not saved; kept the stored settings");
    }
    secureWipe(gRaw.data(), gRaw.size());  // passwords
}

esp_err_t Config::saveLocked()
{
    esp_err_t err = nvs::saveBlob(kSettingsKey, &s_, sizeof(s_));
    if (err != ESP_OK) ESP_LOGE(TAG, "save failed: %s", esp_err_to_name(err));
    return err;
}

}  // namespace sinkhole
