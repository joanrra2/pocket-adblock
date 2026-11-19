#pragma once
// Persistent device settings (one versioned NVS blob) plus small NVS helpers
// other components use for their own fixed-size tables.

#include <cstddef>
#include <cstdint>

#include "esp_err.h"
#include "sinkhole/rtos.hpp"

namespace sinkhole {

enum class UpstreamMode : uint8_t { Builtin = 0, Router = 1, Custom = 2 };

struct Settings {
    uint16_t version;

    char hostname[32];

    // Station (uplink) Wi-Fi. Empty SSID = not provisioned yet.
    char staSsid[33];
    char staPass[65];

    // Device's own access point.
    char apSsid[33];  // empty = "Sinkhole-XXXX" from MAC
    char apPass[65];
    bool apAlways;    // false (default): AP only while no uplink is configured or connected

    // Web admin (HTTP Basic auth). From v15 the password lives in adminHash;
    // adminPass then only holds the default password (still unchanged) or,
    // for a few seconds after an upgrade, the old plain one (see v15 below).
    char adminUser[32];
    char adminPass[64];

    // DNS
    UpstreamMode upstreamMode;
    uint32_t upstreamIp;  // network byte order, used when Custom
    bool blocking;

    // Blocklist auto-update
    char blocklistUrl[256];
    uint16_t updateHours;  // 0 = off

    // MQTT bridge (remote Wake-on-LAN). Empty URI = disabled.
    char mqttUri[128];
    char mqttUser[64];
    char mqttPass[64];
    char mqttPrefix[48];

    // ---- v3 (append-only from here on: older blobs are migrated in place) ----
    bool staticIp;  // false = DHCP
    uint32_t ipAddr, ipMask, ipGw, ipDns;  // network byte order

    // ---- v4 ----
    uint8_t txPower;  // TxPower

    // ---- v5 ----
    uint32_t upstreamIp2;  // backup resolver raced against the primary, 0 = none

    // ---- v6 ----
    char fwManifestUrl[192];  // release manifest for firmware update checks, empty = off
    bool fwAuto;              // install updates automatically (signed builds only)

    // ---- v7 ----
    uint8_t bypassGuard;  // guard::kCanary | guard::kEncryptedDns

    // ---- v8 ----
    bool cnameCheck;  // block allowed names that are CNAMEs of blocked ones

    // ---- v9 ----
    bool haDiscovery;  // announce entities to Home Assistant over MQTT

    // ---- v10 ----
    uint8_t safeSearch;  // safe::kGoogle | kBing | kYoutubeModerate | kYoutubeStrict

    // ---- v11 ----
    bool dot;           // DNS over TLS upstream (CONFIG_SINKHOLE_DNS_OVER_TLS builds)
    char dotHost[64];   // e.g. dns.quad9.net

    // ---- v12 ----
    uint8_t ledKind;      // StatusLed::Kind: 0 off, 1 plain, 2 RGB (WS2812)
    int8_t ledPin;        // -1 = none
    bool ledActiveLow;
    uint8_t ledBrightness;  // RGB only, 1..255

    // ---- v13 ----
    uint8_t privacy;      // QueryLog::setPrivacy level
    uint16_t rateLimit;   // queries per minute per client, 0 = off

    // ---- v14 ----
    bool dhcpServer;                // hand out addresses on the home network (needs static IP)
    uint32_t dhcpFirst, dhcpLast;   // pool, network order
    uint16_t dhcpLeaseMinutes;

    // ---- v15 ----
    // Admin password as PBKDF2-HMAC-SHA256. adminIter 0 = not hashed: adminPass
    // holds the password (the built-in default, or settings from older firmware).
    // Once hashed, adminPass is overwritten with random bytes as soon as the
    // firmware is confirmed (kept until then, so a rollback can still log in).
    uint8_t adminHash[32];  // NOSONAR fixed blob layout stored in NVS
    uint8_t adminSalt[16];  // NOSONAR fixed blob layout stored in NVS
    uint32_t adminIter;
};

// Notifications (CONFIG_SINKHOLE_NOTIFY builds). Their own NVS blob ("notify"),
// not part of Settings: older firmware must always be able to read Settings,
// and it only keeps up to 256 bytes it doesn't know. Fields are only appended.
// Empty topic / token = that channel is off.
struct NotifySettings {
    uint16_t version;
    char ntfyServer[64];    // NOSONAR fixed blob layout stored in NVS; e.g. https://ntfy.sh
    char ntfyTopic[40];     // NOSONAR alerts here; commands read from <topic>-cmd
    char ntfyToken[64];     // NOSONAR optional access token (secret)
    char tgToken[64];       // NOSONAR Telegram bot token (secret)
    char tgChat[24];        // NOSONAR Telegram chat ID
    uint16_t notifyEvents;  // events::Kind bits
    bool notifyCommands;    // accept remote commands
};

enum TxPower : uint8_t { TxAuto = 0, TxFull = 1, TxReduced = 2 };

class Config {
public:
    // Bump when fields are appended to Settings, and add the previous version's
    // byte length to Config::validBytes() so stored settings migrate.
    static constexpr uint16_t kVersion = 15;

    esp_err_t load();  // defaults if missing / older version
    Settings get();    // copy, thread-safe (~1 KB: avoid on small stacks)

    // Read a few fields without copying the struct: cfg.read([](const Settings& s){ return s.apAlways; })
    template <typename F>
    auto read(F&& fn)
    {
        LockGuard g(mu_);
        return fn(static_cast<const Settings&>(s_));
    }

    // Apply a change and persist it: cfg.modify([](Settings& s){ ... });
    template <typename F>
    esp_err_t modify(F&& fn)
    {
        LockGuard g(mu_);
        fn(s_);
        return saveLocked();
    }

    // Notification settings, same pattern as read() / modify().
    template <typename F>
    auto readNotify(F&& fn)
    {
        LockGuard g(mu_);
        return fn(static_cast<const NotifySettings&>(n_));
    }
    template <typename F>
    esp_err_t modifyNotify(F&& fn)
    {
        LockGuard g(mu_);
        fn(n_);
        return saveNotifyLocked();
    }

    bool usingDefaultAdminPassword();

    // Admin credentials. checkAdmin is slow on purpose (PBKDF2, ~0.1-0.3 s):
    // callers cache a successful check.
    bool checkAdmin(const char* user, const char* pass);
    esp_err_t setAdmin(const char* user, const char* pass);
    // After a confirmed firmware: drop the plain copy an upgrade kept.
    void scrubLegacyAdminPassword();

    static void applyDefaults(Settings& s);
    // Stored blob (any known version) -> current Settings. False if unusable.
    // Older blobs get their plain admin password hashed (and kept, see v15).
    static bool upgrade(const uint8_t* raw, size_t len, Settings& out);
    // Hash pass into s (new random salt).
    static esp_err_t hashAdmin(Settings& s, const char* pass);

    static constexpr uint16_t kNotifyVersion = 2;  // 2: events::Watch exists (turned on when upgrading)
    static void applyNotifyDefaults(NotifySettings& n);
    // Stored / backed-up notification blob -> current layout. False if unusable.
    static bool upgradeNotify(const uint8_t* raw, size_t len, NotifySettings& out);

private:
    esp_err_t saveLocked();
    static size_t validBytes(uint16_t version);
    static esp_err_t loadOversized(uint8_t* raw, size_t cap, size_t& n);
    void loadNotifyLocked();
    esp_err_t saveNotifyLocked();

    Mutex mu_;
    Settings s_{};
    NotifySettings n_{};
};

// NVS helpers for fixed-size tables, all in the "sinkhole" namespace.
namespace nvs {
esp_err_t init();  // nvs_flash_init with erase-on-version-mismatch
esp_err_t loadBlob(const char* key, void* data, size_t len, size_t* outLen = nullptr);
esp_err_t saveBlob(const char* key, const void* data, size_t len);
size_t blobSize(const char* key);  // 0 if missing
esp_err_t eraseKey(const char* key);
esp_err_t loadU8(const char* key, uint8_t& out);
esp_err_t saveU8(const char* key, uint8_t v);
}  // namespace nvs

}  // namespace sinkhole
