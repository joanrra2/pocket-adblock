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

    // Web admin (HTTP Basic auth).
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
};

enum TxPower : uint8_t { TxAuto = 0, TxFull = 1, TxReduced = 2 };

class Config {
public:
    // Bump when fields are appended to Settings, and add the previous version's
    // byte length to Config::validBytes() so stored settings migrate.
    static constexpr uint16_t kVersion = 14;

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

    bool usingDefaultAdminPassword();

    static void applyDefaults(Settings& s);

private:
    esp_err_t saveLocked();
    static size_t validBytes(uint16_t version);

    Mutex mu_;
    Settings s_{};
};

// NVS helpers for fixed-size tables, all in the "sinkhole" namespace.
namespace nvs {
esp_err_t init();  // nvs_flash_init with erase-on-version-mismatch
esp_err_t loadBlob(const char* key, void* data, size_t len, size_t* outLen = nullptr);
esp_err_t saveBlob(const char* key, const void* data, size_t len);
size_t blobSize(const char* key);  // 0 if missing
esp_err_t loadU8(const char* key, uint8_t& out);
esp_err_t saveU8(const char* key, uint8_t v);
}  // namespace nvs

}  // namespace sinkhole
