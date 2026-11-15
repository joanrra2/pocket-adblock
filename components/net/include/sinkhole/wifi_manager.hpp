#pragma once
// Wi-Fi uplink (station) + setup access point.
//
// AP policy (default, Settings::apAlways = false):
//   - no uplink configured            -> AP on
//   - uplink configured, not connected -> AP on, station keeps retrying
//   - uplink connected                 -> AP off after a 30 s grace period
//   - BOOT button held 3 s             -> AP forced on for 15 minutes
// With apAlways = true the AP never turns off.
//
// Reconnect: retries forever with exponential backoff (1 s .. 60 s). While a
// phone/PC is on the setup AP, retries slow to every 60 s so the channel scans
// don't keep interrupting the setup session.

#include <atomic>
#include <cstdint>

#include "esp_err.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_wifi_types.h"
#include "sinkhole/config.hpp"
#include "sinkhole/rtos.hpp"

namespace sinkhole {

enum class LinkState : uint8_t { NotConfigured, Connecting, Connected, Failed };

struct WifiStatus {
    LinkState state;
    uint8_t lastReason;   // wifi_err_reason_t of the last disconnect, 0 = none
    uint32_t attempts;    // failed attempts since the last success
    uint32_t nextRetryS;  // seconds until the next automatic retry (Failed only)
    bool apOn;
    uint8_t apClients;
    uint32_t apForcedForS;
};

struct ScanResult {
    char ssid[33];
    int8_t rssi;
    uint8_t channel;
    uint8_t authmode;  // wifi_auth_mode_t
};

class WifiManager {
public:
    static constexpr size_t kMaxScanResults = 24;

    // connected = true on got-IP, false when the uplink is lost.
    using Listener = void (*)(void* ctx, bool connected);

    explicit WifiManager(Config& cfg) : cfg_(cfg) {}

    esp_err_t begin();
    void setListener(Listener fn, void* ctx) { listener_ = fn; listenerCtx_ = ctx; }

    esp_err_t setStation(const char* ssid, const char* pass);  // save + connect
    esp_err_t forgetStation();                                 // clear creds, AP on
    void reconnect();                                          // retry now
    void reconfigureStation();                                 // creds/IP changed: apply + reconnect (deferred)
    void applyTxPower();                                       // after Settings::txPower changes
    float txPowerDbm() const;
    bool txReduced() const { return lowTx_; }
    esp_err_t applyAccessPoint();                              // after AP settings change
    void forceAp(uint32_t minutes);                            // BOOT button

    // Blocking scan (~2 s). One network per SSID (strongest), strongest first,
    // hidden networks skipped. Pauses uplink retries while it runs.
    esp_err_t scan(ScanResult* out, size_t max, size_t& count);
    static const char* authText(uint8_t authmode);

    WifiStatus status() const;
    bool connected() const { return connected_; }
    uint32_t staIp() const { return staIp_; }  // network order, 0 if none
    uint32_t staNetmask() const { return staMask_; }
    uint32_t staDns() const;                   // DHCP-provided DNS, 0 if none
    uint32_t gateway() const { return gateway_; }
    esp_netif_t* staNetif() const { return sta_; }
    uint32_t apIp() const;
    // IPv6 addresses of the uplink as text; hasGlobal = the network routes IPv6.
    size_t ip6Addresses(char out[][46], size_t max, bool* hasGlobal) const;
    uint32_t apNetmask() const;
    int rssi() const;
    void apSsid(char out[33]) const;

    static const char* reasonText(uint8_t reason);
    static const char* stateText(LinkState s);

private:
    static void onEvent(void* arg, esp_event_base_t base, int32_t id, void* data);
    static void onRetryTimer(void* arg);
    static void onApTimer(void* arg);
    static void onIpTimer(void* arg);
    void handleEvent(esp_event_base_t base, int32_t id, void* data);
    void configureAp();
    void applyStaConfig(const char* ssid, const char* pass);
    void applyIpConfig();
    void scheduleRetry();
    void connectSoon();
    bool apWanted();
    void updateAp();
    void setApEnabled(bool on);

    Config& cfg_;
    esp_netif_t* sta_ = nullptr;
    esp_netif_t* ap_ = nullptr;
    esp_timer_handle_t retryTimer_ = nullptr;
    esp_timer_handle_t apTimer_ = nullptr;
    esp_timer_handle_t ipTimer_ = nullptr;
    Listener listener_ = nullptr;
    void* listenerCtx_ = nullptr;

    std::atomic<bool> connected_{false};  // link up AND address assigned
    std::atomic<bool> linkUp_{false};     // associated with the uplink AP
    std::atomic<bool> configured_{false};
    std::atomic<bool> selfDisconnect_{false};
    std::atomic<bool> scanning_{false};
    std::atomic<bool> lowTx_{false};  // Auto mode currently at reduced power
    Mutex scanMu_;
    wifi_ap_record_t raw_[32];  // driver scan records, only touched under scanMu_
    std::atomic<bool> apOn_{true};
    std::atomic<uint8_t> apClients_{0};
    std::atomic<uint8_t> lastReason_{0};
    std::atomic<uint32_t> attempts_{0};
    std::atomic<uint32_t> staIp_{0};
    std::atomic<uint32_t> staMask_{0};
    std::atomic<uint32_t> gateway_{0};
    std::atomic<uint32_t> forcedUntil_{0};  // uptime seconds
    std::atomic<uint32_t> retryAt_{0};      // uptime seconds
    uint32_t retryDelayMs_ = 1000;
};

class Mdns {
public:
    static esp_err_t begin(const char* hostname);
};

}  // namespace sinkhole
