#include "sinkhole/wifi_manager.hpp"

#include <cstdio>
#include <cstring>

#include "esp_log.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "lwip/sockets.h"
#include "mdns.h"
#include "sdkconfig.h"
#include "sinkhole/rtos.hpp"
#include "sinkhole/text.hpp"

namespace sinkhole {

namespace {
constexpr const char* TAG = "wifi";
constexpr uint32_t kMaxRetryMs = 60 * 1000;
constexpr uint32_t kRetryWithApClientsMs = 60 * 1000;
constexpr uint64_t kApGraceUs = 30ULL * 1000 * 1000;
constexpr uint8_t kDhcpsOfferDns = 0x02;  // OFFER_DNS in lwIP's dhcpserver
constexpr int8_t kFullTxQdbm = 80;      // 20 dBm (the driver clamps to the chip maximum)
constexpr int8_t kReducedTxQdbm = 34;   // 8.5 dBm
constexpr uint32_t kTxToggleAfter = 3;  // failed attempts before switching level
constexpr const char* kLowTxKey = "lowtx";
}  // namespace

// ------------------------------------------------------------------ setup

esp_err_t WifiManager::begin()
{
    sta_ = esp_netif_create_default_wifi_sta();
    ap_ = esp_netif_create_default_wifi_ap();

    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    esp_err_t err = esp_wifi_init(&init);
    if (err != ESP_OK) return err;
    esp_wifi_set_storage(WIFI_STORAGE_RAM);  // credentials live in our Settings blob

    esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &WifiManager::onEvent, this);
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &WifiManager::onEvent, this);
    esp_event_handler_register(IP_EVENT, IP_EVENT_GOT_IP6, &WifiManager::onEvent, this);

    esp_timer_create_args_t retry{};
    retry.callback = &WifiManager::onRetryTimer;
    retry.arg = this;
    retry.name = "wifi_retry";
    esp_timer_create(&retry, &retryTimer_);

    esp_timer_create_args_t apT{};
    apT.callback = &WifiManager::onApTimer;
    apT.arg = this;
    apT.name = "ap_policy";
    esp_timer_create(&apT, &apTimer_);

    esp_timer_create_args_t ipT{};
    ipT.callback = &WifiManager::onIpTimer;
    ipT.arg = this;
    ipT.name = "ip_apply";
    esp_timer_create(&ipT, &ipTimer_);

    const Settings s = cfg_.get();
    configured_ = s.staSsid[0] != '\0';
    esp_wifi_set_mode(WIFI_MODE_APSTA);  // AP starts on; policy may turn it off later
    configureAp();
    applyStaConfig(s.staSsid, s.staPass);
    applyIpConfig();

    err = esp_wifi_start();
    if (err != ESP_OK) return err;

    // Latency: modem sleep parks the radio between beacons and can add ~100 ms
    // to every reply. A DNS server is mains-powered, so keep the radio awake.
    esp_wifi_set_ps(WIFI_PS_NONE);

    uint8_t low = 0;
    nvs::loadU8(kLowTxKey, low);  // the level that last worked (Auto mode)
    lowTx_ = low != 0;
    applyTxPower();

    char ssid[33];
    apSsid(ssid);
    ESP_LOGI(TAG, "setup AP \"%s\" at 192.168.4.1; uplink %s", ssid,
             configured_ ? s.staSsid : "(not configured)");
    return ESP_OK;
}

// ------------------------------------------------------------------ TX power

void WifiManager::applyTxPower()
{
#if CONFIG_SINKHOLE_WIFI_MAX_TX_POWER > 0
    esp_wifi_set_max_tx_power(CONFIG_SINKHOLE_WIFI_MAX_TX_POWER);  // pinned at build time
#else
    const uint8_t mode = cfg_.read([](const Settings& s) { return s.txPower; });
    const bool low = mode == TxReduced || (mode == TxAuto && lowTx_);
    esp_wifi_set_max_tx_power(low ? kReducedTxQdbm : kFullTxQdbm);
#endif
}

float WifiManager::txPowerDbm() const
{
    int8_t q = 0;
    return esp_wifi_get_max_tx_power(&q) == ESP_OK ? q / 4.0f : 0.0f;
}

void WifiManager::configureAp()
{
    char cfgSsid[33], cfgPass[65];
    cfg_.read([&](const Settings& s) {
        copyStr(cfgSsid, s.apSsid);
        copyStr(cfgPass, s.apPass);
        return 0;
    });
    wifi_config_t ap{};
    char ssid[33];
    if (cfgSsid[0]) {
        copyStr(ssid, cfgSsid);
    } else {
        uint8_t mac[6];
        esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);
        snprintf(ssid, sizeof(ssid), "Sinkhole-%02X%02X", mac[4], mac[5]);
    }
    copyStr(reinterpret_cast<char*>(ap.ap.ssid), sizeof(ap.ap.ssid), ssid);
    ap.ap.ssid_len = static_cast<uint8_t>(strlen(ssid));

    const char* pass = strlen(cfgPass) >= 8 ? cfgPass : CONFIG_SINKHOLE_AP_PASSWORD;
    copyStr(reinterpret_cast<char*>(ap.ap.password), sizeof(ap.ap.password), pass);
    ap.ap.authmode = WIFI_AUTH_WPA2_PSK;
    ap.ap.max_connection = 4;
    ap.ap.pmf_cfg.capable = true;
    esp_wifi_set_config(WIFI_IF_AP, &ap);

    // Hand out our own address as DNS to AP clients (filtering + captive portal).
    esp_netif_ip_info_t info{};
    if (esp_netif_get_ip_info(ap_, &info) == ESP_OK) {
        esp_netif_dhcps_stop(ap_);
        uint8_t offer = kDhcpsOfferDns;
        esp_netif_dhcps_option(ap_, ESP_NETIF_OP_SET, ESP_NETIF_DOMAIN_NAME_SERVER, &offer,
                               sizeof(offer));
        esp_netif_dns_info_t dns{};
        dns.ip.type = ESP_IPADDR_TYPE_V4;
        dns.ip.u_addr.ip4.addr = info.ip.addr;
        esp_netif_set_dns_info(ap_, ESP_NETIF_DNS_MAIN, &dns);
        esp_netif_dhcps_start(ap_);
    }
}

void WifiManager::applyStaConfig(const char* ssid, const char* pass)
{
    wifi_config_t sta{};
    copyStr(reinterpret_cast<char*>(sta.sta.ssid), sizeof(sta.sta.ssid), ssid);
    copyStr(reinterpret_cast<char*>(sta.sta.password), sizeof(sta.sta.password), pass);
    sta.sta.threshold.authmode = pass[0] ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
    sta.sta.pmf_cfg.capable = true;
    sta.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;  // strongest AP of a mesh, not the first seen
    sta.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;
    esp_wifi_set_config(WIFI_IF_STA, &sta);
}

// Static IP: stop the DHCP client and set the address before (re)connecting;
// esp_netif then reports IP_EVENT_STA_GOT_IP on link-up as usual.
void WifiManager::applyIpConfig()
{
    struct {
        bool staticIp;
        uint32_t ipAddr, ipMask, ipGw, ipDns;
    } s;
    cfg_.read([&](const Settings& c) {
        s = {c.staticIp, c.ipAddr, c.ipMask, c.ipGw, c.ipDns};
        return 0;
    });
    if (s.staticIp && s.ipAddr && s.ipMask) {
        esp_netif_dhcpc_stop(sta_);
        esp_netif_ip_info_t info{};
        info.ip.addr = s.ipAddr;
        info.netmask.addr = s.ipMask;
        info.gw.addr = s.ipGw;
        esp_netif_set_ip_info(sta_, &info);
        if (s.ipDns) {
            esp_netif_dns_info_t dns{};
            dns.ip.type = ESP_IPADDR_TYPE_V4;
            dns.ip.u_addr.ip4.addr = s.ipDns;
            esp_netif_set_dns_info(sta_, ESP_NETIF_DNS_MAIN, &dns);
        }
        char ip[16];
        formatIp4(s.ipAddr, ip);
        ESP_LOGI(TAG, "static IP %s", ip);
    } else {
        esp_netif_dhcpc_start(sta_);  // no-op error if already running
    }
}

// Re-applies credentials + IP settings and reconnects. Deferred by 500 ms so the
// HTTP reply that triggered it still goes out before the link drops.
void WifiManager::reconfigureStation()
{
    esp_timer_stop(ipTimer_);
    esp_timer_start_once(ipTimer_, 500 * 1000);
}

void WifiManager::onIpTimer(void* arg)
{
    auto* self = static_cast<WifiManager*>(arg);
    char ssid[33], pass[65];
    self->cfg_.read([&](const Settings& s) {
        copyStr(ssid, s.staSsid);
        copyStr(pass, s.staPass);
        return 0;
    });
    self->selfDisconnect_ = self->connected_.load();
    esp_wifi_disconnect();
    self->applyStaConfig(ssid, pass);
    self->applyIpConfig();
    if (self->configured_) self->connectSoon();
}

// ------------------------------------------------------------------ AP policy

bool WifiManager::apWanted()
{
    if (!configured_ || !connected_) return true;
    if (uptimeSeconds() < forcedUntil_) return true;
    return cfg_.read([](const Settings& s) { return s.apAlways; });
}

void WifiManager::updateAp()
{
    esp_timer_stop(apTimer_);
    if (apWanted()) {
        setApEnabled(true);
        // Re-check when a forced period ends.
        const uint32_t now = uptimeSeconds();
        if (forcedUntil_ > now)
            esp_timer_start_once(apTimer_, static_cast<uint64_t>(forcedUntil_ - now) * 1000000ULL);
    } else if (apOn_) {
        esp_timer_start_once(apTimer_, kApGraceUs);  // let a setup phone see the result
    }
}

void WifiManager::onApTimer(void* arg)
{
    auto* self = static_cast<WifiManager*>(arg);
    if (!self->apWanted())
        self->setApEnabled(false);
    else
        self->updateAp();
}

void WifiManager::setApEnabled(bool on)
{
    if (apOn_ == on) return;
    apOn_ = on;
    if (!on) apClients_ = 0;
    esp_wifi_set_mode(on ? WIFI_MODE_APSTA : WIFI_MODE_STA);
    if (on) configureAp();
    ESP_LOGI(TAG, "setup AP %s", on ? "on" : "off");
}

esp_err_t WifiManager::applyAccessPoint()
{
    configureAp();
    updateAp();
    return ESP_OK;
}

void WifiManager::forceAp(uint32_t minutes)
{
    forcedUntil_ = uptimeSeconds() + minutes * 60;
    ESP_LOGW(TAG, "setup AP forced on for %lu min", static_cast<unsigned long>(minutes));
    updateAp();
}

// ------------------------------------------------------------------ station control

esp_err_t WifiManager::setStation(const char* ssid, const char* pass)
{
    esp_err_t err = cfg_.modify([&](Settings& s) {
        copyStr(s.staSsid, ssid);
        copyStr(s.staPass, pass);
    });
    if (err != ESP_OK) return err;
    configured_ = ssid[0] != '\0';
    attempts_ = 0;
    lastReason_ = 0;
    ESP_LOGI(TAG, "uplink set to \"%s\", connecting", ssid);
    reconfigureStation();  // deferred, so the HTTP reply still goes out
    return ESP_OK;
}

// First attempt goes through the retry timer: it runs after the driver has
// processed our disconnect, and a pending timer stops the disconnect event
// from scheduling a second (later) attempt.
void WifiManager::connectSoon()
{
    retryDelayMs_ = 1000;
    esp_timer_stop(retryTimer_);
    esp_timer_start_once(retryTimer_, 300 * 1000);
    retryAt_ = uptimeSeconds();
}

esp_err_t WifiManager::forgetStation()
{
    esp_err_t err = cfg_.modify([](Settings& s) {
        s.staSsid[0] = '\0';
        s.staPass[0] = '\0';
    });
    configured_ = false;
    attempts_ = 0;
    lastReason_ = 0;
    retryAt_ = 0;
    esp_timer_stop(retryTimer_);
    esp_wifi_disconnect();  // configured_ is false, so the event is ignored
    applyStaConfig("", "");
    updateAp();
    ESP_LOGI(TAG, "uplink forgotten");
    return err;
}

void WifiManager::reconnect()
{
    if (!configured_) return;
    if (connected_) {
        selfDisconnect_ = true;
        esp_wifi_disconnect();
    }
    connectSoon();
}

void WifiManager::scheduleRetry()
{
    uint32_t delay = retryDelayMs_;
    if (apClients_ > 0 && delay < kRetryWithApClientsMs) delay = kRetryWithApClientsMs;
    esp_timer_stop(retryTimer_);
    esp_timer_start_once(retryTimer_, static_cast<uint64_t>(delay) * 1000);
    retryAt_ = uptimeSeconds() + delay / 1000;
    retryDelayMs_ = retryDelayMs_ * 2 > kMaxRetryMs ? kMaxRetryMs : retryDelayMs_ * 2;
}

void WifiManager::onRetryTimer(void* arg)
{
    auto* self = static_cast<WifiManager*>(arg);
    self->retryAt_ = 0;
    if (self->scanning_) return;  // scan() restarts the attempt when it finishes
    if (self->configured_ && !self->connected_) esp_wifi_connect();
}

// ------------------------------------------------------------------ scan

esp_err_t WifiManager::scan(ScanResult* out, size_t max, size_t& count)
{
    count = 0;
    LockGuard g(scanMu_);
    scanning_ = true;

    wifi_scan_config_t sc{};
    sc.show_hidden = false;
    sc.scan_type = WIFI_SCAN_TYPE_ACTIVE;
    sc.scan_time.active.min = 60;
    sc.scan_time.active.max = 120;
    sc.home_chan_dwell_time = 30;  // hop back so AP clients / the uplink don't drop

    esp_err_t err = esp_wifi_scan_start(&sc, true);
    if (err == ESP_ERR_WIFI_STATE) {
        // An uplink attempt is in progress: abort it, scan, then resume.
        esp_timer_stop(retryTimer_);
        esp_wifi_disconnect();  // reported as ASSOC_LEAVE, not counted as a failure
        vTaskDelay(pdMS_TO_TICKS(300));
        err = esp_wifi_scan_start(&sc, true);
    }

    uint16_t n = sizeof(raw_) / sizeof(raw_[0]);
    if (err == ESP_OK) err = esp_wifi_scan_get_ap_records(&n, raw_);
    esp_wifi_clear_ap_list();  // frees whatever didn't fit in raw_
    scanning_ = false;
    if (configured_ && !connected_) connectSoon();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "scan failed: %s", esp_err_to_name(err));
        return err;
    }

    for (uint16_t i = 0; i < n; i++) {
        const wifi_ap_record_t& r = raw_[i];
        const char* ssid = reinterpret_cast<const char*>(r.ssid);
        if (!ssid[0]) continue;
        size_t j = 0;
        while (j < count && strcmp(out[j].ssid, ssid) != 0) j++;
        if (j < count) {  // same network seen from another AP (mesh/repeater)
            if (r.rssi > out[j].rssi) {
                out[j].rssi = r.rssi;
                out[j].channel = r.primary;
            }
            continue;
        }
        if (count >= max) continue;
        copyStr(out[count].ssid, sizeof(out[count].ssid), ssid);
        out[count].rssi = r.rssi;
        out[count].channel = r.primary;
        out[count].authmode = static_cast<uint8_t>(r.authmode);
        count++;
    }
    // Strongest first (insertion sort, n <= 24).
    for (size_t i = 1; i < count; i++) {
        ScanResult v = out[i];
        size_t j = i;
        for (; j > 0 && out[j - 1].rssi < v.rssi; j--) out[j] = out[j - 1];
        out[j] = v;
    }
    return ESP_OK;
}

const char* WifiManager::authText(uint8_t a)
{
    switch (static_cast<wifi_auth_mode_t>(a)) {
        case WIFI_AUTH_OPEN: return "open";
        case WIFI_AUTH_WEP: return "WEP";
        case WIFI_AUTH_WPA_PSK: return "WPA";
        case WIFI_AUTH_WPA2_PSK: return "WPA2";
        case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
        case WIFI_AUTH_WPA3_PSK: return "WPA3";
        case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3";
        case WIFI_AUTH_WPA2_ENTERPRISE:
        case WIFI_AUTH_WPA3_ENTERPRISE: return "enterprise";
        default: return "secured";
    }
}

// ------------------------------------------------------------------ events

void WifiManager::onEvent(void* arg, esp_event_base_t base, int32_t id, void* data)
{
    static_cast<WifiManager*>(arg)->handleEvent(base, id, data);
}

void WifiManager::handleEvent(esp_event_base_t base, int32_t id, void* data)
{
    if (base == WIFI_EVENT) {
        switch (id) {
            case WIFI_EVENT_STA_START:
                if (configured_) esp_wifi_connect();
                break;
            case WIFI_EVENT_STA_CONNECTED:
                linkUp_ = true;
                // IPv6: link-local now; SLAAC adds a global address if the router
                // advertises a prefix (CONFIG_LWIP_IPV6_AUTOCONFIG).
                esp_netif_create_ip6_linklocal(sta_);
                break;
            case WIFI_EVENT_STA_DISCONNECTED: {
                auto* ev = static_cast<wifi_event_sta_disconnected_t*>(data);
                linkUp_ = false;
                const bool was = connected_;
                connected_ = false;
                staIp_ = 0;
                // Disconnects we caused ourselves (new credentials, forget, reconnect)
                // are not failures: keep the retry, skip the error bookkeeping.
                // ASSOC_LEAVE while not connected = we aborted an attempt in progress.
                const bool self = selfDisconnect_.exchange(false) ||
                                  (!was && ev && ev->reason == WIFI_REASON_ASSOC_LEAVE);
                if (configured_ && !self) {
                    lastReason_ = ev ? ev->reason : 0;
                    attempts_++;
                    if (was || attempts_ == 1 || attempts_ % 10 == 0)
                        ESP_LOGW(TAG, "uplink %s: %s (reason %u, attempt %lu)", was ? "lost" : "failed",
                                 reasonText(lastReason_), lastReason_.load(),
                                 static_cast<unsigned long>(attempts_));
#if CONFIG_SINKHOLE_WIFI_MAX_TX_POWER == 0
                    // Auto TX power: some boards (C3 SuperMini) can't hold a link at
                    // full power. Every few failures, try the other level.
                    if (attempts_ % kTxToggleAfter == 0 &&
                        cfg_.read([](const Settings& s) { return s.txPower; }) == TxAuto) {
                        lowTx_ = !lowTx_;
                        applyTxPower();
                        ESP_LOGW(TAG, "auto TX power: trying %s", lowTx_ ? "reduced (8.5 dBm)" : "full");
                    }
#endif
                }
                // A pending timer means an attempt is already on its way (connectSoon);
        // during a scan, scan() restarts the attempt itself.
        if (configured_ && !scanning_ && !esp_timer_is_active(retryTimer_)) scheduleRetry();
                updateAp();  // never leave the device unreachable
                if (was && listener_) listener_(listenerCtx_, false);
                break;
            }
            case WIFI_EVENT_AP_STACONNECTED:
                apClients_++;
                // Someone is setting the device up: push a pending fast uplink retry
                // out to 60 s, its channel scan would interrupt them right away.
                if (configured_ && !connected_ && esp_timer_is_active(retryTimer_) &&
                    retryAt_ < uptimeSeconds() + kRetryWithApClientsMs / 1000) {
                    esp_timer_stop(retryTimer_);
                    esp_timer_start_once(retryTimer_, static_cast<uint64_t>(kRetryWithApClientsMs) * 1000);
                    retryAt_ = uptimeSeconds() + kRetryWithApClientsMs / 1000;
                }
                break;
            case WIFI_EVENT_AP_STADISCONNECTED:
                if (apClients_) apClients_--;
                break;
            default:
                break;
        }
    } else if (base == IP_EVENT && id == IP_EVENT_GOT_IP6) {
        auto* ev = static_cast<ip_event_got_ip6_t*>(data);
        char a[46];
        inet_ntop(AF_INET6, ev->ip6_info.ip.addr, a, sizeof(a));
        ESP_LOGI(TAG, "IPv6 address %s", a);
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        // Setting a static IP raises GOT_IP immediately, even with the radio
        // link down. Only an address on a live link counts as "connected".
        if (!linkUp_) {
            ESP_LOGD(TAG, "ignoring GOT_IP without link");
            return;
        }
        auto* ev = static_cast<ip_event_got_ip_t*>(data);
        staIp_ = ev->ip_info.ip.addr;
        staMask_ = ev->ip_info.netmask.addr;
        gateway_ = ev->ip_info.gw.addr;
        connected_ = true;
        attempts_ = 0;
        lastReason_ = 0;
        retryAt_ = 0;
        retryDelayMs_ = 1000;
        char ip[16];
        formatIp4(staIp_, ip);
        ESP_LOGI(TAG, "uplink up, ip %s, tx %.1f dBm", ip, txPowerDbm());
        // Remember which level worked so the next boot starts there.
        uint8_t stored = 0;
        nvs::loadU8(kLowTxKey, stored);
        if ((stored != 0) != lowTx_) nvs::saveU8(kLowTxKey, lowTx_ ? 1 : 0);
        updateAp();
        if (listener_) listener_(listenerCtx_, true);
    }
}

// ------------------------------------------------------------------ status

WifiStatus WifiManager::status() const
{
    WifiStatus s{};
    s.state = !configured_ ? LinkState::NotConfigured
              : connected_ ? LinkState::Connected
              : attempts_  ? LinkState::Failed
                           : LinkState::Connecting;
    s.lastReason = lastReason_;
    s.attempts = attempts_;
    const uint32_t now = uptimeSeconds(), at = retryAt_;
    s.nextRetryS = (s.state == LinkState::Failed && at > now) ? at - now : 0;
    s.apOn = apOn_;
    s.apClients = apClients_;
    const uint32_t f = forcedUntil_;
    s.apForcedForS = f > now ? f - now : 0;
    return s;
}

const char* WifiManager::stateText(LinkState s)
{
    switch (s) {
        case LinkState::NotConfigured: return "not configured";
        case LinkState::Connecting: return "connecting";
        case LinkState::Connected: return "connected";
        default: return "retrying";
    }
}

const char* WifiManager::reasonText(uint8_t r)
{
    switch (r) {
        case 0: return "";
        case WIFI_REASON_NO_AP_FOUND: return "network not found";
        case WIFI_REASON_NO_AP_FOUND_W_COMPATIBLE_SECURITY:
        case WIFI_REASON_NO_AP_FOUND_IN_AUTHMODE_THRESHOLD: return "network security not supported";
        case WIFI_REASON_NO_AP_FOUND_IN_RSSI_THRESHOLD: return "signal too weak";
        case WIFI_REASON_AUTH_FAIL:
        case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT:
        case WIFI_REASON_HANDSHAKE_TIMEOUT: return "wrong password?";
        case WIFI_REASON_BEACON_TIMEOUT: return "signal lost";
        case WIFI_REASON_ASSOC_LEAVE: return "disconnected";
        case WIFI_REASON_AUTH_EXPIRE: return "authentication expired";
        case WIFI_REASON_CONNECTION_FAIL: return "connection failed";
        default: return "connection error";
    }
}

uint32_t WifiManager::staDns() const
{
    esp_netif_dns_info_t dns{};
    if (esp_netif_get_dns_info(sta_, ESP_NETIF_DNS_MAIN, &dns) != ESP_OK) return 0;
    return dns.ip.type == ESP_IPADDR_TYPE_V4 ? dns.ip.u_addr.ip4.addr : 0;
}

size_t WifiManager::ip6Addresses(char out[][46], size_t max, bool* hasGlobal) const
{
    esp_ip6_addr_t addrs[LWIP_IPV6_NUM_ADDRESSES];
    const int n = connected_ ? esp_netif_get_all_ip6(sta_, addrs) : 0;
    size_t count = 0;
    if (hasGlobal) *hasGlobal = false;
    for (int i = 0; i < n && count < max; i++) {
        inet_ntop(AF_INET6, addrs[i].addr, out[count], 46);
        if (hasGlobal && esp_netif_ip6_get_addr_type(&addrs[i]) == ESP_IP6_ADDR_IS_GLOBAL) *hasGlobal = true;
        count++;
    }
    return count;
}

uint32_t WifiManager::apIp() const
{
    esp_netif_ip_info_t info{};
    return esp_netif_get_ip_info(ap_, &info) == ESP_OK ? info.ip.addr : 0;
}

uint32_t WifiManager::apNetmask() const
{
    esp_netif_ip_info_t info{};
    return esp_netif_get_ip_info(ap_, &info) == ESP_OK ? info.netmask.addr : 0;
}

int WifiManager::rssi() const
{
    int r = 0;
    return (connected_ && esp_wifi_sta_get_rssi(&r) == ESP_OK) ? r : 0;
}

void WifiManager::apSsid(char out[33]) const
{
    wifi_config_t ap{};
    esp_wifi_get_config(WIFI_IF_AP, &ap);
    copyStr(out, 33, reinterpret_cast<const char*>(ap.ap.ssid));
}

// ------------------------------------------------------------------ mDNS

esp_err_t Mdns::begin(const char* hostname)
{
    esp_err_t err = mdns_init();
    if (err != ESP_OK) return err;
    mdns_hostname_set(hostname);
    mdns_instance_name_set("DNS Sinkhole");
    mdns_service_add(nullptr, "_http", "_tcp", 80, nullptr, 0);
    ESP_LOGI(TAG, "mDNS: http://%s.local", hostname);
    return ESP_OK;
}

}  // namespace sinkhole
