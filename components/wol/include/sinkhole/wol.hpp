#pragma once
// Wake-on-LAN: a registry of LAN hosts, magic-packet sender, an ICMP probe
// that shows which hosts are awake, and an optional MQTT bridge so hosts can be
// woken from outside the LAN without opening any port (outbound connection).

#include <atomic>
#include <cstddef>
#include <cstdint>

#include "esp_err.h"
#include "sdkconfig.h"
#include "sinkhole/config.hpp"
#include "sinkhole/rtos.hpp"
#include "sinkhole/wifi_manager.hpp"

namespace sinkhole {

struct WolHost {
    char name[32];
    uint8_t mac[6];
    uint32_t ip;    // optional, network order; enables the online check
    uint16_t port;  // optional TCP port (3389 RDP, 22 SSH...): online = it accepts; 0 = ping
    // Seconds to wait for it to answer after a wake (30..3600, 0 = 180). Sits in
    // what used to be padding, so stored hosts keep their size and older
    // firmware ignores it; anything out of range reads as the default.
    uint16_t timeout;
};
static_assert(sizeof(WolHost) == 48, "WolHost is stored in NVS: keep its size");

struct WolHostState {
    WolHost host;
    bool online;
    uint32_t lastWake;      // uptime seconds, 0 = never
    bool waking;            // wake-and-verify in progress
    uint32_t wakeDeadline;  // uptime seconds
    char result[48];        // last wake result, e.g. "online after 41 s"
    uint32_t resultAt;      // uptime seconds, 0 = none
    uint8_t misses;         // failed checks in a row (offline after 2)
    bool resultNew;         // result changed, not yet reported to the listener
};

class WolService {
public:
    static constexpr size_t kCapacity = CONFIG_SINKHOLE_WOL_MAX_HOSTS;

    explicit WolService(WifiManager& wifi) : wifi_(wifi) {}

    esp_err_t begin();  // load hosts, start the probe task

    esp_err_t add(const WolHost& h);  // replaces an entry with the same name
    esp_err_t remove(const char* name);
    size_t list(WolHostState* out, size_t max);
    // fn(const WolHost&) for each host, under the lock (keep fn short, no copies).
    template <typename F>
    void forEachHost(F&& fn)
    {
        LockGuard g(mu_);
        for (size_t i = 0; i < count_; i++) fn(static_cast<const WolHost&>(hosts_[i].host));
    }
    // Changes whenever a host is added, removed or edited.
    uint32_t fingerprint()
    {
        uint32_t h = 2166136261u;
        forEachHost([&h](const WolHost& w) {
            for (const char* c = w.name; *c; c++) h = (h ^ static_cast<uint8_t>(*c)) * 16777619u;
            h = (h ^ w.ip) * 16777619u;
        });
        return h;
    }

    esp_err_t wake(const char* name);
    // Checks first (no packet when already online), wakes, then checks every
    // 3 s (resending at 20 s and 60 s) until online or kVerifySeconds pass.
    // The outcome is in WolHostState::result. Hosts without an IP just wake
    // (*verifying = false: there is nothing to check against).
    // ESP_ERR_INVALID_STATE: already online, nothing sent.
    esp_err_t wakeAndVerify(const char* name, bool* verifying = nullptr);
    static constexpr uint32_t kVerifySeconds = 180;
    static uint32_t timeoutOf(const WolHost& h);  // effective wait in seconds
    // Stops waiting for a host being woken. ESP_ERR_INVALID_STATE: not waking.
    esp_err_t cancel(const char* name);
    esp_err_t wakeMac(const uint8_t mac[6]);

    // Notified after each probe round (used by the MQTT bridge).
    using Listener = void (*)(void* ctx, const char* name, bool online);
    void setListener(Listener fn, void* ctx) { listener_ = fn; listenerCtx_ = ctx; }
    // Notified (from the probe task, about a second later) whenever a host's
    // wake result changes: "waking", "online after 41 s", "cancelled"...
    using ResultListener = void (*)(void* ctx, const char* name, const char* result);  // NOSONAR C-style callback like Listener, no heap
    void setResultListener(ResultListener fn, void* ctx) { resultListener_ = fn; resultCtx_ = ctx; }

private:
    static void taskEntry(void* arg);
    void run();
    bool ping(uint32_t ip);
    static bool tcpOpen(uint32_t ip, uint16_t port);
    bool check(const WolHost& h) { return h.port ? tcpOpen(h.ip, h.port) : ping(h.ip); }
    void setResultLocked(int i, const char* text);
    void reportResults();  // outside the lock
    esp_err_t saveLocked();
    int findLocked(const char* name);

    WifiManager& wifi_;
    Mutex mu_;
    WolHostState hosts_[kCapacity]{};
    size_t count_ = 0;
    Listener listener_ = nullptr;
    void* listenerCtx_ = nullptr;
    ResultListener resultListener_ = nullptr;
    void* resultCtx_ = nullptr;  // NOSONAR context for the C-style callback
    StaticTask<3072> task_;
};

// Remote control over MQTT (TLS recommended: mqtts://...). Topics, with
// <p> = Settings::mqttPrefix:
//   <p>/wol/<name>/set    any payload  -> wake that host ("cancel": stop waiting)
//   <p>/wol/<name>/result last wake result, e.g. "online after 41 s" (retained)
//   <p>/wol/<name>/state  "online" / "offline" (retained, published by us)
//   <p>/status            "online" / LWT "offline" (retained)
// What the bridge may read and control besides Wake-on-LAN (provided by the
// app, so this component needs no filter / stats dependencies).
struct MqttHooks {
    void* ctx = nullptr;
    bool (*blocking)(void* ctx) = nullptr;
    void (*setBlocking)(void* ctx, bool on) = nullptr;
    // Writes the stats JSON object published on <prefix>/stats; returns length.
    size_t (*stats)(void* ctx, char* out, size_t cap) = nullptr;
    const char* model = "";
    const char* version = "";
};

// MQTT: remote wake (<prefix>/wol/<name>/set), host states, and optional Home
// Assistant discovery: a Blocking switch, stats sensors and a Wake button +
// online sensor per WoL host appear in Home Assistant by themselves.
class MqttBridge {
public:
    MqttBridge(Config& cfg, WolService& wol, const MqttHooks& hooks) : cfg_(cfg), wol_(wol), hooks_(hooks) {}
    esp_err_t start();  // no-op when no broker URI is configured
    bool connected() const { return connected_; }

private:
    static void onEvent(void* arg, const char* base, int32_t id, void* data);
    static void onHostState(void* ctx, const char* name, bool online);
    static void onHostResult(void* ctx, const char* name, const char* result);
    static void onTick(void* arg);
    void handleEvent(int32_t id, void* data);
    void tick();
    void announce();
    void publishBlocking();
    void enqueue(const char* topic, const char* payload, bool retain);
    void deviceJson(char* out, size_t cap);
    static void objectId(const char* name, char* out, size_t cap);

    Config& cfg_;
    WolService& wol_;
    MqttHooks hooks_;
    void* client_ = nullptr;  // esp_mqtt_client_handle_t
    std::atomic<bool> connected_{false};
    std::atomic<bool> announceNow_{false};
    bool ha_ = false;
    uint32_t hostsHash_ = 0;
    uint32_t ticks_ = 0;
    int8_t lastBlocking_ = -1;  // last published switch state, -1 = none
    // Strings the MQTT client keeps pointers to.
    char uri_[128]{};
    char user_[64]{};
    char pass_[64]{};
    char prefix_[48]{};
    char statusTopic_[64]{};
    char clientId_[32]{};
    char nodeId_[24]{};
    char hostname_[32]{};
    // Only used from the tick timer (single context).
    char buf_[768]{};
    char announced_[WolService::kCapacity][24]{};  // object ids of announced hosts
};

}  // namespace sinkhole
