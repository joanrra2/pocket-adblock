#pragma once
// Wake-on-LAN: a registry of LAN hosts, magic-packet sender, an ICMP probe
// that shows which hosts are awake, and an optional MQTT bridge so hosts can be
// woken from outside the LAN without opening any port (outbound connection).

#include <algorithm>
#include <array>
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
    uint8_t mac[6];  // NOSONAR stored in NVS as raw bytes; all zero: watch-only (never woken, needs the IP)
    // kWolAlert...; sits in what used to be padding, so older firmware keeps
    // the size and ignores it (it would show an alerting host as a plain one).
    uint8_t flags;
    uint8_t reserved;
    uint32_t ip;    // optional, network order; enables the online check
    uint16_t port;  // optional TCP port (3389 RDP, 22 SSH...): online = it accepts; 0 = ping
    // Seconds to wait for it to answer after a wake (30..3600, 0 = 180). Sits in
    // what used to be padding, so stored hosts keep their size and older
    // firmware ignores it; anything out of range reads as the default.
    uint16_t timeout;
};
static_assert(sizeof(WolHost) == 48, "WolHost is stored in NVS: keep its size");
static_assert(offsetof(WolHost, ip) == 40, "WolHost is stored in NVS: keep its layout");
constexpr uint8_t kWolAlert = 1;  // tell the owner when it goes offline / comes back
// Wake result of a watch-only host, published retained on <prefix>/wol/<name>/result
// (Pocket Wake hides its Wake button). Part of the MQTT contract: keep the text.
constexpr const char* kWatchOnlyResult = "watch only";

inline bool watchOnly(const WolHost& h)
{
    return std::ranges::all_of(h.mac, [](uint8_t b) { return b == 0; });
}

// A host's state as the probe saw it change (passed to the listener).
struct WolHostChange {
    const char* name;
    bool online;
    bool first;        // first state since boot or since it was added: not a change
    bool alert;        // the host has kWolAlert
    uint32_t prevFor;  // seconds it spent in the previous state (0 when first)
};

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
    bool known;             // `online` reflects a real check (not just booted)
    uint32_t stateSince;    // uptime seconds of the last state change
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
    // Copies host i. For callers that must not wait while holding the lock
    // (the list may change between calls: check fingerprint() afterwards).
    bool hostAt(size_t i, WolHost& out)
    {
        LockGuard g(mu_);
        if (i >= count_) return false;
        out = hosts_[i].host;
        return true;
    }
    // Changes whenever a host is added, removed or edited.
    uint32_t fingerprint()
    {
        uint32_t h = 2166136261u;
        forEachHost([&h](const WolHost& w) {
            for (const char* c = w.name; *c; c++) h = (h ^ static_cast<uint8_t>(*c)) * 16777619u;
            h = (h ^ w.ip) * 16777619u;
            h = (h ^ (watchOnly(w) ? 1u : 0u)) * 16777619u;  // Wake button or not
        });
        return h;
    }

    esp_err_t wake(const char* name);
    // Checks first (no packet when already online), wakes, then checks every
    // 3 s (resending at 20 s and 60 s) until online or kVerifySeconds pass.
    // The outcome is in WolHostState::result. Hosts without an IP just wake
    // (*verifying = false: there is nothing to check against).
    // ESP_ERR_INVALID_STATE: already online, nothing sent.
    // ESP_ERR_NOT_SUPPORTED: a watch-only host (no MAC).
    esp_err_t wakeAndVerify(const char* name, bool* verifying = nullptr);
    static constexpr uint32_t kVerifySeconds = 180;
    static uint32_t timeoutOf(const WolHost& h);  // effective wait in seconds
    // Stops waiting for a host being woken. ESP_ERR_INVALID_STATE: not waking.
    esp_err_t cancel(const char* name);
    esp_err_t wakeMac(const uint8_t mac[6]);

    // Notified when a host's state is first known and whenever it changes.
    using Listener = void (*)(void* ctx, const WolHostChange& change);  // NOSONAR C-style callback, no heap
    void setListener(Listener fn, void* ctx) { listener_ = fn; listenerCtx_ = ctx; }
    // Notified (from the probe task, about a second later) whenever a host's
    // wake result changes: "waking", "online after 41 s", "cancelled"...
    using ResultListener = void (*)(void* ctx, const char* name, const char* result);  // NOSONAR C-style callback like Listener, no heap
    void setResultListener(ResultListener fn, void* ctx) { resultListener_ = fn; resultCtx_ = ctx; }

private:
    static void taskEntry(void* arg);
    void run();
    // Unknown: the check itself could not run (no free socket, no buffer), so
    // it says nothing about the host and must not count as a miss.
    enum class Probe : uint8_t { Down, Up, Unknown };
    Probe ping(uint32_t ip);
    static Probe tcpOpen(uint32_t ip, uint16_t port);
    Probe check(const WolHost& h) { return h.port ? tcpOpen(h.ip, h.port) : ping(h.ip); }
    void setResultLocked(int i, const char* text);
    bool updateStateLocked(int j, bool up, uint32_t now, WolHostChange& change);
    void updateWakeLocked(int j, bool up, uint32_t now, uint32_t since);
    void reportResults();  // outside the lock
    esp_err_t saveLocked();
    void migrateOldHostsLocked();
    int findLocked(const char* name);

    WifiManager& wifi_;
    Mutex mu_;
    WolHostState hosts_[kCapacity]{};
    static std::array<WolHost, kCapacity> stored_;  // NVS layout scratch, under mu_ (one service)
    size_t count_ = 0;
    Listener listener_ = nullptr;
    void* listenerCtx_ = nullptr;
    ResultListener resultListener_ = nullptr;
    void* resultCtx_ = nullptr;  // NOSONAR context for the C-style callback
#if CONFIG_SINKHOLE_NOTIFY
    // A state change also formats a notification on this task: measured 896
    // bytes left of 3072 on an S3 Pro. Lite builds don't, and keep the RAM.
    StaticTask<4096> task_;
#else
    StaticTask<3072> task_;
#endif
};

// Remote control over MQTT (TLS recommended: mqtts://...). Topics, with
// <p> = Settings::mqttPrefix:
//   <p>/wol/<name>/set    any payload  -> wake that host ("cancel": stop waiting)
//   <p>/wol/<name>/result last wake result, e.g. "online after 41 s"; "watch only"
//                         for a host without a MAC, empty once it gets one (retained)
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

    // Host state / wake result publishers (the app calls them; ctx = the bridge).
    static void onHostState(void* ctx, const char* name, bool online);
    static void onHostResult(void* ctx, const char* name, const char* result);

private:
    static void onEvent(void* arg, const char* base, int32_t id, void* data);  // NOSONAR esp_event handler signature
    static void taskEntry(void* arg);  // NOSONAR FreeRTOS task entry: the signature takes void*
    void handleEvent(int32_t id, void* data);
    void tick();
    bool announce();
    bool publishWatchOnly();
    void publishBlocking();
    bool enqueue(const char* topic, const char* payload, bool retain);
    bool paced(const char* topic, const char* payload);
    void deviceJson(char* out, size_t cap);
    static void objectId(const char* name, char* out, size_t cap);

    Config& cfg_;
    WolService& wol_;
    MqttHooks hooks_;
    void* client_ = nullptr;  // esp_mqtt_client_handle_t
    TaskHandle_t task_ = nullptr;  // the publisher task
    std::atomic<bool> connected_{false};
    // Set by the MQTT task on connect, done by the publisher task.
    std::atomic<bool> announceNow_{false};
    std::atomic<bool> watchOnlyNow_{false};
    std::atomic<bool> statsNow_{false};
    bool ha_ = false;
    // Strings the MQTT client keeps pointers to.
    char uri_[128]{};
    char user_[64]{};
    char pass_[64]{};
    char prefix_[48]{};
    char statusTopic_[64]{};
    char clientId_[32]{};
    char nodeId_[24]{};
    char hostname_[32]{};
    // Publisher task only: members rather than its stack.
    struct Publisher {
        uint32_t hostsHash = 0;
        uint32_t ticks = 0;
        int8_t lastBlocking = -1;  // last published switch state, -1 = none
        std::array<char, 768> buf{};
        std::array<char, 256> dev{};
        std::array<char, 160> topic{};
        std::array<std::array<char, 24>, WolService::kCapacity> announced{};  // object ids of announced hosts
    } pub_;
};

}  // namespace sinkhole
