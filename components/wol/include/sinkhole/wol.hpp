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
    uint32_t ip;  // optional, network order; enables the online probe
};

struct WolHostState {
    WolHost host;
    bool online;
    uint32_t lastWake;  // uptime seconds, 0 = never
};

class WolService {
public:
    static constexpr size_t kCapacity = CONFIG_SINKHOLE_WOL_MAX_HOSTS;

    explicit WolService(WifiManager& wifi) : wifi_(wifi) {}

    esp_err_t begin();  // load hosts, start the probe task

    esp_err_t add(const WolHost& h);  // replaces an entry with the same name
    esp_err_t remove(const char* name);
    size_t list(WolHostState* out, size_t max);

    esp_err_t wake(const char* name);
    esp_err_t wakeMac(const uint8_t mac[6]);

    // Notified after each probe round (used by the MQTT bridge).
    using Listener = void (*)(void* ctx, const char* name, bool online);
    void setListener(Listener fn, void* ctx) { listener_ = fn; listenerCtx_ = ctx; }

private:
    static void taskEntry(void* arg);
    void run();
    bool ping(uint32_t ip);
    esp_err_t saveLocked();
    int findLocked(const char* name);

    WifiManager& wifi_;
    Mutex mu_;
    WolHostState hosts_[kCapacity]{};
    size_t count_ = 0;
    Listener listener_ = nullptr;
    void* listenerCtx_ = nullptr;
    StaticTask<3072> task_;
};

// Remote control over MQTT (TLS recommended: mqtts://...). Topics, with
// <p> = Settings::mqttPrefix:
//   <p>/wol/<name>/set    any payload  -> wake that host
//   <p>/wol/<name>/state  "online" / "offline" (retained, published by us)
//   <p>/status            "online" / LWT "offline" (retained)
class MqttBridge {
public:
    MqttBridge(Config& cfg, WolService& wol) : cfg_(cfg), wol_(wol) {}
    esp_err_t start();  // no-op when no broker URI is configured
    bool connected() const { return connected_; }

private:
    static void onEvent(void* arg, const char* base, int32_t id, void* data);
    static void onHostState(void* ctx, const char* name, bool online);
    void handleEvent(int32_t id, void* data);

    Config& cfg_;
    WolService& wol_;
    void* client_ = nullptr;  // esp_mqtt_client_handle_t
    std::atomic<bool> connected_{false};
    // Strings the MQTT client keeps pointers to.
    char uri_[128]{};
    char user_[64]{};
    char pass_[64]{};
    char prefix_[48]{};
    char statusTopic_[64]{};
    char clientId_[32]{};
};

}  // namespace sinkhole
