#pragma once
// Owns every subsystem (all members, no heap) and wires them together.

#include "sinkhole/blocklist_store.hpp"
#include "sinkhole/boot_button.hpp"
#include "sinkhole/config.hpp"
#include "sinkhole/device_names.hpp"
#include "sinkhole/dns_server.hpp"
#include "sinkhole/domain_filter.hpp"
#include "sinkhole/domain_list.hpp"
#include "sinkhole/lan_dhcp.hpp"
#include "sinkhole/notifier.hpp"
#include "sinkhole/stats.hpp"
#include "sinkhole/status_led.hpp"
#include "sinkhole/updaters.hpp"
#include "sinkhole/web_server.hpp"
#include "sinkhole/wifi_manager.hpp"
#include "sinkhole/wol.hpp"

namespace sinkhole {

class App {  // NOSONAR the one object that wires every service together
public:
    App();
    void start();

private:
    static void onUplinkChange(void* ctx, bool connected);
    static void onHostState(void* ctx, const char* name, bool online);  // NOSONAR C-style listener signature
    static void onHostResult(void* ctx, const char* name, const char* result);  // NOSONAR C-style listener signature
    static void onCommand(void* ctx, const char* command, char* reply, size_t cap);  // NOSONAR C-style listener signature
    void bootEvents();
    static void applyUpstream(void* ctx);
    void applyDhcp();
    MqttHooks mqttHooks();
    static StatusLed::State ledState(void* ctx);
    static bool hookBlocking(void* ctx);
    static void hookSetBlocking(void* ctx, bool on);
    static size_t hookStats(void* ctx, char* out, size_t cap);
    void updateCaptive();
    void startRollbackGuard();

    Config config_;
    BlocklistStore store_;
    DomainList custom_{"custom_block"};
    DomainList allow_{"custom_allow"};
    DomainFilter filter_{store_, custom_, allow_};
    ClientTable clients_;
    DeviceNames names_;
    QueryLog queryLog_;
    Counters counters_;
    WifiManager wifi_{config_};
    LanDhcp dhcp_;
    DnsServer dns_{filter_, clients_, queryLog_, counters_};
    FirmwareUpdater firmware_;
    Updater updater_{config_, store_, wifi_, firmware_};
    WolService wol_{wifi_};
    MqttBridge mqtt_{config_, wol_, mqttHooks()};
#if CONFIG_SINKHOLE_NOTIFY
    Notifier notifier_{config_, wifi_};
#endif
    uint32_t uplinkDownAt_ = 0;  // uptime s when the uplink went down, 0 = up
    BootButton button_{wifi_};
    StatusLed led_;
    History history_;
    void startHistory();
    WebServer web_;
};

}  // namespace sinkhole
