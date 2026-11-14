#pragma once
// Owns every subsystem (all members, no heap) and wires them together.

#include "sinkhole/blocklist_store.hpp"
#include "sinkhole/boot_button.hpp"
#include "sinkhole/config.hpp"
#include "sinkhole/dns_server.hpp"
#include "sinkhole/domain_filter.hpp"
#include "sinkhole/domain_list.hpp"
#include "sinkhole/stats.hpp"
#include "sinkhole/updaters.hpp"
#include "sinkhole/web_server.hpp"
#include "sinkhole/wifi_manager.hpp"
#include "sinkhole/wol.hpp"

namespace sinkhole {

class App {
public:
    App();
    void start();

private:
    static void onUplinkChange(void* ctx, bool connected);
    static void applyUpstream(void* ctx);
    void updateCaptive();
    void startRollbackGuard();

    Config config_;
    BlocklistStore store_;
    DomainList custom_{"custom_block"};
    DomainList allow_{"custom_allow"};
    DomainFilter filter_{store_, custom_, allow_};
    ClientTable clients_;
    QueryLog queryLog_;
    Counters counters_;
    WifiManager wifi_{config_};
    DnsServer dns_{filter_, clients_, queryLog_, counters_};
    FirmwareUpdater firmware_;
    Updater updater_{config_, store_, wifi_, firmware_};
    WolService wol_{wifi_};
    MqttBridge mqtt_{config_, wol_};
    BootButton button_{wifi_};
    WebServer web_;
};

}  // namespace sinkhole
