#include "sinkhole/app.hpp"

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "sdkconfig.h"
#include "sinkhole/memory.hpp"
#include "sinkhole/text.hpp"

namespace sinkhole {

namespace {
constexpr const char* TAG = "app";
constexpr uint64_t kHealthyAfterUs = 60ULL * 1000 * 1000;
}  // namespace

App::App()
    : web_(WebDeps{config_, wifi_, store_, custom_, allow_, filter_, clients_, queryLog_, counters_,
                   dns_, updater_, firmware_, wol_, mqtt_, &App::applyUpstream, this})
{
}

void App::start()
{
    ESP_LOGI(TAG, "DNS Sinkhole %s starting (PSRAM: %s)", FirmwareUpdater::version(),
             psramAvailable() ? "yes" : "no");

    ESP_ERROR_CHECK(nvs::init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    config_.load();
    const Settings s = config_.get();
    if (config_.usingDefaultAdminPassword())
        ESP_LOGW(TAG, "web admin still uses the default password: change it in Settings");

    store_.begin();
    custom_.load();
    allow_.load();
    clients_.load();
    queryLog_.begin();
    filter_.setEnabled(s.blocking);

    wifi_.setListener(&App::onUplinkChange, this);
    ESP_ERROR_CHECK(wifi_.begin());
    Mdns::begin(s.hostname);

    applyUpstream(this);
    updateCaptive();
    ESP_ERROR_CHECK(dns_.start());
    ESP_ERROR_CHECK(web_.start());
    updater_.start();
    wol_.begin();
    mqtt_.start();
    button_.start();

    startRollbackGuard();
    ESP_LOGI(TAG, "ready");
}

// Router mode needs the DHCP-provided DNS, which only exists after got-IP.
void App::onUplinkChange(void* ctx, bool connected)
{
    auto* self = static_cast<App*>(ctx);
    if (connected) applyUpstream(ctx);
    self->updateCaptive();
}

// Without an uplink there is nothing to forward to, so setup-AP clients get the
// captive portal instead (phones then open the setup page by themselves).
void App::updateCaptive()
{
    const bool captive = !wifi_.connected();
    dns_.setCaptive(captive, wifi_.apIp(), wifi_.apNetmask());
}

void App::applyUpstream(void* ctx)
{
    auto* self = static_cast<App*>(ctx);
    const Settings s = self->config_.get();
    const uint32_t self4 = self->wifi_.staIp();

    uint32_t up = 0;
    if (s.upstreamMode == UpstreamMode::Custom) up = s.upstreamIp;
    if (s.upstreamMode == UpstreamMode::Router) {
        const uint32_t dhcp = self->wifi_.staDns();
        const uint32_t gw = self->wifi_.gateway();
        // Never forward to ourselves (the router may hand us out as its DNS).
        if (dhcp && dhcp != self4)
            up = dhcp;
        else if (gw && gw != self4)
            up = gw;
    }
    if (!up) parseIp4(CONFIG_SINKHOLE_UPSTREAM_DNS, up);
    self->dns_.setUpstream(up, s.upstreamIp2);
    self->dns_.setGuard(s.bypassGuard);

    char ip[16], ip2[16] = "none";
    formatIp4(up, ip);
    if (self->dns_.backupUpstream()) formatIp4(self->dns_.backupUpstream(), ip2);
    ESP_LOGI(TAG, "upstream DNS %s, backup %s", ip, ip2);
}

// A freshly flashed image boots as PENDING_VERIFY. If it still runs and the DNS
// task is alive after a minute, keep it; if it crashes first, the bootloader
// rolls back to the previous image on the next reset.
void App::startRollbackGuard()
{
    if (!FirmwareUpdater::pendingVerify()) return;
    ESP_LOGW(TAG, "new firmware on probation for 60 s");
    esp_timer_create_args_t args{};
    args.name = "ota_verify";
    args.arg = this;
    args.callback = [](void* arg) {
        auto* self = static_cast<App*>(arg);
        if (self->dns_.running()) FirmwareUpdater::markValid();
    };
    esp_timer_handle_t t = nullptr;
    if (esp_timer_create(&args, &t) == ESP_OK) esp_timer_start_once(t, kHealthyAfterUs);
}

}  // namespace sinkhole
