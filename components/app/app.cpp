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
                   dns_, updater_, firmware_, wol_, mqtt_, led_, &App::applyUpstream, this})
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

    // Status LED: off unless a board preset / pin was chosen in Settings.
    if (s.ledKind && led_.configure(static_cast<StatusLed::Kind>(s.ledKind), s.ledPin, s.ledActiveLow, s.ledBrightness) != ESP_OK)
        ESP_LOGW(TAG, "status LED: GPIO%d can't be used, LED off", s.ledPin);
    led_.start(&App::ledState, this);

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
    // DNS over TLS: everything allowed goes through the local TLS proxy, with no
    // plain-UDP backup (it would leak the queries the user wants encrypted).
    const bool dot = DotProxy::available() && s.dot && s.dotHost[0];
    self->dns_.dot().setHost(dot ? s.dotHost : "");
    if (dot)
        self->dns_.setUpstream(htonl(INADDR_LOOPBACK), 0, DotProxy::kPort);
    else
        self->dns_.setUpstream(up, s.upstreamIp2);
    self->dns_.setGuard(s.bypassGuard);
    self->dns_.setCnameCheck(s.cnameCheck);
    self->dns_.setSafeSearch(s.safeSearch);

    char ip[16], ip2[16] = "none";
    formatIp4(up, ip);
    if (self->dns_.backupUpstream()) formatIp4(self->dns_.backupUpstream(), ip2);
    if (dot)
        ESP_LOGI(TAG, "upstream DNS over TLS: %s:853", s.dotHost);
    else
        ESP_LOGI(TAG, "upstream DNS %s, backup %s", ip, ip2);
}

// What the status LED shows, most important first (called every 50 ms).
StatusLed::State App::ledState(void* ctx)
{
    auto* self = static_cast<App*>(ctx);
    const WifiStatus ws = self->wifi_.status();
    if (ws.state == LinkState::NotConfigured) return StatusLed::State::Setup;
    if (ws.state != LinkState::Connected) return StatusLed::State::Offline;
    const UpdateStatus us = self->updater_.status();
    if (us.running || self->updater_.firmwareStatus().installing) return StatusLed::State::Updating;
    if (!self->dns_.running() || self->store_.info().count == 0 || (us.lastAttempt && !us.lastOk))
        return StatusLed::State::Failure;
    if (!self->filter_.enabled()) return StatusLed::State::Paused;
    return StatusLed::State::Ok;
}

// What the MQTT bridge may read / control (Home Assistant entities).
MqttHooks App::mqttHooks()
{
    MqttHooks h;
    h.ctx = this;
    h.blocking = &App::hookBlocking;
    h.setBlocking = &App::hookSetBlocking;
    h.stats = &App::hookStats;
    h.model = Updater::boardId();
    h.version = FirmwareUpdater::version();
    return h;
}

bool App::hookBlocking(void* ctx)
{
    return static_cast<App*>(ctx)->filter_.enabled();
}

void App::hookSetBlocking(void* ctx, bool on)
{
    auto* self = static_cast<App*>(ctx);
    self->filter_.setEnabled(on);
    self->config_.modify([on](Settings& s) { s.blocking = on; });
}

size_t App::hookStats(void* ctx, char* out, size_t cap)
{
    auto* self = static_cast<App*>(ctx);
    const uint32_t blocked = self->counters_.blocked, allowed = self->counters_.allowed;
    const uint64_t total = static_cast<uint64_t>(blocked) + allowed;
    const unsigned pct10 = total ? static_cast<unsigned>(blocked * 1000ULL / total) : 0;
    const int n = snprintf(out, cap, "{\"blocked\":%u,\"allowed\":%u,\"percent\":%u.%u,\"domains\":%u,\"clients\":%u}",
                           static_cast<unsigned>(blocked), static_cast<unsigned>(allowed), pct10 / 10, pct10 % 10,
                           static_cast<unsigned>(self->store_.info().count),
                           static_cast<unsigned>(self->clients_.activeCount(3600)));
    return n > 0 ? static_cast<size_t>(n) : 0;
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
