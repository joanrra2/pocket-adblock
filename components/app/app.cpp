#include "sinkhole/app.hpp"

#include <array>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "sdkconfig.h"
#include "sinkhole/events.hpp"
#include "sinkhole/log_buffer.hpp"
#include "sinkhole/memory.hpp"
#include "sinkhole/text.hpp"

namespace sinkhole {

namespace {
constexpr const char* TAG = "app";
constexpr uint64_t kHealthyAfterUs = 60ULL * 1000 * 1000;
}  // namespace

App::App()
    : web_(WebDeps{config_, wifi_, store_, custom_, allow_, filter_, clients_, queryLog_, counters_,
                   dns_, updater_, firmware_, wol_, mqtt_, led_, history_, dhcp_, names_,
#if CONFIG_SINKHOLE_NOTIFY
                   &notifier_,
#else
                   nullptr,
#endif
                   &App::applyUpstream, this})
{
}

void App::start()
{
    LogBuffer::begin();  // before the first log line, so the web UI sees the boot
    ESP_LOGI(TAG, "DNS Sinkhole %s starting (PSRAM: %s)", FirmwareUpdater::version(),
             psramAvailable() ? "yes" : "no");

    ESP_ERROR_CHECK(nvs::init());
    BootLog::begin(FirmwareUpdater::version());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    config_.load();
    // A confirmed image no longer needs the plain admin password an upgrade kept
    // for a rollback (on probation, startRollbackGuard drops it once confirmed).
    if (!FirmwareUpdater::pendingVerify()) config_.scrubLegacyAdminPassword();
    const Settings s = config_.get();
    if (config_.usingDefaultAdminPassword())
        ESP_LOGW(TAG, "web admin still uses the default password: change it in Settings");

    store_.begin();
    custom_.load();
    allow_.load();
    clients_.load();
    names_.load();
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
    wol_.setListener(&App::onHostState, this);
    wol_.setResultListener(&App::onHostResult, this);
#if CONFIG_SINKHOLE_NOTIFY
    if (notifier_.begin(&App::onCommand, this) == ESP_OK) bootEvents();
#endif
    button_.start();

    // Status LED: off unless a board preset / pin was chosen in Settings.
    if (s.ledKind && led_.configure(static_cast<StatusLed::Kind>(s.ledKind), s.ledPin, s.ledActiveLow, s.ledBrightness) != ESP_OK)
        ESP_LOGW(TAG, "status LED: GPIO%d can't be used, LED off", s.ledPin);
    led_.start(&App::ledState, this);

    startHistory();
    startRollbackGuard();
    ESP_LOGI(TAG, "ready");
}

// Wake-on-LAN host events go to MQTT and, when set up, to the phone.
void App::onHostState(void* ctx, const char* name, bool online)  // NOSONAR C-style listener signature
{
    auto* self = static_cast<App*>(ctx);
    MqttBridge::onHostState(&self->mqtt_, name, online);
    events::emit(events::HostState, "%s is %s", name, online ? "online" : "offline");
}

void App::onHostResult(void* ctx, const char* name, const char* result)  // NOSONAR C-style listener signature
{
    auto* self = static_cast<App*>(ctx);
    MqttBridge::onHostResult(&self->mqtt_, name, result);
    if (strcmp(result, "waking") != 0 && strcmp(result, "cancelled") != 0)
        events::emit(events::Wake, "%s: %s", name, result);
}

#if CONFIG_SINKHOLE_NOTIFY
// After a crash or a firmware change, say so once the phone can be reached.
void App::bootEvents()
{
    std::array<BootLog::Record, 2> r{};
    const size_t n = BootLog::list(r.data(), r.size());
    if (n && BootLog::unexpected(r[0]))
        events::emit(events::Restart, "Restarted after a %s (firmware %s)", BootLog::why(r[0]), r[0].version);
    if (n == 2 && strcmp(r[0].version, r[1].version) != 0)
        events::emit(events::Restart, "Firmware updated: %s -> %s", r[1].version, r[0].version);
}

namespace {
// "/Wake@my_bot office-pc" -> verb "wake", arg "office-pc".
void splitCommand(const char* in, char* verb, size_t verbCap, char* arg, size_t argCap)
{
    while (*in == ' ' || *in == '/') in++;
    size_t n = 0;
    while (*in && *in != ' ' && *in != '@' && n + 1 < verbCap) verb[n++] = static_cast<char>(tolower(static_cast<unsigned char>(*in++)));
    verb[n] = '\0';
    while (*in && *in != ' ') in++;  // rest of "@botname"
    while (*in == ' ') in++;
    copyStr(arg, argCap, in);
    for (size_t k = strnlen(arg, argCap); k && arg[k - 1] == ' '; k--) arg[k - 1] = '\0';
}
}  // namespace

namespace {
const char* hostWord(const WolHostState& h)
{
    if (!h.host.ip) return "?";  // no IP: its state is unknown
    return h.online ? "online" : "offline";
}
}  // namespace

void App::onCommand(void* ctx, const char* command, char* reply, size_t cap)  // NOSONAR C-style listener signature
{
    auto* self = static_cast<App*>(ctx);
    std::array<char, 16> verb{};
    std::array<char, 40> arg{};
    splitCommand(command, verb.data(), verb.size(), arg.data(), arg.size());
    const char* v = verb.data();
    if (strcmp(v, "help") == 0 || strcmp(v, "start") == 0) {
        snprintf(reply, cap, "Commands: status, hosts, wake NAME, cancel NAME, pause [minutes], resume");
    } else if (strcmp(v, "status") == 0) {
        const uint32_t now = uptimeSeconds();
        const uint32_t resume = self->filter_.resumeAt();
        std::array<char, 40> state{};
        if (!self->filter_.enabled() && resume > now)
            snprintf(state.data(), state.size(), "paused (%u min left)", static_cast<unsigned>((resume - now + 59) / 60));
        else
            copyStr(state.data(), state.size(), self->filter_.enabled() ? "on" : "off");
        const uint32_t b = self->counters_.blocked;
        const uint32_t a = self->counters_.allowed;
        snprintf(reply, cap, "Blocking %s. %u of %u queries blocked, %u domains on the list, up %u h. Firmware %s.",
                 state.data(), static_cast<unsigned>(b), static_cast<unsigned>(a + b),
                 static_cast<unsigned>(self->store_.info().count), static_cast<unsigned>(now / 3600),
                 FirmwareUpdater::version());
    } else if (strcmp(v, "hosts") == 0) {
        static std::array<WolHostState, WolService::kCapacity> hosts;  // notifier task only
        const size_t n = self->wol_.list(hosts.data(), hosts.size());
        auto used = static_cast<size_t>(snprintf(reply, cap, n ? "Hosts:" : "No Wake-on-LAN hosts yet."));
        for (size_t i = 0; i < n && used < cap; i++) {
            const char* st = hostWord(hosts[i]);
            used += static_cast<size_t>(snprintf(reply + used, cap - used, " %s (%s)%s", hosts[i].host.name, st, i + 1 < n ? "," : ""));
        }
    } else if (strcmp(v, "wake") == 0) {
        bool verifying = false;
        const esp_err_t err = self->wol_.wakeAndVerify(arg.data(), &verifying);
        if (err == ESP_ERR_NOT_FOUND) snprintf(reply, cap, "No host called '%s'. Try: hosts", arg.data());
        else if (err == ESP_ERR_INVALID_STATE) snprintf(reply, cap, "%s is already online.", arg.data());
        else if (err != ESP_OK) snprintf(reply, cap, "Could not send the wake packet.");
        else snprintf(reply, cap, verifying ? "Waking %s; I'll tell you when it answers." : "Magic packet sent to %s.", arg.data());
    } else if (strcmp(v, "cancel") == 0) {
        const esp_err_t err = self->wol_.cancel(arg.data());
        if (err == ESP_OK) snprintf(reply, cap, "Stopped waiting for %s.", arg.data());
        else if (err == ESP_ERR_NOT_FOUND) snprintf(reply, cap, "No host called '%s'.", arg.data());
        else snprintf(reply, cap, "%s is not being woken.", arg.data());
    } else if (strcmp(v, "pause") == 0) {
        unsigned long m = arg[0] ? strtoul(arg.data(), nullptr, 10) : 15;
        if (m < 1 || m > 1440) m = 15;
        self->filter_.pauseFor(static_cast<uint32_t>(m * 60));
        snprintf(reply, cap, "Blocking paused for %lu min.", m);
    } else if (strcmp(v, "resume") == 0) {
        self->filter_.setEnabled(true);
        self->config_.modify([](Settings& s) { s.blocking = true; });
        snprintf(reply, cap, "Blocking is on again.");
    } else {
        snprintf(reply, cap, "Unknown command. Try: help");
    }
}
#endif

// Router mode needs the DHCP-provided DNS, which only exists after got-IP.
void App::onUplinkChange(void* ctx, bool connected)
{
    auto* self = static_cast<App*>(ctx);
    const uint32_t now = uptimeSeconds();
    if (!connected && !self->uplinkDownAt_) self->uplinkDownAt_ = now ? now : 1;
    if (connected && self->uplinkDownAt_) {
        const uint32_t down = now - self->uplinkDownAt_;
        self->uplinkDownAt_ = 0;
        if (down >= 120) events::emit(events::Uplink, "Wi-Fi back after %u min without it", static_cast<unsigned>(down / 60));
    }
    // Also starts the LAN DHCP server. It stays up while the link is down: a
    // Wi-Fi blip must not wipe its lease table.
    if (connected) {
        applyUpstream(ctx);
        BootLog::startTimeSync();
    }
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
    self->queryLog_.setPrivacy(s.privacy);
    self->dns_.setRateLimit(s.rateLimit);
    self->applyDhcp();

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

// LAN DHCP server: only with a static IP and a valid pool (LanDhcp checks it).
// Starts once the uplink is up; after that a no-op unless the settings changed.
void App::applyDhcp()
{
    const auto o = config_.read([](const Settings& s) {
        struct {
            bool on;
            LanDhcp::Options opt;
        } r{s.dhcpServer && s.staticIp,
            {s.ipAddr, s.ipMask, s.ipGw, s.dhcpFirst, s.dhcpLast,
             s.dhcpLeaseMinutes ? s.dhcpLeaseMinutes : uint16_t(720)}};
        return r;
    });
    if (!o.on)
        dhcp_.stop();
    else if (wifi_.connected())
        dhcp_.start(wifi_.staNetif(), o.opt);
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
    BootLog::Record last{};
    BootLog::list(&last, 1);
    const int n = snprintf(out, cap,
                           "{\"blocked\":%u,\"allowed\":%u,\"percent\":%u.%u,\"domains\":%u,\"clients\":%u,"
                           "\"uptime\":%lu,\"restart\":\"%s\"}",
                           static_cast<unsigned>(blocked), static_cast<unsigned>(allowed), pct10 / 10, pct10 % 10,
                           static_cast<unsigned>(self->store_.info().count),
                           static_cast<unsigned>(self->clients_.activeCount(3600)),
                           static_cast<unsigned long>(uptimeSeconds()), BootLog::why(last));
    return n > 0 ? static_cast<size_t>(n) : 0;
}

// 24 h graph: sample the counters every 10 minutes.
void App::startHistory()
{
    esp_timer_create_args_t args{};
    args.name = "history";
    args.arg = this;
    args.callback = [](void* arg) {
        auto* self = static_cast<App*>(arg);
        self->history_.sample(self->counters_.allowed, self->counters_.blocked);
        BootLog::tick();  // a crash later still knows how long this boot ran
    };
    esp_timer_handle_t t = nullptr;
    if (esp_timer_create(&args, &t) == ESP_OK)
        esp_timer_start_periodic(t, static_cast<uint64_t>(History::kSlotSeconds) * 1000 * 1000);
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
        if (!self->dns_.running()) return;
        FirmwareUpdater::markValid();
        // The plain admin password an upgrade kept for a rollback can go now.
        // An NVS write is too much for the esp_timer task's stack: own task.
        xTaskCreate(
            [](void* arg) {  // NOSONAR FreeRTOS task entry: the signature takes void*
                static_cast<App*>(arg)->config_.scrubLegacyAdminPassword();
                vTaskDelete(nullptr);
            },
            "scrub", 4096, self, 2, nullptr);
    };
    esp_timer_handle_t t = nullptr;
    if (esp_timer_create(&args, &t) == ESP_OK) esp_timer_start_once(t, kHealthyAfterUs);
}

}  // namespace sinkhole
