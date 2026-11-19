#include "sinkhole/web_server.hpp"

#include <array>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <initializer_list>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "psa/crypto.h"
#include "sinkhole/events.hpp"
#include "sinkhole/json_writer.hpp"
#include "sinkhole/log_buffer.hpp"
#include "sinkhole/memory.hpp"
#include "sinkhole/perf.hpp"
#include "sinkhole/secret.hpp"
#include "sinkhole/text.hpp"

extern const uint8_t index_html_gz_start[] asm("_binary_index_html_gz_start");
extern const uint8_t index_html_gz_end[] asm("_binary_index_html_gz_end");

namespace sinkhole {

namespace {
constexpr const char* TAG = "web";
constexpr const char* kCsrfHeader = "X-Requested-With";
constexpr const char* kCsrfValue = "sinkhole";
constexpr size_t kFormMax = 768;

void noFree(void*) {}

constexpr size_t kIpText = 46;

void peerIp(httpd_req_t* req, std::array<char, kIpText>& out)
{
    out[0] = '\0';
    sockaddr_in6 sa{};
    socklen_t len = sizeof(sa);
    if (getpeername(httpd_req_to_sockfd(req), reinterpret_cast<sockaddr*>(&sa), &len) != 0) return;
    if (sa.sin6_family != AF_INET6) {
        inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(&sa)->sin_addr, out.data(), out.size());
        return;
    }
    // IPv4 clients show up as ::ffff:a.b.c.d on a dual-stack socket.
    const auto* ip = reinterpret_cast<const uint8_t*>(&sa.sin6_addr);
    static constexpr std::array<uint8_t, 12> kMapped = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    if (memcmp(ip, kMapped.data(), kMapped.size()) == 0)
        snprintf(out.data(), out.size(), "%u.%u.%u.%u", ip[12], ip[13], ip[14], ip[15]);
    else
        inet_ntop(AF_INET6, &sa.sin6_addr, out.data(), out.size());
}

bool endsWith(const char* s, size_t n, const char* suffix)
{
    const size_t k = strnlen(suffix, 16);
    return n > k && strncmp(s + n - k, suffix, k) == 0;
}

// Names a DNS-rebinding page can't point at us: IP literals, single-label names
// and local suffixes, which only the LAN's own DNS (or mDNS) answers.
bool localHostName(char* host, size_t cap)
{
    if (!host[0] || host[0] == '[') return true;  // no Host header (not a browser), or an IPv6 literal
    if (char* colon = strchr(host, ':')) *colon = '\0';  // port
    size_t n = strnlen(host, cap);
    while (n && host[n - 1] == '.') host[--n] = '\0';
    for (size_t i = 0; i < n; i++) host[i] = static_cast<char>(tolower(static_cast<unsigned char>(host[i])));
    in_addr a{};
    if (inet_aton(host, &a) || !memchr(host, '.', n)) return true;
    static constexpr const char* kLocal[] = {".local", ".lan", ".home", ".home.arpa", ".internal", ".localdomain"};
    for (const char* suffix : kLocal)
        if (endsWith(host, n, suffix)) return true;
    return false;
}

const char* upstreamModeName(UpstreamMode m)
{
    switch (m) {
        case UpstreamMode::Router: return "router";
        case UpstreamMode::Custom: return "custom";
        default: return "builtin";
    }
}
}  // namespace

// ------------------------------------------------------------------ routing

const WebServer::Route WebServer::kRoutes[] = {
    {"/", HTTP_GET, &WebServer::getIndex, false},
    {"/api/status", HTTP_GET, &WebServer::getStatus, true},
    {"/api/clients", HTTP_GET, &WebServer::getClients, true},
    {"/api/queries", HTTP_GET, &WebServer::getQueries, true},
    {"/api/lists", HTTP_GET, &WebServer::getLists, true},
    {"/api/lists", HTTP_POST, &WebServer::postLists, true},
    {"/api/records", HTTP_GET, &WebServer::getRecords, true},
    {"/api/top", HTTP_GET, &WebServer::getTop, true},
    {"/api/history", HTTP_GET, &WebServer::getHistory, true},
    {"/api/backup", HTTP_GET, &WebServer::getBackup, true},
    {"/api/restore", HTTP_POST, &WebServer::postRestore, true},
    {"/api/records", HTTP_POST, &WebServer::postRecords, true},
    {"/api/blocking", HTTP_POST, &WebServer::postBlocking, true},
    {"/api/ban", HTTP_POST, &WebServer::postBan, true},
    {"/api/settings", HTTP_GET, &WebServer::getSettings, true},
    {"/api/settings", HTTP_POST, &WebServer::postSettings, true},
    {"/api/wifi", HTTP_POST, &WebServer::postWifi, true},
    {"/api/wifi/scan", HTTP_GET, &WebServer::getWifiScan, true},
    {"/api/blocklist/fetch", HTTP_POST, &WebServer::postBlocklistFetch, true},
    {"/api/blocklist/upload", HTTP_POST, &WebServer::postBlocklistUpload, true},
    {"/api/firmware/upload", HTTP_POST, &WebServer::postFirmwareUpload, true},
    {"/api/firmware/check", HTTP_POST, &WebServer::postFirmwareCheck, true},
    {"/api/firmware/install", HTTP_POST, &WebServer::postFirmwareInstall, true},
    {"/api/reboot", HTTP_POST, &WebServer::postReboot, true},
    {"/api/wol", HTTP_GET, &WebServer::getWol, true},
    {"/api/wol", HTTP_POST, &WebServer::postWol, true},
    {"/api/restarts", HTTP_GET, &WebServer::getRestarts, true},
    {"/api/logs", HTTP_GET, &WebServer::getLogs, true},
    {"/api/names", HTTP_POST, &WebServer::postNames, true},
#if CONFIG_SINKHOLE_NOTIFY
    {"/api/notify", HTTP_GET, &WebServer::getNotify, true},
    {"/api/notify", HTTP_POST, &WebServer::postNotify, true},
#endif
#if CONFIG_SINKHOLE_PERF
    {"/api/perf", HTTP_GET, &WebServer::getPerf, true},
#endif
};

esp_err_t WebServer::start()
{
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.stack_size = 8192;
    cfg.max_uri_handlers = sizeof(kRoutes) / sizeof(kRoutes[0]) + 2;
    cfg.max_open_sockets = 5;
    cfg.lru_purge_enable = true;
    cfg.recv_wait_timeout = 15;  // slow uploads over a weak link
    cfg.global_user_ctx = this;
    cfg.global_user_ctx_free_fn = &noFree;  // we are not heap-allocated

    esp_err_t err = httpd_start(&server_, &cfg);
    if (err != ESP_OK) return err;

    for (const Route& r : kRoutes) {
        httpd_uri_t u = {};
        u.uri = r.uri;
        u.method = r.method;
        u.handler = &WebServer::dispatch;
        u.user_ctx = const_cast<Route*>(&r);
        httpd_register_uri_handler(server_, &u);
    }
    httpd_register_err_handler(server_, HTTPD_404_NOT_FOUND, &WebServer::notFound);
    ESP_LOGI(TAG, "web UI on :80");
    return ESP_OK;
}

// Captive portal: phones probe e.g. /generate_204 or /hotspot-detect.html on some
// other host (which our DNS pointed at us). Redirecting those to the UI makes
// them show "Sign in to network". With an uplink, unknown paths are plain 404s.
esp_err_t WebServer::notFound(httpd_req_t* req, httpd_err_code_t err)
{
    auto* self = static_cast<WebServer*>(httpd_get_global_user_ctx(req->handle));
    if (self->d_.dns.captive()) {
        char loc[32] = "http://";  // NOSONAR captive portal: OSes probe and follow plain HTTP only
        formatIp4(self->d_.wifi.apIp(), loc + 7);
        strcat(loc, "/");
        httpd_resp_set_status(req, "302 Found");
        httpd_resp_set_hdr(req, "Location", loc);
        httpd_resp_set_hdr(req, "Cache-Control", "no-store");
        return httpd_resp_send(req, nullptr, 0);
    }
    httpd_resp_send_err(req, err, "not found");
    return ESP_FAIL;
}

esp_err_t WebServer::dispatch(httpd_req_t* req)
{
    auto* self = static_cast<WebServer*>(httpd_get_global_user_ctx(req->handle));
    const auto* route = static_cast<const Route*>(req->user_ctx);
    if (route->needsAuth && !self->authorized(req, req->method == HTTP_POST)) return ESP_OK;
    return (self->*(route->handler))(req);
}

bool WebServer::hostAllowed(httpd_req_t* req)
{
    if (!d_.cfg.usingDefaultAdminPassword()) return true;
    std::array<char, 96> host{};
    httpd_req_get_hdr_value_str(req, "Host", host.data(), host.size());
    return localHostName(host.data(), host.size());
}

void WebServer::forgetLogins()
{
    goodValid_ = false;
    for (Digest& d : bad_) d.fill(0);
    failures_ = 0;
    lockedUntilUs_ = 0;
}

esp_err_t WebServer::challenge(httpd_req_t* req)
{
    httpd_resp_set_status(req, "401 Unauthorized");
    httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"sinkhole\", charset=\"UTF-8\"");
    return httpd_resp_sendstr(req, "authentication required");
}

// "Basic base64(user:pass)" checked against the stored hash.
bool WebServer::credentialsOk(const char* header)
{
    static std::array<char, 160> cred;  // httpd task only
    const char* b64 = header + 6;
    const int n = base64Decode(b64, strnlen(b64, 200), reinterpret_cast<uint8_t*>(cred.data()), cred.size() - 1);
    bool ok = false;
    if (n > 0) {
        cred[static_cast<size_t>(n)] = '\0';
        if (char* colon = static_cast<char*>(memchr(cred.data(), ':', static_cast<size_t>(n)))) {
            *colon = '\0';
            ok = d_.cfg.checkAdmin(cred.data(), colon + 1);
        }
    }
    secureWipe(cred.data(), cred.size());
    return ok;
}

// Seconds left before another guess is checked (0 = go ahead).
int WebServer::guessWaitSeconds() const
{
    const int64_t now = esp_timer_get_time();
    return now < lockedUntilUs_ ? static_cast<int>((lockedUntilUs_ - now) / 1000000 + 1) : 0;
}

void WebServer::noteWrongPassword(httpd_req_t* req, const Digest& digest)
{
    bad_[badNext_] = digest;
    badNext_ = (badNext_ + 1) % bad_.size();
    failures_++;
    std::array<char, kIpText> ip;
    peerIp(req, ip);
    if (failures_ < static_cast<uint32_t>(kFreeGuesses)) {
        ESP_LOGW(TAG, "wrong admin password from %s", ip.data());
        return;
    }
    // 5 s, 10 s, 20 s ... up to 10 minutes per further guess.
    const uint32_t steps = failures_ - kFreeGuesses < 7 ? failures_ - kFreeGuesses : 7;
    lockedUntilUs_ = esp_timer_get_time() + (5LL << steps) * 1000000;
    ESP_LOGW(TAG, "wrong admin password from %s (%lu in a row): next try in %d s", ip.data(),
             static_cast<unsigned long>(failures_), 5 << steps);
}

bool WebServer::authorized(httpd_req_t* req, bool isPost)
{
    if (!hostAllowed(req)) {
        sendError(req, "403 Forbidden",
                  "open this page by the device's IP address or local name, or change the default password");
        return false;
    }
    static std::array<char, 200> got;  // httpd task only
    got[0] = '\0';
    if (httpd_req_get_hdr_value_str(req, "Authorization", got.data(), got.size()) != ESP_OK ||
        strncmp(got.data(), "Basic ", 6) != 0) {
        challenge(req);
        return false;
    }
    // Browsers send the header with every request: only a new one pays for PBKDF2.
    Digest digest{};
    size_t dlen = 0;
    const bool hashed = psa_hash_compute(PSA_ALG_SHA_256, reinterpret_cast<const uint8_t*>(got.data()),
                                         strnlen(got.data(), got.size()), digest.data(), digest.size(),
                                         &dlen) == PSA_SUCCESS;
    const bool known = hashed && goodValid_ && sameBytes(digest.data(), good_.data(), digest.size());
    if (!known) {
        bool retried = !hashed;
        for (const Digest& b : bad_) retried |= sameBytes(digest.data(), b.data(), digest.size());
        if (retried) {  // the same wrong password again (a page polling): not a new guess
            challenge(req);
            return false;
        }
        if (const int wait = guessWaitSeconds()) {
            std::array<char, 12> after;
            snprintf(after.data(), after.size(), "%d", wait);
            httpd_resp_set_hdr(req, "Retry-After", after.data());
            sendError(req, "429 Too Many Requests", "too many wrong passwords: wait and try again");
            return false;
        }
        if (!credentialsOk(got.data())) {
            noteWrongPassword(req, digest);
            challenge(req);
            return false;
        }
        good_ = digest;
        goodValid_ = true;
        failures_ = 0;
    }
    if (isPost) {
        char csrf[16] = "";
        if (httpd_req_get_hdr_value_str(req, kCsrfHeader, csrf, sizeof(csrf)) != ESP_OK ||
            strcmp(csrf, kCsrfValue) != 0) {
            sendError(req, "403 Forbidden", "missing X-Requested-With header");
            return false;
        }
    }
    return true;
}

// httpd_req_recv, waiting through up to a minute of silence (4 receive
// timeouts of 15 s) but not forever: a client that vanished mid-upload (phone
// left the Wi-Fi) leaves a half-open connection, and retrying for good would
// hold the one httpd task, and the blocklist slot or OTA handle being
// written, until a restart.
namespace {
int recvBody(httpd_req_t* req, char* buf, size_t len)
{
    constexpr int kMaxTimeouts = 4;
    for (int timeouts = 0;; timeouts++) {
        const int n = httpd_req_recv(req, buf, len);
        if (n != HTTPD_SOCK_ERR_TIMEOUT || timeouts + 1 >= kMaxTimeouts) return n;
    }
}
}  // namespace

int WebServer::readForm(httpd_req_t* req, char* buf, size_t len)
{
    if (req->content_len >= len) return -1;
    size_t got = 0;
    while (got < req->content_len) {
        const int n = recvBody(req, buf + got, req->content_len - got);
        if (n <= 0) return -1;
        got += static_cast<size_t>(n);
    }
    buf[got] = '\0';
    return static_cast<int>(got);
}

bool WebServer::field(const char* form, const char* key, char* out, size_t outLen)
{
    if (httpd_query_key_value(form, key, out, outLen) != ESP_OK) return false;
    urlDecode(out);
    return true;
}

esp_err_t WebServer::sendOk(httpd_req_t* req, const char* message)
{
    JsonWriter j(req);
    j.beginObject().boolean("ok", true).str("message", message).endObject();
    return j.finish();
}

esp_err_t WebServer::sendError(httpd_req_t* req, const char* status, const char* message)
{
    httpd_resp_set_status(req, status);
    JsonWriter j(req);
    j.beginObject().boolean("ok", false).str("message", message).endObject();
    return j.finish();
}

// Nothing was changed: Config puts RAM back to the stored settings.
esp_err_t WebServer::sendNotSaved(httpd_req_t* req)
{
    return sendError(req, "500 Internal Server Error", "could not save: the settings storage is full or failing");
}

// ------------------------------------------------------------------ pages

esp_err_t WebServer::getIndex(httpd_req_t* req)
{
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache");
    // Start and end are two linker symbols around the same embedded file.
    const auto size = reinterpret_cast<uintptr_t>(index_html_gz_end) - reinterpret_cast<uintptr_t>(index_html_gz_start);
    return httpd_resp_send(req, reinterpret_cast<const char*>(index_html_gz_start), static_cast<ssize_t>(size));
}

esp_err_t WebServer::getStatus(httpd_req_t* req)
{
    const Settings s = d_.cfg.get();
    const BlocklistInfo bl = d_.store.info();
    const UpdateStatus up = d_.updater.status();
    const uint32_t now = uptimeSeconds();
    char apSsid[33];
    d_.wifi.apSsid(apSsid);

    JsonWriter j(req);
    j.beginObject();
    j.str("version", FirmwareUpdater::version());
    j.str("edition", Updater::flavour());
    j.str("hostname", s.hostname);
    j.num("uptime", now);
    j.num("time", BootLog::now());
    {
        BootLog::Record last{};
        BootLog::list(&last, 1);
        j.str("lastRestart", BootLog::why(last));
    }
    j.num("freeHeap", static_cast<int64_t>(esp_get_free_heap_size()));
    j.num("minFreeHeap", static_cast<int64_t>(esp_get_minimum_free_heap_size()));
    j.boolean("defaultPassword", d_.cfg.usingDefaultAdminPassword());
    j.boolean("firmwarePendingVerify", FirmwareUpdater::pendingVerify());

    const WifiStatus ws = d_.wifi.status();
    char ip6[3][46];
    bool ip6Global = false;
    const size_t n6 = d_.wifi.ip6Addresses(ip6, 3, &ip6Global);
    j.beginObject("wifi")
        .boolean("connected", d_.wifi.connected())
        .str("state", WifiManager::stateText(ws.state))
        .str("reason", WifiManager::reasonText(ws.lastReason))
        .num("attempts", ws.attempts)
        .num("nextRetry", ws.nextRetryS)
        .str("ssid", s.staSsid)
        .ip("ip", d_.wifi.staIp())
        .num("rssi", d_.wifi.rssi())
        .boolean("apOn", ws.apOn)
        .boolean("apAlways", s.apAlways)
        .num("apClients", ws.apClients)
        .num("apForcedFor", ws.apForcedForS)
        .str("apSsid", apSsid)
        .ip("apIp", d_.wifi.apIp())
        .boolean("captive", d_.dns.captive())
        .num("txDbm10", static_cast<int64_t>(d_.wifi.txPowerDbm() * 10))
        .boolean("txReduced", d_.wifi.txReduced())
        .boolean("ip6Global", ip6Global)
        .beginArray("ip6");
    for (size_t i = 0; i < n6; i++) j.str(nullptr, ip6[i]);
    j.endArray().endObject();

    const uint32_t resumeAt = d_.filter.resumeAt();
    j.beginObject("dns")
        .boolean("blocking", d_.filter.enabled())
        .num("resumeIn", resumeAt > now ? resumeAt - now : 0)
        .num("blocked", d_.counters.blocked.load())
        .num("allowed", d_.counters.allowed.load())
        .num("timeouts", d_.counters.upstreamTimeouts.load())
        .num("dropped", d_.counters.dropped.load())
        .num("bypassBlocked", d_.counters.bypassBlocked.load())
        .num("cnameBlocked", d_.counters.cnameBlocked.load())
        .num("rateLimited", d_.counters.rateLimited.load())
        .boolean("dotOn", s.dot && DotProxy::available())
        .boolean("dotConnected", d_.dns.dot().connected())
        .num("dotQueries", d_.dns.dot().queries())
        .num("dotConnects", d_.dns.dot().connects())
        .num("pending", d_.dns.pendingCount())
        .ip("upstream", d_.dns.upstream())
        .ip("backup", d_.dns.backupUpstream())
        .num("winsPrimary", d_.dns.wins(0))
        .num("winsBackup", d_.dns.wins(1))
        .num("filterUs10", d_.dns.filterAvgUs10())
        .str("upstreamMode", upstreamModeName(s.upstreamMode))
        .num("cacheSize", static_cast<int64_t>(d_.dns.cache().capacity()))
        .boolean("cachePsram", d_.dns.cache().inPsram())
        .num("cacheHits", d_.dns.cache().hits())
        .num("cacheMisses", d_.dns.cache().misses())
        .endObject();

    j.beginObject("memory")
        .boolean("psram", psramAvailable())
        .num("psramFree", static_cast<int64_t>(heap_caps_get_free_size(MALLOC_CAP_SPIRAM)))
        .num("internalFree", static_cast<int64_t>(heap_caps_get_free_size(MALLOC_CAP_INTERNAL)))
        .endObject();

    // Least stack each task has had free since boot (bytes): shows how close a
    // task came to overflowing, so stack sizes are set from measurements.
    static constexpr std::array<const char*, 10> kTasks{"dns",   "dot",     "notify",    "updater",  "wol_probe",
                                                        "httpd", "mqtt_task", "esp_timer", "sys_evt", "button"};
    j.beginObject("stackFree");
    for (const char* name : kTasks)
        if (TaskHandle_t t = xTaskGetHandle(name)) j.num(name, static_cast<int64_t>(uxTaskGetStackHighWaterMark(t)));
    j.endObject();

    char slot[2] = {bl.slot, '\0'};
    j.beginObject("blocklist")
        .num("count", bl.count)
        .num("capacity", bl.capacity)
        .num("format", bl.format)
        .boolean("signed", bl.signedOk)
        .boolean("keyConfigured", bl.keyConfigured)
        .num("bloomBytes", bl.bloomBytes)
        .boolean("bloomPsram", bl.bloomPsram)
        .boolean("bloomReady", bl.bloomReady)
        .num("bloomSkips", bl.bloomSkips)
        .str("slot", slot)
        .num("activeFor", bl.count ? now - bl.activatedUptime : 0)
        .num("created", bl.createdUnix)
        .boolean("writing", d_.store.writing())
        .num("custom", static_cast<int64_t>(d_.custom.count()))
        .num("allow", static_cast<int64_t>(d_.allow.count()))
        .endObject();

    j.beginObject("update")
        .boolean("running", up.running)
        .boolean("lastOk", up.lastOk)
        .num("lastAgo", up.lastAttempt ? static_cast<int64_t>(now - up.lastAttempt) : -1)
        .str("message", up.message)
        .endObject();

    const FirmwareCheck fc = d_.updater.firmwareStatus();
    j.beginObject("firmware")
        .str("board", Updater::imageKey())
        .str("latest", fc.latest)
        .boolean("available", fc.available)
        .boolean("installing", fc.installing)
        .num("bytes", fc.bytes)
        .num("checkedAgo", fc.lastCheck ? static_cast<int64_t>(now - fc.lastCheck) : -1)
        .boolean("checkOk", fc.lastOk)
        .str("message", fc.message)
        .boolean("signedBuild", Updater::autoInstallAllowed())
        .boolean("auto", s.fwAuto)
        .boolean("manifest", s.fwManifestUrl[0] != '\0')
        .endObject();

    const LanDhcp::Stats ds = LanDhcp::stats();
    j.beginObject("dhcp")
        .boolean("running", d_.dhcp.running())
        .num("leases", ds.leases)
        .ip("lastLease", ds.lastLeaseIp)
        .num("discovers", ds.discovers)
        .num("requests", ds.requests)
        .num("others", ds.others)
        .num("offers", ds.offers)
        .num("acks", ds.acks)
        .num("naks", ds.naks)
        .endObject();

    j.beginObject("mqtt")
        .boolean("configured", s.mqttUri[0] != '\0')
        .boolean("connected", d_.mqtt.connected())
        .endObject();

    j.endObject();
    return j.finish();
}

namespace {
ClientInfo sClientSnap[ClientTable::kCapacity];  // httpd task only (shared by the client views)
}

esp_err_t WebServer::getClients(httpd_req_t* req)
{
    if (d_.log.privacy() >= 2) {  // privacy mode: clients are not shown
        JsonWriter j(req);
        j.beginArray().endArray();
        return j.finish();
    }
    ClientInfo* snap = sClientSnap;
    char addr[46];
    std::array<char, DeviceNames::kMaxName> name{};
    const size_t n = d_.clients.snapshot(snap, ClientTable::kCapacity);
    const uint32_t now = uptimeSeconds();
    JsonWriter j(req);
    j.beginArray();
    for (size_t i = 0; i < n; i++) {
        const char* from = clientName(snap[i], name.data(), name.size());
        j.beginObject()
            .str("ip", (snap[i].addr.format(addr), addr))
            .str("name", from ? name.data() : "")
            .str("nameFrom", from ? from : "")
            .boolean("v6", snap[i].addr.v6)
            .mac("mac", snap[i].mac)
            .num("blocked", snap[i].blocked)
            .num("allowed", snap[i].allowed)
            .num("seenAgo", now - snap[i].lastSeen)
            .boolean("banned", snap[i].banned)
            .num("refused", snap[i].refused)
            .boolean("noFilter", snap[i].noFilter)
            .endObject();
    }
    j.endArray();
    return j.finish();
}

// GET /api/queries?limit=100&ip=192.168.1.20&blocked=1&q=ads
esp_err_t WebServer::getQueries(httpd_req_t* req)
{
    char qs[160] = "", v[64];
    httpd_req_get_url_query_str(req, qs, sizeof(qs));
    size_t limit = 100;
    QueryFilter f;
    char text[64] = "";
    if (httpd_query_key_value(qs, "limit", v, sizeof(v)) == ESP_OK) {
        limit = strtoul(v, nullptr, 10);
        if (limit < 1 || limit > 500) limit = 500;
    }
    if (httpd_query_key_value(qs, "ip", v, sizeof(v)) == ESP_OK) parseIp4(v, f.ip);
    if (httpd_query_key_value(qs, "blocked", v, sizeof(v)) == ESP_OK) f.blockedOnly = v[0] == '1';
    if (field(qs, "q", text, sizeof(text)) && text[0]) {
        for (char* c = text; *c; c++) *c = static_cast<char>(tolower(static_cast<unsigned char>(*c)));
        f.text = text;
    }

    static QueryEntry page[16];  // httpd task only; small pages keep the lock short
    char addr[46];
    const uint32_t now = uptimeSeconds();
    snapshotNames();
    size_t cursor = 0, sent = 0;
    JsonWriter j(req);
    j.beginObject().num("capacity", static_cast<int64_t>(d_.log.capacity())).beginArray("items");
    while (sent < limit) {
        const size_t want = limit - sent < 16 ? limit - sent : 16;
        const size_t n = d_.log.page(cursor, f, page, want);
        if (!n) break;
        for (size_t i = 0; i < n; i++) {
            j.beginObject()
                .num("ago", now - page[i].uptime)
                .str("ip", (page[i].addr.format(addr), addr))
                .str("name", nameOf(page[i].addr))
                .str("domain", page[i].domain)
                .boolean("blocked", page[i].blocked)
                .endObject();
        }
        sent += n;
    }
    j.endArray().endObject();
    return j.finish();
}

esp_err_t WebServer::getLists(httpd_req_t* req)
{
    char name[DomainList::kMaxLen];
    JsonWriter j(req);
    j.beginObject();
    j.beginArray("block");
    for (size_t i = 0; d_.custom.at(i, name); i++) j.str(nullptr, name);
    j.endArray();
    j.beginArray("allow");
    for (size_t i = 0; d_.allow.at(i, name); i++) j.str(nullptr, name);
    j.endArray();
    j.endObject();
    return j.finish();
}

// Top domains (allowed / blocked, when built with CONFIG_SINKHOLE_TOP_DOMAINS)
// and the busiest clients since boot.
esp_err_t WebServer::getTop(httpd_req_t* req)
{
    static TopDomains::Item items[10];  // httpd task only
    char addr[46];
    JsonWriter j(req);
    j.beginObject().boolean("domains", d_.log.topEnabled());
    for (const bool blocked : {false, true}) {
        const size_t n = d_.log.top(blocked, items, 10);
        j.beginArray(blocked ? "blocked" : "allowed");
        for (size_t i = 0; i < n; i++) j.beginObject().str("name", items[i].name).num("count", items[i].count).endObject();
        j.endArray();
    }
    const size_t n = d_.log.privacy() >= 2 ? 0 : d_.clients.snapshot(sClientSnap, ClientTable::kCapacity);
    size_t order[5];
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {  // top 5 by total queries
        const uint32_t t = sClientSnap[i].blocked + sClientSnap[i].allowed;
        size_t pos = k < 5 ? k++ : 4;
        if (k == 5 && pos == 4 && t <= sClientSnap[order[4]].blocked + sClientSnap[order[4]].allowed) continue;
        while (pos > 0 && sClientSnap[order[pos - 1]].blocked + sClientSnap[order[pos - 1]].allowed < t) {
            order[pos] = order[pos - 1];
            pos--;
        }
        order[pos] = i;
    }
    j.beginArray("clients");
    std::array<char, DeviceNames::kMaxName> name{};
    for (size_t i = 0; i < k; i++) {
        const ClientInfo& c = sClientSnap[order[i]];
        const char* from = clientName(c, name.data(), name.size());
        j.beginObject()
            .str("ip", (c.addr.format(addr), addr))
            .str("name", from ? name.data() : "")
            .num("queries", c.blocked + c.allowed)
            .num("blocked", c.blocked)
            .endObject();
    }
    j.endArray().endObject();
    return j.finish();
}

// Last 24 h in 10-minute slots, oldest first, plus the current partial slot.
esp_err_t WebServer::getPerf(httpd_req_t* req)
{
#if CONFIG_SINKHOLE_PERF
    static perf::StageStats s[perf::kStages];  // httpd task only
    int64_t windowUs = 0;
    perf::Recorder::instance().snapshot(s, windowUs);
    char q[32] = "";
    httpd_req_get_url_query_str(req, q, sizeof(q));
    if (strstr(q, "reset=1")) perf::Recorder::instance().requestReset();
    uint64_t busy = 0;  // cycles in whole queries and replies
    for (perf::Stage t : {perf::QBlocked, perf::QCached, perf::QForwarded, perf::QOther, perf::UTotal}) busy += s[t].sum;
    JsonWriter j(req);
    j.beginObject().num("windowMs", windowUs / 1000).num("cpuMhz", CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ);
    j.num("busyPerMille", windowUs > 0 ? static_cast<int64_t>(perf::cyclesToNs(busy) / 1000) * 1000 / windowUs : 0);
    j.beginObject("ns");
    for (int i = 0; i < perf::kStages; i++) {
        const perf::StageStats& t = s[i];
        if (!t.n) continue;
        j.beginObject(perf::name(static_cast<perf::Stage>(i)))
            .num("n", t.n)
            .num("mean", perf::cyclesToNs(t.sum / t.n))
            .num("min", perf::cyclesToNs(t.min))
            .num("p50", perf::quantileNs(t, 0.5f))
            .num("p99", perf::quantileNs(t, 0.99f))
            .num("max", perf::cyclesToNs(t.max))
            .endObject();
    }
    j.endObject().endObject();
    return j.finish();
#else
    return httpd_resp_send_404(req);
#endif
}

esp_err_t WebServer::getHistory(httpd_req_t* req)
{
    static uint32_t allowed[History::kSlots], blocked[History::kSlots];  // httpd task only
    uint32_t curA = 0, curB = 0;
    const size_t n = d_.history.copy(allowed, blocked, d_.counters.allowed, d_.counters.blocked, curA, curB);
    JsonWriter j(req);
    j.beginObject().num("slotSeconds", History::kSlotSeconds);
    j.beginArray("allowed");
    for (size_t i = 0; i < n; i++) j.num(nullptr, allowed[i]);
    j.endArray().beginArray("blocked");
    for (size_t i = 0; i < n; i++) j.num(nullptr, blocked[i]);
    j.endArray().num("currentAllowed", curA).num("currentBlocked", curB).endObject();
    return j.finish();
}

// ------------------------------------------------------------ backup / restore
// A small text file: header lines, then key=base64 for each stored item
// (settings, custom lists, local names, WoL hosts, device rules). Passwords
// are left out unless ?secrets=1; restore keeps the device's own passwords
// for any that are missing, writes the items back and restarts.

namespace {
constexpr const char* kBackupKeys[] = {"settings", "custom_block", "custom_allow", "local_dns",
                                       "wol_hosts2", "wol_hosts", "banned", "nofilter", "dev_names",
                                       "notify"};
constexpr size_t kBackupMax = 64 * 1024;

// The kBackupKeys entry named `name` (the same pointer each time), or nullptr.
const char* backupKey(const char* name)
{
    for (const char* k : kBackupKeys)
        if (strcmp(name, k) == 0) return k;
    return nullptr;
}

void clearSecrets(Settings& s)
{
    memset(s.staPass, 0, sizeof(s.staPass));
    memset(s.apPass, 0, sizeof(s.apPass));
    memset(s.adminPass, 0, sizeof(s.adminPass));
    memset(s.mqttPass, 0, sizeof(s.mqttPass));
    memset(s.adminHash, 0, sizeof(s.adminHash));
    memset(s.adminSalt, 0, sizeof(s.adminSalt));
    s.adminIter = 0;
}

void clearSecrets(NotifySettings& n)
{
    memset(n.ntfyToken, 0, sizeof(n.ntfyToken));
    memset(n.tgToken, 0, sizeof(n.tgToken));
}
}  // namespace

esp_err_t WebServer::getBackup(httpd_req_t* req)
{
    char q[32] = "", secrets[4] = "";
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK)
        httpd_query_key_value(q, "secrets", secrets, sizeof(secrets));
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_set_hdr(req, "Content-Disposition", "attachment; filename=\"pocket-adblock-backup.txt\"");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");

    char head[160];
    snprintf(head, sizeof(head), "# Pocket AdBlock backup\nformat=1\nfirmware=%s\nedition=%s\nsecrets=%d\n",
             FirmwareUpdater::version(), Updater::flavour(), secrets[0] == '1');
    httpd_resp_sendstr_chunk(req, head);

    for (const char* key : kBackupKeys) {
        const bool isSettings = strcmp(key, "settings") == 0;
        const bool isNotify = strcmp(key, "notify") == 0;
        size_t len = isSettings ? sizeof(Settings) : nvs::blobSize(key);
        if (isNotify && len) len = sizeof(NotifySettings);  // only once something was set
        if (!len) continue;
        auto* raw = static_cast<uint8_t*>(malloc(len));
        auto* b64 = static_cast<char*>(malloc(len / 3 * 4 + 8));
        if (!raw || !b64) {
            free(raw);
            free(b64);
            httpd_resp_sendstr_chunk(req, "# out of memory\n");
            break;
        }
        bool ok = true;
        if (isSettings) {
            Settings s = d_.cfg.get();
            if (secrets[0] != '1') clearSecrets(s);
            memcpy(raw, &s, len);
            secureWipe(&s, sizeof(s));
        } else if (isNotify) {
            NotifySettings n = d_.cfg.readNotify([](const NotifySettings& c) { return c; });
            if (secrets[0] != '1') clearSecrets(n);
            memcpy(raw, &n, len);
            secureWipe(&n, sizeof(n));
        } else {
            ok = nvs::loadBlob(key, raw, len, &len) == ESP_OK;
        }
        if (ok) {
            base64Encode(raw, len, b64);
            httpd_resp_sendstr_chunk(req, key);
            httpd_resp_sendstr_chunk(req, "=");
            httpd_resp_sendstr_chunk(req, b64);
            httpd_resp_sendstr_chunk(req, "\n");
        }
        free(raw);
        free(b64);
    }
    return httpd_resp_sendstr_chunk(req, nullptr);
}

namespace {
// A backup's settings, brought up to this firmware's version (an older file's
// admin password gets hashed); passwords missing from the file keep the
// device's current ones. Replaces data with a full Settings blob.
const char* upgradeBackupSettings(uint8_t*& data, int& len, Config& cfg)
{
    static Settings in, cur;  // httpd task only
    if (len < 64 || !Config::upgrade(data, static_cast<size_t>(len), in)) return "the settings section is not valid";
    cur = cfg.get();
    if (!in.staPass[0]) memcpy(in.staPass, cur.staPass, sizeof(in.staPass));
    if (!in.apPass[0]) memcpy(in.apPass, cur.apPass, sizeof(in.apPass));
    if (!in.mqttPass[0]) memcpy(in.mqttPass, cur.mqttPass, sizeof(in.mqttPass));
    if (in.adminIter == 0 && !in.adminPass[0]) {  // no admin password in the file
        memcpy(in.adminPass, cur.adminPass, sizeof(in.adminPass));
        memcpy(in.adminHash, cur.adminHash, sizeof(in.adminHash));
        memcpy(in.adminSalt, cur.adminSalt, sizeof(in.adminSalt));
        in.adminIter = cur.adminIter;
    }
    auto* full = static_cast<uint8_t*>(malloc(sizeof(Settings)));
    if (!full) return "out of memory";
    memcpy(full, &in, sizeof(Settings));
    secureWipe(&cur, sizeof(cur));
    free(data);
    data = full;
    len = sizeof(Settings);
    return nullptr;
}
}  // namespace

namespace {
// Same for the notification settings: tokens missing from the file keep the
// device's current ones.
const char* upgradeBackupNotify(uint8_t*& data, int& len, Config& cfg)
{
    static NotifySettings in;  // httpd task only
    if (len < 2 || !Config::upgradeNotify(data, static_cast<size_t>(len), in)) return "the notifications section is not valid";
    cfg.readNotify([](const NotifySettings& cur) {
        if (!in.ntfyToken[0]) memcpy(in.ntfyToken, cur.ntfyToken, sizeof(in.ntfyToken));
        if (!in.tgToken[0]) memcpy(in.tgToken, cur.tgToken, sizeof(in.tgToken));
        return 0;
    });
    auto* full = static_cast<uint8_t*>(malloc(sizeof(NotifySettings)));  // NOSONAR freed by postRestore with free(), like every item
    if (!full) return "out of memory";
    memcpy(full, &in, sizeof(NotifySettings));
    secureWipe(&in, sizeof(in));
    secureWipe(data, static_cast<size_t>(len));
    free(data);  // NOSONAR allocated by postRestore with malloc()
    data = full;
    len = sizeof(NotifySettings);
    return nullptr;
}
}  // namespace

esp_err_t WebServer::postRestore(httpd_req_t* req)
{
    if (req->content_len == 0 || req->content_len > kBackupMax)
        return sendError(req, "400 Bad Request", "not a backup file (empty or too large)");
    char* body = static_cast<char*>(malloc(req->content_len + 1));
    if (!body) return sendError(req, "500 Internal Server Error", "out of memory");
    size_t got = 0;
    while (got < req->content_len) {
        const int r = httpd_req_recv(req, body + got, req->content_len - got);
        if (r <= 0) {
            free(body);
            return sendError(req, "400 Bad Request", "upload interrupted");
        }
        got += static_cast<size_t>(r);
    }
    body[got] = '\0';
    // Files edited on Windows have CRLF line ends: drop the CRs.
    size_t kept = 0;
    for (size_t r = 0; r < got; r++)
        if (body[r] != '\r') body[kept++] = body[r];
    body[kept] = '\0';
    if (!strstr(body, "\nformat=1\n") && strncmp(body, "format=1\n", 9) != 0) {
        free(body);
        return sendError(req, "400 Bad Request", "not a Pocket AdBlock backup (format=1 missing)");
    }

    // Decode everything first; write only if the whole file is valid.
    struct Item {
        const char* key;
        uint8_t* data;
        int len;
    } items[sizeof(kBackupKeys) / sizeof(kBackupKeys[0])] = {};
    size_t count = 0;
    const char* why = nullptr;
    char* save = nullptr;
    char* line = strtok_r(body, "\n", &save);
    while (line && !why) {
        char* eq = strchr(line, '=');
        const char* key = nullptr;
        if (eq && line[0] != '#') {
            *eq = '\0';
            key = backupKey(line);
        }
        // One slot per known key: a repeated section must not run past items[].
        bool seen = false;
        for (size_t k = 0; key && k < count; k++) seen = seen || items[k].key == key;
        if (key && (seen || count >= std::size(items))) why = "a section appears twice";
        if (key && !why) {
            const char* val = eq + 1;
            size_t vlen = strlen(val);
            while (vlen && (val[vlen - 1] == '\r' || val[vlen - 1] == ' ')) vlen--;
            auto* data = static_cast<uint8_t*>(malloc(vlen / 4 * 3 + 4));
            const int n = data ? base64Decode(val, vlen, data, vlen / 4 * 3 + 4) : -1;
            if (n > 0) {
                items[count++] = {key, data, n};
            } else {
                free(data);
                why = "a section of the file is damaged";
            }
        }
        line = strtok_r(nullptr, "\n", &save);
    }
    free(body);

    for (size_t i = 0; i < count && !why; i++) {
        if (strcmp(items[i].key, "settings") == 0) why = upgradeBackupSettings(items[i].data, items[i].len, d_.cfg);
        if (strcmp(items[i].key, "notify") == 0) why = upgradeBackupNotify(items[i].data, items[i].len, d_.cfg);
    }
    if (!why && count == 0) why = "the file contains nothing to restore";
    for (size_t i = 0; i < count && !why; i++)
        if (nvs::saveBlob(items[i].key, items[i].data, static_cast<size_t>(items[i].len)) != ESP_OK)
            why = "could not write the settings";
    for (size_t i = 0; i < count; i++) free(items[i].data);
    if (why) return sendError(req, "400 Bad Request", why);
    FirmwareUpdater::restartIn(1500, BootLog::Cause::Restore);  // every part reloads its data at boot
    return sendOk(req, "restored; restarting");
}

esp_err_t WebServer::getRecords(httpd_req_t* req)
{
    LocalRecords::Record r;
    JsonWriter j(req);
    j.beginArray();
    for (size_t i = 0; d_.dns.records().at(i, r); i++)
        j.beginObject()
            .str("name", r.name)
            .ip("ip", r.ip)
            .str("kind", r.kind == LocalRecords::Kind::Forward ? "forward" : "address")
            .endObject();
    j.endArray();
    return j.finish();
}

// action=add|remove, kind=address|forward, name, ip (add only)
esp_err_t WebServer::postRecords(httpd_req_t* req)
{
    char form[kFormMax], action[16] = "", kind[16] = "", name[64] = "", ipText[20] = "";
    if (readForm(req, form, sizeof(form)) < 0) return sendError(req, "400 Bad Request", "bad body");
    field(form, "action", action, sizeof(action));
    field(form, "kind", kind, sizeof(kind));
    field(form, "name", name, sizeof(name));
    field(form, "ip", ipText, sizeof(ipText));
    const auto k = strcmp(kind, "forward") == 0 ? LocalRecords::Kind::Forward : LocalRecords::Kind::Address;
    esp_err_t err;
    if (strcmp(action, "remove") == 0) {
        err = d_.dns.records().remove(name, k);
    } else {
        uint32_t ip = 0;
        if (!parseIp4(ipText, ip)) return sendError(req, "400 Bad Request", "a valid IPv4 address is required");
        err = d_.dns.records().add(name, ip, k);
    }
    if (err == ESP_OK && k == LocalRecords::Kind::Forward) d_.dns.flushCache();  // stale upstream answers
    switch (err) {
        case ESP_OK: return sendOk(req);
        case ESP_ERR_INVALID_ARG: return sendError(req, "400 Bad Request", "not a valid name");
        case ESP_ERR_NO_MEM: return sendError(req, "409 Conflict", "no room for more local names");
        case ESP_ERR_NOT_FOUND: return sendError(req, "404 Not Found", "no such entry");
        default: return sendError(req, "500 Internal Server Error", esp_err_to_name(err));
    }
}

esp_err_t WebServer::postLists(httpd_req_t* req)
{
    char form[kFormMax], action[16], list[16], domain[128];
    if (readForm(req, form, sizeof(form)) < 0) return sendError(req, "400 Bad Request", "bad body");
    if (!field(form, "action", action, sizeof(action)) || !field(form, "list", list, sizeof(list)) ||
        !field(form, "domain", domain, sizeof(domain)))
        return sendError(req, "400 Bad Request", "action, list and domain are required");

    DomainList& target = strcmp(list, "allow") == 0 ? d_.allow : d_.custom;
    esp_err_t err = strcmp(action, "remove") == 0 ? target.remove(domain) : target.add(domain);
    switch (err) {
        case ESP_OK: return sendOk(req);
        case ESP_ERR_INVALID_ARG: return sendError(req, "400 Bad Request", "not a valid domain");
        case ESP_ERR_NO_MEM: return sendError(req, "409 Conflict", "list is full");
        case ESP_ERR_INVALID_STATE: return sendError(req, "409 Conflict", "already in the list");
        case ESP_ERR_NOT_FOUND: return sendError(req, "404 Not Found", "not in the list");
        default: return sendError(req, "500 Internal Server Error", esp_err_to_name(err));
    }
}

esp_err_t WebServer::postBlocking(httpd_req_t* req)
{
    char form[kFormMax], mode[16], minutes[16] = "0";
    if (readForm(req, form, sizeof(form)) < 0 || !field(form, "mode", mode, sizeof(mode)))
        return sendError(req, "400 Bad Request", "mode is required");
    field(form, "minutes", minutes, sizeof(minutes));

    if (strcmp(mode, "pause") == 0) {
        uint32_t m = static_cast<uint32_t>(strtoul(minutes, nullptr, 10));
        if (m == 0 || m > 24 * 60) return sendError(req, "400 Bad Request", "minutes: 1..1440");
        d_.filter.pauseFor(m * 60);
    } else {
        const bool on = strcmp(mode, "on") == 0;
        if (d_.cfg.modify([on](Settings& s) { s.blocking = on; }) != ESP_OK) return sendNotSaved(req);
        d_.filter.setEnabled(on);
    }
    return sendOk(req);
}

esp_err_t WebServer::postBan(httpd_req_t* req)
{
    char form[kFormMax], ipStr[20], banned[4] = "1";
    uint32_t ip = 0;
    if (readForm(req, form, sizeof(form)) < 0 || !field(form, "ip", ipStr, sizeof(ipStr)) ||
        !parseIp4(ipStr, ip))
        return sendError(req, "400 Bad Request", "valid ip is required");
    // nofilter=1/0: per-device "no blocking" rule; otherwise banned=1/0.
    char nofilter[4] = "";
    esp_err_t err;
    if (field(form, "nofilter", nofilter, sizeof(nofilter))) {
        err = d_.clients.setNoFilter(ip, nofilter[0] == '1');
    } else {
        field(form, "banned", banned, sizeof(banned));
        err = d_.clients.setBanned(ip, banned[0] == '1');
    }
    return err == ESP_OK ? sendOk(req) : sendError(req, "409 Conflict", "the list is full");
}

esp_err_t WebServer::getSettings(httpd_req_t* req)
{
    const Settings s = d_.cfg.get();
    JsonWriter j(req);
    // Passwords are never sent back; an empty password field means "keep".
    j.beginObject()
        .str("hostname", s.hostname)
        .str("staSsid", s.staSsid)
        .str("apSsid", s.apSsid)
        .boolean("apAlways", s.apAlways)
        .str("adminUser", s.adminUser)
        .str("upstreamMode", upstreamModeName(s.upstreamMode))
        .ip("upstreamIp", s.upstreamIp)
        .ip("backupIp", s.upstreamIp2)
        .boolean("dotAvailable", DotProxy::available())
        .boolean("notifyAvailable", d_.notifier != nullptr)
        .str("chip", CONFIG_IDF_TARGET)
        .str("ledKind", s.ledKind == 2 ? "rgb" : s.ledKind == 1 ? "plain" : "off")
        .num("ledPin", s.ledPin)
        .boolean("ledLow", s.ledActiveLow)
        .num("ledBrightness", s.ledBrightness)
        .boolean("dot", s.dot)
        .str("dotHost", s.dotHost)
        .boolean("guardCanary", s.bypassGuard & 1)
        .boolean("guardEncrypted", s.bypassGuard & 2)
        .boolean("cnameCheck", s.cnameCheck)
        .num("privacy", s.privacy)
        .num("rateLimit", s.rateLimit)
        .boolean("safeGoogle", s.safeSearch & 1)
        .boolean("safeBing", s.safeSearch & 2)
        .str("safeYoutube", (s.safeSearch & 8) ? "strict" : (s.safeSearch & 4) ? "moderate" : "off")
        .str("blocklistUrl", s.blocklistUrl)
        .num("updateHours", s.updateHours)
        .str("mqttUri", s.mqttUri)
        .str("mqttUser", s.mqttUser)
        .str("mqttPrefix", s.mqttPrefix)
        .boolean("haDiscovery", s.haDiscovery)
        .str("txPower", s.txPower == TxFull ? "full" : s.txPower == TxReduced ? "reduced" : "auto")
        .str("fwManifestUrl", s.fwManifestUrl)
        .boolean("fwAuto", s.fwAuto)
        .str("ipMode", s.staticIp ? "static" : "dhcp")
        // Static values when set, otherwise what DHCP handed out (handy defaults).
        .ip("ipAddr", s.staticIp ? s.ipAddr : d_.wifi.staIp())
        .ip("ipMask", s.staticIp ? s.ipMask : d_.wifi.staNetmask())
        .ip("ipGw", s.staticIp ? s.ipGw : d_.wifi.gateway())
        .ip("ipDns", s.staticIp ? s.ipDns : d_.wifi.staDns())
        .boolean("dhcpServer", s.dhcpServer)
        .ip("dhcpFirst", s.dhcpFirst)
        .ip("dhcpLast", s.dhcpLast)
        .num("dhcpLease", s.dhcpLeaseMinutes)
        .endObject();
    return j.finish();
}

esp_err_t WebServer::postSettings(httpd_req_t* req)
{
    char form[kFormMax], section[16];
    if (readForm(req, form, sizeof(form)) < 0 || !field(form, "section", section, sizeof(section)))
        return sendError(req, "400 Bad Request", "section is required");

    char a[260] = "", b[80] = "", c[80] = "", e[64] = "";

    if (strcmp(section, "wifi") == 0) {
        if (!field(form, "ssid", a, 33) || !a[0]) return sendError(req, "400 Bad Request", "ssid is required");
        field(form, "pass", b, 65);
        d_.wifi.setStation(a, b);
        return sendOk(req, "connecting to the new network");
    }
    if (strcmp(section, "ap") == 0) {
        field(form, "ssid", a, 33);
        field(form, "pass", b, 65);
        field(form, "always", c, 4);
        if (b[0] && strlen(b) < 8) return sendError(req, "400 Bad Request", "AP password needs 8+ characters");
        if (d_.cfg.modify([&](Settings& s) {
            copyStr(s.apSsid, a);
            if (b[0]) copyStr(s.apPass, b);
            s.apAlways = c[0] != '0';
        }) != ESP_OK) return sendNotSaved(req);
        d_.wifi.applyAccessPoint();
        return sendOk(req, "access point updated; reconnect to it if you were using it");
    }
    if (strcmp(section, "admin") == 0) {
        field(form, "user", a, 32);
        field(form, "pass", b, 64);
        if (!a[0] || strlen(b) < 8) return sendError(req, "400 Bad Request", "user and an 8+ character password are required");
        const esp_err_t err = d_.cfg.setAdmin(a, b);
        secureWipe(b, sizeof(b));
        if (err != ESP_OK) return sendError(req, "500 Internal Server Error", "could not save the new password");
        forgetLogins();
        return sendOk(req, "credentials changed; log in again");
    }
    if (strcmp(section, "dns") == 0) {
        field(form, "mode", a, 16);
        field(form, "ip", b, 20);
        UpstreamMode mode = strcmp(a, "router") == 0   ? UpstreamMode::Router
                            : strcmp(a, "custom") == 0 ? UpstreamMode::Custom
                                                       : UpstreamMode::Builtin;
        uint32_t ip = 0, backup = 0;
        if (mode == UpstreamMode::Custom && !parseIp4(b, ip))
            return sendError(req, "400 Bad Request", "custom mode needs a valid IPv4 address");
        if (field(form, "backup", c, 20) && c[0] && !parseIp4(c, backup))
            return sendError(req, "400 Bad Request", "invalid backup address");
        char dot[4] = "", dotHost[64] = "";
        field(form, "dot", dot, sizeof(dot));
        field(form, "dotHost", dotHost, sizeof(dotHost));
        const bool dotOn = dot[0] == '1' && DotProxy::available();
        if (dotOn) {
            bool okHost = dotHost[0] != '\0' && strchr(dotHost, '.') != nullptr;
            for (const char* h = dotHost; *h && okHost; h++)
                okHost = isalnum(static_cast<unsigned char>(*h)) || *h == '.' || *h == '-';
            if (!okHost) return sendError(req, "400 Bad Request", "DNS over TLS needs a server name, e.g. dns.quad9.net");
        }
        if (d_.cfg.modify([&](Settings& s) {
            s.upstreamMode = mode;
            if (ip) s.upstreamIp = ip;
            s.upstreamIp2 = backup;  // empty field = no backup
            s.dot = dotOn;
            if (dotHost[0]) copyStr(s.dotHost, dotHost);
        }) != ESP_OK) return sendNotSaved(req);
        if (d_.applyUpstream) d_.applyUpstream(d_.appCtx);
        return sendOk(req);
    }
    if (strcmp(section, "led") == 0) {
        // kind=off|plain|rgb, pin, low=1 (active low), brightness 1..255, test=1
        char kind[8] = "", pin[8] = "", low[4] = "", bright[8] = "", test[4] = "";
        field(form, "kind", kind, sizeof(kind));
        field(form, "pin", pin, sizeof(pin));
        field(form, "low", low, sizeof(low));
        field(form, "brightness", bright, sizeof(bright));
        field(form, "test", test, sizeof(test));
        const auto k = strcmp(kind, "rgb") == 0     ? StatusLed::Kind::Rgb
                       : strcmp(kind, "plain") == 0 ? StatusLed::Kind::Plain
                                                    : StatusLed::Kind::Off;
        const int gpio = pin[0] ? atoi(pin) : -1;
        const unsigned long br = strtoul(bright, nullptr, 10);
        const uint8_t level = static_cast<uint8_t>(br < 1 ? 24 : br > 255 ? 255 : br);
        if (d_.led.configure(k, gpio, low[0] == '1', level) != ESP_OK)
            return sendError(req, "400 Bad Request", "this pin can't drive an LED (used by flash/PSRAM or not an output)");
        if (d_.cfg.modify([&](Settings& s) {
            s.ledKind = static_cast<uint8_t>(k);
            s.ledPin = static_cast<int8_t>(gpio);
            s.ledActiveLow = low[0] == '1';
            s.ledBrightness = level;
        }) != ESP_OK) return sendNotSaved(req);
        if (test[0] == '1' && k != StatusLed::Kind::Off) d_.led.test();
        return sendOk(req);
    }
    if (strcmp(section, "guard") == 0) {
        field(form, "canary", a, 4);
        field(form, "encrypted", b, 4);
        field(form, "cname", c, 4);
        const uint8_t flags = static_cast<uint8_t>((a[0] == '1' ? 1 : 0) | (b[0] == '1' ? 2 : 0));
        const bool cname = c[0] == '1';
        if (d_.cfg.modify([&](Settings& s) {
            s.bypassGuard = flags;
            s.cnameCheck = cname;
        }) != ESP_OK) return sendNotSaved(req);
        d_.dns.setGuard(flags);
        d_.dns.setCnameCheck(cname);
        // SafeSearch: google=1, bing=1, youtube=off|moderate|strict
        char g[4] = "", bi[4] = "", yt[16] = "";
        field(form, "google", g, sizeof(g));
        field(form, "bing", bi, sizeof(bi));
        field(form, "youtube", yt, sizeof(yt));
        const uint8_t ss = static_cast<uint8_t>((g[0] == '1' ? 1 : 0) | (bi[0] == '1' ? 2 : 0) |
                                                (strcmp(yt, "moderate") == 0 ? 4 : 0) | (strcmp(yt, "strict") == 0 ? 8 : 0));
        char pv[4] = "", rate[8] = "";
        field(form, "privacy", pv, sizeof(pv));
        const bool hasRate = field(form, "rate", rate, sizeof(rate));
        const unsigned long rl = strtoul(rate, nullptr, 10);
        const uint16_t perMin = static_cast<uint16_t>(rl > 60000 ? 60000 : rl);
        const uint8_t privacy = static_cast<uint8_t>(pv[0] == '2' ? 2 : pv[0] == '1' ? 1 : 0);
        if (d_.cfg.modify([&](Settings& s) {
            s.safeSearch = ss;
            s.privacy = privacy;
            if (hasRate) s.rateLimit = perMin;
        }) != ESP_OK) return sendNotSaved(req);
        if (hasRate) d_.dns.setRateLimit(perMin);
        d_.dns.setSafeSearch(ss);
        d_.log.setPrivacy(privacy);
        return sendOk(req);
    }
    if (strcmp(section, "update") == 0) {
        field(form, "url", a, sizeof(a));
        field(form, "hours", b, 8);
        if (a[0] && strncmp(a, "https://", 8) != 0 && strncmp(a, "http://", 7) != 0)  // NOSONAR http:// allowed for LAN mirrors; lists are SHA-256/signature checked, firmware auto-install needs a signed build
            return sendError(req, "400 Bad Request", "URL must start with https://");
        const unsigned long hours = strtoul(b, nullptr, 10);
        if (d_.cfg.modify([&](Settings& s) {
            copyStr(s.blocklistUrl, a);
            s.updateHours = static_cast<uint16_t>(hours > 720 ? 720 : hours);
        }) != ESP_OK) return sendNotSaved(req);
        return sendOk(req);
    }
    if (strcmp(section, "mqtt") == 0) {
        field(form, "uri", a, 128);
        field(form, "user", b, 64);
        field(form, "pass", c, 64);
        field(form, "prefix", e, 48);
        char ha[4] = "";
        field(form, "ha", ha, sizeof(ha));
        if (d_.cfg.modify([&](Settings& s) {
            s.haDiscovery = ha[0] == '1';
            copyStr(s.mqttUri, a);
            copyStr(s.mqttUser, b);
            if (c[0]) copyStr(s.mqttPass, c);
            copyStr(s.mqttPrefix, e[0] ? e : "sinkhole");
        }) != ESP_OK) return sendNotSaved(req);
        return sendOk(req, "saved; reboot to apply");
    }
    if (strcmp(section, "fw") == 0) {
        field(form, "url", a, sizeof(Settings::fwManifestUrl));
        field(form, "auto", b, 4);
        if (a[0] && strncmp(a, "https://", 8) != 0 && strncmp(a, "http://", 7) != 0)  // NOSONAR http:// allowed for LAN mirrors; lists are SHA-256/signature checked, firmware auto-install needs a signed build
            return sendError(req, "400 Bad Request", "URL must start with https://");
        const bool autoOn = b[0] == '1';
        if (autoOn && !Updater::autoInstallAllowed())
            return sendError(req, "400 Bad Request", "automatic install needs a signed firmware build");
        if (d_.cfg.modify([&](Settings& s) {
            copyStr(s.fwManifestUrl, a);
            s.fwAuto = autoOn;
        }) != ESP_OK) return sendNotSaved(req);
        return sendOk(req);
    }
    if (strcmp(section, "radio") == 0) {
        field(form, "tx", a, 16);
        const uint8_t mode = strcmp(a, "full") == 0 ? TxFull : strcmp(a, "reduced") == 0 ? TxReduced : TxAuto;
        if (d_.cfg.modify([mode](Settings& s) { s.txPower = mode; }) != ESP_OK) return sendNotSaved(req);
        d_.wifi.applyTxPower();
        return sendOk(req);
    }
    if (strcmp(section, "dhcp") == 0) {
        // enabled=1, first, last (IPv4 in this device's subnet), lease (minutes)
        field(form, "enabled", a, 4);
        field(form, "first", b, 20);
        field(form, "last", c, 20);
        field(form, "lease", e, 8);
        const bool on = a[0] == '1';
        uint32_t first = 0, last = 0;
        const unsigned long lease = strtoul(e, nullptr, 10);
        const auto net = d_.cfg.read([](const Settings& s) {
            struct { bool st; uint32_t ip, mask, gw; } r{s.staticIp, s.ipAddr, s.ipMask, s.ipGw};
            return r;
        });
        if (on) {
            if (!net.st) return sendError(req, "400 Bad Request", "set a static IP for this device first");
            if (!parseIp4(b, first) || !parseIp4(c, last)) return sendError(req, "400 Bad Request", "invalid pool addresses");
            if (const char* why = LanDhcp::checkPool({net.ip, net.mask, net.gw, first, last, 0}))
                return sendError(req, "400 Bad Request", why);
        }
        if (d_.cfg.modify([&](Settings& s) {
            s.dhcpServer = on;
            if (first) s.dhcpFirst = first;
            if (last) s.dhcpLast = last;
            if (lease) s.dhcpLeaseMinutes = static_cast<uint16_t>(lease < 5 ? 5 : lease > 10080 ? 10080 : lease);
        }) != ESP_OK) return sendNotSaved(req);
        if (d_.applyUpstream) d_.applyUpstream(d_.appCtx);  // applies the DHCP server too
        return sendOk(req);
    }
    if (strcmp(section, "ip") == 0) {
        field(form, "mode", a, 16);
        if (strcmp(a, "static") != 0) {
            if (d_.cfg.modify([](Settings& s) { s.staticIp = false; }) != ESP_OK) return sendNotSaved(req);
            d_.wifi.reconfigureStation();
            return sendOk(req, "switched to DHCP; the address may change");
        }
        char ipS[20] = "", maskS[20] = "", gwS[20] = "", dnsS[20] = "";
        field(form, "ip", ipS, sizeof(ipS));
        field(form, "mask", maskS, sizeof(maskS));
        field(form, "gw", gwS, sizeof(gwS));
        field(form, "dns", dnsS, sizeof(dnsS));
        uint32_t ip = 0, mask = 0, gw = 0, dns = 0;
        if (!parseIp4(ipS, ip) || !parseIp4(gwS, gw)) return sendError(req, "400 Bad Request", "valid IP address and gateway are required");
        in_addr m{};
        if (inet_aton(maskS, &m) == 0) return sendError(req, "400 Bad Request", "invalid netmask");
        mask = m.s_addr;
        const uint32_t hm = ntohl(mask);
        if (hm == 0 || (~hm & (~hm + 1)) != 0) return sendError(req, "400 Bad Request", "invalid netmask");
        if ((ip & mask) != (gw & mask)) return sendError(req, "400 Bad Request", "gateway is not in the same subnet");
        if (dnsS[0] && !parseIp4(dnsS, dns)) return sendError(req, "400 Bad Request", "invalid DNS server");
        if (!dns) dns = gw;  // the device itself still needs a resolver (blocklist downloads)
        if (d_.cfg.modify([&](Settings& s) {
            s.staticIp = true;
            s.ipAddr = ip;
            s.ipMask = mask;
            s.ipGw = gw;
            s.ipDns = dns;
        }) != ESP_OK) return sendNotSaved(req);
        d_.wifi.reconfigureStation();
        char msg[64];
        snprintf(msg, sizeof(msg), "static IP set; reconnecting at http://%s/", ipS);
        return sendOk(req, msg);
    }
    if (strcmp(section, "hostname") == 0) {
        if (!field(form, "hostname", a, 32) || !a[0]) return sendError(req, "400 Bad Request", "hostname is required");
        if (d_.cfg.modify([&](Settings& s) { copyStr(s.hostname, a); }) != ESP_OK) return sendNotSaved(req);
        return sendOk(req, "saved; reboot to apply");
    }
    return sendError(req, "400 Bad Request", "unknown section");
}

esp_err_t WebServer::postWifi(httpd_req_t* req)
{
    char form[kFormMax], action[16];
    if (readForm(req, form, sizeof(form)) < 0 || !field(form, "action", action, sizeof(action)))
        return sendError(req, "400 Bad Request", "action is required");
    if (strcmp(action, "reconnect") == 0) {
        if (!d_.cfg.get().staSsid[0]) return sendError(req, "409 Conflict", "no Wi-Fi network configured");
        d_.wifi.reconnect();
        return sendOk(req, "reconnecting");
    }
    if (strcmp(action, "forget") == 0) {
        d_.wifi.forgetStation();
        return sendOk(req, "Wi-Fi forgotten; the setup access point stays on");
    }
    return sendError(req, "400 Bad Request", "unknown action");
}

esp_err_t WebServer::getWifiScan(httpd_req_t* req)
{
    static ScanResult nets[WifiManager::kMaxScanResults];  // httpd task only
    size_t n = 0;
    esp_err_t err = d_.wifi.scan(nets, WifiManager::kMaxScanResults, n);
    if (err != ESP_OK) return sendError(req, "503 Service Unavailable", "scan failed, try again");
    const Settings s = d_.cfg.get();
    JsonWriter j(req);
    j.beginArray();
    for (size_t i = 0; i < n; i++) {
        j.beginObject()
            .str("ssid", nets[i].ssid)
            .num("rssi", nets[i].rssi)
            .num("channel", nets[i].channel)
            .str("auth", WifiManager::authText(nets[i].authmode))
            .boolean("secure", nets[i].authmode != WIFI_AUTH_OPEN)
            .boolean("current", strcmp(nets[i].ssid, s.staSsid) == 0)
            .endObject();
    }
    j.endArray();
    return j.finish();
}

esp_err_t WebServer::postBlocklistFetch(httpd_req_t* req)
{
    if (!d_.wifi.connected()) return sendError(req, "409 Conflict", "no uplink: join a Wi-Fi network first");
    d_.updater.fetchNow();
    return sendOk(req, "download started");
}

esp_err_t WebServer::postBlocklistUpload(httpd_req_t* req)
{
    if (req->content_len == 0) return sendError(req, "400 Bad Request", "empty body");
    if (d_.store.beginWrite() != ESP_OK)
        return sendError(req, "409 Conflict", "another blocklist update is running");

    size_t left = req->content_len;
    while (left) {
        const int n = recvBody(req, reinterpret_cast<char*>(chunk_), left < sizeof(chunk_) ? left : sizeof(chunk_));
        if (n <= 0) {
            d_.store.abortWrite();
            return ESP_FAIL;  // connection gone
        }
        if (d_.store.write(chunk_, static_cast<size_t>(n)) != ESP_OK) {
            d_.store.abortWrite();
            d_.updater.report(false, "upload: list too large or flash error", 0);
            return sendError(req, "413 Payload Too Large", "list too large for the slot or flash error");
        }
        left -= static_cast<size_t>(n);
    }

    char why[96];
    if (d_.store.finishWrite(why, sizeof(why)) != ESP_OK) {
        d_.updater.report(false, why, req->content_len);
        return sendError(req, "422 Unprocessable Entity", why);
    }
    char msg[96];
    snprintf(msg, sizeof(msg), "uploaded: %lu domains", static_cast<unsigned long>(d_.store.info().count));
    d_.updater.report(true, msg, req->content_len);
    return sendOk(req, msg);
}

esp_err_t WebServer::postFirmwareUpload(httpd_req_t* req)
{
    if (req->content_len == 0) return sendError(req, "400 Bad Request", "empty body");
    esp_err_t err = d_.firmware.begin();
    if (err != ESP_OK) return sendError(req, "409 Conflict", esp_err_to_name(err));

    size_t left = req->content_len;
    while (left) {
        const int n = recvBody(req, reinterpret_cast<char*>(chunk_), left < sizeof(chunk_) ? left : sizeof(chunk_));
        if (n <= 0) {
            d_.firmware.abort();
            return ESP_FAIL;
        }
        err = d_.firmware.write(chunk_, static_cast<size_t>(n));
        if (err != ESP_OK) {
            d_.firmware.abort();
            return sendError(req, "422 Unprocessable Entity", esp_err_to_name(err));
        }
        left -= static_cast<size_t>(n);
    }
    err = d_.firmware.finish();
    if (err != ESP_OK) {
        char msg[128];
        snprintf(msg, sizeof(msg), "image rejected (%s): %s", esp_err_to_name(err),
                 Updater::autoInstallAllowed() ? "wrong chip, corrupt, or not signed with this device's key"
                                               : "wrong chip or corrupt");
        return sendError(req, "422 Unprocessable Entity", msg);
    }
    FirmwareUpdater::restartIn(1500, BootLog::Cause::FirmwareUpload);
    return sendOk(req, "firmware accepted, rebooting");
}

esp_err_t WebServer::postFirmwareCheck(httpd_req_t* req)
{
    if (!d_.wifi.connected()) return sendError(req, "409 Conflict", "no uplink: join a Wi-Fi network first");
    if (!d_.cfg.read([](const Settings& s) { return s.fwManifestUrl[0] != '\0'; }))
        return sendError(req, "409 Conflict", "no update manifest URL configured");
    d_.updater.checkFirmwareNow();
    return sendOk(req, "checking for updates");
}

esp_err_t WebServer::postFirmwareInstall(httpd_req_t* req)
{
    esp_err_t err = d_.updater.installFirmwareNow();
    if (err == ESP_ERR_NOT_FOUND) return sendError(req, "409 Conflict", "no update available; check first");
    if (err != ESP_OK) return sendError(req, "409 Conflict", "an installation is already running");
    return sendOk(req, "installing; the device restarts when done");
}

esp_err_t WebServer::postReboot(httpd_req_t* req)
{
    FirmwareUpdater::restartIn(1000, BootLog::Cause::WebRestart);
    return sendOk(req, "rebooting");
}

namespace {
bool hasMac(const ClientInfo& c)
{
    static constexpr std::array<uint8_t, 6> kZero{};
    return memcmp(c.mac, kZero.data(), kZero.size()) != 0;
}
}  // namespace

const char* WebServer::clientName(const ClientInfo& c, char* out, size_t cap)
{
    if (hasMac(c) && d_.names.find(c.mac, out, cap)) return "you";
    if (!c.addr.v6) {
        uint32_t ip;
        memcpy(&ip, c.addr.a, 4);
        LocalRecords::Record r;
        for (size_t i = 0; d_.dns.records().at(i, r); i++) {
            if (r.kind == LocalRecords::Kind::Address && r.ip == ip) {
                copyStr(out, cap, r.name);
                return "dns";
            }
        }
    }
    if (hasMac(c) && d_.dhcp.hostname(c.mac, out, cap)) return "dhcp";
    return nullptr;
}

void WebServer::snapshotNames()
{
    const size_t n = d_.clients.snapshot(sClientSnap, ClientTable::kCapacity);
    namedCount_ = 0;
    for (size_t i = 0; i < n; i++) {
        NamedClient& nc = named_[namedCount_];
        if (clientName(sClientSnap[i], nc.name.data(), nc.name.size())) {
            nc.addr = sClientSnap[i].addr;
            namedCount_++;
        }
    }
}

const char* WebServer::nameOf(const ClientAddr& a)
{
    for (size_t i = 0; i < namedCount_; i++)
        if (named_[i].addr.v6 == a.v6 && memcmp(named_[i].addr.a, a.a, a.v6 ? 16 : 4) == 0) return named_[i].name.data();
    return "";
}

// mac=aa:bb:..., name= (empty forgets it)
esp_err_t WebServer::postNames(httpd_req_t* req)
{
    std::array<char, kFormMax> form{};
    std::array<char, 48> macStr{};  // "aa%3Abb%3A..." as browsers send it: 27+ before decoding
    std::array<char, 64> name{};
    if (readForm(req, form.data(), form.size()) < 0) return sendError(req, "400 Bad Request", "bad body");
    field(form.data(), "mac", macStr.data(), macStr.size());
    field(form.data(), "name", name.data(), name.size());
    std::array<uint8_t, 6> mac{};
    if (!parseMac(macStr.data(), mac.data())) return sendError(req, "400 Bad Request", "valid MAC required");
    switch (d_.names.set(mac.data(), name.data())) {
        case ESP_OK: return sendOk(req);
        case ESP_ERR_INVALID_ARG: return sendError(req, "400 Bad Request", "name: 1 to 25 characters, no < > \" &");
        case ESP_ERR_NO_MEM: return sendError(req, "409 Conflict", "no room for more names");
        default: return sendError(req, "500 Internal Server Error", "could not save");
    }
}

#if CONFIG_SINKHOLE_NOTIFY
namespace {
bool safeToken(const char* s, size_t maxLen, bool allowEmpty)
{
    const size_t n = strnlen(s, maxLen + 1);
    if (n == 0) return allowEmpty;
    if (n > maxLen) return false;
    for (size_t i = 0; i < n; i++) {
        const auto c = static_cast<unsigned char>(s[i]);
        if (c <= ' ' || c >= 0x7f || c == '/' || c == '?' || c == '#' || c == '&') return false;
    }
    return true;
}

void channelJson(JsonWriter& j, const char* key, const Notifier::ChannelStatus& c, uint32_t now)
{
    j.beginObject(key)
        .boolean("configured", c.configured)
        .boolean("ok", c.lastOk)
        .num("ago", c.lastAt ? static_cast<int64_t>(now - c.lastAt) : -1)
        .str("error", c.error.data())
        .endObject();
}
}  // namespace

// Notification settings (tokens are never sent back) and how sending went.
esp_err_t WebServer::getNotify(httpd_req_t* req)
{
    static NotifySettings s;  // httpd task only
    d_.cfg.readNotify([](const NotifySettings& c) {
        s = c;
        return 0;
    });
    const Notifier::Status st = d_.notifier->status();
    const uint32_t now = uptimeSeconds();
    JsonWriter j(req);
    j.beginObject()
        .str("ntfyServer", s.ntfyServer)
        .str("ntfyTopic", s.ntfyTopic)
        .boolean("ntfyTokenSet", s.ntfyToken[0] != '\0')
        .boolean("tgTokenSet", s.tgToken[0] != '\0')
        .str("tgChat", s.tgChat)
        .num("events", s.notifyEvents)
        .boolean("commands", s.notifyCommands);
    channelJson(j, "ntfy", st.ntfy, now);
    channelJson(j, "telegram", st.telegram, now);
    j.str("lastCommand", st.lastCommand.data())
        .num("lastCommandAgo", st.lastCommandAt ? static_cast<int64_t>(now - st.lastCommandAt) : -1)
        .num("dropped", st.dropped)
        .endObject();
    return j.finish();
}

namespace {
// The save form's fields; nullptr when they are fine, else what to show.
const char* notifyFormError(const char* server, const char* topic, const char* token, const char* tgToken,
                            const char* tgChat)
{
    if (server[0] && strncmp(server, "https://", 8) != 0 && strncmp(server, "http://", 7) != 0)  // NOSONAR http:// for a self-hosted ntfy on the LAN
        return "ntfy server must start with https://";
    if (!safeToken(topic, sizeof(NotifySettings::ntfyTopic) - 5, true))  // room for "-cmd"
        return "topic: letters, digits, - and _ only (up to 34)";
    if (!safeToken(token, sizeof(NotifySettings::ntfyToken) - 1, true) ||
        !safeToken(tgToken, sizeof(NotifySettings::tgToken) - 1, true))
        return "token has characters that can't be right";
    bool chatOk = true;
    for (size_t i = 0; tgChat[i]; i++) chatOk &= isdigit(static_cast<unsigned char>(tgChat[i])) || (i == 0 && tgChat[i] == '-');
    if (!chatOk || strnlen(tgChat, sizeof(NotifySettings::tgChat)) >= sizeof(NotifySettings::tgChat))
        return "chat ID: digits only (use Find)";
    return nullptr;
}
}  // namespace

// action=save (server, topic, token, tgToken, tgChat, events, commands;
// empty token = keep, clearNtfyToken=1 / clearTgToken=1 remove), action=test,
// action=findchat (Telegram chat that last wrote to the bot).
esp_err_t WebServer::postNotify(httpd_req_t* req)
{
    static std::array<char, kFormMax> form;  // httpd task only
    std::array<char, 16> action{};
    if (readForm(req, form.data(), form.size()) < 0 || !field(form.data(), "action", action.data(), action.size()))
        return sendError(req, "400 Bad Request", "action is required");
    if (strcmp(action.data(), "test") == 0) {
        d_.notifier->test();
        return sendOk(req, "test sent");
    }
    if (strcmp(action.data(), "findchat") == 0) {
        std::array<char, 24> chat{};
        std::array<char, 40> name{};
        const esp_err_t err = d_.notifier->findTelegramChat(chat.data(), chat.size(), name.data(), name.size());
        if (err == ESP_ERR_INVALID_STATE) return sendError(req, "409 Conflict", "save the bot token first");
        if (err == ESP_ERR_INVALID_ARG) return sendError(req, "400 Bad Request", "bot token not accepted");
        if (err == ESP_ERR_NOT_FOUND) return sendError(req, "404 Not Found", "no message yet: send /start to your bot, then try again");
        if (err != ESP_OK) return sendError(req, "502 Bad Gateway", "could not reach Telegram");
        JsonWriter j(req);
        j.beginObject().boolean("ok", true).str("chat", chat.data()).str("name", name.data()).endObject();
        return j.finish();
    }
    if (strcmp(action.data(), "save") != 0) return sendError(req, "400 Bad Request", "unknown action");
    std::array<char, 64> server{};
    std::array<char, 48> topic{};
    std::array<char, 72> token{};
    std::array<char, 72> tgToken{};
    std::array<char, 32> tgChat{};
    std::array<char, 8> ev{};
    std::array<char, 4> cmds{};
    std::array<char, 4> clearN{};
    std::array<char, 4> clearT{};
    field(form.data(), "server", server.data(), server.size());
    field(form.data(), "topic", topic.data(), topic.size());
    field(form.data(), "token", token.data(), token.size());
    field(form.data(), "tgToken", tgToken.data(), tgToken.size());
    field(form.data(), "tgChat", tgChat.data(), tgChat.size());
    field(form.data(), "events", ev.data(), ev.size());
    field(form.data(), "commands", cmds.data(), cmds.size());
    field(form.data(), "clearNtfyToken", clearN.data(), clearN.size());
    field(form.data(), "clearTgToken", clearT.data(), clearT.size());
    // Tokens are wiped from these stack buffers on every way out.
    const auto wipe = [&token, &tgToken] {  // form is static: used directly
        secureWipe(token.data(), token.size());
        secureWipe(tgToken.data(), tgToken.size());
        secureWipe(form.data(), form.size());
    };
    if (const char* bad = notifyFormError(server.data(), topic.data(), token.data(), tgToken.data(), tgChat.data())) {
        wipe();
        return sendError(req, "400 Bad Request", bad);
    }
    const auto evMask = static_cast<uint16_t>(strtoul(ev.data(), nullptr, 10) & events::kAllKinds);
    const esp_err_t saved = d_.cfg.modifyNotify([&](NotifySettings& s) {
        copyStr(s.ntfyServer, server[0] ? server.data() : "https://ntfy.sh");
        copyStr(s.ntfyTopic, topic.data());
        if (token[0]) copyStr(s.ntfyToken, token.data());
        if (clearN[0] == '1') memset(s.ntfyToken, 0, sizeof(s.ntfyToken));
        if (tgToken[0]) copyStr(s.tgToken, tgToken.data());
        if (clearT[0] == '1') memset(s.tgToken, 0, sizeof(s.tgToken));
        copyStr(s.tgChat, tgChat.data());
        s.notifyEvents = evMask;
        s.notifyCommands = cmds[0] == '1';
    });
    wipe();
    if (saved != ESP_OK) return sendNotSaved(req);
    d_.notifier->reload();
    return sendOk(req);
}
#endif

// GET /api/logs?from=N: the device log since position N (0 = all that is kept),
// as plain text. X-Log-Next is the position to ask from next time; X-Log-Start
// says where the text begins (> N when older lines were already overwritten).
esp_err_t WebServer::getLogs(httpd_req_t* req)
{
    std::array<char, 32> q{};
    std::array<char, 16> v{};
    uint32_t from = 0;
    if (httpd_req_get_url_query_str(req, q.data(), q.size()) == ESP_OK &&
        httpd_query_key_value(q.data(), "from", v.data(), v.size()) == ESP_OK)
        from = static_cast<uint32_t>(strtoul(v.data(), nullptr, 10));
    // Stop at the end as it is now, so a busy log can't keep the response going.
    uint32_t until = LogBuffer::end();
    auto* buf = reinterpret_cast<char*>(chunk_);
    LogBuffer::Chunk c = LogBuffer::read(from, buf, sizeof(chunk_));
    if (c.next > until) until = c.next;  // a line arrived in between
    std::array<char, 12> start{};
    std::array<char, 12> next{};
    std::array<char, 12> size{};
    snprintf(start.data(), start.size(), "%lu", static_cast<unsigned long>(c.start));
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    httpd_resp_set_hdr(req, "X-Log-Start", start.data());
    snprintf(size.data(), size.size(), "%u", static_cast<unsigned>(LogBuffer::capacity()));
    httpd_resp_set_hdr(req, "X-Log-Size", size.data());
    // The end position goes in a header, sent before the body: compute it first
    // from `until` (what this response will cover).
    snprintf(next.data(), next.size(), "%lu", static_cast<unsigned long>(until > c.start ? until : c.start));
    httpd_resp_set_hdr(req, "X-Log-Next", next.data());
    while (c.len) {
        if (httpd_resp_send_chunk(req, buf, static_cast<ssize_t>(c.len)) != ESP_OK) return ESP_FAIL;
        if (c.next >= until) break;
        const size_t want = until - c.next < sizeof(chunk_) ? until - c.next : sizeof(chunk_);
        c = LogBuffer::read(c.next, buf, want);
    }
    return httpd_resp_send_chunk(req, nullptr, 0);
}

// Last restarts, newest first (the first one is this boot).
esp_err_t WebServer::getRestarts(httpd_req_t* req)
{
    static std::array<BootLog::Record, BootLog::kRecords> recs;  // httpd task only
    const size_t n = BootLog::list(recs.data(), recs.size());
    JsonWriter j(req);
    j.beginObject().num("time", BootLog::now()).beginArray("items");
    for (size_t i = 0; i < n; i++) {
        j.beginObject()
            .num("at", recs[i].bootUnix)
            .num("ranFor", recs[i].ranFor)
            .str("why", BootLog::why(recs[i]))
            .boolean("unexpected", BootLog::unexpected(recs[i]))
            .str("version", recs[i].version)
            .endObject();
    }
    j.endArray().endObject();
    return j.finish();
}

esp_err_t WebServer::getWol(httpd_req_t* req)
{
    static WolHostState snap[WolService::kCapacity];  // httpd task only
    const size_t n = d_.wol.list(snap, WolService::kCapacity);
    const uint32_t now = uptimeSeconds();
    JsonWriter j(req);
    j.beginArray();
    for (size_t i = 0; i < n; i++) {
        j.beginObject()
            .str("name", snap[i].host.name)
            .mac("mac", snap[i].host.mac)
            .ip("ip", snap[i].host.ip)
            .boolean("online", snap[i].online)
            .num("port", snap[i].host.port)
            .num("timeout", WolService::timeoutOf(snap[i].host))
            .boolean("watch", watchOnly(snap[i].host))
            .boolean("alert", (snap[i].host.flags & kWolAlert) != 0)
            .boolean("known", snap[i].known)
            .num("stateAgo", snap[i].known ? static_cast<int64_t>(now - snap[i].stateSince) : -1)
            .boolean("waking", snap[i].waking)
            .num("wakeLeft", snap[i].waking && snap[i].wakeDeadline > now ? snap[i].wakeDeadline - now : 0)
            .str("result", snap[i].result)
            .num("resultAgo", snap[i].resultAt ? static_cast<int64_t>(now - snap[i].resultAt) : -1)
            .num("wokeAgo", snap[i].lastWake ? static_cast<int64_t>(now - snap[i].lastWake) : -1)
            .endObject();
    }
    j.endArray();
    return j.finish();
}

// action=add: name, mac (empty = watch only), ip, port, timeout (seconds),
// alert (1 = tell the owner when it goes offline / comes back) from the form.
esp_err_t WebServer::addWolHost(httpd_req_t* req, const char* form)
{
    std::array<char, 32> name{};
    std::array<char, 48> mac{};  // "aa%3Abb%3A..." as browsers send it: 27+ before decoding
    std::array<char, 20> ip{};
    std::array<char, 8> port{};
    std::array<char, 8> wait{};
    std::array<char, 4> alert{};
    field(form, "name", name.data(), name.size());
    field(form, "alert", alert.data(), alert.size());
    field(form, "mac", mac.data(), mac.size());
    field(form, "ip", ip.data(), ip.size());
    field(form, "port", port.data(), port.size());
    field(form, "timeout", wait.data(), wait.size());
    WolHost h{};
    copyStr(h.name, name.data());
    if (mac[0] && !parseMac(mac.data(), h.mac)) return sendError(req, "400 Bad Request", "invalid MAC");
    if (ip[0] && !parseIp4(ip.data(), h.ip)) return sendError(req, "400 Bad Request", "invalid IP");
    if (!h.ip && watchOnly(h)) return sendError(req, "400 Bad Request", "a MAC to wake it, or an IP to watch it");
    if (alert[0] == '1' && !h.ip) return sendError(req, "400 Bad Request", "alerts need the IP");
    if (alert[0] == '1') h.flags |= kWolAlert;
    const unsigned long p = strtoul(port.data(), nullptr, 10);
    if (p > 65535) return sendError(req, "400 Bad Request", "invalid port");
    if (p && !h.ip) return sendError(req, "400 Bad Request", "a port check needs the IP");
    h.port = static_cast<uint16_t>(p);
    const unsigned long w = strtoul(wait.data(), nullptr, 10);  // seconds, empty = default
    if (w && (w < 30 || w > 3600)) return sendError(req, "400 Bad Request", "wait: 30 s to 60 min");
    h.timeout = static_cast<uint16_t>(w);
    const esp_err_t err = d_.wol.add(h);
    if (err == ESP_ERR_INVALID_ARG) return sendError(req, "400 Bad Request", "name: no spaces, quotes, '/', '+', '#' or '\\'");
    if (err == ESP_ERR_NO_MEM) return sendError(req, "409 Conflict", "host list is full");
    return sendOk(req);
}

esp_err_t WebServer::postWol(httpd_req_t* req)
{
    static std::array<char, kFormMax> form;  // httpd task only
    std::array<char, 16> action{};
    std::array<char, 32> name{};
    std::array<char, 48> mac{};
    if (readForm(req, form.data(), form.size()) < 0 || !field(form.data(), "action", action.data(), action.size()))
        return sendError(req, "400 Bad Request", "action is required");
    field(form.data(), "name", name.data(), name.size());
    if (strcmp(action.data(), "add") == 0) return addWolHost(req, form.data());
    if (strcmp(action.data(), "wake") == 0) {
        if (name[0]) {
            bool verifying = false;
            const esp_err_t err = d_.wol.wakeAndVerify(name.data(), &verifying);
            if (err == ESP_ERR_INVALID_STATE) return sendOk(req, "already online");
            if (err == ESP_ERR_NOT_FOUND) return sendError(req, "404 Not Found", "unknown host");
            if (err == ESP_ERR_NOT_SUPPORTED) return sendError(req, "409 Conflict", "watch-only: no MAC to wake");
            if (err != ESP_OK) return sendError(req, "500 Internal Server Error", "send failed");
            return sendOk(req, verifying ? "waking; checking until it answers" : "magic packet sent");
        }
        std::array<uint8_t, 6> raw{};
        field(form.data(), "mac", mac.data(), mac.size());
        if (!parseMac(mac.data(), raw.data())) return sendError(req, "400 Bad Request", "name or mac required");
        return d_.wol.wakeMac(raw.data()) == ESP_OK ? sendOk(req, "magic packet sent")
                                                     : sendError(req, "500 Internal Server Error", "send failed");
    }
    if (strcmp(action.data(), "remove") == 0)
        return d_.wol.remove(name.data()) == ESP_OK ? sendOk(req) : sendError(req, "404 Not Found", "unknown host");
    if (strcmp(action.data(), "cancel") == 0) {
        const esp_err_t err = d_.wol.cancel(name.data());
        if (err == ESP_ERR_NOT_FOUND) return sendError(req, "404 Not Found", "unknown host");
        return sendOk(req, err == ESP_OK ? "cancelled" : "not waking");
    }
    return sendError(req, "400 Bad Request", "unknown action");
}

}  // namespace sinkhole
