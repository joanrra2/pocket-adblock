#include "sinkhole/web_server.hpp"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_system.h"
#include "lwip/inet.h"
#include "sinkhole/json_writer.hpp"
#include "sinkhole/memory.hpp"
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

size_t base64Encode(const uint8_t* in, size_t len, char* out, size_t outLen)
{
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t v = static_cast<uint32_t>(in[i]) << 16;
        if (i + 1 < len) v |= static_cast<uint32_t>(in[i + 1]) << 8;
        if (i + 2 < len) v |= in[i + 2];
        if (o + 4 >= outLen) break;
        out[o++] = tbl[(v >> 18) & 63];
        out[o++] = tbl[(v >> 12) & 63];
        out[o++] = i + 1 < len ? tbl[(v >> 6) & 63] : '=';
        out[o++] = i + 2 < len ? tbl[v & 63] : '=';
    }
    out[o] = '\0';
    return o;
}

// Constant-time compare for credentials.
bool safeEquals(const char* a, const char* b)
{
    size_t la = strlen(a), lb = strlen(b);
    uint8_t diff = static_cast<uint8_t>(la != lb);
    for (size_t i = 0; i < la; i++) diff |= static_cast<uint8_t>(a[i] ^ b[i % (lb ? lb : 1)]);
    return diff == 0;
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
        char loc[32] = "http://";
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

bool WebServer::authorized(httpd_req_t* req, bool isPost)
{
    const Settings s = d_.cfg.get();

    char cred[sizeof(s.adminUser) + sizeof(s.adminPass) + 1];
    snprintf(cred, sizeof(cred), "%s:%s", s.adminUser, s.adminPass);
    char expected[200] = "Basic ";
    base64Encode(reinterpret_cast<const uint8_t*>(cred), strlen(cred), expected + 6,
                 sizeof(expected) - 6);

    char got[200] = "";
    if (httpd_req_get_hdr_value_str(req, "Authorization", got, sizeof(got)) != ESP_OK ||
        !safeEquals(got, expected)) {
        httpd_resp_set_status(req, "401 Unauthorized");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"sinkhole\", charset=\"UTF-8\"");
        httpd_resp_sendstr(req, "authentication required");
        return false;
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

int WebServer::readForm(httpd_req_t* req, char* buf, size_t len)
{
    if (req->content_len >= len) return -1;
    size_t got = 0;
    while (got < req->content_len) {
        int n = httpd_req_recv(req, buf + got, req->content_len - got);
        if (n == HTTPD_SOCK_ERR_TIMEOUT) continue;
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

// ------------------------------------------------------------------ pages

esp_err_t WebServer::getIndex(httpd_req_t* req)
{
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache");
    return httpd_resp_send(req, reinterpret_cast<const char*>(index_html_gz_start),
                           index_html_gz_end - index_html_gz_start);
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
    j.str("hostname", s.hostname);
    j.num("uptime", now);
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
        .str("board", Updater::boardId())
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
    ClientInfo* snap = sClientSnap;
    char addr[46];
    const size_t n = d_.clients.snapshot(snap, ClientTable::kCapacity);
    const uint32_t now = uptimeSeconds();
    JsonWriter j(req);
    j.beginArray();
    for (size_t i = 0; i < n; i++) {
        j.beginObject()
            .str("ip", (snap[i].addr.format(addr), addr))
            .boolean("v6", snap[i].addr.v6)
            .mac("mac", snap[i].mac)
            .num("blocked", snap[i].blocked)
            .num("allowed", snap[i].allowed)
            .num("seenAgo", now - snap[i].lastSeen)
            .boolean("banned", snap[i].banned)
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
    const size_t n = d_.clients.snapshot(sClientSnap, ClientTable::kCapacity);
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
    for (size_t i = 0; i < k; i++) {
        const ClientInfo& c = sClientSnap[order[i]];
        j.beginObject()
            .str("ip", (c.addr.format(addr), addr))
            .num("queries", c.blocked + c.allowed)
            .num("blocked", c.blocked)
            .endObject();
    }
    j.endArray().endObject();
    return j.finish();
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
        d_.filter.setEnabled(on);
        d_.cfg.modify([on](Settings& s) { s.blocking = on; });
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
    field(form, "banned", banned, sizeof(banned));
    esp_err_t err = d_.clients.setBanned(ip, banned[0] == '1');
    return err == ESP_OK ? sendOk(req) : sendError(req, "409 Conflict", "ban list is full");
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
        .boolean("dot", s.dot)
        .str("dotHost", s.dotHost)
        .boolean("guardCanary", s.bypassGuard & 1)
        .boolean("guardEncrypted", s.bypassGuard & 2)
        .boolean("cnameCheck", s.cnameCheck)
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
        d_.cfg.modify([&](Settings& s) {
            copyStr(s.apSsid, a);
            if (b[0]) copyStr(s.apPass, b);
            s.apAlways = c[0] != '0';
        });
        d_.wifi.applyAccessPoint();
        return sendOk(req, "access point updated; reconnect to it if you were using it");
    }
    if (strcmp(section, "admin") == 0) {
        field(form, "user", a, 32);
        field(form, "pass", b, 64);
        if (!a[0] || strlen(b) < 8) return sendError(req, "400 Bad Request", "user and an 8+ character password are required");
        d_.cfg.modify([&](Settings& s) {
            copyStr(s.adminUser, a);
            copyStr(s.adminPass, b);
        });
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
        d_.cfg.modify([&](Settings& s) {
            s.upstreamMode = mode;
            if (ip) s.upstreamIp = ip;
            s.upstreamIp2 = backup;  // empty field = no backup
            s.dot = dotOn;
            if (dotHost[0]) copyStr(s.dotHost, dotHost);
        });
        if (d_.applyUpstream) d_.applyUpstream(d_.appCtx);
        return sendOk(req);
    }
    if (strcmp(section, "guard") == 0) {
        field(form, "canary", a, 4);
        field(form, "encrypted", b, 4);
        field(form, "cname", c, 4);
        const uint8_t flags = static_cast<uint8_t>((a[0] == '1' ? 1 : 0) | (b[0] == '1' ? 2 : 0));
        const bool cname = c[0] == '1';
        d_.cfg.modify([&](Settings& s) {
            s.bypassGuard = flags;
            s.cnameCheck = cname;
        });
        d_.dns.setGuard(flags);
        d_.dns.setCnameCheck(cname);
        // SafeSearch: google=1, bing=1, youtube=off|moderate|strict
        char g[4] = "", bi[4] = "", yt[16] = "";
        field(form, "google", g, sizeof(g));
        field(form, "bing", bi, sizeof(bi));
        field(form, "youtube", yt, sizeof(yt));
        const uint8_t ss = static_cast<uint8_t>((g[0] == '1' ? 1 : 0) | (bi[0] == '1' ? 2 : 0) |
                                                (strcmp(yt, "moderate") == 0 ? 4 : 0) | (strcmp(yt, "strict") == 0 ? 8 : 0));
        d_.cfg.modify([ss](Settings& s) { s.safeSearch = ss; });
        d_.dns.setSafeSearch(ss);
        return sendOk(req);
    }
    if (strcmp(section, "update") == 0) {
        field(form, "url", a, sizeof(a));
        field(form, "hours", b, 8);
        if (a[0] && strncmp(a, "https://", 8) != 0 && strncmp(a, "http://", 7) != 0)
            return sendError(req, "400 Bad Request", "URL must start with https://");
        const unsigned long hours = strtoul(b, nullptr, 10);
        d_.cfg.modify([&](Settings& s) {
            copyStr(s.blocklistUrl, a);
            s.updateHours = static_cast<uint16_t>(hours > 720 ? 720 : hours);
        });
        return sendOk(req);
    }
    if (strcmp(section, "mqtt") == 0) {
        field(form, "uri", a, 128);
        field(form, "user", b, 64);
        field(form, "pass", c, 64);
        field(form, "prefix", e, 48);
        char ha[4] = "";
        field(form, "ha", ha, sizeof(ha));
        d_.cfg.modify([&](Settings& s) {
            s.haDiscovery = ha[0] == '1';
            copyStr(s.mqttUri, a);
            copyStr(s.mqttUser, b);
            if (c[0]) copyStr(s.mqttPass, c);
            copyStr(s.mqttPrefix, e[0] ? e : "sinkhole");
        });
        return sendOk(req, "saved; reboot to apply");
    }
    if (strcmp(section, "fw") == 0) {
        field(form, "url", a, sizeof(Settings::fwManifestUrl));
        field(form, "auto", b, 4);
        if (a[0] && strncmp(a, "https://", 8) != 0 && strncmp(a, "http://", 7) != 0)
            return sendError(req, "400 Bad Request", "URL must start with https://");
        const bool autoOn = b[0] == '1';
        if (autoOn && !Updater::autoInstallAllowed())
            return sendError(req, "400 Bad Request", "automatic install needs a signed firmware build");
        d_.cfg.modify([&](Settings& s) {
            copyStr(s.fwManifestUrl, a);
            s.fwAuto = autoOn;
        });
        return sendOk(req);
    }
    if (strcmp(section, "radio") == 0) {
        field(form, "tx", a, 16);
        const uint8_t mode = strcmp(a, "full") == 0 ? TxFull : strcmp(a, "reduced") == 0 ? TxReduced : TxAuto;
        d_.cfg.modify([mode](Settings& s) { s.txPower = mode; });
        d_.wifi.applyTxPower();
        return sendOk(req);
    }
    if (strcmp(section, "ip") == 0) {
        field(form, "mode", a, 16);
        if (strcmp(a, "static") != 0) {
            d_.cfg.modify([](Settings& s) { s.staticIp = false; });
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
        d_.cfg.modify([&](Settings& s) {
            s.staticIp = true;
            s.ipAddr = ip;
            s.ipMask = mask;
            s.ipGw = gw;
            s.ipDns = dns;
        });
        d_.wifi.reconfigureStation();
        char msg[64];
        snprintf(msg, sizeof(msg), "static IP set; reconnecting at http://%s/", ipS);
        return sendOk(req, msg);
    }
    if (strcmp(section, "hostname") == 0) {
        if (!field(form, "hostname", a, 32) || !a[0]) return sendError(req, "400 Bad Request", "hostname is required");
        d_.cfg.modify([&](Settings& s) { copyStr(s.hostname, a); });
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
        int n = httpd_req_recv(req, reinterpret_cast<char*>(chunk_), left < sizeof(chunk_) ? left : sizeof(chunk_));
        if (n == HTTPD_SOCK_ERR_TIMEOUT) continue;
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
        int n = httpd_req_recv(req, reinterpret_cast<char*>(chunk_), left < sizeof(chunk_) ? left : sizeof(chunk_));
        if (n == HTTPD_SOCK_ERR_TIMEOUT) continue;
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
    FirmwareUpdater::restartIn(1500);
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
    FirmwareUpdater::restartIn(1000);
    return sendOk(req, "rebooting");
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
            .num("wokeAgo", snap[i].lastWake ? static_cast<int64_t>(now - snap[i].lastWake) : -1)
            .endObject();
    }
    j.endArray();
    return j.finish();
}

esp_err_t WebServer::postWol(httpd_req_t* req)
{
    char form[kFormMax], action[16], name[32] = "", macStr[24] = "", ipStr[20] = "";
    if (readForm(req, form, sizeof(form)) < 0 || !field(form, "action", action, sizeof(action)))
        return sendError(req, "400 Bad Request", "action is required");
    field(form, "name", name, sizeof(name));
    field(form, "mac", macStr, sizeof(macStr));
    field(form, "ip", ipStr, sizeof(ipStr));

    if (strcmp(action, "wake") == 0) {
        if (name[0]) {
            esp_err_t err = d_.wol.wake(name);
            return err == ESP_OK ? sendOk(req, "magic packet sent")
                                 : sendError(req, "404 Not Found", "unknown host");
        }
        uint8_t mac[6];
        if (!parseMac(macStr, mac)) return sendError(req, "400 Bad Request", "name or mac required");
        return d_.wol.wakeMac(mac) == ESP_OK ? sendOk(req, "magic packet sent")
                                              : sendError(req, "500 Internal Server Error", "send failed");
    }
    if (strcmp(action, "add") == 0) {
        WolHost h{};
        copyStr(h.name, name);
        if (!parseMac(macStr, h.mac)) return sendError(req, "400 Bad Request", "valid MAC required");
        if (ipStr[0] && !parseIp4(ipStr, h.ip)) return sendError(req, "400 Bad Request", "invalid IP");
        esp_err_t err = d_.wol.add(h);
        if (err == ESP_ERR_INVALID_ARG) return sendError(req, "400 Bad Request", "name: no spaces, '/', '+' or '#'");
        if (err == ESP_ERR_NO_MEM) return sendError(req, "409 Conflict", "host list is full");
        return sendOk(req);
    }
    if (strcmp(action, "remove") == 0) {
        return d_.wol.remove(name) == ESP_OK ? sendOk(req) : sendError(req, "404 Not Found", "unknown host");
    }
    return sendError(req, "400 Bad Request", "unknown action");
}

}  // namespace sinkhole
