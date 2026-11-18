#pragma once
// Web UI + JSON API on :80 (both on the LAN and on the device's own AP).
//
// Security model (LAN trust boundary, plain HTTP like the original project):
//   - every /api/* call needs HTTP Basic auth (admin user/password)
//   - every POST also needs "X-Requested-With: sinkhole", which a cross-site
//     <img>/<form> cannot add, so cached Basic credentials can't be CSRF'd.
//   - the password is checked against a PBKDF2 hash; a good Authorization
//     header is remembered (as a SHA-256) so only new ones pay for PBKDF2
//   - wrong passwords: after kFreeGuesses different ones, the device waits
//     longer and longer (429 + Retry-After) before checking another one
//   - while the default password is set, the Host header must be an IP address
//     or a local name (DNS rebinding: a web page can't reach the API)

#include <array>
#include <cstddef>
#include <cstdint>

#include "esp_err.h"
#include "esp_http_server.h"
#include "sinkhole/blocklist_store.hpp"
#include "sinkhole/config.hpp"
#include "sinkhole/dns_server.hpp"
#include "sinkhole/domain_filter.hpp"
#include "sinkhole/domain_list.hpp"
#include "sinkhole/stats.hpp"
#include "sinkhole/updaters.hpp"
#include "sinkhole/status_led.hpp"
#include "sinkhole/lan_dhcp.hpp"
#include "sinkhole/wifi_manager.hpp"
#include "sinkhole/wol.hpp"

namespace sinkhole {

struct WebDeps {
    Config& cfg;
    WifiManager& wifi;
    BlocklistStore& store;
    DomainList& custom;
    DomainList& allow;
    DomainFilter& filter;
    ClientTable& clients;
    QueryLog& log;
    Counters& counters;
    DnsServer& dns;
    Updater& updater;
    FirmwareUpdater& firmware;
    WolService& wol;
    MqttBridge& mqtt;
    StatusLed& led;
    History& history;
    LanDhcp& dhcp;
    void (*applyUpstream)(void* ctx);
    void* appCtx;
};

class WebServer {
public:
    explicit WebServer(const WebDeps& deps) : d_(deps) {}
    esp_err_t start();

private:
    using Handler = esp_err_t (WebServer::*)(httpd_req_t*);
    struct Route {
        const char* uri;
        httpd_method_t method;
        Handler handler;
        bool needsAuth;
    };

    static esp_err_t dispatch(httpd_req_t* req);
    static esp_err_t notFound(httpd_req_t* req, httpd_err_code_t err);
    bool authorized(httpd_req_t* req, bool isPost);
    bool hostAllowed(httpd_req_t* req);
    void forgetLogins();  // after the credentials changed
    using Digest = std::array<uint8_t, 32>;
    static esp_err_t challenge(httpd_req_t* req);
    bool credentialsOk(const char* header);
    int guessWaitSeconds() const;
    void noteWrongPassword(httpd_req_t* req, const Digest& digest);
    int readForm(httpd_req_t* req, char* buf, size_t len);
    static bool field(const char* form, const char* key, char* out, size_t outLen);
    esp_err_t sendOk(httpd_req_t* req, const char* message = "ok");
    esp_err_t sendError(httpd_req_t* req, const char* status, const char* message);

    esp_err_t getIndex(httpd_req_t* req);
    esp_err_t getStatus(httpd_req_t* req);
    esp_err_t getClients(httpd_req_t* req);
    esp_err_t getQueries(httpd_req_t* req);
    esp_err_t getLists(httpd_req_t* req);
    esp_err_t postLists(httpd_req_t* req);
    esp_err_t getRecords(httpd_req_t* req);
    esp_err_t getTop(httpd_req_t* req);
    esp_err_t getHistory(httpd_req_t* req);
    esp_err_t getBackup(httpd_req_t* req);
    esp_err_t postRestore(httpd_req_t* req);
    esp_err_t postRecords(httpd_req_t* req);
    esp_err_t postBlocking(httpd_req_t* req);
    esp_err_t postBan(httpd_req_t* req);
    esp_err_t getSettings(httpd_req_t* req);
    esp_err_t postSettings(httpd_req_t* req);
    esp_err_t postWifi(httpd_req_t* req);
    esp_err_t getWifiScan(httpd_req_t* req);
    esp_err_t postBlocklistFetch(httpd_req_t* req);
    esp_err_t postBlocklistUpload(httpd_req_t* req);
    esp_err_t postFirmwareUpload(httpd_req_t* req);
    esp_err_t postFirmwareCheck(httpd_req_t* req);
    esp_err_t postFirmwareInstall(httpd_req_t* req);
    esp_err_t postReboot(httpd_req_t* req);
    esp_err_t getWol(httpd_req_t* req);
    esp_err_t getPerf(httpd_req_t* req);
    esp_err_t postWol(httpd_req_t* req);

    static const Route kRoutes[];

    WebDeps d_;
    httpd_handle_t server_ = nullptr;
    uint8_t chunk_[2048];  // upload buffer; the httpd task serves one request at a time

    // Login state (httpd task only).
    static constexpr int kFreeGuesses = 5;
    static constexpr size_t kBadRemembered = 4;
    Digest good_{};  // SHA-256 of the last accepted Authorization header
    bool goodValid_ = false;
    std::array<Digest, kBadRemembered> bad_{};  // recent wrong headers: retried, not counted again
    size_t badNext_ = 0;
    uint32_t failures_ = 0;  // different wrong passwords in a row
    int64_t lockedUntilUs_ = 0;
};

}  // namespace sinkhole
