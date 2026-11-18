#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "sdkconfig.h"
#include "sinkhole/text.hpp"
#include "sinkhole/updaters.hpp"

namespace sinkhole {

namespace {
constexpr const char* TAG = "update";
constexpr uint32_t kRetryAfterFailureS = 15 * 60;
constexpr uint32_t kFirstFetchDelayS = 20;     // let Wi-Fi/DNS settle after boot
// With a list already stored, check this long after boot (then every interval):
// unchanged lists cost a 64-byte download, so devices that reboot often still update.
constexpr uint32_t kBootCheckDelayS = 10 * 60;
constexpr uint32_t kFirstFwCheckS = 120;
constexpr uint32_t kFwCheckEveryS = 24 * 3600;
constexpr int kMaxRedirects = 5;

// The project's own daily lists, biggest first. A board whose slot can't hold
// the chosen one (a backup from a 16 MB board restored on a 4 MB one, a URL
// typed by hand) steps down to the next instead of failing every check.
constexpr const char* kListSizes[] = {"blocklist-extended.bin", "blocklist-strict.bin", "blocklist-aggressive.bin",
                                      "blocklist.bin"};

// Writes url with the next smaller list's file name; false when url is not one
// of those lists (custom lists are left alone) or already the smallest.
bool smallerList(const char* url, char* out, size_t cap)
{
    const char* name = strrchr(url, '/');
    if (!name) return false;
    name++;
    for (size_t i = 0; i + 1 < sizeof(kListSizes) / sizeof(kListSizes[0]); i++) {
        if (strcmp(name, kListSizes[i]) != 0) continue;
        const int n = snprintf(out, cap, "%.*s%s", static_cast<int>(name - url), url, kListSizes[i + 1]);
        return n > 0 && static_cast<size_t>(n) < cap;
    }
    return false;
}

// The project's daily lists. They are published twice: "<name>.bin" in the
// compact sorted format (v2) that every firmware reads, and "<name>-v4.bin" as a
// fuse filter (smaller, 3x faster lookups, no bloom filter). This firmware
// fetches the -v4 file but keeps the v2 name in the settings, so a board
// downgraded to older firmware still finds a list it can read. Older firmware
// never sees a v4 list unless someone types its URL, and then rejects its header
// and keeps the active list.
constexpr const char* kOfficialLists[] = {"blocklist.bin", "blocklist-light.bin", "blocklist-aggressive.bin",
                                          "blocklist-strict.bin", "blocklist-extended.bin"};
constexpr const char* kOfficialRelease = "/releases/download/blocklist/";

// Writes the fuse-filter twin of an official list URL; false for any other URL.
bool fuseVariant(const char* url, char* out, size_t cap)
{
    const char* name = strrchr(url, '/');
    if (!name || !strstr(url, kOfficialRelease)) return false;
    name++;
    for (const char* list : kOfficialLists) {
        if (strcmp(name, list) != 0) continue;
        const int n = snprintf(out, cap, "%.*s-v4.bin", static_cast<int>(strlen(url) - 4), url);
        return n > 0 && static_cast<size_t>(n) < cap;
    }
    return false;
}

bool isRedirect(int status)
{
    return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
}

// Finds "key": "value" in a small, trusted-format JSON document. Returns false
// if missing or the value does not fit.
bool jsonString(const char* doc, const char* key, char* out, size_t outLen)
{
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char* p = strstr(doc, pat);
    if (!p) return false;
    p = strchr(p + strlen(pat), ':');
    if (!p) return false;
    p = strchr(p, '"');
    if (!p) return false;
    const char* end = strchr(++p, '"');
    if (!end || static_cast<size_t>(end - p) >= outLen) return false;
    memcpy(out, p, end - p);
    out[end - p] = '\0';
    return true;
}

struct BufferSink {
    char* buf;
    size_t cap;
    size_t len;
};
}  // namespace

// ------------------------------------------------------------------ public

esp_err_t Updater::start()
{
    return task_.start("updater", &Updater::taskEntry, this, 3) ? ESP_OK : ESP_ERR_NO_MEM;
}

void Updater::taskEntry(void* arg)
{
    auto* self = static_cast<Updater*>(arg);
    self->store_.finishStartup();  // low priority, after Wi-Fi and DNS are up
    self->run();
}

void Updater::fetchNow()
{
    manual_ = true;
    task_.notify();
}

void Updater::checkFirmwareNow()
{
    manualCheck_ = true;
    task_.notify();
}

esp_err_t Updater::installFirmwareNow()
{
    {
        LockGuard g(mu_);
        if (!fwStatus_.available || !fwUrl_[0]) return ESP_ERR_NOT_FOUND;
        if (fwStatus_.installing) return ESP_ERR_INVALID_STATE;
    }
    manualInstall_ = true;
    task_.notify();
    return ESP_OK;
}

UpdateStatus Updater::status()
{
    LockGuard g(mu_);
    return status_;
}

FirmwareCheck Updater::firmwareStatus()
{
    LockGuard g(mu_);
    return fwStatus_;
}

void Updater::report(bool ok, const char* message, uint32_t bytes)
{
    LockGuard g(mu_);
    status_.lastOk = ok;
    status_.lastAttempt = uptimeSeconds();
    status_.bytes = bytes;
    copyStr(status_.message, message);
}

bool Updater::autoInstallAllowed()
{
#if CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT || CONFIG_SECURE_BOOT
    return true;  // images are signature-checked before they can boot
#else
    return false;
#endif
}

const char* Updater::boardId()
{
    return CONFIG_SINKHOLE_BOARD_ID[0] ? CONFIG_SINKHOLE_BOARD_ID : CONFIG_IDF_TARGET;
}

const char* Updater::imageKey()
{
    static char key[64];
    if (!key[0]) {
        if (strcmp(CONFIG_SINKHOLE_FLAVOUR, "lite") == 0)
            snprintf(key, sizeof(key), "%s", boardId());
        else
            snprintf(key, sizeof(key), "%s-%s", boardId(), CONFIG_SINKHOLE_FLAVOUR);
    }
    return key;
}

int Updater::compareVersions(const char* a, const char* b)
{
    if (*a == 'v') a++;
    if (*b == 'v') b++;
    for (int part = 0; part < 4; part++) {
        char* ea;
        char* eb;
        const long x = strtol(a, &ea, 10);
        const long y = strtol(b, &eb, 10);
        if (x != y) return x < y ? -1 : 1;
        a = *ea == '.' ? ea + 1 : ea;
        b = *eb == '.' ? eb + 1 : eb;
        if (*ea != '.' && *eb != '.') break;
    }
    // Same numbers: a pre-release ("0.2.1-dev", "-rc1") is older than the
    // release itself, as in semver.
    const bool preA = *a == '-', preB = *b == '-';
    if (preA != preB) return preA ? -1 : 1;
    return 0;
}

// ------------------------------------------------------------------ loop

void Updater::run()
{
    for (;;) {
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(60 * 1000));
        if (!wifi_.connected()) continue;
        if (manualInstall_.exchange(false)) {
            installFirmware();
            continue;
        }
        if (!store_.writing() && blocklistDue()) fetchBlocklist();
        if (firmwareDue()) {
            checkFirmware();
            const FirmwareCheck fc = firmwareStatus();
            const bool autoOn = cfg_.read([](const Settings& s) { return s.fwAuto; });
            if (fc.available && autoOn && autoInstallAllowed()) {
                ESP_LOGW(TAG, "auto-installing firmware %s", fc.latest);
                installFirmware();
            }
        }
    }
}

bool Updater::blocklistDue()
{
    if (manual_.exchange(false)) return true;
    struct {
        uint16_t hours;
        bool hasUrl;
    } c;
    cfg_.read([&](const Settings& s) {
        c = {s.updateHours, s.blocklistUrl[0] != '\0'};
        return 0;
    });
    if (!c.hours || !c.hasUrl) return false;

    const uint32_t now = uptimeSeconds();
    const UpdateStatus st = status();
    if (st.lastAttempt == 0) {
        // Never tried since boot: fetch soon if there is no list at all,
        // otherwise wait one interval (the stored list survives reboots).
        if (store_.info().count == 0) return now >= kFirstFetchDelayS;
        return now >= kBootCheckDelayS;
    }
    const uint32_t wait = st.lastOk ? static_cast<uint32_t>(c.hours) * 3600 : kRetryAfterFailureS;
    return now - st.lastAttempt >= wait;
}

bool Updater::firmwareDue()
{
    if (manualCheck_.exchange(false)) return true;
    const bool hasUrl = cfg_.read([](const Settings& s) { return s.fwManifestUrl[0] != '\0'; });
    if (!hasUrl) return false;
    const uint32_t now = uptimeSeconds();
    const FirmwareCheck fc = firmwareStatus();
    if (fc.lastCheck == 0) return now >= kFirstFwCheckS;
    return now - fc.lastCheck >= (fc.lastOk ? kFwCheckEveryS : kRetryAfterFailureS);
}

// ------------------------------------------------------------------ jobs

Updater::ListFetch Updater::downloadList(const char* url, char* why, size_t whyLen, uint32_t& bytes)
{
    bytes = 0;
    snprintf(why, whyLen, "ok");
    esp_err_t err = store_.beginWrite();
    if (err != ESP_OK) {
        snprintf(why, whyLen, "another blocklist update is running");
        return ListFetch::Failed;
    }
    err = httpGet(
        url, [](void* ctx, const uint8_t* d, size_t n) { return static_cast<BlocklistStore*>(ctx)->write(d, n); },
        &store_, why, whyLen, bytes);
    if (err == ESP_OK) return store_.finishWrite(why, whyLen) == ESP_OK ? ListFetch::Updated : ListFetch::Failed;
    const bool same = store_.unchanged();
    const bool tooBig = store_.tooBig();
    if (tooBig)
        snprintf(why, whyLen, "list too big for this board: %lu domains, room for %lu",
                 static_cast<unsigned long>(store_.tooBigCount()),
                 static_cast<unsigned long>(store_.info().capacity));
    store_.abortWrite();
    return same ? ListFetch::Unchanged : tooBig ? ListFetch::TooBig : ListFetch::Failed;
}

void Updater::fetchBlocklist()
{
    char url[sizeof(Settings::blocklistUrl)];
    cfg_.read([&](const Settings& s) { return copyStr(url, s.blocklistUrl); });
    if (!url[0]) {
        report(false, "no blocklist URL configured", 0);
        return;
    }
    {
        LockGuard g(mu_);
        status_.running = true;
    }
    char why[96];
    uint32_t bytes = 0;
    char fuse[sizeof(url) + 8];
    const bool twin = fuseVariant(url, fuse, sizeof(fuse));
    ListFetch r = downloadList(twin ? fuse : url, why, sizeof(why), bytes);
    if (twin && r == ListFetch::Failed) {  // not published (a fork's older CI?) or broken: the v2 file
        ESP_LOGW(TAG, "blocklist: %s: %s; trying %s", strrchr(fuse, '/') + 1, why, strrchr(url, '/') + 1);
        r = downloadList(url, why, sizeof(why), bytes);
    }
    {
        LockGuard g(mu_);
        status_.running = false;
    }
    if (r == ListFetch::Unchanged) {  // stopped after the header: nothing to do
        report(true, "already up to date", bytes);
        ESP_LOGI(TAG, "blocklist: unchanged, kept the active list");
        return;
    }
    const esp_err_t err = r == ListFetch::Updated ? ESP_OK : ESP_FAIL;
    char smaller[sizeof(Settings::blocklistUrl)];
    if (r == ListFetch::TooBig && smallerList(url, smaller, sizeof(smaller))) {
        // Nothing was written; the active list keeps filtering. Switch for good
        // and fetch the smaller list right away.
        cfg_.modify([&](Settings& s) {
            if (strcmp(s.blocklistUrl, url) == 0) copyStr(s.blocklistUrl, smaller);
        });
        ESP_LOGW(TAG, "blocklist: %s; switching to %s", why, strrchr(smaller, '/') + 1);
        snprintf(why, sizeof(why), "too big for this board: switched to %s", strrchr(smaller, '/') + 1);
        report(false, why, bytes);
        manual_ = true;
        task_.notify();
        return;
    }
    if (err == ESP_OK) {
        char msg[96];
        snprintf(msg, sizeof(msg), "updated: %lu domains", static_cast<unsigned long>(store_.info().count));
        report(true, msg, bytes);
    } else {
        report(false, why, bytes);
    }
    ESP_LOGI(TAG, "blocklist: %s (%lu bytes)", err == ESP_OK ? "done" : why, static_cast<unsigned long>(bytes));
}

void Updater::checkFirmware()
{
    char url[sizeof(Settings::fwManifestUrl)];
    cfg_.read([&](const Settings& s) { return copyStr(url, s.fwManifestUrl); });
    char why[96] = "";
    uint32_t bytes = 0;
    BufferSink sink{manifest_, sizeof(manifest_) - 1, 0};
    esp_err_t err = url[0] ? httpGet(
                                 url,
                                 [](void* ctx, const uint8_t* d, size_t n) {
                                     auto* s = static_cast<BufferSink*>(ctx);
                                     if (s->len + n > s->cap) return ESP_ERR_INVALID_SIZE;  // manifests are tiny
                                     memcpy(s->buf + s->len, d, n);
                                     s->len += n;
                                     return ESP_OK;
                                 },
                                 &sink, why, sizeof(why), bytes)
                           : ESP_ERR_INVALID_ARG;
    manifest_[sink.len] = '\0';

    char latest[24] = "", image[sizeof(fwUrl_)] = "";
    if (err == ESP_OK && !jsonString(manifest_, "version", latest, sizeof(latest))) {
        err = ESP_ERR_INVALID_RESPONSE;
        snprintf(why, sizeof(why), "manifest has no version");
    }
    if (err == ESP_OK && !jsonString(manifest_, imageKey(), image, sizeof(image))) {
        err = ESP_ERR_NOT_FOUND;
        if (strcmp(flavour(), "custom") == 0)
            snprintf(why, sizeof(why), "custom build: install updates manually");
        else
            snprintf(why, sizeof(why), "no image for %s in the manifest", imageKey());
    }

    LockGuard g(mu_);
    fwStatus_.lastCheck = uptimeSeconds();
    fwStatus_.lastOk = err == ESP_OK;
    if (err != ESP_OK) {
        copyStr(fwStatus_.message, why[0] ? why : "check failed");
        ESP_LOGW(TAG, "firmware check: %s", fwStatus_.message);
        return;
    }
    copyStr(fwStatus_.latest, latest);
    fwStatus_.available = compareVersions(latest, FirmwareUpdater::version()) > 0;
    copyStr(fwUrl_, image);
    snprintf(fwStatus_.message, sizeof(fwStatus_.message), "%s", fwStatus_.available ? "update available" : "up to date");
    ESP_LOGI(TAG, "firmware check: running %s, latest %s (%s)", FirmwareUpdater::version(), latest,
             fwStatus_.message);
}

void Updater::installFirmware()
{
    char url[sizeof(fwUrl_)];
    {
        LockGuard g(mu_);
        copyStr(url, fwUrl_);
        fwStatus_.installing = true;
        fwStatus_.bytes = 0;
        copyStr(fwStatus_.message, "downloading…");
    }
    char why[96] = "";
    uint32_t bytes = 0;
    esp_err_t err = fw_.begin();
    if (err == ESP_OK) {
        err = httpGet(
            url,
            [](void* ctx, const uint8_t* d, size_t n) { return static_cast<FirmwareUpdater*>(ctx)->write(d, n); },
            &fw_, why, sizeof(why), bytes);
        if (err == ESP_OK) {
            err = fw_.finish();  // verifies the image (and its signature on signed builds)
            if (err != ESP_OK) snprintf(why, sizeof(why), "image rejected: %s", esp_err_to_name(err));
        } else {
            fw_.abort();
        }
    } else {
        snprintf(why, sizeof(why), "OTA busy: %s", esp_err_to_name(err));
    }
    LockGuard g(mu_);
    fwStatus_.installing = false;
    fwStatus_.bytes = bytes;
    if (err == ESP_OK) {
        copyStr(fwStatus_.message, "installed, restarting");
        ESP_LOGW(TAG, "firmware %s installed, restarting", fwStatus_.latest);
        FirmwareUpdater::restartIn(2000, BootLog::Cause::FirmwareInstall);
    } else {
        copyStr(fwStatus_.message, why);
        ESP_LOGE(TAG, "firmware install failed: %s", why);
    }
}

// ------------------------------------------------------------------ HTTP

esp_err_t Updater::httpGet(const char* url, Sink sink, void* ctx, char* why, size_t whyLen, uint32_t& bytes)
{
    esp_http_client_config_t cfg = {};
    cfg.url = url;
    cfg.timeout_ms = 15000;
    cfg.buffer_size = 2048;
    cfg.buffer_size_tx = 2048;  // GitHub's signed redirect URLs are long
    cfg.crt_bundle_attach = esp_crt_bundle_attach;
    cfg.keep_alive_enable = false;

    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (!client) {
        snprintf(why, whyLen, "http client init failed");
        return ESP_ERR_NO_MEM;
    }

    esp_err_t result = ESP_FAIL;
    int status = 0;
    for (int hop = 0; hop <= kMaxRedirects; hop++) {
        esp_err_t err = esp_http_client_open(client, 0);
        if (err != ESP_OK) {
            snprintf(why, whyLen, "connect failed: %s", esp_err_to_name(err));
            goto done;
        }
        esp_http_client_fetch_headers(client);
        status = esp_http_client_get_status_code(client);
        if (!isRedirect(status)) break;
        esp_http_client_flush_response(client, nullptr);
        esp_http_client_set_redirection(client);
        esp_http_client_close(client);
    }
    if (status != 200) {
        snprintf(why, whyLen, "HTTP status %d", status);
        goto done;
    }
    for (;;) {
        int n = esp_http_client_read(client, reinterpret_cast<char*>(buf_), sizeof(buf_));
        if (n < 0) {
            snprintf(why, whyLen, "read error");
            goto done;
        }
        if (n == 0) {
            if (esp_http_client_is_complete_data_received(client)) break;
            snprintf(why, whyLen, "connection closed early");
            goto done;
        }
        if (sink(ctx, buf_, static_cast<size_t>(n)) != ESP_OK) {
            snprintf(why, whyLen, "data rejected (too large or flash error)");
            goto done;
        }
        bytes += static_cast<uint32_t>(n);
        if (fw_.active()) {
            LockGuard g(mu_);
            fwStatus_.bytes = bytes;
        }
    }
    result = ESP_OK;

done:
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    return result;
}

}  // namespace sinkhole
