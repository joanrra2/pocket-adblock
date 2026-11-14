#include <cstdio>
#include <cstring>

#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "sinkhole/text.hpp"
#include "sinkhole/updaters.hpp"

namespace sinkhole {

namespace {
constexpr const char* TAG = "bl-update";
constexpr uint32_t kRetryAfterFailureS = 15 * 60;
constexpr uint32_t kFirstFetchDelayS = 20;  // let Wi-Fi/DNS settle after boot
constexpr int kMaxRedirects = 5;

bool isRedirect(int status)
{
    return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
}
}  // namespace

esp_err_t BlocklistUpdater::start()
{
    return task_.start("bl_update", &BlocklistUpdater::taskEntry, this, 3) ? ESP_OK
                                                                           : ESP_ERR_NO_MEM;
}

void BlocklistUpdater::taskEntry(void* arg)
{
    static_cast<BlocklistUpdater*>(arg)->run();
}

void BlocklistUpdater::fetchNow()
{
    manual_ = true;
    task_.notify();
}

UpdateStatus BlocklistUpdater::status()
{
    LockGuard g(mu_);
    return status_;
}

void BlocklistUpdater::report(bool ok, const char* message, uint32_t bytes)
{
    LockGuard g(mu_);
    status_.lastOk = ok;
    status_.lastAttempt = uptimeSeconds();
    status_.bytes = bytes;
    copyStr(status_.message, message);
}

bool BlocklistUpdater::due()
{
    if (manual_.exchange(false)) return true;
    const Settings s = cfg_.get();
    if (!s.updateHours || !s.blocklistUrl[0]) return false;

    const uint32_t now = uptimeSeconds();
    UpdateStatus st = status();
    if (st.lastAttempt == 0) {
        // Never tried since boot: fetch soon if there is no list at all,
        // otherwise wait one interval (the stored list survives reboots).
        if (store_.info().count == 0) return now >= kFirstFetchDelayS;
        return now >= static_cast<uint32_t>(s.updateHours) * 3600;
    }
    const uint32_t wait = st.lastOk ? static_cast<uint32_t>(s.updateHours) * 3600 : kRetryAfterFailureS;
    return now - st.lastAttempt >= wait;
}

void BlocklistUpdater::run()
{
    for (;;) {
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(60 * 1000));
        if (!wifi_.connected()) continue;
        if (store_.writing()) continue;  // an upload is in progress
        if (due()) fetch();
    }
}

void BlocklistUpdater::fetch()
{
    char url[sizeof(Settings::blocklistUrl)];
    copyStr(url, cfg_.get().blocklistUrl);
    if (!url[0]) {
        report(false, "no blocklist URL configured", 0);
        return;
    }
    {
        LockGuard g(mu_);
        status_.running = true;
    }
    char why[96] = "ok";
    uint32_t bytes = 0;
    esp_err_t err = download(url, why, sizeof(why), bytes);
    {
        LockGuard g(mu_);
        status_.running = false;
    }
    if (err == ESP_OK) {
        char msg[96];
        snprintf(msg, sizeof(msg), "updated: %lu domains", static_cast<unsigned long>(store_.info().count));
        report(true, msg, bytes);
    } else {
        report(false, why, bytes);
    }
    ESP_LOGI(TAG, "%s (%lu bytes)", err == ESP_OK ? "done" : why, static_cast<unsigned long>(bytes));
}

esp_err_t BlocklistUpdater::download(const char* url, char* why, size_t whyLen, uint32_t& bytes)
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

    if (store_.beginWrite() != ESP_OK) {
        snprintf(why, whyLen, "another blocklist update is running");
        goto done;
    }
    for (;;) {
        int n = esp_http_client_read(client, reinterpret_cast<char*>(buf_), sizeof(buf_));
        if (n < 0) {
            snprintf(why, whyLen, "read error");
            store_.abortWrite();
            goto done;
        }
        if (n == 0) {
            if (esp_http_client_is_complete_data_received(client)) break;
            snprintf(why, whyLen, "connection closed early");
            store_.abortWrite();
            goto done;
        }
        if (store_.write(buf_, static_cast<size_t>(n)) != ESP_OK) {
            snprintf(why, whyLen, "list too large for the slot or flash error");
            store_.abortWrite();
            goto done;
        }
        bytes += static_cast<uint32_t>(n);
    }
    result = store_.finishWrite(why, whyLen);

done:
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    return result;
}

}  // namespace sinkhole
