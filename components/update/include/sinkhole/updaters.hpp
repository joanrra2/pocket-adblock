#pragma once
// Firmware OTA (streamed from an HTTP upload) and blocklist updates (HTTP
// upload or scheduled HTTPS pull into the inactive A/B slot).

#include <atomic>
#include <cstddef>
#include <cstdint>

#include "esp_err.h"
#include "esp_ota_ops.h"
#include "sinkhole/boot_log.hpp"
#include "sinkhole/blocklist_store.hpp"
#include "sinkhole/config.hpp"
#include "sinkhole/rtos.hpp"
#include "sinkhole/wifi_manager.hpp"

namespace sinkhole {

class FirmwareUpdater {
public:
    esp_err_t begin();
    esp_err_t write(const void* data, size_t len);
    esp_err_t finish();  // validates the image and selects it for next boot
    void abort();
    bool active() const { return handle_ != 0; }

    static void restartIn(uint32_t ms, BootLog::Cause cause);
    static const char* version();
    // Rollback support: a freshly flashed image boots in PENDING_VERIFY state.
    static bool pendingVerify();
    static void markValid();

private:
    esp_ota_handle_t handle_ = 0;
    const esp_partition_t* target_ = nullptr;
};

struct UpdateStatus {
    bool running;
    bool lastOk;
    uint32_t lastAttempt;  // uptime seconds, 0 = never
    uint32_t bytes;
    char message[96];
};

struct FirmwareCheck {
    bool available;        // newer version for this board in the manifest
    bool installing;
    bool lastOk;
    uint32_t lastCheck;    // uptime seconds, 0 = never
    uint32_t bytes;        // install progress
    char latest[24];
    char message[96];
};

// One background task (one TLS-capable stack) for all downloads:
//   - blocklist: scheduled and on demand, into the inactive A/B slot
//   - firmware: daily manifest check; install on request, or automatically on
//     signed builds (an unsigned build must never auto-install code)
class Updater {
public:
    Updater(Config& cfg, BlocklistStore& store, WifiManager& wifi, FirmwareUpdater& fw)
        : cfg_(cfg), store_(store), wifi_(wifi), fw_(fw)
    {
    }

    esp_err_t start();
    void fetchNow();
    UpdateStatus status();
    // For uploads: record the outcome so the UI shows one status line.
    void report(bool ok, const char* message, uint32_t bytes);

    void checkFirmwareNow();
    esp_err_t installFirmwareNow();  // ESP_ERR_NOT_FOUND if no update is known
    FirmwareCheck firmwareStatus();
    static bool autoInstallAllowed();  // built with signed-image verification
    static const char* boardId();
    // Manifest key: <board> (Lite), <board>-pro (Pro), <board>-custom (never published).
    static const char* imageKey();
    static const char* flavour() { return CONFIG_SINKHOLE_FLAVOUR; }

    // Exposed for tests: "1.2.10" > "1.2.9"; a leading "v" is ignored.
    static int compareVersions(const char* a, const char* b);

private:
    using Sink = esp_err_t (*)(void* ctx, const uint8_t* data, size_t len);

    static void taskEntry(void* arg);
    void run();
    bool blocklistDue();
    bool firmwareDue();
    enum class ListFetch { Updated, Unchanged, TooBig, Failed };
    ListFetch downloadList(const char* url, char* why, size_t whyLen, uint32_t& bytes);
    void fetchBlocklist();
    void checkFirmware();
    void installFirmware();
    esp_err_t httpGet(const char* url, Sink sink, void* ctx, char* why, size_t whyLen, uint32_t& bytes);

    Config& cfg_;
    BlocklistStore& store_;
    WifiManager& wifi_;
    FirmwareUpdater& fw_;

    Mutex mu_;
    UpdateStatus status_{};
    FirmwareCheck fwStatus_{};
    char fwUrl_[256]{};  // image for this board from the last good check
    std::atomic<bool> manual_{false};
    std::atomic<bool> manualCheck_{false};
    std::atomic<bool> manualInstall_{false};

    uint8_t buf_[2048];
    char manifest_[2048];
    StaticTask<8192> task_;  // TLS handshake needs a deep stack
};

}  // namespace sinkhole
