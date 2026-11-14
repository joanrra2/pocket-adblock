#pragma once
// Firmware OTA (streamed from an HTTP upload) and blocklist updates (HTTP
// upload or scheduled HTTPS pull into the inactive A/B slot).

#include <atomic>
#include <cstddef>
#include <cstdint>

#include "esp_err.h"
#include "esp_ota_ops.h"
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

    static void restartIn(uint32_t ms);
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

class BlocklistUpdater {
public:
    BlocklistUpdater(Config& cfg, BlocklistStore& store, WifiManager& wifi)
        : cfg_(cfg), store_(store), wifi_(wifi)
    {
    }

    esp_err_t start();
    void fetchNow();
    UpdateStatus status();
    // For uploads: record the outcome so the UI shows one status line.
    void report(bool ok, const char* message, uint32_t bytes);

private:
    static void taskEntry(void* arg);
    void run();
    bool due();
    void fetch();
    esp_err_t download(const char* url, char* why, size_t whyLen, uint32_t& bytes);

    Config& cfg_;
    BlocklistStore& store_;
    WifiManager& wifi_;

    Mutex mu_;
    UpdateStatus status_{};
    std::atomic<bool> manual_{false};

    uint8_t buf_[2048];
    StaticTask<8192> task_;  // TLS handshake needs a deep stack
};

}  // namespace sinkhole
