#include <cstdint>

#include "esp_app_desc.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sinkhole/updaters.hpp"

namespace sinkhole {

namespace {
constexpr const char* TAG = "fw-ota";

void restartCb(void*)
{
    esp_restart();
}

esp_timer_handle_t gRestartTimer = nullptr;  // created once at boot
}  // namespace

esp_err_t FirmwareUpdater::initRestartTimer()
{
    if (gRestartTimer) return ESP_OK;
    esp_timer_create_args_t args{};
    args.callback = &restartCb;
    args.name = "restart";
    return esp_timer_create(&args, &gRestartTimer);
}

esp_err_t FirmwareUpdater::begin()
{
    if (handle_) return ESP_ERR_INVALID_STATE;
    target_ = esp_ota_get_next_update_partition(nullptr);
    if (!target_) return ESP_ERR_NOT_FOUND;
    // Sequential writes: erase as we go instead of wiping the whole slot up front.
    esp_err_t err = esp_ota_begin(target_, OTA_WITH_SEQUENTIAL_WRITES, &handle_);
    if (err != ESP_OK) {
        handle_ = 0;
        return err;
    }
    ESP_LOGI(TAG, "writing to %s", target_->label);
    return ESP_OK;
}

esp_err_t FirmwareUpdater::write(const void* data, size_t len)
{
    if (!handle_) return ESP_ERR_INVALID_STATE;
    return esp_ota_write(handle_, data, len);
}

esp_err_t FirmwareUpdater::finish()
{
    if (!handle_) return ESP_ERR_INVALID_STATE;
    esp_err_t err = esp_ota_end(handle_);  // verifies image + checksum
    handle_ = 0;
    if (err != ESP_OK) return err;
    err = esp_ota_set_boot_partition(target_);
    if (err == ESP_OK) ESP_LOGI(TAG, "new firmware in %s, reboot to run it", target_->label);
    return err;
}

void FirmwareUpdater::abort()
{
    if (handle_) esp_ota_abort(handle_);
    handle_ = 0;
}

void FirmwareUpdater::restartIn(uint32_t ms, BootLog::Cause cause)
{
    BootLog::noteRestart(cause);
    const esp_err_t err = gRestartTimer ? esp_timer_start_once(gRestartTimer, static_cast<uint64_t>(ms) * 1000)
                                        : ESP_ERR_INVALID_STATE;
    if (err == ESP_OK || (gRestartTimer && esp_timer_is_active(gRestartTimer))) return;  // started, or already coming
    // No timer: restart from here after the delay rather than not at all. The
    // caller's reply may not go out, but the device never runs on half-applied
    // state (a restore that is in flash but not in RAM).
    ESP_LOGW(TAG, "restart timer unavailable (%s), restarting directly", esp_err_to_name(err));
    vTaskDelay(pdMS_TO_TICKS(ms));
    esp_restart();
}

const char* FirmwareUpdater::version()
{
    return esp_app_get_description()->version;
}

bool FirmwareUpdater::pendingVerify()
{
    esp_ota_img_states_t state;
    const esp_partition_t* running = esp_ota_get_running_partition();
    return esp_ota_get_state_partition(running, &state) == ESP_OK &&
           state == ESP_OTA_IMG_PENDING_VERIFY;
}

void FirmwareUpdater::markValid()
{
    if (esp_ota_mark_app_valid_cancel_rollback() == ESP_OK)
        ESP_LOGI(TAG, "firmware marked valid, rollback cancelled");
}

}  // namespace sinkhole
