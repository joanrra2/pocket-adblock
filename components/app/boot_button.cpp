#include "sinkhole/boot_button.hpp"

#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "sdkconfig.h"

namespace sinkhole {

namespace {
constexpr const char* TAG = "button";
constexpr uint32_t kPollMs = 50;
constexpr uint32_t kApHoldMs = 3000;
constexpr uint32_t kResetHoldMs = 10000;
constexpr uint32_t kForcedApMinutes = 15;
}  // namespace

void BootButton::start()
{
#if CONFIG_SINKHOLE_BOOT_BUTTON_GPIO >= 0
    gpio_config_t io{};
    io.pin_bit_mask = 1ULL << CONFIG_SINKHOLE_BOOT_BUTTON_GPIO;
    io.mode = GPIO_MODE_INPUT;
    io.pull_up_en = GPIO_PULLUP_ENABLE;
    gpio_config(&io);
    task_.start("button", &BootButton::taskEntry, this, 1);
#endif
}

void BootButton::taskEntry(void* arg)
{
    static_cast<BootButton*>(arg)->run();
}

void BootButton::run()
{
#if CONFIG_SINKHOLE_BOOT_BUTTON_GPIO >= 0
    const auto pin = static_cast<gpio_num_t>(CONFIG_SINKHOLE_BOOT_BUTTON_GPIO);
    uint32_t heldMs = 0;
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(kPollMs));
        if (gpio_get_level(pin) == 0) {
            heldMs += kPollMs;
            if (heldMs == kApHoldMs) ESP_LOGW(TAG, "release now for setup AP, keep holding for factory reset");
            if (heldMs >= kResetHoldMs) {
                ESP_LOGW(TAG, "factory reset");
                nvs_flash_erase();
                esp_restart();
            }
        } else {
            if (heldMs >= kApHoldMs) wifi_.forceAp(kForcedApMinutes);
            heldMs = 0;
        }
    }
#endif
}

}  // namespace sinkhole
