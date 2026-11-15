#include "sinkhole/status_led.hpp"

#include "driver/gpio.h"
#include "driver/rmt_encoder.h"
#include "driver/rmt_tx.h"
#include "esp_log.h"
#include "esp_private/esp_gpio_reserve.h"
#include "esp_timer.h"

namespace sinkhole {

namespace {
constexpr const char* TAG = "led";
constexpr uint64_t kTickUs = 50 * 1000;
constexpr uint32_t kRmtHz = 10 * 1000 * 1000;  // 0.1 us ticks for the WS2812 timing
}  // namespace

bool StatusLed::pinUsable(int pin)
{
    return pin >= 0 && GPIO_IS_VALID_OUTPUT_GPIO(pin) && !esp_gpio_is_reserved(1ULL << pin);
}

void StatusLed::release()
{
    if (rmtChan_) {
        rmt_disable(static_cast<rmt_channel_handle_t>(rmtChan_));
        rmt_del_channel(static_cast<rmt_channel_handle_t>(rmtChan_));
        rmtChan_ = nullptr;
    }
    if (rmtEnc_) {
        rmt_del_encoder(static_cast<rmt_encoder_handle_t>(rmtEnc_));
        rmtEnc_ = nullptr;
    }
    if (pin_ >= 0) gpio_reset_pin(static_cast<gpio_num_t>(pin_));
    kind_ = Kind::Off;
    pin_ = -1;
}

esp_err_t StatusLed::configure(Kind kind, int pin, bool activeLow, uint8_t brightness)
{
    if (kind != Kind::Off && !pinUsable(pin)) return ESP_ERR_INVALID_ARG;
    LockGuard g(mu_);
    release();
    if (kind == Kind::Off) return ESP_OK;
    activeLow_ = activeLow;
    brightness_ = brightness ? brightness : 1;
    lastRgb_ = 0xFFFFFFFF;

    if (kind == Kind::Plain) {
        gpio_config_t io = {};
        io.pin_bit_mask = 1ULL << pin;
        io.mode = GPIO_MODE_OUTPUT;
        esp_err_t err = gpio_config(&io);
        if (err != ESP_OK) return err;
        gpio_set_level(static_cast<gpio_num_t>(pin), activeLow ? 1 : 0);
    } else {
        rmt_tx_channel_config_t ch = {};
        ch.gpio_num = static_cast<gpio_num_t>(pin);
        ch.clk_src = RMT_CLK_SRC_DEFAULT;
        ch.resolution_hz = kRmtHz;
        ch.mem_block_symbols = SOC_RMT_MEM_WORDS_PER_CHANNEL;
        ch.trans_queue_depth = 1;
        rmt_channel_handle_t chan = nullptr;
        esp_err_t err = rmt_new_tx_channel(&ch, &chan);
        if (err != ESP_OK) return err;
        // WS2812: 0 = 0.3 us high + 0.9 us low, 1 = 0.9 us high + 0.3 us low, MSB first.
        rmt_bytes_encoder_config_t enc = {};
        enc.bit0 = {.duration0 = 3, .level0 = 1, .duration1 = 9, .level1 = 0};
        enc.bit1 = {.duration0 = 9, .level0 = 1, .duration1 = 3, .level1 = 0};
        enc.flags.msb_first = 1;
        rmt_encoder_handle_t encoder = nullptr;
        err = rmt_new_bytes_encoder(&enc, &encoder);
        if (err == ESP_OK) err = rmt_enable(chan);
        if (err != ESP_OK) {
            if (encoder) rmt_del_encoder(encoder);
            rmt_del_channel(chan);
            return err;
        }
        rmtChan_ = chan;
        rmtEnc_ = encoder;
    }
    kind_ = kind;
    pin_ = pin;
    ESP_LOGI(TAG, "%s LED on GPIO%d%s", kind == Kind::Rgb ? "RGB" : "plain", pin, activeLow ? " (active low)" : "");
    return ESP_OK;
}

void StatusLed::start(Provider provider, void* ctx)
{
    provider_ = provider;
    ctx_ = ctx;
    esp_timer_create_args_t args = {};
    args.callback = &StatusLed::onTick;
    args.arg = this;
    args.name = "status_led";
    esp_timer_handle_t t = nullptr;
    if (esp_timer_create(&args, &t) == ESP_OK) esp_timer_start_periodic(t, kTickUs);
}

void StatusLed::test(uint32_t seconds)
{
    testUntil_ = ticks_ + seconds * 20;
}

void StatusLed::onTick(void* arg)
{
    static_cast<StatusLed*>(arg)->tick();
}

// Called with mu_ held. r/g/b are full-scale colours; brightness scales them.
void StatusLed::show(bool on, uint8_t r, uint8_t g, uint8_t b)
{
    if (kind_ == Kind::Plain) {
        gpio_set_level(static_cast<gpio_num_t>(pin_), on != activeLow_);
        return;
    }
    const auto scale = [this, on](uint8_t c) { return static_cast<uint8_t>(on ? (c * brightness_ + 254) / 255 : 0); };
    const uint8_t grb[3] = {scale(g), scale(r), scale(b)};
    const uint32_t packed = static_cast<uint32_t>(grb[0]) << 16 | grb[1] << 8 | grb[2];
    if (packed == lastRgb_) return;
    lastRgb_ = packed;
    rmt_transmit_config_t tx = {};
    rmt_transmit(static_cast<rmt_channel_handle_t>(rmtChan_), static_cast<rmt_encoder_handle_t>(rmtEnc_), grb,
                 sizeof(grb), &tx);
}

void StatusLed::tick()
{
    const uint32_t t = ++ticks_;  // 50 ms steps
    LockGuard g(mu_);
    if (kind_ == Kind::Off) return;

    if (t < testUntil_) {  // test: cycle red / green / blue (plain LED: fast blink)
        const uint32_t phase = (t / 6) % 3;
        show(kind_ == Kind::Rgb || (t / 3) % 2 == 0, phase == 0 ? 255 : 0, phase == 1 ? 255 : 0, phase == 2 ? 255 : 0);
        return;
    }
    const State s = provider_ ? provider_(ctx_) : State::Ok;
    switch (s) {
        case State::Setup:  // 1 Hz
            show((t / 10) % 2 == 0, 255, 170, 0);
            break;
        case State::Offline:  // 1 s on / 3 s off
            show(t % 80 < 20, 0, 200, 200);
            break;
        case State::Updating:  // 2.5 Hz
            show((t / 4) % 2 == 0, 0, 0, 255);
            break;
        case State::Failure:  // 5 Hz
            show((t / 2) % 2 == 0, 255, 0, 0);
            break;
        case State::Paused:  // short blink every 3 s
            show(t % 60 < 3, 255, 100, 0);
            break;
        case State::Ok:  // plain: off; RGB: dim green (a quarter of the set brightness)
            if (kind_ == Kind::Rgb)
                show(true, 0, 64, 0);
            else
                show(false, 0, 0, 0);
            break;
    }
}

}  // namespace sinkhole
