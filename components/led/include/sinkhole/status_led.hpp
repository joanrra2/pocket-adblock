#pragma once
// Status LED: a plain LED on a GPIO, or one WS2812 RGB LED (via RMT). Which
// one and on which pin is board wiring the chip can't detect, so it is a
// setting (the web UI offers presets for common boards of this chip). Pins the
// flash / PSRAM use are refused. Off by default.
//
//   Setup access point   slow blink         yellow
//   No uplink            very slow blink    teal
//   Updating             medium blink       blue
//   Failure              fast blink         red
//   Blocking paused      short blink / 3 s  orange
//   All good             off (plain LED)    dim green (RGB)

#include <atomic>
#include <cstdint>

#include "esp_err.h"
#include "sinkhole/rtos.hpp"

namespace sinkhole {

class StatusLed {
public:
    enum class Kind : uint8_t { Off = 0, Plain = 1, Rgb = 2 };
    enum class State : uint8_t { Ok, Paused, Setup, Offline, Updating, Failure };

    using Provider = State (*)(void* ctx);  // called every 50 ms from the timer task

    // Validates the pin (output-capable, not used by flash/PSRAM) and applies.
    esp_err_t configure(Kind kind, int pin, bool activeLow, uint8_t brightness);
    void start(Provider provider, void* ctx);
    void test(uint32_t seconds = 4);  // cycle colours / blink fast, then back to the state
    static bool pinUsable(int pin);

private:
    static void onTick(void* arg);
    void tick();
    void show(bool on, uint8_t r, uint8_t g, uint8_t b);
    void release();

    Mutex mu_;
    Kind kind_ = Kind::Off;
    int pin_ = -1;
    bool activeLow_ = false;
    uint8_t brightness_ = 24;
    void* rmtChan_ = nullptr;  // rmt_channel_handle_t
    void* rmtEnc_ = nullptr;   // rmt_encoder_handle_t
    Provider provider_ = nullptr;
    void* ctx_ = nullptr;
    uint32_t ticks_ = 0;
    std::atomic<uint32_t> testUntil_{0};  // tick count
    uint32_t lastRgb_ = 0xFFFFFFFF;       // avoid re-sending the same colour
};

}  // namespace sinkhole
