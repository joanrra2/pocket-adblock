#include "sinkhole/boot_log.hpp"

#include <array>
#include <cstring>
#include <ctime>
#include <sys/time.h>

#include "esp_attr.h"
#include "esp_log.h"
#include "esp_netif_sntp.h"
#include "esp_system.h"
#include "sdkconfig.h"
#include "sinkhole/config.hpp"
#include "sinkhole/rtos.hpp"
#include "sinkhole/text.hpp"

namespace sinkhole {

namespace {
constexpr const char* TAG = "boot";
constexpr const char* kKey = "boots";
constexpr uint32_t kMagic = 0x5b007109;
// Anything earlier is a clock that was never set.
constexpr time_t kValidAfter = 1700000000;  // Nov 2023

// Survives software resets, panics and watchdog resets (not a power cut).
struct RtcState {
    uint32_t magic;
    uint32_t bootUnix;
    uint32_t uptime;
    uint8_t cause;
};
RTC_NOINIT_ATTR RtcState sRtc;

std::array<BootLog::Record, BootLog::kRecords> sRecords{};  // newest first
size_t sCount = 0;
bool sSyncStarted = false;

void onTimeSync(struct timeval* tv)
{
    if (tv->tv_sec < kValidAfter) return;
    const uint32_t boot = static_cast<uint32_t>(tv->tv_sec) - uptimeSeconds();
    if (!sRtc.bootUnix) ESP_LOGI(TAG, "clock set by NTP");
    sRtc.bootUnix = boot;
}
}  // namespace

void BootLog::begin(const char* version)
{
    const bool rtcValid = sRtc.magic == kMagic;
    size_t len = 0;
    if (nvs::loadBlob(kKey, sRecords.data(), sizeof(sRecords), &len) != ESP_OK) len = 0;
    sCount = len / sizeof(Record);

    // The previous boot (newest stored record): fill in what RTC memory knows.
    if (sCount && rtcValid) {
        if (!sRecords[0].bootUnix) sRecords[0].bootUnix = sRtc.bootUnix;
        sRecords[0].ranFor = sRtc.uptime;
    }
    const esp_reset_reason_t reason = esp_reset_reason();
    Record r{};
    r.reason = static_cast<uint8_t>(reason);
    r.cause = rtcValid && reason == ESP_RST_SW ? sRtc.cause : 0;
    copyStr(r.version, version);
    if (sCount == kRecords) sCount--;
    memmove(&sRecords[1], &sRecords[0], sCount * sizeof(Record));
    sRecords[0] = r;
    sCount++;
    nvs::saveBlob(kKey, sRecords.data(), sCount * sizeof(Record));

    sRtc = RtcState{kMagic, 0, 0, 0};
    ESP_LOGI(TAG, "restart reason: %s", why(r));
}

void BootLog::noteRestart(Cause cause)
{
    sRtc.cause = static_cast<uint8_t>(cause);
    tick();
}

void BootLog::tick()
{
    sRtc.magic = kMagic;
    sRtc.uptime = uptimeSeconds();
}

void BootLog::startTimeSync()
{
    if (sSyncStarted || !CONFIG_SINKHOLE_NTP_SERVER[0]) return;
    esp_sntp_config_t cfg = ESP_NETIF_SNTP_DEFAULT_CONFIG(CONFIG_SINKHOLE_NTP_SERVER);
    cfg.sync_cb = &onTimeSync;
    if (esp_netif_sntp_init(&cfg) == ESP_OK) sSyncStarted = true;
}

bool BootLog::timeKnown()
{
    return time(nullptr) >= kValidAfter;
}

uint32_t BootLog::now()
{
    const time_t t = time(nullptr);
    return t >= kValidAfter ? static_cast<uint32_t>(t) : 0;
}

uint32_t BootLog::bootUnix()
{
    return timeKnown() ? now() - uptimeSeconds() : 0;
}

size_t BootLog::list(Record* out, size_t cap)
{
    const size_t n = sCount < cap ? sCount : cap;
    memcpy(out, sRecords.data(), n * sizeof(Record));
    if (n) {
        out[0].bootUnix = bootUnix();
        out[0].ranFor = uptimeSeconds();
    }
    return n;
}

const char* BootLog::why(const Record& r)
{
    if (r.reason == ESP_RST_SW) {
        switch (static_cast<Cause>(r.cause)) {
            case Cause::FirmwareUpload: return "firmware uploaded";
            case Cause::FirmwareInstall: return "firmware update";
            case Cause::Restore: return "settings restored";
            case Cause::WebRestart: return "restarted from the web UI";
            case Cause::FactoryReset: return "factory reset";
            case Cause::Remote: return "remote restart";
            default: return "software restart";
        }
    }
    switch (static_cast<esp_reset_reason_t>(r.reason)) {
        case ESP_RST_POWERON: return "power on";
        case ESP_RST_EXT: return "reset pin";
        case ESP_RST_PANIC: return "crash";
        case ESP_RST_INT_WDT:
        case ESP_RST_TASK_WDT:
        case ESP_RST_WDT: return "watchdog";
        case ESP_RST_BROWNOUT: return "power dip (brownout)";
        case ESP_RST_DEEPSLEEP: return "wake from sleep";
        case ESP_RST_USB: return "USB reset";
        case ESP_RST_JTAG: return "debugger reset";
        default: return "unknown";
    }
}

bool BootLog::unexpected(const Record& r)
{
    switch (static_cast<esp_reset_reason_t>(r.reason)) {
        case ESP_RST_PANIC:
        case ESP_RST_INT_WDT:
        case ESP_RST_TASK_WDT:
        case ESP_RST_WDT:
        case ESP_RST_BROWNOUT: return true;
        default: return false;
    }
}

}  // namespace sinkhole
