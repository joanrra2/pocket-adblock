#pragma once
// Wall clock (NTP) and the last restarts: why each one happened, which firmware
// was running and, once the clock is known, when.
//
// The reason the firmware restarts itself (an update, a restore, the web UI...)
// is written to RTC memory just before esp_restart(), so the next boot can name
// it. RTC memory also carries the boot time and the last seen uptime across a
// crash or watchdog reset, so the previous boot's record gets them filled in.
// Only a power cut loses those. One small NVS write per boot, none while running.

#include <cstddef>
#include <cstdint>

namespace sinkhole {

class BootLog {
public:
    // Why the firmware restarted itself (kept with the record).
    enum class Cause : uint8_t {
        None = 0,
        FirmwareUpload = 1,    // image uploaded in the web UI
        FirmwareInstall = 2,   // online update (Install or automatic)
        Restore = 3,           // settings restored from a backup
        WebRestart = 4,        // Restart in the web UI
        FactoryReset = 5,      // BOOT held 10 s
        Remote = 6,            // remote command (MQTT / notifications)
    };

    struct Record {
        uint32_t bootUnix;  // 0 = not known (no clock during that boot)
        uint32_t ranFor;    // seconds that boot ran (approx.), 0 = not known
        uint8_t reason;     // esp_reset_reason_t
        uint8_t cause;      // Cause, for software restarts
        char version[18];
    };
    static constexpr size_t kRecords = 10;

    // At boot, after NVS is up: stores this boot's record.
    static void begin(const char* version);
    // Just before a deliberate restart.
    static void noteRestart(Cause cause);
    // Remember the uptime in RTC memory (call every few minutes).
    static void tick();
    // NTP, once there is an uplink. Safe to call again.
    static void startTimeSync();

    static bool timeKnown();
    static uint32_t now();       // unix seconds, 0 until the clock is set
    static uint32_t bootUnix();  // this boot, 0 until the clock is set

    // Newest first; the first one is this boot.
    static size_t list(Record* out, size_t cap);
    // "power on", "crash", "watchdog", or the Cause when the firmware restarted itself.
    static const char* why(const Record& r);
    static bool unexpected(const Record& r);  // crash, watchdog, brownout
};

}  // namespace sinkhole
