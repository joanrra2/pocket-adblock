#pragma once
// Things worth telling the owner about (a PC came online, a crash, a failed
// update...). Any component can emit one; the notifier (Pro builds, when set
// up) turns them into phone notifications. Without a sink, emit() returns at
// once, so Lite builds pay nothing.

#include <cstdint>

namespace sinkhole::events {

// Bits of Settings::notifyEvents: which kinds the owner wants to hear about.
enum Kind : uint16_t {
    Restart = 1,     // crash, watchdog or power dip; firmware updates
    Wake = 2,        // wake results ("office-pc online after 41 s")
    HostState = 4,   // a host with an IP went online / offline
    Update = 8,      // blocklist download failed, firmware update installed
    Uplink = 16,     // Wi-Fi back after an outage
    Reply = 0x8000,  // answer to a remote command (always sent)
};
constexpr uint16_t kAllKinds = Restart | Wake | HostState | Update | Uplink;

using Sink = void (*)(Kind kind, const char* text);
void setSink(Sink sink);
bool active();  // a sink is set
// printf-style; the text is cut at 160 characters.
void emit(Kind kind, const char* fmt, ...) __attribute__((format(printf, 2, 3)));

}  // namespace sinkhole::events
