#pragma once
// BOOT button recovery (polled, active low):
//   hold >= 3 s, release  -> setup AP on for 15 minutes
//   hold >= 10 s          -> factory reset (settings erased, then reboot)

#include "sinkhole/rtos.hpp"
#include "sinkhole/wifi_manager.hpp"

namespace sinkhole {

class BootButton {
public:
    explicit BootButton(WifiManager& wifi) : wifi_(wifi) {}
    void start();

private:
    static void taskEntry(void* arg);
    void run();

    WifiManager& wifi_;
    StaticTask<2560> task_;
};

}  // namespace sinkhole
