#include "sinkhole/app.hpp"

extern "C" void app_main(void)
{
    // Function-local static: constructed here, after the scheduler is running,
    // and lives in .bss for the lifetime of the firmware. No heap.
    static sinkhole::App app;
    app.start();
}
