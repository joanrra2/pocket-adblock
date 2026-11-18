#pragma once
// The device log (what ESP_LOGx prints on the serial port) kept in a ring
// buffer for the web UI: 64 KB in PSRAM when the board has it, 4 KB of internal
// RAM otherwise (the last ~40 lines). Allocated once at boot.
//
// Readers poll with a byte position: read(from) returns what was logged since,
// and the position to ask from next time. Positions only grow; text older than
// the buffer is gone (the reader starts at the next whole line).

#include <cstddef>
#include <cstdint>

namespace sinkhole {

class LogBuffer {
public:
    static void begin();  // allocate and hook esp_log (early in boot)

    struct Chunk {
        uint32_t start;  // position of the first byte copied
        uint32_t next;   // position after the last byte copied
        size_t len;
    };
    // Copies up to cap bytes logged at or after `from`.
    static Chunk read(uint32_t from, char* out, size_t cap);
    static uint32_t end();  // position after the newest byte
    static size_t capacity();
    static bool inPsram();
};

}  // namespace sinkhole
