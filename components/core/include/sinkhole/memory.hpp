#pragma once
// Boot-time sizing of large tables: prefer PSRAM when the board has it, fall
// back to a small internal-RAM table when it doesn't. Allocated once during
// App::start() and never freed, so there is still no heap churn at runtime.
// The same binary runs on chips/boards with and without PSRAM.

#include <cstddef>
#include <cstdint>

#include "esp_heap_caps.h"

namespace sinkhole {

struct Region {
    void* ptr = nullptr;
    size_t count = 0;  // number of elements that fit
    bool psram = false;
};

inline bool psramAvailable()
{
    return heap_caps_get_total_size(MALLOC_CAP_SPIRAM) > 0;
}

// Tries `psramCount` elements in PSRAM, halving down to `internalCount`, then
// `internalCount` elements in internal RAM. count == 0 means disabled/failed.
inline Region allocTable(size_t elemSize, size_t psramCount, size_t internalCount)
{
    Region r;
    if (psramAvailable()) {
        for (size_t n = psramCount; n >= internalCount && n > 0; n /= 2) {
            r.ptr = heap_caps_calloc(n, elemSize, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
            if (r.ptr) {
                r.count = n;
                r.psram = true;
                return r;
            }
        }
    }
    if (internalCount) {
        r.ptr = heap_caps_calloc(internalCount, elemSize, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
        if (r.ptr) r.count = internalCount;
    }
    return r;
}

// Room to open a TLS session now. mbedTLS takes its 16 KB receive buffer in
// one piece from internal RAM, and about 36 KB in all by the end of the
// handshake. Without that room the handshake fails part way, after taking
// what was left from everything else (DNS included) and leaving holes, so
// callers skip the connection and try again later instead.
constexpr size_t kTlsMinFree = 36 * 1024;
constexpr size_t kTlsMinBlock = 17 * 1024;

inline bool tlsRoom()
{
    constexpr uint32_t kCaps = MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT;
    return heap_caps_get_free_size(kCaps) >= kTlsMinFree && heap_caps_get_largest_free_block(kCaps) >= kTlsMinBlock;
}

}  // namespace sinkhole
