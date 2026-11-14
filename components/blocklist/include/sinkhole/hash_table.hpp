#pragma once
// Pure, platform-independent pieces of the blocklist: the hash function, the
// on-flash header and a binary-search view over sorted 40-bit hashes.
// Header-only so the host tests in test/host can use it without ESP-IDF.
//
// Compatible with esp32-c3-adblock's blocklist.bin (raw, headerless, same hash).

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace sinkhole {

constexpr int kHashBytes = 5;  // 40-bit
constexpr uint64_t kHashMask = (1ULL << (kHashBytes * 8)) - 1;

// FNV-1a 64-bit truncated to 40 bits. Must match tools/build_blocklist.py.
constexpr uint64_t fnv1a40(const char* s, size_t n)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < n; i++) {
        h ^= static_cast<uint8_t>(s[i]);
        h *= 0x100000001b3ULL;
    }
    return h & kHashMask;
}

inline uint64_t loadHash(const uint8_t* p)
{
    uint64_t v = 0;
    for (int k = 0; k < kHashBytes; k++) v |= static_cast<uint64_t>(p[k]) << (8 * k);
    return v;
}

// 64-byte header at the start of each blocklist partition (and optionally at the
// start of an uploaded file). Raw uploads get a header synthesized on the device.
struct __attribute__((packed)) BlocklistHeader {
    char magic[4];        // "SHBL"
    uint8_t version;      // 1
    uint8_t hashBytes;    // 5
    uint16_t headerSize;  // 64
    uint32_t count;       // number of hashes in the payload
    uint32_t createdUnix; // build time, 0 if unknown
    uint8_t sha256[32];   // SHA-256 of the payload (count * hashBytes bytes)
    uint8_t reserved[16];
};
static_assert(sizeof(BlocklistHeader) == 64, "header must be 64 bytes");

constexpr char kBlocklistMagic[4] = {'S', 'H', 'B', 'L'};
constexpr uint8_t kBlocklistVersion = 1;

inline bool headerLooksValid(const BlocklistHeader& h)
{
    return memcmp(h.magic, kBlocklistMagic, 4) == 0 && h.version == kBlocklistVersion &&
           h.hashBytes == kHashBytes && h.headerSize == sizeof(BlocklistHeader);
}

// Read-only view over `count` sorted little-endian 40-bit hashes.
class HashTable {
public:
    HashTable() = default;
    HashTable(const uint8_t* data, uint32_t count) : data_(data), count_(count) {}

    uint32_t size() const { return count_; }
    bool empty() const { return count_ == 0; }

    bool contains(uint64_t h) const
    {
        uint32_t lo = 0, hi = count_;
        while (lo < hi) {
            uint32_t mid = lo + (hi - lo) / 2;
            uint64_t v = loadHash(data_ + static_cast<size_t>(mid) * kHashBytes);
            if (v == h) return true;
            if (v < h)
                lo = mid + 1;
            else
                hi = mid;
        }
        return false;
    }

    // Strictly ascending? (Required for binary search; checked before activation.)
    bool isSorted() const
    {
        for (uint32_t i = 1; i < count_; i++) {
            if (loadHash(data_ + static_cast<size_t>(i - 1) * kHashBytes) >=
                loadHash(data_ + static_cast<size_t>(i) * kHashBytes))
                return false;
        }
        return true;
    }

private:
    const uint8_t* data_ = nullptr;
    uint32_t count_ = 0;
};

// Calls fn(suffix, len) for "a.b.example.com", "b.example.com", "example.com".
// Stops before the bare TLD, like the original firmware. fn returns true to stop.
template <typename F>
inline bool forEachSuffix(const char* domain, size_t len, F&& fn)
{
    const char* p = domain;
    const char* end = domain + len;
    while (p < end) {
        if (fn(p, static_cast<size_t>(end - p))) return true;
        const char* dot = static_cast<const char*>(memchr(p, '.', static_cast<size_t>(end - p)));
        if (!dot) break;
        const char* next = dot + 1;
        if (!memchr(next, '.', static_cast<size_t>(end - next))) break;
        p = next;
    }
    return false;
}

}  // namespace sinkhole
