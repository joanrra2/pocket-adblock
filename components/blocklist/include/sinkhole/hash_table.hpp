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
    uint8_t version;      // 1 = sorted 5-byte hashes, 2 = compact (see below)
    uint8_t hashBytes;    // 5 (logical hash width)
    uint16_t headerSize;  // 64
    uint32_t count;       // number of hashes
    uint32_t createdUnix; // build time, 0 if unknown
    uint8_t sha256[32];   // SHA-256 of the payload
    uint8_t reserved[16];
};
static_assert(sizeof(BlocklistHeader) == 64, "header must be 64 bytes");

constexpr char kBlocklistMagic[4] = {'S', 'H', 'B', 'L'};
constexpr uint8_t kBlocklistV1 = 1;
constexpr uint8_t kBlocklistV2 = 2;

// v2 "compact" payload (upstream issue #3): each 40-bit hash = 16-bit bucket
// (top bits) + 24-bit suffix.
//   uint32 coarse[256]  entries before bucket i*256 (little endian)    1 KB
//   uint8  counts[65536] entries per bucket (max 255)                   64 KB
//   uint8  suffix[count][3], grouped by bucket, ascending within it
// 3 bytes per domain instead of 5, and a lookup touches the index plus one
// small bucket instead of ~17 binary-search steps.
constexpr size_t kV2Buckets = 65536;
constexpr size_t kV2CoarseBytes = 256 * 4;
constexpr size_t kV2IndexBytes = kV2CoarseBytes + kV2Buckets;

inline size_t payloadSize(uint8_t version, uint32_t count)
{
    return version == kBlocklistV2 ? kV2IndexBytes + static_cast<size_t>(count) * 3
                                   : static_cast<size_t>(count) * kHashBytes;
}

// Largest list a slot of `slotBytes` can hold in a given format.
inline uint32_t capacityFor(uint8_t version, size_t slotBytes)
{
    const size_t usable = slotBytes > 64 ? slotBytes - 64 : 0;
    if (version == kBlocklistV2) return usable > kV2IndexBytes ? static_cast<uint32_t>((usable - kV2IndexBytes) / 3) : 0;
    return static_cast<uint32_t>(usable / kHashBytes);
}

inline bool headerLooksValid(const BlocklistHeader& h)
{
    return memcmp(h.magic, kBlocklistMagic, 4) == 0 &&
           (h.version == kBlocklistV1 || h.version == kBlocklistV2) && h.hashBytes == kHashBytes &&
           h.headerSize == sizeof(BlocklistHeader);
}

inline uint32_t rd32le(const uint8_t* p)
{
    return static_cast<uint32_t>(p[0]) | static_cast<uint32_t>(p[1]) << 8 |
           static_cast<uint32_t>(p[2]) << 16 | static_cast<uint32_t>(p[3]) << 24;
}

// Read-only view over a blocklist payload in either format.
class HashTable {
public:
    HashTable() = default;
    HashTable(const uint8_t* payload, uint32_t count, uint8_t version = kBlocklistV1)
        : data_(payload), count_(count), version_(version)
    {
    }

    uint32_t size() const { return count_; }
    bool empty() const { return count_ == 0; }
    uint8_t version() const { return version_; }

    bool contains(uint64_t h) const { return version_ == kBlocklistV2 ? containsV2(h) : containsV1(h); }

    // Structure check before activation: v1 strictly ascending; v2 index
    // consistent with the count and suffixes ascending within each bucket.
    bool isValid() const { return version_ == kBlocklistV2 ? validV2() : validV1(); }

private:
    bool containsV1(uint64_t h) const
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

    bool validV1() const
    {
        for (uint32_t i = 1; i < count_; i++) {
            if (loadHash(data_ + static_cast<size_t>(i - 1) * kHashBytes) >=
                loadHash(data_ + static_cast<size_t>(i) * kHashBytes))
                return false;
        }
        return true;
    }

    const uint8_t* counts() const { return data_ + kV2CoarseBytes; }
    const uint8_t* suffixes() const { return data_ + kV2IndexBytes; }

    bool containsV2(uint64_t h) const
    {
        const uint32_t bucket = static_cast<uint32_t>(h >> 24);   // top 16 of 40 bits
        const uint32_t suffix = static_cast<uint32_t>(h) & 0xFFFFFF;
        const uint8_t* cnt = counts();
        uint32_t start = rd32le(data_ + (bucket >> 8) * 4);
        for (uint32_t b = bucket & ~0xFFu; b < bucket; b++) start += cnt[b];
        const uint8_t* s = suffixes() + static_cast<size_t>(start) * 3;
        for (uint32_t i = 0; i < cnt[bucket]; i++, s += 3) {
            const uint32_t v = static_cast<uint32_t>(s[0]) | static_cast<uint32_t>(s[1]) << 8 |
                               static_cast<uint32_t>(s[2]) << 16;
            if (v == suffix) return true;
            if (v > suffix) return false;  // ascending within the bucket
        }
        return false;
    }

    bool validV2() const
    {
        const uint8_t* cnt = counts();
        const uint8_t* s = suffixes();
        uint32_t total = 0;
        for (uint32_t b = 0; b < kV2Buckets; b++) {
            if ((b & 0xFF) == 0 && rd32le(data_ + (b >> 8) * 4) != total) return false;
            uint32_t prev = 0;
            for (uint32_t i = 0; i < cnt[b]; i++, s += 3) {
                const uint32_t v = static_cast<uint32_t>(s[0]) | static_cast<uint32_t>(s[1]) << 8 |
                                   static_cast<uint32_t>(s[2]) << 16;
                if (i && v <= prev) return false;
                prev = v;
            }
            total += cnt[b];
        }
        return total == count_;
    }

    const uint8_t* data_ = nullptr;
    uint32_t count_ = 0;
    uint8_t version_ = kBlocklistV1;
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
