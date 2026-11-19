#pragma once
// Pure, platform-independent pieces of the blocklist: the hash function, the
// on-flash header and a binary-search view over sorted 40-bit hashes.
// Header-only so the host tests in test/host can use it without ESP-IDF.
//
// Compatible with esp32-c3-adblock's blocklist.bin (raw, headerless, same hash).

#include <cmath>
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
constexpr uint8_t kBlocklistV4 = 4;

// reserved[0] bit 0: an ECDSA P-256 signature (64 bytes, raw r||s) follows the
// payload. It signs SHA-256 of the first kSignedHeaderBytes header bytes, which
// include the payload SHA-256 and this flag, so it covers the whole list.
constexpr uint8_t kFlagSigned = 0x01;
constexpr size_t kSignedHeaderBytes = 49;
constexpr size_t kSignatureBytes = 64;
inline bool isSigned(const BlocklistHeader& h) { return h.reserved[0] & kFlagSigned; }

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

// v4 "fuse" payload: a 3-wise binary fuse filter (Graf & Lemire, 2022) over the
// 40-bit hashes. A lookup reads 3 fingerprints and XORs them; no sorting, no
// search, and no list of the domains (so no bloom filter can be built from it,
// and none is needed). f is chosen so false matches are no more frequent than
// v2's 40-bit hash collisions at the same list size.
//   uint64 seed; uint32 segmentLength, segmentCountLength, arrayLength;
//   uint8 f (fingerprint bits), 0, 0, 0; uint32 0                  (28 bytes)
//   arrayLength f-bit fingerprints, LSB first, then 8 zero bytes
// The header's reserved[4..7] holds the payload size.
constexpr size_t kV4HeadBytes = 28;
constexpr size_t kV4Pad = 8;

// Fingerprint bits for n domains: ceil(40 - log2 n), in 8..24.
inline uint8_t v4FingerprintBits(uint32_t n)
{
    int log2n = 0;
    while (log2n < 31 && (n >> (log2n + 1))) log2n++;
    const int f = 40 - log2n;
    return static_cast<uint8_t>(f < 8 ? 8 : f > 24 ? 24 : f);
}

// Payload size of a v4 list of n domains. Mirrors payload_v4() in
// tools/build_blocklist.py (used only to tell how many domains fit a slot).
inline size_t v4PayloadBytes(uint32_t n)
{
    const double dn = n < 2 ? 2.0 : static_cast<double>(n);
    const int segExp = static_cast<int>(std::floor(std::log(dn) / std::log(3.33) + 2.25));
    const uint64_t segLen = segExp >= 18 ? (1u << 18) : (1u << (segExp < 0 ? 0 : segExp));
    const double factor = std::fmax(1.125, 0.875 + 0.25 * std::log(1e6) / std::log(dn));
    const uint64_t capacity = static_cast<uint64_t>(std::llround(n * factor));
    const uint64_t segs = (capacity + segLen - 1) / segLen;  // segments incl. the 2 extra
    const uint64_t segCount = segs <= 2 ? 1 : segs - 2;
    const uint64_t arrayLen = (segCount + 2) * segLen;
    return kV4HeadBytes + static_cast<size_t>((arrayLen * v4FingerprintBits(n) + 7) / 8) + kV4Pad;
}

// Most domains whose v4 payload fits `bytes`. Fewer fingerprint bits are needed
// past each power of two, so search each [2^k, 2^(k+1)) range separately.
inline uint32_t v4Capacity(size_t bytes)
{
    uint32_t best = 0;
    for (int k = 0; k < 26; k++) {
        uint32_t lo = 1u << k, hi = (2u << k) - 1;
        if (v4PayloadBytes(lo) > bytes) continue;
        while (lo < hi) {  // largest n in the range that fits
            const uint32_t mid = lo + (hi - lo + 1) / 2;
            if (v4PayloadBytes(mid) <= bytes) lo = mid;
            else hi = mid - 1;
        }
        if (lo > best) best = lo;
    }
    return best;
}

inline uint32_t rd32le(const uint8_t* p)
{
    return static_cast<uint32_t>(p[0]) | static_cast<uint32_t>(p[1]) << 8 |
           static_cast<uint32_t>(p[2]) << 16 | static_cast<uint32_t>(p[3]) << 24;
}

inline size_t payloadSize(uint8_t version, uint32_t count)
{
    return version == kBlocklistV2 ? kV2IndexBytes + static_cast<size_t>(count) * 3
                                   : static_cast<size_t>(count) * kHashBytes;
}

inline size_t payloadSize(const BlocklistHeader& h)
{
    return h.version == kBlocklistV4 ? rd32le(h.reserved + 4) : payloadSize(h.version, h.count);
}

// Largest list a slot of `slotBytes` can hold in a given format (v4: an estimate).
inline uint32_t capacityFor(uint8_t version, size_t slotBytes)
{
    const size_t usable = slotBytes > 64 ? slotBytes - 64 : 0;
    if (version == kBlocklistV4) return usable > kSignatureBytes ? v4Capacity(usable - kSignatureBytes) : 0;
    if (version == kBlocklistV2) return usable > kV2IndexBytes ? static_cast<uint32_t>((usable - kV2IndexBytes) / 3) : 0;
    return static_cast<uint32_t>(usable / kHashBytes);
}

// No board holds anywhere near this many domains (16 MB of flash, 5 bytes each
// at most), and below it count * 5 can't wrap a 32-bit size_t: a header with a
// huge count must be refused before any size is worked out from it.
constexpr uint32_t kMaxListDomains = 1u << 26;

inline bool headerLooksValid(const BlocklistHeader& h)
{
    return memcmp(h.magic, kBlocklistMagic, 4) == 0 && h.count <= kMaxListDomains &&
           (h.version == kBlocklistV1 || h.version == kBlocklistV2 || h.version == kBlocklistV4) &&
           h.hashBytes == kHashBytes && h.headerSize == sizeof(BlocklistHeader);
}

// Read-only view over a blocklist payload in either format.
class HashTable {
public:
    HashTable() = default;
    HashTable(const uint8_t* payload, uint32_t count, uint8_t version = kBlocklistV1, size_t payloadBytes = 0)
        : data_(payload), count_(count), version_(version), bytes_(payloadBytes)
    {
    }

    uint32_t size() const { return count_; }
    bool empty() const { return count_ == 0; }
    uint8_t version() const { return version_; }

    bool contains(uint64_t h) const
    {
        if (version_ == kBlocklistV4) return containsV4(h);
        return version_ == kBlocklistV2 ? containsV2(h) : containsV1(h);
    }
    // False for a filter (v4): it can't list its domains, so callers skip the bloom filter.
    bool canList() const { return version_ != kBlocklistV4; }

    // Calls fn(hash) for every entry, in order (used to build the bloom filter).
    template <typename F>
    void forEach(F&& fn) const
    {
        if (version_ == kBlocklistV4) return;  // a filter can't list its keys
        if (version_ != kBlocklistV2) {
            for (uint32_t i = 0; i < count_; i++) fn(loadHash(data_ + static_cast<size_t>(i) * kHashBytes));
            return;
        }
        const uint8_t* cnt = counts();
        const uint8_t* s = suffixes();
        for (uint32_t b = 0; b < kV2Buckets; b++)
            for (uint32_t i = 0; i < cnt[b]; i++, s += 3)
                fn(static_cast<uint64_t>(b) << 24 | static_cast<uint64_t>(s[0]) | static_cast<uint64_t>(s[1]) << 8 |
                   static_cast<uint64_t>(s[2]) << 16);
    }

    // Structure check before activation: v1 strictly ascending; v2 index
    // consistent with the count and suffixes ascending within each bucket.
    bool isValid() const
    {
        if (version_ == kBlocklistV4) return validV4();
        return version_ == kBlocklistV2 ? validV2() : validV1();
    }

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
            // Bucket counts come from the file: never walk past count_ entries.
            if (cnt[b] > count_ - total) return false;
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

    // ---- v4 (binary fuse filter) ----
    static uint64_t rd64le(const uint8_t* p) { return rd32le(p) | static_cast<uint64_t>(rd32le(p + 4)) << 32; }
    static uint64_t mix(uint64_t h)  // murmur3 finalizer
    {
        h ^= h >> 33;
        h *= 0xff51afd7ed558ccdULL;
        h ^= h >> 33;
        h *= 0xc4ceb9fe1a85ec53ULL;
        h ^= h >> 33;
        return h;
    }
    uint32_t v4Fingerprint(uint32_t i) const  // f-bit entry i (the payload is padded)
    {
        const uint8_t f = data_[20];
        const uint32_t bit = i * f;
        const uint8_t* p = data_ + kV4HeadBytes + (bit >> 3);
        const uint64_t w = rd32le(p) | static_cast<uint64_t>(p[4]) << 32;
        return static_cast<uint32_t>(w >> (bit & 7)) & ((1u << f) - 1);
    }

    bool containsV4(uint64_t key) const
    {
        const uint64_t h = mix(key + rd64le(data_));
        const uint32_t segLen = rd32le(data_ + 8), segCountLen = rd32le(data_ + 12);
        // high 32 bits of h * segCountLen, with 32-bit multiplies only
        const uint64_t lo = (h & 0xFFFFFFFFu) * segCountLen, hi = (h >> 32) * segCountLen;
        const uint32_t h0 = static_cast<uint32_t>((hi + (lo >> 32)) >> 32);
        const uint32_t mask = segLen - 1;
        const uint32_t h1 = (h0 + segLen) ^ (static_cast<uint32_t>(h >> 18) & mask);
        const uint32_t h2 = (h0 + 2 * segLen) ^ (static_cast<uint32_t>(h) & mask);
        const uint32_t fp = static_cast<uint32_t>(h ^ (h >> 32)) & ((1u << data_[20]) - 1);
        return fp == (v4Fingerprint(h0) ^ v4Fingerprint(h1) ^ v4Fingerprint(h2));
    }

    bool validV4() const  // structure only: the content is covered by the SHA-256
    {
        if (bytes_ < kV4HeadBytes) return false;
        const uint32_t segLen = rd32le(data_ + 8), segCountLen = rd32le(data_ + 12), len = rd32le(data_ + 16);
        const uint8_t f = data_[20];
        if (f < 8 || f > 24 || segLen < 4 || segLen > (1u << 18) || (segLen & (segLen - 1))) return false;
        // 64-bit: these come from the file, and a 32-bit sum or product could
        // wrap into a size that matches while the lookups index far past it.
        if (segCountLen == 0 || segCountLen % segLen ||
            len != static_cast<uint64_t>(segCountLen) + 2ull * segLen)
            return false;
        return bytes_ == kV4HeadBytes + (static_cast<uint64_t>(len) * f + 7) / 8 + kV4Pad && count_ > 0;
    }

    const uint8_t* data_ = nullptr;
    uint32_t count_ = 0;
    uint8_t version_ = kBlocklistV1;
    size_t bytes_ = 0;  // payload size (v4 validation)
};

// Bloom filter over 40-bit domain hashes, on caller-provided memory. The inputs
// are already FNV hashes, so k bit positions come from double hashing.
class BloomBits {
public:
    void attach(uint8_t* bits, size_t bytes, uint8_t k)
    {
        bits_ = bits;
        bytes_ = bytes;
        nbits_ = static_cast<uint32_t>(bytes * 8);
        k_ = k;
    }
    void clear() { memset(bits_, 0, bytes_); }
    void add(uint64_t h)
    {
        uint32_t a, b;
        seeds(h, a, b);
        for (uint8_t i = 0; i < k_; i++, a += b) {
            const uint32_t bit = slot(a);
            bits_[bit >> 3] |= static_cast<uint8_t>(1u << (bit & 7));
        }
    }
    bool mayContain(uint64_t h) const
    {
        uint32_t a, b;
        seeds(h, a, b);
        for (uint8_t i = 0; i < k_; i++, a += b) {
            const uint32_t bit = slot(a);
            if (!(bits_[bit >> 3] & (1u << (bit & 7)))) return false;
        }
        return true;
    }
    bool ready() const { return bits_ != nullptr; }
    size_t bytes() const { return bytes_; }

private:
    // 32-bit only: 64-bit division is a slow library call on these MCUs.
    static void seeds(uint64_t h, uint32_t& a, uint32_t& b)
    {
        a = static_cast<uint32_t>((h * 0x9E3779B97F4A7C15ULL) >> 32);
        b = static_cast<uint32_t>((h * 0xC2B2AE3D27D4EB4FULL) >> 32) | 1;  // odd step
    }
    uint32_t slot(uint32_t a) const  // multiply-shift range reduction, no modulo
    {
        return static_cast<uint32_t>((static_cast<uint64_t>(a) * nbits_) >> 32);
    }
    uint8_t* bits_ = nullptr;
    size_t bytes_ = 0;
    uint32_t nbits_ = 0;
    uint8_t k_ = 0;
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
