// Host unit tests for the platform-independent parts (hash table, DNS packet
// handling). No ESP-IDF needed, run from the repo root:
//   g++ -std=c++17 -Icomponents/blocklist/include -Icomponents/dns/include test/host/test_logic.cpp -o test_logic
//   ./test_logic
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "sinkhole/dns_packet.hpp"
#include "sinkhole/hash_table.hpp"

using namespace sinkhole;

static int failures = 0;
#define CHECK(c)                                                       \
    do {                                                               \
        if (!(c)) {                                                    \
            std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c);   \
            failures++;                                                \
        }                                                              \
    } while (0)

static uint64_t h(const char* s) { return fnv1a40(s, std::strlen(s)); }

static void testHashTable()
{
    // Same values as tools/build_blocklist.py's fnv() for these strings.
    CHECK(h("") == (0xcbf29ce484222325ULL & kHashMask));

    std::vector<uint64_t> v = {h("doubleclick.net"), h("ads.example.com"), h("tracker.io")};
    std::sort(v.begin(), v.end());
    std::vector<uint8_t> blob;
    for (uint64_t x : v)
        for (int k = 0; k < kHashBytes; k++) blob.push_back(static_cast<uint8_t>(x >> (8 * k)));

    HashTable t(blob.data(), static_cast<uint32_t>(v.size()));
    CHECK(t.isValid());
    CHECK(t.contains(h("doubleclick.net")));
    CHECK(t.contains(h("tracker.io")));
    CHECK(!t.contains(h("github.com")));

    std::vector<std::string> seen;
    const char* d = "a.b.ads.example.com";
    forEachSuffix(d, std::strlen(d), [&](const char* s, size_t n) {
        seen.emplace_back(s, n);
        return false;
    });
    CHECK(seen.size() == 4);
    CHECK(seen.back() == "example.com");  // never the bare TLD
}

// Same layout as tools/build_blocklist.py payload_v2().
static std::vector<uint8_t> buildV2(const std::vector<uint64_t>& sorted)
{
    std::vector<std::vector<uint32_t>> buckets(kV2Buckets);
    for (uint64_t h : sorted) buckets[h >> 24].push_back(static_cast<uint32_t>(h) & 0xFFFFFF);
    std::vector<uint8_t> out(kV2IndexBytes);
    uint32_t total = 0;
    for (size_t b = 0; b < kV2Buckets; b++) {
        if (b % 256 == 0)
            for (int k = 0; k < 4; k++) out[(b / 256) * 4 + k] = static_cast<uint8_t>(total >> (8 * k));
        out[kV2CoarseBytes + b] = static_cast<uint8_t>(buckets[b].size());
        total += static_cast<uint32_t>(buckets[b].size());
    }
    for (const auto& b : buckets)
        for (uint32_t s : b) {
            out.push_back(static_cast<uint8_t>(s));
            out.push_back(static_cast<uint8_t>(s >> 8));
            out.push_back(static_cast<uint8_t>(s >> 16));
        }
    return out;
}

static void testCompactFormat()
{
    // 300k pseudo-random 40-bit hashes, sorted and unique.
    uint64_t x = 0x9E3779B97F4A7C15ULL;
    std::vector<uint64_t> v;
    for (int i = 0; i < 300000; i++) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        v.push_back(x & kHashMask);
    }
    std::sort(v.begin(), v.end());
    v.erase(std::unique(v.begin(), v.end()), v.end());
    const uint32_t n = static_cast<uint32_t>(v.size());

    std::vector<uint8_t> v1;
    for (uint64_t h : v)
        for (int k = 0; k < kHashBytes; k++) v1.push_back(static_cast<uint8_t>(h >> (8 * k)));
    std::vector<uint8_t> v2 = buildV2(v);
    CHECK(v2.size() == payloadSize(kBlocklistV2, n));
    CHECK(v2.size() < v1.size());

    HashTable a(v1.data(), n, kBlocklistV1), b(v2.data(), n, kBlocklistV2);
    CHECK(a.isValid());
    CHECK(b.isValid());
    int mismatches = 0, misses = 0;
    for (size_t i = 0; i < v.size(); i += 7) misses += !b.contains(v[i]);
    for (int i = 0; i < 200000; i++) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        const uint64_t probe = x & kHashMask;
        mismatches += a.contains(probe) != b.contains(probe);
    }
    CHECK(misses == 0);
    CHECK(mismatches == 0);

    // Corruptions are caught before activation.
    std::vector<uint8_t> bad = v2;
    bad[kV2CoarseBytes + 1234] ^= 1;  // a bucket count
    CHECK(!HashTable(bad.data(), n, kBlocklistV2).isValid());
    // Suffix order: swap the first two (whole, 3-byte) suffixes of a bucket
    // holding at least two; they are distinct and sorted, so this must fail.
    bad = v2;
    size_t first = 0, bucket = 0;
    while (bucket < kV2Buckets && v2[kV2CoarseBytes + bucket] < 2) first += v2[kV2CoarseBytes + bucket++];
    CHECK(bucket < kV2Buckets);
    uint8_t* s0 = bad.data() + kV2IndexBytes + first * 3;
    std::swap_ranges(s0, s0 + 3, s0 + 3);
    CHECK(!HashTable(bad.data(), n, kBlocklistV2).isValid());

    CHECK(capacityFor(kBlocklistV1, 0xD0000) == 170380);
    CHECK(capacityFor(kBlocklistV2, 0xD0000) == 261781);

    // Bloom filter over the same table: never a false negative, ~1% false
    // positives at 10 bits per entry, and forEach() yields every hash.
    std::vector<uint8_t> bits(n * 10 / 8 + 1);
    BloomBits bloom;
    bloom.attach(bits.data(), bits.size(), 7);
    size_t seen = 0;
    b.forEach([&](uint64_t h) { bloom.add(h); seen++; });
    CHECK(seen == n);
    int falseNeg = 0, falsePos = 0, probes = 0;
    for (uint64_t h : v) falseNeg += !bloom.mayContain(h);
    for (int i = 0; i < 200000; i++) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        const uint64_t probe = x & kHashMask;
        if (std::binary_search(v.begin(), v.end(), probe)) continue;
        probes++;
        falsePos += bloom.mayContain(probe);
    }
    CHECK(falseNeg == 0);
    CHECK(falsePos * 100 < probes * 2);  // < 2%
    std::printf("bloom: %d false positives in %d probes (%.2f%%)\n", falsePos, probes, 100.0 * falsePos / probes);
}

static std::vector<uint8_t> makeQuery(const char* name, uint16_t qtype, bool edns)
{
    std::vector<uint8_t> p = {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, static_cast<uint8_t>(edns)};
    const char* s = name;
    while (*s) {
        const char* dot = std::strchr(s, '.');
        size_t n = dot ? static_cast<size_t>(dot - s) : std::strlen(s);
        p.push_back(static_cast<uint8_t>(n));
        p.insert(p.end(), s, s + n);
        s += n + (dot ? 1 : 0);
    }
    p.push_back(0);
    p.push_back(static_cast<uint8_t>(qtype >> 8));
    p.push_back(static_cast<uint8_t>(qtype));
    p.push_back(0);
    p.push_back(1);
    if (edns) {  // OPT record
        const uint8_t opt[] = {0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0};
        p.insert(p.end(), opt, opt + sizeof(opt));
    }
    return p;
}

static void testDnsPacket()
{
    auto q = makeQuery("WWW.Ads.Example.com", dns::kTypeA, true);
    dns::Question qq;
    CHECK(dns::parseQuery(q.data(), q.size(), qq));
    CHECK(std::strcmp(qq.name, "ads.example.com") == 0);
    CHECK(qq.qtype == dns::kTypeA);
    CHECK(dns::questionEnd(q.data(), q.size()) == qq.end);

    uint8_t buf[512];
    std::memcpy(buf, q.data(), q.size());
    size_t n = dns::buildBlocked(buf, sizeof(buf), qq);
    CHECK(n == qq.end + 16);
    CHECK(buf[0] == 0x12 && buf[1] == 0x34);        // txid kept
    CHECK(buf[2] & 0x80);                           // response
    CHECK(dns::rd16(buf + 6) == 1);                 // one answer
    CHECK(dns::rd16(buf + 10) == 0);                // OPT dropped
    int records = 0;
    CHECK(dns::forEachRecord(buf, n, qq.end, [&](uint8_t* ttl, uint16_t type) {
        records++;
        CHECK(type == dns::kTypeA);
        CHECK(dns::rd32(ttl) == dns::kBlockedTtl);
    }));
    CHECK(records == 1);

    auto aaaa = makeQuery("ads.example.com", dns::kTypeAAAA, false);
    std::memcpy(buf, aaaa.data(), aaaa.size());
    dns::parseQuery(buf, aaaa.size(), qq);
    CHECK(dns::buildBlocked(buf, sizeof(buf), qq) == qq.end + 28);

    auto mx = makeQuery("ads.example.com", 15, false);
    std::memcpy(buf, mx.data(), mx.size());
    dns::parseQuery(buf, mx.size(), qq);
    CHECK(dns::buildBlocked(buf, sizeof(buf), qq) == qq.end);  // NODATA
    CHECK(dns::rd16(buf + 6) == 0);

    // Responses and garbage are rejected as queries.
    buf[2] |= 0x80;
    CHECK(!dns::parseQuery(buf, mx.size(), qq));
    const uint8_t junk[] = {1, 2, 3};
    CHECK(!dns::parseQuery(junk, sizeof(junk), qq));

    // Case-insensitive question key (0x20 randomisation must still match).
    auto a1 = makeQuery("example.com", 1, false), a2 = makeQuery("ExAmPlE.CoM", 1, false);
    CHECK(dns::questionKey(a1.data(), a1.size()) == dns::questionKey(a2.data(), a2.size()));
}

int main()
{
    testHashTable();
    testCompactFormat();
    testDnsPacket();
    std::printf(failures ? "%d FAILED\n" : "all host tests passed\n", failures);
    return failures ? 1 : 0;
}
