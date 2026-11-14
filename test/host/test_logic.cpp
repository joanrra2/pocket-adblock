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
    CHECK(t.isSorted());
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
    testDnsPacket();
    std::printf(failures ? "%d FAILED\n" : "all host tests passed\n", failures);
    return failures ? 1 : 0;
}
