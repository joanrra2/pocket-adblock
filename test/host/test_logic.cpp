// Host unit tests for the platform-independent parts (hash table, DNS packet
// handling). No ESP-IDF needed, run from the repo root:
//   g++ -std=c++17 -Icomponents/blocklist/include -Icomponents/dns/include test/host/test_logic.cpp -o test_logic
//   ./test_logic [LIST.bin DOMAINS.txt]
// With a list built by tools/build_blocklist.py and its source domains, it also
// checks that every domain is blocked (directly or through a listed parent) and
// that random names are not.
#include <array>
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "sinkhole/bypass_guard.hpp"
#include "sinkhole/dns_packet.hpp"
#include "sinkhole/hash_table.hpp"
#include "sinkhole/notify_parse.hpp"
#include "sinkhole/safe_search.hpp"

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

// ---- v4 (binary fuse filter): same construction as payload_v4() in tools/build_blocklist.py
static uint64_t fuseMix(uint64_t h)
{
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ULL;
    return h ^ (h >> 33);
}

static uint32_t mulHi32(uint64_t h, uint32_t m)  // (h * m) >> 64, portable
{
    const uint64_t lo = (h & 0xFFFFFFFFu) * m, hi = (h >> 32) * m;
    return static_cast<uint32_t>((hi + (lo >> 32)) >> 32);
}

static void fuseSlots(uint64_t h, uint32_t segLen, uint32_t scl, uint32_t out[3])
{
    const uint32_t h0 = mulHi32(h, scl);
    out[0] = h0;
    out[1] = (h0 + segLen) ^ (static_cast<uint32_t>(h >> 18) & (segLen - 1));
    out[2] = (h0 + 2 * segLen) ^ (static_cast<uint32_t>(h) & (segLen - 1));
}

static std::vector<uint8_t> buildV4(const std::vector<uint64_t>& keys, uint64_t seed)
{
    const uint32_t n = static_cast<uint32_t>(keys.size());
    const uint8_t f = v4FingerprintBits(n);
    const double dn = n < 2 ? 2.0 : n;
    const uint32_t segLen =
        std::min(1u << 18, 1u << static_cast<int>(std::floor(std::log(dn) / std::log(3.33) + 2.25)));
    const double factor = std::max(1.125, 0.875 + 0.25 * std::log(1e6) / std::log(dn));
    const uint64_t cap = static_cast<uint64_t>(std::llround(n * factor));
    const uint64_t segs = (cap + segLen - 1) / segLen;
    const uint32_t segCount = segs <= 2 ? 1 : static_cast<uint32_t>(segs - 2);
    const uint32_t scl = segCount * segLen, len = (segCount + 2) * segLen;

    std::vector<uint32_t> count(len);
    std::vector<uint64_t> xorh(len);
    std::vector<uint64_t> hs;
    for (uint64_t k : keys) hs.push_back(fuseMix(k + seed));
    uint32_t sl[3];
    for (uint64_t h : hs) {
        fuseSlots(h, segLen, scl, sl);
        for (uint32_t i : sl) count[i]++, xorh[i] ^= h;
    }
    std::vector<uint32_t> queue;
    for (uint32_t i = 0; i < len; i++)
        if (count[i] == 1) queue.push_back(i);
    std::vector<std::pair<uint64_t, uint32_t>> stack;
    while (!queue.empty()) {
        const uint32_t i = queue.back();
        queue.pop_back();
        if (count[i] != 1) continue;
        const uint64_t h = xorh[i];
        stack.emplace_back(h, i);
        fuseSlots(h, segLen, scl, sl);
        for (uint32_t j : sl) {
            count[j]--;
            xorh[j] ^= h;
            if (count[j] == 1) queue.push_back(j);
        }
    }
    if (stack.size() != n) return {};  // the caller retries with another seed
    std::vector<uint32_t> fps(len);
    const uint32_t fmask = (1u << f) - 1;
    for (auto it = stack.rbegin(); it != stack.rend(); ++it) {
        fuseSlots(it->first, segLen, scl, sl);
        fps[it->second] =
            (static_cast<uint32_t>(it->first ^ (it->first >> 32)) & fmask) ^ fps[sl[0]] ^ fps[sl[1]] ^ fps[sl[2]];
    }
    std::vector<uint8_t> out(kV4HeadBytes);
    for (int k = 0; k < 8; k++) out[k] = static_cast<uint8_t>(seed >> (8 * k));
    for (int k = 0; k < 4; k++) {
        out[8 + k] = static_cast<uint8_t>(segLen >> (8 * k));
        out[12 + k] = static_cast<uint8_t>(scl >> (8 * k));
        out[16 + k] = static_cast<uint8_t>(len >> (8 * k));
    }
    out[20] = f;
    uint64_t acc = 0;
    int nacc = 0;
    for (uint32_t v : fps) {
        acc |= static_cast<uint64_t>(v) << nacc;
        for (nacc += f; nacc >= 8; nacc -= 8, acc >>= 8) out.push_back(static_cast<uint8_t>(acc));
    }
    if (nacc) out.push_back(static_cast<uint8_t>(acc));
    out.resize(out.size() + kV4Pad);
    return out;
}

static void testFuseFormat()
{
    uint64_t x = 0x2545F4914F6CDD1DULL;
    auto next = [&] {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        return x & kHashMask;
    };
    for (uint32_t n : {1u, 2u, 1000u, 150000u, 300000u}) {
        std::vector<uint64_t> v;
        while (v.size() < n) {
            v.push_back(next());
            if (v.size() == n) {
                std::sort(v.begin(), v.end());
                v.erase(std::unique(v.begin(), v.end()), v.end());
            }
        }
        std::vector<uint8_t> p;
        for (uint64_t seed = 1; p.empty() && seed < 50; seed++) p = buildV4(v, seed * 0x9E3779B97F4A7C15ULL);
        CHECK(!p.empty());
        if (p.empty()) continue;
        CHECK(p.size() == v4PayloadBytes(n));
        HashTable t(p.data(), n, kBlocklistV4, p.size());
        CHECK(t.isValid());
        CHECK(!t.canList());
        size_t listed = 0;
        t.forEach([&listed](uint64_t) { listed++; });
        CHECK(listed == 0);
        int misses = 0;
        int falsePos = 0;
        for (uint64_t k : v)
            if (!t.contains(k)) misses++;
        const int probes = 400000;
        for (int i = 0; i < probes; i++)
            if (t.contains(next())) falsePos++;
        CHECK(misses == 0);
        // f = ceil(40 - log2 n) keeps false matches at or below n / 2^40 per lookup.
        const double expected = probes * std::ldexp(1.0, -v4FingerprintBits(n));
        CHECK(falsePos <= 3 + 4 * expected);
        if (n == 300000)
            std::printf("fuse: %u domains, %u-bit fingerprints, %.2f bits/domain, %d false matches in %d probes\n", n,
                        v4FingerprintBits(n), 8.0 * p.size() / n, falsePos, probes);

        // Structure errors are caught (the content itself is covered by the SHA-256).
        std::vector<uint8_t> bad = p;
        bad[20] = 25;  // fingerprint width
        CHECK(!HashTable(bad.data(), n, kBlocklistV4, bad.size()).isValid());
        bad = p;
        bad[8] ^= 1;  // segment length no longer a power of two
        CHECK(!HashTable(bad.data(), n, kBlocklistV4, bad.size()).isValid());
        CHECK(!HashTable(p.data(), n, kBlocklistV4, p.size() - 1).isValid());  // truncated
        CHECK(!HashTable(p.data(), 0, kBlocklistV4, p.size()).isValid());
    }

    // Slot capacity: the reported count fits, and 2% more does not.
    for (size_t slot : {size_t{0xB0000}, size_t{0x270000}, size_t{0x670000}}) {
        const uint32_t cap = capacityFor(kBlocklistV4, slot);
        CHECK(64 + v4PayloadBytes(cap) + kSignatureBytes <= slot);
        CHECK(64 + v4PayloadBytes(cap + cap / 50) + kSignatureBytes > slot);
        std::printf("v4 capacity: slot 0x%zX holds %u domains (v2: %u)\n", slot, cap,
                    capacityFor(kBlocklistV2, slot));
    }

    // Header: v4 carries its payload size in reserved[4..7].
    BlocklistHeader hd{};
    std::memcpy(hd.magic, kBlocklistMagic, 4);
    hd.version = kBlocklistV4;
    hd.hashBytes = kHashBytes;
    hd.headerSize = sizeof(BlocklistHeader);
    hd.count = 5;
    hd.reserved[4] = 0x34;
    hd.reserved[5] = 0x12;
    CHECK(headerLooksValid(hd));
    CHECK(payloadSize(hd) == 0x1234);
    hd.version = 3;
    CHECK(!headerLooksValid(hd));
}

// A list made by tools/build_blocklist.py (any format) against its source domains.
static void testBuiltList(const char* listPath, const char* domainsPath)
{
    std::ifstream lf(listPath, std::ios::binary), df(domainsPath);
    CHECK(lf.good() && df.good());
    const std::vector<uint8_t> file((std::istreambuf_iterator<char>(lf)), std::istreambuf_iterator<char>());
    CHECK(file.size() > sizeof(BlocklistHeader));
    if (file.size() <= sizeof(BlocklistHeader)) return;
    BlocklistHeader hd;
    std::memcpy(&hd, file.data(), sizeof(hd));
    CHECK(headerLooksValid(hd));
    const size_t bytes = payloadSize(hd);
    CHECK(sizeof(hd) + bytes + (isSigned(hd) ? kSignatureBytes : 0) == file.size());
    if (sizeof(hd) + bytes > file.size()) return;
    HashTable t(file.data() + sizeof(hd), hd.count, hd.version, bytes);
    CHECK(t.isValid());
    std::string line;
    size_t domains = 0, missed = 0;
    while (std::getline(df, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        domains++;
        bool hit = false;
        forEachSuffix(line.c_str(), line.size(), [&hit, &t](const char* s, size_t n) {
            hit = t.contains(fnv1a40(s, n));
            return hit;
        });
        if (hit) continue;
        if (missed < 5) std::printf("not blocked: %s\n", line.c_str());
        missed++;
    }
    size_t falsePos = 0;
    for (int i = 0; i < 100000; i++) {
        const std::string name = "unlisted-" + std::to_string(i) + ".example-test.invalid";
        if (t.contains(fnv1a40(name.data(), name.size()))) falsePos++;
    }
    CHECK(domains > 0);
    CHECK(missed == 0);
    CHECK(falsePos <= 2);
    std::printf("%s: format v%u, %u entries, %zu source domains all blocked, %zu false matches in 100000\n", listPath,
                hd.version, hd.count, domains, falsePos);
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

static void testBypassGuard()
{
    using guard::Hit;
    auto chk = [](const char* n, uint8_t f) { return guard::check(n, std::strlen(n), f); };
    const uint8_t all = guard::kCanary | guard::kEncryptedDns;
    CHECK(chk("use-application-dns.net", guard::kCanary) == Hit::Canary);
    CHECK(chk("mask.icloud.com", all) == Hit::Canary);
    CHECK(chk("mask-h2.icloud.com", all) == Hit::Canary);
    CHECK(chk("icloud.com", all) == Hit::None);               // parent is not a canary
    CHECK(chk("notmask.icloud.com", all) == Hit::None);       // label boundary
    CHECK(chk("dns.google", guard::kCanary) == Hit::None);    // list off
    CHECK(chk("dns.google", all) == Hit::EncryptedDns);
    CHECK(chk("mozilla.cloudflare-dns.com", all) == Hit::EncryptedDns);  // subdomain
    CHECK(chk("xcloudflare-dns.com", all) == Hit::None);
    CHECK(chk("google.com", all) == Hit::None);
    CHECK(chk("use-application-dns.net", 0) == Hit::None);

    auto q = makeQuery("use-application-dns.net", dns::kTypeA, true);
    dns::Question qq;
    CHECK(dns::parseQuery(q.data(), q.size(), qq));
    const size_t n = dns::buildNxdomain(q.data(), qq);
    CHECK(n == qq.end);
    CHECK((q[3] & 0x0F) == 3);                           // NXDOMAIN
    CHECK(q[2] & 0x80);                                  // response
    CHECK(dns::rd16(q.data() + 6) == 0 && dns::rd16(q.data() + 10) == 0);  // no answers, OPT dropped
}

static void testCnameTargets()
{
    // Response: metrics.shop.com CNAME shop.eulerian.net (compressed against
    // the question: "shop" + pointer to "eulerian.net" in a second CNAME), A.
    auto p = makeQuery("metrics.shop.com", dns::kTypeA, false);
    const size_t qend = p.size();
    p[2] |= 0x80;
    p[7] = 3;  // ANCOUNT
    auto rr = [&](uint16_t type, const std::vector<uint8_t>& rdata) {
        const uint8_t h[] = {0xC0, 0x0C, static_cast<uint8_t>(type >> 8), static_cast<uint8_t>(type), 0, 1,
                             0, 0, 0, 60, 0, static_cast<uint8_t>(rdata.size())};
        p.insert(p.end(), h, h + sizeof(h));
        p.insert(p.end(), rdata.begin(), rdata.end());
    };
    const size_t firstRdata = p.size() + 12;
    rr(dns::kTypeCname, {8, 'e', 'u', 'l', 'e', 'r', 'i', 'a', 'n', 3, 'n', 'e', 't', 0});
    rr(dns::kTypeCname, {4, 'S', 'H', 'O', 'P', 0xC0, static_cast<uint8_t>(firstRdata)});  // -> eulerian.net
    rr(dns::kTypeA, {1, 2, 3, 4});

    std::vector<std::string> seen;
    bool hit = dns::anyCnameTarget(p.data(), p.size(), qend, [&](const char* n, size_t l) {
        seen.emplace_back(n, l);
        return std::string(n, l) == "shop.eulerian.net";
    });
    CHECK(hit);
    CHECK(seen.size() == 2 && seen[0] == "eulerian.net" && seen[1] == "shop.eulerian.net");
    CHECK(!dns::anyCnameTarget(p.data(), p.size(), qend, [](const char*, size_t) { return false; }));

    char name[254];
    CHECK(dns::readName(p.data(), p.size(), dns::kHeaderLen, name, sizeof(name)));
    CHECK(std::string(name) == "metrics.shop.com");
    // A pointer loop and a truncated packet are rejected, not followed forever.
    std::vector<uint8_t> loop = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xC0, 12};
    CHECK(!dns::readName(loop.data(), loop.size(), 12, name, sizeof(name)));
    CHECK(!dns::anyCnameTarget(p.data(), firstRdata + 3, qend, [](const char*, size_t) { return true; }));
}

static void testSafeSearch()
{
    auto chk = [](const char* n, uint8_t f) { return safe::check(n, std::strlen(n), f); };
    const uint8_t gb = safe::kGoogle | safe::kBing;
    CHECK(chk("google.com", gb) == safe::Google);
    CHECK(chk("google.es", gb) == safe::Google);
    CHECK(chk("google.co.uk", gb) == safe::Google);
    CHECK(chk("google.com.br", gb) == safe::Google);
    CHECK(chk("mail.google.com", gb) == safe::None);    // other Google services pass
    CHECK(chk("google.blog", gb) == safe::None);        // not a country domain
    CHECK(chk("google.com.evil.io", gb) == safe::None);
    CHECK(chk("google.com", safe::kBing) == safe::None);  // flag off
    CHECK(chk("bing.com", gb) == safe::Bing);
    CHECK(chk("youtube.com", gb) == safe::None);
    CHECK(chk("youtube.com", safe::kYoutubeModerate) == safe::YoutubeModerate);
    CHECK(chk("m.youtube.com", safe::kYoutubeStrict) == safe::YoutubeStrict);
    CHECK(chk("youtubei.googleapis.com", safe::kYoutubeStrict) == safe::YoutubeStrict);
    CHECK(chk("i.ytimg.com", safe::kYoutubeStrict) == safe::None);
    CHECK(safe::kDefaultIps[safe::Google] == safe::ip4(216, 239, 38, 120));
}

// ntfy / Telegram answers, as the notifier reads them (notify_parse.hpp).
static void testNotifyParse()
{
    using namespace sinkhole::notify;
    // ntfy: one object per line; ids and messages, escapes decoded.
    std::string ntfy =
        R"({"id":"KWjLikMx0VpA","time":1795045386,"event":"message","topic":"t-cmd","message":"wake office-pc"})" "\n"
        R"({"id":"b2","time":1795045387,"event":"message","topic":"t-cmd","message":"say \"hi\"\nnow"})" "\n"
        R"({"id":"b3","time":1795045388,"event":"keepalive","topic":"t-cmd"})" "\n";
    std::vector<std::string> ids;
    std::vector<std::string> events;
    std::vector<std::string> texts;
    ntfyLines(ntfy.data(), [&ids, &events, &texts](const char* id, const char* ev, const char* text) {
        ids.emplace_back(id);
        events.emplace_back(ev);
        texts.emplace_back(text);
    });
    CHECK(ids.size() == 3);
    CHECK(ids[0] == "KWjLikMx0VpA" && texts[0] == "wake office-pc");
    CHECK(texts[1] == "say \"hi\"\nnow");
    CHECK(events[2] == "keepalive" && texts[2].empty());

    // Telegram getUpdates: a private chat, then a group; "from" ids must not be
    // taken for the chat id; \u escapes outside ASCII become '?'.
    const char* tg =
        R"({"ok":true,"result":[)"
        R"({"update_id":512345001,"message":{"message_id":5,"from":{"id":777,"is_bot":false,"first_name":"Ana"},)"
        R"("chat":{"id":111222333,"first_name":"Ana","type":"private"},"date":1700000000,"text":"/wake@pocket_bot office-pc",)"
        R"("entities":[{"offset":0,"length":16,"type":"bot_command"}]}},)"
        R"({"update_id":512345002,"message":{"message_id":6,"from":{"id":888,"is_bot":false,"first_name":"Bo"},)"
        R"("chat":{"id":-1001234567890,"title":"Home","type":"supergroup"},"date":1700000001,"text":"caf\u00e9 \u0041"}},)"
        R"({"update_id":512345003,"edited_message":{"message_id":6,"chat":{"id":5,"type":"private"},"date":1}})"
        R"(]})";
    std::vector<int64_t> chats;
    std::vector<std::string> said;
    const int64_t last = telegramUpdates(tg, [&chats, &said](int64_t, int64_t chat, const char* text) {
        chats.push_back(chat);
        said.emplace_back(text);
    });
    CHECK(last == 512345003);
    CHECK(chats.size() == 2);
    CHECK(chats[0] == 111222333 && said[0] == "/wake@pocket_bot office-pc");
    CHECK(chats[1] == -1001234567890LL && said[1] == "caf? A");
    int64_t chat = 0;
    std::array<char, 32> name{};
    CHECK(telegramLastChat(tg, chat, name.data(), name.size()) && chat == 5 && name[0] == '\0');
    const char* one = R"({"ok":true,"result":[{"update_id":1,"message":{"chat":{"id":42,"first_name":"Joan","type":"private"},"text":"/start"}}]})";
    CHECK(telegramLastChat(one, chat, name.data(), name.size()) && chat == 42 && std::string(name.data()) == "Joan");
    CHECK(telegramUpdates(R"({"ok":true,"result":[]})", [](int64_t, int64_t, const char*) {}) == 0);
}

int main(int argc, char** argv)
{
    if (argc == 3) testBuiltList(argv[1], argv[2]);
    testFuseFormat();
    testCnameTargets();
    testSafeSearch();
    testHashTable();
    testCompactFormat();
    testDnsPacket();
    testBypassGuard();
    testNotifyParse();
    std::printf(failures ? "%d FAILED\n" : "all host tests passed\n", failures);
    return failures ? 1 : 0;
}
