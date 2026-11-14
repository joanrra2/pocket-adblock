#include "sinkhole/dns_cache.hpp"

#include <cctype>
#include <cstring>

#include "esp_log.h"
#include "sdkconfig.h"
#include "sinkhole/dns_packet.hpp"
#include "sinkhole/memory.hpp"
#include "sinkhole/rtos.hpp"

namespace sinkhole {

namespace {
constexpr const char* TAG = "dns-cache";
constexpr uint32_t kEmptyAnswerTtl = 30;  // NODATA/NXDOMAIN without SOA
}  // namespace

void DnsCache::begin()
{
    Region r = allocTable(sizeof(Entry), CONFIG_SINKHOLE_DNS_CACHE_PSRAM,
                          CONFIG_SINKHOLE_DNS_CACHE_INTERNAL);
    entries_ = static_cast<Entry*>(r.ptr);
    sets_ = r.count / 2;
    psram_ = r.psram;
    if (sets_)
        ESP_LOGI(TAG, "%u entries in %s", static_cast<unsigned>(sets_ * 2),
                 psram_ ? "PSRAM" : "internal RAM");
    else
        ESP_LOGI(TAG, "disabled");
}

size_t DnsCache::lookup(uint32_t key, const uint8_t* query, size_t qend, uint8_t* out, size_t cap)
{
    if (!sets_) return 0;
    Entry* set = &entries_[(key % sets_) * 2];
    const uint32_t now = uptimeSeconds();

    for (int w = 0; w < 2; w++) {
        Entry& e = set[w];
        if (e.key != key) continue;
        const uint32_t age = now - e.storedAt;
        if (age >= e.ttl) {
            e.key = 0;  // expired
            break;
        }
        // Guard against 32-bit key collisions: the question must match exactly.
        if (e.qend != qend || e.len > cap) break;
        bool same = true;
        for (size_t i = dns::kHeaderLen; i < qend && same; i++)
            same = tolower(e.data[i]) == tolower(query[i]);
        if (!same) break;

        memcpy(out, e.data, e.len);
        out[0] = query[0];  // client's txid
        out[1] = query[1];
        // Keep the client's RD bit, report the remaining TTL.
        out[2] = static_cast<uint8_t>((out[2] & ~0x01) | (query[2] & 0x01));
        dns::forEachRecord(out, e.len, e.qend, [age](uint8_t* ttl, uint16_t type) {
            if (type == dns::kTypeOpt) return;
            uint32_t t = dns::rd32(ttl);
            dns::wr32(ttl, t > age ? t - age : 1);
        });
        hits_++;
        return e.len;
    }
    misses_++;
    return 0;
}

void DnsCache::store(uint32_t key, const uint8_t* resp, size_t len)
{
    if (!sets_ || len > kMaxResponse || len < dns::kHeaderLen) return;
    if (resp[2] & 0x02) return;  // truncated: client will retry over TCP
    const uint8_t rcode = resp[3] & 0x0F;
    if (rcode != 0 && rcode != 3) return;  // only NOERROR / NXDOMAIN

    const size_t qend = dns::questionEnd(resp, len);
    if (!qend) return;

    // Same key or a free way first, otherwise evict the older of the two.
    Entry* set = &entries_[(key % sets_) * 2];
    Entry* slot = set[0].key == key || set[0].key == 0 ? &set[0]
                  : set[1].key == key || set[1].key == 0 ? &set[1]
                  : (set[0].storedAt <= set[1].storedAt ? &set[0] : &set[1]);  // evict older

    // forEachRecord only reads here (the callback doesn't write).
    uint32_t minTtl = UINT32_MAX;
    bool ok = dns::forEachRecord(const_cast<uint8_t*>(resp), len, qend,
                                 [&minTtl](uint8_t* ttl, uint16_t type) {
                                     if (type == dns::kTypeOpt) return;
                                     uint32_t t = dns::rd32(ttl);
                                     if (t < minTtl) minTtl = t;
                                 });
    if (!ok) return;
    if (minTtl == UINT32_MAX) minTtl = kEmptyAnswerTtl;
    if (minTtl == 0) return;
    if (minTtl > CONFIG_SINKHOLE_DNS_CACHE_MAX_TTL) minTtl = CONFIG_SINKHOLE_DNS_CACHE_MAX_TTL;

    slot->key = key;
    slot->storedAt = uptimeSeconds();
    slot->ttl = minTtl;
    slot->len = static_cast<uint16_t>(len);
    slot->qend = static_cast<uint16_t>(qend);
    memcpy(slot->data, resp, len);
}

}  // namespace sinkhole
