#include "sinkhole/dns_cache.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>

#include "esp_heap_caps.h"
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

bool DnsCache::setup(Table& t, size_t room, size_t entries, bool psram, bool fullyAssociative)
{
    if (!fullyAssociative) entries &= ~static_cast<size_t>(1);  // whole 2-way sets
    if (!entries) return false;
    const size_t stride = sizeof(Hdr) + room;
    void* mem = heap_caps_calloc(entries, stride,
                                 psram ? (MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT) : (MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
    if (!mem) return false;
    t.mem = static_cast<uint8_t*>(mem);
    t.stride = stride;
    t.room = room;
    t.ways = fullyAssociative ? entries : 2;
    t.sets = entries / t.ways;
    return true;
}

void DnsCache::begin()
{
    // PSRAM: one table of full-size slots, as many as configured.
    if (psramAvailable() && setup(large_, kMaxResponse, CONFIG_SINKHOLE_DNS_CACHE_PSRAM, true, false)) {
        psram_ = true;
        ESP_LOGI(TAG, "%u entries in PSRAM", static_cast<unsigned>(capacity()));
        return;
    }
    // Internal RAM: the budget of CONFIG_SINKHOLE_DNS_CACHE_INTERNAL full-size
    // slots, split into a few full-size ones and many small ones.
    const size_t budget = CONFIG_SINKHOLE_DNS_CACHE_INTERNAL * (sizeof(Hdr) + kMaxResponse);
    const size_t big = std::max<size_t>(2, CONFIG_SINKHOLE_DNS_CACHE_INTERNAL / 10);
    const size_t bigBytes = big * (sizeof(Hdr) + kMaxResponse);
    setup(large_, kMaxResponse, big, false, true);
    if (budget > bigBytes)
        setup(small_, kSmallResponse, (budget - bigBytes) / (sizeof(Hdr) + kSmallResponse), false, true);
    if (capacity())
        ESP_LOGI(TAG, "%u entries in internal RAM (%u small + %u full-size)", static_cast<unsigned>(capacity()),
                 static_cast<unsigned>(small_.sets * small_.ways), static_cast<unsigned>(large_.sets * large_.ways));
    else
        ESP_LOGI(TAG, "disabled");
}

size_t DnsCache::lookupIn(Table& t, uint32_t key, const uint8_t* query, size_t qend, uint8_t* out, size_t cap,
                          uint32_t now)
{
    if (!t.sets) return 0;
    for (size_t w = 0; w < t.ways; w++) {
        Hdr* e = t.way(key, w);
        if (e->key != key) continue;
        const uint32_t age = now - e->storedAt;
        if (age >= e->ttl) {
            e->key = 0;  // expired
            return 0;
        }
        // Guard against 32-bit key collisions: the question must match exactly.
        const uint8_t* data = Table::data(e);
        if (e->qend != qend || e->len > cap) return 0;
        for (size_t i = dns::kHeaderLen; i < qend; i++)
            if (tolower(data[i]) != tolower(query[i])) return 0;

        memcpy(out, data, e->len);
        out[0] = query[0];  // client's txid
        out[1] = query[1];
        // Keep the client's RD bit, report the remaining TTL.
        out[2] = static_cast<uint8_t>((out[2] & ~0x01) | (query[2] & 0x01));
        dns::forEachRecord(out, e->len, e->qend, [age](uint8_t* ttl, uint16_t type) {
            if (type == dns::kTypeOpt) return;
            uint32_t v = dns::rd32(ttl);
            dns::wr32(ttl, v > age ? v - age : 1);
        });
        return e->len;
    }
    return 0;
}

size_t DnsCache::lookup(uint32_t key, const uint8_t* query, size_t qend, uint8_t* out, size_t cap)
{
    if (!capacity()) return 0;
    const uint32_t now = uptimeSeconds();
    size_t n = lookupIn(small_, key, query, qend, out, cap, now);
    if (!n) n = lookupIn(large_, key, query, qend, out, cap, now);
    if (n)
        hits_++;
    else
        misses_++;
    return n;
}

void DnsCache::forget(Table& t, uint32_t key)
{
    if (!t.sets) return;
    for (size_t w = 0; w < t.ways; w++)
        if (t.way(key, w)->key == key) t.way(key, w)->key = 0;
}

void DnsCache::clear()
{
    for (Table* t : {&small_, &large_})
        for (size_t i = 0; i < t->sets * t->ways; i++) reinterpret_cast<Hdr*>(t->mem + i * t->stride)->key = 0;
}

void DnsCache::store(uint32_t key, const uint8_t* resp, size_t len)
{
    if (!capacity() || len > kMaxResponse || len < dns::kHeaderLen) return;
    if (resp[2] & 0x02) return;  // truncated: client will retry over TCP
    const uint8_t rcode = resp[3] & 0x0F;
    if (rcode != 0 && rcode != 3) return;  // only NOERROR / NXDOMAIN

    const size_t qend = dns::questionEnd(resp, len);
    if (!qend) return;

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
    // Floor for TTL-0 / very short answers (lookup() still reports the
    // upstream's own TTL to clients, aged, never below 1 s).
    minTtl = std::max<uint32_t>(minTtl, CONFIG_SINKHOLE_DNS_CACHE_MIN_TTL);  // no warning when 0
    if (minTtl == 0) return;
    if (minTtl > CONFIG_SINKHOLE_DNS_CACHE_MAX_TTL) minTtl = CONFIG_SINKHOLE_DNS_CACHE_MAX_TTL;

    // Small answers go to the small table when there is one; an answer for
    // the same key in the other table is dropped so lookups never see two.
    const bool small = small_.sets && len <= small_.room;
    Table& t = small ? small_ : large_;
    if (!t.sets) return;
    forget(small ? large_ : small_, key);

    // Same key first, then a free way, otherwise evict the oldest.
    Hdr* slot = nullptr;
    Hdr* oldest = t.way(key, 0);
    for (size_t w = 0; w < t.ways; w++) {
        Hdr* e = t.way(key, w);
        if (e->key == key) {
            slot = e;
            break;
        }
        if (!slot && e->key == 0) slot = e;
        if (e->storedAt < oldest->storedAt) oldest = e;
    }
    if (!slot) slot = oldest;
    slot->key = key;
    slot->storedAt = uptimeSeconds();
    slot->ttl = minTtl;
    slot->len = static_cast<uint16_t>(len);
    slot->qend = static_cast<uint16_t>(qend);
    memcpy(Table::data(slot), resp, len);
}

}  // namespace sinkhole
