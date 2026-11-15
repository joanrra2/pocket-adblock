#include "sinkhole/stats.hpp"

#include <cstring>

#include "esp_log.h"
#include "esp_netif.h"
#include "sdkconfig.h"
#include "sinkhole/memory.hpp"
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/sockets.h"
#include "sinkhole/config.hpp"

namespace sinkhole {

void ClientAddr::format(char out[46]) const
{
    if (v6)
        inet_ntop(AF_INET6, a, out, 46);
    else
        inet_ntop(AF_INET, a, out, 46);
}

namespace {
constexpr const char* kBannedKey = "banned";

struct ArpLookup {
    ClientInfo* clients;
    size_t count;
};

// Runs in the lwIP thread (etharp_* is not thread-safe).
esp_err_t resolveMacs(void* ctx)
{
    auto* job = static_cast<ArpLookup*>(ctx);
    static const uint8_t zero[6] = {};
    for (size_t i = 0; i < job->count; i++) {
        ClientInfo& c = job->clients[i];
        if (c.addr.v6 || memcmp(c.mac, zero, 6) != 0) continue;  // ARP is IPv4 only
        ip4_addr_t ip;
        ip.addr = c.addr.v4();
        for (struct netif* nif = netif_list; nif; nif = nif->next) {
            struct eth_addr* eth = nullptr;
            const ip4_addr_t* found = nullptr;
            if (etharp_find_addr(nif, &ip, &eth, &found) >= 0 && eth) {
                memcpy(c.mac, eth->addr, 6);
                break;
            }
        }
    }
    return ESP_OK;
}
}  // namespace

// ------------------------------------------------------------ ClientTable

esp_err_t ClientTable::load()
{
    LockGuard g(mu_);
    size_t n = 0;
    nvs::loadBlob(kBannedKey, banned_, sizeof(banned_), &n);
    bannedCount_ = n / sizeof(uint32_t);
    return ESP_OK;
}

ClientInfo* ClientTable::findLocked(const ClientAddr& addr)
{
    for (size_t i = 0; i < count_; i++)
        if (clients_[i].addr == addr) return &clients_[i];
    return nullptr;
}

bool ClientTable::withinRate(const ClientAddr& addr, uint16_t perMinute)
{
    if (!perMinute) return true;
    const uint32_t now = uptimeSeconds();
    LockGuard g(mu_);
    ClientInfo* c = findOrAddLocked(addr);
    if (now - c->rateStart >= 60) {
        c->rateStart = now;
        c->rateCount = 0;
    }
    if (c->rateCount >= perMinute) {
        c->refused++;
        return false;
    }
    c->rateCount++;
    return true;
}

ClientInfo* ClientTable::findOrAddLocked(const ClientAddr& addr)
{
    ClientInfo* c = findLocked(addr);
    if (!c) {
        if (count_ < kCapacity) {
            c = &clients_[count_++];
        } else {
            // Evict the least recently seen client.
            c = &clients_[0];
            for (size_t i = 1; i < count_; i++)
                if (clients_[i].lastSeen < c->lastSeen) c = &clients_[i];
        }
        memset(c, 0, sizeof(*c));
        c->addr = addr;
        const uint32_t ip = addr.v4();
        for (size_t i = 0; ip && i < bannedCount_; i++)
            if (banned_[i] == ip) c->banned = true;
        c->rateStart = uptimeSeconds();
        c->lastSeen = c->rateStart;
    }
    return c;
}

bool ClientTable::record(const ClientAddr& addr, bool blocked)
{
    LockGuard g(mu_);
    ClientInfo* c = findOrAddLocked(addr);
    c->lastSeen = uptimeSeconds();
    if (blocked || c->banned)
        c->blocked++;
    else
        c->allowed++;
    return c->banned;
}

bool ClientTable::isBanned(uint32_t ip)
{
    LockGuard g(mu_);
    for (size_t i = 0; i < bannedCount_; i++)
        if (banned_[i] == ip) return true;
    return false;
}

esp_err_t ClientTable::setBanned(uint32_t ip, bool banned)
{
    LockGuard g(mu_);
    if (ClientInfo* c = findLocked(ClientAddr::fromV4(ip))) c->banned = banned;
    size_t idx = bannedCount_;
    for (size_t i = 0; i < bannedCount_; i++)
        if (banned_[i] == ip) idx = i;
    if (banned && idx == bannedCount_) {
        if (bannedCount_ >= kMaxBanned) return ESP_ERR_NO_MEM;
        banned_[bannedCount_++] = ip;
    } else if (!banned && idx < bannedCount_) {
        banned_[idx] = banned_[--bannedCount_];
    } else {
        return ESP_OK;
    }
    return saveBannedLocked();
}

esp_err_t ClientTable::saveBannedLocked()
{
    return nvs::saveBlob(kBannedKey, banned_, bannedCount_ * sizeof(uint32_t));
}

size_t ClientTable::activeCount(uint32_t seconds)
{
    const uint32_t now = uptimeSeconds();
    LockGuard g(mu_);
    size_t n = 0;
    for (size_t i = 0; i < count_; i++) n += now - clients_[i].lastSeen <= seconds;
    return n;
}

size_t ClientTable::snapshot(ClientInfo* out, size_t max)
{
    {
        LockGuard g(mu_);
        ArpLookup job{clients_, count_};
        // Holding mu_ while the lwIP thread walks the table: the DNS task only
        // blocks briefly on record(); lwIP never takes mu_, so no deadlock.
        esp_netif_tcpip_exec(resolveMacs, &job);
        size_t n = count_ < max ? count_ : max;
        memcpy(out, clients_, n * sizeof(ClientInfo));
        return n;
    }
}

// ------------------------------------------------------------ QueryLog

void QueryLog::begin()
{
#if CONFIG_SINKHOLE_QUERY_HISTORY_EXTENDED
    // PSRAM: the configured size, halved until it fits. No PSRAM: a modest 64
    // entries (5 KB) of internal RAM, never the full table.
    Region r = allocTable(sizeof(QueryEntry), CONFIG_SINKHOLE_QUERY_HISTORY_ENTRIES, 64);
    if (r.count > kSmall) {
        LockGuard g(mu_);
        ring_ = static_cast<QueryEntry*>(r.ptr);
        cap_ = r.count;
        psram_ = r.psram;
    }
    ESP_LOGI("stats", "query history: %u entries in %s", static_cast<unsigned>(cap_),
             psram_ ? "PSRAM" : "internal RAM");
#endif
    top_.begin();
}

void TopDomains::begin()
{
#if CONFIG_SINKHOLE_TOP_DOMAINS
    Region r = allocTable(sizeof(Entry), CONFIG_SINKHOLE_TOP_DOMAINS_ENTRIES, 0);  // PSRAM only
    if (r.count >= kWays) {
        e_ = static_cast<Entry*>(r.ptr);
        sets_ = r.count / kWays;
    }
    ESP_LOGI("stats", "top domains: %u counters%s", static_cast<unsigned>(sets_ * kWays),
             sets_ ? " in PSRAM" : " (off: needs PSRAM)");
#endif
}

void TopDomains::recordLocked(const char* name, bool blocked)
{
    if (!sets_) return;
    uint32_t h = 2166136261u;
    for (const char* c = name; *c; c++) h = (h ^ static_cast<uint8_t>(*c)) * 16777619u;
    const uint32_t key = (h & ~1u) | (blocked ? 1u : 0u);
    Entry* set = &e_[(key >> 1) % sets_ * kWays];
    Entry* victim = &set[0];
    for (size_t w = 0; w < kWays; w++) {
        Entry& e = set[w];
        if (e.count && e.key == key && strncmp(e.name, name, sizeof(e.name) - 1) == 0) {
            e.count++;
            return;
        }
        if (e.count < victim->count) victim = &e;
    }
    victim->key = key;
    victim->count = 1;
    strncpy(victim->name, name, sizeof(victim->name) - 1);
    victim->name[sizeof(victim->name) - 1] = '\0';
}

size_t TopDomains::topLocked(bool blocked, Item* out, size_t max) const
{
    size_t n = 0;
    for (size_t i = 0; i < sets_ * kWays; i++) {
        const Entry& e = e_[i];
        if (!e.count || (e.key & 1u) != (blocked ? 1u : 0u)) continue;
        if (n == max && e.count <= out[n - 1].count) continue;
        size_t pos = n < max ? n++ : max - 1;  // insertion sort, highest first
        while (pos > 0 && out[pos - 1].count < e.count) {
            out[pos] = out[pos - 1];
            pos--;
        }
        memcpy(out[pos].name, e.name, sizeof(out[pos].name));
        out[pos].count = e.count;
    }
    return n;
}

void QueryLog::add(const ClientAddr& addr, const char* domain, bool blocked)
{
    const uint8_t privacy = privacy_;
    if (privacy >= 1) domain = "(hidden)";
    LockGuard g(mu_);
    if (privacy == 0) top_.recordLocked(domain, blocked);
    QueryEntry& e = ring_[head_];
    e.uptime = uptimeSeconds();
    e.addr = privacy >= 2 ? ClientAddr{} : addr;
    e.blocked = blocked;
    strncpy(e.domain, domain, sizeof(e.domain) - 1);
    e.domain[sizeof(e.domain) - 1] = '\0';
    head_ = (head_ + 1) % cap_;
    if (count_ < cap_) count_++;
}

void QueryLog::markBlocked(const ClientAddr& addr, const char* domain)
{
    LockGuard g(mu_);
    for (size_t k = 0; k < count_ && k < 64; k++) {
        QueryEntry& e = ring_[(head_ + cap_ - 1 - k) % cap_];
        if (!e.blocked && e.addr == addr && strncmp(e.domain, domain, sizeof(e.domain) - 1) == 0) {
            e.blocked = true;
            return;
        }
    }
}

size_t QueryLog::page(size_t& cursor, const QueryFilter& f, QueryEntry* out, size_t max)
{
    LockGuard g(mu_);
    size_t n = 0;
    while (cursor < count_ && n < max) {
        const QueryEntry& e = ring_[(head_ + cap_ - 1 - cursor) % cap_];
        cursor++;
        if (f.ip && e.addr.v4() != f.ip) continue;
        if (f.blockedOnly && !e.blocked) continue;
        if (f.text && !strstr(e.domain, f.text)) continue;
        out[n++] = e;
    }
    return n;
}

}  // namespace sinkhole
