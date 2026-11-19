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
constexpr const char* kNoFilterKey = "nofilter";

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
    n = 0;
    nvs::loadBlob(kNoFilterKey, noFilter_, sizeof(noFilter_), &n);
    noFilterCount_ = n / sizeof(uint32_t);
    return ESP_OK;
}

ClientInfo* ClientTable::findLocked(const ClientAddr& addr)
{
    for (size_t i = 0; i < count_; i++)
        if (clients_[i].addr == addr) return &clients_[i];
    return nullptr;
}

bool ClientTable::withinRate(const ClientAddr& addr, uint16_t perMinute, bool* noFilter, ClientInfo** slot)
{
    const uint32_t now = uptimeSeconds();
    LockGuard g(mu_);
    ClientInfo* c = findOrAddLocked(addr);
    if (noFilter) *noFilter = c->noFilter;
    if (slot) *slot = c;
    if (!perMinute) return true;
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
        for (size_t i = 0; ip && i < noFilterCount_; i++)
            if (noFilter_[i] == ip) c->noFilter = true;
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

bool ClientTable::record(ClientInfo* c, bool blocked)
{
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

esp_err_t ClientTable::setInList(uint32_t* list, size_t& count, uint32_t ip, bool on, const char* key)
{
    size_t idx = count;
    for (size_t i = 0; i < count; i++)
        if (list[i] == ip) idx = i;
    if (on && idx == count) {
        if (count >= kMaxBanned) return ESP_ERR_NO_MEM;
        list[count++] = ip;
    } else if (!on && idx < count) {
        list[idx] = list[--count];
    } else {
        return ESP_OK;
    }
    return nvs::saveBlob(key, list, count * sizeof(uint32_t));
}

esp_err_t ClientTable::setNoFilter(uint32_t ip, bool on)
{
    LockGuard g(mu_);
    if (ClientInfo* c = findLocked(ClientAddr::fromV4(ip))) c->noFilter = on;
    return setInList(noFilter_, noFilterCount_, ip, on, kNoFilterKey);
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
    size_t n = 0;
    {
        LockGuard g(mu_);
        n = count_ < max ? count_ : max;
        memcpy(out, clients_, n * sizeof(ClientInfo));
    }
    // The ARP walk runs on the copy, without mu_: the DNS task takes mu_ for
    // every query and would otherwise wait behind the lwIP thread.
    ArpLookup job{out, n};
    esp_netif_tcpip_exec(resolveMacs, &job);
    // Keep the MACs it found in the same slots (unless a slot was reused meanwhile).
    static const uint8_t zero[6] = {};
    LockGuard g(mu_);
    for (size_t i = 0; i < n && i < count_; i++) {
        ClientInfo& c = clients_[i];
        if (memcmp(&c.addr, &out[i].addr, sizeof(c.addr)) == 0 && memcmp(c.mac, zero, 6) == 0)
            memcpy(c.mac, out[i].mac, 6);
    }
    return n;
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

void History::sample(uint32_t allowedTotal, uint32_t blockedTotal)
{
    LockGuard g(mu_);
    allowed_[head_] = allowedTotal - lastAllowed_;
    blocked_[head_] = blockedTotal - lastBlocked_;
    lastAllowed_ = allowedTotal;
    lastBlocked_ = blockedTotal;
    head_ = (head_ + 1) % kSlots;
    if (filled_ < kSlots) filled_++;
}

size_t History::copy(uint32_t* allowed, uint32_t* blocked, uint32_t allowedTotal, uint32_t blockedTotal,
                     uint32_t& curAllowed, uint32_t& curBlocked)
{
    LockGuard g(mu_);
    for (size_t i = 0; i < filled_; i++) {
        const size_t k = (head_ + kSlots - filled_ + i) % kSlots;
        allowed[i] = allowed_[k];
        blocked[i] = blocked_[k];
    }
    curAllowed = allowedTotal - lastAllowed_;
    curBlocked = blockedTotal - lastBlocked_;
    return filled_;
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
    // Copy 16 entries at a time and filter them outside the lock: a search
    // that matches little would otherwise hold it for the whole ring, and
    // the DNS task waits for it on every query.
    QueryEntry chunk[16];
    size_t n = 0;
    for (;;) {
        size_t got = 0, total;
        {
            LockGuard g(mu_);
            total = count_;
            const size_t base = head_ + cap_ - 1;
            while (got < 16 && cursor + got < count_) {
                chunk[got] = ring_[(base - cursor - got) % cap_];
                got++;
            }
        }
        for (size_t k = 0; k < got; k++) {
            cursor++;
            const QueryEntry& e = chunk[k];
            if (f.ip && e.addr.v4() != f.ip) continue;
            if (f.blockedOnly && !e.blocked) continue;
            if (f.text && !strstr(e.domain, f.text)) continue;
            out[n++] = e;
            if (n == max) return n;
        }
        if (!got || cursor >= total) return n;
    }
}

}  // namespace sinkhole
