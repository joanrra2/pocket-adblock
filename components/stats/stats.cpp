#include "sinkhole/stats.hpp"

#include <cstring>

#include "esp_log.h"
#include "esp_netif.h"
#include "sdkconfig.h"
#include "sinkhole/memory.hpp"
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "sinkhole/config.hpp"

namespace sinkhole {

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
        if (memcmp(c.mac, zero, 6) != 0) continue;
        ip4_addr_t ip;
        ip.addr = c.ip;
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

ClientInfo* ClientTable::findLocked(uint32_t ip)
{
    for (size_t i = 0; i < count_; i++)
        if (clients_[i].ip == ip) return &clients_[i];
    return nullptr;
}

bool ClientTable::record(uint32_t ip, bool blocked)
{
    LockGuard g(mu_);
    ClientInfo* c = findLocked(ip);
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
        c->ip = ip;
        for (size_t i = 0; i < bannedCount_; i++)
            if (banned_[i] == ip) c->banned = true;
    }
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
    if (ClientInfo* c = findLocked(ip)) c->banned = banned;
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
}

void QueryLog::add(uint32_t ip, const char* domain, bool blocked)
{
    LockGuard g(mu_);
    QueryEntry& e = ring_[head_];
    e.uptime = uptimeSeconds();
    e.ip = ip;
    e.blocked = blocked;
    strncpy(e.domain, domain, sizeof(e.domain) - 1);
    e.domain[sizeof(e.domain) - 1] = '\0';
    head_ = (head_ + 1) % cap_;
    if (count_ < cap_) count_++;
}

size_t QueryLog::page(size_t& cursor, const QueryFilter& f, QueryEntry* out, size_t max)
{
    LockGuard g(mu_);
    size_t n = 0;
    while (cursor < count_ && n < max) {
        const QueryEntry& e = ring_[(head_ + cap_ - 1 - cursor) % cap_];
        cursor++;
        if (f.ip && e.ip != f.ip) continue;
        if (f.blockedOnly && !e.blocked) continue;
        if (f.text && !strstr(e.domain, f.text)) continue;
        out[n++] = e;
    }
    return n;
}

}  // namespace sinkhole
