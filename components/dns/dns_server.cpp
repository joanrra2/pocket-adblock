#include "sinkhole/dns_server.hpp"

#include <cerrno>
#include <cstring>
#include <initializer_list>

#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "sinkhole/bypass_guard.hpp"
#include "sinkhole/dns_packet.hpp"

namespace sinkhole {

namespace {
constexpr const char* TAG = "dns";
constexpr uint16_t kDnsPort = 53;
constexpr TickType_t kTimeout = pdMS_TO_TICKS(CONFIG_SINKHOLE_DNS_UPSTREAM_TIMEOUT_MS);
constexpr uint32_t kLocalTtl = 60;  // local names: short, so edits show up quickly
constexpr uint32_t kSafeTtl = 300;
constexpr uint32_t kSafeRefreshS = 6 * 3600, kSafeRetryS = 60;

int openUdp(uint16_t port)
{
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) return -1;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(s);
        return -1;
    }
    return s;
}

// IPv6-only listener next to the IPv4 one (separate sockets keep client
// addresses unambiguous). Returns -1 if IPv6 is unavailable.
int openUdp6(uint16_t port)
{
    int s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) return -1;
    int one = 1;
    setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(s);
        return -1;
    }
    return s;
}
}  // namespace

esp_err_t DnsServer::start()
{
    cache_.begin();
    records_.load();
    serverSock_ = openUdp(kDnsPort);
    upstreamSock_ = openUdp(0);  // ephemeral source port
    server6Sock_ = openUdp6(kDnsPort);
    if (server6Sock_ < 0) ESP_LOGW(TAG, "no IPv6 listener (errno %d)", errno);
    if (serverSock_ < 0 || upstreamSock_ < 0) {
        ESP_LOGE(TAG, "socket setup failed: errno %d", errno);
        return ESP_FAIL;
    }
    if (!task_.start("dns", &DnsServer::taskEntry, this, 6)) return ESP_ERR_NO_MEM;
    return ESP_OK;
}

void DnsServer::taskEntry(void* arg)
{
    static_cast<DnsServer*>(arg)->run();
}

void DnsServer::run()
{
    running_ = true;
    ESP_LOGI(TAG, "listening on :%u (IPv4%s)", kDnsPort, server6Sock_ >= 0 ? " + IPv6" : "");
    for (;;) {
        fd_set rd;
        FD_ZERO(&rd);
        FD_SET(serverSock_, &rd);
        FD_SET(upstreamSock_, &rd);
        int maxFd = serverSock_ > upstreamSock_ ? serverSock_ : upstreamSock_;
        if (server6Sock_ >= 0) {
            FD_SET(server6Sock_, &rd);
            if (server6Sock_ > maxFd) maxFd = server6Sock_;
        }
        timeval tv{0, 100 * 1000};  // also drives expiry
        int n = select(maxFd + 1, &rd, nullptr, nullptr, &tv);
        if (n > 0) {
            // Replies first: they free pending slots.
            if (FD_ISSET(upstreamSock_, &rd)) onUpstreamPacket();
            if (FD_ISSET(serverSock_, &rd)) onClientPacket(serverSock_);
            if (server6Sock_ >= 0 && FD_ISSET(server6Sock_, &rd)) onClientPacket(server6Sock_);
        }
        expirePending();
        if (flushCache_.exchange(false)) cache_.clear();
        refreshSafeTargets();
    }
}

DnsServer::Pending* DnsServer::allocPending()
{
    for (auto& p : pending_)
        if (!p.used) return &p;
    return nullptr;
}

void DnsServer::reply(const ClientSockAddr& to, bool v6, const uint8_t* data, size_t len)
{
    if (v6)
        sendto(server6Sock_, data, len, 0, reinterpret_cast<const sockaddr*>(&to.v6), sizeof(to.v6));
    else
        sendto(serverSock_, data, len, 0, reinterpret_cast<const sockaddr*>(&to.v4), sizeof(to.v4));
}

void DnsServer::onClientPacket(int sock)
{
    ClientSockAddr from{};
    const bool v6 = sock == server6Sock_;
    socklen_t fromLen = v6 ? sizeof(from.v6) : sizeof(from.v4);
    int len = recvfrom(sock, buf_, sizeof(buf_), 0, reinterpret_cast<sockaddr*>(&from), &fromLen);
    if (len <= 0) return;

    dns::Question q;
    if (!dns::parseQuery(buf_, static_cast<size_t>(len), q)) {
        counters_.dropped++;
        return;
    }

    const ClientAddr client = v6 ? ClientAddr::fromV6(reinterpret_cast<const uint8_t*>(&from.v6.sin6_addr))
                                 : ClientAddr::fromV4(from.v4.sin_addr.s_addr);
    const uint32_t clientIp = client.v4();
    if (captive_ && !v6) {
        const uint32_t apIp = apIp_, mask = apMask_;
        if (apIp && (clientIp & mask) == (apIp & mask)) {
            reply(from, false, buf_, dns::buildCaptive(buf_, sizeof(buf_), q, apIp));
            return;
        }
    }

    // Local names first: they are the user's own and never blocked.
    LocalRecords::Kind localKind;
    uint32_t localIp = 0;
    const bool local = records_.lookup(q.name, q.nameLen, localKind, localIp);
    if (local && localKind == LocalRecords::Kind::Address) {
        counters_.allowed++;
        clients_.record(client, false);
        log_.add(client, q.name, false);
        reply(from, v6, buf_, dns::buildCaptive(buf_, sizeof(buf_), q, localIp, kLocalTtl));
        return;
    }
    const uint32_t forwardTo = local ? localIp : 0;  // forward rule: that server only

    // SafeSearch: search hostnames get the provider's safe endpoint (A only;
    // NODATA for AAAA etc. so clients use it). Stays on while blocking is paused.
    if (const uint8_t ss = forwardTo ? 0 : safe_.load()) {
        const safe::Target t = safe::check(q.name, q.nameLen, ss);
        if (t != safe::None) {
            counters_.allowed++;
            clients_.record(client, false);
            log_.add(client, q.name, false);
            reply(from, v6, buf_, dns::buildCaptive(buf_, sizeof(buf_), q, safeIps_[t], kSafeTtl));
            return;
        }
    }

    // Bypass guard (canary domains / encrypted-DNS resolvers): NXDOMAIN, so
    // browsers and phones keep using this server. Respects pause and allow list.
    if (const uint8_t g = forwardTo ? 0 : guard_.load()) {
        const guard::Hit hit = guard::check(q.name, q.nameLen, g);
        if (hit != guard::Hit::None && filter_.enabled() &&
            (hit == guard::Hit::Canary || !filter_.isAllowed(q.name, q.nameLen))) {
            counters_.blocked++;
            counters_.bypassBlocked++;
            clients_.record(client, true);
            log_.add(client, q.name, true);
            reply(from, v6, buf_, dns::buildNxdomain(buf_, q));
            return;
        }
    }

    const int64_t t0 = esp_timer_get_time();
    const bool blocked = !forwardTo && filter_.isBlocked(q.name, q.nameLen);
    // Rolling average of the filter cost (allow/custom/blocklist), published
    // every 256 queries; only this task writes the accumulators.
    filterSumUs_ += static_cast<uint32_t>(esp_timer_get_time() - t0);
    if (++filterN_ == 256) {
        filterAvgUs10_ = filterSumUs_ * 10 / 256;
        filterSumUs_ = 0;
        filterN_ = 0;
    }
    const bool banned = clients_.record(client, blocked);
    log_.add(client, q.name, blocked || banned);

    if (blocked || banned) {
        counters_.blocked++;
        size_t rlen = dns::buildBlocked(buf_, sizeof(buf_), q);
        reply(from, v6, buf_, rlen);
        return;
    }

    counters_.allowed++;

    const uint32_t qkey = dns::questionKey(buf_, q.end);
    const uint32_t ckey = DnsCache::keyFor(qkey, dns::rd16(buf_ + 10) > 0);
    if (size_t hit = cache_.lookup(ckey, buf_, q.end, out_, sizeof(out_))) {
        // Cached answers are re-checked too, so allow-list and setting changes
        // apply at once (only answers that carry aliases cost anything).
        if (cnameCloaked(out_, hit, q.end)) {
            countCnameBlocked(client, q.name);
            reply(from, v6, buf_, dns::buildBlocked(buf_, sizeof(buf_), q));
            return;
        }
        reply(from, v6, out_, hit);
        return;
    }

    const uint32_t up = forwardTo ? forwardTo : upstream_.load();
    Pending* p = up ? allocPending() : nullptr;
    if (!p) {
        counters_.dropped++;  // no upstream yet, or table full: client will retry
        return;
    }

    // Fresh random txid, unique among in-flight queries (cache-poisoning hygiene
    // and protection against two clients using the same id).
    uint16_t id;
    bool clash;
    do {
        id = static_cast<uint16_t>(esp_random());
        clash = false;
        for (const auto& o : pending_)
            if (o.used && o.upstreamId == id) clash = true;
    } while (clash);

    p->used = true;
    p->upstreamId = id;
    p->clientId = dns::rd16(buf_);
    p->questionKey = qkey;
    p->cacheKey = ckey;
    p->upstreamIp = up;
    p->upstreamIp2 = forwardTo ? 0 : upstream2_.load();
    p->failedMask = 0;
    p->client = from;
    p->clientV6 = v6;
    p->internal = -1;
    p->deadline = xTaskGetTickCount() + kTimeout;
    pendingInUse_++;

    dns::wr16(buf_, id);
    sockaddr_in to{};
    to.sin_family = AF_INET;
    to.sin_port = htons(kDnsPort);
    int sent = 0;
    for (uint32_t target : {p->upstreamIp, p->upstreamIp2}) {
        if (!target) continue;
        to.sin_addr.s_addr = target;
        if (sendto(upstreamSock_, buf_, static_cast<size_t>(len), 0,
                   reinterpret_cast<sockaddr*>(&to), sizeof(to)) >= 0)
            sent++;
    }
    if (!sent) {
        p->used = false;
        pendingInUse_--;
    }
}

void DnsServer::onUpstreamPacket()
{
    sockaddr_in from{};
    socklen_t fromLen = sizeof(from);
    int len = recvfrom(upstreamSock_, buf_, sizeof(buf_), 0, reinterpret_cast<sockaddr*>(&from),
                       &fromLen);
    if (len < static_cast<int>(dns::kHeaderLen)) return;
    if (from.sin_port != htons(kDnsPort)) return;

    const uint16_t id = dns::rd16(buf_);
    const size_t qend = dns::questionEnd(buf_, static_cast<size_t>(len));
    const uint32_t key = qend ? dns::questionKey(buf_, qend) : 0;

    for (auto& p : pending_) {
        if (!p.used || p.upstreamId != id) continue;
        const uint32_t src = from.sin_addr.s_addr;
        const int which = src == p.upstreamIp ? 0 : (p.upstreamIp2 && src == p.upstreamIp2) ? 1 : -1;
        if (which < 0) return;                              // spoofed / wrong server
        if (qend && p.questionKey != key) return;           // not our question
        // Racing two resolvers: a SERVFAIL/REFUSED from one must not beat a real
        // answer from the other. Relay an error only once both have failed.
        const uint8_t rcode = buf_[3] & 0x0F;
        if (p.upstreamIp2 && rcode != 0 && rcode != 3) {
            p.failedMask |= static_cast<uint8_t>(1 << which);
            if (p.failedMask != 0x3) return;
        }
        if (p.internal >= 0) {  // our SafeSearch endpoint lookup: keep the first A
            const int t = p.internal;
            dns::forEachRecord(buf_, static_cast<size_t>(len), qend, [&](uint8_t* ttl, uint16_t type) {
                if (type == dns::kTypeA && dns::rd16(ttl + 4) == 4 && !(safeResolved_ & (1 << t))) {
                    uint32_t ip;
                    memcpy(&ip, ttl + 6, 4);
                    safeIps_[t] = ip;
                    safeResolved_ |= static_cast<uint8_t>(1 << t);
                }
            });
            if (safeResolved_ == (1 << safe::kTargets) - 1) safeRefreshAt_ = uptimeSeconds() + kSafeRefreshS;
            p.used = false;
            pendingInUse_--;
            return;
        }
        wins_[which]++;
        dns::wr16(buf_, p.clientId);
        // CNAME cloaking: an allowed name that is an alias of a blocked one
        // (metrics.shop.com -> shop.eulerian.net) is blocked too. Not cached,
        // so allow-list changes apply at once.
        if (qend && rcode == 0 && cnameCloaked(buf_, static_cast<size_t>(len), qend)) {
            dns::Question q{};
            q.end = qend;
            q.qtype = dns::rd16(buf_ + qend - 4);
            const ClientAddr client =
                p.clientV6 ? ClientAddr::fromV6(reinterpret_cast<const uint8_t*>(&p.client.v6.sin6_addr))
                           : ClientAddr::fromV4(p.client.v4.sin_addr.s_addr);
            char name[254];
            if (!dns::readName(buf_, static_cast<size_t>(len), dns::kHeaderLen, name, sizeof(name))) name[0] = '\0';
            countCnameBlocked(client, strncmp(name, "www.", 4) == 0 && name[4] ? name + 4 : name);
            reply(p.client, p.clientV6, buf_, dns::buildBlocked(buf_, sizeof(buf_), q));
            p.used = false;
            pendingInUse_--;
            return;
        }
        reply(p.client, p.clientV6, buf_, static_cast<size_t>(len));  // client first, cache after
        cache_.store(p.cacheKey, buf_, static_cast<size_t>(len));
        p.used = false;
        pendingInUse_--;
        return;
    }
    // Late reply for an expired query: ignore.
}

bool DnsServer::cnameCloaked(const uint8_t* pkt, size_t len, size_t qend)
{
    if (!cnameCheck_ || dns::rd16(pkt + 6) < 2) return false;  // an alias needs >= 2 answers
    return dns::anyCnameTarget(pkt, len, qend, [this](const char* n, size_t l) { return filter_.isBlocked(n, l); });
}

// The query was counted and logged as allowed when it arrived.
void DnsServer::countCnameBlocked(const ClientAddr& client, const char* name)
{
    if (name[0]) log_.markBlocked(client, name);
    counters_.allowed--;
    counters_.blocked++;
    counters_.cnameBlocked++;
}

// Looks up the SafeSearch endpoints through the upstream (their addresses
// change, e.g. strict.bing.com), every 6 h, or every minute until all resolve.
void DnsServer::refreshSafeTargets()
{
    const uint8_t ss = safe_;
    const uint32_t up = upstream_;
    const uint32_t now = uptimeSeconds();
    if (!ss || !up || now < safeRefreshAt_) return;
    safeResolved_ = 0;
    for (int t = 0; t < safe::kTargets; t++) {
        Pending* p = allocPending();
        if (!p) break;
        uint8_t pkt[64] = {0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0};
        size_t n = dns::kHeaderLen;
        for (const char* s = safe::kTargetNames[t]; *s;) {
            const char* dot = strchr(s, '.');
            const size_t l = dot ? static_cast<size_t>(dot - s) : strlen(s);
            pkt[n++] = static_cast<uint8_t>(l);
            memcpy(pkt + n, s, l);
            n += l;
            s += l + (dot ? 1 : 0);
        }
        pkt[n++] = 0;
        dns::wr16(pkt + n, dns::kTypeA);
        dns::wr16(pkt + n + 2, 1);
        n += 4;
        uint16_t id;
        bool clash;
        do {
            id = static_cast<uint16_t>(esp_random());
            clash = false;
            for (const auto& o : pending_)
                if (o.used && o.upstreamId == id) clash = true;
        } while (clash);
        dns::wr16(pkt, id);
        *p = Pending{};
        p->used = true;
        p->upstreamId = id;
        p->questionKey = dns::questionKey(pkt, n);
        p->upstreamIp = up;
        p->internal = static_cast<int8_t>(t);
        p->deadline = xTaskGetTickCount() + kTimeout;
        pendingInUse_++;
        sockaddr_in to{};
        to.sin_family = AF_INET;
        to.sin_port = htons(kDnsPort);
        to.sin_addr.s_addr = up;
        sendto(upstreamSock_, pkt, n, 0, reinterpret_cast<sockaddr*>(&to), sizeof(to));
    }
    safeRefreshAt_ = now + kSafeRetryS;  // becomes 6 h once all resolved (checked next round)
}

void DnsServer::expirePending()
{
    const TickType_t now = xTaskGetTickCount();
    for (auto& p : pending_) {
        if (p.used && static_cast<int32_t>(now - p.deadline) >= 0) {
            p.used = false;
            pendingInUse_--;
            if (p.internal < 0) counters_.upstreamTimeouts++;
        }
    }
}

}  // namespace sinkhole
