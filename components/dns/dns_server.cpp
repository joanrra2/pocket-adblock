#include "sinkhole/dns_server.hpp"

#include <cerrno>
#include <cstring>
#include <initializer_list>

#include "esp_log.h"
#include "esp_random.h"
#include "sinkhole/dns_packet.hpp"

namespace sinkhole {

namespace {
constexpr const char* TAG = "dns";
constexpr uint16_t kDnsPort = 53;
constexpr TickType_t kTimeout = pdMS_TO_TICKS(CONFIG_SINKHOLE_DNS_UPSTREAM_TIMEOUT_MS);

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
}  // namespace

esp_err_t DnsServer::start()
{
    cache_.begin();
    serverSock_ = openUdp(kDnsPort);
    upstreamSock_ = openUdp(0);  // ephemeral source port
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
    ESP_LOGI(TAG, "listening on :%u", kDnsPort);
    for (;;) {
        fd_set rd;
        FD_ZERO(&rd);
        FD_SET(serverSock_, &rd);
        FD_SET(upstreamSock_, &rd);
        timeval tv{0, 100 * 1000};  // also drives expiry
        int maxFd = serverSock_ > upstreamSock_ ? serverSock_ : upstreamSock_;
        int n = select(maxFd + 1, &rd, nullptr, nullptr, &tv);
        if (n > 0) {
            // Replies first: they free pending slots.
            if (FD_ISSET(upstreamSock_, &rd)) onUpstreamPacket();
            if (FD_ISSET(serverSock_, &rd)) onClientPacket();
        }
        expirePending();
    }
}

DnsServer::Pending* DnsServer::allocPending()
{
    for (auto& p : pending_)
        if (!p.used) return &p;
    return nullptr;
}

void DnsServer::reply(const sockaddr_in& to, const uint8_t* data, size_t len)
{
    sendto(serverSock_, data, len, 0, reinterpret_cast<const sockaddr*>(&to), sizeof(to));
}

void DnsServer::onClientPacket()
{
    sockaddr_in from{};
    socklen_t fromLen = sizeof(from);
    int len = recvfrom(serverSock_, buf_, sizeof(buf_), 0, reinterpret_cast<sockaddr*>(&from),
                       &fromLen);
    if (len <= 0) return;

    dns::Question q;
    if (!dns::parseQuery(buf_, static_cast<size_t>(len), q)) {
        counters_.dropped++;
        return;
    }

    const uint32_t clientIp = from.sin_addr.s_addr;
    if (captive_) {
        const uint32_t apIp = apIp_, mask = apMask_;
        if (apIp && (clientIp & mask) == (apIp & mask)) {
            reply(from, buf_, dns::buildCaptive(buf_, sizeof(buf_), q, apIp));
            return;
        }
    }

    const bool blocked = filter_.isBlocked(q.name, q.nameLen);
    const bool banned = clients_.record(clientIp, blocked);
    log_.add(clientIp, q.name, blocked || banned);

    if (blocked || banned) {
        counters_.blocked++;
        size_t rlen = dns::buildBlocked(buf_, sizeof(buf_), q);
        reply(from, buf_, rlen);
        return;
    }

    counters_.allowed++;

    const uint32_t qkey = dns::questionKey(buf_, q.end);
    const uint32_t ckey = DnsCache::keyFor(qkey, dns::rd16(buf_ + 10) > 0);
    if (size_t hit = cache_.lookup(ckey, buf_, q.end, out_, sizeof(out_))) {
        reply(from, out_, hit);
        return;
    }

    const uint32_t up = upstream_;
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
    p->upstreamIp2 = upstream2_;
    p->failedMask = 0;
    p->client = from;
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
        wins_[which]++;
        dns::wr16(buf_, p.clientId);
        reply(p.client, buf_, static_cast<size_t>(len));  // client first, cache after
        cache_.store(p.cacheKey, buf_, static_cast<size_t>(len));
        p.used = false;
        pendingInUse_--;
        return;
    }
    // Late reply for an expired query: ignore.
}

void DnsServer::expirePending()
{
    const TickType_t now = xTaskGetTickCount();
    for (auto& p : pending_) {
        if (p.used && static_cast<int32_t>(now - p.deadline) >= 0) {
            p.used = false;
            pendingInUse_--;
            counters_.upstreamTimeouts++;
        }
    }
}

}  // namespace sinkhole
