#pragma once
// UDP DNS server on :53. One task, two sockets, select():
//   client query  -> blocked? answer locally : forward with a fresh txid
//   upstream reply -> match txid + source + question, relay to the client
// Forwarding never blocks: in-flight queries live in a fixed pending table and
// are dropped after CONFIG_SINKHOLE_DNS_UPSTREAM_TIMEOUT_MS (the client retries).

#include <atomic>
#include <cstddef>
#include <cstdint>

#include "esp_err.h"
#include "lwip/sockets.h"
#include "sdkconfig.h"
#include "sinkhole/dns_cache.hpp"
#include "sinkhole/domain_filter.hpp"
#include "sinkhole/rtos.hpp"
#include "sinkhole/stats.hpp"

namespace sinkhole {

union ClientSockAddr {
    sockaddr_in v4;
    sockaddr_in6 v6;
};

class DnsServer {
public:
    DnsServer(DomainFilter& filter, ClientTable& clients, QueryLog& log, Counters& counters)
        : filter_(filter), clients_(clients), log_(log), counters_(counters)
    {
    }

    esp_err_t start();
    // With a backup set, every forwarded query is sent to both and the first
    // matching answer wins: a dead or slow resolver costs no latency.
    void setUpstream(uint32_t primary, uint32_t backup = 0)
    {
        upstream_ = primary;
        upstream2_ = backup != primary ? backup : 0;
    }
    uint32_t backupUpstream() const { return upstream2_; }
    uint32_t wins(int i) const { return wins_[i]; }
    // Average time to decide blocked/allowed, in 0.1 us (0 until 256 queries).
    uint32_t filterAvgUs10() const { return filterAvgUs10_; }
    // Captive portal: while there is no uplink, clients on the setup AP get our
    // own address for every name, so phones pop up the setup page by themselves.
    void setCaptive(bool on, uint32_t apIp, uint32_t apMask)
    {
        apIp_ = apIp;
        apMask_ = apMask;
        captive_ = on;
    }
    bool captive() const { return captive_; }
    uint32_t upstream() const { return upstream_; }
    uint32_t pendingCount() const { return pendingInUse_; }
    bool running() const { return running_; }
    const DnsCache& cache() const { return cache_; }

private:
    struct Pending {
        bool used;
        uint16_t upstreamId;
        uint16_t clientId;
        uint32_t questionKey;
        uint32_t cacheKey;
        uint32_t upstreamIp;
        uint32_t upstreamIp2;  // 0 = no backup for this query
        uint8_t failedMask;    // which upstreams answered with an error
        bool clientV6;
        ClientSockAddr client;
        TickType_t deadline;
    };

    static void taskEntry(void* arg);
    void run();
    void onClientPacket(int sock);
    void onUpstreamPacket();
    void expirePending();
    Pending* allocPending();
    void reply(const ClientSockAddr& to, bool v6, const uint8_t* data, size_t len);

    DomainFilter& filter_;
    ClientTable& clients_;
    QueryLog& log_;
    Counters& counters_;

    int serverSock_ = -1;
    int server6Sock_ = -1;  // IPv6 clients (IPV6_V6ONLY), -1 if unavailable
    int upstreamSock_ = -1;
    std::atomic<uint32_t> upstream_{0};
    std::atomic<uint32_t> upstream2_{0};
    std::atomic<uint32_t> wins_[2] = {0, 0};  // first answers: primary / backup
    std::atomic<uint32_t> filterAvgUs10_{0};
    uint32_t filterSumUs_ = 0;
    uint32_t filterN_ = 0;
    std::atomic<uint32_t> pendingInUse_{0};
    std::atomic<bool> running_{false};
    std::atomic<bool> captive_{false};
    std::atomic<uint32_t> apIp_{0};
    std::atomic<uint32_t> apMask_{0};

    DnsCache cache_;
    Pending pending_[CONFIG_SINKHOLE_DNS_MAX_PENDING]{};
    uint8_t buf_[1536];  // any non-fragmented UDP datagram
    uint8_t out_[DnsCache::kMaxResponse];
    StaticTask<5120> task_;
};

}  // namespace sinkhole
