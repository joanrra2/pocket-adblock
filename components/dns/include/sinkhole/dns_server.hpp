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

class DnsServer {
public:
    DnsServer(DomainFilter& filter, ClientTable& clients, QueryLog& log, Counters& counters)
        : filter_(filter), clients_(clients), log_(log), counters_(counters)
    {
    }

    esp_err_t start();
    void setUpstream(uint32_t ipNetOrder) { upstream_ = ipNetOrder; }
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
        sockaddr_in client;
        TickType_t deadline;
    };

    static void taskEntry(void* arg);
    void run();
    void onClientPacket();
    void onUpstreamPacket();
    void expirePending();
    Pending* allocPending();
    void reply(const sockaddr_in& to, const uint8_t* data, size_t len);

    DomainFilter& filter_;
    ClientTable& clients_;
    QueryLog& log_;
    Counters& counters_;

    int serverSock_ = -1;
    int upstreamSock_ = -1;
    std::atomic<uint32_t> upstream_{0};
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
