#pragma once
// Optional DHCP server on the home network (station interface), for routers
// whose DNS setting can't be changed: turn the router's DHCP off and this one
// hands out addresses with the router as gateway and this device as DNS.
// Needs a static IP. Uses lwIP's DHCP server directly on the station netif
// (esp_netif only allows it on the access point).

#include <atomic>
#include <cstdint>

#include "esp_err.h"
#include "esp_netif.h"
#include "sdkconfig.h"
#include "sinkhole/rtos.hpp"

namespace sinkhole {

class LanDhcp {
public:
    // lwIP keeps one lease entry per client and silently drops the oldest one
    // past CONFIG_LWIP_DHCPS_MAX_STATION_NUM, which would hand the same address
    // to two devices. A pool no larger than the table can't overflow it: when
    // every address is taken, new clients get a NAK instead.
    static constexpr uint32_t kMaxPool = CONFIG_LWIP_DHCPS_MAX_STATION_NUM;

    struct Options {
        uint32_t ip;     // this device (network order); also the DNS handed out
        uint32_t mask;
        uint32_t gw;     // the router: handed out as gateway, kept out of the pool
        uint32_t first;  // pool, inclusive
        uint32_t last;
        uint16_t leaseMinutes;
        bool operator==(const Options&) const = default;
    };

    // Counters since boot, for the status page and for telling "nothing
    // arrives" apart from "answers don't get through".
    struct Stats {
        uint32_t discovers, requests, others;  // received on the home network
        uint32_t offers, acks, naks;           // replies built
        uint32_t leases;                       // ACKs actually sent
        uint32_t lastLeaseIp;
    };

    // nullptr if the pool fits the network, else why not (shown to the user).
    // lwIP silently replaces an invalid pool with one next to this device's
    // address, so nothing reaches it unchecked.
    static const char* checkPool(const Options& o);

    // Starts, or restarts when the options or the netif changed. With the same
    // options it keeps running and keeps the lease table: a restart forgets
    // every lease, and clients renewing theirs then get a NAK.
    esp_err_t start(esp_netif_t* sta, const Options& o);
    void stop();
    bool running() const { return running_; }
    // The hostname a client sent with its DHCP request (option 12); false if
    // the server isn't running, doesn't know the MAC or got no name.
    bool hostname(const uint8_t* mac, char* out, size_t cap);
    static Stats stats();

private:
    static esp_err_t startInLwip(void* ctx);
    static esp_err_t stopInLwip(void* ctx);

    Mutex mu_;
    void* dhcps_ = nullptr;  // dhcps_t*
    esp_netif_t* netif_ = nullptr;
    Options opt_{};
    Options want_{};
    bool restarted_ = false;
    std::atomic<bool> running_{false};
    // lwIP thread only: netif index when started. esp_netif re-adds a netif
    // with a new index after a Wi-Fi restart, and a server still bound to the
    // old index never sees another packet.
    uint8_t servedIdx_ = 0;
};

}  // namespace sinkhole
