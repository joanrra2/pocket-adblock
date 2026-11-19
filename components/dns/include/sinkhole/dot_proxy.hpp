#pragma once
// DNS over TLS (RFC 7858) as a local UDP upstream: the DNS server forwards to
// 127.0.0.1:kPort like to any resolver; this task keeps one TLS connection to
// the provider (port 853), sends each query length-prefixed, and returns the
// answers over UDP. Queries are pipelined; the connection is opened on first
// use and re-opened after errors or when the server closes it.
//
// Build option CONFIG_SINKHOLE_DNS_OVER_TLS (~40 KB RAM for the TLS session):
// boards with PSRAM. Without it, start() is a no-op and available() is false.

#include <atomic>
#include <cstdint>

#include "esp_err.h"
#include "sdkconfig.h"
#include "sinkhole/rtos.hpp"

namespace sinkhole {

class DotProxy {
public:
    static constexpr uint16_t kPort = 8853;  // loopback only

    static constexpr bool available()
    {
#ifdef CONFIG_SINKHOLE_DNS_OVER_TLS
        return true;
#else
        return false;
#endif
    }

    esp_err_t start();
    // host e.g. "dns.quad9.net" (empty = idle). bootstrap: the plain upstream
    // (network order) that looks the host up; never this device itself.
    void setHost(const char* host, uint32_t bootstrap);
    bool connected() const { return connected_; }
    uint32_t queries() const { return queries_; }
    uint32_t connects() const { return connects_; }

private:
    static void taskEntry(void* arg);
    void run();

    Mutex mu_;
    char host_[64]{};
    uint32_t bootstrap_ = 0;
    std::atomic<bool> hostChanged_{false};
    std::atomic<bool> connected_{false};
    std::atomic<uint32_t> queries_{0};
    std::atomic<uint32_t> connects_{0};
#ifdef CONFIG_SINKHOLE_DNS_OVER_TLS
    // A TLS handshake to dns.quad9.net left 1856 bytes of 6144 (S3): 1 KB
    // more, as certificate chains and curves differ between providers.
    StaticTask<7168> task_;
#endif
};

}  // namespace sinkhole
