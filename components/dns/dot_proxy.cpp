#include "sinkhole/dot_proxy.hpp"

#include <cstring>

#include "esp_log.h"
#include "sinkhole/memory.hpp"
#include "sinkhole/text.hpp"

#ifdef CONFIG_SINKHOLE_DNS_OVER_TLS
#include "esp_crt_bundle.h"
#include "esp_tls.h"
#include "lwip/sockets.h"
#endif

namespace sinkhole {

namespace {
constexpr const char* TAG = "dot";
}

void DotProxy::setHost(const char* host)
{
    LockGuard g(mu_);
    if (strcmp(host_, host) == 0) return;
    copyStr(host_, host);
    hostChanged_ = true;
}

#ifndef CONFIG_SINKHOLE_DNS_OVER_TLS

esp_err_t DotProxy::start() { return ESP_OK; }
void DotProxy::taskEntry(void*) {}
void DotProxy::run() {}

#else

esp_err_t DotProxy::start()
{
    return task_.start("dot", &DotProxy::taskEntry, this, 5) ? ESP_OK : ESP_ERR_NO_MEM;
}

void DotProxy::taskEntry(void* arg)
{
    static_cast<DotProxy*>(arg)->run();
}

namespace {

// Reads exactly n bytes from the TLS stream (blocking, bounded by the socket timeout).
bool readExact(esp_tls_t* tls, uint8_t* out, size_t n)
{
    while (n) {
        const ssize_t r = esp_tls_conn_read(tls, out, n);
        if (r <= 0) return false;
        out += r;
        n -= static_cast<size_t>(r);
    }
    return true;
}

bool writeAll(esp_tls_t* tls, const uint8_t* data, size_t n)
{
    while (n) {
        const ssize_t w = esp_tls_conn_write(tls, data, n);
        if (w <= 0) return false;
        data += w;
        n -= static_cast<size_t>(w);
    }
    return true;
}

}  // namespace

void DotProxy::run()
{
    const int udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = htons(kPort);
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (udp < 0 || bind(udp, reinterpret_cast<sockaddr*>(&local), sizeof(local)) < 0) {
        ESP_LOGE(TAG, "loopback socket failed");
        vTaskDelete(nullptr);
        return;
    }

    esp_tls_t* tls = nullptr;
    int tlsFd = -1;
    sockaddr_in replyTo{};  // the DNS server's upstream socket
    static uint8_t buf[2 + 1536];
    char host[64];
    uint32_t lastActivity = 0;
    uint32_t lowMemoryLogged = 0;

    auto disconnect = [&]() {
        if (tls) esp_tls_conn_destroy(tls);
        tls = nullptr;
        tlsFd = -1;
        connected_ = false;
    };
    auto connect = [&]() -> bool {
        {
            LockGuard g(mu_);
            copyStr(host, host_);
        }
        if (!host[0]) return false;
        // Low on internal RAM: no TLS answer for this query (a backup server,
        // when set, still answers it; the client retries otherwise).
        if (!tlsRoom()) {
            if (const uint32_t now = uptimeSeconds(); lowMemoryLogged == 0 || now - lowMemoryLogged >= 60) {
                lowMemoryLogged = now ? now : 1;
                ESP_LOGW(TAG, "not enough free memory for a TLS session, not connecting");
            }
            return false;
        }
        tls = esp_tls_init();
        if (!tls) return false;
        esp_tls_cfg_t cfg = {};
        cfg.crt_bundle_attach = esp_crt_bundle_attach;
        cfg.timeout_ms = 4000;
        cfg.non_block = false;
        if (esp_tls_conn_new_sync(host, static_cast<int>(strlen(host)), 853, &cfg, tls) != 1) {
            ESP_LOGW(TAG, "connect to %s:853 failed", host);
            esp_tls_conn_destroy(tls);
            tls = nullptr;
            return false;
        }
        esp_tls_get_conn_sockfd(tls, &tlsFd);
        timeval tv{2, 0};  // bound blocking reads of a started answer
        setsockopt(tlsFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        connected_ = true;
        connects_++;
        ESP_LOGI(TAG, "connected to %s:853", host);
        return true;
    };

    for (;;) {
        if (hostChanged_.exchange(false)) disconnect();

        // Answers already decrypted and buffered in mbedTLS don't wake select().
        const bool pending = tls && esp_tls_get_bytes_avail(tls) > 0;
        fd_set rd;
        FD_ZERO(&rd);
        FD_SET(udp, &rd);
        int maxFd = udp;
        if (tlsFd >= 0) {
            FD_SET(tlsFd, &rd);
            if (tlsFd > maxFd) maxFd = tlsFd;
        }
        timeval tv{pending ? 0 : 1, 0};
        const int n = select(maxFd + 1, &rd, nullptr, nullptr, &tv);

        // Close quietly when idle for a while; reopened on the next query.
        if (tls && uptimeSeconds() - lastActivity > 120) disconnect();
        if (n < 0) continue;

        if (FD_ISSET(udp, &rd)) {
            socklen_t fromLen = sizeof(replyTo);
            const int len = recvfrom(udp, buf + 2, sizeof(buf) - 2, 0, reinterpret_cast<sockaddr*>(&replyTo), &fromLen);
            if (len > 0) {
                buf[0] = static_cast<uint8_t>(len >> 8);
                buf[1] = static_cast<uint8_t>(len);
                // One retry on a fresh connection: providers close idle ones.
                for (int attempt = 0; attempt < 2; attempt++) {
                    if (!tls && !connect()) break;
                    if (writeAll(tls, buf, static_cast<size_t>(len) + 2)) {
                        queries_++;
                        lastActivity = uptimeSeconds();
                        break;
                    }
                    disconnect();
                }
            }
        }

        if (tls && (pending || (tlsFd >= 0 && FD_ISSET(tlsFd, &rd)))) {
            uint8_t hdr[2];
            if (!readExact(tls, hdr, 2)) {
                disconnect();  // closed by the server (or error): reopen on demand
                continue;
            }
            const size_t len = static_cast<size_t>(hdr[0]) << 8 | hdr[1];
            if (len > sizeof(buf) || !readExact(tls, buf, len)) {
                disconnect();
                continue;
            }
            lastActivity = uptimeSeconds();
            sendto(udp, buf, len, 0, reinterpret_cast<sockaddr*>(&replyTo), sizeof(replyTo));
        }
    }
}

#endif

}  // namespace sinkhole
