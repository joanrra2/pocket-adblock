#include <cstring>

#include "esp_log.h"
#include "esp_random.h"
#include "lwip/sockets.h"
#include "sinkhole/text.hpp"
#include "sinkhole/wol.hpp"

namespace sinkhole {

namespace {
constexpr const char* TAG = "wol";
constexpr const char* kHostsKey = "wol_hosts";
constexpr uint16_t kWolPort = 9;
constexpr uint32_t kProbeIntervalMs = 30 * 1000;

struct __attribute__((packed)) IcmpEcho {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
    uint8_t payload[8];
};

uint16_t inetChecksum(const void* data, size_t len)
{
    const uint8_t* p = static_cast<const uint8_t*>(data);
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2) sum += static_cast<uint32_t>(p[i] << 8 | p[i + 1]);
    if (len & 1) sum += static_cast<uint32_t>(p[len - 1] << 8);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return htons(static_cast<uint16_t>(~sum));
}
}  // namespace

esp_err_t WolService::begin()
{
    {
        LockGuard g(mu_);
        WolHost stored[kCapacity];
        size_t n = 0;
        nvs::loadBlob(kHostsKey, stored, sizeof(stored), &n);
        count_ = n / sizeof(WolHost);
        for (size_t i = 0; i < count_; i++) {
            hosts_[i] = WolHostState{};
            hosts_[i].host = stored[i];
            hosts_[i].host.name[sizeof(hosts_[i].host.name) - 1] = '\0';
        }
    }
    return task_.start("wol_probe", &WolService::taskEntry, this, 2) ? ESP_OK : ESP_ERR_NO_MEM;
}

int WolService::findLocked(const char* name)
{
    for (size_t i = 0; i < count_; i++)
        if (strcmp(hosts_[i].host.name, name) == 0) return static_cast<int>(i);
    return -1;
}

esp_err_t WolService::saveLocked()
{
    WolHost stored[kCapacity];
    for (size_t i = 0; i < count_; i++) stored[i] = hosts_[i].host;
    return nvs::saveBlob(kHostsKey, stored, count_ * sizeof(WolHost));
}

esp_err_t WolService::add(const WolHost& h)
{
    if (!h.name[0]) return ESP_ERR_INVALID_ARG;
    // Names end up in MQTT topics: keep them simple.
    for (const char* p = h.name; *p; p++)
        if (*p == '/' || *p == '+' || *p == '#' || *p == ' ') return ESP_ERR_INVALID_ARG;

    LockGuard g(mu_);
    int i = findLocked(h.name);
    if (i < 0) {
        if (count_ >= kCapacity) return ESP_ERR_NO_MEM;
        i = static_cast<int>(count_++);
        hosts_[i] = WolHostState{};
    }
    hosts_[i].host = h;
    return saveLocked();
}

esp_err_t WolService::remove(const char* name)
{
    LockGuard g(mu_);
    int i = findLocked(name);
    if (i < 0) return ESP_ERR_NOT_FOUND;
    for (size_t j = static_cast<size_t>(i) + 1; j < count_; j++) hosts_[j - 1] = hosts_[j];
    count_--;
    return saveLocked();
}

size_t WolService::list(WolHostState* out, size_t max)
{
    LockGuard g(mu_);
    size_t n = count_ < max ? count_ : max;
    memcpy(out, hosts_, n * sizeof(WolHostState));
    return n;
}

esp_err_t WolService::wake(const char* name)
{
    uint8_t mac[6];
    {
        LockGuard g(mu_);
        int i = findLocked(name);
        if (i < 0) return ESP_ERR_NOT_FOUND;
        memcpy(mac, hosts_[i].host.mac, 6);
        hosts_[i].lastWake = uptimeSeconds();
    }
    ESP_LOGI(TAG, "waking %s", name);
    return wakeMac(mac);
}

esp_err_t WolService::wakeMac(const uint8_t mac[6])
{
    // Magic packet: 6 x 0xFF followed by the MAC 16 times.
    uint8_t pkt[102];
    memset(pkt, 0xFF, 6);
    for (int i = 0; i < 16; i++) memcpy(pkt + 6 + i * 6, mac, 6);

    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) return ESP_FAIL;
    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes));

    sockaddr_in to{};
    to.sin_family = AF_INET;
    to.sin_port = htons(kWolPort);

    int sent = 0;
    // Subnet-directed broadcast of the uplink network (reaches wired hosts
    // through the router's bridge), then the limited broadcast as a fallback.
    if (wifi_.connected()) {
        to.sin_addr.s_addr = wifi_.staIp() | ~wifi_.staNetmask();
        for (int r = 0; r < 3; r++)
            if (sendto(s, pkt, sizeof(pkt), 0, reinterpret_cast<sockaddr*>(&to), sizeof(to)) > 0)
                sent++;
    }
    to.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    if (sendto(s, pkt, sizeof(pkt), 0, reinterpret_cast<sockaddr*>(&to), sizeof(to)) > 0) sent++;
    close(s);
    return sent ? ESP_OK : ESP_FAIL;
}

bool WolService::ping(uint32_t ip)
{
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (s < 0) return false;
    timeval tv{1, 0};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    IcmpEcho req{};
    req.type = 8;  // echo request
    req.id = static_cast<uint16_t>(esp_random());
    req.seq = htons(1);
    memcpy(req.payload, "sinkhole", 8);
    req.checksum = inetChecksum(&req, sizeof(req));

    sockaddr_in to{};
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = ip;
    bool ok = false;
    if (sendto(s, &req, sizeof(req), 0, reinterpret_cast<sockaddr*>(&to), sizeof(to)) > 0) {
        uint8_t rx[64];
        for (int tries = 0; tries < 4 && !ok; tries++) {
            sockaddr_in from{};
            socklen_t fl = sizeof(from);
            int n = recvfrom(s, rx, sizeof(rx), 0, reinterpret_cast<sockaddr*>(&from), &fl);
            if (n <= 0) break;  // timeout
            if (from.sin_addr.s_addr != ip) continue;
            const size_t ihl = static_cast<size_t>(rx[0] & 0x0F) * 4;  // lwIP passes the IP header
            if (static_cast<size_t>(n) < ihl + sizeof(IcmpEcho)) continue;
            const auto* rep = reinterpret_cast<const IcmpEcho*>(rx + ihl);
            ok = rep->type == 0 && rep->id == req.id;
        }
    }
    close(s);
    return ok;
}

void WolService::taskEntry(void* arg)
{
    static_cast<WolService*>(arg)->run();
}

void WolService::run()
{
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(kProbeIntervalMs));
        if (!wifi_.connected()) continue;
        for (size_t i = 0; i < kCapacity; i++) {
            WolHost h;
            {
                LockGuard g(mu_);
                if (i >= count_) break;
                h = hosts_[i].host;
            }
            if (!h.ip) continue;
            const bool up = ping(h.ip);
            bool changed = false;
            {
                LockGuard g(mu_);
                int j = findLocked(h.name);
                if (j >= 0) {
                    changed = hosts_[j].online != up;
                    hosts_[j].online = up;
                }
            }
            if (changed && listener_) listener_(listenerCtx_, h.name, up);
        }
    }
}

}  // namespace sinkhole
