#include <array>
#include <cstring>

#include <cerrno>
#include <fcntl.h>

#include "esp_log.h"
#include "esp_random.h"
#include "lwip/sockets.h"
#include "sinkhole/text.hpp"
#include "sinkhole/wol.hpp"

namespace sinkhole {

namespace {
constexpr const char* TAG = "wol";
constexpr const char* kHostsKey = "wol_hosts2";   // WolHost with port
constexpr const char* kOldHostsKey = "wol_hosts";  // before ports: migrated at boot
struct OldWolHost {
    char name[32];
    uint8_t mac[6];
    uint32_t ip;
};
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
        // Older firmware (or an old backup restored) wrote hosts without a
        // port under the old key: convert them and drop the old entry.
        if (nvs::blobSize(kOldHostsKey)) {
            OldWolHost old[kCapacity];
            nvs::loadBlob(kOldHostsKey, old, sizeof(old), &n);
            const size_t m = n / sizeof(OldWolHost);
            for (size_t i = 0; i < m; i++) {
                stored[i] = WolHost{};
                memcpy(stored[i].name, old[i].name, sizeof(old[i].name));
                memcpy(stored[i].mac, old[i].mac, 6);
                stored[i].ip = old[i].ip;
            }
            nvs::saveBlob(kHostsKey, stored, m * sizeof(WolHost));
            nvs::eraseKey(kOldHostsKey);
            ESP_LOGI(TAG, "migrated %u hosts", static_cast<unsigned>(m));
        }
        n = 0;
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
    // Names end up in MQTT topics and Home Assistant JSON: keep them simple.
    for (const char* p = h.name; *p; p++)
        if (*p == '/' || *p == '+' || *p == '#' || *p == ' ' || *p == '"' || *p == '\\' || static_cast<uint8_t>(*p) < 0x20)
            return ESP_ERR_INVALID_ARG;

    if (watchOnly(h) && !h.ip) return ESP_ERR_INVALID_SIZE;  // nothing to wake or watch

    LockGuard g(mu_);
    int i = findLocked(h.name);
    const bool wasWatchOnly = i >= 0 && watchOnly(hosts_[i].host);
    if (i < 0) {
        if (count_ >= kCapacity) return ESP_ERR_NO_MEM;
        i = static_cast<int>(count_++);
        hosts_[i] = WolHostState{};
    } else if (hosts_[i].host.ip != h.ip || hosts_[i].host.port != h.port) {
        // Another address or check: its state starts over (no stale alert).
        hosts_[i].known = false;
        hosts_[i].online = false;
        hosts_[i].misses = 0;
    }
    hosts_[i].host = h;
    hosts_[i].host.reserved = 0;
    // The result topic tells MQTT apps a host can't be woken; an empty result
    // clears that once it has a MAC (see kWatchOnlyResult).
    if (watchOnly(h) && !wasWatchOnly) setResultLocked(i, kWatchOnlyResult);
    if (!watchOnly(h) && wasWatchOnly) setResultLocked(i, "");
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
        if (watchOnly(hosts_[i].host)) return ESP_ERR_NOT_SUPPORTED;
        memcpy(mac, hosts_[i].host.mac, 6);
        hosts_[i].lastWake = uptimeSeconds();
    }
    ESP_LOGI(TAG, "waking %s", name);
    return wakeMac(mac);
}

void WolService::setResultLocked(int i, const char* text)
{
    copyStr(hosts_[i].result, text);
    hosts_[i].resultAt = uptimeSeconds();
    hosts_[i].resultNew = true;
}

uint32_t WolService::timeoutOf(const WolHost& h)
{
    return h.timeout >= 30 && h.timeout <= 3600 ? h.timeout : kVerifySeconds;
}

esp_err_t WolService::cancel(const char* name)
{
    LockGuard g(mu_);
    const int i = findLocked(name);
    if (i < 0) return ESP_ERR_NOT_FOUND;
    if (!hosts_[i].waking) return ESP_ERR_INVALID_STATE;
    hosts_[i].waking = false;
    setResultLocked(i, "cancelled");
    ESP_LOGI(TAG, "wake of %s cancelled", name);
    return ESP_OK;
}

void WolService::reportResults()
{
    if (!resultListener_) return;
    for (size_t i = 0; i < kCapacity; i++) {
        WolHost h;
        std::array<char, sizeof(WolHostState::result)> text{};
        {
            LockGuard g(mu_);
            if (i >= count_) break;
            if (!hosts_[i].resultNew) continue;
            hosts_[i].resultNew = false;
            h = hosts_[i].host;
            copyStr(text.data(), text.size(), hosts_[i].result);
        }
        resultListener_(resultCtx_, h.name, text.data());
    }
}

esp_err_t WolService::wakeAndVerify(const char* name, bool* verifying)
{
    if (verifying) *verifying = false;
    WolHost h;
    {
        LockGuard g(mu_);
        const int i = findLocked(name);
        if (i < 0) return ESP_ERR_NOT_FOUND;
        if (watchOnly(hosts_[i].host)) return ESP_ERR_NOT_SUPPORTED;
        if (hosts_[i].waking) {  // already on it
            if (verifying) *verifying = true;
            return ESP_OK;
        }
        h = hosts_[i].host;
    }
    if (!h.ip) {  // nothing to verify against: just send
        const esp_err_t err = wake(name);
        LockGuard g(mu_);
        const int i = findLocked(name);
        if (i >= 0 && err == ESP_OK) setResultLocked(i, "magic packet sent");
        return err;
    }
    if (check(h) == Probe::Up || check(h) == Probe::Up) {  // one lost packet must not trigger a wake
        LockGuard g(mu_);
        const int i = findLocked(name);
        if (i >= 0) {
            hosts_[i].online = true;
            setResultLocked(i, "already online");
        }
        return ESP_ERR_INVALID_STATE;  // nothing sent: it is up
    }
    const esp_err_t err = wake(name);
    LockGuard g(mu_);
    const int i = findLocked(name);
    if (i >= 0 && err == ESP_OK) {
        if (verifying) *verifying = true;
        hosts_[i].waking = true;
        hosts_[i].wakeDeadline = uptimeSeconds() + timeoutOf(hosts_[i].host);
        setResultLocked(i, "waking");
    }
    return err;
}

// Non-blocking connect with a 1 s limit: Up when the port accepts.
WolService::Probe WolService::tcpOpen(uint32_t ip, uint16_t port)
{
    int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) return Probe::Unknown;  // out of sockets: not the host's fault
    fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK);
    sockaddr_in to{};
    to.sin_family = AF_INET;
    to.sin_port = htons(port);
    to.sin_addr.s_addr = ip;
    bool open = connect(s, reinterpret_cast<sockaddr*>(&to), sizeof(to)) == 0;
    const int connectErr = open ? 0 : errno;
    if (connectErr == ENOMEM || connectErr == ENOBUFS) {
        close(s);
        return Probe::Unknown;
    }
    if (connectErr == EINPROGRESS) {
        fd_set wr;
        FD_ZERO(&wr);
        FD_SET(s, &wr);
        timeval tv{1, 0};
        if (select(s + 1, nullptr, &wr, nullptr, &tv) > 0) {
            int err = 0;
            socklen_t len = sizeof(err);
            open = getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0;
        }
    }
    close(s);
    return open ? Probe::Up : Probe::Down;
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

WolService::Probe WolService::ping(uint32_t ip)
{
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (s < 0) return Probe::Unknown;  // out of sockets: not the host's fault
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
    const bool sent = sendto(s, &req, sizeof(req), 0, reinterpret_cast<sockaddr*>(&to), sizeof(to)) > 0;
    if (sent) {
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
    if (!sent) return Probe::Unknown;  // no buffer or no route: nothing was asked
    return ok ? Probe::Up : Probe::Down;
}

void WolService::taskEntry(void* arg)
{
    static_cast<WolService*>(arg)->run();
}

// Offline only after two failed checks in a row (a lost packet or a busy
// service must not flip the state). Known once it answers or misses twice;
// that first state is reported too (MQTT wants it) but is not a change.
// Returns true when the listener should hear about it.
bool WolService::updateStateLocked(int j, bool up, uint32_t now, WolHostChange& change)
{
    WolHostState& s = hosts_[j];
    if (up)
        s.misses = 0;
    else if (s.misses < 255)
        s.misses++;
    const bool online = up || (s.online && s.misses < 2);
    const bool first = !s.known && (up || s.misses >= 2);
    const bool changed = first || (s.known && s.online != online);
    if (changed) {
        change.first = first;
        change.prevFor = first ? 0 : now - s.stateSince;
        s.stateSince = now;
        s.known = true;
    }
    s.online = online;
    change.online = online;
    return changed;
}

// A host being woken: done when it answers, or when its wait runs out.
void WolService::updateWakeLocked(int j, bool up, uint32_t now, uint32_t since)
{
    WolHostState& s = hosts_[j];
    if (!s.waking) return;
    std::array<char, 48> text{};
    if (up) {
        snprintf(text.data(), text.size(), "online after %u s", static_cast<unsigned>(now - since));
    } else if (now >= s.wakeDeadline) {
        const uint32_t waited = timeoutOf(s.host);
        if (waited % 60 == 0)
            snprintf(text.data(), text.size(), "no answer after %u min", static_cast<unsigned>(waited / 60));
        else
            snprintf(text.data(), text.size(), "no answer after %u s", static_cast<unsigned>(waited));
    } else {
        return;
    }
    s.waking = false;
    setResultLocked(j, text.data());
}

// Every host with an IP is checked every kProbeIntervalMs; a host being
// woken is checked every 3 s until it answers or its deadline passes.
void WolService::run()
{
    uint32_t tick = 0;
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        tick++;
        reportResults();
        if (!wifi_.connected()) continue;
        const bool routine = tick % (kProbeIntervalMs / 1000) == 0;
        for (size_t i = 0; i < kCapacity; i++) {
            WolHost h;
            bool waking;
            uint32_t since = 0;
            {
                LockGuard g(mu_);
                if (i >= count_) break;
                h = hosts_[i].host;
                waking = hosts_[i].waking;
                since = hosts_[i].lastWake;
            }
            if (!h.ip || !(routine || (waking && tick % 3 == 0))) continue;
            const uint32_t now = uptimeSeconds();
            const uint32_t age = now - since;
            // Resend at 20 s and 60 s, then every 2 minutes for long waits.
            const bool resend = (age >= 20 && age < 23) || (age >= 60 && age < 63) || (age >= 180 && (age - 60) % 120 < 3);
            if (waking && resend) {
                uint8_t mac[6];
                memcpy(mac, h.mac, 6);
                wakeMac(mac);  // some network cards miss the first packets
            }
            const Probe probe = check(h);
            const bool up = probe == Probe::Up;
            bool changed = false;
            WolHostChange change{h.name, up, false, (h.flags & kWolAlert) != 0, 0};
            {
                LockGuard g(mu_);
                const int j = findLocked(h.name);  // the list may have changed meanwhile
                if (j >= 0 && probe != Probe::Unknown) changed = updateStateLocked(j, up, now, change);
                if (j >= 0) updateWakeLocked(j, up, now, since);
            }
            if (changed && listener_) listener_(listenerCtx_, change);
        }
    }
}

}  // namespace sinkhole
