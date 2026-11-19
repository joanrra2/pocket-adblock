#include "sinkhole/lan_dhcp.hpp"

#include <cstring>
#include <initializer_list>

#include "dhcpserver/dhcpserver.h"
#include "dhcpserver/dhcpserver_options.h"
#include "esp_log.h"
#include "esp_netif_net_stack.h"
#include "lwip/def.h"
#include "lwip/ip.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "sinkhole/lan_dhcp_hooks.h"
#include "sinkhole/text.hpp"

namespace sinkhole {

#define LAN_DHCP_STR2(x) #x
#define LAN_DHCP_STR(x) LAN_DHCP_STR2(x)

namespace {
constexpr const char* TAG = "lan-dhcp";

// Shared with the lwIP hooks below (one server per device).
struct Diag {
    std::atomic<const struct netif*> served{nullptr};  // set while running
    std::atomic<uint32_t> discovers{0}, requests{0}, others{0};
    std::atomic<uint32_t> offers{0}, acks{0}, naks{0};
    std::atomic<uint32_t> leases{0}, lastIp{0};
};
Diag g;

// DHCP message types (RFC 2132 option 53) and lwIP's parse results.
constexpr uint8_t kDiscover = 1, kOffer = 2, kRequest = 3, kAck = 5, kNak = 6;
const char* stateName(int16_t s)
{
    switch (s) {
        case 1: return "offer";
        case 2: return "declined";
        case 3: return "ack";
        case 4: return "nak";
        case 6: return "released";
        case 7: return "ack (inform)";
        default: return "ignored";
    }
}

void onLease(void*, uint8_t ip[4], uint8_t mac[6])
{
    uint32_t a;
    memcpy(&a, ip, 4);
    g.lastIp = a;
    g.leases++;
    char ipText[16];
    formatIp4(a, ipText);
    ESP_LOGI(TAG, "lease %s -> %02x:%02x:%02x:%02x:%02x:%02x", ipText, mac[0], mac[1], mac[2], mac[3], mac[4],
             mac[5]);
}
}  // namespace

const char* LanDhcp::checkPool(const Options& o)
{
    const uint32_t ip = ntohl(o.ip), mask = ntohl(o.mask), gw = ntohl(o.gw);
    const uint32_t first = ntohl(o.first), last = ntohl(o.last);
    if (mask == 0 || ((~mask + 1) & ~mask) != 0 || ~mask < 3) return "this device's netmask can't hold a pool";
    const uint32_t net = ip & mask, bcast = net | ~mask;
    if ((first & mask) != net || (last & mask) != net) return "pool must be in this device's network";
    if (first > last) return "first address must not be after the last one";
    if (first == net || last == bcast) return "pool must not include the network or broadcast address";
    // lwIP compares pool addresses as raw network-order words, which only
    // orders correctly while they differ in the last byte alone.
    if ((first >> 8) != (last >> 8)) return "pool must stay within one x.x.x.0-255 block";
    if (last - first + 1 > kMaxPool) return "pool too large: at most " LAN_DHCP_STR(CONFIG_LWIP_DHCPS_MAX_STATION_NUM) " addresses";
    for (uint32_t x : {ip, gw})
        if (x >= first && x <= last) return "pool must not include this device or the router";
    return nullptr;
}

// Runs in the lwIP thread (dhcps creates a UDP pcb bound to the netif).
esp_err_t LanDhcp::startInLwip(void* ctx)
{
    auto* self = static_cast<LanDhcp*>(ctx);
    auto* nif = static_cast<struct netif*>(esp_netif_get_netif_impl(self->netif_));
    if (!nif) return ESP_ERR_INVALID_STATE;
    auto* d = static_cast<dhcps_t*>(self->dhcps_);
    const uint8_t idx = netif_get_index(nif);
    const struct netif* served = g.served.load();
    self->restarted_ = false;
    if (d && served == nif && idx == self->servedIdx_ && self->opt_ == self->want_) return ESP_OK;

    if (!d) {
        d = dhcps_new();
        if (!d) return ESP_ERR_NO_MEM;
        self->dhcps_ = d;
    }
    // A second dhcps_start without a stop would arm a second lease timer.
    if (served) dhcps_stop(d, const_cast<struct netif*>(served));
    g.served = nullptr;

    const Options& o = self->want_;
    ip4_addr_t mask;
    mask.addr = o.mask;
    dhcps_set_option_info(d, SUBNET_MASK, &mask, sizeof(mask));
    dhcps_lease_t pool{};
    pool.enable = true;
    pool.start_ip.addr = o.first;
    pool.end_ip.addr = o.last;
    dhcps_set_option_info(d, REQUESTED_IP_ADDRESS, &pool, sizeof(pool));
    dhcps_time_t lease = o.leaseMinutes;  // DHCPS_LEASE_UNIT is 60 s
    dhcps_set_option_info(d, IP_ADDRESS_LEASE_TIME, &lease, sizeof(lease));
    dhcps_offer_t router = OFFER_ROUTER;  // the netif's gateway: the real router
    dhcps_set_option_info(d, ROUTER_SOLICITATION_ADDRESS, &router, sizeof(router));
    dhcps_offer_t dns = OFFER_DNS;
    dhcps_set_option_info(d, DOMAIN_NAME_SERVER, &dns, sizeof(dns));
    ip_addr_t self4 = IPADDR4_INIT(o.ip);
    dhcps_dns_setserver(d, &self4);
    dhcps_set_new_lease_cb(d, &onLease, self);
    ip4_addr_t ip;
    ip.addr = o.ip;
    if (dhcps_start(d, nif, ip) != ERR_OK) return ESP_FAIL;
    self->opt_ = o;
    self->servedIdx_ = idx;
    self->restarted_ = true;
    g.served = nif;
    return ESP_OK;
}

esp_err_t LanDhcp::stopInLwip(void* ctx)
{
    auto* self = static_cast<LanDhcp*>(ctx);
    auto* d = static_cast<dhcps_t*>(self->dhcps_);
    const struct netif* served = g.served.load();
    g.served = nullptr;
    if (d && served) dhcps_stop(d, const_cast<struct netif*>(served));
    return ESP_OK;
}

namespace {
struct HostQuery {
    dhcps_t* dhcps;
    const uint8_t* mac;
    char* out;
    size_t cap;
    bool found;
};

esp_err_t hostInLwip(void* ctx)  // NOSONAR signature required by esp_netif_tcpip_exec
{
    auto* q = static_cast<HostQuery*>(ctx);
    q->found = q->dhcps && dhcps_get_hostname_on_mac(q->dhcps, q->mac, q->out, q->cap);
    return ESP_OK;
}
}  // namespace

bool LanDhcp::hostname(const uint8_t* mac, char* out, size_t cap)
{
    if (!running_ || !cap) return false;
    out[0] = '\0';
    LockGuard lock(mu_);
    HostQuery q{static_cast<dhcps_t*>(dhcps_), mac, out, cap, false};
    esp_netif_tcpip_exec(&hostInLwip, &q);  // the lease list belongs to the lwIP thread
    return q.found && out[0];
}

esp_err_t LanDhcp::start(esp_netif_t* sta, const Options& o)
{
    LockGuard lock(mu_);
    if (const char* why = checkPool(o)) {
        ESP_LOGE(TAG, "not starting: %s", why);
        if (running_) esp_netif_tcpip_exec(&LanDhcp::stopInLwip, this);
        running_ = false;
        return ESP_ERR_INVALID_ARG;
    }
    netif_ = sta;
    want_ = o;
    const esp_err_t err = esp_netif_tcpip_exec(&LanDhcp::startInLwip, this);
    running_ = err == ESP_OK;
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "DHCP server failed to start: %s", esp_err_to_name(err));
    } else if (restarted_) {
        char a[16], b[16];
        formatIp4(o.first, a);
        formatIp4(o.last, b);
        ESP_LOGI(TAG, "DHCP server on, pool %s - %s, lease %u min", a, b, o.leaseMinutes);
    }
    return err;
}

void LanDhcp::stop()
{
    LockGuard lock(mu_);
    if (!running_) return;
    esp_netif_tcpip_exec(&LanDhcp::stopInLwip, this);
    running_ = false;
    ESP_LOGI(TAG, "DHCP server off");
}

LanDhcp::Stats LanDhcp::stats()
{
    return {g.discovers, g.requests, g.others, g.offers, g.acks, g.naks, g.leases, g.lastIp};
}

}  // namespace sinkhole

using sinkhole::g;

// lwIP hooks (see lan_dhcp_hooks.h). Both servers (setup AP and home network)
// call them; only packets on the served netif count.
extern "C" int16_t sinkhole_dhcps_post_state(const void* msg, uint16_t len, int16_t state)
{
    const struct netif* served = g.served.load();
    if (!served || ip_current_input_netif() != served) return state;
    const auto* m = static_cast<const uint8_t*>(msg);
    uint8_t type = 0;
    for (uint16_t i = 240; i + 1 < len && m[i] != 255;) {  // options after the magic cookie
        if (m[i] == 0) {
            i++;
            continue;
        }
        if (m[i] == 53 && m[i + 1] >= 1 && i + 2 < len) {
            type = m[i + 2];
            break;
        }
        i += 2 + m[i + 1];
    }
    if (type == sinkhole::kDiscover)
        g.discovers++;
    else if (type == sinkhole::kRequest)
        g.requests++;
    else
        g.others++;
    const uint8_t* mac = m + 28;  // chaddr
    ESP_LOGI(sinkhole::TAG, "DHCP type %u from %02x:%02x:%02x:%02x:%02x:%02x -> %s", type, mac[0], mac[1], mac[2],
             mac[3], mac[4], mac[5], sinkhole::stateName(state));
    return state;
}

extern "C" void sinkhole_dhcps_reply(const struct netif* netif, uint8_t type)
{
    if (!netif || netif != g.served.load()) return;
    if (type == sinkhole::kOffer)
        g.offers++;
    else if (type == sinkhole::kAck)
        g.acks++;
    else if (type == sinkhole::kNak)
        g.naks++;
}
