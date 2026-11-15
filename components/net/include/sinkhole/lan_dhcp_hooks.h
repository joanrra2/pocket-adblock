#pragma once
// lwIP DHCP server hooks (C). Compiled into the lwip component through
// ESP_IDF_LWIP_HOOK_FILENAME (see components/net/CMakeLists.txt), so LanDhcp
// can count what the server receives and answers on the home network. Both
// run in the lwIP thread; the definitions are in lan_dhcp.cpp.

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct netif;

// After a request is parsed: msg = the raw DHCP message (len bytes, zero
// padded), state = the reply lwIP decided on. Returns state unchanged.
int16_t sinkhole_dhcps_post_state(const void* msg, uint16_t len, int16_t state);
// While a reply (OFFER / ACK / NAK) is being built for a netif.
void sinkhole_dhcps_reply(const struct netif* netif, uint8_t type);

#ifdef __cplusplus
}
#endif

#define LWIP_HOOK_DHCPS_POST_STATE(msg, len, state) sinkhole_dhcps_post_state((msg), (len), (state))
// Used by dhcpserver.c as a statement without a trailing semicolon.
#define LWIP_HOOK_DHCPS_POST_APPEND_OPTS(netif, dhcps, type, pp_opts) sinkhole_dhcps_reply((netif), (type));
