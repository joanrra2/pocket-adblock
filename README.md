# Pocket AdBlock

[![build](https://github.com/joanrra2/pocket-adblock/actions/workflows/build.yml/badge.svg)](https://github.com/joanrra2/pocket-adblock/actions/workflows/build.yml)
[![ESP-IDF v6.1](https://img.shields.io/badge/ESP--IDF-v6.1-blue)](https://github.com/espressif/esp-idf/releases/tag/v6.1)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-support%20this%20project-ff5e5b?logo=ko-fi&logoColor=white)](https://ko-fi.com/joanramon)

A Pi-hole-style **DNS ad-blocker and Wake-on-LAN node** for a few-dollar ESP32,
written in plain **ESP-IDF v6.1** (no Arduino). It runs on a $2 ESP32-C3 with no
PSRAM, and takes advantage of PSRAM when the board has it.

- **~218k domains on a 4 MB C3, ~830k on 8 MB+** stored as compact 40-bit hashes in flash,
  memory-mapped and binary-searched. No file system, no RAM index.
- **Non-blocking DNS forwarding**: one slow upstream lookup never stalls other clients.
- **Hidden trackers caught (CNAME cloaking)**: a site's own subdomain that is an alias of
  a blocked tracker (`smetrics.ikea.com` → `…2o7.net`) is blocked too, also for cached answers.
- **Bypass protection**: Firefox's automatic DNS-over-HTTPS and iCloud Private Relay are
  told to stand down; optionally, well-known encrypted-DNS servers are blocked.
- **DNS answer cache** (4096 entries in PSRAM on boards that have it, 32 in internal RAM otherwise).
  Answers with TTL 0 or a few seconds (some resolvers, Quad9 at times, send them) are still
  cached for 30 s, while clients see the upstream's own TTL
  (`SINKHOLE_DNS_CACHE_MIN_TTL`, 0 turns this off).
- **A/B blocklist slots**: updates go to the inactive slot and are verified
  (SHA-256, size, sort order) before going live. A bad download never replaces a working list.
- **OTA for firmware and blocklists** from the web UI, with automatic rollback if new
  firmware doesn't come up healthy.
- **Never unreachable**: a WPA2 setup access point with a captive portal comes up whenever
  the uplink Wi-Fi isn't set or can't be reached; the uplink is retried forever.
- **Wake-on-LAN** for your PCs, with online status, plus **remote wake over MQTT**
  (outbound connection only, no port forwarding). Wake a PC, then connect with AnyDesk, RustDesk, RDP and so on.
- **Static memory**: tasks, stacks and tables are fixed-size members; nothing is allocated after boot.

> Built on the hash-in-flash idea from
> [M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock), whose weekly
> blocklist this firmware can use directly. This is an independent ESP-IDF rewrite,
> not an official port.

## Hardware

| Board | Status | Notes |
|---|---|---|
| ESP32-S3 with octal flash + PSRAM (WROOM-2 N16R8V / N32R16V) | tested | use the `esp32s3-octal-flash` profile, 8 MB layout |
| ESP32-S3 (quad flash, with or without PSRAM) | builds in CI | PSRAM used when present |
| ESP32-C3 (SuperMini etc., 4 MB, no PSRAM) | builds in CI | the original $2 target |
| ESP32 (classic), ESP32-C6 | builds in CI | |

Power it from a stable USB supply. Many routers have a spare USB port that is enough.

## Install from the browser

Open the **[web installer](https://joanrra2.github.io/pocket-adblock/)** in Chrome or Edge,
pick your board and press *Connect and install*. No toolchain needed.

## Build & flash

Requires [ESP-IDF v6.1](https://docs.espressif.com/projects/esp-idf/en/v6.1/).

```bash
# ESP32-C3 / generic S3 / ESP32 (4 MB layout)
idf.py set-target esp32c3
idf.py build flash monitor
```

```bash
# ESP32-S3 with octal flash (e.g. N32R16V): its own build dir + profile
idf.py -B build-s3 -D SDKCONFIG=build-s3/sdkconfig \
  -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;boards/esp32s3-octal-flash.defaults" \
  set-target esp32s3 build flash monitor
```

### Build options (`idf.py menuconfig` → DNS Sinkhole)

Features that cost extra RAM are compile-time options, off by default. Board
profiles in `boards/` turn on what suits that hardware.

| Option | Default | RAM | Recommended for |
|---|---|---|---|
| `SINKHOLE_QUERY_HISTORY_EXTENDED` (+ `_ENTRIES`, 2048) | off (32 queries) | 76 B per entry, PSRAM | boards with PSRAM (on in the octal S3 profile, 4096) |
| `SINKHOLE_BLOOM_FILTER` (+ `_BITS_PER_ENTRY`, 10) | off | ~1.25 B per slot entry: ~270 KB (4 MB layout), ~1 MB (8 MB layout) | boards with PSRAM; not the C3 (it needs that RAM for HTTPS). On an S3: not-listed lookups 80.8 → 54.7 µs |

Prebuilt images for every board are attached to each
[release](../../releases): flash `*-full.bin` at `0x0` the first time.

> **Windows:** keep the project in a short path such as `C:\src\pocket-adblock`.
> Managed components have deep paths and fail past Windows' 260-character limit.

## First setup

1. Join the Wi-Fi **`Sinkhole-XXXX`** (password `sinkhole-setup`). Phones show
   "Sign in to network" and open the setup page by themselves (captive portal);
   otherwise open **http://192.168.4.1**. Log in as `admin` / `sinkhole`.
2. **Settings → Your Wi-Fi:** enter your network. Once it connects, the page shows the
   device's new address and the setup AP switches off 30 s later.
3. Change the admin password and the setup AP password (Settings). A banner reminds
   you while the default admin password is still set.
4. Point your router's DHCP DNS, or individual devices, at the device's address
   (also reachable as **http://sinkhole.local**).

### Make sure nothing bypasses it (IPv6!)

Devices use whatever DNS servers the network hands them, and they hand out **two**
kinds: IPv4 (DHCP) and IPv6 (router advertisements / DHCPv6). If your router
advertises its own or your ISP's IPv6 DNS, phones and PCs quietly use that one and
ads come back, even though the IPv4 DNS points here. Pick one:

- In the router, set the advertised IPv6 DNS (RDNSS/DHCPv6) to this device: it answers
  DNS over IPv6 too, at the addresses listed under *Network* on the overview, or
- turn off IPv6 DNS advertisement / IPv6 on the LAN if you don't need it.

When the network routes IPv6 (the device gets a global address by SLAAC) the
overview shows a reminder about this.

Browsers and phones can also skip local DNS with their own encrypted DNS.
*Settings → Bypass protection* handles the automatic cases:

- **Tell browsers and phones to use this DNS** (on by default) answers the official
  canary domains with NXDOMAIN: Firefox then turns off its automatic DNS-over-HTTPS
  (`use-application-dns.net`) and Apple devices turn off iCloud Private Relay
  (`mask.icloud.com`). Chrome and Edge only upgrade to encrypted DNS when the system
  resolver supports it, which this one doesn't.
- **Block known encrypted-DNS servers** (off by default) also blocks the names of
  well-known DNS-over-HTTPS/TLS servers (Google, Cloudflare, Quad9, NextDNS, AdGuard…),
  for apps and browsers set to one by hand. A phone with *Private DNS* set to one of
  them loses Internet until it is set back to *Automatic* or *Off*. Domains on the
  allow list still pass.

Both pause together with blocking. A browser set by hand to an encrypted-DNS server
by IP address can't be stopped by DNS: set it to "use the system's DNS" / off.

### Wi-Fi behaviour and recovery

| Situation | What happens |
|---|---|
| No uplink configured | Setup AP on, captive portal |
| Uplink not found / wrong password / lost | Setup AP comes back on; the uplink is retried forever (1 s → 60 s backoff, every 60 s while someone is on the setup AP); the reason is shown in the UI |
| Uplink connected | Setup AP off after 30 s (or always on, if you choose so in Settings) |
| Hold **BOOT** 3 s | Setup AP on for 15 minutes, e.g. if you forgot the device's address |
| Hold **BOOT** 10 s | Factory reset: settings erased (the blocklist is kept) |

Settings also has **Reconnect now** and **Forget** for the uplink.

By default the blocklist auto-updates every 24 h from esp32-c3-adblock's weekly
release. You can change the URL, or upload your own list, under **Updates**.

### Local names

*Settings → Local names* gives devices on your network a name and can hand whole
suffixes to another DNS server:

- **Name → address**: `nas.home → 192.168.1.10`. Answered locally (TTL 60 s); exact
  name only. Also overrides blocking for that one name.
- **Suffix → DNS server**: `lan → 192.168.1.1` sends `lan` and everything under it to
  your router, so the names it knows from DHCP work. `in-addr.arpa → router` does the
  same for reverse lookups (IP → name). Longest suffix wins; never blocked.

24 entries by default (`SINKHOLE_MAX_LOCAL_RECORDS`, 56 bytes each).

## Blocklists

```bash
python3 tools/build_blocklist.py blocklist.bin                # default sources
python3 tools/build_blocklist.py big.bin URL_OR_FILE ...      # hosts / domains / ||adblock^
```

Lists get a 64-byte header with the domain count and a SHA-256, which the device
verifies before activating. The default **compact format (v2)** stores 3 bytes per
domain plus a 65 KB index, so slots hold more and lookups are faster:

| Same 138,896 domains | v1 (`--v1`) | v2 (default) |
|---|---|---|
| File size | 694 KB | 483 KB (-31%) |
| 4 MB / 8 MB layout capacity | 144k / 511k | 218k / 830k |
| Filter time per query (ESP32-S3) | 81 µs | 59 µs |

Raw headerless lists from esp32-c3-adblock (`--raw`) and v1 lists are still accepted.
Blocking a domain also blocks its subdomains. The **Always allow** list wins over every blocklist.

## Wake-on-LAN

Add a host under **Wake-on-LAN** (name, MAC, optional IP for the online indicator)
and press **Wake**. The PC needs wired Ethernet with WoL enabled in BIOS/UEFI and on
its network adapter.

**From anywhere:** set an MQTT broker in Settings (TLS recommended, e.g. a free
HiveMQ Cloud or your Home Assistant's Mosquitto). Then:

| Topic | Direction | Payload |
|---|---|---|
| `sinkhole/wol/<name>/set` | you → device | anything: wakes `<name>` |
| `sinkhole/wol/<name>/state` | device → you | `online` / `offline` (retained) |
| `sinkhole/status` | device → you | `online` / `offline` (LWT, retained) |
| `sinkhole/blocking/set` | you → device | `ON` / `OFF` |
| `sinkhole/blocking` | device → you | `ON` / `OFF` (retained, on every change) |
| `sinkhole/stats` | device → you | `{"blocked","allowed","percent","domains","clients"}` every 60 s |

```bash
mosquitto_pub -h broker -p 8883 -u user -P pass -t sinkhole/wol/office-pc/set -m wake
```

### Home Assistant

With **Show in Home Assistant** ticked (default) and the broker your Home Assistant
uses, a *Pocket AdBlock* device appears by itself (MQTT discovery): a **Blocking**
switch, sensors for blocked / allowed queries, blocked share, blocklist size and
active clients, and for every Wake-on-LAN host a **Wake** button plus an **online**
sensor (hosts with an IP). Adding or removing hosts updates Home Assistant within
a few seconds. MQTT changes apply after a restart.

## Updates

- **Firmware:** upload `build/pocket-adblock.bin` (or a release's `*-ota.bin`) under
  **Updates**. The new image stays on probation for 60 s and the bootloader rolls back if it crashes first.
- **Blocklist:** **Download now**, upload a `.bin`, or let the schedule run.

### Online updates and signing

Release firmware checks `manifest.json` from the latest GitHub release once a day
(*Updates → Online updates*) and offers **Install**.

| What | How | Effect |
|---|---|---|
| Signed blocklists | `tools/keys.py blocklist-key keys/bl.pem`, put the printed `CONFIG_SINKHOLE_BLOCKLIST_PUBKEY` line in your sdkconfig, build lists with `--sign=keys/bl.pem` | signed lists are verified (ECDSA P-256); with `SINKHOLE_BLOCKLIST_REQUIRE_SIGNED` unsigned/raw lists are refused |
| Signed firmware | `tools/keys.py firmware-key keys/firmware_signing.pem`, add `boards/signed-firmware.defaults` | OTA only accepts images signed with that key (RSA-3072); unlocks automatic install |
| Automatic install | *Install updates automatically* (signed builds only) | new releases install themselves, with the usual 60 s health probation and rollback |

No eFuses are burned: a board can always be re-flashed over USB. In CI, the
`FIRMWARE_SIGNING_KEY` and `BLOCKLIST_SIGNING_KEY` secrets (and the
`BLOCKLIST_PUBKEY` variable) turn signing on for releases and the weekly list.

## Security

Plain HTTP on the LAN, the same trust model as the original project. Every API call
needs HTTP Basic auth, and every change also needs an `X-Requested-With` header, which
blocks CSRF via cached credentials. Change the default passwords. The setup AP uses WPA2.

## Benchmark vs esp32-c3-adblock

Same ESP32-S3 board (WROOM-2 N32R16V), same 138,896-domain list, same Wi-Fi, measured
from a wired PC with `tools/dns_bench.py`. The original (Arduino, commit at the time of
writing) was built for the S3 with an added PlatformIO env; ours is the default build
(no bloom filter).

| | esp32-c3-adblock | pocket-adblock |
|---|---|---|
| Blocked query, p50 / p99 | 5.05 / 10.96 ms | **1.87 / 5.90 ms** |
| Same allowed name again, p50 | 18.99 ms (forwarded every time) | **1.87 ms** (answer cache) |
| Throughput, 16 parallel clients | 347 queries/s | **697 queries/s** |
| Blocked queries while uncached names wait on the upstream, p50 / max | 47 / 315 ms (stuck behind each lookup) | **1.9 / 5.9 ms** |
| Firmware image | 1,222,688 B | **1,021,808 B** |
| Free internal heap at runtime | 210 KB | 198 KB (+ cache and history in PSRAM) |

## Architecture

```
main/main.cpp            app_main(): static App app; app.start();
components/
  core/       Config (NVS settings), static RTOS wrappers, PSRAM-aware table allocation
  blocklist/  A/B flash store (mmap), custom block/allow lists, domain filter
  dns/        DNS server (select loop, pending table), answer cache, packet helpers
  net/        Wi-Fi AP+STA manager, mDNS
  update/     firmware OTA, blocklist downloader
  web/        HTTP API + embedded gzipped UI (www/index.html)
  wol/        Wake-on-LAN, ICMP probe, MQTT bridge
  stats/      clients, ban list, recent queries
  app/        wires everything together
tools/        blocklist builder
test/host/    host unit tests (g++, no IDF)
```

Latency notes: Wi-Fi power save is disabled (modem sleep can add ~100 ms per reply),
the CPU runs at full clock, and only the DNS cache lives in PSRAM. Wi-Fi, lwIP and TLS
buffers stay in internal RAM.

## Support

If this is useful to you, you can support development on
[Ko-fi](https://ko-fi.com/joanramon) ☕

## License

MIT, see [LICENSE](LICENSE). Third-party credits: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
