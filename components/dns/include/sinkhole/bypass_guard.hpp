#pragma once
// Keeps devices from routing DNS around the sinkhole. Header-only (host tests).
//
// Canary domains are the official "this network filters DNS" signals:
//   use-application-dns.net   Firefox turns its automatic DNS-over-HTTPS off
//   mask.icloud.com, -h2      Apple turns iCloud Private Relay off
// Both expect NXDOMAIN. Safe to leave on: only those clients ask for them.
//
// The optional encrypted-DNS list blocks well-known DoH/DoT resolver names, so
// a browser or app configured to use one by name can't look it up. Off by
// default: a phone with "Private DNS" set to such a hostname loses Internet
// until it is set back to Automatic/Off. Names on the allow list still pass.

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace sinkhole::guard {

enum : uint8_t { kCanary = 1, kEncryptedDns = 2 };
enum class Hit : uint8_t { None, Canary, EncryptedDns };

constexpr const char* kCanaryNames[] = {
    "use-application-dns.net",
    "mask.icloud.com",
    "mask-h2.icloud.com",
};

// Hostnames only used as DoH/DoT endpoints (subdomains match too).
constexpr const char* kEncryptedDnsNames[] = {
    "dns.google",            "dns.google.com",          "dns64.dns.google",
    "cloudflare-dns.com",    "one.one.one.one",         "dns.quad9.net",
    "dns9.quad9.net",        "dns10.quad9.net",         "dns11.quad9.net",
    "dns12.quad9.net",       "doh.opendns.com",         "dns.nextdns.io",
    "doh.cleanbrowsing.org", "dns.adguard-dns.com",     "dns.adguard.com",
    "doh.mullvad.net",       "dns.mullvad.net",         "doh.dns.sb",
    "dns.alidns.com",        "doh.pub",                 "dns.controld.com",
    "freedns.controld.com",  "doh.libredns.gr",         "dns0.eu",
    "dns.twnic.tw",
};

// name equals entry, or ends with "." + entry.
inline bool matches(const char* name, size_t len, const char* entry)
{
    const size_t n = strlen(entry);
    if (len < n) return false;
    if (memcmp(name + len - n, entry, n) != 0) return false;
    return len == n || name[len - n - 1] == '.';
}

// name: lower-case, no trailing dot (as parsed by dns::parseQuery).
inline Hit check(const char* name, size_t len, uint8_t flags)
{
    if (flags & kCanary)
        for (const char* e : kCanaryNames)
            if (matches(name, len, e)) return Hit::Canary;
    if (flags & kEncryptedDns)
        for (const char* e : kEncryptedDnsNames)
            if (matches(name, len, e)) return Hit::EncryptedDns;
    return Hit::None;
}

}  // namespace sinkhole::guard
