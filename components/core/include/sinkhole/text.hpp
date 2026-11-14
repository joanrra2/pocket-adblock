#pragma once
// Small string helpers that work on fixed buffers.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace sinkhole {

// strncpy that always terminates. Returns false if the source was truncated.
inline bool copyStr(char* dst, size_t dstLen, const char* src)
{
    if (dstLen == 0) return false;
    size_t n = src ? strnlen(src, dstLen) : 0;
    bool fits = n < dstLen;
    if (!fits) n = dstLen - 1;
    if (n) memcpy(dst, src, n);
    dst[n] = '\0';
    return fits;
}

template <size_t N>
inline bool copyStr(char (&dst)[N], const char* src)
{
    return copyStr(dst, N, src);
}

// In-place decoding of application/x-www-form-urlencoded values.
inline void urlDecode(char* s)
{
    auto hex = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    char* out = s;
    for (char* in = s; *in; ++in) {
        if (*in == '+') {
            *out++ = ' ';
        } else if (*in == '%' && hex(in[1]) >= 0 && hex(in[2]) >= 0) {
            *out++ = static_cast<char>(hex(in[1]) << 4 | hex(in[2]));
            in += 2;
        } else {
            *out++ = *in;
        }
    }
    *out = '\0';
}

// "aa:bb:cc:dd:ee:ff" or "aa-bb-..." -> 6 bytes.
inline bool parseMac(const char* s, uint8_t mac[6])
{
    unsigned v[6];
    char sep1 = 0;
    if (sscanf(s, "%2x%c%2x%*c%2x%*c%2x%*c%2x%*c%2x", &v[0], &sep1, &v[1], &v[2], &v[3], &v[4],
               &v[5]) != 7)
        return false;
    for (int i = 0; i < 6; i++) mac[i] = static_cast<uint8_t>(v[i]);
    return true;
}

inline void formatMac(const uint8_t mac[6], char out[18])
{
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4],
             mac[5]);
}

// IPv4 in network byte order (as stored by lwIP) <-> dotted string.
bool parseIp4(const char* s, uint32_t& out);
void formatIp4(uint32_t ip, char out[16]);

}  // namespace sinkhole
