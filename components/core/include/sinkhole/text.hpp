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
// Base64 (RFC 4648) for settings backups. encode: out needs 4*ceil(n/3)+1.
inline size_t base64Encode(const uint8_t* in, size_t n, char* out)
{
    static constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        const uint32_t v = static_cast<uint32_t>(in[i]) << 16 | (i + 1 < n ? in[i + 1] << 8 : 0) | (i + 2 < n ? in[i + 2] : 0);
        out[o++] = kAlphabet[v >> 18 & 63];
        out[o++] = kAlphabet[v >> 12 & 63];
        out[o++] = i + 1 < n ? kAlphabet[v >> 6 & 63] : '=';
        out[o++] = i + 2 < n ? kAlphabet[v & 63] : '=';
    }
    out[o] = '\0';
    return o;
}

// Decodes in place-safe into out (cap bytes); returns the length or -1.
inline int base64Decode(const char* in, size_t n, uint8_t* out, size_t cap)
{
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    if (n % 4) return -1;
    size_t o = 0;
    for (size_t i = 0; i < n; i += 4) {
        int v[4];
        for (int k = 0; k < 4; k++) v[k] = in[i + k] == '=' ? 0 : val(in[i + k]);
        if (v[0] < 0 || v[1] < 0 || v[2] < 0 || v[3] < 0) return -1;
        const uint32_t w = static_cast<uint32_t>(v[0]) << 18 | v[1] << 12 | v[2] << 6 | v[3];
        const int bytes = in[i + 2] == '=' ? 1 : in[i + 3] == '=' ? 2 : 3;
        if (o + bytes > cap) return -1;
        out[o++] = static_cast<uint8_t>(w >> 16);
        if (bytes > 1) out[o++] = static_cast<uint8_t>(w >> 8);
        if (bytes > 2) out[o++] = static_cast<uint8_t>(w);
    }
    return static_cast<int>(o);
}

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
