#pragma once
// DNS wire-format helpers. Pure functions on caller-owned buffers, header-only
// so they can be unit tested on the host (test/host).

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace sinkhole::dns {

constexpr size_t kHeaderLen = 12;
constexpr uint16_t kTypeA = 1;
constexpr uint16_t kTypeAAAA = 28;
constexpr uint32_t kBlockedTtl = 300;

struct Question {
    char name[254];      // lower-case, dotted, "www." stripped
    size_t nameLen;
    uint16_t qtype;
    size_t end;          // offset just past QTYPE/QCLASS
};

inline uint16_t rd16(const uint8_t* p) { return static_cast<uint16_t>(p[0] << 8 | p[1]); }
inline void wr16(uint8_t* p, uint16_t v)
{
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v);
}

// Parses the first question of a standard query. False for anything we
// should not answer from here (responses, compressed names, truncated input).
inline bool parseQuery(const uint8_t* pkt, size_t len, Question& q)
{
    if (len < kHeaderLen + 5) return false;
    if (pkt[2] & 0x80) return false;              // QR=1: a response, not a query
    if (((pkt[2] >> 3) & 0x0F) != 0) return false;  // opcode must be QUERY
    if (rd16(pkt + 4) < 1) return false;          // QDCOUNT

    size_t i = kHeaderLen, o = 0;
    while (i < len) {
        uint8_t l = pkt[i++];
        if (l == 0) break;
        if (l & 0xC0) return false;  // no compression in questions
        if (i + l > len || o + l + 1 >= sizeof(q.name)) return false;
        if (o) q.name[o++] = '.';
        for (uint8_t k = 0; k < l; k++)
            q.name[o++] = static_cast<char>(tolower(pkt[i++]));
    }
    if (i + 4 > len) return false;
    q.name[o] = '\0';
    q.qtype = rd16(pkt + i);
    q.end = i + 4;
    if (o > 4 && memcmp(q.name, "www.", 4) == 0) {
        memmove(q.name, q.name + 4, o - 3);
        o -= 4;
    }
    q.nameLen = o;
    return true;
}

// Rewrites the query in `buf` into a sinkhole answer: A -> 0.0.0.0,
// AAAA -> ::, anything else -> NOERROR/NODATA. Drops EDNS and other sections
// (a reply with a stray OPT count would be malformed). Returns reply length.
inline size_t buildBlocked(uint8_t* buf, size_t cap, const Question& q)
{
    const bool rd = buf[2] & 0x01;
    buf[2] = static_cast<uint8_t>(0x80 | 0x04 | (rd ? 0x01 : 0));  // QR, AA, RD
    buf[3] = 0x80;                                                 // RA, RCODE=0
    wr16(buf + 4, 1);                                              // QDCOUNT
    wr16(buf + 8, 0);                                              // NSCOUNT
    wr16(buf + 10, 0);                                             // ARCOUNT

    size_t rdlen = q.qtype == kTypeA ? 4 : (q.qtype == kTypeAAAA ? 16 : 0);
    if (!rdlen || q.end + 12 + rdlen > cap) {
        wr16(buf + 6, 0);
        return q.end;
    }
    wr16(buf + 6, 1);  // ANCOUNT
    uint8_t* a = buf + q.end;
    a[0] = 0xC0;  // pointer to the name at offset 12
    a[1] = 0x0C;
    wr16(a + 2, q.qtype);
    wr16(a + 4, 1);  // IN
    a[6] = 0;
    a[7] = 0;
    wr16(a + 8, kBlockedTtl);
    wr16(a + 10, static_cast<uint16_t>(rdlen));
    memset(a + 12, 0, rdlen);
    return q.end + 12 + rdlen;
}

// Skips a (possibly compressed) name starting at `i`. Returns the offset after it, 0 if bad.
inline size_t skipName(const uint8_t* pkt, size_t len, size_t i)
{
    while (i < len) {
        uint8_t l = pkt[i];
        if (l == 0) return i + 1;
        if ((l & 0xC0) == 0xC0) return i + 2 <= len ? i + 2 : 0;
        if (l & 0xC0) return 0;
        i += 1 + l;
    }
    return 0;
}

// Calls fn(ttlPtr, type) for every resource record (answer, authority,
// additional). Returns false if the packet is malformed.
template <typename F>
inline bool forEachRecord(uint8_t* pkt, size_t len, size_t questionEnd, F&& fn)
{
    const unsigned total = rd16(pkt + 6) + rd16(pkt + 8) + rd16(pkt + 10);
    size_t i = questionEnd;
    for (unsigned r = 0; r < total; r++) {
        i = skipName(pkt, len, i);
        if (!i || i + 10 > len) return false;
        const uint16_t type = rd16(pkt + i);
        const uint16_t rdlen = rd16(pkt + i + 8);
        fn(pkt + i + 4, type);
        i += 10 + rdlen;
        if (i > len) return false;
    }
    return true;
}

constexpr uint16_t kTypeOpt = 41;  // EDNS pseudo-record: its "TTL" is flags, not a TTL

inline uint32_t rd32(const uint8_t* p)
{
    return static_cast<uint32_t>(p[0]) << 24 | static_cast<uint32_t>(p[1]) << 16 |
           static_cast<uint32_t>(p[2]) << 8 | p[3];
}
inline void wr32(uint8_t* p, uint32_t v)
{
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

// Captive-portal answer: A -> ipNetOrder (TTL 0, so nothing caches it after setup),
// anything else -> NODATA.
inline size_t buildCaptive(uint8_t* buf, size_t cap, const Question& q, uint32_t ipNetOrder)
{
    if (q.qtype != kTypeA) {
        Question nodata = q;
        nodata.qtype = 0;  // no answer section
        return buildBlocked(buf, cap, nodata);
    }
    size_t n = buildBlocked(buf, cap, q);
    if (n != q.end + 16) return n;
    uint8_t* a = buf + q.end;
    memset(a + 6, 0, 4);                  // TTL 0
    memcpy(a + 12, &ipNetOrder, 4);       // already network byte order
    return n;
}

// Offset just past the first question (works for queries and responses), 0 if malformed.
inline size_t questionEnd(const uint8_t* pkt, size_t len)
{
    if (len < kHeaderLen + 5 || rd16(pkt + 4) < 1) return 0;
    size_t i = kHeaderLen;
    while (i < len) {
        uint8_t l = pkt[i++];
        if (l == 0) break;
        if (l & 0xC0) return 0;
        i += l;
    }
    return i + 4 <= len ? i + 4 : 0;
}

// FNV-1a over the raw question bytes: lets us match an upstream reply to the
// query it belongs to without keeping a copy of the question.
inline uint32_t questionKey(const uint8_t* pkt, size_t end)
{
    uint32_t h = 2166136261u;
    for (size_t i = kHeaderLen; i < end; i++) {
        h ^= static_cast<uint8_t>(tolower(pkt[i]));
        h *= 16777619u;
    }
    return h;
}

}  // namespace sinkhole::dns
