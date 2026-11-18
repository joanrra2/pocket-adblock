#pragma once
// Helpers for passwords and other secrets: constant-time compares and a wipe
// the compiler can't drop.

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace sinkhole {

// Zero memory through a volatile pointer, so it isn't optimised away like a
// memset of a buffer that is never read again.
inline void secureWipe(void* p, size_t n)
{
    auto* v = static_cast<volatile unsigned char*>(p);
    while (n--) *v++ = 0;
}

// Constant time for equal-length buffers.
inline bool sameBytes(const void* a, const void* b, size_t n)
{
    const auto* x = static_cast<const unsigned char*>(a);
    const auto* y = static_cast<const unsigned char*>(b);
    unsigned char diff = 0;
    for (size_t i = 0; i < n; i++) diff |= static_cast<unsigned char>(x[i] ^ y[i]);
    return diff == 0;
}

// Constant time in the length of a (both strings at most cap bytes).
inline bool sameText(const char* a, const char* b, size_t cap)
{
    const size_t la = strnlen(a, cap);
    const size_t lb = strnlen(b, cap);
    unsigned char diff = la != lb ? 1 : 0;
    for (size_t i = 0; i < la; i++) diff |= static_cast<unsigned char>(a[i] ^ b[lb ? i % lb : 0]);
    return diff == 0;
}

}  // namespace sinkhole
