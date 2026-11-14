#pragma once
// SafeSearch enforcement: search hostnames are answered with the address of
// the provider's official "safe" endpoint (what Google, Bing and YouTube
// document for networks). Header-only (host tests).

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace sinkhole::safe {

enum : uint8_t {
    kGoogle = 1,
    kBing = 2,
    kYoutubeModerate = 4,
    kYoutubeStrict = 8,
};

// Safe endpoints, looked up through the upstream (addresses do change).
enum Target : int8_t { None = -1, Google = 0, Bing = 1, YoutubeModerate = 2, YoutubeStrict = 3, kTargets = 4 };
constexpr const char* kTargetNames[kTargets] = {
    "forcesafesearch.google.com",
    "strict.bing.com",
    "restrictmoderate.youtube.com",
    "restrict.youtube.com",
};
// Used until the first lookup succeeds (network byte order on little-endian).
constexpr uint32_t ip4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    return static_cast<uint32_t>(a) | static_cast<uint32_t>(b) << 8 | static_cast<uint32_t>(c) << 16 |
           static_cast<uint32_t>(d) << 24;
}
constexpr uint32_t kDefaultIps[kTargets] = {
    ip4(216, 239, 38, 120),
    ip4(150, 171, 27, 16),
    ip4(216, 239, 38, 119),
    ip4(216, 239, 38, 120),
};

// "google.com", "google.es", "google.co.uk", "google.com.br" ("www." is already
// stripped by the parser). Not mail.google.com, google.blog, ...
inline bool isGoogleSearch(const char* name, size_t len)
{
    if (len < 8 || memcmp(name, "google.", 7) != 0) return false;
    size_t labels = 1, labelLen = 0;
    for (size_t i = 7; i < len; i++) {
        if (name[i] == '.') {
            if (!labelLen) return false;
            labels++;
            labelLen = 0;
        } else if (++labelLen > 3) {
            return false;
        }
    }
    return labelLen && labels <= 2;
}

inline bool equals(const char* name, size_t len, const char* s)
{
    return strlen(s) == len && memcmp(name, s, len) == 0;
}

inline Target check(const char* name, size_t len, uint8_t flags)
{
    if ((flags & kGoogle) && isGoogleSearch(name, len)) return Google;
    if ((flags & kBing) && equals(name, len, "bing.com")) return Bing;
    if (flags & (kYoutubeModerate | kYoutubeStrict)) {
        static constexpr const char* kYoutube[] = {"youtube.com", "m.youtube.com", "youtubei.googleapis.com",
                                                   "youtube.googleapis.com", "youtube-nocookie.com"};
        for (const char* y : kYoutube)
            if (equals(name, len, y)) return (flags & kYoutubeStrict) ? YoutubeStrict : YoutubeModerate;
    }
    return None;
}

}  // namespace sinkhole::safe
