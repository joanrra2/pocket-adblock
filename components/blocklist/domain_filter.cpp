#include "sinkhole/domain_filter.hpp"

#include "sinkhole/hash_table.hpp"
#include "sinkhole/rtos.hpp"

namespace sinkhole {

void DomainFilter::pauseFor(uint32_t seconds)
{
    enabled_ = false;
    resumeAt_ = seconds ? uptimeSeconds() + seconds : 0;
}

bool DomainFilter::enabled()
{
    uint32_t r = resumeAt_;
    if (!enabled_ && r && uptimeSeconds() >= r) {
        enabled_ = true;
        resumeAt_ = 0;
    }
    return enabled_;
}

bool DomainFilter::isAllowed(const char* domain, size_t len)
{
    uint64_t hashes[16];
    size_t n = 0;
    forEachSuffix(domain, len, [&](const char* s, size_t l) {
        hashes[n++] = fnv1a40(s, l);
        return n == sizeof(hashes) / sizeof(hashes[0]);
    });
    return allow_.containsAny(hashes, n);
}

bool DomainFilter::isBlocked(const char* domain, size_t len)
{
    if (!len || !enabled()) return false;

    // Hash each suffix once and reuse it for all three lists.
    uint64_t hashes[16];
    size_t n = 0;
    forEachSuffix(domain, len, [&](const char* s, size_t l) {
        hashes[n++] = fnv1a40(s, l);
        return n == sizeof(hashes) / sizeof(hashes[0]);
    });

    // One lock per list for all suffixes (not one per suffix), and empty
    // lists are skipped without locking: this is the per-query hot path.
    if (allow_.containsAny(hashes, n)) return false;
    if (custom_.containsAny(hashes, n)) return true;
    return store_.containsAny(hashes, n);
}

}  // namespace sinkhole
