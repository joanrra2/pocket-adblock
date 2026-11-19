#include "sinkhole/domain_filter.hpp"

#include <array>

#include "sinkhole/hash_table.hpp"
#include "sinkhole/rtos.hpp"

namespace sinkhole {

void DomainFilter::setEnabled(bool on)
{
    state_ = on ? kOn : kOff;
}

void DomainFilter::pauseFor(uint32_t seconds)
{
    // A deadline is never kOn (0) or kOff: uptime + 1..86400 s fits easily.
    state_ = seconds ? uptimeSeconds() + seconds : kOff;
}

bool DomainFilter::enabled()
{
    uint32_t s = state_;
    if (s == kOn) return true;
    if (s == kOff || uptimeSeconds() < s) return false;
    // The pause is over. Only this exact deadline is cleared: a new pause or
    // switch set by another task in between stays as it is.
    if (state_.compare_exchange_strong(s, kOn)) return true;
    return s == kOn;
}

uint32_t DomainFilter::resumeAt() const
{
    const uint32_t s = state_;
    return s == kOff ? 0 : s;
}

bool DomainFilter::isAllowed(const char* domain, size_t len)
{
    std::array<uint64_t, kMaxSuffixes> hashes;
    const size_t n = suffixHashes(domain, len, hashes);
    return allow_.containsAny(hashes.data(), n);
}

bool DomainFilter::isBlocked(const char* domain, size_t len)
{
    if (!len || !enabled()) return false;

    // Hash each suffix once and reuse it for all three lists.
    std::array<uint64_t, kMaxSuffixes> hashes;
    const size_t n = suffixHashes(domain, len, hashes);

    // One lock per list for all suffixes (not one per suffix), and empty
    // lists are skipped without locking: this is the per-query hot path.
    if (allow_.containsAny(hashes.data(), n)) return false;
    if (custom_.containsAny(hashes.data(), n)) return true;
    return store_.containsAny(hashes.data(), n);
}

}  // namespace sinkhole
