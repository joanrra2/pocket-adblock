#pragma once
// Decides whether a domain is blocked: allow list > custom block list > flash list.
// Every check also applies to parent domains (blocking ads.com blocks x.ads.com).

#include <atomic>
#include <cstddef>
#include <cstdint>

#include "sinkhole/blocklist_store.hpp"
#include "sinkhole/domain_list.hpp"

namespace sinkhole {

class DomainFilter {
public:
    DomainFilter(BlocklistStore& store, DomainList& custom, DomainList& allow)
        : store_(store), custom_(custom), allow_(allow)
    {
    }

    // domain: lower-case, no trailing dot, "www." already stripped.
    bool isBlocked(const char* domain, size_t len);
    // On the allow list (the domain or a parent)?
    bool isAllowed(const char* domain, size_t len);

    // Global switch with optional auto-resume (pause for N seconds).
    void setEnabled(bool on);
    void pauseFor(uint32_t seconds);
    bool enabled();
    uint32_t resumeAt() const;  // uptime seconds; 0 = on, or off with no resume

private:
    // On, off, or paused until an uptime second, in one atomic so a resume
    // can't cancel a pause set at the same moment by another task.
    static constexpr uint32_t kOn = 0;
    static constexpr uint32_t kOff = UINT32_MAX;

    BlocklistStore& store_;
    DomainList& custom_;
    DomainList& allow_;
    std::atomic<uint32_t> state_{kOn};
};

}  // namespace sinkhole
