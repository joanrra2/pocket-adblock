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
    void setEnabled(bool on) { enabled_ = on; resumeAt_ = 0; }
    void pauseFor(uint32_t seconds);
    bool enabled();
    uint32_t resumeAt() const { return resumeAt_; }

private:
    BlocklistStore& store_;
    DomainList& custom_;
    DomainList& allow_;
    std::atomic<bool> enabled_{true};
    std::atomic<uint32_t> resumeAt_{0};  // uptime seconds, 0 = not scheduled
};

}  // namespace sinkhole
