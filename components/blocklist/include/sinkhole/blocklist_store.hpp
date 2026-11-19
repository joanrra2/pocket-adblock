#pragma once
// A/B blocklist storage on raw flash partitions ("bl_a" / "bl_b", subtype 0x40).
//
// The active slot is memory-mapped, so a lookup is a binary search on a plain
// pointer: no file system, no RAM index. Updates stream into the inactive slot,
// get verified (size, SHA-256, sort order) and only then become active; a bad
// or interrupted download never touches the list that is serving queries.

#include <atomic>
#include <cstddef>
#include <cstdint>

#include "esp_err.h"
#include "esp_partition.h"
#include "psa/crypto.h"
#include "sinkhole/hash_table.hpp"
#include "sinkhole/rtos.hpp"

namespace sinkhole {

struct BlocklistInfo {
    uint32_t count;
    uint32_t createdUnix;
    uint32_t activatedUptime;  // seconds since boot when it went live
    char slot;                 // 'A', 'B' or '-' when none
    uint32_t capacity;         // max hashes a slot can hold (in the active format)
    uint8_t format;            // 1, 2 (compact), 4 (fuse filter) or 0 when none
    bool signedOk;             // signature verified against the configured key
    bool keyConfigured;        // firmware built with a blocklist public key
    uint32_t bloomBytes;       // 0 = no bloom filter
    bool bloomPsram;
    bool bloomReady;
    uint32_t bloomSkips;       // lookups answered by the bloom filter alone
};

class BlocklistStore {
public:
    esp_err_t begin();
    // Builds the bloom filter for the list found at boot (begin() leaves it for
    // later so Wi-Fi and DNS start right away). Called from the updater task.
    void finishStartup();

    bool contains(uint64_t hash);
    // Any of several hashes (the suffixes of one name) under a single lock.
    bool containsAny(const uint64_t* hashes, size_t n);
    BlocklistInfo info();

    // ---- writer (one at a time; used by HTTP upload and the URL updater) ----
    esp_err_t beginWrite();
    esp_err_t write(const uint8_t* data, size_t len);
    // Verifies and activates. `why` gets a human-readable reason on failure.
    esp_err_t finishWrite(char* why, size_t whyLen);
    void abortWrite();
    bool writing() const { return writing_.load(); }
    // The update being written has the same header (checksum, count, format) as
    // the active list: write() stopped after 64 bytes, nothing touched flash.
    bool unchanged() const { return unchanged_; }
    // The header announced more domains than this board's slot holds.
    bool tooBig() const { return tooBig_; }
    uint32_t tooBigCount() const { return tooBigCount_; }

private:
    struct Mapped {
        const esp_partition_t* part = nullptr;
        esp_partition_mmap_handle_t handle = 0;
        const uint8_t* base = nullptr;
        BlocklistHeader hdr{};
        HashTable table;
        bool valid = false;
        bool signedOk = false;
    };

    const esp_partition_t* slotPartition(int slot) const { return slots_[slot]; }
    bool mapSlot(int slot, Mapped& out, bool verifyHash, char* why, size_t whyLen);
    static void unmap(Mapped& m);
    esp_err_t writeAt(size_t offset, const uint8_t* data, size_t len);
    esp_err_t payloadWrite(const uint8_t* data, size_t len);
    void importKey();
    bool allocateBloom();
    void rebuildBloom(const HashTable& table);
    bool bloomExcludes(uint64_t hash) const;
    void invalidateBloom()
    {
        bloomReady_ = false;
        bloomGen_++;
    }
    bool verifySignature(const BlocklistHeader& hdr, const uint8_t* sig);

    const esp_partition_t* slots_[2] = {nullptr, nullptr};
    uint32_t capacity_[kBlocklistV4 + 1] = {};  // per format, for one slot

    Mutex mu_;  // guards active_ / activeSlot_
    Mapped active_;
    int activeSlot_ = -1;
    uint32_t activatedUptime_ = 0;

    // writer state
    std::atomic<bool> writing_{false};
    bool unchanged_ = false;
    bool tooBig_ = false;
    uint32_t tooBigCount_ = 0;
    int writeSlot_ = -1;
    size_t erasedUpTo_ = 0;
    size_t payloadBytes_ = 0;
    uint8_t headBuf_[sizeof(BlocklistHeader)]{};
    size_t headLen_ = 0;
    enum class Mode { Detect, WithHeader, Raw } mode_ = Mode::Detect;
    psa_hash_operation_t sha_ = PSA_HASH_OPERATION_INIT;
    size_t expectedPayload_ = 0;  // known once an SHBL header arrived
    uint8_t sig_[kSignatureBytes]{};
    size_t sigLen_ = 0;
    bool trailerOverflow_ = false;
    psa_key_id_t pubKey_ = 0;

    // Optional RAM bloom filter (CONFIG_SINKHOLE_BLOOM_FILTER).
    BloomBits bloom_;
    bool bloomPsram_ = false;
    bool bloomFailed_ = false;
    bool bloomAtStartup_ = false;  // allocation failed once: don't retry on every update
    std::atomic<bool> bloomReady_{false};
    std::atomic<uint32_t> bloomGen_{0};  // +1 whenever the filter stops answering
    std::atomic<uint32_t> bloomSkips_{0};
};

}  // namespace sinkhole
