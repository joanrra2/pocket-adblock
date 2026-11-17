#include "sinkhole/blocklist_store.hpp"

#include <cstdio>
#include <cstring>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "sdkconfig.h"
#include "sinkhole/config.hpp"
#include "sinkhole/memory.hpp"

namespace sinkhole {

namespace {
constexpr const char* TAG = "blocklist";
constexpr const char* kSlotKey = "bl_slot";
constexpr esp_partition_subtype_t kSubtype = static_cast<esp_partition_subtype_t>(0x40);
constexpr size_t kSector = 4096;
constexpr size_t kHdr = sizeof(BlocklistHeader);

void setWhy(char* why, size_t len, const char* msg)
{
    if (why && len) snprintf(why, len, "%s", msg);
}
}  // namespace

esp_err_t BlocklistStore::begin()
{
    psa_crypto_init();  // idempotent; ESP-IDF normally did it already
    importKey();

    slots_[0] = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, kSubtype, "bl_a");
    slots_[1] = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, kSubtype, "bl_b");
    if (!slots_[0] || !slots_[1]) {
        ESP_LOGE(TAG, "blocklist partitions bl_a/bl_b missing from the partition table");
        return ESP_ERR_NOT_FOUND;
    }

    // capacityFor(v4) searches; work it out once, not on every status request.
    static constexpr uint8_t kFormats[] = {kBlocklistV1, kBlocklistV2, kBlocklistV4};
    for (uint8_t v : kFormats) capacity_[v] = capacityFor(v, slots_[0]->size);

    uint8_t preferred = 0;
    nvs::loadU8(kSlotKey, preferred);
    preferred &= 1;

    char why[64];
    for (int attempt = 0; attempt < 2; attempt++) {
        int slot = attempt == 0 ? preferred : (preferred ^ 1);
        Mapped m;
        if (mapSlot(slot, m, true, why, sizeof(why))) {
            LockGuard g(mu_);
            active_ = m;
            activeSlot_ = slot;
            activatedUptime_ = uptimeSeconds();
            ESP_LOGI(TAG, "slot %c active: %lu hashes", 'A' + slot,
                     static_cast<unsigned long>(m.hdr.count));
            if (slot != preferred) nvs::saveU8(kSlotKey, static_cast<uint8_t>(slot));
            rebuildBloom(m.table);
            return ESP_OK;
        }
        ESP_LOGW(TAG, "slot %c unusable: %s", 'A' + slot, why);
    }
    ESP_LOGW(TAG, "no blocklist yet: forwarding everything until one is loaded");
    return ESP_OK;
}

bool BlocklistStore::mapSlot(int slot, Mapped& out, bool verifyHash, char* why, size_t whyLen)
{
    const esp_partition_t* part = slots_[slot];
    BlocklistHeader hdr;
    if (esp_partition_read(part, 0, &hdr, sizeof(hdr)) != ESP_OK) {
        setWhy(why, whyLen, "flash read failed");
        return false;
    }
    if (!headerLooksValid(hdr)) {
        setWhy(why, whyLen, "empty or not an SHBL list");
        return false;
    }
    const size_t payload = payloadSize(hdr);
    const size_t sigBytes = isSigned(hdr) ? kSignatureBytes : 0;
    if (hdr.count == 0 || kHdr + payload + sigBytes > part->size) {
        setWhy(why, whyLen, "count does not fit the partition");
        return false;
    }

    const void* ptr = nullptr;
    esp_partition_mmap_handle_t handle = 0;
    esp_err_t err =
        esp_partition_mmap(part, 0, kHdr + payload, ESP_PARTITION_MMAP_DATA, &ptr, &handle);
    if (err != ESP_OK) {
        setWhy(why, whyLen, "mmap failed");
        return false;
    }
    const uint8_t* base = static_cast<const uint8_t*>(ptr);
    HashTable table(base + kHdr, hdr.count, hdr.version, payload);

    if (verifyHash) {
        uint8_t digest[32];
        size_t dlen = 0;
        psa_status_t st = psa_hash_compute(PSA_ALG_SHA_256, base + kHdr, payload, digest,
                                           sizeof(digest), &dlen);
        if (st != PSA_SUCCESS || memcmp(digest, hdr.sha256, sizeof(digest)) != 0) {
            esp_partition_munmap(handle);
            setWhy(why, whyLen, "SHA-256 mismatch");
            return false;
        }
    }
    if (!table.isValid()) {
        esp_partition_munmap(handle);
        setWhy(why, whyLen, "hashes not sorted / index inconsistent");
        return false;
    }
    bool signedOk = false;
    if (isSigned(hdr) && pubKey_) {
        uint8_t sig[kSignatureBytes];
        if (esp_partition_read(part, kHdr + payload, sig, sizeof(sig)) != ESP_OK || !verifySignature(hdr, sig)) {
            esp_partition_munmap(handle);
            setWhy(why, whyLen, "signature does not verify");
            return false;
        }
        signedOk = true;
    }
#if CONFIG_SINKHOLE_BLOCKLIST_REQUIRE_SIGNED
    if (!signedOk) {
        esp_partition_munmap(handle);
        setWhy(why, whyLen, "unsigned list (this firmware requires signed lists)");
        return false;
    }
#endif

    out.part = part;
    out.handle = handle;
    out.base = base;
    out.hdr = hdr;
    out.table = table;
    out.valid = true;
    out.signedOk = signedOk;
    return true;
}

void BlocklistStore::unmap(Mapped& m)
{
    if (m.valid) esp_partition_munmap(m.handle);
    m = Mapped{};
}

bool BlocklistStore::contains(uint64_t hash)
{
    if (bloomReady_ && !bloom_.mayContain(hash)) {  // definitely not listed: no flash read
        bloomSkips_++;
        return false;
    }
    LockGuard g(mu_);
    return active_.valid && active_.table.contains(hash);
}

bool BlocklistStore::containsAny(const uint64_t* hashes, size_t n)
{
    uint64_t candidates[16];
    size_t m = 0;
    for (size_t i = 0; i < n && m < 16; i++) {
        if (bloomReady_ && !bloom_.mayContain(hashes[i])) {  // definitely not listed
            bloomSkips_++;
            continue;
        }
        candidates[m++] = hashes[i];
    }
    if (!m) return false;
    LockGuard g(mu_);
    if (!active_.valid) return false;
    for (size_t i = 0; i < m; i++)
        if (active_.table.contains(candidates[i])) return true;
    return false;
}

BlocklistInfo BlocklistStore::info()
{
    LockGuard g(mu_);
    BlocklistInfo i{};
    i.count = active_.valid ? active_.hdr.count : 0;
    i.createdUnix = active_.valid ? active_.hdr.createdUnix : 0;
    i.activatedUptime = activatedUptime_;
    i.slot = activeSlot_ < 0 ? '-' : static_cast<char>('A' + activeSlot_);
    i.format = active_.valid ? active_.hdr.version : 0;
    i.signedOk = active_.valid && active_.signedOk;
    i.keyConfigured = pubKey_ != 0;
    i.bloomBytes = static_cast<uint32_t>(bloom_.bytes());
    i.bloomPsram = bloomPsram_;
    i.bloomReady = bloomReady_;
    i.bloomSkips = bloomSkips_;
    i.capacity = capacity_[i.format ? i.format : kBlocklistV4];  // empty: what the default lists can use
    return i;
}

// ------------------------------------------------------------------ writer

esp_err_t BlocklistStore::beginWrite()
{
    bool expected = false;
    if (!writing_.compare_exchange_strong(expected, true)) return ESP_ERR_INVALID_STATE;
    if (!slots_[0] || !slots_[1]) {
        writing_ = false;
        return ESP_ERR_NOT_FOUND;
    }
    {
        LockGuard g(mu_);
        writeSlot_ = activeSlot_ < 0 ? 0 : (activeSlot_ ^ 1);
    }
    erasedUpTo_ = 0;
    payloadBytes_ = 0;
    unchanged_ = false;
    tooBig_ = false;
    headLen_ = 0;
    mode_ = Mode::Detect;
    expectedPayload_ = 0;
    sigLen_ = 0;
    trailerOverflow_ = false;
    sha_ = PSA_HASH_OPERATION_INIT;
    if (psa_hash_setup(&sha_, PSA_ALG_SHA_256) != PSA_SUCCESS) {
        writing_ = false;
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "writing slot %c", 'A' + writeSlot_);
    return ESP_OK;
}

esp_err_t BlocklistStore::writeAt(size_t offset, const uint8_t* data, size_t len)
{
    const esp_partition_t* part = slots_[writeSlot_];
    if (offset + len > part->size) return ESP_ERR_INVALID_SIZE;
    // Erase sector by sector just ahead of the write position.
    while (erasedUpTo_ < offset + len) {
        esp_err_t err = esp_partition_erase_range(part, erasedUpTo_, kSector);
        if (err != ESP_OK) return err;
        erasedUpTo_ += kSector;
    }
    return esp_partition_write(part, offset, data, len);
}

esp_err_t BlocklistStore::payloadWrite(const uint8_t* data, size_t len)
{
    // Bytes beyond the payload the header announced are a signature trailer.
    if (mode_ == Mode::WithHeader && expectedPayload_) {
        const size_t room = payloadBytes_ < expectedPayload_ ? expectedPayload_ - payloadBytes_ : 0;
        if (len > room) {
            const size_t extra = len - room;
            if (sigLen_ + extra > sizeof(sig_)) {
                trailerOverflow_ = true;
            } else {
                memcpy(sig_ + sigLen_, data + room, extra);
                sigLen_ += extra;
            }
            len = room;
        }
    }
    if (!len) return ESP_OK;
    if (psa_hash_update(&sha_, data, len) != PSA_SUCCESS) return ESP_FAIL;
    esp_err_t err = writeAt(kHdr + payloadBytes_, data, len);
    if (err == ESP_OK) payloadBytes_ += len;
    return err;
}

esp_err_t BlocklistStore::write(const uint8_t* data, size_t len)
{
    if (!writing_) return ESP_ERR_INVALID_STATE;

    // Collect the first 64 bytes to decide between "SHBL header" and raw hashes.
    if (mode_ == Mode::Detect) {
        size_t take = kHdr - headLen_;
        if (take > len) take = len;
        memcpy(headBuf_ + headLen_, data, take);
        headLen_ += take;
        data += take;
        len -= take;
        if (headLen_ < kHdr) return ESP_OK;  // need more

        if (memcmp(headBuf_, kBlocklistMagic, 4) == 0) {
            mode_ = Mode::WithHeader;  // header kept in headBuf_, written at finish
            BlocklistHeader h;
            memcpy(&h, headBuf_, sizeof(h));
            expectedPayload_ = headerLooksValid(h) ? payloadSize(h) : 0;
            // Too big for this board's slot? Say so now instead of failing at the end.
            if (expectedPayload_ && kHdr + expectedPayload_ > slots_[writeSlot_]->size) {
                tooBig_ = true;
                tooBigCount_ = h.count;
                return ESP_ERR_INVALID_SIZE;
            }
            // Same list as the active one? Stop here: no download, no flash wear.
            int active;
            {
                LockGuard g(mu_);
                active = activeSlot_;
            }
            BlocklistHeader cur;
            if (expectedPayload_ && active >= 0 && esp_partition_read(slots_[active], 0, &cur, sizeof(cur)) == ESP_OK &&
                cur.count == h.count && cur.version == h.version &&
                memcmp(cur.sha256, h.sha256, sizeof(h.sha256)) == 0) {
                unchanged_ = true;
                return ESP_ERR_INVALID_STATE;  // aborts the download
            }
        } else {
            mode_ = Mode::Raw;  // those 64 bytes were already payload
            esp_err_t err = payloadWrite(headBuf_, kHdr);
            if (err != ESP_OK) return err;
        }
    }
    return payloadWrite(data, len);
}

esp_err_t BlocklistStore::finishWrite(char* why, size_t whyLen)
{
    if (!writing_) return ESP_ERR_INVALID_STATE;

    if (mode_ == Mode::Detect && headLen_ > 0) {  // tiny raw file (< 64 bytes)
        mode_ = Mode::Raw;
        if (payloadWrite(headBuf_, headLen_) != ESP_OK) {
            setWhy(why, whyLen, "flash write failed");
            abortWrite();
            return ESP_FAIL;
        }
    }

    BlocklistHeader hdr{};
    uint8_t digest[32];
    size_t dlen = 0;
    psa_status_t st = psa_hash_finish(&sha_, digest, sizeof(digest), &dlen);
    if (st != PSA_SUCCESS) {
        setWhy(why, whyLen, "hash failed");
        abortWrite();
        return ESP_FAIL;
    }

    if (mode_ == Mode::WithHeader) {
        memcpy(&hdr, headBuf_, sizeof(hdr));
        if (!headerLooksValid(hdr)) {
            setWhy(why, whyLen, "unsupported SHBL header");
            abortWrite();
            return ESP_ERR_INVALID_VERSION;
        }
        if (hdr.count == 0 || payloadBytes_ != payloadSize(hdr)) {
            setWhy(why, whyLen, "header count does not match payload (truncated download?)");
            abortWrite();
            return ESP_ERR_INVALID_SIZE;
        }
        if (memcmp(hdr.sha256, digest, sizeof(digest)) != 0) {
            setWhy(why, whyLen, "SHA-256 mismatch");
            abortWrite();
            return ESP_ERR_INVALID_CRC;
        }
        if (trailerOverflow_ || sigLen_ != (isSigned(hdr) ? kSignatureBytes : 0)) {
            setWhy(why, whyLen, isSigned(hdr) ? "signature missing or truncated" : "unexpected data after the list");
            abortWrite();
            return ESP_ERR_INVALID_SIZE;
        }
        if (isSigned(hdr) && writeAt(kHdr + payloadBytes_, sig_, kSignatureBytes) != ESP_OK) {
            setWhy(why, whyLen, "flash write failed");
            abortWrite();
            return ESP_FAIL;
        }
    } else {
        // Raw upload (esp32-c3-adblock format): headerless v1, 5 bytes per hash.
        if (payloadBytes_ == 0 || payloadBytes_ % kHashBytes != 0) {
            setWhy(why, whyLen, "size is not a whole number of 5-byte hashes");
            abortWrite();
            return ESP_ERR_INVALID_SIZE;
        }
        memcpy(hdr.magic, kBlocklistMagic, 4);
        hdr.version = kBlocklistV1;
        hdr.hashBytes = kHashBytes;
        hdr.headerSize = kHdr;
        hdr.count = static_cast<uint32_t>(payloadBytes_ / kHashBytes);
        hdr.createdUnix = 0;
        memcpy(hdr.sha256, digest, sizeof(digest));
    }

    if (writeAt(0, reinterpret_cast<const uint8_t*>(&hdr), sizeof(hdr)) != ESP_OK) {
        setWhy(why, whyLen, "flash write failed");
        abortWrite();
        return ESP_FAIL;
    }

    // Map the freshly written slot; SHA already verified while streaming,
    // mapSlot() still checks the header and the sort order.
    Mapped fresh;
    if (!mapSlot(writeSlot_, fresh, false, why, whyLen)) {
        abortWrite();
        return ESP_FAIL;
    }

    Mapped old;
    bloomReady_ = false;  // the old filter must not answer for the new list
    {
        LockGuard g(mu_);
        old = active_;
        active_ = fresh;
        activeSlot_ = writeSlot_;
        activatedUptime_ = uptimeSeconds();
    }
    unmap(old);
    rebuildBloom(fresh.table);
    nvs::saveU8(kSlotKey, static_cast<uint8_t>(writeSlot_));
    ESP_LOGI(TAG, "slot %c active: %lu hashes (format v%u)", 'A' + writeSlot_,
             static_cast<unsigned long>(hdr.count), hdr.version);

    writeSlot_ = -1;
    writing_ = false;
    return ESP_OK;
}

// ------------------------------------------------------------------ bloom filter

// Allocated the first time a sorted list (v1/v2) becomes active: a filter list
// (v4, the default) never needs it, so those boards keep the PSRAM. Once
// allocated it stays (lookups may still be reading it).
bool BlocklistStore::allocateBloom()
{
#if CONFIG_SINKHOLE_BLOOM_FILTER
    if (bloom_.ready()) return true;
    if (bloomFailed_) return false;
    const uint32_t cap = capacityFor(kBlocklistV2, slots_[0]->size);  // the densest format
    const size_t bytes = (static_cast<size_t>(cap) * CONFIG_SINKHOLE_BLOOM_BITS_PER_ENTRY + 7) / 8;
    void* mem = psramAvailable() ? heap_caps_calloc(1, bytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT) : nullptr;
    bloomPsram_ = mem != nullptr;
    if (!mem) mem = heap_caps_calloc(1, bytes, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!mem) {
        bloomFailed_ = true;
        ESP_LOGW(TAG, "bloom filter: no room for %u KB, running without it", static_cast<unsigned>(bytes / 1024));
        return false;
    }
    // k = bits per entry * ln 2 (optimal number of hash functions).
    const uint8_t k = static_cast<uint8_t>((CONFIG_SINKHOLE_BLOOM_BITS_PER_ENTRY * 693 + 500) / 1000);
    bloom_.attach(static_cast<uint8_t*>(mem), bytes, k ? k : 1);
    ESP_LOGI(TAG, "bloom filter: %u KB in %s, %d bits/domain, k=%u", static_cast<unsigned>(bytes / 1024),
             bloomPsram_ ? "PSRAM" : "internal RAM", CONFIG_SINKHOLE_BLOOM_BITS_PER_ENTRY, k);
    return true;
#else
    return false;
#endif
}

// Lookups bypass the filter (bloomReady_ = false) while it is rebuilt.
void BlocklistStore::rebuildBloom(const HashTable& table)
{
    bloomReady_ = false;
    if (!table.canList()) return;  // a filter list (v4) answers in 3 reads: no bloom filter needed
    if (!allocateBloom()) return;
    const int64_t t0 = esp_timer_get_time();
    bloom_.clear();
    table.forEach([this](uint64_t h) { bloom_.add(h); });
    bloomReady_ = true;
    ESP_LOGI(TAG, "bloom filter rebuilt: %lu domains in %lld ms", static_cast<unsigned long>(table.size()),
             static_cast<long long>((esp_timer_get_time() - t0) / 1000));
}

// ------------------------------------------------------------------ signatures

void BlocklistStore::importKey()
{
    static const char* hex = CONFIG_SINKHOLE_BLOCKLIST_PUBKEY;
    if (strlen(hex) != 130) {
        if (hex[0]) ESP_LOGE(TAG, "SINKHOLE_BLOCKLIST_PUBKEY must be 130 hex chars (uncompressed P-256)");
        return;
    }
    uint8_t point[65];
    for (size_t i = 0; i < sizeof(point); i++) {
        unsigned v = 0;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return;
        point[i] = static_cast<uint8_t>(v);
    }
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    if (psa_import_key(&attr, point, sizeof(point), &pubKey_) != PSA_SUCCESS) {
        pubKey_ = 0;
        ESP_LOGE(TAG, "blocklist public key rejected");
    } else {
        ESP_LOGI(TAG, "blocklist signatures verified with the built-in key");
    }
}

bool BlocklistStore::verifySignature(const BlocklistHeader& hdr, const uint8_t* sig)
{
    uint8_t digest[32];
    size_t dlen = 0;
    if (psa_hash_compute(PSA_ALG_SHA_256, reinterpret_cast<const uint8_t*>(&hdr), kSignedHeaderBytes,
                         digest, sizeof(digest), &dlen) != PSA_SUCCESS)
        return false;
    return psa_verify_hash(pubKey_, PSA_ALG_ECDSA(PSA_ALG_SHA_256), digest, sizeof(digest), sig,
                           kSignatureBytes) == PSA_SUCCESS;
}

void BlocklistStore::abortWrite()
{
    if (!writing_) return;
    psa_hash_abort(&sha_);
    writeSlot_ = -1;
    writing_ = false;
}

}  // namespace sinkhole
