#include "sinkhole/blocklist_store.hpp"

#include <cstdio>
#include <cstring>

#include "esp_log.h"
#include "sinkhole/config.hpp"

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

    slots_[0] = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, kSubtype, "bl_a");
    slots_[1] = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, kSubtype, "bl_b");
    if (!slots_[0] || !slots_[1]) {
        ESP_LOGE(TAG, "blocklist partitions bl_a/bl_b missing from the partition table");
        return ESP_ERR_NOT_FOUND;
    }

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
    const size_t payload = static_cast<size_t>(hdr.count) * kHashBytes;
    if (hdr.count == 0 || kHdr + payload > part->size) {
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
    HashTable table(base + kHdr, hdr.count);

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
    if (!table.isSorted()) {
        esp_partition_munmap(handle);
        setWhy(why, whyLen, "hashes not sorted");
        return false;
    }

    out.part = part;
    out.handle = handle;
    out.base = base;
    out.hdr = hdr;
    out.table = table;
    out.valid = true;
    return true;
}

void BlocklistStore::unmap(Mapped& m)
{
    if (m.valid) esp_partition_munmap(m.handle);
    m = Mapped{};
}

bool BlocklistStore::contains(uint64_t hash)
{
    LockGuard g(mu_);
    return active_.valid && active_.table.contains(hash);
}

BlocklistInfo BlocklistStore::info()
{
    LockGuard g(mu_);
    BlocklistInfo i{};
    i.count = active_.valid ? active_.hdr.count : 0;
    i.createdUnix = active_.valid ? active_.hdr.createdUnix : 0;
    i.activatedUptime = activatedUptime_;
    i.slot = activeSlot_ < 0 ? '-' : static_cast<char>('A' + activeSlot_);
    i.capacity = slots_[0] ? static_cast<uint32_t>((slots_[0]->size - kHdr) / kHashBytes) : 0;
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
    headLen_ = 0;
    mode_ = Mode::Detect;
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

    if (payloadBytes_ == 0 || payloadBytes_ % kHashBytes != 0) {
        setWhy(why, whyLen, "size is not a whole number of 5-byte hashes");
        abortWrite();
        return ESP_ERR_INVALID_SIZE;
    }
    const uint32_t count = static_cast<uint32_t>(payloadBytes_ / kHashBytes);

    if (mode_ == Mode::WithHeader) {
        memcpy(&hdr, headBuf_, sizeof(hdr));
        if (!headerLooksValid(hdr)) {
            setWhy(why, whyLen, "unsupported SHBL header");
            abortWrite();
            return ESP_ERR_INVALID_VERSION;
        }
        if (hdr.count != count) {
            setWhy(why, whyLen, "header count does not match payload (truncated download?)");
            abortWrite();
            return ESP_ERR_INVALID_SIZE;
        }
        if (memcmp(hdr.sha256, digest, sizeof(digest)) != 0) {
            setWhy(why, whyLen, "SHA-256 mismatch");
            abortWrite();
            return ESP_ERR_INVALID_CRC;
        }
    } else {
        memcpy(hdr.magic, kBlocklistMagic, 4);
        hdr.version = kBlocklistVersion;
        hdr.hashBytes = kHashBytes;
        hdr.headerSize = kHdr;
        hdr.count = count;
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
    {
        LockGuard g(mu_);
        old = active_;
        active_ = fresh;
        activeSlot_ = writeSlot_;
        activatedUptime_ = uptimeSeconds();
    }
    unmap(old);
    nvs::saveU8(kSlotKey, static_cast<uint8_t>(writeSlot_));
    ESP_LOGI(TAG, "slot %c active: %lu hashes", 'A' + writeSlot_,
             static_cast<unsigned long>(count));

    writeSlot_ = -1;
    writing_ = false;
    return ESP_OK;
}

void BlocklistStore::abortWrite()
{
    if (!writing_) return;
    psa_hash_abort(&sha_);
    writeSlot_ = -1;
    writing_ = false;
}

}  // namespace sinkhole
