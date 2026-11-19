#pragma once
// Reads a restore file as it arrives, in pieces of any size, and decodes each
// known "key=base64" line straight into one caller-owned buffer. The file
// itself is never held in RAM. Header-only so the host tests cover it.
//
// File format: lines of key=value. "# ..." lines are comments, "format=1"
// must be present, unknown keys (firmware=, edition=...) are skipped. CRs and
// spaces are ignored, so files edited on Windows still restore.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace sinkhole {

// The stored items a backup holds, in the order it writes them.
inline constexpr std::array<const char*, 10> kBackupKeys{"settings",   "custom_block", "custom_allow", "local_dns",
                                                         "wol_hosts2", "wol_hosts",    "banned",       "nofilter",
                                                         "dev_names",  "notify"};

class BackupReader {
public:
    struct Item {
        const char* key;  // the kBackupKeys entry (same pointer)
        uint8_t* data;    // inside the caller's buffer
        size_t len;
    };

    // Decoded data is at most 3/4 of the file: a buffer of that size always fits.
    static constexpr size_t decodedCap(size_t fileLen) { return fileLen / 4 * 3 + 3; }

    BackupReader(uint8_t* buf, size_t cap) : buf_(buf), cap_(cap) {}

    void feed(const char* p, size_t n)
    {
        for (size_t i = 0; i < n && !why_; i++) put(p[i]);
    }

    // After the last piece: nullptr when the whole file is good, else why not.
    const char* finish()
    {
        if (!why_ && keyLen_) put('\n');  // last line without a line end
        if (!formatOk_) return "not a Pocket AdBlock backup (format=1 missing)";
        if (why_) return why_;
        if (count_ == 0) return "the file contains nothing to restore";
        return nullptr;
    }

    size_t count() const { return count_; }
    Item& item(size_t i) { return items_[i]; }

private:
    enum class State : uint8_t { Key, Value, Format, Skip };

    static int b64(char c)
    {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    }

    static const char* knownKey(const char* name)
    {
        for (const char* k : kBackupKeys)
            if (std::strcmp(name, k) == 0) return k;
        return nullptr;
    }

    void put(char c)
    {
        if (c == '\r' || c == ' ') return;
        if (c == '\n') {
            endLine();
            return;
        }
        switch (state_) {
            case State::Key:
                if (keyLen_ == 0 && c == '#') {
                    state_ = State::Skip;
                } else if (c == '=') {
                    key_[keyLen_] = '\0';
                    startValue();
                } else if (keyLen_ + 1 >= key_.size()) {
                    state_ = State::Skip;  // longer than any key we know
                } else {
                    key_[keyLen_++] = c;
                }
                break;
            case State::Format:
                formatOne_ = fmtLen_ == 0 && c == '1';
                fmtLen_++;
                break;
            case State::Value:
                valueChar(c);
                break;
            case State::Skip:
                break;
        }
    }

    void startValue()
    {
        if (std::strcmp(key_.data(), "format") == 0) {
            state_ = State::Format;
            fmtLen_ = 0;
            formatOne_ = false;
            return;
        }
        const char* k = knownKey(key_.data());
        if (!k) {
            state_ = State::Skip;
            return;
        }
        // One slot per known key: a repeated section must not run past items_.
        for (size_t i = 0; i < count_; i++)
            if (items_[i].key == k) {
                why_ = "a section appears twice";
                return;
            }
        items_[count_] = {k, buf_ + used_, 0};
        quadLen_ = 0;
        pad_ = 0;
        state_ = State::Value;
    }

    void valueChar(char c)
    {
        if (pad_ && (c != '=' || quadLen_ == 0)) {  // nothing may follow the padding
            why_ = kDamaged;
            return;
        }
        int v = 0;
        if (c == '=') {
            if (quadLen_ < 2) {
                why_ = kDamaged;
                return;
            }
            pad_++;
        } else {
            v = b64(c);
            if (v < 0) {
                why_ = kDamaged;
                return;
            }
        }
        quad_ = quad_ << 6 | static_cast<uint32_t>(v);
        if (++quadLen_ < 4) return;
        const size_t bytes = 3u - pad_;
        if (used_ + bytes > cap_) {
            why_ = kDamaged;
            return;
        }
        buf_[used_++] = static_cast<uint8_t>(quad_ >> 16);
        if (bytes > 1) buf_[used_++] = static_cast<uint8_t>(quad_ >> 8);
        if (bytes > 2) buf_[used_++] = static_cast<uint8_t>(quad_);
        items_[count_].len += bytes;
        quadLen_ = 0;
        quad_ = 0;
    }

    void endLine()
    {
        if (state_ == State::Format) {
            formatOk_ = formatOk_ || (fmtLen_ == 1 && formatOne_);
        } else if (state_ == State::Value && !why_) {
            if (quadLen_ != 0 || items_[count_].len == 0)
                why_ = kDamaged;
            else
                count_++;
        }
        state_ = State::Key;
        keyLen_ = 0;
    }

    static constexpr const char* kDamaged = "a section of the file is damaged";

    uint8_t* buf_;
    size_t cap_;
    size_t used_ = 0;
    std::array<Item, kBackupKeys.size()> items_{};
    size_t count_ = 0;
    const char* why_ = nullptr;
    State state_ = State::Key;
    std::array<char, 16> key_{};
    size_t keyLen_ = 0;
    uint32_t quad_ = 0;
    uint8_t quadLen_ = 0;
    uint8_t pad_ = 0;
    size_t fmtLen_ = 0;
    bool formatOne_ = false;
    bool formatOk_ = false;
};

}  // namespace sinkhole
