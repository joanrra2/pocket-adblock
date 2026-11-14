#include "sinkhole/json_writer.hpp"

#include <cinttypes>
#include <cstdio>
#include <cstring>

#include "sinkhole/text.hpp"

namespace sinkhole {

JsonWriter::JsonWriter(httpd_req_t* req) : req_(req)
{
    httpd_resp_set_type(req_, "application/json");
    httpd_resp_set_hdr(req_, "Cache-Control", "no-store");
}

void JsonWriter::flush()
{
    if (len_ && err_ == ESP_OK) err_ = httpd_resp_send_chunk(req_, buf_, len_);
    len_ = 0;
}

void JsonWriter::raw(const char* s, size_t n)
{
    while (n) {
        if (len_ == sizeof(buf_)) flush();
        size_t take = sizeof(buf_) - len_;
        if (take > n) take = n;
        memcpy(buf_ + len_, s, take);
        len_ += take;
        s += take;
        n -= take;
    }
}

void JsonWriter::raw(const char* s)
{
    raw(s, strlen(s));
}

void JsonWriter::escaped(const char* s)
{
    raw("\"", 1);
    for (; *s; s++) {
        unsigned char c = static_cast<unsigned char>(*s);
        if (c == '"' || c == '\\') {
            char e[2] = {'\\', static_cast<char>(c)};
            raw(e, 2);
        } else if (c < 0x20) {
            char e[8];
            snprintf(e, sizeof(e), "\\u%04x", c);
            raw(e);
        } else {
            raw(reinterpret_cast<const char*>(&c), 1);
        }
    }
    raw("\"", 1);
}

void JsonWriter::prefix(const char* key)
{
    const uint32_t bit = 1u << depth_;
    if (firstMask_ & bit)
        firstMask_ &= ~bit;
    else
        raw(",", 1);
    if (key) {
        escaped(key);
        raw(":", 1);
    }
}

JsonWriter& JsonWriter::beginObject(const char* key)
{
    if (depth_ > 0 || key) prefix(key);
    raw("{", 1);
    depth_++;
    firstMask_ |= 1u << depth_;
    return *this;
}

JsonWriter& JsonWriter::endObject()
{
    depth_--;
    raw("}", 1);
    return *this;
}

JsonWriter& JsonWriter::beginArray(const char* key)
{
    if (depth_ > 0 || key) prefix(key);
    raw("[", 1);
    depth_++;
    firstMask_ |= 1u << depth_;
    return *this;
}

JsonWriter& JsonWriter::endArray()
{
    depth_--;
    raw("]", 1);
    return *this;
}

JsonWriter& JsonWriter::str(const char* key, const char* value)
{
    prefix(key);
    escaped(value ? value : "");
    return *this;
}

JsonWriter& JsonWriter::num(const char* key, int64_t value)
{
    prefix(key);
    char n[24];
    snprintf(n, sizeof(n), "%" PRId64, value);
    raw(n);
    return *this;
}

JsonWriter& JsonWriter::boolean(const char* key, bool value)
{
    prefix(key);
    raw(value ? "true" : "false");
    return *this;
}

JsonWriter& JsonWriter::ip(const char* key, uint32_t ipNetOrder)
{
    char s[16] = "";
    if (ipNetOrder) formatIp4(ipNetOrder, s);
    return str(key, s);
}

JsonWriter& JsonWriter::mac(const char* key, const uint8_t m[6])
{
    char s[18];
    formatMac(m, s);
    return str(key, s);
}

esp_err_t JsonWriter::finish()
{
    flush();
    if (err_ == ESP_OK) err_ = httpd_resp_send_chunk(req_, nullptr, 0);
    return err_;
}

}  // namespace sinkhole
