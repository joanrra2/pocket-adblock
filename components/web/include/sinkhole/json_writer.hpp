#pragma once
// Streaming JSON writer into a fixed buffer, flushed as HTTP chunks.
// No heap, no DOM: good enough for the small API responses here.

#include <cstddef>
#include <cstdint>

#include "esp_http_server.h"

namespace sinkhole {

class JsonWriter {
public:
    explicit JsonWriter(httpd_req_t* req);

    JsonWriter& beginObject(const char* key = nullptr);
    JsonWriter& endObject();
    JsonWriter& beginArray(const char* key = nullptr);
    JsonWriter& endArray();

    JsonWriter& str(const char* key, const char* value);
    JsonWriter& num(const char* key, int64_t value);
    JsonWriter& boolean(const char* key, bool value);
    JsonWriter& ip(const char* key, uint32_t ipNetOrder);
    JsonWriter& mac(const char* key, const uint8_t mac[6]);

    esp_err_t finish();  // flush and terminate the chunked response

private:
    void prefix(const char* key);
    void raw(const char* s);
    void raw(const char* s, size_t n);
    void escaped(const char* s);
    void flush();

    httpd_req_t* req_;
    char buf_[512];
    size_t len_ = 0;
    uint32_t firstMask_ = 1;  // bit per nesting level: next item is the first
    int depth_ = 0;
    esp_err_t err_ = ESP_OK;
};

}  // namespace sinkhole
