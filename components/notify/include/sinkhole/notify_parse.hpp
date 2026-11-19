#pragma once
// Just enough JSON for the answers ntfy and the Telegram Bot API send: a few
// string and number fields, found by key. No ESP-IDF dependencies, so the host
// tests (test/host) run the same code.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace sinkhole::notify {

// One escape, p just after the backslash; moves p past it.
inline char jsonEscape(const char*& p)
{
    const char e = *p++;
    if (e == 'n') return '\n';
    if (e == 't') return '\t';
    if (e != 'u') return e;  // \" \\ \/
    if (strnlen(p, 4) < 4) return '?';
    const std::array<char, 5> hex{p[0], p[1], p[2], p[3], 0};
    p += 4;
    if (const long v = strtol(hex.data(), nullptr, 16); v > 0 && v < 128) return static_cast<char>(v);
    return '?';  // outside ASCII
}

// Copies the JSON string value at p (just after the opening quote) into out,
// decoding the common escapes (\uXXXX: ASCII kept, the rest becomes '?').
// Returns the position after the closing quote.
inline const char* jsonString(const char* p, char* out, size_t cap)
{
    size_t n = 0;
    while (*p && *p != '"') {
        char c = *p++;
        if (c == '\\' && *p) c = jsonEscape(p);
        if (n + 1 < cap) out[n++] = c;
    }
    if (cap) out[n] = '\0';
    return *p == '"' ? p + 1 : p;
}

// "key":"value" at or after from, before limit (nullptr = end of text).
inline bool jsonField(const char* from, const char* limit, const char* key, char* out, size_t cap)
{
    std::array<char, 32> pat;
    snprintf(pat.data(), pat.size(), R"("%s":")", key);
    const char* p = strstr(from, pat.data());
    if (!p || (limit && p >= limit)) return false;
    jsonString(p + strnlen(pat.data(), pat.size()), out, cap);
    return true;
}

// "key":<number> at or after from, before limit.
inline bool jsonNumber(const char* from, const char* limit, const char* key, int64_t& out)
{
    std::array<char, 32> pat;
    snprintf(pat.data(), pat.size(), R"("%s":)", key);
    const char* p = strstr(from, pat.data());
    if (!p || (limit && p >= limit)) return false;
    out = strtoll(p + strnlen(pat.data(), pat.size()), nullptr, 10);
    return true;
}

// ntfy poll answer: one JSON object per line. fn(id, event, message) per line
// (message empty when the line has none). Modifies buf (line ends).
template <typename F>
void ntfyLines(char* buf, F&& fn)
{
    for (char* line = buf; line && *line;) {
        char* end = strchr(line, '\n');
        if (end) *end = '\0';
        std::array<char, 24> id{};
        std::array<char, 24> event{};
        std::array<char, 120> text{};
        jsonField(line, nullptr, "id", id.data(), id.size());
        jsonField(line, nullptr, "event", event.data(), event.size());
        jsonField(line, nullptr, "message", text.data(), text.size());
        if (id[0]) fn(id.data(), event.data(), text.data());
        line = end ? end + 1 : nullptr;
    }
}

// Telegram getUpdates answer. fn(updateId, chatId, text) for each update that
// is a text message; returns the highest update_id seen (0 = none).
template <typename F>
int64_t telegramUpdates(const char* buf, F&& fn)
{
    int64_t last = 0;
    for (const char* p = strstr(buf, "\"update_id\":"); p;) {
        const char* next = strstr(p + 1, "\"update_id\":");
        int64_t id = 0;
        jsonNumber(p, next, "update_id", id);
        if (id > last) last = id;
        const char* chat = strstr(p, "\"chat\":{");
        int64_t chatId = 0;
        if (std::array<char, 120> text{}; chat && (!next || chat < next) && jsonNumber(chat, next, "id", chatId) &&
            jsonField(p, next, "text", text.data(), text.size()))
            fn(id, chatId, text.data());
        p = next;
    }
    return last;
}

// The chat of the newest message in a getUpdates answer (who wrote to the bot).
inline bool telegramLastChat(const char* buf, int64_t& chatId, char* name, size_t nameCap)
{
    const char* chat = nullptr;
    for (const char* p = strstr(buf, "\"chat\":{"); p; p = strstr(p + 1, "\"chat\":{")) chat = p;
    if (!chat || !jsonNumber(chat, nullptr, "id", chatId)) return false;
    if (!jsonField(chat, nullptr, "first_name", name, nameCap) && !jsonField(chat, nullptr, "title", name, nameCap) && nameCap)
        name[0] = '\0';
    return true;
}

}  // namespace sinkhole::notify
