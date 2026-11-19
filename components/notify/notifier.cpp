#include "sinkhole/notifier.hpp"

#include <cctype>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "esp_crt_bundle.h"
#include "esp_heap_caps.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "sinkhole/notify_parse.hpp"
#include "sinkhole/text.hpp"

namespace sinkhole {

namespace {
constexpr const char* TAG = "notify";
constexpr uint32_t kPollMs = 15000;  // command check interval
constexpr UBaseType_t kQueueLen = 8;
Notifier* sSelf = nullptr;

void urlEncode(const char* in, char* out, size_t cap)
{
    static constexpr char kHex[] = "0123456789ABCDEF";
    size_t n = 0;
    for (; *in && n + 4 < cap; in++) {
        const auto c = static_cast<unsigned char>(*in);
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out[n++] = static_cast<char>(c);
        } else {
            out[n++] = '%';
            out[n++] = kHex[c >> 4];
            out[n++] = kHex[c & 15];
        }
    }
    out[n] = '\0';
}

const char* ntfyTags(uint16_t kind)
{
    switch (kind) {
        case events::Restart: return "warning";
        case events::Wake: return "computer";
        case events::HostState: return "electric_plug";
        case events::Update: return "arrows_counterclockwise";
        case events::Uplink: return "signal_strength";
        default: return "speech_balloon";
    }
}
}  // namespace

// One HTTPS client per service, kept open between requests (keep-alive).
struct Notifier::Http {
    esp_http_client_handle_t h = nullptr;

    void close()
    {
        if (h) esp_http_client_cleanup(h);
        h = nullptr;
    }

    // Returns the HTTP status (0 = no answer); the body (cut to cap - 1) in out.
    // A kept-open connection the server has meanwhile closed fails on the first
    // write: then once more on a new connection.
    int request(const char* url, esp_http_client_method_t method, const char* body, const char* contentType,
                const char* const* headers, char* out, size_t cap)
    {
        const bool reused = h != nullptr;
        const int st = attempt(url, method, body, contentType, headers, out, cap);
        return st == 0 && reused ? attempt(url, method, body, contentType, headers, out, cap) : st;
    }

    // Where the event handler puts the answer.
    struct Body {
        char* out;
        size_t cap;
        size_t len;
    };

    static esp_err_t onEvent(esp_http_client_event_t* e)
    {
        auto* b = static_cast<Body*>(e->user_data);
        if (e->event_id != HTTP_EVENT_ON_DATA || !b || b->len + 1 >= b->cap) return ESP_OK;
        size_t n = static_cast<size_t>(e->data_len);
        if (n > b->cap - 1 - b->len) n = b->cap - 1 - b->len;  // too long: the rest is dropped
        memcpy(b->out + b->len, e->data, n);
        b->len += n;
        return ESP_OK;
    }

    // perform() resets the client between requests (chunked answers included)
    // and keeps the connection for the next one.
    int attempt(const char* url, esp_http_client_method_t method, const char* body, const char* contentType,
                const char* const* headers, char* out, size_t cap)
    {
        Body b{out, cap, 0};
        if (!h) {
            esp_http_client_config_t cfg = {};
            cfg.url = url;
            cfg.timeout_ms = 10000;
            cfg.buffer_size = 1024;
            cfg.buffer_size_tx = 1024;
            cfg.crt_bundle_attach = esp_crt_bundle_attach;
            cfg.keep_alive_enable = true;
            cfg.event_handler = &Http::onEvent;
            h = esp_http_client_init(&cfg);
            if (!h) return 0;
        } else {
            esp_http_client_set_url(h, url);
        }
        esp_http_client_set_user_data(h, &b);
        esp_http_client_set_method(h, method);
        esp_http_client_delete_header(h, "Content-Type");
        if (contentType) esp_http_client_set_header(h, "Content-Type", contentType);
        for (const char* const* hd = headers; hd && *hd; hd += 2) esp_http_client_set_header(h, hd[0], hd[1]);
        esp_http_client_set_post_field(h, body, body ? static_cast<int>(strlen(body)) : 0);
        const esp_err_t err = esp_http_client_perform(h);
        esp_http_client_set_user_data(h, nullptr);
        out[b.len] = 0;
        if (err != ESP_OK) {
            close();
            return 0;
        }
        return esp_http_client_get_status_code(h);
    }
};

esp_err_t Notifier::begin(CommandHandler handler, void* ctx)  // NOSONAR context for the callback
{
    handler_ = handler;
    handlerCtx_ = ctx;
    buf_ = static_cast<char*>(heap_caps_malloc(kBufSize, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    if (!buf_) buf_ = static_cast<char*>(heap_caps_malloc(kBufSize, MALLOC_CAP_8BIT));
    queue_ = xQueueCreate(kQueueLen, sizeof(Msg));
    ntfyHttp_ = new Http();
    tgHttp_ = new Http();
    sendHttp_ = new Http();
    if (!buf_ || !queue_) return ESP_ERR_NO_MEM;
    sSelf = this;
    events::setSink(&Notifier::sink);
    return task_.start("notify", &Notifier::taskEntry, this, 3) ? ESP_OK : ESP_ERR_NO_MEM;
}

void Notifier::reload()
{
    reload_ = true;
    Msg wake{};  // nudge the task (kind 0 is dropped)
    if (queue_) xQueueSend(queue_, &wake, 0);
}

void Notifier::sink(events::Kind kind, const char* text)
{
    Notifier* self = sSelf;
    if (!self) return;
    Msg m{};
    m.kind = kind;
    copyStr(m.text.data(), m.text.size(), text);
    if (xQueueSend(self->queue_, &m, 0) != pdTRUE) {
        LockGuard g(self->mu_);
        self->status_.dropped++;
    }
}

void Notifier::test()
{
    Msg m{};
    m.kind = events::Reply;
    copyStr(m.text.data(), m.text.size(), "Test from Pocket AdBlock: notifications work.");
    if (queue_) xQueueSend(queue_, &m, 0);
}

Notifier::Status Notifier::status()
{
    LockGuard g(mu_);
    Status s = status_;
    s.queued = queue_ ? static_cast<uint32_t>(uxQueueMessagesWaiting(queue_)) : 0;
    return s;
}

void Notifier::note(ChannelStatus& st, bool ok, const char* error)
{
    LockGuard g(mu_);
    st.lastOk = ok;
    st.lastAt = uptimeSeconds();
    copyStr(st.error.data(), st.error.size(), ok ? "" : error);
}

void Notifier::loadSettings()
{
    cfg_.readNotify([this](const NotifySettings& s) {
        copyStr(c_.ntfyServer.data(), c_.ntfyServer.size(), s.ntfyServer);
        copyStr(c_.ntfyTopic.data(), c_.ntfyTopic.size(), s.ntfyTopic);
        copyStr(c_.ntfyToken.data(), c_.ntfyToken.size(), s.ntfyToken);
        copyStr(c_.tgToken.data(), c_.tgToken.size(), s.tgToken);
        copyStr(c_.tgChat.data(), c_.tgChat.size(), s.tgChat);
        c_.events = s.notifyEvents;
        c_.commands = s.notifyCommands;
        return 0;
    });
    // Strip a trailing slash from the server.
    size_t n = strnlen(c_.ntfyServer.data(), c_.ntfyServer.size());
    while (n && c_.ntfyServer[n - 1] == '/') c_.ntfyServer[--n] = '\0';
    LockGuard g(mu_);
    status_.ntfy.configured = c_.ntfyServer[0] && c_.ntfyTopic[0];
    status_.telegram.configured = c_.tgToken[0] && c_.tgChat[0];
    ntfySince_[0] = '\0';  // a new topic or chat: skip what was sent before
    tgOffset_ = 0;
}

void Notifier::taskEntry(void* arg)  // NOSONAR FreeRTOS task signature
{
    static_cast<Notifier*>(arg)->run();
}

void Notifier::run()
{
    uint32_t lastPoll = 0;
    for (;;) {
        if (reload_.exchange(false)) {
            LockGuard net(netMu_);
            loadSettings();
            ntfyHttp_->close();
            tgHttp_->close();
        }
        const bool any = status_.ntfy.configured || status_.telegram.configured;
        const bool polling = any && c_.commands;
        Msg m{};
        // Messages wait in the queue while the uplink is down.
        if (wifi_.connected() && xQueueReceive(queue_, &m, pdMS_TO_TICKS(polling ? 1000 : 5000)) == pdTRUE) {
            if (m.kind) deliver(m);
        } else if (!wifi_.connected()) {
            vTaskDelay(pdMS_TO_TICKS(2000));
            continue;
        }
        const uint32_t now = uptimeSeconds();
        if (polling && now - lastPoll >= kPollMs / 1000) {
            lastPoll = now;
            if (status_.ntfy.configured) pollNtfy();
            if (status_.telegram.configured) pollTelegram();
        }
    }
}

void Notifier::deliver(const Msg& m)
{
    if (m.kind != events::Reply && !(c_.events & m.kind)) return;
    LockGuard net(netMu_);
    if (status_.ntfy.configured && m.channel != 2) sendNtfy(m);
    if (status_.telegram.configured && m.channel != 1) sendTelegram(m.text.data());
}

bool Notifier::sendNtfy(const Msg& m)
{
    std::array<char, 128> url;
    snprintf(url.data(), url.size(), "%s/%s", c_.ntfyServer.data(), c_.ntfyTopic.data());
    std::array<char, 80> bearer{};
    if (c_.ntfyToken[0]) snprintf(bearer.data(), bearer.size(), "Bearer %s", c_.ntfyToken.data());
    const char* headers[] = {"Title", "Pocket AdBlock", "Tags", ntfyTags(m.kind),
                             c_.ntfyToken[0] ? "Authorization" : nullptr, bearer.data(), nullptr};
    const int st = sendHttp_->request(url.data(), HTTP_METHOD_POST, m.text.data(), "text/plain", headers, buf_, 512);
    sendHttp_->close();
    const bool ok = st >= 200 && st < 300;
    std::array<char, 48> why{};
    if (!ok) snprintf(why.data(), why.size(), st ? "HTTP %d" : "no connection", st);
    note(status_.ntfy, ok, why.data());
    if (!ok) ESP_LOGW(TAG, "ntfy: %s", why.data());
    return ok;
}

bool Notifier::sendTelegram(const char* text)
{
    std::array<char, 140> url;
    snprintf(url.data(), url.size(), "https://api.telegram.org/bot%s/sendMessage", c_.tgToken.data());
    std::array<char, 600> body;
    std::array<char, 500> enc;
    urlEncode(text, enc.data(), enc.size());
    snprintf(body.data(), body.size(), "chat_id=%s&text=%s", c_.tgChat.data(), enc.data());
    const int st = sendHttp_->request(url.data(), HTTP_METHOD_POST, body.data(), "application/x-www-form-urlencoded",
                                      nullptr, buf_, 512);
    sendHttp_->close();
    const bool ok = st == 200;
    std::array<char, 48> why{};
    if (!ok) {
        if (st == 401 || st == 404) copyStr(why.data(), why.size(), "bot token not accepted");
        else if (st == 400 || st == 403) copyStr(why.data(), why.size(), "chat not found: send /start to the bot");
        else snprintf(why.data(), why.size(), st ? "HTTP %d" : "no connection", st);
        ESP_LOGW(TAG, "telegram: %s", why.data());
    }
    note(status_.telegram, ok, why.data());
    return ok;
}

// Commands are messages published to <topic>-cmd. The first poll only finds
// where we are (older messages are not run).
void Notifier::pollNtfy()
{
    LockGuard net(netMu_);
    std::array<char, 160> url;
    snprintf(url.data(), url.size(), "%s/%s-cmd/json?poll=1&since=%s", c_.ntfyServer.data(), c_.ntfyTopic.data(),
             ntfySince_[0] ? ntfySince_.data() : "all");
    std::array<char, 80> bearer{};
    if (c_.ntfyToken[0]) snprintf(bearer.data(), bearer.size(), "Bearer %s", c_.ntfyToken.data());
    const char* headers[] = {c_.ntfyToken[0] ? "Authorization" : nullptr, bearer.data(), nullptr};
    const int st = ntfyHttp_->request(url.data(), HTTP_METHOD_GET, nullptr, nullptr, headers, buf_, kBufSize);
    if (st != 200) return;
    const bool first = !ntfySince_[0];
    notify::ntfyLines(buf_, [this, first](const char* id, const char* event, const char* text) {
        copyStr(ntfySince_.data(), ntfySince_.size(), id);
        // Messages published in the same second can come back on the next
        // poll too: run each id once.
        bool seen = false;
        for (const auto& r : ranIds_) seen |= strcmp(r.data(), id) == 0;
        if (first || seen || strcmp(event, "message") != 0 || !text[0]) return;
        copyStr(ranIds_[ranNext_].data(), ranIds_[ranNext_].size(), id);
        ranNext_ = (ranNext_ + 1) % ranIds_.size();
        runCommand(1, text);
    });
    if (first && !ntfySince_[0]) {
        // Nothing there yet: from now on, ask for messages newer than this poll.
        snprintf(ntfySince_.data(), ntfySince_.size(), "%" PRIu32, static_cast<uint32_t>(time(nullptr)));
    }
}

void Notifier::pollTelegram()
{
    LockGuard net(netMu_);
    std::array<char, 180> url;
    // offset -1: only the newest update, to learn where we are without running old commands.
    snprintf(url.data(), url.size(), "https://api.telegram.org/bot%s/getUpdates?timeout=0&limit=5&offset=%" PRId64,
             c_.tgToken.data(), tgOffset_ ? tgOffset_ : static_cast<int64_t>(-1));
    const int st = tgHttp_->request(url.data(), HTTP_METHOD_GET, nullptr, nullptr, nullptr, buf_, kBufSize);
    if (st != 200) {
        if (st == 401 || st == 404) note(status_.telegram, false, "bot token not accepted");
        return;
    }
    const bool first = tgOffset_ == 0;
    const int64_t last = notify::telegramUpdates(buf_, [this, first](int64_t, int64_t chatId, const char* text) {
        if (first) return;
        std::array<char, 24> from{};
        snprintf(from.data(), from.size(), "%" PRId64, chatId);
        // Only the configured chat may send commands.
        if (strcmp(from.data(), c_.tgChat.data()) == 0) runCommand(2, text);
        else ESP_LOGW(TAG, "telegram: ignored a message from another chat");
    });
    if (last) tgOffset_ = last + 1;
    else if (first) tgOffset_ = 1;
}

void Notifier::runCommand(uint8_t channel, const char* text)
{
    {
        LockGuard g(mu_);
        copyStr(status_.lastCommand.data(), status_.lastCommand.size(), text);
        status_.lastCommandAt = uptimeSeconds();
    }
    ESP_LOGI(TAG, "command from %s: %s", channel == 1 ? "ntfy" : "telegram", text);
    Msg reply{};
    reply.kind = events::Reply;
    reply.channel = channel;
    if (handler_) handler_(handlerCtx_, text, reply.text.data(), reply.text.size());
    if (reply.text[0]) xQueueSend(queue_, &reply, 0);
}

esp_err_t Notifier::findTelegramChat(char* chatId, size_t idCap, char* name, size_t nameCap)
{
    std::array<char, 64> token{};
    cfg_.readNotify([&token](const NotifySettings& s) {
        copyStr(token.data(), token.size(), s.tgToken);
        return 0;
    });
    if (!token[0]) return ESP_ERR_INVALID_STATE;
    LockGuard net(netMu_);
    std::array<char, 160> url;
    snprintf(url.data(), url.size(), "https://api.telegram.org/bot%s/getUpdates?timeout=0&limit=20", token.data());
    const int st = tgHttp_->request(url.data(), HTTP_METHOD_GET, nullptr, nullptr, nullptr, buf_, kBufSize);
    if (st == 401 || st == 404) return ESP_ERR_INVALID_ARG;
    if (st != 200) return ESP_FAIL;
    int64_t id = 0;
    if (!notify::telegramLastChat(buf_, id, name, nameCap)) return ESP_ERR_NOT_FOUND;
    snprintf(chatId, idCap, "%" PRId64, id);
    return ESP_OK;
}

}  // namespace sinkhole
