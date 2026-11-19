#pragma once
// Phone notifications and remote commands over ntfy and/or Telegram (Pro
// builds: CONFIG_SINKHOLE_NOTIFY). Outbound HTTPS only, no open ports.
//
//   ntfy:     alerts are published to <server>/<topic>; commands are read from
//             <server>/<topic>-cmd (polled). The topic is the secret: make it
//             long and random (the UI generates one), or protect it with a token.
//   Telegram: alerts go to one chat through your bot; commands are read with
//             getUpdates and accepted from that chat only.
//
// Commands (only when "accept commands" is on): help, status, hosts,
// wake NAME, cancel NAME, pause [minutes], resume. NAME must be a saved
// Wake-on-LAN host; nothing else on the device can be changed this way.
//
// One task does all the networking, one request at a time, keeping at most
// one HTTPS connection per service open (~30 KB of internal RAM each).

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "sinkhole/config.hpp"
#include "sinkhole/events.hpp"
#include "sinkhole/rtos.hpp"
#include "sinkhole/wifi_manager.hpp"

namespace sinkhole {

class Notifier {
public:
    // Runs a remote command; writes the answer to reply.
    using CommandHandler = void (*)(void* ctx, const char* command, char* reply, size_t cap);  // NOSONAR C-style callback, no heap

    Notifier(Config& cfg, WifiManager& wifi) : cfg_(cfg), wifi_(wifi) {}
    esp_err_t begin(CommandHandler handler, void* ctx);  // NOSONAR context for the callback
    void reload();  // settings changed: reconnect, re-read the topic / chat

    // Queues a test message to every configured service.
    void test();
    // Telegram: the chat that last wrote to the bot (after the owner sent it
    // /start), so the UI can fill in the chat ID. Runs in the caller's task,
    // between the notifier's own requests. ESP_ERR_NOT_FOUND: nobody wrote yet.
    esp_err_t findTelegramChat(char* chatId, size_t idCap, char* name, size_t nameCap);

    struct ChannelStatus {
        bool configured;
        bool lastOk;
        uint32_t lastAt;  // uptime s, 0 = nothing sent yet
        std::array<char, 48> error{};
    };
    struct Status {
        ChannelStatus ntfy;
        ChannelStatus telegram;
        std::array<char, 48> lastCommand{};
        uint32_t lastCommandAt;
        uint32_t queued;
        uint32_t dropped;
    };
    Status status();

private:
    struct Msg {
        uint16_t kind;
        uint8_t channel;  // 0 = every service, 1 = ntfy, 2 = Telegram (command replies)
        std::array<char, 161> text;
    };
    struct Http;  // one HTTPS client per service

    static void sink(events::Kind kind, const char* text);
    static void taskEntry(void* arg);  // NOSONAR FreeRTOS task signature
    void run();
    void loadSettings();
    void deliver(const Msg& m);
    bool sendNtfy(const Msg& m);
    bool sendTelegram(const char* text);
    void pollNtfy();
    void pollTelegram();
    void runCommand(uint8_t channel, const char* text);
    void note(ChannelStatus& st, bool ok, const char* error);

    Config& cfg_;
    WifiManager& wifi_;
    CommandHandler handler_ = nullptr;
    void* handlerCtx_ = nullptr;  // NOSONAR context for the callback
    QueueHandle_t queue_ = nullptr;
    Mutex mu_;        // status_, settings copy
    Mutex netMu_;     // one HTTPS request at a time (task + findTelegramChat)
    Status status_{};
    std::atomic<bool> reload_{true};

    // Settings copy (task only, refreshed on reload).
    struct Cfg {
        std::array<char, 64> ntfyServer;
        std::array<char, 40> ntfyTopic;
        std::array<char, 64> ntfyToken;
        std::array<char, 64> tgToken;
        std::array<char, 24> tgChat;
        uint16_t events;
        bool commands;
    } c_{};
    std::array<char, 24> ntfySince_{};  // last command id seen ("" = not polled yet)
    std::array<std::array<char, 24>, 8> ranIds_{};  // ntfy ids of the last commands run
    size_t ranNext_ = 0;
    int64_t tgOffset_ = 0;              // next getUpdates offset (0 = not polled yet)
    Http* ntfyHttp_ = nullptr;
    Http* tgHttp_ = nullptr;
    // Sends use their own client, closed after each message: a client that has
    // sent a POST came back empty on later polls (esp_http_client, keep-alive).
    Http* sendHttp_ = nullptr;
    char* buf_ = nullptr;  // response buffer (PSRAM when there is some)
    static constexpr size_t kBufSize = 6144;
    StaticTask<6144> task_;
};

}  // namespace sinkhole
