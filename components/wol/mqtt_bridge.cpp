#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <strings.h>

#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mqtt_client.h"
#include "sinkhole/text.hpp"
#include "sinkhole/wol.hpp"

namespace sinkhole {

namespace {
constexpr const char* TAG = "mqtt";
constexpr uint32_t kTickMs = 5000;         // announce/refresh check
constexpr uint32_t kStatsEveryTicks = 12;  // stats every 60 s
constexpr const char* kHaPrefix = "homeassistant";
// Every queued QoS 1 message is a heap copy kept until the broker acks it.
// The limit bounds that heap; bulk messages (discovery) wait for the queue to
// drain below kPaceBytes, so state changes and wake results keep room.
constexpr uint64_t kOutboxLimit = 8 * 1024;
constexpr int kPaceBytes = 4 * 1024;
constexpr int kPaceWaits = 100;  // x 100 ms: give up on a broker that stopped acking
// Discovery + stats: one 768-byte payload and snprintf; measured on the S3.
constexpr uint32_t kTaskStack = 3072;
}  // namespace

esp_err_t MqttBridge::start()
{
    const Settings s = cfg_.get();
    if (!s.mqttUri[0]) {
        ESP_LOGI(TAG, "no broker configured, remote wake disabled");
        return ESP_OK;
    }
    copyStr(uri_, s.mqttUri);
    copyStr(user_, s.mqttUser);
    copyStr(pass_, s.mqttPass);
    copyStr(prefix_, s.mqttPrefix[0] ? s.mqttPrefix : "sinkhole");
    copyStr(hostname_, s.hostname);
    ha_ = s.haDiscovery;
    snprintf(statusTopic_, sizeof(statusTopic_), "%s/status", prefix_);
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(clientId_, sizeof(clientId_), "sinkhole-%02x%02x%02x", mac[3], mac[4], mac[5]);
    snprintf(nodeId_, sizeof(nodeId_), "pocketadblock_%02x%02x%02x", mac[3], mac[4], mac[5]);

    esp_mqtt_client_config_t cfg = {};
    cfg.broker.address.uri = uri_;
    cfg.broker.verification.crt_bundle_attach = esp_crt_bundle_attach;
    cfg.credentials.client_id = clientId_;
    if (user_[0]) cfg.credentials.username = user_;
    if (pass_[0]) cfg.credentials.authentication.password = pass_;
    cfg.session.last_will.topic = statusTopic_;
    cfg.session.last_will.msg = "offline";
    cfg.session.last_will.qos = 1;
    cfg.session.last_will.retain = 1;
    cfg.session.keepalive = 60;
    cfg.outbox.limit = kOutboxLimit;

    auto client = esp_mqtt_client_init(&cfg);
    if (!client) return ESP_ERR_NO_MEM;
    client_ = client;
    esp_mqtt_client_register_event(client, MQTT_EVENT_ANY, &MqttBridge::onEvent, this);

    // Discovery, stats and the switch state are published from a task of
    // their own, not an esp_timer callback: they wait for the MQTT client lock
    // (held while it reconnects) and for the outbox to drain, which would
    // stall every other timer (LED, Wi-Fi retry, restart). Created here, at
    // boot and only with a broker set, so boards without MQTT keep the RAM.
    TaskHandle_t task = nullptr;
    if (xTaskCreate(&MqttBridge::taskEntry, "mqtt_pub", kTaskStack, this, 2, &task) == pdPASS)
        task_ = task;
    else
        ESP_LOGE(TAG, "no memory for the publisher task: no discovery or stats");
    return esp_mqtt_client_start(client);
}

void MqttBridge::onEvent(void* arg, const char* base, int32_t id, void* data)
{
    (void)base;
    static_cast<MqttBridge*>(arg)->handleEvent(id, data);
}

void MqttBridge::taskEntry(void* arg)  // NOSONAR FreeRTOS task entry: the signature takes void*
{
    auto* self = static_cast<MqttBridge*>(arg);
    for (;;) {
        // Woken early on connect, so Home Assistant gets the entities at once.
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(kTickMs));
        self->tick();
    }
}

void MqttBridge::onHostState(void* ctx, const char* name, bool online)  // NOSONAR C-style listener signature
{
    auto* self = static_cast<MqttBridge*>(ctx);
    if (!self->connected_) return;
    std::array<char, 128> topic{};
    snprintf(topic.data(), topic.size(), "%s/wol/%s/state", self->prefix_, name);
    // Queued, not published here: this runs on the probe task's small stack,
    // and a publish would write to TLS and wait for a reconnect.
    self->enqueue(topic.data(), online ? "online" : "offline", true);
}

void MqttBridge::onHostResult(void* ctx, const char* name, const char* result)  // NOSONAR C-style listener signature
{
    auto* self = static_cast<MqttBridge*>(ctx);
    if (!self->connected_) return;
    std::array<char, 128> topic{};
    snprintf(topic.data(), topic.size(), "%s/wol/%s/result", self->prefix_, name);
    self->enqueue(topic.data(), result, true);
}

// Retained "watch only" results for hosts without a MAC, on every connect:
// a result set while offline (or before boot) must still reach the broker.
bool MqttBridge::publishWatchOnly()
{
    WolHost h{};
    for (size_t i = 0; wol_.hostAt(i, h); i++) {
        if (!watchOnly(h)) continue;
        snprintf(pub_.topic.data(), pub_.topic.size(), "%s/wol/%s/result", prefix_, h.name);
        if (!paced(pub_.topic.data(), kWatchOnlyResult)) return false;
    }
    return true;
}

bool MqttBridge::enqueue(const char* topic, const char* payload, bool retain)
{
    const int id = esp_mqtt_client_enqueue(static_cast<esp_mqtt_client_handle_t>(client_), topic, payload,
                                           static_cast<int>(strlen(payload)), 1, retain ? 1 : 0, true);
    if (id == -2) ESP_LOGW(TAG, "queue full, not sent: %s", topic);
    return id >= 0;
}

// Waits for the outbox to drain below kPaceBytes, then queues. False when the
// broker went away or stopped acking: the caller retries the whole batch later.
bool MqttBridge::paced(const char* topic, const char* payload)
{
    auto client = static_cast<esp_mqtt_client_handle_t>(client_);
    for (int i = 0; i < kPaceWaits; i++) {
        if (!connected_) return false;
        if (esp_mqtt_client_get_outbox_size(client) <= kPaceBytes) return enqueue(topic, payload, true);
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    ESP_LOGW(TAG, "broker is not acking, will retry");
    return false;
}

void MqttBridge::publishBlocking()
{
    if (!hooks_.blocking) return;
    const bool on = hooks_.blocking(hooks_.ctx);
    pub_.lastBlocking = on;
    char topic[80];
    snprintf(topic, sizeof(topic), "%s/blocking", prefix_);
    enqueue(topic, on ? "ON" : "OFF", true);
}

// "Office PC" -> "office_pc": Home Assistant object ids are [a-z0-9_].
void MqttBridge::objectId(const char* name, char* out, size_t cap)
{
    size_t n = 0;
    for (; *name && n + 1 < cap; name++) {
        const unsigned char c = static_cast<unsigned char>(*name);
        out[n++] = isalnum(c) ? static_cast<char>(tolower(c)) : '_';
    }
    out[n] = '\0';
}

void MqttBridge::deviceJson(char* out, size_t cap)
{
    snprintf(out, cap,
             "\"avty_t\":\"%s\",\"dev\":{\"ids\":[\"%s\"],\"name\":\"Pocket AdBlock\",\"mf\":\"Pocket AdBlock\","
             "\"mdl\":\"%s\",\"sw\":\"%s\",\"cu\":\"http://%s.local/\"}",  // NOSONAR the device UI is plain HTTP on the LAN (TLS would cost ~40 KB RAM)
             statusTopic_, nodeId_, hooks_.model, hooks_.version, hostname_);
}

// Retained discovery configs. Home Assistant creates the entities, and
// re-creates them whenever it restarts (it reads the retained messages).
// Paced: false when the broker went away part way (retried as a whole).
bool MqttBridge::announce()
{
    deviceJson(pub_.dev.data(), pub_.dev.size());

    if (hooks_.setBlocking) {
        snprintf(pub_.topic.data(), pub_.topic.size(), "%s/switch/%s/blocking/config", kHaPrefix, nodeId_);
        snprintf(pub_.buf.data(), pub_.buf.size(),
                 "{\"name\":\"Blocking\",\"uniq_id\":\"%s_blocking\",\"stat_t\":\"%s/blocking\","
                 "\"cmd_t\":\"%s/blocking/set\",\"icon\":\"mdi:shield-check\",%s}",
                 nodeId_, prefix_, prefix_, pub_.dev.data());
        if (!paced(pub_.topic.data(), pub_.buf.data())) return false;
    }
    if (hooks_.stats) {
        struct Sensor {
            const char* id;
            const char* name;
            const char* unit;
            const char* stateClass;
            const char* icon;
        };
        static constexpr Sensor kSensors[] = {
            {"blocked", "Queries blocked", "queries", "total_increasing", "mdi:shield-off"},
            {"allowed", "Queries allowed", "queries", "total_increasing", "mdi:check-network"},
            {"percent", "Blocked share", "%", "measurement", "mdi:percent"},
            {"domains", "Blocklist domains", "domains", "measurement", "mdi:format-list-bulleted"},
            {"clients", "Active clients", "clients", "measurement", "mdi:devices"},
            {"uptime", "Uptime", "s", "measurement", "mdi:timer-outline"},
        };
        for (const Sensor& s : kSensors) {
            snprintf(pub_.topic.data(), pub_.topic.size(), "%s/sensor/%s/%s/config", kHaPrefix, nodeId_, s.id);
            snprintf(pub_.buf.data(), pub_.buf.size(),
                     "{\"name\":\"%s\",\"uniq_id\":\"%s_%s\",\"stat_t\":\"%s/stats\","
                     "\"val_tpl\":\"{{ value_json.%s }}\",\"unit_of_meas\":\"%s\",\"stat_cla\":\"%s\","
                     "\"icon\":\"%s\",%s}",
                     s.name, nodeId_, s.id, prefix_, s.id, s.unit, s.stateClass, s.icon, pub_.dev.data());
            if (!paced(pub_.topic.data(), pub_.buf.data())) return false;
        }
        // Text sensor: why the device last restarted (crash, watchdog, update...).
        snprintf(pub_.topic.data(), pub_.topic.size(), "%s/sensor/%s/restart/config", kHaPrefix, nodeId_);
        snprintf(pub_.buf.data(), pub_.buf.size(),
                 "{\"name\":\"Last restart\",\"uniq_id\":\"%s_restart\",\"stat_t\":\"%s/stats\","
                 "\"val_tpl\":\"{{ value_json.restart }}\",\"ent_cat\":\"diagnostic\",\"icon\":\"mdi:restart\",%s}",
                 nodeId_, prefix_, pub_.dev.data());
        if (!paced(pub_.topic.data(), pub_.buf.data())) return false;
    }

    // Hosts are copied one at a time (hostAt): pacing waits, and must not
    // hold the WoL lock (the probe and the web UI need it) while it does.
    std::array<char, 24> id{};
    WolHost h{};
    // Hosts that were removed get an empty retained config, which deletes
    // the entity. Done first: the loop below overwrites pub_.announced.
    for (const auto& old : pub_.announced) {
        if (!old[0]) continue;
        bool still = false;
        for (size_t i = 0; !still && wol_.hostAt(i, h); i++) {
            objectId(h.name, id.data(), id.size());
            still = strcmp(old.data(), id.data()) == 0;
        }
        if (still) continue;
        snprintf(pub_.topic.data(), pub_.topic.size(), "%s/button/%s/wol_%.23s/config", kHaPrefix, nodeId_, old.data());
        if (!paced(pub_.topic.data(), "")) return false;
        snprintf(pub_.topic.data(), pub_.topic.size(), "%s/binary_sensor/%s/wol_%.23s/config", kHaPrefix, nodeId_, old.data());
        if (!paced(pub_.topic.data(), "")) return false;
    }

    // One Wake button per host (+ online sensor when it has an IP).
    size_t n = 0;
    for (; n < WolService::kCapacity && wol_.hostAt(n, h); n++) {
        objectId(h.name, pub_.announced[n].data(), pub_.announced[n].size());
        const char* oid = pub_.announced[n].data();
        snprintf(pub_.topic.data(), pub_.topic.size(), "%s/button/%s/wol_%s/config", kHaPrefix, nodeId_, oid);
        if (watchOnly(h)) {
            pub_.buf[0] = '\0';  // nothing to wake: no button
        } else {
            snprintf(pub_.buf.data(), pub_.buf.size(),
                     "{\"name\":\"Wake %s\",\"uniq_id\":\"%s_wol_%s\",\"cmd_t\":\"%s/wol/%s/set\","
                     "\"pl_prs\":\"wake\",\"icon\":\"mdi:power\",%s}",
                     h.name, nodeId_, oid, prefix_, h.name, pub_.dev.data());
        }
        if (!paced(pub_.topic.data(), pub_.buf.data())) return false;
        snprintf(pub_.topic.data(), pub_.topic.size(), "%s/binary_sensor/%s/wol_%s/config", kHaPrefix, nodeId_, oid);
        if (h.ip) {
            snprintf(pub_.buf.data(), pub_.buf.size(),
                     "{\"name\":\"%s online\",\"uniq_id\":\"%s_wol_%s_online\",\"stat_t\":\"%s/wol/%s/state\","
                     "\"pl_on\":\"online\",\"pl_off\":\"offline\",\"dev_cla\":\"connectivity\",%s}",
                     h.name, nodeId_, oid, prefix_, h.name, pub_.dev.data());
        } else {
            pub_.buf[0] = '\0';
        }
        if (!paced(pub_.topic.data(), pub_.buf.data())) return false;
    }
    for (size_t i = n; i < WolService::kCapacity; i++) pub_.announced[i][0] = '\0';
    ESP_LOGI(TAG, "Home Assistant discovery sent (%u WoL hosts)", static_cast<unsigned>(n));
    return true;
}

void MqttBridge::tick()
{
    if (!connected_) return;
    if (watchOnlyNow_.exchange(false) && !publishWatchOnly()) watchOnlyNow_ = true;
    if (ha_) {
        // Re-announce when the WoL host list changed (names and IPs).
        const uint32_t h = wol_.fingerprint();
        if (announceNow_.exchange(false) || h != pub_.hostsHash) {
            if (announce()) {
                pub_.hostsHash = h;
                statsNow_ = true;  // fresh states right after announcing
            } else {
                announceNow_ = true;  // broker gone or slow: again on the next tick
            }
        }
    }
    // Switch changed elsewhere (web UI, pause ending): tell Home Assistant now.
    if (hooks_.blocking && pub_.lastBlocking >= 0 && hooks_.blocking(hooks_.ctx) != (pub_.lastBlocking == 1))
        publishBlocking();
    ++pub_.ticks;
    if (statsNow_.exchange(false) || pub_.ticks >= kStatsEveryTicks) {
        pub_.ticks = 0;
        publishBlocking();
        if (hooks_.stats) {
            hooks_.stats(hooks_.ctx, pub_.buf.data(), pub_.buf.size());
            snprintf(pub_.topic.data(), pub_.topic.size(), "%s/stats", prefix_);
            enqueue(pub_.topic.data(), pub_.buf.data(), false);
        }
    }
}

void MqttBridge::handleEvent(int32_t id, void* data)
{
    auto client = static_cast<esp_mqtt_client_handle_t>(client_);
    auto* ev = static_cast<esp_mqtt_event_handle_t>(data);

    if (id == MQTT_EVENT_CONNECTED) {
        connected_ = true;
        char topic[96];
        snprintf(topic, sizeof(topic), "%s/wol/+/set", prefix_);
        esp_mqtt_client_subscribe_single(client, topic, 1);
        if (hooks_.setBlocking) {
            snprintf(topic, sizeof(topic), "%s/blocking/set", prefix_);
            esp_mqtt_client_subscribe_single(client, topic, 1);
        }
        esp_mqtt_client_publish(client, statusTopic_, "online", 0, 1, 1);
        // The rest is bulk: the publisher task sends it, paced.
        watchOnlyNow_ = true;
        announceNow_ = ha_;
        statsNow_ = true;
        if (task_) xTaskNotifyGive(task_);
        ESP_LOGI(TAG, "connected%s", ha_ ? ", Home Assistant discovery on" : "");
    } else if (id == MQTT_EVENT_DISCONNECTED) {
        connected_ = false;
    } else if (id == MQTT_EVENT_DATA && ev && ev->topic_len > 0) {
        char topic[128];
        size_t n = static_cast<size_t>(ev->topic_len) < sizeof(topic) - 1
                       ? static_cast<size_t>(ev->topic_len)
                       : sizeof(topic) - 1;
        memcpy(topic, ev->topic, n);
        topic[n] = '\0';

        const size_t plen = strlen(prefix_);
        if (strncmp(topic, prefix_, plen) != 0) return;
        const char* rest = topic + plen;

        // "<prefix>/blocking/set" with ON / OFF (Home Assistant switch)
        if (strcmp(rest, "/blocking/set") == 0 && hooks_.setBlocking) {
            const bool on = (ev->data_len >= 2 && strncasecmp(ev->data, "ON", 2) == 0) ||
                            (ev->data_len >= 1 && ev->data[0] == '1');
            hooks_.setBlocking(hooks_.ctx, on);
            char st[80];
            snprintf(st, sizeof(st), "%s/blocking", prefix_);
            esp_mqtt_client_publish(client, st, on ? "ON" : "OFF", 0, 1, 1);
            ESP_LOGI(TAG, "remote blocking %s", on ? "on" : "off");
            return;
        }
        // "<prefix>/wol/<name>/set"
        if (strncmp(rest, "/wol/", 5) != 0) return;
        char* name = topic + plen + 5;
        char* slash = strchr(name, '/');
        if (!slash || strcmp(slash, "/set") != 0) return;
        *slash = '\0';
        if (ev->data_len == 6 && strncasecmp(ev->data, "cancel", 6) == 0) {
            esp_err_t err = wol_.cancel(name);
            ESP_LOGI(TAG, "remote cancel '%s': %s", name, esp_err_to_name(err));
            return;
        }
        esp_err_t err = wol_.wakeAndVerify(name);
        ESP_LOGI(TAG, "remote wake '%s': %s", name, esp_err_to_name(err));
        if (err == ESP_ERR_NOT_SUPPORTED) {  // watch-only: say so instead of staying silent
            std::array<char, 128> result{};
            snprintf(result.data(), result.size(), "%s/wol/%s/result", prefix_, name);
            enqueue(result.data(), kWatchOnlyResult, true);
        }
    }
}

}  // namespace sinkhole
