#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <strings.h>

#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "mqtt_client.h"
#include "sinkhole/text.hpp"
#include "sinkhole/wol.hpp"

namespace sinkhole {

namespace {
constexpr const char* TAG = "mqtt";
constexpr uint64_t kTickUs = 5ULL * 1000 * 1000;  // announce/refresh check
constexpr uint32_t kStatsEveryTicks = 12;         // stats every 60 s
constexpr const char* kHaPrefix = "homeassistant";
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

    auto client = esp_mqtt_client_init(&cfg);
    if (!client) return ESP_ERR_NO_MEM;
    client_ = client;
    esp_mqtt_client_register_event(client, MQTT_EVENT_ANY, &MqttBridge::onEvent, this);
    wol_.setListener(&MqttBridge::onHostState, this);
    wol_.setResultListener(&MqttBridge::onHostResult, this);

    esp_timer_create_args_t targs{};
    targs.callback = &MqttBridge::onTick;
    targs.arg = this;
    targs.name = "mqtt_tick";
    esp_timer_handle_t timer = nullptr;
    if (esp_timer_create(&targs, &timer) == ESP_OK) esp_timer_start_periodic(timer, kTickUs);
    return esp_mqtt_client_start(client);
}

void MqttBridge::onEvent(void* arg, const char* base, int32_t id, void* data)
{
    (void)base;
    static_cast<MqttBridge*>(arg)->handleEvent(id, data);
}

void MqttBridge::onTick(void* arg)
{
    static_cast<MqttBridge*>(arg)->tick();
}

void MqttBridge::onHostState(void* ctx, const char* name, bool online)
{
    auto* self = static_cast<MqttBridge*>(ctx);
    if (!self->connected_) return;
    char topic[128];
    snprintf(topic, sizeof(topic), "%s/wol/%s/state", self->prefix_, name);
    esp_mqtt_client_publish(static_cast<esp_mqtt_client_handle_t>(self->client_), topic,
                            online ? "online" : "offline", 0, 1, 1);
}

void MqttBridge::onHostResult(void* ctx, const char* name, const char* result)
{
    auto* self = static_cast<MqttBridge*>(ctx);
    if (!self->connected_) return;
    std::array<char, 128> topic{};
    snprintf(topic.data(), topic.size(), "%s/wol/%s/result", self->prefix_, name);
    self->enqueue(topic.data(), result, true);
}

void MqttBridge::enqueue(const char* topic, const char* payload, bool retain)
{
    esp_mqtt_client_enqueue(static_cast<esp_mqtt_client_handle_t>(client_), topic, payload,
                            static_cast<int>(strlen(payload)), 1, retain ? 1 : 0, true);
}

void MqttBridge::publishBlocking()
{
    if (!hooks_.blocking) return;
    const bool on = hooks_.blocking(hooks_.ctx);
    lastBlocking_ = on;
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
void MqttBridge::announce()
{
    char dev[256], topic[160];
    deviceJson(dev, sizeof(dev));

    if (hooks_.setBlocking) {
        snprintf(topic, sizeof(topic), "%s/switch/%s/blocking/config", kHaPrefix, nodeId_);
        snprintf(buf_, sizeof(buf_),
                 "{\"name\":\"Blocking\",\"uniq_id\":\"%s_blocking\",\"stat_t\":\"%s/blocking\","
                 "\"cmd_t\":\"%s/blocking/set\",\"icon\":\"mdi:shield-check\",%s}",
                 nodeId_, prefix_, prefix_, dev);
        enqueue(topic, buf_, true);
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
            snprintf(topic, sizeof(topic), "%s/sensor/%s/%s/config", kHaPrefix, nodeId_, s.id);
            snprintf(buf_, sizeof(buf_),
                     "{\"name\":\"%s\",\"uniq_id\":\"%s_%s\",\"stat_t\":\"%s/stats\","
                     "\"val_tpl\":\"{{ value_json.%s }}\",\"unit_of_meas\":\"%s\",\"stat_cla\":\"%s\","
                     "\"icon\":\"%s\",%s}",
                     s.name, nodeId_, s.id, prefix_, s.id, s.unit, s.stateClass, s.icon, dev);
            enqueue(topic, buf_, true);
        }
        // Text sensor: why the device last restarted (crash, watchdog, update...).
        snprintf(topic, sizeof(topic), "%s/sensor/%s/restart/config", kHaPrefix, nodeId_);
        snprintf(buf_, sizeof(buf_),
                 "{\"name\":\"Last restart\",\"uniq_id\":\"%s_restart\",\"stat_t\":\"%s/stats\","
                 "\"val_tpl\":\"{{ value_json.restart }}\",\"ent_cat\":\"diagnostic\",\"icon\":\"mdi:restart\",%s}",
                 nodeId_, prefix_, dev);
        enqueue(topic, buf_, true);
    }

    // One Wake button per host (+ online sensor when it has an IP). Hosts that
    // were removed get an empty retained config, which deletes the entity.
    char current[WolService::kCapacity][24] = {};
    size_t n = 0;
    wol_.forEachHost([&](const WolHost& h) {
        if (n >= WolService::kCapacity) return;
        const size_t i = n++;
        const char* name = h.name;
        objectId(name, current[i], sizeof(current[i]));
        snprintf(topic, sizeof(topic), "%s/button/%s/wol_%s/config", kHaPrefix, nodeId_, current[i]);
        snprintf(buf_, sizeof(buf_),
                 "{\"name\":\"Wake %s\",\"uniq_id\":\"%s_wol_%s\",\"cmd_t\":\"%s/wol/%s/set\","
                 "\"pl_prs\":\"wake\",\"icon\":\"mdi:power\",%s}",
                 name, nodeId_, current[i], prefix_, name, dev);
        enqueue(topic, buf_, true);
        snprintf(topic, sizeof(topic), "%s/binary_sensor/%s/wol_%s/config", kHaPrefix, nodeId_, current[i]);
        if (h.ip) {
            snprintf(buf_, sizeof(buf_),
                     "{\"name\":\"%s online\",\"uniq_id\":\"%s_wol_%s_online\",\"stat_t\":\"%s/wol/%s/state\","
                     "\"pl_on\":\"online\",\"pl_off\":\"offline\",\"dev_cla\":\"connectivity\",%s}",
                     name, nodeId_, current[i], prefix_, name, dev);
            enqueue(topic, buf_, true);
        } else {
            enqueue(topic, "", true);
        }
    });
    for (auto& old : announced_) {
        if (!old[0]) continue;
        bool still = false;
        for (size_t i = 0; i < n && !still; i++) still = strcmp(old, current[i]) == 0;
        if (still) continue;
        snprintf(topic, sizeof(topic), "%s/button/%s/wol_%s/config", kHaPrefix, nodeId_, old);
        enqueue(topic, "", true);
        snprintf(topic, sizeof(topic), "%s/binary_sensor/%s/wol_%s/config", kHaPrefix, nodeId_, old);
        enqueue(topic, "", true);
    }
    memcpy(announced_, current, sizeof(announced_));
    ESP_LOGI(TAG, "Home Assistant discovery sent (%u WoL hosts)", static_cast<unsigned>(n));
}

void MqttBridge::tick()
{
    if (!connected_) return;
    if (ha_) {
        // Re-announce when the WoL host list changed (names and IPs).
        const uint32_t h = wol_.fingerprint();
        if (announceNow_.exchange(false) || h != hostsHash_) {
            hostsHash_ = h;
            announce();
            ticks_ = kStatsEveryTicks;  // fresh states right after announcing
        }
    }
    // Switch changed elsewhere (web UI, pause ending): tell Home Assistant now.
    if (hooks_.blocking && lastBlocking_ >= 0 && hooks_.blocking(hooks_.ctx) != (lastBlocking_ == 1))
        publishBlocking();
    if (++ticks_ >= kStatsEveryTicks) {
        ticks_ = 0;
        publishBlocking();
        if (hooks_.stats) {
            hooks_.stats(hooks_.ctx, buf_, sizeof(buf_));
            char topic[80];
            snprintf(topic, sizeof(topic), "%s/stats", prefix_);
            enqueue(topic, buf_, false);
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
        announceNow_ = ha_;
        ticks_ = kStatsEveryTicks;  // publish states on the next tick
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
    }
}

}  // namespace sinkhole
