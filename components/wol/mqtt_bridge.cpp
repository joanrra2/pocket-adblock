#include <cstdio>
#include <cstring>

#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "mqtt_client.h"
#include "sinkhole/text.hpp"
#include "sinkhole/wol.hpp"

namespace sinkhole {

namespace {
constexpr const char* TAG = "mqtt";
}

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
    snprintf(statusTopic_, sizeof(statusTopic_), "%s/status", prefix_);
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(clientId_, sizeof(clientId_), "sinkhole-%02x%02x%02x", mac[3], mac[4], mac[5]);

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
    return esp_mqtt_client_start(client);
}

void MqttBridge::onEvent(void* arg, const char* base, int32_t id, void* data)
{
    (void)base;
    static_cast<MqttBridge*>(arg)->handleEvent(id, data);
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

void MqttBridge::handleEvent(int32_t id, void* data)
{
    auto client = static_cast<esp_mqtt_client_handle_t>(client_);
    auto* ev = static_cast<esp_mqtt_event_handle_t>(data);

    if (id == MQTT_EVENT_CONNECTED) {
        connected_ = true;
        char topic[96];
        snprintf(topic, sizeof(topic), "%s/wol/+/set", prefix_);
        esp_mqtt_client_subscribe_single(client, topic, 1);
        esp_mqtt_client_publish(client, statusTopic_, "online", 0, 1, 1);
        ESP_LOGI(TAG, "connected, listening on %s", topic);
    } else if (id == MQTT_EVENT_DISCONNECTED) {
        connected_ = false;
    } else if (id == MQTT_EVENT_DATA && ev && ev->topic_len > 0) {
        // Expect "<prefix>/wol/<name>/set"
        char topic[128];
        size_t n = static_cast<size_t>(ev->topic_len) < sizeof(topic) - 1
                       ? static_cast<size_t>(ev->topic_len)
                       : sizeof(topic) - 1;
        memcpy(topic, ev->topic, n);
        topic[n] = '\0';

        const size_t plen = strlen(prefix_);
        if (strncmp(topic, prefix_, plen) != 0 || strncmp(topic + plen, "/wol/", 5) != 0) return;
        char* name = topic + plen + 5;
        char* slash = strchr(name, '/');
        if (!slash || strcmp(slash, "/set") != 0) return;
        *slash = '\0';
        esp_err_t err = wol_.wake(name);
        ESP_LOGI(TAG, "remote wake '%s': %s", name, esp_err_to_name(err));
    }
}

}  // namespace sinkhole
