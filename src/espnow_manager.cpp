#include "espnow_manager.h"
#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
#include <string.h>

static espnow_recv_cb_t s_recv_cb = nullptr;

static void on_recv(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
    if (!s_recv_cb || len < (int)ESPNOW_PACKET_SIZE) return;
    s_recv_cb(info->src_addr, (const espnow_packet_t *)data);
}

static void on_send(const uint8_t *mac, esp_now_send_status_t status) {
    if (status != ESP_NOW_SEND_SUCCESS) {
        Serial.printf("[espnow] send to %02X:%02X:%02X:%02X:%02X:%02X failed\n",
                      mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
}

bool espnow_manager_init(espnow_recv_cb_t recv_cb) {
    s_recv_cb = recv_cb;

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();

    if (esp_now_init() != ESP_OK) {
        Serial.println("[espnow] init failed");
        return false;
    }

    esp_now_register_recv_cb(on_recv);
    esp_now_register_send_cb(on_send);
    return true;
}

bool espnow_set_pmk(const uint8_t pmk[16]) {
    return esp_now_set_pmk(pmk) == ESP_OK;
}

bool espnow_add_peer(const uint8_t mac[6], const uint8_t lmk[16]) {
    if (esp_now_is_peer_exist(mac)) {
        esp_now_del_peer(mac);
    }

    esp_now_peer_info_t peer = {};
    memcpy(peer.peer_addr, mac, 6);
    peer.channel = ESPNOW_CHANNEL;
    peer.ifidx   = WIFI_IF_STA;
    if (lmk) {
        peer.encrypt = true;
        memcpy(peer.lmk, lmk, 16);
    } else {
        peer.encrypt = false;
    }

    esp_err_t err = esp_now_add_peer(&peer);
    if (err != ESP_OK) {
        Serial.printf("[espnow] add_peer failed: %d\n", err);
        return false;
    }
    return true;
}

bool espnow_send_raw(const uint8_t dest_mac[6], const uint8_t *data, size_t len) {
    // Add as unencrypted peer temporarily if not already known
    if (!esp_now_is_peer_exist(dest_mac)) {
        esp_now_peer_info_t peer = {};
        memcpy(peer.peer_addr, dest_mac, 6);
        peer.channel = ESPNOW_CHANNEL;
        peer.ifidx   = WIFI_IF_STA;
        peer.encrypt = false;
        esp_now_add_peer(&peer);
    }
    return esp_now_send(dest_mac, data, len) == ESP_OK;
}

bool espnow_send_to_all_encrypted(const uint8_t *data, size_t len) {
    bool sent = false;
    esp_now_peer_info_t pi;
    bool first = true;
    while (esp_now_fetch_peer(first, &pi) == ESP_OK) {
        first = false;
        if (pi.encrypt) {
            esp_now_send(pi.peer_addr, data, len);
            sent = true;
        }
    }
    return sent;
}

void espnow_get_own_mac(uint8_t mac_out[6]) {
    WiFi.macAddress(mac_out);
}
