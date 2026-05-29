/*
 * espnow_manager.cpp
 *
 * Implements the ESP-NOW radio abstraction.  The Wi-Fi driver must be running
 * (even in STA mode with no AP association) before esp_now_init() can be
 * called — that is why WiFi.mode(WIFI_STA) appears in the init function.
 */

#include "espnow_manager.h"
#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
#include <string.h>

// Single receive callback registered by the application layer (pairing module).
static espnow_recv_cb_t s_recv_cb = nullptr;

/*
 * on_recv — internal ESP-NOW receive callback.
 *
 * The ESP-NOW stack calls this on every received frame.  We drop frames that
 * are shorter than our fixed packet size to guard against malformed input,
 * then forward to the application callback with the sender's MAC and a typed
 * pointer to the packet.
 */
static void on_recv(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
    if (!s_recv_cb || len < (int)ESPNOW_PACKET_SIZE) return;
    s_recv_cb(info->src_addr, (const espnow_packet_t *)data);
}

/*
 * on_send — internal ESP-NOW send-status callback.
 *
 * Called after each esp_now_send() attempt.  We only log failures; success
 * is the common case and does not need to be surfaced.
 */
static void on_send(const uint8_t *mac, esp_now_send_status_t status) {
    if (status != ESP_NOW_SEND_SUCCESS) {
        Serial.printf("[espnow] send to %02X:%02X:%02X:%02X:%02X:%02X failed\n",
                      mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
}

bool espnow_manager_init(espnow_recv_cb_t recv_cb) {
    s_recv_cb = recv_cb;

    // ESP-NOW requires the Wi-Fi subsystem to be up.  Station mode keeps the
    // radio active without needing an associated access point.
    // WiFi.disconnect() clears any previous association state.
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
    // The PMK is used by the ESP32 hardware to encrypt the stored LMKs.
    // It must be set to the same value on both devices before encrypted
    // frames can be exchanged.
    return esp_now_set_pmk(pmk) == ESP_OK;
}

bool espnow_add_peer(const uint8_t mac[6], const uint8_t lmk[16]) {
    // Remove any stale entry for this MAC so we can re-add with fresh keys.
    // esp_now_add_peer() fails if the peer already exists.
    if (esp_now_is_peer_exist(mac)) {
        esp_now_del_peer(mac);
    }

    esp_now_peer_info_t peer = {};
    memcpy(peer.peer_addr, mac, 6);
    peer.channel = ESPNOW_CHANNEL;
    peer.ifidx   = WIFI_IF_STA;

    if (lmk) {
        // Encrypted peer: install the per-peer LMK so the hardware can
        // encrypt/decrypt frames to/from this device automatically.
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
    // During pairing the peer is not yet in the peer table, so we add it as
    // an unencrypted entry on the fly.  The broadcast address (FF:...:FF) also
    // needs to be in the table before we can send to it.
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
    // Walk the ESP-NOW peer table and send to every entry that has encryption
    // enabled (i.e., every device we have successfully paired with).
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
    // Returns the STA-mode MAC address, which is what ESP-NOW uses as the
    // source address for outgoing frames.
    WiFi.macAddress(mac_out);
}
