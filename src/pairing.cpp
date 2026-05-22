#include "pairing.h"
#include "config.h"
#include "crypto.h"
#include "espnow_manager.h"
#include "nvs_storage.h"
#include <Arduino.h>
#include <string.h>

static pairing_state_t s_state = PAIRING_IDLE;
static uint32_t s_start_ms = 0;
static uint8_t s_own_mac[6];

static const uint8_t BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static void finalize_pairing(const uint8_t peer_mac[6], const uint8_t their_pub[ECDH_PUBKEY_LEN]) {
    uint8_t secret[32];
    if (!crypto_compute_shared_secret(their_pub, secret)) {
        Serial.println("[pairing] shared secret computation failed");
        s_state = PAIRING_IDLE;
        return;
    }

    uint8_t pmk[16], lmk[16];
    crypto_derive_keys(secret, pmk, lmk);

    if (!espnow_set_pmk(pmk)) {
        Serial.println("[pairing] failed to set PMK");
    }

    if (!espnow_add_peer(peer_mac, lmk)) {
        Serial.println("[pairing] failed to add peer");
        s_state = PAIRING_IDLE;
        return;
    }

    nvs_save_peer(peer_mac, lmk);

    Serial.printf("[pairing] Paired with %02X:%02X:%02X:%02X:%02X:%02X\n",
                  peer_mac[0], peer_mac[1], peer_mac[2],
                  peer_mac[3], peer_mac[4], peer_mac[5]);
    s_state = PAIRING_COMPLETE;
}

void pairing_init() {
    espnow_get_own_mac(s_own_mac);
    s_state = PAIRING_IDLE;
}

bool pairing_start() {
    if (s_state != PAIRING_IDLE) {
        Serial.println("[pairing] already in progress");
        return false;
    }

    uint8_t pub[ECDH_PUBKEY_LEN];
    if (!crypto_generate_keypair(pub)) {
        Serial.println("[pairing] keypair generation failed");
        return false;
    }

    espnow_packet_t pkt = {};
    pkt.type = PKT_PAIRING_REQUEST;
    memcpy(pkt.mac, s_own_mac, 6);
    pkt.payload_len = ECDH_PUBKEY_LEN;
    memcpy(pkt.payload, pub, ECDH_PUBKEY_LEN);

    if (!espnow_send_raw(BROADCAST_MAC, (uint8_t *)&pkt, ESPNOW_PACKET_SIZE)) {
        Serial.println("[pairing] broadcast failed");
        return false;
    }

    s_state    = PAIRING_WAIT_RESPONSE;
    s_start_ms = millis();
    Serial.println("[pairing] Pairing mode started, broadcasting request...");
    return true;
}

void pairing_on_recv(const uint8_t *src_mac, const uint8_t *data, size_t len) {
    if (len < ESPNOW_PACKET_SIZE) return;
    const espnow_packet_t *pkt = (const espnow_packet_t *)data;

    switch (pkt->type) {
        case PKT_PAIRING_REQUEST: {
            if (s_state != PAIRING_IDLE) return;

            Serial.printf("[pairing] Request from %02X:%02X:%02X:%02X:%02X:%02X\n",
                          src_mac[0], src_mac[1], src_mac[2],
                          src_mac[3], src_mac[4], src_mac[5]);

            uint8_t pub[ECDH_PUBKEY_LEN];
            if (!crypto_generate_keypair(pub)) {
                Serial.println("[pairing] keypair generation failed");
                return;
            }

            // Send response directly to requester
            espnow_packet_t resp = {};
            resp.type = PKT_PAIRING_RESPONSE;
            memcpy(resp.mac, s_own_mac, 6);
            resp.payload_len = ECDH_PUBKEY_LEN;
            memcpy(resp.payload, pub, ECDH_PUBKEY_LEN);

            espnow_send_raw(src_mac, (uint8_t *)&resp, ESPNOW_PACKET_SIZE);

            finalize_pairing(pkt->mac, pkt->payload);

            // Send confirm after finalizing
            if (s_state == PAIRING_COMPLETE) {
                espnow_packet_t confirm = {};
                confirm.type = PKT_PAIRING_CONFIRM;
                memcpy(confirm.mac, s_own_mac, 6);
                confirm.payload_len = 0;
                espnow_send_raw(src_mac, (uint8_t *)&confirm, ESPNOW_PACKET_SIZE);
            }
            break;
        }

        case PKT_PAIRING_RESPONSE: {
            if (s_state != PAIRING_WAIT_RESPONSE) return;

            Serial.printf("[pairing] Response from %02X:%02X:%02X:%02X:%02X:%02X\n",
                          src_mac[0], src_mac[1], src_mac[2],
                          src_mac[3], src_mac[4], src_mac[5]);

            finalize_pairing(pkt->mac, pkt->payload);
            break;
        }

        case PKT_PAIRING_CONFIRM: {
            Serial.println("[pairing] Pairing confirmed by peer");
            s_state = PAIRING_COMPLETE;
            break;
        }

        case PKT_DATA: {
            Serial.printf("[data] From %02X:%02X:%02X:%02X:%02X:%02X: %.*s\n",
                          src_mac[0], src_mac[1], src_mac[2],
                          src_mac[3], src_mac[4], src_mac[5],
                          (int)pkt->payload_len, pkt->payload);
            break;
        }

        default:
            break;
    }
}

void pairing_tick() {
    if (s_state == PAIRING_WAIT_RESPONSE) {
        if (millis() - s_start_ms > PAIRING_TIMEOUT_MS) {
            Serial.println("[pairing] Timeout, no response received");
            s_state = PAIRING_IDLE;
        }
    }
}

pairing_state_t pairing_get_state() {
    return s_state;
}
