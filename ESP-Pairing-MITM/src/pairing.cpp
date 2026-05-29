/*
 * pairing.cpp
 *
 * Implements the ECDH-based ESP-NOW pairing state machine.
 *
 * Security note: the PAIRING_REQUEST broadcast is sent in the clear (no
 * encryption), which is safe for ECDH because an eavesdropper who sees both
 * public keys cannot compute the shared secret without one of the private keys.
 * A man-in-the-middle attack is prevented by the requirement of physical access
 * — both devices must have "pair" typed on their serial consoles in proximity.
 */

#include "pairing.h"
#include "config.h"
#include "crypto.h"
#include "espnow_manager.h"
#include "nvs_storage.h"
#include <Arduino.h>
#include <string.h>

static pairing_state_t s_state    = PAIRING_IDLE;
static uint32_t        s_start_ms = 0;   // millis() when pairing began (for timeout)
static uint8_t         s_own_mac[6];

// The ESP-NOW broadcast address.  Every device in radio range receives frames
// sent to this destination, regardless of whether it is a registered peer.
static const uint8_t BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/*
 * finalize_pairing — shared logic run by both initiator and responder once
 * both public keys are known.
 *
 * Steps:
 *   1. Compute ECDH shared secret from the peer's public key and our private key.
 *   2. Derive PMK and LMK from the shared secret via SHA-256.
 *   3. Install the PMK globally and register the peer with its LMK.
 *   4. Persist the peer record to NVS so it survives a reboot.
 */
static void finalize_pairing(const uint8_t peer_mac[6], const uint8_t their_pub[ECDH_PUBKEY_LEN]) {
    uint8_t secret[32];
    if (!crypto_compute_shared_secret(their_pub, secret)) {
        Serial.println("[pairing] shared secret computation failed");
        s_state = PAIRING_IDLE;
        return;
    }

    uint8_t pmk[16], lmk[16];
    crypto_derive_keys(secret, pmk, lmk);

    // The PMK is a device-global setting.  Setting it here overwrites any
    // previous PMK, which is acceptable for a single-pair-at-a-time model.
    if (!espnow_set_pmk(pmk)) {
        Serial.println("[pairing] failed to set PMK");
    }

    // Register the peer with the derived LMK so subsequent frames to/from
    // this MAC are automatically encrypted/decrypted by the ESP32 hardware.
    if (!espnow_add_peer(peer_mac, lmk)) {
        Serial.println("[pairing] failed to add peer");
        s_state = PAIRING_IDLE;
        return;
    }

    // Persist peer MAC + LMK to NVS so the pairing survives power cycles.
    nvs_save_peer(peer_mac, lmk);

    Serial.printf("[pairing] Paired with %02X:%02X:%02X:%02X:%02X:%02X\n",
                  peer_mac[0], peer_mac[1], peer_mac[2],
                  peer_mac[3], peer_mac[4], peer_mac[5]);
    s_state = PAIRING_COMPLETE;
}

void pairing_init() {
    // Cache the device's own MAC so we can embed it in outgoing packets
    // without repeatedly querying the Wi-Fi driver.
    espnow_get_own_mac(s_own_mac);
    s_state = PAIRING_IDLE;
}

bool pairing_start() {
    if (s_state != PAIRING_IDLE) {
        Serial.println("[pairing] already in progress");
        return false;
    }

    // Generate a fresh ephemeral key pair for this pairing session.
    uint8_t pub[ECDH_PUBKEY_LEN];
    if (!crypto_generate_keypair(pub)) {
        Serial.println("[pairing] keypair generation failed");
        return false;
    }

    // Build and broadcast the PAIRING_REQUEST frame.  The broadcast reaches
    // all nearby ESP-NOW-capable devices; only those in PAIRING_IDLE will act.
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
            // We only respond to pairing requests when idle — this prevents
            // us from accepting a second pairing while one is already in flight.
            if (s_state != PAIRING_IDLE) return;

            Serial.printf("[pairing] Request from %02X:%02X:%02X:%02X:%02X:%02X\n",
                          src_mac[0], src_mac[1], src_mac[2],
                          src_mac[3], src_mac[4], src_mac[5]);

            // Generate our own ephemeral key pair for this session.
            uint8_t pub[ECDH_PUBKEY_LEN];
            if (!crypto_generate_keypair(pub)) {
                Serial.println("[pairing] keypair generation failed");
                return;
            }

            // Send our public key directly back to the initiator (unicast,
            // unencrypted).  We embed our own MAC so the initiator can store it.
            espnow_packet_t resp = {};
            resp.type = PKT_PAIRING_RESPONSE;
            memcpy(resp.mac, s_own_mac, 6);
            resp.payload_len = ECDH_PUBKEY_LEN;
            memcpy(resp.payload, pub, ECDH_PUBKEY_LEN);

            espnow_send_raw(src_mac, (uint8_t *)&resp, ESPNOW_PACKET_SIZE);

            // Both devices now have each other's public keys, so we can
            // compute the shared secret and finalise the pairing.
            finalize_pairing(pkt->mac, pkt->payload);

            // Inform the initiator that our side is complete.  This is sent
            // encrypted because finalize_pairing() already registered the peer.
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
            // Only the initiator (in WAIT_RESPONSE) processes this packet.
            if (s_state != PAIRING_WAIT_RESPONSE) return;

            Serial.printf("[pairing] Response from %02X:%02X:%02X:%02X:%02X:%02X\n",
                          src_mac[0], src_mac[1], src_mac[2],
                          src_mac[3], src_mac[4], src_mac[5]);

            finalize_pairing(pkt->mac, pkt->payload);
            break;
        }

        case PKT_PAIRING_CONFIRM: {
            // The responder successfully derived keys on its side.
            Serial.println("[pairing] Pairing confirmed by peer");
            s_state = PAIRING_COMPLETE;
            break;
        }

        case PKT_DATA: {
            // Normal encrypted data frame — print the sender's MAC and payload.
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
    // Called from loop() to enforce the pairing timeout without blocking.
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
