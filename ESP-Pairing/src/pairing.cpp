/*
 * pairing.cpp
 *
 * Implements the ECDH-based ESP-NOW pairing state machine with out-of-band
 * fingerprint verification to defeat man-in-the-middle attacks.
 *
 * Security note: PAIRING_REQUEST and PAIRING_RESPONSE frames are sent
 * unencrypted because no shared key yet exists.  A passive eavesdropper who
 * sees both public keys cannot derive the shared secret (ECDH hardness
 * assumption).  However, an active MITM can intercept and replace the public
 * keys with its own, causing each victim to derive a shared secret with the
 * adversary rather than with each other.
 *
 * Mitigation — fingerprint verification:
 *   After computing the ECDH shared secret, both devices derive a short
 *   fingerprint via a domain-separated SHA-256 (see crypto_derive_fingerprint).
 *   Because the fingerprint is a deterministic function of the shared secret,
 *   legitimate devices display the SAME value while MITM-intercept victims
 *   display DIFFERENT values (one for each adversary-victim secret).  The user
 *   compares the two displayed fingerprints out-of-band and types "confirm"
 *   only if they match.  Typing "cancel" or letting the 30-second window expire
 *   aborts the pairing without installing any keys.
 */

#include "pairing.h"
#include "config.h"
#include "crypto.h"
#include "espnow_manager.h"
#include "nvs_storage.h"
#include <Arduino.h>
#include <string.h>

static pairing_state_t s_state    = PAIRING_IDLE;
static uint32_t        s_start_ms = 0;
static uint8_t         s_own_mac[6];

// Staged key material — set by stage_pairing(), consumed by commit_pairing().
// Zeroed immediately if the user cancels or the timeout fires.
static uint8_t s_pending_mac[6];
static uint8_t s_pending_lmk[16];
// Note: the ECDH-derived PMK is intentionally not staged here.  The device PMK
// is generated once at first boot (in main.cpp) and never changed, so pairing
// only needs to install the per-peer LMK.

static const uint8_t BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/*
 * stage_pairing — compute keys and fingerprint, then pause for user input.
 *
 * Unlike the old finalize_pairing(), this function does NOT register the peer
 * or install the PMK.  It stores the derived keys in the s_pending_* buffers
 * and transitions to PAIRING_WAIT_USER_CONFIRM so the user can verify the
 * fingerprint before any key material is committed to the ESP-NOW stack.
 */
static void stage_pairing(const uint8_t peer_mac[6], const uint8_t their_pub[ECDH_PUBKEY_LEN]) {
    uint8_t secret[32];
    if (!crypto_compute_shared_secret(their_pub, secret)) {
        Serial.println("[pairing] shared secret computation failed");
        s_state = PAIRING_IDLE;
        return;
    }

    // Derive keys from the shared secret; only the LMK is staged for commit.
    // The PMK output is discarded — the device PMK is fixed at boot and must
    // not be overwritten here, which was the root cause of multi-peer breakage.
    uint8_t unused_pmk[16];
    crypto_derive_keys(secret, unused_pmk, s_pending_lmk);
    memcpy(s_pending_mac, peer_mac, 6);

    // Derive a 3-byte fingerprint from the shared secret using a separate
    // domain-separated hash so it is independent of the PMK/LMK bytes.
    // Both legitimate devices will display the same fingerprint; MITM victims
    // will display different ones because they share different secrets.
    uint8_t fp[3];
    crypto_derive_fingerprint(secret, fp);

    Serial.printf("\n*** Pairing fingerprint: %02X:%02X:%02X ***\n", fp[0], fp[1], fp[2]);
    Serial.println("    Compare this with your peer's fingerprint.");
    Serial.println("    Type 'confirm' if they match, or 'cancel' if they differ.\n");

    s_state    = PAIRING_WAIT_USER_CONFIRM;
    s_start_ms = millis();  // restart the countdown for the confirmation window
}

/*
 * commit_pairing — register the staged peer and persist it to NVS.
 *
 * Only called after the user types "confirm" via pairing_confirm().
 * The device PMK is NOT set here — it is generated once at first boot in
 * main.cpp and persisted to NVS, so it is already active when this runs.
 * Only the per-peer LMK (derived via ECDH) is installed here.
 */
static void commit_pairing() {
    if (!espnow_add_peer(s_pending_mac, s_pending_lmk)) {
        Serial.println("[pairing] failed to add peer");
        s_state = PAIRING_IDLE;
        return;
    }

    nvs_save_peer(s_pending_mac, s_pending_lmk);

    Serial.printf("[pairing] Paired with %02X:%02X:%02X:%02X:%02X:%02X\n",
                  s_pending_mac[0], s_pending_mac[1], s_pending_mac[2],
                  s_pending_mac[3], s_pending_mac[4], s_pending_mac[5]);
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

    // Broadcast PAIRING_REQUEST to all nearby devices.  Only those in
    // PAIRING_IDLE will respond; the rest silently ignore the frame.
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

bool pairing_confirm() {
    if (s_state != PAIRING_WAIT_USER_CONFIRM) {
        Serial.println("[pairing] not waiting for confirmation");
        return false;
    }
    commit_pairing();
    return true;
}

bool pairing_cancel() {
    if (s_state != PAIRING_WAIT_USER_CONFIRM) {
        Serial.println("[pairing] not waiting for confirmation");
        return false;
    }
    // Zero out staged key material so it cannot be accidentally committed later.
    memset(s_pending_mac, 0, sizeof(s_pending_mac));
    memset(s_pending_lmk, 0, sizeof(s_pending_lmk));
    s_state = PAIRING_IDLE;
    Serial.println("[pairing] Pairing cancelled");
    return true;
}

void pairing_on_recv(const uint8_t *src_mac, const uint8_t *data, size_t len) {
    if (len < ESPNOW_PACKET_SIZE) return;
    const espnow_packet_t *pkt = (const espnow_packet_t *)data;

    switch (pkt->type) {

        case PKT_PAIRING_REQUEST: {
            // Only respond when idle — prevents accepting a second concurrent
            // pairing attempt while one is already in flight.
            if (s_state != PAIRING_IDLE) return;

            Serial.printf("[pairing] Request from %02X:%02X:%02X:%02X:%02X:%02X\n",
                          src_mac[0], src_mac[1], src_mac[2],
                          src_mac[3], src_mac[4], src_mac[5]);

            // Generate our ephemeral key pair for this session.
            uint8_t pub[ECDH_PUBKEY_LEN];
            if (!crypto_generate_keypair(pub)) {
                Serial.println("[pairing] keypair generation failed");
                return;
            }

            // Send our public key to the initiator BEFORE computing the
            // fingerprint so both sides begin key derivation at the same time.
            espnow_packet_t resp = {};
            resp.type = PKT_PAIRING_RESPONSE;
            memcpy(resp.mac, s_own_mac, 6);
            resp.payload_len = ECDH_PUBKEY_LEN;
            memcpy(resp.payload, pub, ECDH_PUBKEY_LEN);
            espnow_send_raw(src_mac, (uint8_t *)&resp, ESPNOW_PACKET_SIZE);

            // Stage the pairing: compute fingerprint and wait for user input.
            // We do NOT commit (register peer, install PMK) until "confirm".
            stage_pairing(pkt->mac, pkt->payload);
            break;
        }

        case PKT_PAIRING_RESPONSE: {
            // Only the initiator in WAIT_RESPONSE state processes this.
            if (s_state != PAIRING_WAIT_RESPONSE) return;

            Serial.printf("[pairing] Response from %02X:%02X:%02X:%02X:%02X:%02X\n",
                          src_mac[0], src_mac[1], src_mac[2],
                          src_mac[3], src_mac[4], src_mac[5]);

            stage_pairing(pkt->mac, pkt->payload);
            break;
        }

        case PKT_PAIRING_CONFIRM:
            // In the fingerprint-verified protocol both sides independently wait
            // for local user input.  The CONFIRM packet is no longer sent, but we
            // handle it gracefully in case a peer runs older firmware.
            break;

        case PKT_DATA: {
            // Encrypted data frame from a paired peer.
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
    if (s_state == PAIRING_WAIT_RESPONSE || s_state == PAIRING_WAIT_USER_CONFIRM) {
        if (millis() - s_start_ms > PAIRING_TIMEOUT_MS) {
            if (s_state == PAIRING_WAIT_USER_CONFIRM) {
                // Zero out staged key material before discarding it.
                memset(s_pending_lmk, 0, sizeof(s_pending_lmk));
                Serial.println("[pairing] Confirmation timeout — pairing aborted");
            } else {
                Serial.println("[pairing] Timeout, no response received");
            }
            s_state = PAIRING_IDLE;
        }
    }
}

pairing_state_t pairing_get_state() {
    return s_state;
}
