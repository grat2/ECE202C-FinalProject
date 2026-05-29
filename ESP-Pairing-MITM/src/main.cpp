/*
 * main.cpp
 *
 * Application entry point.  Wires together the crypto, ESP-NOW, NVS, and
 * pairing modules, and provides a simple line-oriented serial command interface
 * for triggering pairing and testing encrypted communication.
 *
 * Serial commands (115200 baud):
 *   pair        — enter pairing mode (generate key pair, broadcast request)
 *   list        — print all peers saved in NVS
 *   send <msg>  — send an encrypted message to all registered peers
 *   clear       — erase all peer records from NVS
 *   mac         — print this device's own MAC address
 *   help        — show command list
 */

#include <Arduino.h>
#include <string.h>
#include <stdio.h>

#include "config.h"
#include "crypto.h"
#include "espnow_manager.h"
#include "nvs_storage.h"
#include "pairing.h"

/*
 * on_espnow_recv — called by espnow_manager for every received frame.
 *
 * We forward every frame to the pairing state machine, which handles all
 * packet types (PAIRING_REQUEST, RESPONSE, CONFIRM, and DATA).
 */
static void on_espnow_recv(const uint8_t *src_mac, const espnow_packet_t *pkt) {
    pairing_on_recv(src_mac, (const uint8_t *)pkt, ESPNOW_PACKET_SIZE);
}

/*
 * on_peer_load — NVS load callback invoked once per saved peer at boot.
 *
 * Re-registers each peer with the ESP-NOW stack so encrypted frames can be
 * exchanged immediately without having to re-pair after a reboot.
 */
static void on_peer_load(const uint8_t mac[6], const uint8_t lmk[16]) {
    espnow_add_peer(mac, lmk);
    Serial.printf("[boot] Loaded peer %02X:%02X:%02X:%02X:%02X:%02X\n",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void print_mac(const uint8_t mac[6]) {
    Serial.printf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/*
 * handle_command — parse and dispatch one newline-terminated serial command.
 */
static void handle_command(const char *cmd) {

    if (strcmp(cmd, "pair") == 0) {
        // Kick off the pairing handshake.  pairing_start() broadcasts our
        // public key and waits (non-blocking) for a response.
        pairing_start();

    } else if (strcmp(cmd, "list") == 0) {
        // Iterate NVS and print every saved peer's MAC address.
        Serial.println("[list] Saved peers:");
        nvs_load_all_peers([](const uint8_t mac[6], const uint8_t lmk[16]) {
            Serial.print("  MAC: ");
            for (int i = 0; i < 6; i++) Serial.printf("%02X%s", mac[i], i < 5 ? ":" : "");
            Serial.println();
        });

    } else if (strncmp(cmd, "send ", 5) == 0) {
        // Everything after "send " is the message payload.
        const char *msg = cmd + 5;
        size_t msg_len = strlen(msg);

        // The payload field in espnow_packet_t is ECDH_PUBKEY_LEN (64) bytes.
        if (msg_len == 0 || msg_len > ECDH_PUBKEY_LEN) {
            Serial.println("[send] Message must be 1-64 chars");
            return;
        }

        uint8_t own_mac[6];
        espnow_get_own_mac(own_mac);

        // Build a DATA packet.  Embedding our MAC lets the receiver log who
        // sent the message without relying on ESP-NOW's src_addr field.
        espnow_packet_t pkt = {};
        pkt.type = PKT_DATA;
        memcpy(pkt.mac, own_mac, 6);
        pkt.payload_len = (uint16_t)msg_len;
        memcpy(pkt.payload, msg, msg_len);

        if (!espnow_send_to_all_encrypted((uint8_t *)&pkt, ESPNOW_PACKET_SIZE)) {
            Serial.println("[send] No encrypted peers registered");
        }

    } else if (strcmp(cmd, "clear") == 0) {
        if (nvs_clear_all()) {
            Serial.println("[clear] All peers cleared from NVS");
        } else {
            Serial.println("[clear] Failed to clear NVS");
        }

    } else if (strcmp(cmd, "mac") == 0) {
        uint8_t mac[6];
        espnow_get_own_mac(mac);
        Serial.print("Own MAC: ");
        print_mac(mac);
        Serial.println();

    } else if (strcmp(cmd, "help") == 0) {
        Serial.println("Commands:");
        Serial.println("  pair        - Start pairing mode");
        Serial.println("  list        - List saved peers");
        Serial.println("  send <msg>  - Send encrypted message to all peers");
        Serial.println("  clear       - Clear all saved peers");
        Serial.println("  mac         - Print own MAC address");

    } else {
        Serial.printf("Unknown command: '%s' (type 'help')\n", cmd);
    }
}

// Serial input buffer — accumulates characters until a newline is received.
static char s_cmd_buf[128];
static int  s_cmd_len = 0;

void setup() {
    Serial.begin(57600);
    delay(500);
    Serial.println("\n=== ESP-NOW Pairing System ===");

    // Initialise subsystems in dependency order:
    //   crypto first (needed by pairing)
    //   NVS second  (needed to restore saved peers)
    //   ESP-NOW third (needed by pairing and NVS restore)
    if (!crypto_init()) {
        Serial.println("[FATAL] crypto init failed");
        while (1) delay(1000);
    }

    if (!nvs_storage_init()) {
        Serial.println("[FATAL] NVS init failed");
        while (1) delay(1000);
    }

    if (!espnow_manager_init(on_espnow_recv)) {
        Serial.println("[FATAL] ESP-NOW init failed");
        while (1) delay(1000);
    }

    pairing_init();

    // Reload saved peers from NVS so previously paired devices are immediately
    // usable without requiring re-pairing after every reboot.
    nvs_load_all_peers(on_peer_load);

    uint8_t mac[6];
    espnow_get_own_mac(mac);
    Serial.print("Own MAC: ");
    print_mac(mac);
    Serial.println();
    Serial.println("Type 'help' for commands.");
}

void loop() {
    // Non-blocking serial line reader.  Characters accumulate in s_cmd_buf
    // until '\n' arrives, at which point the complete line is dispatched.
    // '\r' is silently ignored to handle CRLF line endings from some terminals.
    while (Serial.available()) {
        char c = (char)Serial.read();
        if (c == '\r') continue;
        if (c == '\n') {
            s_cmd_buf[s_cmd_len] = '\0';
            if (s_cmd_len > 0) handle_command(s_cmd_buf);
            s_cmd_len = 0;
        } else if (s_cmd_len < (int)sizeof(s_cmd_buf) - 1) {
            s_cmd_buf[s_cmd_len++] = c;
        }
    }

    // Poll the pairing state machine to detect and handle the inactivity timeout.
    pairing_tick();
}
