#include <Arduino.h>
#include <string.h>
#include <stdio.h>

#include "config.h"
#include "crypto.h"
#include "espnow_manager.h"
#include "nvs_storage.h"
#include "pairing.h"

static void on_espnow_recv(const uint8_t *src_mac, const espnow_packet_t *pkt) {
    pairing_on_recv(src_mac, (const uint8_t *)pkt, ESPNOW_PACKET_SIZE);
}

static void on_peer_load(const uint8_t mac[6], const uint8_t lmk[16]) {
    espnow_add_peer(mac, lmk);
    Serial.printf("[boot] Loaded peer %02X:%02X:%02X:%02X:%02X:%02X\n",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void print_mac(const uint8_t mac[6]) {
    Serial.printf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void handle_command(const char *cmd) {
    if (strcmp(cmd, "pair") == 0) {
        pairing_start();

    } else if (strcmp(cmd, "list") == 0) {
        Serial.println("[list] Saved peers:");
        nvs_load_all_peers([](const uint8_t mac[6], const uint8_t lmk[16]) {
            Serial.print("  MAC: ");
            for (int i = 0; i < 6; i++) Serial.printf("%02X%s", mac[i], i < 5 ? ":" : "");
            Serial.println();
        });

    } else if (strncmp(cmd, "send ", 5) == 0) {
        const char *msg = cmd + 5;
        size_t msg_len = strlen(msg);
        if (msg_len == 0 || msg_len > ECDH_PUBKEY_LEN) {
            Serial.println("[send] Message must be 1–64 chars");
            return;
        }

        uint8_t own_mac[6];
        espnow_get_own_mac(own_mac);

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

static char s_cmd_buf[128];
static int  s_cmd_len = 0;

void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.println("\n=== ESP-NOW Pairing System ===");

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

    // Restore previously paired peers
    nvs_load_all_peers(on_peer_load);

    uint8_t mac[6];
    espnow_get_own_mac(mac);
    Serial.print("Own MAC: ");
    print_mac(mac);
    Serial.println();
    Serial.println("Type 'help' for commands.");
}

void loop() {
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

    pairing_tick();
}
