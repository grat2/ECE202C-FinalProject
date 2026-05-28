/*
 * mitm.h
 *
 * Interface for the Man-in-the-Middle attack module.
 *
 * The adversary exploits the fact that the ESP-NOW pairing handshake uses
 * unauthenticated ECDH: Device A has no way to verify that a PAIRING_RESPONSE
 * came from Device B specifically rather than from an adversary in the middle.
 *
 * Two operating modes:
 *
 *   Sniff-only (attack disabled):
 *     The adversary passively logs all PAIRING_REQUEST broadcasts it receives,
 *     printing each device's MAC address and public key to the serial terminal.
 *     This demonstrates that the public keys are transmitted in the clear and
 *     are trivially observable by anyone in radio range.
 *
 *   Attack mode (attack enabled):
 *     On every observed PAIRING_REQUEST the adversary intercepts the handshake:
 *     it responds with its own public key, derives the shared LMK, and registers
 *     the victim as an encrypted ESP-NOW peer.  If two or more victims are
 *     intercepted this way, relay mode can be enabled to transparently forward
 *     traffic between them while decrypting every frame.
 *
 * Relay mode:
 *     Once paired with multiple victims the adversary sits between them.
 *     Because the ESP32 hardware auto-decrypts incoming frames (using each
 *     peer's registered LMK) and auto-encrypts outgoing frames, relay is as
 *     simple as calling esp_now_send() on the other victim's MAC.  The victims
 *     observe apparently normal communication and have no indication of the
 *     interception.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "config.h"

// Record for one successfully MITM'd device.
typedef struct {
    uint8_t mac[6];   // victim's Wi-Fi MAC address
    uint8_t lmk[16];  // derived Local Master Key (adversary ↔ victim)
    bool    active;   // true once pairing with this victim is complete
} victim_t;

// mitm_init — initialise Wi-Fi, ESP-NOW, and the victim table.
// Must be called once in setup() before any frames are sent or received.
void mitm_init();

// mitm_set_attack — enable or disable active interception.
// When disabled the module logs observed pairing frames but does not respond.
void mitm_set_attack(bool enabled);

// mitm_set_relay — enable or disable the relay of frames between paired victims.
// Relay requires at least two active victim entries.
void mitm_set_relay(bool enabled);

bool mitm_get_attack();
bool mitm_get_relay();

// mitm_on_recv — feed a received ESP-NOW frame into the attack state machine.
// Registered as the ESP-NOW receive callback via mitm_init().
void mitm_on_recv(const uint8_t *src_mac, const uint8_t *data, size_t len);

// mitm_print_status — dump current state and victim table to Serial.
void mitm_print_status();
