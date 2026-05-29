/*
 * pairing.h
 *
 * Public interface for the ESP-NOW secure pairing state machine.
 *
 * Pairing protocol overview (initiator side):
 *   1. User types "pair" → pairing_start() is called.
 *   2. Device generates an ECDH key pair and broadcasts a PAIRING_REQUEST
 *      containing its MAC and public key to the Wi-Fi broadcast address.
 *   3. State moves to PAIRING_WAIT_RESPONSE.
 *   4. When a PAIRING_RESPONSE arrives, finalize_pairing() runs:
 *      computes the shared secret, derives PMK/LMK, registers the peer.
 *   5. State moves to PAIRING_COMPLETE.
 *
 * Responder side:
 *   1. Device is in PAIRING_IDLE when the PAIRING_REQUEST broadcast arrives.
 *   2. It generates its own ECDH key pair, sends a PAIRING_RESPONSE directly
 *      to the initiator's MAC, then runs finalize_pairing().
 *   3. After deriving keys it sends a PAIRING_CONFIRM to the initiator.
 *   4. State moves to PAIRING_COMPLETE.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// States of the pairing state machine.
typedef enum {
    PAIRING_IDLE,           // Not pairing; ready to accept a request or start one.
    PAIRING_WAIT_RESPONSE,  // We sent a REQUEST and are waiting for a RESPONSE.
    PAIRING_COMPLETE,       // Keys have been derived and the peer registered.
} pairing_state_t;

// pairing_init — cache our own MAC address; call once after espnow_manager_init.
void pairing_init();

// pairing_start — enter pairing mode as the initiator.
// Generates a key pair and broadcasts PAIRING_REQUEST.
// Returns false if already in progress or if the broadcast fails.
bool pairing_start();

// pairing_on_recv — feed a received ESP-NOW frame into the state machine.
// Called by main.cpp's espnow receive callback for every incoming frame.
void pairing_on_recv(const uint8_t *src_mac, const uint8_t *data, size_t len);

// pairing_tick — check for pairing timeout; call from loop().
// If PAIRING_TIMEOUT_MS elapses without a response, state resets to IDLE.
void pairing_tick();

// pairing_get_state — return the current state (useful for status display).
pairing_state_t pairing_get_state();
