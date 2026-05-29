/*
 * pairing.h
 *
 * Public interface for the ESP-NOW secure pairing state machine with
 * fingerprint-based MITM protection.
 *
 * Pairing protocol — initiator side:
 *   1. User types "pair" → pairing_start() broadcasts a PAIRING_REQUEST
 *      containing our ECDH public key to the Wi-Fi broadcast address.
 *   2. State moves to PAIRING_WAIT_RESPONSE.
 *   3. On PAIRING_RESPONSE: compute ECDH shared secret, derive a 3-byte
 *      fingerprint, print it to Serial, move to PAIRING_WAIT_USER_CONFIRM.
 *   4. User reads the fingerprint aloud and compares with the peer's display.
 *      Type "confirm" → pairing_confirm() → keys installed → PAIRING_COMPLETE.
 *      Type "cancel" (or wait 30 s) → pairing_cancel() → PAIRING_IDLE.
 *
 * Pairing protocol — responder side:
 *   1. PAIRING_REQUEST arrives → generate key pair → send PAIRING_RESPONSE.
 *   2. Compute shared secret, display fingerprint → PAIRING_WAIT_USER_CONFIRM.
 *   3. Same confirm/cancel flow as the initiator.
 *
 * MITM protection:
 *   An adversary that substitutes its own public key causes each victim to
 *   derive a *different* shared secret (one with the adversary rather than with
 *   each other).  Their displayed fingerprints therefore differ, allowing users
 *   to detect and abort the compromised pairing before any keys are installed.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// States of the pairing state machine.
typedef enum {
    PAIRING_IDLE,              // Not pairing; ready to accept a request or start one.
    PAIRING_WAIT_RESPONSE,     // We sent a REQUEST and are waiting for a RESPONSE.
    PAIRING_WAIT_USER_CONFIRM, // Fingerprint displayed; waiting for "confirm"/"cancel".
    PAIRING_COMPLETE,          // Keys installed and peer registered.
} pairing_state_t;

// pairing_init — cache our own MAC address; call once after espnow_manager_init.
void pairing_init();

// pairing_start — enter pairing mode as the initiator.
// Generates a key pair and broadcasts PAIRING_REQUEST.
// Returns false if already in progress or if the broadcast fails.
bool pairing_start();

// pairing_confirm — finalize a staged pairing after the user verifies the fingerprint.
// Must be called while in PAIRING_WAIT_USER_CONFIRM.  Installs the PMK/LMK and
// registers the peer.  Returns false if not in the expected state.
bool pairing_confirm();

// pairing_cancel — abort a staged pairing.
// Clears all staged key material and resets to PAIRING_IDLE.
// Returns false if not in PAIRING_WAIT_USER_CONFIRM.
bool pairing_cancel();

// pairing_on_recv — feed a received ESP-NOW frame into the state machine.
// Called by main.cpp's espnow receive callback for every incoming frame.
void pairing_on_recv(const uint8_t *src_mac, const uint8_t *data, size_t len);

// pairing_tick — check for timeouts; call from loop().
// Handles both the response-wait timeout and the user-confirmation timeout.
void pairing_tick();

// pairing_get_state — return the current state (useful for status display).
pairing_state_t pairing_get_state();
