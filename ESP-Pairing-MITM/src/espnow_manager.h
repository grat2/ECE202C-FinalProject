/*
 * espnow_manager.h
 *
 * Thin abstraction layer over the ESP-NOW radio API.
 *
 * Responsibilities:
 *   - Initialise the Wi-Fi radio and the ESP-NOW stack.
 *   - Register/remove peers (with or without encryption).
 *   - Send frames (raw / unencrypted during pairing; encrypted after).
 *   - Route received frames to the application via a single callback.
 *
 * ESP-NOW encryption model:
 *   esp_now_set_pmk(pmk)  — sets a global 16-byte Primary Master Key that
 *                           the hardware uses internally to protect stored LMKs.
 *   peer_info.lmk         — per-peer 16-byte Local Master Key; the actual key
 *                           used to encrypt/decrypt frames to/from that peer.
 *   Both the PMK and LMK must be the same on both communicating devices.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "config.h"

// Callback type invoked for every received ESP-NOW frame that passes the
// minimum size check.  src_mac is the sender's MAC; pkt points into a
// temporary buffer and must not be stored past the callback's return.
typedef void (*espnow_recv_cb_t)(const uint8_t *src_mac, const espnow_packet_t *pkt);

// espnow_manager_init — put Wi-Fi in station mode, start ESP-NOW, and
// register the send/receive callbacks.  Must be called before any send/add.
bool espnow_manager_init(espnow_recv_cb_t recv_cb);

// espnow_set_pmk — set the global 16-byte Primary Master Key.
// Call this once after key derivation so the hardware can protect stored LMKs.
bool espnow_set_pmk(const uint8_t pmk[16]);

// espnow_add_peer — register a peer so frames can be sent to its MAC.
// If lmk is non-null the peer is added with encryption enabled (encrypt=true)
// and the LMK is installed.  Replaces any existing entry for this MAC.
bool espnow_add_peer(const uint8_t mac[6], const uint8_t lmk[16]);

// espnow_send_raw — send an unencrypted frame.
// Used during the pairing handshake before keys have been established.
// Automatically registers the destination as an unencrypted peer if unknown.
bool espnow_send_raw(const uint8_t dest_mac[6], const uint8_t *data, size_t len);

// espnow_send_to_all_encrypted — iterate the peer table and send data to
// every peer that has encryption enabled.  Returns true if at least one
// peer was found.
bool espnow_send_to_all_encrypted(const uint8_t *data, size_t len);

// espnow_get_own_mac — fill mac_out with this device's Wi-Fi station MAC.
void espnow_get_own_mac(uint8_t mac_out[6]);
