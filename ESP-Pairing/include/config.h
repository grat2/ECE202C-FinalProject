/*
 * config.h
 *
 * Project-wide constants, packet type definitions, and the shared wire format
 * for all ESP-NOW frames exchanged during pairing and normal data transfer.
 */

#pragma once

#include <stdint.h>

// Maximum number of encrypted peers this device can remember across reboots.
#define MAX_PEERS           10

// How long (ms) the initiator waits for a PAIRING_RESPONSE before giving up.
#define PAIRING_TIMEOUT_MS  30000

// Wi-Fi channel used for all ESP-NOW traffic.  Both devices must be on the
// same channel; channel 1 is a safe default that avoids most interference.
#define ESPNOW_CHANNEL      1

/*
 * Packet type byte — the first field of every espnow_packet_t frame.
 *
 * Pairing handshake (all sent unencrypted):
 *   REQUEST  → initiator broadcasts its public key to 0xFF:...:0xFF
 *   RESPONSE → responder unicasts its own public key back to the initiator
 *   CONFIRM  → responder signals that key derivation succeeded on its side
 *
 * Normal operation:
 *   DATA     → encrypted payload sent between already-paired peers
 */
typedef enum : uint8_t {
    PKT_PAIRING_REQUEST  = 0x01,
    PKT_PAIRING_RESPONSE = 0x02,
    PKT_PAIRING_CONFIRM  = 0x03,
    PKT_DATA             = 0x10,
} pkt_type_t;

// NVS (non-volatile storage) namespace used to persist peer records.
// Each entry key is the peer's MAC address as a 12-character hex string.
#define NVS_NAMESPACE   "espnow_peers"
#define NVS_PEER_COUNT  "peer_count"

/*
 * An ECDH public key for the P-256 curve is an (x, y) coordinate pair,
 * each 32 bytes wide.  We transmit them concatenated (x||y) without the
 * standard 0x04 uncompressed-point prefix to save one byte of payload space.
 */
#define ECDH_PUBKEY_LEN 64

/*
 * espnow_packet_t — the single wire format for all ESP-NOW frames.
 *
 * Fields:
 *   type        — one of the pkt_type_t values above
 *   mac         — sender's own MAC address (6 bytes)
 *   payload_len — number of valid bytes in `payload`
 *   payload     — ECDH public key (pairing packets) or application data (DATA)
 *
 * #pragma pack(push,1) forces no padding so the struct layout matches exactly
 * what is written to and read from the radio.
 */
#pragma pack(push, 1)
typedef struct {
    uint8_t  type;
    uint8_t  mac[6];
    uint16_t payload_len;
    uint8_t  payload[ECDH_PUBKEY_LEN];
} espnow_packet_t;
#pragma pack(pop)

// Convenience macro for the total on-wire size of every packet.
#define ESPNOW_PACKET_SIZE sizeof(espnow_packet_t)
