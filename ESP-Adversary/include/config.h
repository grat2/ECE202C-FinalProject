/*
 * config.h (adversary)
 *
 * Packet type definitions and wire format shared with the ESP-Pairing project.
 * The adversary must parse and forge packets that look identical to those
 * produced by the legitimate pairing firmware.
 */

#pragma once

#include <stdint.h>

// Wi-Fi channel the victim devices use — the adversary must listen on the
// same channel to receive their frames.
#define ESPNOW_CHANNEL  1

// Maximum number of victim devices the adversary will MITM simultaneously.
// Each victim requires a separate LMK entry in the ESP-NOW peer table.
#define MAX_VICTIMS     4

// Packet type byte — first field of every espnow_packet_t.
typedef enum : uint8_t {
    PKT_PAIRING_REQUEST  = 0x01,
    PKT_PAIRING_RESPONSE = 0x02,
    PKT_PAIRING_CONFIRM  = 0x03,
    PKT_DATA             = 0x10,
} pkt_type_t;

// ECDH P-256 public key: x||y (64 bytes, no 0x04 prefix).
#define ECDH_PUBKEY_LEN 64

// Wire format — must be byte-for-byte identical to ESP-Pairing's definition.
#pragma pack(push, 1)
typedef struct {
    uint8_t  type;
    uint8_t  mac[6];
    uint16_t payload_len;
    uint8_t  payload[ECDH_PUBKEY_LEN];
} espnow_packet_t;
#pragma pack(pop)

#define ESPNOW_PACKET_SIZE sizeof(espnow_packet_t)
