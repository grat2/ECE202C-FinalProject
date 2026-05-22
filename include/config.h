#pragma once

#include <stdint.h>

#define MAX_PEERS           10
#define PAIRING_TIMEOUT_MS  30000
#define ESPNOW_CHANNEL      1

// Packet types
typedef enum : uint8_t {
    PKT_PAIRING_REQUEST  = 0x01,
    PKT_PAIRING_RESPONSE = 0x02,
    PKT_PAIRING_CONFIRM  = 0x03,
    PKT_DATA             = 0x10,
} pkt_type_t;

// NVS
#define NVS_NAMESPACE   "espnow_peers"
#define NVS_PEER_COUNT  "peer_count"

// ECDH public key is 64 bytes (uncompressed P-256: x||y, without 0x04 prefix)
#define ECDH_PUBKEY_LEN 64

#pragma pack(push, 1)
typedef struct {
    uint8_t type;
    uint8_t mac[6];
    uint16_t payload_len;
    uint8_t payload[ECDH_PUBKEY_LEN];
} espnow_packet_t;
#pragma pack(pop)

#define ESPNOW_PACKET_SIZE sizeof(espnow_packet_t)
