#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "config.h"

typedef void (*espnow_recv_cb_t)(const uint8_t *src_mac, const espnow_packet_t *pkt);

bool espnow_manager_init(espnow_recv_cb_t recv_cb);
bool espnow_set_pmk(const uint8_t pmk[16]);
bool espnow_add_peer(const uint8_t mac[6], const uint8_t lmk[16]);
bool espnow_send_raw(const uint8_t dest_mac[6], const uint8_t *data, size_t len);
bool espnow_send_to_all_encrypted(const uint8_t *data, size_t len);
void espnow_get_own_mac(uint8_t mac_out[6]);
