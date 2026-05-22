#pragma once

#include <stdint.h>
#include <stdbool.h>

typedef void (*peer_load_cb_t)(const uint8_t mac[6], const uint8_t lmk[16]);

bool nvs_storage_init();
bool nvs_save_peer(const uint8_t mac[6], const uint8_t lmk[16]);
void nvs_load_all_peers(peer_load_cb_t cb);
bool nvs_clear_all();
