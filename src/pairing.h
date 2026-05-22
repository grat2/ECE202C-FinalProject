#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef enum {
    PAIRING_IDLE,
    PAIRING_WAIT_RESPONSE,
    PAIRING_COMPLETE,
} pairing_state_t;

void pairing_init();
bool pairing_start();
void pairing_on_recv(const uint8_t *src_mac, const uint8_t *data, size_t len);
void pairing_tick();
pairing_state_t pairing_get_state();
