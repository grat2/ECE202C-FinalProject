#pragma once

#include <stdint.h>
#include <stdbool.h>

bool crypto_init();
bool crypto_generate_keypair(uint8_t pub_out[64]);
bool crypto_compute_shared_secret(const uint8_t their_pub[64], uint8_t secret_out[32]);
void crypto_derive_keys(const uint8_t secret[32], uint8_t pmk_out[16], uint8_t lmk_out[16]);
