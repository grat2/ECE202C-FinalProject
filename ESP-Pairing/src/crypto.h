/*
 * crypto.h
 *
 * Thin wrapper around mbedTLS that provides the three cryptographic operations
 * needed for the ESP-NOW pairing handshake:
 *
 *   1. ECDH key-pair generation  (P-256 / secp256r1)
 *   2. ECDH shared-secret computation
 *   3. Key derivation: shared secret → 16-byte PMK + 16-byte LMK
 *
 * Only one key pair is active at a time.  Calling crypto_generate_keypair()
 * again discards the previous private key and starts fresh.
 *
 * A fourth operation, crypto_derive_fingerprint(), produces a short out-of-band
 * verification code from the shared secret.  Both devices display this code so
 * the user can detect a man-in-the-middle substitution before committing.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

/*
 * crypto_init — must be called once before any other function in this module.
 *
 * Seeds the mbedTLS CTR-DRBG (counter-mode DRBG) random number generator
 * using the ESP32's hardware true-random-number generator as an entropy
 * source.  Returns false if seeding fails.
 */
bool crypto_init();

/*
 * crypto_generate_keypair — generate a fresh ECDH key pair.
 *
 * Writes the 64-byte uncompressed public key (x||y, no 0x04 prefix) into
 * pub_out.  The corresponding private key is kept internally and used by
 * crypto_compute_shared_secret().  Returns false on error.
 */
bool crypto_generate_keypair(uint8_t pub_out[64]);

/*
 * crypto_compute_shared_secret — perform the ECDH multiplication.
 *
 * Given the peer's 64-byte public key (received over the air), multiplies it
 * by our private key to produce a 32-byte shared secret.  Both sides arrive
 * at the same secret without ever transmitting it.  Returns false on error or
 * if the peer's public key fails validation.
 */
bool crypto_compute_shared_secret(const uint8_t their_pub[64], uint8_t secret_out[32]);

/*
 * crypto_derive_keys — stretch the 32-byte ECDH secret into two 16-byte keys.
 *
 * Applies SHA-256 to the shared secret, then splits the 32-byte digest:
 *   pmk_out = digest[0..15]   — used as the ESP-NOW Primary Master Key
 *   lmk_out = digest[16..31]  — used as the per-peer Local Master Key
 *
 * Both devices perform this identically, so they arrive at the same PMK/LMK
 * without any additional communication.
 */
void crypto_derive_keys(const uint8_t secret[32], uint8_t pmk_out[16], uint8_t lmk_out[16]);

/*
 * crypto_derive_fingerprint — derive a short out-of-band verification code.
 *
 * Computes SHA-256("FP" || secret) and writes the first 3 bytes into fp_out.
 * Displaying these 3 bytes as 6 hex digits gives a 1-in-16 million false-match
 * probability.  The "FP" prefix domain-separates this hash from the key
 * derivation in crypto_derive_keys() so the two outputs are independent.
 *
 * If an adversary substitutes its own public key during the handshake, each
 * victim derives a different shared secret (one with the adversary rather than
 * with each other), causing their fingerprints to diverge.
 */
void crypto_derive_fingerprint(const uint8_t secret[32], uint8_t fp_out[3]);
