/*
 * crypto.cpp
 *
 * Implementation of the ECDH key exchange and key derivation used during
 * the ESP-NOW pairing handshake.
 *
 * Library choices:
 *   - mbedTLS is bundled with the ESP32 Arduino / ESP-IDF framework, so no
 *     extra library dependency is needed.
 *   - We use the lower-level mbedtls_ecp_* API (rather than the higher-level
 *     mbedtls_ecdh_context API) because the ecdh_context internals became
 *     opaque in mbedTLS 3.x and can no longer be accessed directly.
 *   - The CTR-DRBG (counter-mode deterministic random bit generator) is the
 *     recommended CSPRNG in mbedTLS.  It is seeded from esp_random(), which
 *     sources from the ESP32's hardware RNG backed by RF noise.
 */

#include "crypto.h"
#include <Arduino.h>
#include <string.h>

#include "mbedtls/ecp.h"       // Elliptic-curve point arithmetic
#include "mbedtls/ecdh.h"      // mbedtls_ecdh_compute_shared
#include "mbedtls/sha256.h"    // Key derivation hash
#include "mbedtls/entropy.h"   // Entropy source abstraction
#include "mbedtls/ctr_drbg.h"  // Deterministic random bit generator

// Module-level mbedTLS state.  Using static globals avoids heap allocation
// and keeps lifetimes simple on an embedded target.
static mbedtls_entropy_context  s_entropy;   // entropy pool
static mbedtls_ctr_drbg_context s_ctr_drbg; // seeded PRNG
static mbedtls_ecp_group        s_grp;       // P-256 curve parameters
static mbedtls_mpi              s_d;         // our private key (scalar)
static mbedtls_ecp_point        s_Q;         // our public key  (curve point)
static bool s_initialized = false;
static bool s_has_keypair  = false;

/*
 * hw_entropy — mbedTLS entropy callback backed by the ESP32 hardware RNG.
 *
 * mbedTLS calls this to gather raw entropy for seeding the DRBG.  esp_random()
 * returns a 32-bit value from the hardware TRNG (fed by thermal/RF noise),
 * so we call it repeatedly to fill the requested byte count.
 */
static int hw_entropy(void *data, unsigned char *output, size_t len, size_t *olen) {
    (void)data;
    for (size_t i = 0; i < len; i += 4) {
        uint32_t rnd = esp_random();
        size_t chunk = (i + 4 <= len) ? 4 : (len - i);
        memcpy(output + i, &rnd, chunk);
    }
    *olen = len;
    return 0;
}

bool crypto_init() {
    // Zero-initialise all contexts before use — required by mbedTLS.
    mbedtls_entropy_init(&s_entropy);
    mbedtls_ctr_drbg_init(&s_ctr_drbg);
    mbedtls_ecp_group_init(&s_grp);
    mbedtls_mpi_init(&s_d);
    mbedtls_ecp_point_init(&s_Q);

    // Register the hardware RNG as a strong entropy source so the DRBG seed
    // has real unpredictability even if the standard sources are weak.
    mbedtls_entropy_add_source(&s_entropy, hw_entropy, nullptr,
                               32, MBEDTLS_ENTROPY_SOURCE_STRONG);

    // "pers" is a personalisation string that mixes device-specific context
    // into the DRBG seed, making the output unique to this application.
    const char *pers = "espnow_pairing";
    int ret = mbedtls_ctr_drbg_seed(&s_ctr_drbg, mbedtls_entropy_func, &s_entropy,
                                    (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        Serial.printf("[crypto] ctr_drbg_seed failed: -0x%04X\n", -ret);
        return false;
    }

    s_initialized = true;
    return true;
}

bool crypto_generate_keypair(uint8_t pub_out[64]) {
    if (!s_initialized) return false;

    // Free and re-initialise the key material so each call produces an
    // independent key pair — important if pairing is retried after a failure.
    mbedtls_ecp_group_free(&s_grp);
    mbedtls_mpi_free(&s_d);
    mbedtls_ecp_point_free(&s_Q);
    mbedtls_ecp_group_init(&s_grp);
    mbedtls_mpi_init(&s_d);
    mbedtls_ecp_point_init(&s_Q);
    s_has_keypair = false;

    // Load the P-256 (secp256r1) curve parameters into s_grp.
    // P-256 provides 128-bit security and is well supported in mbedTLS.
    int ret = mbedtls_ecp_group_load(&s_grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        Serial.printf("[crypto] group_load failed: -0x%04X\n", -ret);
        return false;
    }

    // Generate a random private key scalar (s_d) and its corresponding public
    // key point (s_Q = s_d * G) on the P-256 curve.
    ret = mbedtls_ecp_gen_keypair(&s_grp, &s_d, &s_Q,
                                  mbedtls_ctr_drbg_random, &s_ctr_drbg);
    if (ret != 0) {
        Serial.printf("[crypto] gen_keypair failed: -0x%04X\n", -ret);
        return false;
    }

    // Serialise the public key point to "uncompressed" binary format:
    //   byte 0   = 0x04  (signals uncompressed point)
    //   bytes 1-32  = x coordinate (big-endian)
    //   bytes 33-64 = y coordinate (big-endian)
    // Total: 65 bytes.
    uint8_t buf[65];
    size_t olen = 0;
    ret = mbedtls_ecp_point_write_binary(&s_grp, &s_Q,
                                         MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &olen, buf, sizeof(buf));
    if (ret != 0 || olen != 65) {
        Serial.printf("[crypto] point_write_binary failed: -0x%04X\n", -ret);
        return false;
    }

    // Strip the 0x04 prefix so the caller receives a compact 64-byte x||y
    // that fits neatly in the espnow_packet_t payload field.
    memcpy(pub_out, buf + 1, 64);
    s_has_keypair = true;
    return true;
}

bool crypto_compute_shared_secret(const uint8_t their_pub[64], uint8_t secret_out[32]) {
    if (!s_initialized || !s_has_keypair) return false;

    // Reconstruct the full 65-byte uncompressed point by re-adding the 0x04
    // prefix that we stripped before transmitting.
    uint8_t their_buf[65];
    their_buf[0] = 0x04;
    memcpy(their_buf + 1, their_pub, 64);

    mbedtls_ecp_point Qp; // peer's public key point
    mbedtls_mpi z;        // resulting shared secret (x-coordinate of s_d * Qp)
    mbedtls_ecp_point_init(&Qp);
    mbedtls_mpi_init(&z);

    // Deserialise the peer's public key from its binary representation.
    int ret = mbedtls_ecp_point_read_binary(&s_grp, &Qp, their_buf, 65);
    if (ret != 0) {
        Serial.printf("[crypto] point_read_binary failed: -0x%04X\n", -ret);
        goto fail;
    }

    // Verify the peer's public key is actually on the P-256 curve.
    // This guards against invalid-curve attacks where a malicious point
    // could leak our private key.
    ret = mbedtls_ecp_check_pubkey(&s_grp, &Qp);
    if (ret != 0) {
        Serial.println("[crypto] peer public key failed validation");
        goto fail;
    }

    // ECDH multiplication: z = s_d * Qp.
    // Both devices compute this with their own private key and the other's
    // public key, arriving at the same point (and therefore the same z).
    ret = mbedtls_ecdh_compute_shared(&s_grp, &z, &Qp, &s_d,
                                      mbedtls_ctr_drbg_random, &s_ctr_drbg);
    if (ret != 0) {
        Serial.printf("[crypto] compute_shared failed: -0x%04X\n", -ret);
        goto fail;
    }

    // The shared secret is the x-coordinate of the resulting curve point,
    // exported as a 32-byte big-endian integer.
    ret = mbedtls_mpi_write_binary(&z, secret_out, 32);
    if (ret != 0) goto fail;

    mbedtls_ecp_point_free(&Qp);
    mbedtls_mpi_free(&z);
    return true;

fail:
    mbedtls_ecp_point_free(&Qp);
    mbedtls_mpi_free(&z);
    return false;
}

void crypto_derive_keys(const uint8_t secret[32], uint8_t pmk_out[16], uint8_t lmk_out[16]) {
    // Hash the 32-byte ECDH secret with SHA-256 to produce 32 bytes of
    // key material.  Splitting the digest gives two independent 128-bit keys
    // without any additional HKDF machinery.
    //   PMK = SHA-256(secret)[0..15]   — ESP-NOW Primary Master Key
    //   LMK = SHA-256(secret)[16..31]  — ESP-NOW Local Master Key (per peer)
    uint8_t hash[32];
    mbedtls_sha256(secret, 32, hash, 0 /* 0 = SHA-256, not SHA-224 */);
    memcpy(pmk_out, hash,      16);
    memcpy(lmk_out, hash + 16, 16);
}
