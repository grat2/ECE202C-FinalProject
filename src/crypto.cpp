#include "crypto.h"
#include <Arduino.h>
#include <string.h>

#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/sha256.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

static mbedtls_entropy_context  s_entropy;
static mbedtls_ctr_drbg_context s_ctr_drbg;
static mbedtls_ecp_group        s_grp;
static mbedtls_mpi              s_d;   // private key
static mbedtls_ecp_point        s_Q;   // own public key
static bool s_initialized = false;
static bool s_has_keypair  = false;

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
    mbedtls_entropy_init(&s_entropy);
    mbedtls_ctr_drbg_init(&s_ctr_drbg);
    mbedtls_ecp_group_init(&s_grp);
    mbedtls_mpi_init(&s_d);
    mbedtls_ecp_point_init(&s_Q);

    mbedtls_entropy_add_source(&s_entropy, hw_entropy, nullptr,
                               32, MBEDTLS_ENTROPY_SOURCE_STRONG);

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

    // Reset for a fresh key pair each pairing attempt
    mbedtls_ecp_group_free(&s_grp);
    mbedtls_mpi_free(&s_d);
    mbedtls_ecp_point_free(&s_Q);
    mbedtls_ecp_group_init(&s_grp);
    mbedtls_mpi_init(&s_d);
    mbedtls_ecp_point_init(&s_Q);
    s_has_keypair = false;

    int ret = mbedtls_ecp_group_load(&s_grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        Serial.printf("[crypto] group_load failed: -0x%04X\n", -ret);
        return false;
    }

    ret = mbedtls_ecp_gen_keypair(&s_grp, &s_d, &s_Q,
                                  mbedtls_ctr_drbg_random, &s_ctr_drbg);
    if (ret != 0) {
        Serial.printf("[crypto] gen_keypair failed: -0x%04X\n", -ret);
        return false;
    }

    // Export uncompressed point: 04 || x(32) || y(32) = 65 bytes
    uint8_t buf[65];
    size_t olen = 0;
    ret = mbedtls_ecp_point_write_binary(&s_grp, &s_Q,
                                         MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &olen, buf, sizeof(buf));
    if (ret != 0 || olen != 65) {
        Serial.printf("[crypto] point_write_binary failed: -0x%04X\n", -ret);
        return false;
    }

    // Drop the 0x04 prefix; caller gets raw x||y (64 bytes)
    memcpy(pub_out, buf + 1, 64);
    s_has_keypair = true;
    return true;
}

bool crypto_compute_shared_secret(const uint8_t their_pub[64], uint8_t secret_out[32]) {
    if (!s_initialized || !s_has_keypair) return false;

    // Prepend 0x04 to reconstruct uncompressed point format
    uint8_t their_buf[65];
    their_buf[0] = 0x04;
    memcpy(their_buf + 1, their_pub, 64);

    mbedtls_ecp_point Qp;
    mbedtls_mpi z;
    mbedtls_ecp_point_init(&Qp);
    mbedtls_mpi_init(&z);

    int ret = mbedtls_ecp_point_read_binary(&s_grp, &Qp, their_buf, 65);
    if (ret != 0) {
        Serial.printf("[crypto] point_read_binary failed: -0x%04X\n", -ret);
        goto fail;
    }

    ret = mbedtls_ecp_check_pubkey(&s_grp, &Qp);
    if (ret != 0) {
        Serial.println("[crypto] peer public key failed validation");
        goto fail;
    }

    ret = mbedtls_ecdh_compute_shared(&s_grp, &z, &Qp, &s_d,
                                      mbedtls_ctr_drbg_random, &s_ctr_drbg);
    if (ret != 0) {
        Serial.printf("[crypto] compute_shared failed: -0x%04X\n", -ret);
        goto fail;
    }

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
    uint8_t hash[32];
    mbedtls_sha256(secret, 32, hash, 0);
    memcpy(pmk_out, hash,      16);
    memcpy(lmk_out, hash + 16, 16);
}
