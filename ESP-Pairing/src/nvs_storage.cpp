/*
 * nvs_storage.cpp
 *
 * Stores and retrieves paired-peer records (MAC + LMK) using the ESP32 NVS
 * (Non-Volatile Storage) API.
 *
 * Storage layout (within the "espnow_peers" namespace):
 *   Key:   12-char uppercase hex string of the peer's MAC (e.g. "A1B2C3D4E5F6")
 *   Value: 22-byte binary blob — [ MAC (6 bytes) | LMK (16 bytes) ]
 *
 * Re-storing the MAC inside the blob (even though it is also the key) avoids
 * having to parse the hex key back to bytes during nvs_load_all_peers().
 */

#include "nvs_storage.h"
#include "config.h"
#include <Arduino.h>
#include <nvs_flash.h>
#include <nvs.h>
#include <string.h>
#include <stdio.h>

static nvs_handle_t s_handle;
static bool         s_open = false;

bool nvs_storage_init() {
    // nvs_flash_init() must be called before any NVS access.
    // If the NVS partition has no free pages or an incompatible version
    // (e.g. after a schema change), we erase and reinitialise it.
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        err = nvs_flash_init();
    }
    if (err != ESP_OK) {
        Serial.printf("[nvs] flash_init failed: %d\n", err);
        return false;
    }

    // Open (or create) the application namespace in read/write mode.
    err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &s_handle);
    if (err != ESP_OK) {
        Serial.printf("[nvs] open failed: %d\n", err);
        return false;
    }

    s_open = true;
    return true;
}

/*
 * mac_to_key — format a 6-byte MAC as a 12-char uppercase hex string.
 *
 * NVS keys are limited to 15 characters.  A 12-char hex MAC fits within that
 * limit and is both compact and human-readable.
 * key_out must have room for 13 bytes (12 hex chars + null terminator).
 */
static void mac_to_key(const uint8_t mac[6], char key_out[18]) {
    snprintf(key_out, 18, "%02X%02X%02X%02X%02X%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

bool nvs_save_peer(const uint8_t mac[6], const uint8_t lmk[16]) {
    if (!s_open) return false;

    char key[18];
    mac_to_key(mac, key);

    // Pack MAC and LMK into a single 22-byte blob.  Storing both together
    // makes retrieval trivial — one blob read gives everything needed to
    // re-register the peer with ESP-NOW.
    uint8_t blob[22];
    memcpy(blob,     mac, 6);
    memcpy(blob + 6, lmk, 16);

    esp_err_t err = nvs_set_blob(s_handle, key, blob, sizeof(blob));
    if (err != ESP_OK) {
        Serial.printf("[nvs] set_blob failed: %d\n", err);
        return false;
    }

    // Commit writes the staged changes to flash.  Without this, data written
    // since the last commit can be lost if power is removed.
    nvs_commit(s_handle);
    return true;
}

void nvs_load_all_peers(peer_load_cb_t cb) {
    if (!s_open || !cb) return;

    // nvs_entry_find / nvs_entry_next iterate all keys in the namespace that
    // match the requested type (NVS_TYPE_BLOB).  This avoids having to store
    // a separate count or maintain an index.
    nvs_iterator_t it = nullptr;
    esp_err_t err = nvs_entry_find(NVS_DEFAULT_PART_NAME, NVS_NAMESPACE, NVS_TYPE_BLOB, &it);
    while (err == ESP_OK && it != nullptr) {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);

        uint8_t blob[22];
        size_t blob_len = sizeof(blob);
        // Only invoke the callback if we read back exactly the 22-byte blob
        // we wrote — guards against accidentally reading unrelated entries.
        if (nvs_get_blob(s_handle, info.key, blob, &blob_len) == ESP_OK && blob_len == 22) {
            cb(blob, blob + 6); // blob[0..5] = MAC, blob[6..21] = LMK
        }

        err = nvs_entry_next(&it);
    }

    // The iterator must be released to avoid a resource leak even if the
    // loop exited because there were no more entries (err != ESP_OK).
    nvs_release_iterator(it);
}

bool nvs_clear_all() {
    if (!s_open) return false;
    // nvs_erase_all removes every key in the open namespace, then we commit
    // so the erasure is durable.
    esp_err_t err = nvs_erase_all(s_handle);
    nvs_commit(s_handle);
    return err == ESP_OK;
}
