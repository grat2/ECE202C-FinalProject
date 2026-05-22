#include "nvs_storage.h"
#include "config.h"
#include <Arduino.h>
#include <nvs_flash.h>
#include <nvs.h>
#include <string.h>
#include <stdio.h>

static nvs_handle_t s_handle;
static bool s_open = false;

bool nvs_storage_init() {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        err = nvs_flash_init();
    }
    if (err != ESP_OK) {
        Serial.printf("[nvs] flash_init failed: %d\n", err);
        return false;
    }

    err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &s_handle);
    if (err != ESP_OK) {
        Serial.printf("[nvs] open failed: %d\n", err);
        return false;
    }

    s_open = true;
    return true;
}

// Key format: "peer_AABBCCDDEEFF" (17 chars), value: 22-byte blob (6 MAC + 16 LMK)
static void mac_to_key(const uint8_t mac[6], char key_out[18]) {
    snprintf(key_out, 18, "%02X%02X%02X%02X%02X%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

bool nvs_save_peer(const uint8_t mac[6], const uint8_t lmk[16]) {
    if (!s_open) return false;

    char key[18];
    mac_to_key(mac, key);

    uint8_t blob[22];
    memcpy(blob,     mac, 6);
    memcpy(blob + 6, lmk, 16);

    esp_err_t err = nvs_set_blob(s_handle, key, blob, sizeof(blob));
    if (err != ESP_OK) {
        Serial.printf("[nvs] set_blob failed: %d\n", err);
        return false;
    }
    nvs_commit(s_handle);
    return true;
}

void nvs_load_all_peers(peer_load_cb_t cb) {
    if (!s_open || !cb) return;

    nvs_iterator_t it = nullptr;
    esp_err_t err = nvs_entry_find(NVS_DEFAULT_PART_NAME, NVS_NAMESPACE, NVS_TYPE_BLOB, &it);
    while (err == ESP_OK && it != nullptr) {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);

        uint8_t blob[22];
        size_t blob_len = sizeof(blob);
        if (nvs_get_blob(s_handle, info.key, blob, &blob_len) == ESP_OK && blob_len == 22) {
            cb(blob, blob + 6);
        }

        err = nvs_entry_next(&it);
    }
    nvs_release_iterator(it);
}

bool nvs_clear_all() {
    if (!s_open) return false;
    esp_err_t err = nvs_erase_all(s_handle);
    nvs_commit(s_handle);
    return err == ESP_OK;
}
