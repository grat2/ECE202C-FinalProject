/*
 * nvs_storage.h
 *
 * Persistence layer for paired-peer records using the ESP32's Non-Volatile
 * Storage (NVS) partition — a key-value store in flash memory that survives
 * power cycles and firmware updates (unless the NVS partition is erased).
 *
 * Each record stores a peer's MAC address (6 bytes) and its LMK (16 bytes).
 * The NVS key for each record is the peer's MAC formatted as a 12-char hex
 * string (e.g. "A1B2C3D4E5F6"), which guarantees uniqueness and human
 * readability when inspecting flash contents with `nvs_read` tooling.
 *
 * On boot, nvs_load_all_peers() is called to re-register every saved peer
 * with the ESP-NOW stack so encrypted communication resumes automatically.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

// Callback invoked once per saved peer during nvs_load_all_peers().
// mac points to 6 bytes (MAC address), lmk points to 16 bytes (Local Master Key).
typedef void (*peer_load_cb_t)(const uint8_t mac[6], const uint8_t lmk[16]);

// nvs_storage_init — initialise the NVS flash partition and open the namespace.
// Must be called before any other function in this module.
bool nvs_storage_init();

// nvs_save_peer — write or overwrite the record for the given MAC/LMK pair.
// Records are committed to flash immediately so they are not lost on a crash.
bool nvs_save_peer(const uint8_t mac[6], const uint8_t lmk[16]);

// nvs_load_all_peers — iterate every saved record and invoke cb for each one.
// Typically called at boot to restore the ESP-NOW peer table from flash.
void nvs_load_all_peers(peer_load_cb_t cb);

// nvs_clear_all — erase all records from the NVS namespace and commit.
// Used by the "clear" serial command to unpair all devices.
bool nvs_clear_all();
