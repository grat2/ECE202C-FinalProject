# ECE 202C Final Project — ESP-NOW Secure Pairing System

## Overview

Currently, to enable encrypted ESP-NOW communications, a user requires these things from both devices that need to communicate with each other prior to initiating the communication channel:
- MAC address
- PMK/LMK (private keys for encryption of data to transmit/receive)

This project implements a system where two devices can "pair" and share this information securely without any prior knowledge of the other device — only physical access to both is required. The goal is a pairing system analogous to the Bluetooth standard: convenient setup with strong security guarantees.

---

## Project Structure

```
ECE202C-FinalProject/
├── ESP-Pairing/        # Secure pairing firmware (ECDH + fingerprint verification)
├── ESP-Pairing-MITM/   # Intentionally vulnerable pairing target (for MITM demo)
└── ESP-Adversary/      # MITM adversary firmware that attacks ESP-Pairing-MITM
```

**ESP-Pairing** is the main deliverable. **ESP-Pairing-MITM** and **ESP-Adversary** exist as a pair to demonstrate the attack that ESP-Pairing's fingerprint verification is designed to defeat.

---

## How Pairing Works

1. User types `pair` on Device A — it generates an ECDH (P-256) key pair and broadcasts a `PAIRING_REQUEST` containing its public key.
2. User types `pair` on Device B — it generates its own key pair and sends a `PAIRING_RESPONSE` directly back to Device A with its public key.
3. Both devices independently compute `shared_secret = ECDH(my_private, their_public)`.
4. Both derive keys via SHA-256: `PMK = digest[0..15]`, `LMK = digest[16..31]`.
5. Both derive a 3-byte fingerprint via a domain-separated SHA-256: `SHA-256("FP" || shared_secret)[0..2]`, displayed as 6 hex digits.
6. **Users compare fingerprints** out-of-band (read them aloud or look at both serial terminals).
7. Each user types `confirm` if the fingerprints match — only then are the PMK and LMK installed and the peer registered. Type `cancel` to abort.
8. Peer info (MAC + LMK) and the PMK are saved to NVS and restored automatically after a reboot.

### Serial Commands

| Command | Action |
|---|---|
| `pair` | Enter pairing mode |
| `confirm` | Accept the pending pairing (fingerprints match) |
| `cancel` | Reject the pending pairing (fingerprints differ) |
| `list` | List all paired peers saved in NVS |
| `send <msg>` | Send an encrypted message to all paired peers |
| `clear` | Erase all saved peers from NVS |
| `mac` | Print this device's MAC address |

---

## Security Properties

- **Passive eavesdropping resistance**: Public keys are transmitted in the clear, but an eavesdropper cannot derive the shared secret without one of the private keys (ECDH hardness assumption).
- **MITM resistance via fingerprint verification**: An active attacker who intercepts and replaces public keys will cause each victim to derive a different shared secret, producing mismatched fingerprints. The users detect and abort the attack before any keys are installed.
- **Invalid-curve attack protection**: The peer's public key is validated against the P-256 curve (`mbedtls_ecp_check_pubkey`) before use, preventing a class of attacks that could leak the private key via a crafted off-curve point.
- **Encrypted post-pairing communication**: All data frames after pairing use AES encryption via the ESP32's hardware ESP-NOW stack (PMK + per-peer LMK).
- **NVS persistence**: Paired peer records and the PMK survive power cycles without requiring re-pairing.

---

## Known Limitations and Vulnerabilities

### 1. Plaintext NVS Storage (Physical Access Attack)

**Severity: High (requires physical access)**

The PMK and all peer LMKs are stored unencrypted in the ESP32's NVS flash partition. An attacker with physical access to a device can dump the flash (e.g., `esptool read_flash`) and extract all key material in plaintext. Combined with a captured radio trace, this allows full decryption of all past and future ESP-NOW traffic.

**Mitigation**: ESP-IDF supports NVS encryption via `nvs_flash_secure_init()`, which protects the NVS partition using a flash-encryption key stored in eFuses. Enabling it would significantly raise the bar for physical extraction, but requires provisioning each device with a unique flash encryption key — added complexity beyond the scope of this demo.

### 2. No Forward Secrecy

**Severity: Medium**

The ECDH handshake uses ephemeral key pairs (a fresh pair is generated for each pairing session), which would normally provide forward secrecy. However, once the derived PMK and LMK are persisted to NVS, they are no longer ephemeral. A device compromise at any future point exposes all keys and allows decryption of any previously recorded ciphertext.

**Mitigation**: True forward secrecy would require session-level key renegotiation (e.g., re-running the ECDH handshake for each communication session rather than reusing stored keys). This conflicts with the goal of persistent, reconnection-free pairing and would require a more complex protocol.

### 3. PMK Overwrite on Re-pairing

**Severity: Medium (multi-peer scenarios) — Mitigated**

The ESP-NOW PMK is a device-global setting. If a new pairing session were allowed to derive and overwrite the PMK, any previously paired peers relying on the old PMK would stop working. In multi-peer scenarios this is also a denial-of-service vector: an adversary within radio range who can trigger a pairing request could sever all existing encrypted sessions.

**Mitigation (implemented)**: The device PMK is generated from hardware-RNG randomness on first boot, persisted to NVS, and never changed again. Each pairing session now derives only a per-peer LMK from the ECDH exchange. Because the PMK is stable, adding a new peer cannot disrupt communication with existing peers. The PMK is set at device startup (before re-registering NVS-persisted peers) so it is already active when peers are loaded.

### 4. Single Global PMK Across All Peers

**Severity: Low–Medium**

Because the PMK is device-global and shared across all peers (see limitation 3), the PMK does not provide isolation between different pairing relationships. If any single peer's pairing session is compromised, the PMK context for all peers on that device is affected.

**Mitigation**: Same as limitation 3 — a stable, randomly generated PMK decouples peer isolation from the PMK entirely and places all per-peer secrecy in the LMK, which is already per-peer.

---

## MITM Demo

The `ESP-Pairing-MITM` firmware is an intentionally vulnerable version of the pairing code with fingerprint verification removed. The `ESP-Adversary` firmware demonstrates the attack it is vulnerable to:

1. Flash `ESP-Adversary` onto one ESP32 and `ESP-Pairing-MITM` onto two others (Device A and B).
2. On the adversary serial console, type `attack on`.
3. Type `pair` on Device A. The adversary intercepts the handshake and responds with its own public key — Device A believes it paired with Device B, but it actually paired with the adversary.
4. Type `pair` on Device B. Same interception occurs.
5. Type `relay on` on the adversary. Messages between A and B are now transparently forwarded through the adversary, which can read every frame.
6. Type `inject <msg>` to send forged messages to both victims.

The `ESP-Pairing` firmware defeats this attack: an adversary that substitutes its public key causes the fingerprints on the two victim devices to differ, alerting the users before any keys are committed.
