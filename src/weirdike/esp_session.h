/*
 * WeirdIKE -- src/esp/esp_session.h : stateful ESP sender/receiver (M2d-3). Pure C99.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Combines the three tested ESP building blocks into one runtime object:
 *   TX: esp_seq_take -> RNG IV -> esp_seal
 *   RX: peek Seq -> esp_replay_precheck -> esp_open (into a PRIVATE temp) -> esp_replay_commit
 *       -> only THEN copy the plaintext to the caller
 * so the anti-replay contract is enforced structurally (no authenticated-but-replayed plaintext ever
 * reaches the caller). The session DEEP-COPIES the CHILD_SA keys and owns its runtime state; deinit
 * zeroizes everything. Fixed suite: AES-CBC-256 + HMAC-SHA2-256-128. No TS policy, no UDP-4500 here.
 */
#ifndef WEIRDIKE_ESP_SESSION_H
#define WEIRDIKE_ESP_SESSION_H

#include <stdint.h>
#include <stddef.h>
#include "weirdike.h"     /* weirdike_child_sa_t, weirdike_crypto_t */
#include "esp.h"
#include "esp_replay.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ESP_SESSION_EXHAUSTED (-2)   /* TX sequence space used up -> SA must be rekeyed */

typedef struct {
    const weirdike_crypto_t *crypto;

    uint32_t inbound_spi;
    uint32_t outbound_spi;

    uint8_t enc_key_in[32];    uint8_t enc_key_out[32];
    size_t  enc_key_len;       /* 16/24/32 = AES-CBC-128/192/256 (A1) */
    uint8_t integ_key_in[64];  uint8_t integ_key_out[64];
    size_t  integ_key_len;     /* 20 SHA1-96 (ICV 12), 32 SHA2-256-128 (16), 48 SHA2-384-192 (24), 64 SHA2-512-256 (32) */

    esp_seq_t    tx_seq;
    esp_replay_t rx_replay;
    /* RX scratch, HOST-PLACED (>= ESP_MAX_PACKET; PSRAM on the ESP32-P4, heap on Linux, a static
     * block on a small MCU). The plaintext of an inbound packet is decrypted HERE, checked, the
     * replay window committed, and only then copied to the caller -- never on the stack, never in
     * the caller's buffer before the commit. Same memory model as the IKE workspace. */
    uint8_t *scratch;
    size_t   scratch_cap;
} esp_session_t;

/* scratch: host-placed RX area (>= ESP_MAX_PACKET), must outlive the session; may be shared by
 * sessions that are never opened concurrently. Missing/too small -> -1.
 * Deep-copy the CHILD_SA keys/SPIs into a fresh session. Rejects a non AES-CBC-256 + HMAC-SHA256-128
 * child or a crypto adapter missing random/aes_cbc/hmac_sha256. Returns 0, or -1 on bad args. */
int esp_session_init(esp_session_t *s, const weirdike_child_sa_t *child, const weirdike_crypto_t *crypto,
                     uint8_t *scratch, size_t scratch_cap);

/* Zeroize keys + counters/replay state. Safe to call twice. */
void esp_session_deinit(esp_session_t *s);

/* Seal one outbound ESP packet (fresh IV, next TX sequence number). Returns 0 on success,
 * ESP_SESSION_EXHAUSTED if the sequence space is used up (rekey required), or -1 on other errors.
 * A consumed sequence number is NEVER rolled back on a later failure (a gap is harmless; reuse is not). */
int esp_session_seal(esp_session_t *s, uint8_t next_header,
                     const uint8_t *payload, size_t payload_len,
                     uint8_t *packet, size_t packet_cap, size_t *packet_len);

/* Open one inbound ESP packet: SPI check -> replay precheck -> ICV verify -> decrypt into the
 * session scratch -> padding/format check -> replay commit -> copy the plaintext to payload.
 * Returns 0 (sets *next_header + payload), or -1 (wrong SA / replay / ICV / padding / payload_cap
 * too small). On -1 the replay window is unchanged and no usable plaintext is left in payload or
 * the scratch: the caller never sees plaintext that was not committed. */
int esp_session_open(esp_session_t *s, const uint8_t *packet, size_t packet_len,
                     uint8_t *next_header, uint8_t *payload, size_t payload_cap, size_t *payload_len);

#ifdef __cplusplus
}
#endif

#endif /* WEIRDIKE_ESP_SESSION_H */
