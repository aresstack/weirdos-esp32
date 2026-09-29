/*
 * WeirdIKE -- src/esp/esp.h : ESP dataplane seal/open (RFC 4303 + RFC 3602). Pure C99.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * DATA PLANE, deliberately separate from the IKE control plane (src/core). Fixed suite:
 * ENCR_AES_CBC-256 + AUTH_HMAC_SHA2_256_128, ESP-over-IP (no UDP-4500 wrapper here).
 *
 * Packet layout (encrypt-then-MAC):
 *    0..3    SPI              (big-endian)
 *    4..7    Sequence Number  (big-endian)
 *    8..23   IV               (16 B, caller-supplied -> deterministic, RNG lives in the sender)
 *   24..N    Ciphertext = AES-CBC-256(enc_key, IV, plaintext)
 *              plaintext = payload | Padding(01 02 .. pad_len) | PadLength | NextHeader
 *   last16   ICV = first 16 bytes of HMAC-SHA256(integ_key, SPI | Seq | IV | Ciphertext)
 *
 * AES-CBC block alignment:  payload_len + pad_len + 2 == 0 (mod 16).
 * Tunnel mode with an inner IPv4 packet uses NextHeader = 4 (IPPROTO_IPIP).
 *
 * NO sequence-number counter and NO anti-replay state here: seq is a plain in/out value. That
 * (and UDP-4500/NAT-T) is a later slice.
 */
#ifndef WEIRDIKE_ESP_H
#define WEIRDIKE_ESP_H

#include <stdint.h>
#include <stddef.h>
#include "ike_crypto.h"   /* weirdike_crypto_t (aes_cbc + hmac_sha256) */

#ifdef __cplusplus
extern "C" {
#endif

#define ESP_SPI_LEN     4
#define ESP_SEQ_LEN     4
#define ESP_IV_LEN      16
#define ESP_ICV_LEN     16
#define ESP_HDR_LEN     (ESP_SPI_LEN + ESP_SEQ_LEN + ESP_IV_LEN)   /* 24: SPI|Seq|IV */
#define ESP_KEY_LEN     32                                          /* AES-256 + HMAC-SHA256 key */
#define ESP_MAX_PACKET  1500

/* NextHeader value for tunnel mode carrying an inner IPv4 packet (IPPROTO_IPIP). */
#define ESP_NH_IPV4     4

/* Peek the ESP header (SPI + Sequence Number) without any authentication. Needs packet_len >= 8.
 * Returns 0 and sets spi + seq, or -1 on bad args/length. The returned SPI/Seq are UNAUTHENTICATED
 * until esp_open() succeeds -- use only to pre-screen (e.g. anti-replay precheck / SA demux). */
int esp_peek_header(const uint8_t *packet, size_t packet_len, uint32_t *spi, uint32_t *seq);

/* Seal one ESP packet. iv[16] is caller-supplied. Writes SPI|Seq|IV|ciphertext|ICV into out and
 * sets *out_len. Returns 0 on success; -1 on bad args / key length != 32 / buffer too small. */
int esp_seal(const weirdike_crypto_t *crypto,
             uint32_t spi, uint32_t seq,
             const uint8_t *enc_key, size_t enc_key_len,
             const uint8_t *integ_key, size_t integ_key_len,
             const uint8_t iv[ESP_IV_LEN], uint8_t next_header,
             const uint8_t *payload, size_t payload_len,
             uint8_t *out, size_t out_cap, size_t *out_len);

/* Open one ESP packet into CALLER-SUPPLIED scratch (>= the packet's ciphertext, i.e. pass
 * ESP_MAX_PACKET; workspace/PSRAM on a host, never the stack). Order, unchanged and structural:
 * SPI == expected_spi -> ICV (constant-time) -> ONLY THEN decrypt into scratch -> trailer check
 * (01 02 .. pad_len). On success the plaintext payload is scratch[0 .. *payload_len) and *seq_out /
 * *next_header_out are set; the caller copies it out (esp_open) or commits its replay state first
 * and copies afterwards (esp_session_open). Returns 0, or -1 on bad args / bounds / SPI mismatch /
 * ICV mismatch / bad padding -- then the scratch is wiped: no usable plaintext survives a failure. */
int esp_open_scratch(const weirdike_crypto_t *crypto,
                     uint32_t expected_spi,
                     const uint8_t *enc_key, size_t enc_key_len,
                     const uint8_t *integ_key, size_t integ_key_len,
                     const uint8_t *packet, size_t packet_len,
                     uint8_t *scratch, size_t scratch_cap,
                     uint32_t *seq_out, uint8_t *next_header_out, size_t *payload_len);

/* Convenience: esp_open_scratch() + copy of the payload to payload_out (*payload_len), scratch
 * wiped. Returns 0, or -1 (also when payload_cap is too small); on any failure no usable plaintext
 * is left in payload_out or scratch. */
int esp_open(const weirdike_crypto_t *crypto,
             uint32_t expected_spi,
             const uint8_t *enc_key, size_t enc_key_len,
             const uint8_t *integ_key, size_t integ_key_len,
             const uint8_t *packet, size_t packet_len,
             uint8_t *scratch, size_t scratch_cap,
             uint32_t *seq_out, uint8_t *next_header_out,
             uint8_t *payload_out, size_t payload_cap, size_t *payload_len);

#ifdef __cplusplus
}
#endif

#endif /* WEIRDIKE_ESP_H */
