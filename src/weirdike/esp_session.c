/*
 * WeirdIKE -- src/esp/esp_session.c : stateful ESP sender/receiver (M2d-3).
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "esp_session.h"
#include <string.h>

static void wipe(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

int esp_session_init(esp_session_t *s, const weirdike_child_sa_t *child, const weirdike_crypto_t *crypto,
                     uint8_t *scratch, size_t scratch_cap) {
    if (!s || !child || !crypto) return -1;
    if (!crypto->random || !crypto->aes_cbc) return -1;
    if (!scratch || scratch_cap < ESP_MAX_PACKET) return -1;   /* host-placed RX scratch is mandatory */
    if (child->encr != WEIRDIKE_ENCR_AES_CBC) return -1;
    /* AP9: two ESP integrity suites -- HMAC-SHA2-256-128 (32-B key, 16-B ICV) and HMAC-SHA1-96
     * (20-B key, 12-B ICV, LANCOM DEFAULT alternative). Key lengths must match the algorithm. */
    size_t ilen;
    if      (child->integ == WEIRDIKE_AUTH_HMAC_SHA2_256_128 && crypto->hmac_sha256) ilen = 32;
    else if (child->integ == WEIRDIKE_AUTH_HMAC_SHA1_96      && crypto->hmac_sha1)   ilen = 20;
    else if (child->integ == WEIRDIKE_AUTH_HMAC_SHA2_384_192 && crypto->hmac_sha384) ilen = 48;   /* A2 */
    else if (child->integ == WEIRDIKE_AUTH_HMAC_SHA2_512_256 && crypto->hmac_sha512) ilen = 64;   /* A2 */
    else return -1;
    /* A1: AES-CBC-128/192/256 -- both directions carry the same negotiated key size. */
    size_t elen = child->enc_key_in_len;
    if ((elen != 16 && elen != 24 && elen != 32) || child->enc_key_out_len != elen ||
        child->integ_key_in_len != ilen || child->integ_key_out_len != ilen) return -1;

    memset(s, 0, sizeof(*s));
    s->crypto        = crypto;
    s->inbound_spi   = child->inbound_spi;
    s->outbound_spi  = child->outbound_spi;
    s->enc_key_len   = elen;
    s->integ_key_len = ilen;
    memcpy(s->enc_key_in,    child->enc_key_in,    32);
    memcpy(s->enc_key_out,   child->enc_key_out,   32);
    memcpy(s->integ_key_in,  child->integ_key_in,  ilen);
    memcpy(s->integ_key_out, child->integ_key_out, ilen);
    esp_seq_init(&s->tx_seq);
    esp_replay_init(&s->rx_replay);
    s->scratch = scratch; s->scratch_cap = scratch_cap;
    return 0;
}

void esp_session_deinit(esp_session_t *s) {
    if (!s) return;
    if (s->scratch && s->scratch_cap) wipe(s->scratch, s->scratch_cap);   /* no plaintext remnants */
    wipe(s, sizeof(*s));   /* keys + SPIs + counters + replay state */
}

int esp_session_seal(esp_session_t *s, uint8_t next_header,
                     const uint8_t *payload, size_t payload_len,
                     uint8_t *packet, size_t packet_cap, size_t *packet_len) {
    if (!s || !packet_len) return -1;
    *packet_len = 0;

    uint32_t seq;
    if (esp_seq_take(&s->tx_seq, &seq) != 0) return ESP_SESSION_EXHAUSTED;

    uint8_t iv[ESP_IV_LEN];
    if (s->crypto->random(s->crypto->ctx, iv, ESP_IV_LEN) != 0) return -1;  /* seq stays consumed */

    /* esp_seal returns -1 on failure; the sequence number is intentionally NOT rolled back. */
    return esp_seal(s->crypto, s->outbound_spi, seq, s->enc_key_out, s->enc_key_len, s->integ_key_out, s->integ_key_len,
                    iv, next_header, payload, payload_len, packet, packet_cap, packet_len);
}

int esp_session_open(esp_session_t *s, const uint8_t *packet, size_t packet_len,
                     uint8_t *next_header, uint8_t *payload, size_t payload_cap, size_t *payload_len) {
    if (!s || !payload_len) return -1;
    *payload_len = 0;
    if (!packet || !payload) return -1;

    uint32_t spi = 0, seq = 0;
    if (esp_peek_header(packet, packet_len, &spi, &seq) != 0) return -1;
    if (spi != s->inbound_spi) return -1;                          /* wrong SA (cheap, pre-crypto) */
    if (esp_replay_precheck(&s->rx_replay, seq) != 0) return -1;   /* dup/old -> NO state change */

    /* Decrypt into the session's PRIVATE, host-placed scratch (not the stack, not the caller's
     * buffer) so nothing reaches the caller before the replay commit. */
    if (!s->scratch || s->scratch_cap < ESP_MAX_PACKET) return -1;
    uint8_t *tmp = s->scratch; size_t tmp_len = 0;
    uint32_t auth_seq = 0; uint8_t nh = 0;
    if (esp_open_scratch(s->crypto, s->inbound_spi, s->enc_key_in, s->enc_key_len, s->integ_key_in, s->integ_key_len,
                         packet, packet_len, tmp, s->scratch_cap, &auth_seq, &nh, &tmp_len) != 0)
        return -1;                                                /* ICV/pad failed -> window intact, scratch wiped */

    /* Authenticated. Advance the window using the AUTHENTICATED seq, re-checking current state. */
    if (esp_replay_commit(&s->rx_replay, auth_seq) != 0) { wipe(tmp, tmp_len); return -1; }
    if (tmp_len > payload_cap) { wipe(tmp, tmp_len); return -1; }

    if (tmp_len) memcpy(payload, tmp, tmp_len);   /* committed -> now (and only now) the caller gets it */
    *payload_len = tmp_len;
    if (next_header) *next_header = nh;
    wipe(tmp, tmp_len);
    return 0;
}
