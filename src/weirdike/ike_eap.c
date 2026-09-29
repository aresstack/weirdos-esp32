/*
 * WeirdIKE -- ike_eap.c : bounded EAP / EAP-MSCHAPv2 wire helpers. Pure C99.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "ike_eap.h"
#include <string.h>

static uint16_t be16(const uint8_t *p) { return (uint16_t)(((uint16_t)p[0] << 8) | p[1]); }
static void put16(uint8_t *p, size_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }

int eap_parse(const uint8_t *data, size_t len, eap_packet_t *out) {
    if (!data || !out || len < 4) return -1;
    memset(out, 0, sizeof(*out));
    uint16_t wire = be16(data + 2);
    if (wire != len) return -1;   /* IKE EAP payload has no link-layer padding -> require exact */
    out->code = data[0]; out->identifier = data[1];
    if (out->code == EAP_CODE_SUCCESS || out->code == EAP_CODE_FAILURE) {
        if (len != 4) return -1;
        return 0;
    }
    if (out->code != EAP_CODE_REQUEST && out->code != EAP_CODE_RESPONSE) return -1;
    if (len < 5) return -1;
    out->type = data[4];
    out->type_data = data + 5;
    out->type_data_len = len - 5;
    return 0;
}

int eap_build_identity_response(uint8_t identifier, const uint8_t *identity, size_t identity_len,
                                uint8_t *out, size_t cap, size_t *out_len) {
    size_t n = 5u + identity_len;
    if (!out || !out_len || (identity_len && !identity) || n > 0xffffu || cap < n) return -1;
    out[0] = EAP_CODE_RESPONSE; out[1] = identifier; put16(out + 2, n); out[4] = EAP_TYPE_IDENTITY;
    if (identity_len) memcpy(out + 5, identity, identity_len);
    *out_len = n; return 0;
}

/* Full Request/Response MSCHAPv2 header: EAP(4) | Type(1) | Opcode(1) | MS-ID(1) | MS-Length(2). */
#define MS_FULL_HDR 9u

static int parse_full_mschap(const uint8_t *data, size_t len, uint8_t code, uint8_t opcode,
                             eap_packet_t *ep) {
    if (eap_parse(data, len, ep) != 0) return -1;
    if (ep->code != code || ep->type != EAP_TYPE_MSCHAPV2 || ep->type_data_len < 4) return -1;
    if (ep->type_data[0] != opcode) return -1;
    /* MS-Length is measured from Opcode, i.e. EAP Length - Code/Id/Len/Type = len-5. */
    if (be16(ep->type_data + 2) != len - 5u) return -1;
    return 0;
}

int eap_mschapv2_parse_challenge(const uint8_t *data, size_t len, eap_mschapv2_challenge_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    eap_packet_t ep;
    if (parse_full_mschap(data, len, EAP_CODE_REQUEST, MSCHAPV2_OP_CHALLENGE, &ep) != 0) return -1;
    /* type_data: opcode | ms-id | ms-length2 | value-size | challenge16 | optional name */
    if (ep.type_data_len < 4u + 1u + 16u) return -1;
    if (ep.type_data[4] != 16) return -1;
    out->eap_identifier = ep.identifier;
    out->mschapv2_identifier = ep.type_data[1];
    memcpy(out->authenticator_challenge, ep.type_data + 5, 16);
    out->name = ep.type_data + 21;
    out->name_len = ep.type_data_len - 21;
    return 0;
}

int eap_mschapv2_build_response(uint8_t eap_identifier, uint8_t mschapv2_identifier,
                                const uint8_t peer_challenge[16], const uint8_t nt_response[24],
                                const uint8_t *identity, size_t identity_len,
                                uint8_t *out, size_t cap, size_t *out_len) {
    /* after full header: Value-Size1 + Peer16 + Reserved8 + NT24 + Flags1 + Identity */
    size_t n = MS_FULL_HDR + 1u + 16u + 8u + 24u + 1u + identity_len;
    if (!out || !out_len || !peer_challenge || !nt_response || (identity_len && !identity) ||
        n > 0xffffu || cap < n) return -1;
    memset(out, 0, n);
    out[0] = EAP_CODE_RESPONSE; out[1] = eap_identifier; put16(out + 2, n); out[4] = EAP_TYPE_MSCHAPV2;
    out[5] = MSCHAPV2_OP_RESPONSE; out[6] = mschapv2_identifier; put16(out + 7, n - 5u);
    out[9] = 49;   /* response Value-Size */
    memcpy(out + 10, peer_challenge, 16);
    /* out[26..33] reserved = 0 */
    memcpy(out + 34, nt_response, 24);
    out[58] = 0;   /* flags */
    if (identity_len) memcpy(out + 59, identity, identity_len);
    *out_len = n; return 0;
}

static int hex_nibble(uint8_t c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

int eap_mschapv2_parse_success(const uint8_t *data, size_t len, eap_mschapv2_success_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    eap_packet_t ep;
    if (parse_full_mschap(data, len, EAP_CODE_REQUEST, MSCHAPV2_OP_SUCCESS, &ep) != 0) return -1;
    /* Message begins after opcode|ms-id|ms-len (4 bytes). Require S=<40 hex> token. */
    const uint8_t *m = ep.type_data + 4; size_t mn = ep.type_data_len - 4;
    const uint8_t *s = NULL;
    for (size_t i = 0; i + 42 <= mn; i++) {
        if ((i == 0 || m[i - 1] == ' ') && m[i] == 'S' && m[i + 1] == '=') { s = m + i + 2; break; }
    }
    if (!s) return -1;
    for (size_t i = 0; i < 20; i++) {
        int hi = hex_nibble(s[2 * i]), lo = hex_nibble(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out->authenticator_response[i] = (uint8_t)((hi << 4) | lo);
    }
    out->eap_identifier = ep.identifier;
    out->mschapv2_identifier = ep.type_data[1];
    out->message = m; out->message_len = mn;
    return 0;
}

int eap_mschapv2_build_success_response(uint8_t eap_identifier, uint8_t out[6], size_t *out_len) {
    if (!out || !out_len) return -1;
    out[0] = EAP_CODE_RESPONSE; out[1] = eap_identifier; out[2] = 0; out[3] = 6;
    out[4] = EAP_TYPE_MSCHAPV2; out[5] = MSCHAPV2_OP_SUCCESS;
    *out_len = 6; return 0;
}

int eap_mschapv2_is_failure(const uint8_t *data, size_t len) {
    eap_packet_t ep;
    return parse_full_mschap(data, len, EAP_CODE_REQUEST, MSCHAPV2_OP_FAILURE, &ep) == 0 ? 1 : 0;
}
