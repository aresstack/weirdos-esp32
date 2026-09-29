/*
 * WeirdIKE -- ike_eap.h : bounded EAP / EAP-MSCHAPv2 wire helpers.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef WEIRDIKE_IKE_EAP_H
#define WEIRDIKE_IKE_EAP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IKE_PL_EAP 48

#define EAP_CODE_REQUEST  1
#define EAP_CODE_RESPONSE 2
#define EAP_CODE_SUCCESS  3
#define EAP_CODE_FAILURE  4
#define EAP_TYPE_IDENTITY 1
#define EAP_TYPE_MSCHAPV2 26

#define MSCHAPV2_OP_CHALLENGE 1
#define MSCHAPV2_OP_RESPONSE  2
#define MSCHAPV2_OP_SUCCESS   3
#define MSCHAPV2_OP_FAILURE   4
#define MSCHAPV2_OP_CHANGE_PASSWORD 7

typedef struct {
    uint8_t code;
    uint8_t identifier;
    uint8_t type;                 /* 0 for outer EAP Success/Failure */
    const uint8_t *type_data;     /* borrowed from input */
    size_t type_data_len;
} eap_packet_t;

/* Parse one EAP packet exactly. Request/Response require a Type byte; Success/Failure require
 * Length=4 and therefore have type=0. Reject unknown Code, truncation and trailing bytes. */
int eap_parse(const uint8_t *data, size_t len, eap_packet_t *out);

/* Build an EAP-Response/Identity with the request's Identifier. */
int eap_build_identity_response(uint8_t identifier, const uint8_t *identity, size_t identity_len,
                                uint8_t *out, size_t cap, size_t *out_len);

typedef struct {
    uint8_t eap_identifier;
    uint8_t mschapv2_identifier;
    uint8_t authenticator_challenge[16];
    const uint8_t *name; size_t name_len;       /* borrowed */
} eap_mschapv2_challenge_t;

/* Parse EAP-Request/MSCHAPv2 Challenge. Enforce Value-Size=16 and MS-Length=EAP-Length-5. */
int eap_mschapv2_parse_challenge(const uint8_t *data, size_t len, eap_mschapv2_challenge_t *out);

/* Build EAP-Response/MSCHAPv2 Response: Peer-Challenge16 | Reserved8 | NT-Response24 | Flags0,
 * then the complete user identity sent on the wire (domain prefix is allowed here). */
int eap_mschapv2_build_response(uint8_t eap_identifier, uint8_t mschapv2_identifier,
                                const uint8_t peer_challenge[16], const uint8_t nt_response[24],
                                const uint8_t *identity, size_t identity_len,
                                uint8_t *out, size_t cap, size_t *out_len);

typedef struct {
    uint8_t eap_identifier;
    uint8_t mschapv2_identifier;
    uint8_t authenticator_response[20];   /* binary decoded S=<40 uppercase/lowercase hex> */
    const uint8_t *message; size_t message_len;  /* complete ASCII message after MS header */
} eap_mschapv2_success_t;

/* Parse EAP-Request/MSCHAPv2 Success and require a valid S=<40 hex> authenticator response. */
int eap_mschapv2_parse_success(const uint8_t *data, size_t len, eap_mschapv2_success_t *out);

/* Acknowledge a verified MSCHAPv2 Success Request. Per the EAP-MSCHAPv2 format this is the short
 * six-octet packet: EAP Response | same Identifier | Length=6 | Type=26 | Opcode=Success. */
int eap_mschapv2_build_success_response(uint8_t eap_identifier,
                                        uint8_t out[6], size_t *out_len);

/* Inspect an EAP-Request/MSCHAPv2 Failure without trying password-change/retry semantics yet. */
int eap_mschapv2_is_failure(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* WEIRDIKE_IKE_EAP_H */
