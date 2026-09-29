/*
 * WeirdIKE -- eap_mschapv2_peer.h : client-side EAP-MSCHAPv2 method state machine.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef WEIRDIKE_EAP_MSCHAPV2_PEER_H
#define WEIRDIKE_EAP_MSCHAPV2_PEER_H

#include <stddef.h>
#include <stdint.h>
#include "ike_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EAP_MSCHAPV2_MAX_IDENTITY 256
#define EAP_MSCHAPV2_MAX_PASSWORD 256
#define EAP_MSCHAPV2_MAX_PACKET   768

typedef enum {
    EAP_PEER_WAIT_REQUEST = 0,
    EAP_PEER_WAIT_METHOD_RESULT,
    EAP_PEER_WAIT_OUTER_RESULT,
    EAP_PEER_COMPLETE,
    EAP_PEER_FAILED
} eap_mschapv2_peer_state_t;

typedef struct {
    const weirdike_crypto_t *crypto;
    uint8_t identity[EAP_MSCHAPV2_MAX_IDENTITY]; size_t identity_len;
    uint8_t password[EAP_MSCHAPV2_MAX_PASSWORD]; size_t password_len;
    eap_mschapv2_peer_state_t state;

    uint8_t authenticator_challenge[16];
    uint8_t peer_challenge[16];
    uint8_t nt_response[24];
    uint8_t expected_authenticator_response[20];
    uint8_t msk[64];
    int have_method_keys;

    /* RFC 3748 duplicate Request handling: compare the complete request, then resend the exact
     * previous response without reprocessing it. Identifier alone may legally wrap/reappear. */
    int have_last_request;
    uint8_t last_request[EAP_MSCHAPV2_MAX_PACKET]; size_t last_request_len;
    uint8_t last_response[EAP_MSCHAPV2_MAX_PACKET]; size_t last_response_len;
} eap_mschapv2_peer_t;

/* Deep-copy credentials into the method state. Domain-qualified identities are transmitted whole;
 * ChallengeHash uses only the account part after '\\' as MSCHAPv2 requires. */
int eap_mschapv2_peer_init(eap_mschapv2_peer_t *p, const weirdike_crypto_t *crypto,
                           const uint8_t *identity, size_t identity_len,
                           const uint8_t *password, size_t password_len);

/* Process one complete EAP packet from the authenticator. If a response is required, write it and
 * set *response_len > 0. Outer EAP Success completes the method and produces no EAP response.
 * Return 0 for a valid transition, -1 for malformed/unexpected/authentication failure. */
int eap_mschapv2_peer_process(eap_mschapv2_peer_t *p,
                              const uint8_t *request, size_t request_len,
                              uint8_t *response, size_t response_cap, size_t *response_len);

int eap_mschapv2_peer_complete(const eap_mschapv2_peer_t *p);

/* Copy the 64-byte EAP MSK after outer EAP Success. Secret output; caller must wipe it. */
int eap_mschapv2_peer_get_msk(const eap_mschapv2_peer_t *p, uint8_t out[64]);

/* Wipe password, MSK and all challenge/response material. */
void eap_mschapv2_peer_deinit(eap_mschapv2_peer_t *p);

#ifdef __cplusplus
}
#endif

#endif /* WEIRDIKE_EAP_MSCHAPV2_PEER_H */
