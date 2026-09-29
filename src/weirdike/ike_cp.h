/*
 * WeirdIKE -- ike_cp.h : IKEv2 Configuration Payload (RFC 7296 3.15), IPv4 client subset.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef WEIRDIKE_IKE_CP_H
#define WEIRDIKE_IKE_CP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IKE_PL_CP 47
#define IKE_CFG_REQUEST 1
#define IKE_CFG_REPLY   2
#define IKE_CFG_SET     3
#define IKE_CFG_ACK     4

#define IKE_CP_INTERNAL_IP4_ADDRESS 1
#define IKE_CP_INTERNAL_IP4_NETMASK 2
#define IKE_CP_INTERNAL_IP4_DNS     3
#define IKE_CP_INTERNAL_IP4_SUBNET 13
#define IKE_CP_INTERNAL_DNS_DOMAIN 25   /* F: DNS search domain (RFC 8598), UTF-8 string */
#define IKE_CP_MAX_DOMAIN 64

#define IKE_CP_MAX_DNS 4
#define IKE_CP_MAX_SUBNETS 4

/* Build one complete CP payload (generic payload header included) for a remote-access client.
 * INTERNAL_IP4_ADDRESS is always requested as required by RFC 7296. DNS/SUBNET requests are
 * optional zero-length attributes. next_payload is the payload following CP in the inner chain. */
int ike_cp_build_ipv4_request(uint8_t next_payload, int request_dns, int request_subnets,
                              uint8_t *out, size_t cap, size_t *out_len);

typedef struct {
    int have_address;
    uint8_t address[4];
    int have_netmask;
    uint8_t netmask[4];
    uint8_t dns[IKE_CP_MAX_DNS][4];
    size_t dns_count;
    struct { uint8_t network[4]; uint8_t netmask[4]; } subnet[IKE_CP_MAX_SUBNETS];
    size_t subnet_count;
    char   dns_domain[IKE_CP_MAX_DOMAIN + 1]; size_t dns_domain_len;   /* F: INTERNAL_DNS_DOMAIN (first), NUL-terminated */
    size_t ignored_attributes;  /* syntactically valid unsupported/overflow attributes */
} ike_cp_ipv4_reply_t;

/* Parse one complete CP payload (generic header included). Require CFG_REPLY and exact payload
 * length. Unknown attributes are ignored as RFC 7296 requires; malformed known lengths fail. */
int ike_cp_parse_ipv4_reply(const uint8_t *payload, size_t len, ike_cp_ipv4_reply_t *out);

#ifdef __cplusplus
}
#endif

#endif /* WEIRDIKE_IKE_CP_H */
