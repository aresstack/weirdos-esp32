/*
 * WeirdIKE -- ike_cp.c : IKEv2 Configuration Payload, IPv4 client subset. Pure C99.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "ike_cp.h"
#include <string.h>

#define GEN_HDR 4u
#define CP_HDR  4u   /* CFG Type + 3 reserved, after generic header */
#define ATTR_HDR 4u

static uint16_t be16(const uint8_t *p) { return (uint16_t)(((uint16_t)p[0] << 8) | p[1]); }
static void put16(uint8_t *p, size_t n) { p[0]=(uint8_t)(n>>8); p[1]=(uint8_t)n; }

static int append_empty_attr(uint8_t *out, size_t cap, size_t *off, uint16_t type) {
    if (!out || !off || *off + ATTR_HDR > cap) return -1;
    out[*off+0]=(uint8_t)(type>>8); out[*off+1]=(uint8_t)type;
    out[*off+2]=0; out[*off+3]=0; *off += ATTR_HDR; return 0;
}

int ike_cp_build_ipv4_request(uint8_t next_payload, int request_dns, int request_subnets,
                              uint8_t *out, size_t cap, size_t *out_len) {
    if (!out || !out_len || cap < GEN_HDR + CP_HDR) return -1;
    size_t off = GEN_HDR + CP_HDR;
    memset(out,0,cap < 32 ? cap : 32);
    out[0]=next_payload; out[1]=0;
    out[4]=IKE_CFG_REQUEST;
    /* A CFG_REQUEST must contain at least one INTERNAL_ADDRESS attribute. */
    if (append_empty_attr(out,cap,&off,IKE_CP_INTERNAL_IP4_ADDRESS)!=0) return -1;
    /* F: ask for the netmask and the DNS search domain as well (LANCOM/NCP request them too); a
     * responder that does not support them simply omits them (RFC 7296 3.15.1). */
    if (append_empty_attr(out,cap,&off,IKE_CP_INTERNAL_IP4_NETMASK)!=0) return -1;
    if (request_dns && append_empty_attr(out,cap,&off,IKE_CP_INTERNAL_IP4_DNS)!=0) return -1;
    if (request_dns && append_empty_attr(out,cap,&off,IKE_CP_INTERNAL_DNS_DOMAIN)!=0) return -1;   /* F: search domain after DNS */
    if (request_subnets && append_empty_attr(out,cap,&off,IKE_CP_INTERNAL_IP4_SUBNET)!=0) return -1;
    if (off > 0xffffu) return -1;
    put16(out+2,off); *out_len=off; return 0;
}

int ike_cp_parse_ipv4_reply(const uint8_t *p, size_t len, ike_cp_ipv4_reply_t *out) {
    if (!p || !out || len < GEN_HDR+CP_HDR) return -1;
    memset(out,0,sizeof(*out));
    uint16_t plen=be16(p+2);
    if (plen != len || p[4] != IKE_CFG_REPLY) return -1;
    /* Sender must set reserved bytes/bits to zero, receiver ignores them per RFC. Attribute type's
     * high reserved bit is masked rather than rejected for the same reason. */
    size_t off=GEN_HDR+CP_HDR;
    while (off < len) {
        if (off + ATTR_HDR > len) return -1;
        uint16_t type=(uint16_t)(be16(p+off)&0x7fffu);
        uint16_t n=be16(p+off+2); off += ATTR_HDR;
        if (off + n > len) return -1;
        const uint8_t *v=p+off;
        if (type==IKE_CP_INTERNAL_IP4_ADDRESS) {
            if (n!=4) return -1;
            if (!out->have_address) { memcpy(out->address,v,4); out->have_address=1; }
            else out->ignored_attributes++;
        } else if (type==IKE_CP_INTERNAL_IP4_NETMASK) {
            if (n!=4) return -1;
            if (!out->have_netmask) { memcpy(out->netmask,v,4); out->have_netmask=1; }
            else out->ignored_attributes++;
        } else if (type==IKE_CP_INTERNAL_IP4_DNS) {
            if (n!=4) return -1;
            if (out->dns_count<IKE_CP_MAX_DNS) memcpy(out->dns[out->dns_count++],v,4);
            else out->ignored_attributes++;
        } else if (type==IKE_CP_INTERNAL_DNS_DOMAIN) {   /* F: UTF-8 domain, first one kept */
            if (n==0 || out->dns_domain_len) out->ignored_attributes++;
            else { size_t k = n > IKE_CP_MAX_DOMAIN ? IKE_CP_MAX_DOMAIN : n; memcpy(out->dns_domain, v, k); out->dns_domain[k] = 0; out->dns_domain_len = k; }
        } else if (type==IKE_CP_INTERNAL_IP4_SUBNET) {
            if (n!=8) return -1;
            if (out->subnet_count<IKE_CP_MAX_SUBNETS) {
                memcpy(out->subnet[out->subnet_count].network,v,4);
                memcpy(out->subnet[out->subnet_count].netmask,v+4,4);
                out->subnet_count++;
            } else out->ignored_attributes++;
        } else {
            out->ignored_attributes++;
        }
        off += n;
    }
    return off==len ? 0 : -1;
}
