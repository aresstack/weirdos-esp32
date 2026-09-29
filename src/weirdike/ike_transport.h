/*
 * WeirdIKE -- ike_transport.h : UDP transport adapter (IKE over UDP 500 / NAT-T 4500).
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The core knows nothing about underlays ("modem-ecm"/"wifi-sta"/"ppp0"): the HOST hands WeirdIKE
 * a transport whose ctx is ALREADY configured to egress on the right interface. open() just opens;
 * the adapter's ctx decides where it binds. This keeps the core identical on ESP32/lwIP and NuttX.
 */
#ifndef WEIRDIKE_TRANSPORT_H
#define WEIRDIKE_TRANSPORT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* IP endpoint. IPv4 lives in ip[0..3] when is_v6 == 0 (IPv6 is a later slice). */
typedef struct {
    uint8_t  ip[16];
    int      is_v6;
    uint16_t port;
} weirdike_endpoint_t;

typedef struct {
    void *ctx;                                          /* opaque; pre-bound to the chosen egress */

    /* Open a UDP socket bound to local_port (500, and 4500 for NAT-T). Egress binding is the
     * adapter's own concern (its ctx already knows the interface). Returns 0 on success. */
    int  (*open)(void *ctx, uint16_t local_port);

    /* Resolve a hostname/literal to an endpoint (caller sets the port afterwards). */
    int  (*resolve)(void *ctx, const char *host, weirdike_endpoint_t *out);

    /* Effective LOCAL IP + UDP port actually used for egress (NAT-D needs this). MUST return the
     * concrete source of the pre-bound underlay -- NEVER 0.0.0.0. If the socket is INADDR_ANY, the
     * adapter must resolve the selected source (or, better, bind concretely to the underlay IP). */
    int  (*local_endpoint)(void *ctx, weirdike_endpoint_t *out);

    /* Send one datagram. Returns 0 on success, <0 on error. */
    int  (*send)(void *ctx, const weirdike_endpoint_t *dst, const uint8_t *data, size_t len);

    /* Receive one datagram. Non-blocking when timeout_ms == 0. Returns bytes read,
     * 0 if nothing pending, <0 on error. Fills *src with the sender. */
    int  (*recv)(void *ctx, weirdike_endpoint_t *src, uint8_t *buf, size_t buflen, int timeout_ms);

    void (*close)(void *ctx);
} weirdike_transport_t;

#ifdef __cplusplus
}
#endif

#endif /* WEIRDIKE_TRANSPORT_H */
