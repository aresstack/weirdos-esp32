/*
 * WeirdIKE -- src/core/weirdike.c : public-API + initiator state-machine scaffold.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * STATUS: skeleton. Message build/parse + key derivation for IKE_SA_INIT -> IKE_AUTH -> CHILD_SA
 * are extracted from CycloneIPSEC in later slices (see docs/ANALYSIS.md). This file already
 * implements the hardened lifecycle: caller-owned OR heap contexts, deep-copied config, secret
 * zeroization, injected memory + explicit time. It exercises the adapter vtables so the OS-agnostic
 * build is proven in CI (host now; ESP32/NuttX later).
 */
#include "weirdike.h"
#include "ike_wire.h"
#include "ike_parse.h"
#include "ike_keymat.h"
#include "ike_suite.h"
#include "ike_policy.h"
#include "ike_auth_msg.h"
#include "ike_auth_resp.h"
#include "ike_child_keymat.h"
#include "ike_natt.h"
#include "ike_sk.h"      /* AP4: SK{} seal/open for INFORMATIONAL */
#include "ike_info.h"    /* AP4: INFORMATIONAL inner payloads (empty/DPD, DELETE) */
#include "ike_rekey.h"   /* AP5: CREATE_CHILD_SA inner payloads (child rekey, PFS) */
#include "ike_cp.h"      /* AP6: Configuration Payload (INTERNAL_IP4_*) */
#include "ike_auth.h"    /* AP7: ike_maced_id / ike_psk_auth for the MSK-keyed final AUTH */
#include "ike_auth_wire.h"   /* AP7: EAP-round inner chains, IKE_PL_EAP/CP/CERT, IKE_CERT_X509_DER */
#include "ike_eap.h"     /* AP7: EAP wire */
#include "eap_mschapv2_peer.h"   /* AP8: EAP-MSCHAPv2 peer method */
#include "weirdike_ws.h"         /* the WORKSPACE block: transcript, caches, RX/TX/crypto scratch */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>    /* snprintf: secrets-free wire summaries for the diagnostic log */

/* ---- IKE-SA state object ---------------------------------------------------------------------
 * Everything that belongs to ONE IKE SA: SPIs, negotiated suite, SK_* keys, the two Message-ID
 * spaces (ours / peer's), our single outstanding request, the peer-request window (size 1) and
 * the liveness clock. Two instances (WEIRDIKE_IKE_SA_SLOTS) let an old and a new IKE SA coexist
 * during an IKE-SA rekey; today only sa[0] is active (sa_active) -- the rekey logic that fills
 * the second slot is a later feature, the FSM already addresses state through SA(c) only.
 * The request/response BYTES of a slot live in the workspace (ws->sa[slot]). */
enum { REQ_DPD = 0, REQ_DELETE_IKE = 1, REQ_CHILD_REKEY = 2, REQ_DELETE_CHILD = 3,
       REQ_IKE_REKEY = 4,          /* our CREATE_CHILD_SA carrying an IKE proposal (IKE-SA rekey) */
       REQ_DELETE_IKE_OLD = 5 };   /* DELETE of the OLD IKE SA after a rekey (lives in the old slot) */
typedef struct {
    int                 in_use;
    int                 role_initiator;       /* 1 = we are the initiator of THIS IKE SA (IKE_AUTH SA, or a
                                               * rekey we started); 0 = the peer initiated the rekey that
                                               * created it. Drives the I flag and the SK_e/SK_a direction. */
    uint8_t             spi_i[8];
    uint8_t             spi_r[8];             /* from the IKE_SA_INIT response / the rekey exchange */
    weirdike_ike_suite_t suite;               /* negotiated IKE-SA suite (SHA256 until negotiated) */
    ike_keys_t          sk;                   /* key schedule (secret) */
    int                 have_keys;
    /* after an IKE-SA rekey: this slot is the OLD SA, alive until its DELETE is exchanged */
    int                 is_old;
    int                 old_delete_ours;      /* we initiated the rekey -> WE delete the old SA (RFC 7296 2.8) */
    uint32_t            old_deadline_ms;      /* peer-initiated: local safety drop if its DELETE never comes */
    /* initial exchanges (IKE_SA_INIT / IKE_AUTH rounds): retransmit timer */
    uint32_t            deadline_ms;
    int                 retransmit_count;
    /* OUR request window: exactly one outstanding request (INFORMATIONAL / CREATE_CHILD_SA) */
    uint32_t            tx_mid;               /* next Message ID for a request we initiate */
    int                 req_active;
    int                 req_is_delete;        /* the pending request is the graceful-close DELETE */
    int                 req_kind;             /* REQ_* */
    uint32_t            req_mid;
    int                 req_retransmit;
    uint32_t            req_deadline_ms;
    /* PEER request window (size 1) + response cache marker (bytes in ws->sa[slot].resp) */
    int                 rx_have;              /* a cached response to the peer's last request exists */
    uint32_t            rx_mid;               /* its Message ID */
    uint32_t            rx_next_mid;          /* next peer-request Message ID we accept (starts at 0) */
    /* liveness (DPD clock): last valid inbound IKE message */
    uint32_t            last_rx_ms;
    int                 last_rx_armed;
} ike_sa_state_t;

/* ---- Child-SA slot: one installed Child SA + its bookkeeping. The public weirdike_child_sa_t is
 * the data-plane view (keys, SPIs, selectors); the rest is control-plane state of that SA. ---- */
typedef struct {
    weirdike_child_sa_t sa;            /* keys + SPIs + selectors (secret) */
    uint8_t             spi_i[4];      /* our inbound SPI, wire bytes (DELETE matching) */
    uint32_t            born_ms;       /* lifetime clock (current SA) */
    int                 born_armed;
    int                 delete_ours;   /* previous SA: WE delete it (we initiated the rekey, RFC 7296 2.8) */
    uint32_t            deadline_ms;   /* previous SA: local safety drop if nobody deletes it */
    int                 in_use;
} child_slot_t;

struct weirdike_ctx {
    const weirdike_crypto_t    *crypto;
    const weirdike_transport_t *transport;
    const weirdike_platform_t  *platform;

    /* deep-copied config (bounded -> fixed-size context, caller-owned placement works) */
    char            host[WEIRDIKE_MAX_HOST];
    uint16_t        server_port;
    weirdike_auth_t auth;
    uint8_t         psk[WEIRDIKE_MAX_PSK];
    size_t          psk_len;
    weirdike_id_type_t local_id_type;
    uint8_t            local_id[WEIRDIKE_MAX_ID];  size_t local_id_len;
    weirdike_id_type_t remote_id_type;
    uint8_t            remote_id[WEIRDIKE_MAX_ID]; size_t remote_id_len;
    weirdike_ts_t   local_ts;
    weirdike_ts_t   remote_ts;
    int             enable_nat_t;
    /* proposal policy (deep-copied, NORMALIZED, validated against the build at init) */
    weirdike_ike_policy_t   ike_policy;
    weirdike_child_policy_t child_policy;

    /* runtime */
    weirdike_state_t    state;
    weirdike_endpoint_t peer;
    ike_sa_state_t      sa[WEIRDIKE_IKE_SA_SLOTS];   /* IKE-SA state objects; SA(c) = the active one */
    int                 sa_active;
    int                 sa_old;                /* slot of the OLD IKE SA during a rekey transition, -1 = none */
    uint32_t            ike_gen;               /* IKE-SA generation (1 = IKE_AUTH SA, +1 per rekey) */
    uint32_t            ike_lifetime_ms;       /* 0 = no self-initiated IKE-SA rekey */
    uint32_t            ike_born_ms;           /* when the CURRENT IKE SA became active */
    /* our in-flight IKE-SA rekey (initiator side); the candidate SA is prepared in sa[ikerk_slot] */
    int                 ikerk_active;
    int                 ikerk_slot;
    uint8_t             ikerk_ni[32];          /* our nonce of the rekey exchange (secret until keyed) */
    void               *ikerk_dh_priv;
    uint16_t            ikerk_dh_group;
    /* Child-SA slots: CUR(c) = the current SA (TX+RX), PREV(c) = the previous one kept RX-only
     * during a rekey overlap. Indices, not copies: a rekey rotates slots. -1 = none. */
    child_slot_t        child_slots[WEIRDIKE_CHILD_SLOTS];
    int                 child_cur;
    int                 child_prev;
    int                 transport_open;  /* close() only if a successful open() happened (idempotent) */
    int                 heap_owned;       /* context block obtained by weirdike_new() (freed by weirdike_free) */
    struct weirdike_ws *ws;               /* WORKSPACE block (host-placed) -- layout in weirdike_ws.h */
    int                 ws_owned;         /* workspace obtained by weirdike_new() */
    const weirdike_mem_t *mem;            /* provider used by weirdike_new() (NULL = stdlib) */
    void               *dh_priv;          /* opaque DH private handle from crypto->ke_keygen (M1a) */
    weirdike_dh_id_t    dh_group;

    /* IKE_SA_INIT exchange state (M1c/M1d) */
    uint8_t             ni[32];  size_t ni_len;
    /* verbatim SA_INIT transcript (RealMessage1/RealMessage2) for IKE_AUTH signed octets */
    weirdike_endpoint_t local_ep;          /* our observed source (for NAT-D) */
    uint8_t             peer_ke[WEIRDIKE_KE_MAX]; size_t peer_ke_len;
    uint8_t             nr[256];      size_t nr_len;
    int                 nat_t_peer;         /* peer sent NAT-D notifies (NAT-T negotiated) */
    int                 nat_detected;       /* only meaningful when nat_t_peer */

    /* IKE_AUTH exchange state (M2b) */
    uint8_t             child_spi_i[4];                              /* our inbound ESP SPI (initiator) */
    int                 have_child_sa;                               /* IKE_AUTH negotiated a Child SA */
    uint8_t             child_spi_r[4];                              /* responder inbound ESP SPI */
    weirdike_ts_t       child_ts_i, child_ts_r;                      /* narrowed selectors from the responder */
    weirdike_ts_t       child_ts_r_list[WEIRDIKE_TS_MAX]; size_t n_child_ts_r;   /* E2: full narrowed TSr set */
    weirdike_ts_t       remote_ts_extra[WEIRDIKE_TS_MAX - 1]; size_t n_remote_ts_extra;   /* E2: configured extra TSr */
    int                 use_natt;                                    /* IKE migrated to UDP/4500 (non-ESP marker) */
    int                 keepalive_armed;                             /* NAT-T keepalive timer running */
    uint32_t            keepalive_deadline_ms;

    /* diagnostics (NO secrets) -- see weirdike_get_diag() */
    int                 diag_auth_done;
    int                 diag_ike_auth_ok;
    int                 diag_child_sa_ok;
    uint16_t            diag_child_notify;     /* Child SA rejected AFTER a successful IKE_AUTH (else 0) */
    int                 diag_ike_auth_rejected; /* peer rejected OUR IKE_AUTH (error notify, no AUTH payload) */
    int                 diag_auth_local_fail;   /* peer AUTH present, OUR verification failed */
    uint16_t            diag_child_encr, diag_child_bits, diag_child_integ;   /* negotiated Child suite */
    uint8_t             diag_idr_type;
    uint8_t             diag_idr[WEIRDIKE_MAX_ID];  size_t diag_idr_len;

    /* AP3: NON-SECRET diagnostics that MUST survive wipe_secrets()/FAILED. Keys are always wiped,
     * but the negotiated suite, the furthest good state and the last error notify are metadata a
     * diagnosis needs AFTER a failure. wipe_secrets() deliberately does not touch these. */
    int                 diag_have_ike_suite;   /* the IKE-SA suite was negotiated (ike_suite valid) */
    weirdike_state_t    diag_reached_state;    /* furthest successful protocol state ever reached */
    uint16_t            diag_last_notify;      /* last error-class notify received (0 = none) */
    int                 diag_peer_pfs_rejected;/* peer answered our PFS Child rekey without D-H/KE (see weirdike_diag_t) */

    /* --- AP4: INFORMATIONAL (DPD + DELETE), valid once the IKE SA is authenticated -------------- */
    uint32_t            cur_ms;                /* last weirdike_poll()/start() time (for RX handlers) */
    int                 closing;               /* graceful close requested/in progress */
    int                 disconnect_pending;    /* wait for an older local request before sending DELETE */
    int                 child_deleted;         /* peer deleted our Child SA -> data plane must stop */

    /* --- AP5: Child-SA rekey (CREATE_CHILD_SA). Shares the ONE outstanding-request window with
     * INFORMATIONAL (SA(c)->req_*); req_kind says what the pending request is. ----------------- */
    uint32_t            child_lifetime_ms;     /* soft lifetime -> we initiate a rekey */
    uint16_t            pfs_group;             /* 0 = no PFS, else D-H group for Child rekeys */
    uint32_t            child_gen;             /* 1 = first Child SA; +1 per installed rekey */
    int                 dpd_disable;           /* D: no self-initiated DPD probes */
    uint32_t            dpd_idle_ms, dpd_retries, keepalive_ms;
    uint64_t            child_lifetime_bytes;  /* C2: soft byte lifetime (0 = none) */
    uint64_t            child_bytes;           /* host-reported ESP traffic of the current Child SA */
    uint16_t            diag_child_rekey_dh;   /* D-H group of the last Child rekey response (0 = none) */
    int                 diag_child_rekey_ke;   /* KE payload present in that response */
    /* our in-flight rekey (initiator side) */
    uint8_t             rk_spi_i[4];           /* proposed new inbound SPI */
    uint8_t             rk_ni[32];             /* our nonce of the CREATE_CHILD_SA */
    void               *rk_dh_priv;            /* PFS private handle */
    uint16_t            rk_dh_group;
    int                 sa_init_ke_retries;    /* AP5.6: INVALID_KE_PAYLOAD retries done (max 1) */
    int                 sa_init_cookie_retries;   /* I2: COOKIE challenges answered (max 1) */

    /* --- AP7/AP8: EAP-MSCHAPv2 (multi-round IKE_AUTH, server authenticated by certificate) ---- */
    uint8_t             eap_identity[WEIRDIKE_MAX_EAP_ID]; size_t eap_identity_len;
    uint8_t             eap_password[WEIRDIKE_MAX_EAP_PASS]; size_t eap_password_len;   /* secret */
    int                 request_cp;
    int                 trust_mode;            /* weirdike_trust_mode_t for the server certificate */
    eap_mschapv2_peer_t eap;                   /* method state (holds password + MSK -> wiped) */
    int                 eap_active;            /* IKE_AUTH runs the EAP flow */
    int                 eap_server_verified;   /* responder cert chained to CA + signature ok */
    uint8_t             msk[64]; int have_msk; /* EAP MSK -> final AUTH key (secret) */
    uint32_t            auth_mid;              /* Message ID of the current IKE_AUTH round */
    uint8_t             auth_id_type; uint8_t auth_id[WEIRDIKE_MAX_ID]; size_t auth_id_len;   /* IDi used */
    /* responder identity from EAP round 1 (the final IKE_AUTH response carries AUTH without IDr):
     * prf(SK_pr, IDr') for the responder signed octets + the IDr itself for policy/diag */
    uint8_t             eap_maced_idr[IKE_AUTH_MAC_MAX]; size_t eap_maced_idr_len;
    uint8_t             eap_idr_type; uint8_t eap_idr[WEIRDIKE_MAX_ID]; size_t eap_idr_len;
    weirdike_cp_t       cp; int have_cp;       /* AP6: assigned INTERNAL_IP4_* */
};

/* The ACTIVE IKE-SA state object. All FSM code goes through this accessor (never sa[0] directly),
 * so switching the active slot during a future IKE-SA rekey touches no protocol code. */
#define SA(c) (&(c)->sa[(c)->sa_active])
/* Child-SA slots (only dereference when HAVE_*). */
#define HAVE_CHILD(c) ((c)->child_cur  >= 0)
#define HAVE_PREV(c)  ((c)->child_prev >= 0)
#define CUR(c)        (&(c)->child_slots[(c)->child_cur])
#define PREV(c)       (&(c)->child_slots[(c)->child_prev])
/* Workspace region of the ACTIVE IKE SA: its one outstanding request (verbatim, retransmit) and
 * the cached response to the peer's last request (replayed on a retransmit of N, replaced when
 * request N+1 is answered -- window size 1). */
#define SAWS(c)       (&(c)->ws->sa[(c)->sa_active])

/* SK{} envelope helpers (defined with the INFORMATIONAL code below; used by IKE_AUTH EAP rounds too). */
static int sk_send(weirdike_ctx *c, uint8_t exch, int is_response, uint32_t mid,
                   uint8_t first_payload, const uint8_t *inner, size_t inner_len,
                   uint8_t *store, size_t *store_len);
static void activate_new_ike_sa(weirdike_ctx *c, int n, int we_initiated);
static void old_slot_release(weirdike_ctx *c, const char *why);
static int  peer_ike_rekey(weirdike_ctx *c, const ike_create_child_msg_t *m, uint8_t *out, size_t cap,
                           uint8_t *rfp, int *new_slot);
/* The OLD IKE SA is kept at most this long after a PEER-initiated rekey if its DELETE never comes. */
#define WEIRDIKE_IKE_OLD_SA_MAX_MS 60000u
#define WEIRDIKE_CHILD_LIFETIME_DEFAULT_MS (3300u * 1000u)   /* 55 min (peers usually rekey at 60) */

/* IKE retransmission: exponential backoff 1,2,4,8,16,32 s, then FAILED. RFC 7296 has no fixed
 * timer; this is a simple bounded scheme for lossy internet paths. */
#define WEIRDIKE_MAX_RETRANSMITS 5
#define WEIRDIKE_RTO_BASE_MS     1000u
/* RFC 3948: NAT keepalive interval (a single 0xFF on UDP/4500) -- 20 s is the common default. */
#define WEIRDIKE_NATT_KEEPALIVE_MS 20000u
/* AP4 DPD: probe the peer only after this much INBOUND IKE silence (NAT-T 0xFF keepalives are
 * one-way and do NOT prove peer liveness). Any decrypted INFORMATIONAL resets the clock. */
#define WEIRDIKE_DPD_IDLE_MS 30000u
/* Prefix that feeds the SK{} ICV: IKE header (28) + SK generic payload header (4). */
#define WEIRDIKE_SK_PREFIX (IKE_HDR_LEN + 4)

/* ---- memory provider + alignment ----
 * The alignment both blocks need = the strictest member alignment of the structs (pointers,
 * size_t, uint32_t): derived portably in C99 from a probe struct, no _Alignof needed. */
struct weirdike_align_probe { char c; union { void *p; uint64_t u; double d; size_t s; } u; };
#define WEIRDIKE_MEM_ALIGN offsetof(struct weirdike_align_probe, u)

static void *w_alloc(const weirdike_mem_t *m, size_t n, size_t align, weirdike_mem_kind_t kind) {
    if (m) return m->alloc ? m->alloc(m->ctx, n, align, kind) : NULL;
    void *p = malloc(n);   /* stdlib: max_align_t >= every alignment we require */
    if (p && ((uintptr_t)p % align) != 0) { free(p); return NULL; }
    return p;
}
static void w_free(const weirdike_mem_t *m, void *ptr, weirdike_mem_kind_t kind) {
    if (!ptr) return;
    if (m) { if (m->free) m->free(m->ctx, ptr, kind); return; }
    free(ptr);
}
/* Provider hooks must be paired: both set (custom) or the provider NULL (stdlib). */
static int mem_ok(const weirdike_mem_t *m) {
    if (!m) return 1;
    return m->alloc != NULL && m->free != NULL;
}
static void w_zero(const weirdike_platform_t *p, void *ptr, size_t n) {
    if (p && p->secure_zero) { p->secure_zero(p->ctx, ptr, n); return; }
    volatile uint8_t *v = (volatile uint8_t *)ptr;
    while (n--) *v++ = 0;
}
static void w_log(struct weirdike_ctx *c, int level, const char *msg) {
    if (c->platform && c->platform->log) c->platform->log(c->platform->ctx, level, msg);
}
/* Bounded copy that REFUSES to truncate: returns 0 on success, -1 if src doesn't fit (never
 * silently uses a different value -- important for crypto config like host/IDs). NULL src -> "". */
static int str_copy_checked(char *dst, size_t dstsz, const char *src) {
    if (dstsz == 0) return -1;
    if (!src) { dst[0] = 0; return 0; }
    size_t i = 0;
    for (; src[i]; i++) {
        if (i + 1 >= dstsz) return -1;   /* would truncate -> reject */
        dst[i] = src[i];
    }
    dst[i] = 0;
    return 0;
}

/* Deep-copy an IKE identity into bounded context storage. Rejects (does not truncate) oversized
 * ids. type NONE stores nothing (derived later). Returns 0 on success. */
static int copy_id(weirdike_id_type_t *dtype, uint8_t *ddata, size_t dcap, size_t *dlen,
                   const weirdike_id_t *src) {
    *dtype = src->type;
    *dlen  = 0;
    switch (src->type) {                 /* type <-> length semantics (RFC 7296 3.5) */
        case WEIRDIKE_ID_NONE:        if (src->len != 0) return -1; return 0;
        case WEIRDIKE_ID_IPV4_ADDR:   if (src->len != 4) return -1; break;
        case WEIRDIKE_ID_FQDN:
        case WEIRDIKE_ID_RFC822_ADDR:
        case WEIRDIKE_ID_KEY_ID:      if (src->len == 0) return -1; break;
        default:                      return -1;   /* unknown ID type */
    }
    if (src->len > dcap || !src->data) return -1;
    memcpy(ddata, src->data, src->len);
    *dlen = src->len;
    return 0;
}

void weirdike_ts_any_ipv4(weirdike_ts_t *ts) {
    if (!ts) return;
    memset(ts, 0, sizeof(*ts));
    ts->address_family = 4;
    ts->ip_protocol    = 0;        /* any */
    ts->start_port     = 0;
    ts->end_port       = 0xFFFF;
    memset(ts->end_addr, 0xFF, 4); /* 0.0.0.0 .. 255.255.255.255 */
}

int weirdike_natd_hash(const weirdike_crypto_t *crypto,
                       const uint8_t spi_i[8], const uint8_t spi_r[8],
                       const weirdike_endpoint_t *ep, uint8_t out[20]) {
    if (!crypto || !crypto->sha1 || !spi_i || !spi_r || !ep || !out) return -1;
    uint8_t buf[8 + 8 + 16 + 2];   /* SPIi | SPIr | IP(4 or 16) | Port(2, network order) */
    size_t n = 0;
    memcpy(buf + n, spi_i, 8); n += 8;
    memcpy(buf + n, spi_r, 8); n += 8;
    size_t iplen = ep->is_v6 ? 16u : 4u;
    memcpy(buf + n, ep->ip, iplen); n += iplen;
    buf[n++] = (uint8_t)((ep->port >> 8) & 0xFF);
    buf[n++] = (uint8_t)(ep->port & 0xFF);
    return crypto->sha1(crypto->ctx, buf, n, out) == 0 ? 0 : -1;
}

/* ---- lifecycle ---- */
/* init() failure after the blocks were touched: leave NOTHING behind in either block (config
 * copies, CA PEM, partial secrets). */
static weirdike_ctx *init_fail(struct weirdike_ctx *c) {
    const weirdike_platform_t *p = c->platform;
    if (c->ws) w_zero(p, c->ws, sizeof(*c->ws));
    w_zero(p, c, sizeof(*c));
    return NULL;
}

int weirdike_mem_req(const weirdike_config_t *cfg, weirdike_mem_req_t *out) {
    (void)cfg;   /* every config needs the same fixed layout today; the API allows cfg-dependence */
    if (!out) return -1;
    out->context_bytes   = sizeof(struct weirdike_ctx); out->context_align   = WEIRDIKE_MEM_ALIGN;
    out->workspace_bytes = sizeof(struct weirdike_ws);  out->workspace_align = WEIRDIKE_MEM_ALIGN;
    return 0;
}
size_t weirdike_context_size(void)   { return sizeof(struct weirdike_ctx); }
size_t weirdike_workspace_size(void) { return sizeof(struct weirdike_ws); }

weirdike_ctx *weirdike_init(void *ctx_mem, size_t ctx_len,
                            void *ws_mem,  size_t ws_len,
                            const weirdike_config_t   *cfg,
                            const weirdike_crypto_t    *crypto,
                            const weirdike_transport_t *transport,
                            const weirdike_platform_t  *platform) {
    /* Both blocks: size AND alignment (caller-owned static arrays are not aligned by default). */
    if (!ctx_mem || ctx_len < sizeof(struct weirdike_ctx) || ((uintptr_t)ctx_mem % WEIRDIKE_MEM_ALIGN) != 0) return NULL;
    if (!ws_mem  || ws_len  < sizeof(struct weirdike_ws)  || ((uintptr_t)ws_mem  % WEIRDIKE_MEM_ALIGN) != 0) return NULL;
    if (!cfg || !crypto || !transport) return NULL;
    if (cfg->psk_len > sizeof(((struct weirdike_ctx *)0)->psk))  /* reject oversized PSK, no trunc */
        return NULL;

    struct weirdike_ctx *c = (struct weirdike_ctx *)ctx_mem;
    memset(c, 0, sizeof(*c));
    c->ws = (struct weirdike_ws *)ws_mem;
    memset(c->ws, 0, sizeof(*c->ws));

    /* Reject (do NOT truncate) oversized host/IDs before touching anything else. */
    if (str_copy_checked(c->host, sizeof(c->host), cfg->server_host) != 0) return NULL;
    if (c->host[0] == 0) return NULL;   /* server_host is required (no alternative endpoint config yet) */
    if (copy_id(&c->local_id_type,  c->local_id,  sizeof(c->local_id),  &c->local_id_len,  &cfg->local_id)  != 0) return NULL;
    if (copy_id(&c->remote_id_type, c->remote_id, sizeof(c->remote_id), &c->remote_id_len, &cfg->remote_id) != 0) return NULL;

    c->crypto       = crypto;
    c->transport    = transport;
    c->platform     = platform;
    c->server_port  = cfg->server_port ? cfg->server_port : 500;
    c->auth         = cfg->auth;
    c->enable_nat_t = cfg->enable_nat_t;
    c->local_ts     = cfg->local_ts;    /* TSi / TSr, structured, copied by value */
    c->remote_ts    = cfg->remote_ts;
    c->n_remote_ts_extra = cfg->n_remote_ts_extra > WEIRDIKE_TS_MAX - 1 ? WEIRDIKE_TS_MAX - 1 : cfg->n_remote_ts_extra;   /* E2 */
    for (size_t i = 0; i < c->n_remote_ts_extra; i++) c->remote_ts_extra[i] = cfg->remote_ts_extra[i];

    if (cfg->psk && cfg->psk_len) {
        c->psk_len = cfg->psk_len;      /* validated <= sizeof above */
        memcpy(c->psk, cfg->psk, c->psk_len);
    }

    /* Proposal policy: NULL = built-in default; otherwise deep-copy, normalize (deterministic
     * order, no duplicates) and reject anything this build cannot run -- same rule as host/IDs:
     * never silently use a different value than configured. */
    if (cfg->ike_policy) c->ike_policy = *cfg->ike_policy; else weirdike_ike_policy_default(&c->ike_policy);
    if (cfg->child_policy) c->child_policy = *cfg->child_policy; else weirdike_child_policy_default(&c->child_policy);
    if (ike_policy_normalize_ike(&c->ike_policy) != 0 || ike_policy_normalize_child(&c->child_policy) != 0) return NULL;
    if (weirdike_policy_check(&c->ike_policy, &c->child_policy) != 0) return NULL;

    /* AP7/AP8: EAP-MSCHAPv2 needs identity + password + a CA to authenticate the SERVER (RFC 7296
     * 2.16). Refuse an EAP configuration without them -- never "EAP without server check". */
    if (cfg->auth == WEIRDIKE_AUTH_EAP_MSCHAPV2) {
        if (!cfg->eap_identity || !cfg->eap_identity_len || cfg->eap_identity_len > WEIRDIKE_MAX_EAP_ID ||
            !cfg->eap_password || !cfg->eap_password_len || cfg->eap_password_len > WEIRDIKE_MAX_EAP_PASS ||
            cfg->ca_pem_len > WEIRDIKE_MAX_CA_PEM - 1 || cfg->extra_pem_len > WEIRDIKE_MAX_EXTRA_PEM - 1 ||
            cfg->trust_mode < 0 || cfg->trust_mode > (int)WEIRDIKE_TRUST_NONE) return init_fail(c);
        /* Trust model: explicit anchors are MANDATORY in ANCHOR_PEM (today's contract: no EAP without
         * server authentication). The host-store modes are checked against the adapter in start();
         * NONE is an explicit, documented choice -- never an implicit fallback. */
        if (cfg->trust_mode == (int)WEIRDIKE_TRUST_ANCHOR_PEM && (!cfg->ca_pem || !cfg->ca_pem_len)) return init_fail(c);
        c->trust_mode = cfg->trust_mode;
        memcpy(c->eap_identity, cfg->eap_identity, cfg->eap_identity_len); c->eap_identity_len = cfg->eap_identity_len;
        memcpy(c->eap_password, cfg->eap_password, cfg->eap_password_len); c->eap_password_len = cfg->eap_password_len;
        if (cfg->ca_pem && cfg->ca_pem_len) { memcpy(c->ws->ca_pem, cfg->ca_pem, cfg->ca_pem_len); c->ws->ca_pem[cfg->ca_pem_len] = 0; c->ws->ca_pem_len = cfg->ca_pem_len; }
        if (cfg->extra_pem && cfg->extra_pem_len) { memcpy(c->ws->extra_pem, cfg->extra_pem, cfg->extra_pem_len); c->ws->extra_pem[cfg->extra_pem_len] = 0; c->ws->extra_pem_len = cfg->extra_pem_len; }
    } else if (cfg->auth != WEIRDIKE_AUTH_PSK) return init_fail(c);
    c->request_cp = cfg->request_cp;

    SA(c)->suite = WEIRDIKE_IKE_SUITE_SHA256;   /* until IKE_SA_INIT negotiates the real one */
    /* AP5: rekey parameters (0 = defaults). A PFS group must be one this build can run. */
    c->child_lifetime_ms = cfg->child_lifetime_s ? cfg->child_lifetime_s * 1000u : WEIRDIKE_CHILD_LIFETIME_DEFAULT_MS;
    c->pfs_group = cfg->pfs_group;
    if (c->pfs_group && !weirdike_ike_dh_supported(c->pfs_group)) return init_fail(c);
    c->child_cur = -1; c->child_prev = -1;   /* no Child SA installed (memset gave 0 = slot 0!) */
    c->sa_active = 0; c->sa_old = -1;
    c->sa[0].in_use = 1; c->sa[0].role_initiator = 1;   /* the IKE_AUTH SA: we are its initiator */
    c->ike_lifetime_ms = cfg->ike_lifetime_s * 1000u;
    c->dpd_disable  = cfg->dpd_disable ? 1 : 0;
    c->dpd_idle_ms  = cfg->dpd_interval_s ? cfg->dpd_interval_s * 1000u : WEIRDIKE_DPD_IDLE_MS;
    c->dpd_retries  = cfg->dpd_retries ? cfg->dpd_retries : WEIRDIKE_MAX_RETRANSMITS;
    c->keepalive_ms = cfg->natt_keepalive_s ? cfg->natt_keepalive_s * 1000u : WEIRDIKE_NATT_KEEPALIVE_MS;
    c->child_lifetime_bytes = (uint64_t)cfg->child_lifetime_kb * 1024u;
    c->state = WEIRDIKE_STATE_IDLE;
    return c;
}

weirdike_ctx *weirdike_new(const weirdike_config_t   *cfg,
                           const weirdike_crypto_t    *crypto,
                           const weirdike_transport_t *transport,
                           const weirdike_platform_t  *platform,
                           const weirdike_mem_t       *mem) {
    if (!mem_ok(mem)) return NULL;   /* check BEFORE allocating (alloc/free paired) */
    weirdike_mem_req_t rq;
    if (weirdike_mem_req(cfg, &rq) != 0) return NULL;
    void *cm = w_alloc(mem, rq.context_bytes, rq.context_align, WEIRDIKE_MEM_CONTEXT);
    if (!cm) return NULL;
    void *wm = w_alloc(mem, rq.workspace_bytes, rq.workspace_align, WEIRDIKE_MEM_WORKSPACE);
    if (!wm) { w_free(mem, cm, WEIRDIKE_MEM_CONTEXT); return NULL; }
    weirdike_ctx *c = weirdike_init(cm, rq.context_bytes, wm, rq.workspace_bytes, cfg, crypto, transport, platform);
    if (!c) { w_free(mem, wm, WEIRDIKE_MEM_WORKSPACE); w_free(mem, cm, WEIRDIKE_MEM_CONTEXT); return NULL; }
    c->heap_owned = 1; c->ws_owned = 1; c->mem = mem;
    return c;
}

/* ---- Child-SA slot management ---- */
static int child_slot_alloc(struct weirdike_ctx *c) {
    for (int i = 0; i < WEIRDIKE_CHILD_SLOTS; i++) {
        if (!c->child_slots[i].in_use) {
            memset(&c->child_slots[i], 0, sizeof(c->child_slots[i]));
            c->child_slots[i].in_use = 1;
            return i;
        }
    }
    return -1;
}
static void child_slot_release(struct weirdike_ctx *c, int idx) {
    if (idx < 0 || idx >= WEIRDIKE_CHILD_SLOTS) return;
    w_zero(c->platform, &c->child_slots[idx], sizeof(c->child_slots[idx]));   /* keys + bookkeeping */
}
/* Drop the PREVIOUS (overlap) Child SA: wipe its keys, free the slot. */
static void drop_child_prev(weirdike_ctx *c) {
    if (!HAVE_PREV(c)) return;
    child_slot_release(c, c->child_prev);
    c->child_prev = -1;
}
/* Wipe only the CURRENT Child-SA secret material. Keep the diagnostic negotiated-suite metadata. */
static void wipe_child_sa(struct weirdike_ctx *c) {
    if (!c) return;
    if (HAVE_CHILD(c)) { child_slot_release(c, c->child_cur); c->child_cur = -1; }
    c->have_child_sa = 0;
    memset(c->child_spi_i, 0, sizeof(c->child_spi_i));
    memset(c->child_spi_r, 0, sizeof(c->child_spi_r));
}

/* Single place that wipes every secret held in the context: PSK, every IKE-SA slot's key
 * schedule, both Child-SA slots, nonces, rekey/EAP material. ALL secret state, not just child_sa. */
static void wipe_secrets(struct weirdike_ctx *c) {
    const weirdike_platform_t *p = c->platform;
    w_zero(p, c->psk, sizeof(c->psk));
    wipe_child_sa(c);
    drop_child_prev(c);                                     /* AP5 overlap SA */
    w_zero(p, c->ni, sizeof(c->ni));   /* Ni feeds key derivation */
    for (int i = 0; i < WEIRDIKE_IKE_SA_SLOTS; i++) {       /* all seven SK_* of every IKE-SA slot */
        w_zero(p, &c->sa[i].sk, sizeof(c->sa[i].sk));
        c->sa[i].have_keys = 0;
    }
    w_zero(p, c->rk_ni, sizeof(c->rk_ni));
    w_zero(p, c->ikerk_ni, sizeof(c->ikerk_ni)); c->ikerk_active = 0;   /* IKE-SA rekey in flight */
    c->sa_old = -1;                                                       /* every slot's keys are wiped above */
    /* AP7/AP8: EAP password, method state (peer challenge, NT-Response, MSK) and the MSK copy. */
    w_zero(p, c->eap_password, sizeof(c->eap_password)); c->eap_password_len = 0;
    eap_mschapv2_peer_deinit(&c->eap);
    w_zero(p, c->msk, sizeof(c->msk)); c->have_msk = 0;
    c->psk_len = 0;
    c->ni_len = 0;
}

/* Release runtime resources acquired during/after start(): the DH private handle and the socket.
 * Used both by the start() error-unwind and by deinit(). Idempotent. */
static void release_runtime(struct weirdike_ctx *c) {
    if (c->dh_priv && c->crypto && c->crypto->ke_free) {
        c->crypto->ke_free(c->crypto->ctx, c->dh_group, c->dh_priv);
    }
    c->dh_priv = NULL;
    if (c->rk_dh_priv && c->crypto && c->crypto->ke_free) {   /* AP5: PFS handle of an aborted rekey */
        c->crypto->ke_free(c->crypto->ctx, c->rk_dh_group, c->rk_dh_priv);
    }
    c->rk_dh_priv = NULL;
    if (c->ikerk_dh_priv && c->crypto && c->crypto->ke_free) {   /* D-H handle of an aborted IKE-SA rekey */
        c->crypto->ke_free(c->crypto->ctx, c->ikerk_dh_group, c->ikerk_dh_priv);
    }
    c->ikerk_dh_priv = NULL;
    if (c->transport_open && c->transport && c->transport->close) {
        c->transport->close(c->transport->ctx);
        c->transport_open = 0;
    }
}

/* Send an IKE message to the peer, prepending the NAT-T non-ESP marker when on UDP/4500. The stored
 * IKE bytes stay marker-free (IKE Length/ICV/AUTH transcripts must never include the marker). */
static int ike_send(struct weirdike_ctx *c, const uint8_t *ike, size_t len) {
    const weirdike_transport_t *t = c->transport;
    if (c->use_natt) {
        /* [non-ESP marker][IKE message] assembled in ws->tx_msg. sk_send() already builds its
         * message at tx_msg + marker (zero-copy here); a retransmitted STORED request is moved in
         * (the stored copy itself stays marker-free: Length/ICV/AUTH transcripts exclude it). */
        uint8_t *buf = c->ws->tx_msg;
        if (len > WEIRDIKE_MAX_IKE_MSG) return -1;
        if (ike != buf + NATT_NON_ESP_MARKER_LEN) memmove(buf + NATT_NON_ESP_MARKER_LEN, ike, len);
        memset(buf, 0, NATT_NON_ESP_MARKER_LEN);   /* RFC 3948 2.2: four zero octets */
        return t->send(t->ctx, &c->peer, buf, len + NATT_NON_ESP_MARKER_LEN);
    }
    return t->send(t->ctx, &c->peer, ike, len);
}

/* Common failure path: release DH handle + socket, wipe any partial secrets, go FAILED + log. */
static void fail(struct weirdike_ctx *c, const char *msg) {
    release_runtime(c);
    wipe_secrets(c);
    c->state = WEIRDIKE_STATE_FAILED;
    if (msg) w_log(c, WEIRDIKE_LOG_ERROR, msg);
}

void weirdike_deinit(weirdike_ctx *c) {
    if (!c) return;
    release_runtime(c);   /* idempotent: frees DH state + closes a transport we actually opened */
    wipe_secrets(c);
    if (c->ws) w_zero(c->platform, c->ws, sizeof(*c->ws));   /* transcript, caches, scratch: all gone */
    c->state = WEIRDIKE_STATE_CLOSED;
}

void weirdike_free(weirdike_ctx *c) {
    if (!c) return;
    const weirdike_mem_t *m = c->mem;
    int heap = c->heap_owned, wso = c->ws_owned;
    void *ws = c->ws;
    weirdike_deinit(c);
    if (wso) { c->ws_owned = 0; c->ws = NULL; w_free(m, ws, WEIRDIKE_MEM_WORKSPACE); }
    if (heap) { c->heap_owned = 0; w_free(m, c, WEIRDIKE_MEM_CONTEXT); }   /* c is the start of the block */
}

/* ---- run ---- */
int weirdike_start(weirdike_ctx *c, uint32_t now_ms) {
    if (!c) return -1;
    if (c->state != WEIRDIKE_STATE_IDLE) return -1;   /* start() only from IDLE; re-init after FAILED/CLOSED */
    const weirdike_transport_t *t  = c->transport;
    const weirdike_crypto_t    *cr = c->crypto;

    /* We need our effective local endpoint for NAT-D AND for deriving IDi from the source IP when
     * local_id is NONE -- so local_endpoint() is required in either case. */
    int need_local = c->enable_nat_t || (c->local_id_type == WEIRDIKE_ID_NONE);

    /* Mandatory adapters. recv is OPTIONAL (external RX via weirdike_input_datagram()); ke_free is
     * mandatory (we hold DH private state); ke_shared/hmac_sha256 complete the exchange; sha1 for NAT-D. */
    if (!t->open || !t->resolve || !t->send || !t->close ||
        !cr->random || !cr->ke_keygen || !cr->ke_free || !cr->ke_shared || !cr->hmac_sha256 ||
        !cr->aes_cbc ||   /* IKE_AUTH SK{} seal/open needs AES-CBC (same primitive, no 2nd abstraction) */
        (need_local && !t->local_endpoint) || (c->enable_nat_t && !cr->sha1) ||
        (c->auth == WEIRDIKE_AUTH_EAP_MSCHAPV2 && (!cr->x509_verify || !cr->x509_verify_sig))) {   /* AP7 */
        c->state = WEIRDIKE_STATE_FAILED;
        w_log(c, WEIRDIKE_LOG_ERROR, "weirdike: missing required adapter callback");
        return -1;
    }
    /* Host-store trust modes need a host trust store behind the adapter -- refuse honestly, never
     * fall back to the PEM anchors or to "no check". */
    if (c->auth == WEIRDIKE_AUTH_EAP_MSCHAPV2 &&
        (c->trust_mode == (int)WEIRDIKE_TRUST_HOST_STORE || c->trust_mode == (int)WEIRDIKE_TRUST_HOST_STORE_PLUS_PEM) &&
        (!cr->x509_host_store || !cr->x509_host_store(cr->ctx))) {
        c->state = WEIRDIKE_STATE_FAILED;
        w_log(c, WEIRDIKE_LOG_ERROR, "weirdike: trust mode 'host store' but the host provides no trust store (no fallback)");
        return -1;
    }

    if (t->open(t->ctx, 500) != 0) { c->state = WEIRDIKE_STATE_FAILED; return -1; }
    c->transport_open = 1;

    /* From here every failure must unwind (release_runtime: close transport + free KE state). */
    if (t->resolve(t->ctx, c->host, &c->peer) != 0) goto fail;
    c->peer.port = c->server_port;

    /* --- M1c: build + send the real IKE_SA_INIT request --- */
    if (cr->random(cr->ctx, SA(c)->spi_i, 8) != 0) goto fail;   /* our Initiator SPI */

    uint8_t *ke_pub = c->ws->crypto.ke_pub;
    size_t  ke_pub_len = sizeof(c->ws->crypto.ke_pub);
    c->dh_group = c->ike_policy.dh[0];   /* KE carries the first allowed group; INVALID_KE_PAYLOAD switches it (B1) */
    if (cr->ke_keygen(cr->ctx, c->dh_group, &c->dh_priv, ke_pub, &ke_pub_len) != 0 || ke_pub_len != weirdike_dh_pub_len(c->dh_group))
        goto fail;

    c->ni_len = 32;
    if (cr->random(cr->ctx, c->ni, c->ni_len) != 0) goto fail;

    /* Effective local endpoint (for NAT-D and/or IDi-from-source-IP). */
    if (need_local && t->local_endpoint(t->ctx, &c->local_ep) != 0) goto fail;

    uint8_t natd_src[20], natd_dst[20];
    const uint8_t *psrc = NULL, *pdst = NULL;
    if (c->enable_nat_t) {
        const uint8_t spi_r0[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };   /* SPIr = 0 in the request */
        /* SOURCE hashes OUR own address, DESTINATION hashes the peer's. */
        if (weirdike_natd_hash(cr, SA(c)->spi_i, spi_r0, &c->local_ep, natd_src) != 0) goto fail;
        if (weirdike_natd_hash(cr, SA(c)->spi_i, spi_r0, &c->peer,     natd_dst) != 0) goto fail;
        psrc = natd_src; pdst = natd_dst;
    }

    /* Build DIRECTLY into the retained RealMessage1 buffer (needed verbatim for the IKE_AUTH signed
     * octets and for retransmits). A full policy (16 transforms per type) yields an SA payload of
     * several hundred bytes, so no small stack buffer here -- WEIRDIKE_MAX_IKE_MSG is the bound. */
    int mlen = ike_build_sa_init_request(c->ws->sa_init_req, sizeof(c->ws->sa_init_req), SA(c)->spi_i, &c->ike_policy,
                                         ke_pub, weirdike_dh_pub_len(c->dh_group), c->ni, c->ni_len, psrc, pdst);
    if (mlen < 0) goto fail;
    c->ws->sa_init_req_len = (size_t)mlen;
    if (t->send(t->ctx, &c->peer, c->ws->sa_init_req, (size_t)mlen) != 0) goto fail;

    SA(c)->retransmit_count = 0;
    SA(c)->deadline_ms = now_ms + WEIRDIKE_RTO_BASE_MS;
    c->state = WEIRDIKE_STATE_SA_INIT_SENT;
    w_log(c, WEIRDIKE_LOG_INFO, "weirdike: IKE_SA_INIT sent");
    return 0;

fail:
    release_runtime(c);
    c->state = WEIRDIKE_STATE_FAILED;
    return -1;
}

const char *weirdike_notify_name(uint16_t t) {
    switch (t) {
        case 1:  return "UNSUPPORTED_CRITICAL_PAYLOAD";
        case 4:  return "INVALID_IKE_SPI";
        case 5:  return "INVALID_MAJOR_VERSION";
        case 7:  return "INVALID_SYNTAX";
        case 9:  return "INVALID_MESSAGE_ID";
        case 11: return "INVALID_SPI";
        case 14: return "NO_PROPOSAL_CHOSEN";
        case 17: return "INVALID_KE_PAYLOAD";
        case 24: return "AUTHENTICATION_FAILED";
        case 34: return "SINGLE_PAIR_REQUIRED";
        case 35: return "NO_ADDITIONAL_SAS";
        case 36: return "INTERNAL_ADDRESS_FAILURE";
        case 37: return "FAILED_CP_REQUIRED";
        case 38: return "TS_UNACCEPTABLE";
        case 39: return "INVALID_SELECTORS";
        case 43: return "TEMPORARY_FAILURE";
        case 44: return "CHILD_SA_NOT_FOUND";
        default: return NULL;
    }
}

/* ---- secrets-free wire summaries (diagnostics): what we put into IKE_AUTH #1 and what came back ---- */
static const char *id_type_name(uint8_t t) {
    switch (t) {
        case WEIRDIKE_ID_IPV4_ADDR:   return "IPV4";
        case WEIRDIKE_ID_FQDN:        return "FQDN";
        case WEIRDIKE_ID_RFC822_ADDR: return "RFC822";
        case WEIRDIKE_ID_KEY_ID:      return "KEY_ID";
        case 5:                       return "IPV6";
        case 9:                       return "DER_ASN1_DN";
        default:                      return "?";
    }
}
static void ts_str(const weirdike_ts_t *t, char *b, size_t n) {
    if (t->address_family == 4)
        snprintf(b, n, "%u.%u.%u.%u-%u.%u.%u.%u/p%u:%u-%u",
                 t->start_addr[0], t->start_addr[1], t->start_addr[2], t->start_addr[3],
                 t->end_addr[0], t->end_addr[1], t->end_addr[2], t->end_addr[3],
                 (unsigned)t->ip_protocol, (unsigned)t->start_port, (unsigned)t->end_port);
    else snprintf(b, n, "af%u", (unsigned)t->address_family);
}
static void log_auth_request_summary(struct weirdike_ctx *c, const char *auth_kind, uint8_t id_type, size_t id_len,
                                     int have_idr, uint8_t idr_type, int have_auth, int have_cp,
                                     const weirdike_ts_t *tsi, const weirdike_ts_t *tsr) {
    char si[48], sr[48], b[260];
    ts_str(tsi, si, sizeof(si)); ts_str(tsr, sr, sizeof(sr));
    snprintf(b, sizeof(b), "weirdike: IKE_AUTH #1 wire: auth=%s IDi=%s(len %u) IDr=%s AUTH=%s CP=%s SAi2=encr:%u integ:%u TSi=%s TSr=%s",
             auth_kind, id_type_name(id_type), (unsigned)id_len, have_idr ? id_type_name(idr_type) : "none",
             have_auth ? "yes" : "no", have_cp ? "yes" : "no",
             (unsigned)c->child_policy.n_encr, (unsigned)c->child_policy.n_integ, si, sr);
    w_log(c, WEIRDIKE_LOG_INFO, b);
}

/* Human name for the common IKEv2 error-notify types (RFC 7296 3.10.1) -- for diagnostics only. */
static const char *ike_notify_error_name(uint16_t t) {
    switch (t) {
        case 1:  return "weirdike: peer error UNSUPPORTED_CRITICAL_PAYLOAD";
        case 4:  return "weirdike: peer error INVALID_IKE_SPI";
        case 5:  return "weirdike: peer error INVALID_MAJOR_VERSION";
        case 7:  return "weirdike: peer error INVALID_SYNTAX";
        case 9:  return "weirdike: peer error INVALID_MESSAGE_ID";
        case 11: return "weirdike: peer error INVALID_SPI";
        case 14: return "weirdike: peer error NO_PROPOSAL_CHOSEN";
        case 17: return "weirdike: peer error INVALID_KE_PAYLOAD";
        case 24: return "weirdike: peer error AUTHENTICATION_FAILED";
        case 38: return "weirdike: peer error TS_UNACCEPTABLE";
        default: return "weirdike: responder sent an error notify";
    }
}

static int policy_dh_listed(const weirdike_ike_policy_t *p, uint16_t g) {
    for (size_t i = 0; i < p->n_dh; i++) if (p->dh[i] == g) return 1;
    return 0;
}

/* AP5.6: rebuild + resend IKE_SA_INIT with a FRESH KE for `group` (same SPIi/Ni; the old D-H value
 * is discarded). The retained RealMessage1 is replaced, so the AUTH transcript stays consistent.
 * Requires a KE encoder for `group` -- today only MODP2048 (ike_build_sa_init_request refuses the
 * rest), so a demanded other group yields -1 here and the caller FAILs honestly. */
static int sa_init_resend_with_group(weirdike_ctx *c, uint16_t group) {
    const weirdike_crypto_t *cr = c->crypto;
    if (c->dh_priv && cr->ke_free) cr->ke_free(cr->ctx, c->dh_group, c->dh_priv);
    c->dh_priv = NULL;
    uint8_t *ke_pub = c->ws->crypto.ke_pub; size_t kl = sizeof(c->ws->crypto.ke_pub);
    if (cr->ke_keygen(cr->ctx, group, &c->dh_priv, ke_pub, &kl) != 0 || kl != weirdike_dh_pub_len(group)) { c->dh_priv = NULL; return -1; }
    c->dh_group = group;
    /* A policy copy whose first (KE) group is the demanded one; the offer itself is unchanged. */
    weirdike_ike_policy_t p = c->ike_policy; uint16_t first = p.dh[0];
    for (size_t i = 0; i < p.n_dh; i++) if (p.dh[i] == group) { p.dh[i] = first; p.dh[0] = group; break; }
    uint8_t natd_src[20], natd_dst[20]; const uint8_t *psrc = NULL, *pdst = NULL;
    if (c->enable_nat_t) {
        const uint8_t spi_r0[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
        if (weirdike_natd_hash(cr, SA(c)->spi_i, spi_r0, &c->local_ep, natd_src) != 0) return -1;
        if (weirdike_natd_hash(cr, SA(c)->spi_i, spi_r0, &c->peer,     natd_dst) != 0) return -1;
        psrc = natd_src; pdst = natd_dst;
    }
    int mlen = ike_build_sa_init_request(c->ws->sa_init_req, sizeof(c->ws->sa_init_req), SA(c)->spi_i, &p,
                                         ke_pub, weirdike_dh_pub_len(c->dh_group), c->ni, c->ni_len, psrc, pdst);
    if (mlen < 0) return -1;
    c->ws->sa_init_req_len = (size_t)mlen;
    if (c->transport->send(c->transport->ctx, &c->peer, c->ws->sa_init_req, (size_t)mlen) != 0) return -1;
    SA(c)->retransmit_count = 0;
    SA(c)->deadline_ms = c->cur_ms + WEIRDIKE_RTO_BASE_MS;
    w_log(c, WEIRDIKE_LOG_INFO, "weirdike: INVALID_KE_PAYLOAD -> IKE_SA_INIT re-sent with the demanded D-H group");
    return 0;
}

/* I2: N(COOKIE) challenge (RFC 7296 2.6): repeat IKE_SA_INIT with the cookie as the first payload.
 * Same SPIi, same D-H value and nonce (the responder keeps no state; it only wants proof of a
 * reachable source). The retained RealMessage1 becomes the cookie'd request (AUTH transcript). */
static int sa_init_resend_with_cookie(weirdike_ctx *c, const uint8_t *cookie, size_t clen) {
    const weirdike_crypto_t *cr = c->crypto;
    if (!cookie || clen == 0 || clen > 64) return -1;
    weirdike_ike_policy_t p = c->ike_policy; uint16_t first = p.dh[0];
    for (size_t i = 0; i < p.n_dh; i++) if (p.dh[i] == c->dh_group) { p.dh[i] = first; p.dh[0] = c->dh_group; break; }
    uint8_t natd_src[20], natd_dst[20]; const uint8_t *psrc = NULL, *pdst = NULL;
    if (c->enable_nat_t) {
        const uint8_t spi_r0[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
        if (weirdike_natd_hash(cr, SA(c)->spi_i, spi_r0, &c->local_ep, natd_src) != 0) return -1;
        if (weirdike_natd_hash(cr, SA(c)->spi_i, spi_r0, &c->peer,     natd_dst) != 0) return -1;
        psrc = natd_src; pdst = natd_dst;
    }
    int mlen = ike_build_sa_init_request_cookie(c->ws->sa_init_req, sizeof(c->ws->sa_init_req), SA(c)->spi_i, &p,
                                                c->ws->crypto.ke_pub, weirdike_dh_pub_len(c->dh_group), c->ni, c->ni_len,
                                                psrc, pdst, cookie, clen);
    if (mlen < 0) return -1;
    c->ws->sa_init_req_len = (size_t)mlen;
    if (c->transport->send(c->transport->ctx, &c->peer, c->ws->sa_init_req, (size_t)mlen) != 0) return -1;
    SA(c)->retransmit_count = 0;
    SA(c)->deadline_ms = c->cur_ms + WEIRDIKE_RTO_BASE_MS;
    w_log(c, WEIRDIKE_LOG_INFO, "weirdike: COOKIE challenge -> IKE_SA_INIT re-sent with N(COOKIE)");
    return 0;
}

static void handle_sa_init_response(weirdike_ctx *c, const uint8_t *data, size_t len,
                                    const weirdike_endpoint_t *from) {
    ike_sa_init_response_t r;
    int rc = ike_parse_sa_init_response(data, len, SA(c)->spi_i, &r);
    if (rc == IKE_PARSE_NOT_FOR_US) return;                 /* different SPIi -> ignore */
    if (rc == IKE_PARSE_COOKIE) {                           /* I2: cookie challenge, bounded to one round */
        if (c->sa_init_cookie_retries == 0) {
            c->sa_init_cookie_retries++;
            if (sa_init_resend_with_cookie(c, r.cookie, r.cookie_len) == 0) return;
            fail(c, "weirdike: COOKIE retry failed"); return;
        }
        fail(c, "weirdike: peer keeps demanding COOKIEs (giving up)"); return;
    }
    if (rc == IKE_PARSE_PEER_ERROR) {
        c->diag_last_notify = r.error_notify;
        /* AP5.6 INVALID_KE_PAYLOAD(group): re-send IKE_SA_INIT with a KE for the demanded group --
         * ONLY if the policy lists it, this build can run it, it differs from what we sent, and we
         * have not retried yet (one retry; a peer that keeps bouncing groups is broken). Never
         * reuse the old D-H value. Anything else -> FAILED with the notify retained (AP3). */
        if (r.error_notify == 17 && r.invalid_ke_group && c->sa_init_ke_retries == 0 &&
            r.invalid_ke_group != c->dh_group && weirdike_ike_dh_supported(r.invalid_ke_group) &&
            policy_dh_listed(&c->ike_policy, r.invalid_ke_group)) {
            c->sa_init_ke_retries++;
            if (sa_init_resend_with_group(c, r.invalid_ke_group) == 0) return;
            fail(c, "weirdike: INVALID_KE_PAYLOAD retry failed"); return;
        }
        fail(c, ike_notify_error_name(r.error_notify)); return;
    }
    if (rc != IKE_PARSE_OK)         { fail(c, "weirdike: malformed IKE_SA_INIT response"); return; }
    if (!r.proposal_ok)             { fail(c, "weirdike: malformed IKE-SA selection in IKE_SA_INIT response"); return; }
    /* Policy gate: EVERY selected transform must be in the configured allow-lists. A transform this
     * build implements but the policy did not offer is rejected too -- no silent downgrade. */
    if (!ike_policy_ike_allows(&c->ike_policy, &r.suite)) {
        fail(c, "weirdike: responder selected an IKE-SA transform outside the configured policy"); return;
    }
    if (!weirdike_ike_suite_supported(&r.suite)) {   /* cannot happen (policy <= build), defensive */
        fail(c, "weirdike: responder selected an IKE-SA transform this build cannot run"); return;
    }

    /* The negotiated IKE-SA suite drives keymat / SK{} / AUTH sizes from here on. */
    SA(c)->suite = r.suite;
    c->diag_have_ike_suite = 1;   /* AP3: non-secret; survives a later wipe_secrets()/FAILED */

    /* Retain RealMessage2 verbatim (needed for IKE_AUTH signed octets). */
    if (len > sizeof(c->ws->sa_init_resp)) { fail(c, "weirdike: SA_INIT response too large to retain"); return; }
    memcpy(c->ws->sa_init_resp, data, len);
    c->ws->sa_init_resp_len = len;

    /* Capture responder SPI, peer KE and Nr (for M2 SKEYSEED). The KE group MUST be the one we sent
     * (RFC 7296 2.7: a responder that wants another group answers INVALID_KE_PAYLOAD instead). */
    if (r.peer_ke_group != c->dh_group || r.peer_ke_len != weirdike_dh_pub_len(c->dh_group) ||
        r.peer_ke_len > sizeof(c->peer_ke)) { fail(c, "weirdike: SA_INIT response KE group/length mismatch"); return; }
    memcpy(SA(c)->spi_r, r.spi_r, 8);
    memcpy(c->peer_ke, r.peer_ke, r.peer_ke_len); c->peer_ke_len = r.peer_ke_len;
    memcpy(c->nr, r.nr, r.nr_len); c->nr_len = r.nr_len;

    /* NAT-T negotiation (peer sent NAT-D) is separate from NAT detection (hashes mismatch). The
     * parser guarantees >=1 SOURCE and exactly one DESTINATION together, or neither. */
    c->nat_t_peer   = (r.natd_src_count > 0 && r.natd_dst_present);
    c->nat_detected = 0;
    if (c->enable_nat_t && c->nat_t_peer) {
        if (!from) {   /* can't verify NAT-D without the real packet source */
            fail(c, "weirdike: NAT-T but no observed source endpoint");
            return;
        }
        uint8_t exp[20];
        /* SOURCE: NAT on the sender's leg unless SOME received source hash matches the observed src
         * (RFC 7296 permits multiple NAT_DETECTION_SOURCE_IP -- any match means "no NAT there"). */
        int src_match = 0;
        if (weirdike_natd_hash(c->crypto, SA(c)->spi_i, SA(c)->spi_r, from, exp) == 0) {
            for (size_t i = 0; i < r.natd_src_count; i++)
                if (memcmp(exp, r.natd_src[i], 20) == 0) { src_match = 1; break; }
        }
        /* DESTINATION: NAT on our leg unless the received dest hash matches our local endpoint. */
        int dst_match = 0;
        if (weirdike_natd_hash(c->crypto, SA(c)->spi_i, SA(c)->spi_r, &c->local_ep, exp) == 0)
            dst_match = (memcmp(exp, r.natd_dst, 20) == 0);
        c->nat_detected = (!src_match || !dst_match);
    }

    /* --- M2a: DH shared secret -> IKE SA key schedule (RFC 7296 2.13/2.14) --- */
    {
        uint8_t *gir = c->ws->crypto.gir;
        size_t  gir_len = sizeof(c->ws->crypto.gir);
        int rc = c->crypto->ke_shared(c->crypto->ctx, c->dh_group, c->dh_priv,
                                      c->peer_ke, c->peer_ke_len, gir, &gir_len);
        if (rc != 0 || gir_len != weirdike_dh_shared_len(c->dh_group)) {   /* g^ir length is fixed per group */
            w_zero(c->platform, gir, sizeof(c->ws->crypto.gir));
            fail(c, "weirdike: DH shared-secret failed");
            return;
        }
        /* DH private no longer needed -> free now (transport stays open). */
        if (c->crypto->ke_free) c->crypto->ke_free(c->crypto->ctx, c->dh_group, c->dh_priv);
        c->dh_priv = NULL;

        /* Sizes come from the NEGOTIATED suite: PRF output, INTEG key, ENCR key (SHA256 -> 32/32/32,
         * SHA512 -> 64/64/32). SK_d/SK_p use the PRF length; SK_a the INTEG key length. */
        ike_prf_fn prf = weirdike_prf_cb(c->crypto, SA(c)->suite.prf);
        size_t prf_len       = weirdike_prf_len(SA(c)->suite.prf);
        size_t integ_key_len = weirdike_integ_key_len(SA(c)->suite.integ);
        size_t encr_key_len  = weirdike_encr_key_len(SA(c)->suite.encr, SA(c)->suite.encr_key_bits);
        if (!prf || prf_len == 0 || integ_key_len == 0 || encr_key_len == 0) {
            w_zero(c->platform, gir, sizeof(c->ws->crypto.gir));
            fail(c, "weirdike: unsupported negotiated IKE suite");
            return;
        }
        int krc = ike_derive_keys(prf, c->crypto->ctx, prf_len, integ_key_len, encr_key_len,
                                  c->ni, c->ni_len, c->nr, c->nr_len, gir, gir_len,
                                  SA(c)->spi_i, SA(c)->spi_r, &SA(c)->sk);
        w_zero(c->platform, gir, sizeof(c->ws->crypto.gir));           /* wipe g^ir right after the KDF */
        if (krc != 0) { fail(c, "weirdike: key derivation failed"); return; }  /* fail() wipes SK_* */
        SA(c)->have_keys = 1;
    }

    /* NAT-T: if NAT was detected, migrate IKE to UDP/4500 (non-ESP marker) before IKE_AUTH. Same
     * pre-bound transport context, just a new local port; NAT-D is not recomputed. */
    if (c->enable_nat_t && c->nat_detected) {
        const weirdike_transport_t *t = c->transport;
        if (t->close) { t->close(t->ctx); c->transport_open = 0; }
        if (t->open(t->ctx, 4500) != 0) { fail(c, "weirdike: could not open UDP/4500 for NAT-T"); return; }
        c->transport_open = 1;
        c->peer.port = 4500;
        c->use_natt = 1;
        w_log(c, WEIRDIKE_LOG_INFO, "weirdike: NAT detected -> IKE migrated to UDP/4500");
    }

    c->state = WEIRDIKE_STATE_SA_INIT_DONE;   /* M1 acceptance + IKE SA keys ready */
    c->diag_reached_state = WEIRDIKE_STATE_SA_INIT_DONE;   /* AP3: furthest good state (survives FAILED) */
    w_log(c, WEIRDIKE_LOG_INFO, "weirdike: IKE_SA_INIT done, IKE SA keys derived (M2a)");
}

/* --- M2b: build + send the IKE_AUTH request (driven from poll() at SA_INIT_DONE) --- */
static void send_ike_auth(struct weirdike_ctx *c, uint32_t now_ms) {
    const weirdike_crypto_t *cr = c->crypto;   /* TX now goes through ike_send() (NAT-T aware) */

    /* Our inbound ESP SPI (SAi2). Reject the reserved 0..255 range; regenerate a few times. */
    uint8_t spi[4]; int spi_ok = 0;
    for (int tries = 0; tries < 8; tries++) {
        if (cr->random(cr->ctx, spi, 4) != 0) { fail(c, "weirdike: RNG failed (child SPI)"); return; }
        if (!(spi[0] == 0 && spi[1] == 0 && spi[2] == 0)) { spi_ok = 1; break; }
    }
    if (!spi_ok) { fail(c, "weirdike: could not generate a valid child SPI"); return; }
    memcpy(c->child_spi_i, spi, 4);

    uint8_t iv[16];
    if (cr->random(cr->ctx, iv, sizeof(iv)) != 0) { fail(c, "weirdike: RNG failed (IV)"); return; }

    /* IDi: explicit config, or derived from our IPv4 source address when type is NONE. With EAP and
     * no explicit IDi, the EAP identity is the IDi (RFC822 if it holds '@', else KEY_ID). */
    uint8_t id_type; const uint8_t *id_data; size_t id_len; uint8_t ipbuf[4];
    if (c->local_id_type == WEIRDIKE_ID_NONE && c->auth == WEIRDIKE_AUTH_EAP_MSCHAPV2) {
        int at = 0; for (size_t i = 0; i < c->eap_identity_len; i++) if (c->eap_identity[i] == '@') at = 1;
        id_type = at ? WEIRDIKE_ID_RFC822_ADDR : WEIRDIKE_ID_KEY_ID; id_data = c->eap_identity; id_len = c->eap_identity_len;
    } else if (c->local_id_type == WEIRDIKE_ID_NONE) {
        if (c->local_ep.is_v6) { fail(c, "weirdike: cannot derive IPv4 IDi from an IPv6 source"); return; }
        memcpy(ipbuf, c->local_ep.ip, 4);
        id_type = WEIRDIKE_ID_IPV4_ADDR; id_data = ipbuf; id_len = 4;
    } else {
        id_type = (uint8_t)c->local_id_type; id_data = c->local_id; id_len = c->local_id_len;
    }
    /* Retain the IDi we use: the final EAP AUTH signs MACedIDForI over exactly this. */
    c->auth_id_type = id_type; c->auth_id_len = id_len; if (id_len) memcpy(c->auth_id, id_data, id_len);
    c->auth_mid = 1;

    /* TSi/TSr default to any-IPv4 when the host left them unset. */
    weirdike_ts_t tsi = c->local_ts, tsr = c->remote_ts;
    if (tsi.address_family == 0) weirdike_ts_any_ipv4(&tsi);
    if (tsr.address_family == 0) weirdike_ts_any_ipv4(&tsr);

    /* ---- AP7: EAP first round = IKE_AUTH WITHOUT AUTH (RFC 7296 2.16): IDi | [IDr] | CERTREQ |
     * [CP] | SAi2 | TSi | TSr, sealed like any other SK{} request (Message ID 1). ---- */
    if (c->auth == WEIRDIKE_AUTH_EAP_MSCHAPV2) {
        if (eap_mschapv2_peer_init(&c->eap, cr, c->eap_identity, c->eap_identity_len,
                                   c->eap_password, c->eap_password_len) != 0) { fail(c, "weirdike: EAP method init failed"); return; }
        uint8_t cpbuf[64]; size_t cpl = 0;
        if (c->request_cp && ike_cp_build_ipv4_request(IKE_PL_SA, 1, 1, cpbuf, sizeof(cpbuf), &cpl) != 0) { fail(c, "weirdike: CP request build failed"); return; }
        ike_auth_inner_t ii; memset(&ii, 0, sizeof(ii));
        ii.id_type = id_type; ii.id_data = id_data; ii.id_len = id_len;
        ii.have_idr = (c->remote_id_type != WEIRDIKE_ID_NONE);
        ii.idr_type = (uint8_t)c->remote_id_type; ii.idr_data = c->remote_id; ii.idr_len = c->remote_id_len;
        ii.omit_auth = 1; ii.add_certreq = 1;
        ii.cp = c->request_cp ? cpbuf : NULL; ii.cp_len = c->request_cp ? cpl : 0;
        ii.child_spi_i = c->child_spi_i; ii.child_policy = &c->child_policy; ii.ts_i = &tsi; ii.ts_r = &tsr;
        ii.ts_r_extra = c->n_remote_ts_extra ? c->remote_ts_extra : NULL; ii.n_ts_r_extra = c->n_remote_ts_extra;   /* E2 */
        uint8_t *inner = c->ws->tx_inner; size_t il = 0;
        if (ike_build_auth_inner(&ii, inner, sizeof(c->ws->tx_inner), &il) != 0) { fail(c, "weirdike: failed to build EAP IKE_AUTH request"); return; }
        log_auth_request_summary(c, "EAP", id_type, id_len, ii.have_idr, ii.idr_type, 0, ii.cp != NULL, &tsi, &tsr);
        if (sk_send(c, IKE_EXCHANGE_AUTH, 0, c->auth_mid, IKE_PL_IDI, inner, il, SAWS(c)->req, &SAWS(c)->req_len) != 0) {
            fail(c, "weirdike: send IKE_AUTH (EAP) failed"); return; }
        c->eap_active = 1;
        SA(c)->retransmit_count = 0;
        SA(c)->deadline_ms = now_ms + WEIRDIKE_RTO_BASE_MS;
        c->state = WEIRDIKE_STATE_AUTH_SENT;
        w_log(c, WEIRDIKE_LOG_INFO, "weirdike: IKE_AUTH sent (EAP: no AUTH, CERTREQ, awaiting server certificate)");
        return;
    }

    /* IKE Config Mode (RFC 7296 2.19): CP(CFG_REQUEST) for INTERNAL_IP4_ADDRESS/DNS in the PSK
     * IKE_AUTH as well -- request_cp is a property of the connection, not of the auth method. */
    uint8_t psk_cpbuf[64]; size_t psk_cpl = 0;
    if (c->request_cp && ike_cp_build_ipv4_request(IKE_PL_SA, 1, 1, psk_cpbuf, sizeof(psk_cpbuf), &psk_cpl) != 0) {
        fail(c, "weirdike: CP request build failed"); return; }

    ike_auth_req_t in;
    memset(&in, 0, sizeof(in));
    in.cp = c->request_cp ? psk_cpbuf : NULL; in.cp_len = c->request_cp ? psk_cpl : 0;
    in.spi_i = SA(c)->spi_i;  in.spi_r = SA(c)->spi_r;
    in.sk_ei = SA(c)->sk.sk_ei; in.sk_ai = SA(c)->sk.sk_ai; in.sk_pi = SA(c)->sk.sk_pi; in.sk_e_len = SA(c)->sk.sk_e_len;
    /* Negotiated IKE-SA suite -> AUTH/SK{} primitives (SHA256: 32/32/16, SHA512: 64/64/32). */
    in.prf           = weirdike_prf_cb(cr, SA(c)->suite.prf);
    in.prf_len       = weirdike_prf_len(SA(c)->suite.prf);
    in.integ         = weirdike_integ_cb(cr, SA(c)->suite.integ);
    in.integ_out_len = weirdike_integ_key_len(SA(c)->suite.integ);
    in.icv_len       = weirdike_integ_icv_len(SA(c)->suite.integ);
    in.sk_a_len      = weirdike_integ_key_len(SA(c)->suite.integ);
    if (!in.prf || !in.integ) { fail(c, "weirdike: unsupported IKE suite for IKE_AUTH"); return; }
    in.psk = c->psk; in.psk_len = c->psk_len;
    in.real_msg1 = c->ws->sa_init_req; in.real_msg1_len = c->ws->sa_init_req_len;
    in.nr = c->nr; in.nr_len = c->nr_len;
    in.id_type = id_type; in.id_data = id_data; in.id_len = id_len;
    in.have_idr = (c->remote_id_type != WEIRDIKE_ID_NONE);
    in.idr_type = (uint8_t)c->remote_id_type; in.idr_data = c->remote_id; in.idr_len = c->remote_id_len;
    in.child_spi_i = c->child_spi_i;
    in.child_policy = &c->child_policy;   /* SAi2 = every allowed ESP ENCR/INTEG + NO_ESN */
    in.ts_i = &tsi; in.ts_r = &tsr;
    in.ts_r_extra = c->n_remote_ts_extra ? c->remote_ts_extra : NULL; in.n_ts_r_extra = c->n_remote_ts_extra;   /* E2 */
    in.iv = iv;
    in.scratch_inner = c->ws->tx_inner;             in.scratch_inner_cap = sizeof(c->ws->tx_inner);
    in.scratch_so    = c->ws->crypto.signed_octets; in.scratch_so_cap    = sizeof(c->ws->crypto.signed_octets);

    size_t mlen = 0;
    if (ike_build_auth_request(cr, &in, SAWS(c)->req, sizeof(SAWS(c)->req), &mlen) != 0) {
        fail(c, "weirdike: failed to build IKE_AUTH request"); return;
    }
    SAWS(c)->req_len = mlen;   /* keep verbatim: a retransmit re-sends these exact bytes, never re-seals */
    log_auth_request_summary(c, "PSK", id_type, id_len, in.have_idr, in.idr_type, 1, in.cp != NULL, &tsi, &tsr);
    if (ike_send(c, SAWS(c)->req, mlen) != 0) { fail(c, "weirdike: send IKE_AUTH failed"); return; }

    SA(c)->retransmit_count = 0;
    SA(c)->deadline_ms = now_ms + WEIRDIKE_RTO_BASE_MS;
    c->state = WEIRDIKE_STATE_AUTH_SENT;
    w_log(c, WEIRDIKE_LOG_INFO, "weirdike: IKE_AUTH sent");
}

/* Decode 4 wire bytes as a big-endian SPI into the host uint32_t. Never memcpy/ntohl a uint32_t
 * (avoids alignment/aliasing/endianness bugs on the ESP32); the ESP encoder writes it back BE. */
static uint32_t be32_bytes(const uint8_t p[4]) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

/* --- M2c: install the first CHILD_SA from the negotiated result + SK_d/Ni/Nr. No ESP dataplane
 * here -- just derive KEYMAT and fill the public weirdike_child_sa_t. Returns 0 on success. --- */
static int install_child_sa(struct weirdike_ctx *c, const ike_auth_response_t *r) {
    ike_child_keys_t ck;
    /* CHILD KEYMAT uses the NEGOTIATED IKE-SA PRF (SHA-512 for the FRITZ!Box), not a fixed SHA-256 --
     * else the derived ESP keys are wrong and the peer cannot decrypt our ESP. ESP cipher stays SHA-256. */
    ike_prf_fn prf = weirdike_prf_cb(c->crypto, SA(c)->suite.prf);
    size_t prf_len = weirdike_prf_len(SA(c)->suite.prf);
    /* AP9: Child key lengths follow the NEGOTIATED ESP suite (AES-256 = 32; HMAC-SHA2-256-128 = 32,
     * HMAC-SHA1-96 = 20). ike_child_keymat splits KEYMAT with exactly these sizes (RFC 7296 2.17). */
    size_t enc_len   = weirdike_encr_key_len((weirdike_encr_id_t)r->child_encr, r->child_encr_key_bits);
    size_t integ_len = weirdike_integ_key_len((weirdike_integ_id_t)r->child_integ);
    if (!prf || prf_len == 0 || enc_len == 0 || integ_len == 0 ||
        ike_derive_child_keys_ex(prf, c->crypto->ctx, prf_len, SA(c)->sk.sk_d, SA(c)->sk.sk_d_len,
                                 c->ni, c->ni_len, c->nr, c->nr_len, enc_len, integ_len, &ck) != 0) return -1;

    if (HAVE_CHILD(c)) wipe_child_sa(c);   /* defensive: the first Child SA never overlaps anything */
    { int idx = child_slot_alloc(c); if (idx < 0) { w_zero(c->platform, &ck, sizeof(ck)); return -1; } c->child_cur = idx; }
    memcpy(CUR(c)->spi_i, c->child_spi_i, 4);
    weirdike_child_sa_t *ch = &CUR(c)->sa;
    /* SPIi (ours) is our INBOUND SPI; SPIr (peer's) is what we put OUTBOUND. Big-endian decode. */
    ch->inbound_spi  = be32_bytes(c->child_spi_i);
    ch->outbound_spi = be32_bytes(c->child_spi_r);
    /* The NEGOTIATED Child suite (policy-gated by the caller; today necessarily AES-CBC-256 +
     * HMAC-SHA2-256-128, the only ESP suite the data plane and ike_child_keymat implement). */
    ch->encr  = (weirdike_encr_id_t)r->child_encr;
    ch->integ = (weirdike_integ_id_t)r->child_integ;
    /* initiator->responder = OUR OUTBOUND; responder->initiator = OUR INBOUND. */
    memcpy(ch->enc_key_out,   ck.enc_i2r,   enc_len);   ch->enc_key_out_len   = enc_len;
    memcpy(ch->integ_key_out, ck.integ_i2r, integ_len); ch->integ_key_out_len = integ_len;
    memcpy(ch->enc_key_in,    ck.enc_r2i,   enc_len);   ch->enc_key_in_len    = enc_len;
    memcpy(ch->integ_key_in,  ck.integ_r2i, integ_len); ch->integ_key_in_len  = integ_len;
    ch->nat_detected = c->nat_detected;
    ch->local_ts  = r->ts_i;   /* narrowed TSi = the network WE protect */
    ch->remote_ts = r->ts_r;   /* narrowed TSr = the peer network */
    ch->n_remote_ts = r->n_ts_r ? r->n_ts_r : 1;   /* E2: the full narrowed set */
    for (size_t i = 0; i < ch->n_remote_ts; i++) ch->remote_ts_list[i] = r->n_ts_r ? r->ts_r_list[i] : r->ts_r;

    w_zero(c->platform, &ck, sizeof(ck));   /* the only lasting copy lives in CUR(c)->sa */
    c->child_gen = 1; CUR(c)->born_ms = c->cur_ms; CUR(c)->born_armed = 1; c->child_bytes = 0;   /* AP5 lifetime clock */
    c->child_deleted = 0;
    return 0;
}

/* --- M2b/M2c: verify the IKE_AUTH response. ESTABLISHED = IKE SA AUTHENTICATED only. A negotiated
 * Child SA is orthogonal; only fully-derived Child keymat promotes to CHILD_ESTABLISHED. --- */
static void handle_auth_response(struct weirdike_ctx *c, const uint8_t *data, size_t len) {
    ike_auth_verify_in_t vi;
    memset(&vi, 0, sizeof(vi));
    vi.spi_i = SA(c)->spi_i; vi.spi_r = SA(c)->spi_r;
    vi.sk_er = SA(c)->sk.sk_er; vi.sk_ar = SA(c)->sk.sk_ar; vi.sk_pr = SA(c)->sk.sk_pr; vi.sk_e_len = SA(c)->sk.sk_e_len;
    /* Same negotiated-suite primitives as the request side. */
    vi.prf           = weirdike_prf_cb(c->crypto, SA(c)->suite.prf);
    vi.prf_len       = weirdike_prf_len(SA(c)->suite.prf);
    vi.integ         = weirdike_integ_cb(c->crypto, SA(c)->suite.integ);
    vi.integ_out_len = weirdike_integ_key_len(SA(c)->suite.integ);
    vi.icv_len       = weirdike_integ_icv_len(SA(c)->suite.integ);
    vi.sk_a_len      = weirdike_integ_key_len(SA(c)->suite.integ);
    if (!vi.prf || !vi.integ) return;   /* unsupported suite -> ignore (cannot verify) */
    /* PSK: the shared key. EAP: NULL in the EAP rounds (the responder authenticated by signature),
     * then the MSK for the final round (RFC 7296 2.16: AUTH = prf(prf(MSK, "Key Pad for IKEv2"), ...)). */
    if (c->eap_active) { vi.psk = c->have_msk ? c->msk : NULL; vi.psk_len = c->have_msk ? sizeof(c->msk) : 0; }
    else               { vi.psk = c->psk; vi.psk_len = c->psk_len; }
    vi.real_msg2 = c->ws->sa_init_resp; vi.real_msg2_len = c->ws->sa_init_resp_len;
    vi.ni = c->ni; vi.ni_len = c->ni_len;
    vi.msg_id = c->auth_mid;

    /* Decrypt into ws->rx_plain; every view in r points there (valid for this call only). */
    ike_auth_response_t r;
    ike_auth_scratch_t as;
    as.inner = c->ws->rx_plain;             as.inner_cap = sizeof(c->ws->rx_plain);
    as.so    = c->ws->crypto.signed_octets; as.so_cap    = sizeof(c->ws->crypto.signed_octets);
    int rc = ike_verify_auth_response(c->crypto, &vi, data, len, &as, &r);
    if (rc != 0) return;   /* not interpretable (stray packet / ICV fail) -> ignore, await retransmit */

    /* ---- AP7/AP8: EAP rounds (everything before the final MSK-keyed AUTH) ---- */
    if (c->eap_active && !c->have_msk) {
        if (r.error_notify) { c->diag_last_notify = r.error_notify; fail(c, ike_notify_error_name(r.error_notify)); return; }
        if (!c->eap_server_verified) {
            /* Round-1 response: IDr | CERT | AUTH(signature) | EAP. The server MUST prove itself with a
             * certificate chaining to our CA (and matching the configured identity) BEFORE any EAP. */
            if (!r.have_idr || !r.cert.len || r.cert_encoding != IKE_CERT_X509_DER || !r.auth_data.len ||
                (r.auth_method != 1 && r.auth_method != 14) || !r.maced_idr_len) {
                fail(c, "weirdike: EAP: responder sent no usable certificate/signature"); return; }
            char expect[WEIRDIKE_MAX_ID + 1]; const char *exp = NULL;
            /* certificate identity (SAN/CN) is part of the TRUST check -> not in NONE; the IKE-level
             * IDr policy (remote_id) below stays in every mode */
            if (c->trust_mode != (int)WEIRDIKE_TRUST_NONE &&
                (c->remote_id_type == WEIRDIKE_ID_FQDN || c->remote_id_type == WEIRDIKE_ID_RFC822_ADDR)) {
                memcpy(expect, c->remote_id, c->remote_id_len); expect[c->remote_id_len] = 0; exp = expect;
            }
            int xv = c->crypto->x509_verify(c->crypto->ctx, c->trust_mode, r.cert.ptr, r.cert.len,
                                            r.cert2.len ? r.cert2.ptr : NULL, r.cert2.len,
                                            c->ws->ca_pem_len ? c->ws->ca_pem : NULL, c->ws->ca_pem_len,
                                            c->ws->extra_pem_len ? c->ws->extra_pem : NULL, c->ws->extra_pem_len, exp);
            if (xv == -2) { fail(c, "weirdike: EAP: server certificate identity does not match the expected server identity"); return; }
            if (xv != 0) {
                fail(c, c->trust_mode == (int)WEIRDIKE_TRUST_HOST_STORE          ? "weirdike: EAP: server certificate does not chain to the host trust store (public CAs)" :
                        c->trust_mode == (int)WEIRDIKE_TRUST_HOST_STORE_PLUS_PEM ? "weirdike: EAP: server certificate chains neither to the host trust store nor to the extra anchors" :
                        c->trust_mode == (int)WEIRDIKE_TRUST_NONE                ? "weirdike: EAP: server certificate unparsable" :
                                                                                   "weirdike: EAP: server certificate does not chain to the configured trust anchor(s)");
                return;
            }
            if (c->trust_mode == (int)WEIRDIKE_TRUST_NONE)
                w_log(c, WEIRDIKE_LOG_INFO, "weirdike: EAP: trust mode NONE -- server certificate chain/identity NOT checked (signature only)");
            /* ResponderSignedOctets = RealMessage2 | Ni | prf(SK_pr, IDr')  (workspace crypto scratch) */
            uint8_t *so = c->ws->crypto.signed_octets; size_t sol = 0;
            memcpy(so, c->ws->sa_init_resp, c->ws->sa_init_resp_len); sol = c->ws->sa_init_resp_len;
            memcpy(so + sol, c->ni, c->ni_len); sol += c->ni_len;
            memcpy(so + sol, r.maced_idr, r.maced_idr_len); sol += r.maced_idr_len;
            int sv = c->crypto->x509_verify_sig(c->crypto->ctx, r.cert.ptr, r.cert.len, r.auth_method, so, sol, r.auth_data.ptr, r.auth_data.len);
            w_zero(c->platform, so, sol);
            if (sv != 0) { fail(c, "weirdike: EAP: server signature over the IKE_AUTH signed octets is invalid"); return; }
            c->eap_server_verified = 1;
            /* PROMOTE what outlives rx_plain: the IDr bytes (diag + final-round policy) and MACedIDForR. */
            c->diag_idr_type = r.idr_type; c->diag_idr_len = r.idr.len <= sizeof(c->diag_idr) ? r.idr.len : 0;
            if (c->diag_idr_len) memcpy(c->diag_idr, r.idr.ptr, c->diag_idr_len);
            /* retain IDr / prf(SK_pr, IDr') for the final round (RFC 7296 2.16: no IDr there) */
            memcpy(c->eap_maced_idr, r.maced_idr, r.maced_idr_len); c->eap_maced_idr_len = r.maced_idr_len;
            c->eap_idr_type = r.idr_type; c->eap_idr_len = r.idr.len <= sizeof(c->eap_idr) ? r.idr.len : 0;
            if (c->eap_idr_len) memcpy(c->eap_idr, r.idr.ptr, c->eap_idr_len);
            w_log(c, WEIRDIKE_LOG_INFO, "weirdike: EAP: server certificate + signature verified");
        }
        if (!r.eap.len) { fail(c, "weirdike: EAP: expected an EAP payload"); return; }
        uint8_t *resp = c->ws->crypto.eap_pkt; size_t rl = 0;   /* EAP reply under construction */
        if (eap_mschapv2_peer_process(&c->eap, r.eap.ptr, r.eap.len, resp, sizeof(c->ws->crypto.eap_pkt), &rl) != 0) {
            fail(c, "weirdike: EAP-MSCHAPv2 failed (wrong user/password or authenticator response)"); return; }
        uint8_t *inner = c->ws->tx_inner; size_t il = 0; uint8_t fp = 0;   /* our next IKE_AUTH inner chain */
        if (rl > 0) {
            if (ike_build_eap_inner(resp, rl, inner, sizeof(c->ws->tx_inner), &il) != 0) { fail(c, "weirdike: EAP response build failed"); return; }
            fp = IKE_PL_EAP;
        } else {
            if (!eap_mschapv2_peer_complete(&c->eap) || eap_mschapv2_peer_get_msk(&c->eap, c->msk) != 0) {
                fail(c, "weirdike: EAP finished without an MSK"); return; }
            c->have_msk = 1;
            /* Final AUTH: MACedIDForI = prf(SK_pi, IDi'); AUTH = prf(prf(MSK,KeyPad), RealMessage1 | Nr | MACedIDForI) */
            ike_prf_fn prf = vi.prf; size_t plen = vi.prf_len;
            uint8_t maced[IKE_AUTH_MAC_MAX], auth[IKE_AUTH_MAC_MAX];
            uint8_t *so = c->ws->crypto.signed_octets; size_t sol = 0;
            if (ike_maced_id(prf, c->crypto->ctx, plen, SA(c)->sk.sk_pi, plen, c->auth_id_type, c->auth_id, c->auth_id_len, maced) != 0) { fail(c, "weirdike: MACedID failed"); return; }
            memcpy(so, c->ws->sa_init_req, c->ws->sa_init_req_len); sol = c->ws->sa_init_req_len;
            memcpy(so + sol, c->nr, c->nr_len); sol += c->nr_len;
            memcpy(so + sol, maced, plen); sol += plen;
            int arc = ike_psk_auth(prf, c->crypto->ctx, plen, c->msk, sizeof(c->msk), so, sol, auth);
            w_zero(c->platform, so, sol); w_zero(c->platform, maced, sizeof(maced));
            if (arc != 0) { fail(c, "weirdike: final EAP AUTH failed"); return; }
            if (ike_build_auth_only_inner(IKE_AUTH_METHOD_SHARED_KEY, auth, plen, inner, sizeof(c->ws->tx_inner), &il) != 0) { fail(c, "weirdike: AUTH build failed"); return; }
            w_zero(c->platform, auth, sizeof(auth));
            fp = IKE_PL_AUTH;
            w_log(c, WEIRDIKE_LOG_INFO, "weirdike: EAP-MSCHAPv2 succeeded; sending the final MSK-keyed AUTH");
        }
        c->auth_mid++;
        if (sk_send(c, IKE_EXCHANGE_AUTH, 0, c->auth_mid, fp, inner, il, SAWS(c)->req, &SAWS(c)->req_len) != 0) { fail(c, "weirdike: send IKE_AUTH round failed"); return; }
        SA(c)->retransmit_count = 0;
        SA(c)->deadline_ms = c->cur_ms + WEIRDIKE_RTO_BASE_MS;
        return;
    }

    /* ---- AP7/AP8 final EAP round: the responder's AUTH is keyed with the MSK and comes WITHOUT an
     * IDr (that was authenticated in round 1 via certificate). Verify it here with the retained
     * prf(SK_pr, IDr'): AUTH_r = prf(prf(MSK, KeyPad), RealMessage2 | Ni | MACedIDForR). ---- */
    if (c->eap_active && c->have_msk && !r.ike_auth_ok && r.auth_method == IKE_AUTH_METHOD_SHARED_KEY &&
        r.auth_data.len == vi.prf_len && c->eap_maced_idr_len == vi.prf_len && !r.have_idr) {
        uint8_t *so = c->ws->crypto.signed_octets; size_t sol = 0;
        uint8_t exp[IKE_AUTH_MAC_MAX];
        memcpy(so, c->ws->sa_init_resp, c->ws->sa_init_resp_len); sol = c->ws->sa_init_resp_len;
        memcpy(so + sol, c->ni, c->ni_len); sol += c->ni_len;
        memcpy(so + sol, c->eap_maced_idr, c->eap_maced_idr_len); sol += c->eap_maced_idr_len;
        if (ike_psk_auth(vi.prf, c->crypto->ctx, vi.prf_len, c->msk, sizeof(c->msk), so, sol, exp) == 0) {
            uint8_t d = 0; for (size_t i = 0; i < vi.prf_len; i++) d |= (uint8_t)(exp[i] ^ r.auth_data.ptr[i]);
            if (d == 0) {
                r.ike_auth_ok = 1;
                r.idr_type = c->eap_idr_type; r.idr.ptr = c->eap_idr; r.idr.len = c->eap_idr_len;   /* retained from round 1 */
            }
        }
        w_zero(c->platform, so, sol); w_zero(c->platform, exp, sizeof(exp));
    }

    /* Diagnostics snapshot (NO secrets): AUTH + child outcome + peer identity, semantically separated:
     *   peer rejected OUR IKE_AUTH   = error notify and NO AUTH payload         -> ike_auth_rejected
     *   OUR verification failed      = AUTH payload present, AUTH_r mismatch    -> auth_local_fail
     *   Child SA rejected separately = IKE_AUTH ok, no child, error notify      -> child_notify */
    c->diag_auth_done         = 1;
    c->diag_ike_auth_ok       = r.ike_auth_ok;
    c->diag_child_sa_ok       = r.child_sa_ok;
    c->diag_ike_auth_rejected = (!r.ike_auth_ok && r.error_notify && !r.have_auth);
    c->diag_auth_local_fail   = (!r.ike_auth_ok && r.have_auth);
    c->diag_child_notify      = (r.ike_auth_ok && !r.child_sa_ok) ? r.error_notify : 0;
    if (r.error_notify) c->diag_last_notify = r.error_notify;   /* AP3: unified last error notify */
    c->diag_child_encr   = r.child_encr; c->diag_child_bits = r.child_encr_key_bits; c->diag_child_integ = r.child_integ;
    c->diag_idr_type     = r.idr_type;
    c->diag_idr_len      = (r.idr.len <= sizeof(c->diag_idr)) ? r.idr.len : 0;
    if (c->diag_idr_len) memcpy(c->diag_idr, r.idr.ptr, c->diag_idr_len);   /* promoted: outlives rx_plain */
    {
        const char *nn = r.error_notify ? weirdike_notify_name(r.error_notify) : NULL;
        char b[200];
        snprintf(b, sizeof(b), "weirdike: IKE_AUTH response payloads: IDr=%s AUTH=%s CP=%s SA=%s TSi=%s TSr=%s EAP=%s NOTIFY=%s(%u)",
                 r.have_idr ? "yes" : "no", r.have_auth ? "yes" : "no", r.cp.len ? "yes" : "no",
                 r.have_sa ? "yes" : "no", r.have_tsi ? "yes" : "no", r.have_tsr ? "yes" : "no", r.eap.len ? "yes" : "no",
                 r.error_notify ? (nn ? nn : "?") : "none", (unsigned)r.error_notify);
        w_log(c, WEIRDIKE_LOG_INFO, b);
        if (!r.ike_auth_ok) {
            if (c->diag_ike_auth_rejected)
                snprintf(b, sizeof(b), "weirdike: peer rejected IKE_AUTH: %s (%u) -- the peer did not accept OUR authentication (no AUTH payload from it)",
                         nn ? nn : "error notify", (unsigned)r.error_notify);
            else if (c->diag_auth_local_fail)
                snprintf(b, sizeof(b), "weirdike: IKE_AUTH: responder AUTH present but LOCAL verification failed (PSK mismatch on our side, or IDr'/signed-octets mismatch)%s%s",
                         r.error_notify ? "; notify " : "", r.error_notify ? (nn ? nn : "?") : "");
            else
                snprintf(b, sizeof(b), "weirdike: IKE_AUTH response carries neither a usable IDr+AUTH nor an error notify (IDr=%s AUTH=%s)",
                         r.have_idr ? "yes" : "no", r.have_auth ? "yes" : "no");
            fail(c, b); return;
        }
        if (!r.child_sa_ok)
            w_log(c, WEIRDIKE_LOG_INFO, r.error_notify ? "weirdike: IKE_AUTH authenticated; Child SA rejected by the peer (see NOTIFY above)"
                                                       : "weirdike: IKE_AUTH authenticated; no Child SA in the response");
    }
    /* AP3: the IKE SA is now AUTHENTICATED. Record it as a reached milestone here -- before the
     * child/remote-id gates that may still fail() -- so a later Child-only failure still shows the
     * furthest successful protocol state (IKE_AUTH ok). c->state is promoted below. */
    c->diag_reached_state = WEIRDIKE_STATE_ESTABLISHED;

    /* Child policy gate (after AUTH, so a forged SAr2 cannot influence anything before the peer is
     * authenticated): the selected ESP transforms must all be in the child allow-lists. An IKE SA
     * whose only Child SA we must refuse is a dead end (no CREATE_CHILD_SA yet) -> FAILED, not a
     * silently narrowed tunnel. */
    if (r.child_sa_ok && !ike_policy_child_allows(&c->child_policy, r.child_encr, r.child_encr_key_bits, r.child_integ)) {
        c->diag_child_sa_ok = 0;
        fail(c, "weirdike: responder selected a Child-SA transform outside the configured policy"); return;
    }

    /* Policy: if a specific peer identity is configured, the authenticated IDr must match it. */
    if (c->remote_id_type != WEIRDIKE_ID_NONE) {
        if (r.idr_type != (uint8_t)c->remote_id_type || r.idr.len != c->remote_id_len ||
            memcmp(r.idr.ptr, c->remote_id, c->remote_id_len) != 0) {
            fail(c, "weirdike: authenticated peer identity does not match configured remote_id");
            return;
        }
    }

    c->state = WEIRDIKE_STATE_ESTABLISHED;   /* IKE SA authenticated. NOT "tunnel ready". */
    /* The SA_INIT transcript (RealMessage1/2) fed every IKE_AUTH round's signed octets; nothing
     * after ESTABLISHED needs it (an IKE-SA rekey derives from SK_d, not from the transcript).
     * Its logical lifetime ends here -> release the workspace region. */
    w_zero(c->platform, c->ws->sa_init_req,  sizeof(c->ws->sa_init_req));  c->ws->sa_init_req_len  = 0;
    w_zero(c->platform, c->ws->sa_init_resp, sizeof(c->ws->sa_init_resp)); c->ws->sa_init_resp_len = 0;
    c->ike_gen = 1; c->ike_born_ms = c->cur_ms;   /* IKE-SA generation 1; lifetime clock for a self-initiated rekey */
    SA(c)->tx_mid = c->auth_mid + 1;         /* SA_INIT=0, IKE_AUTH=1..N (EAP rounds) -> next request id */
    SA(c)->rx_next_mid = 0;                  /* responder's independent request-ID space starts at 0 */
    if (c->eap_active) {                      /* AP8: EAP done -> wipe the method state + password now */
        eap_mschapv2_peer_deinit(&c->eap);
        w_zero(c->platform, c->eap_password, sizeof(c->eap_password)); c->eap_password_len = 0;
        w_zero(c->platform, c->msk, sizeof(c->msk)); c->have_msk = 0;
        c->eap_active = 0;
        w_log(c, WEIRDIKE_LOG_INFO, "weirdike: IKE_SA authenticated via EAP-MSCHAPv2 (server by certificate)");
    }
    /* AP6: Configuration Payload reply (assigned tunnel address / DNS / subnets). */
    if (r.cp.len) {
        ike_cp_ipv4_reply_t rep;
        if (ike_cp_parse_ipv4_reply(r.cp.ptr, r.cp.len, &rep) == 0) {
            memset(&c->cp, 0, sizeof(c->cp));
            c->cp.have_address = rep.have_address; memcpy(c->cp.address, rep.address, 4);
            c->cp.have_netmask = rep.have_netmask; memcpy(c->cp.netmask, rep.netmask, 4);
            c->cp.dns_count = rep.dns_count > 4 ? 4 : rep.dns_count;
            for (size_t i = 0; i < c->cp.dns_count; i++) memcpy(c->cp.dns[i], rep.dns[i], 4);
            c->cp.subnet_count = rep.subnet_count > 4 ? 4 : rep.subnet_count;
            for (size_t i = 0; i < c->cp.subnet_count; i++) { memcpy(c->cp.subnet[i], rep.subnet[i].network, 4); memcpy(c->cp.subnet_mask[i], rep.subnet[i].netmask, 4); }
            c->cp.dns_domain_len = rep.dns_domain_len > 64 ? 64 : rep.dns_domain_len; memcpy(c->cp.dns_domain, rep.dns_domain, c->cp.dns_domain_len); c->cp.dns_domain[c->cp.dns_domain_len] = 0;   /* F */
            c->have_cp = 1;
            w_log(c, WEIRDIKE_LOG_INFO, "weirdike: Configuration Payload reply received (INTERNAL_IP4_*)");
        }
    }
    if (r.child_sa_ok) {                      /* orthogonal: negotiation succeeded */
        c->have_child_sa = 1;
        memcpy(c->child_spi_r, r.child_spi_r, 4);
        c->child_ts_i = r.ts_i; c->child_ts_r = r.ts_r;
        c->n_child_ts_r = r.n_ts_r ? r.n_ts_r : 1;   /* E2 */
        for (size_t i = 0; i < c->n_child_ts_r; i++) c->child_ts_r_list[i] = r.n_ts_r ? r.ts_r_list[i] : r.ts_r;
        /* Promote to CHILD_ESTABLISHED only after the keymat is fully installed (atomic). */
        if (install_child_sa(c, &r) == 0) {
            c->state = WEIRDIKE_STATE_CHILD_ESTABLISHED;
            c->diag_reached_state = WEIRDIKE_STATE_CHILD_ESTABLISHED;   /* AP3 */
            w_log(c, WEIRDIKE_LOG_INFO, "weirdike: CHILD_SA established (keys derived)");
        }
    }
    if (c->state == WEIRDIKE_STATE_ESTABLISHED)
        w_log(c, WEIRDIKE_LOG_INFO, "weirdike: IKE_SA established (authenticated, no child)");
}

/* ===================== AP4: INFORMATIONAL (DPD + DELETE) under SK{} ===========================
 * WeirdIKE is always the ORIGINAL IKE-SA initiator, so it ALWAYS seals with SK_ei/SK_ai and opens
 * with SK_er/SK_ar, regardless of who initiated a given INFORMATIONAL exchange (RFC 7296 2.14: the
 * Initiator flag marks the original SA initiator, not the exchange initiator). Two independent
 * Message-ID spaces (RFC 7296 2.2): our requests use info_tx_mid; a peer request is answered with
 * its own Message ID echoed back. */

typedef struct { ike_aes_cbc_fn aes; ike_prf_fn integ; size_t integ_out, icv; } info_crypto_t;

static int info_crypto_slot(weirdike_ctx *c, int s, info_crypto_t *ic) {
    const ike_sa_state_t *sa = &c->sa[s];
    if (!c->crypto || !c->crypto->aes_cbc || !c->crypto->random) return -1;
    ic->aes       = c->crypto->aes_cbc;
    ic->integ     = weirdike_integ_cb(c->crypto, sa->suite.integ);
    ic->integ_out = weirdike_integ_key_len(sa->suite.integ);
    ic->icv       = weirdike_integ_icv_len(sa->suite.integ);
    /* AES-256 SK_e is 32 B (matches ike_sk_seal's sk_e[32]); INTEG must be a keyed HMAC. */
    if (!ic->integ || ic->integ_out == 0 || ic->icv == 0) return -1;
    if (weirdike_encr_key_len(sa->suite.encr, sa->suite.encr_key_bits) != 32) return -1;
    return 0;
}

/* Build + seal + send one INFORMATIONAL message. is_response!=0 sets the Response flag and echoes
 * `mid`; otherwise `mid` is our request id. Optionally stores the verbatim datagram (retransmit /
 * dedup cache). Returns 0 on success. */
/* Slot-aware: seals with the keys and the ROLE of IKE SA `s` (the original IKE_AUTH SA and a rekey
 * we initiated: I flag set, SK_ei/SK_ai; an SA the PEER created by rekeying: I flag clear,
 * SK_er/SK_ar -- RFC 7296 2.14: the Initiator flag marks the initiator of THAT IKE SA). */
static int sk_send_slot(weirdike_ctx *c, int s, uint8_t exch, int is_response, uint32_t mid,
                        uint8_t first_payload, const uint8_t *inner, size_t inner_len,
                        uint8_t *store, size_t *store_len) {
    const ike_sa_state_t *sa = &c->sa[s];
    info_crypto_t ic; if (info_crypto_slot(c, s, &ic) != 0) return -1;
    size_t cipher_len = 0, msg_len = 0;
    if (ike_sk_calc_size(WEIRDIKE_SK_PREFIX, inner_len, ic.icv, &cipher_len, &msg_len) != 0) return -1;
    if (msg_len > WEIRDIKE_MAX_IKE_MSG) return -1;
    uint8_t *msg = c->ws->tx_msg + NATT_NON_ESP_MARKER_LEN;   /* marker room in front (see ike_send) */
    size_t n = 0;
    memcpy(msg + n, sa->spi_i, 8); n += 8;
    memcpy(msg + n, sa->spi_r, 8); n += 8;
    msg[n++] = IKE_PL_SK;
    msg[n++] = IKE_VERSION;
    msg[n++] = exch;
    msg[n++] = (uint8_t)((sa->role_initiator ? IKE_FLAG_INITIATOR : 0) | (is_response ? IKE_FLAG_RESPONSE : 0));
    msg[n++] = (uint8_t)(mid >> 24); msg[n++] = (uint8_t)(mid >> 16);
    msg[n++] = (uint8_t)(mid >> 8);  msg[n++] = (uint8_t)mid;
    msg[n++] = (uint8_t)(msg_len >> 24); msg[n++] = (uint8_t)(msg_len >> 16);
    msg[n++] = (uint8_t)(msg_len >> 8);  msg[n++] = (uint8_t)msg_len;
    /* SK generic payload header: NextPayload = first inner payload type (or NONE), len over SK pl. */
    size_t sk_pl_len = msg_len - IKE_HDR_LEN;
    msg[n++] = first_payload;
    msg[n++] = 0;
    msg[n++] = (uint8_t)(sk_pl_len >> 8); msg[n++] = (uint8_t)sk_pl_len;
    /* n == WEIRDIKE_SK_PREFIX now. */
    uint8_t iv[IKE_SK_IV_LEN];
    if (c->crypto->random(c->crypto->ctx, iv, IKE_SK_IV_LEN) != 0) return -1;
    size_t out_len = 0;
    const uint8_t *sk_e = sa->role_initiator ? sa->sk.sk_ei : sa->sk.sk_er;
    const uint8_t *sk_a = sa->role_initiator ? sa->sk.sk_ai : sa->sk.sk_ar;
    if (ike_sk_seal(ic.aes, c->crypto->ctx, ic.integ, c->crypto->ctx, ic.integ_out, ic.icv,
                    sk_e, sa->sk.sk_e_len, sk_a, sa->sk.sk_a_len, iv,
                    msg, WEIRDIKE_SK_PREFIX, WEIRDIKE_MAX_IKE_MSG, inner, inner_len, &out_len) != 0) return -1;
    if (ike_send(c, msg, out_len) != 0) return -1;
    if (store && store_len) { memcpy(store, msg, out_len); *store_len = out_len; }
    return 0;
}
static int sk_send(weirdike_ctx *c, uint8_t exch, int is_response, uint32_t mid,
                   uint8_t first_payload, const uint8_t *inner, size_t inner_len,
                   uint8_t *store, size_t *store_len) {
    return sk_send_slot(c, c->sa_active, exch, is_response, mid, first_payload, inner, inner_len, store, store_len);
}
static int info_send(weirdike_ctx *c, int is_response, uint32_t mid,
                     uint8_t first_payload, const uint8_t *inner, size_t inner_len,
                     uint8_t *store, size_t *store_len) {
    return sk_send(c, IKE_EXCHANGE_INFORMATIONAL, is_response, mid, first_payload, inner, inner_len, store, store_len);
}

/* Classify + decrypt a received SK{} message of exchange `exch`. Returns 0 and fills the outs, or
 * -1 (not ours / malformed / ICV fail). */
static int sk_open_slot(weirdike_ctx *c, int s, uint8_t exch, const uint8_t *data, size_t len,
                        uint8_t *first_pl, uint32_t *mid, int *is_response,
                        uint8_t *inner, size_t inner_cap, size_t *inner_len) {
    const ike_sa_state_t *sa = &c->sa[s];
    if (len < WEIRDIKE_SK_PREFIX) return -1;
    if (memcmp(data, sa->spi_i, 8) != 0 || memcmp(data + 8, sa->spi_r, 8) != 0) return -1;
    if (data[16] != IKE_PL_SK) return -1;
    if (data[18] != exch) return -1;
    uint8_t flags = data[19];
    /* The peer's I flag is the opposite of our role on this SA; our own echo would carry ours -> drop. */
    if (((flags & IKE_FLAG_INITIATOR) != 0) == (sa->role_initiator != 0)) return -1;
    *is_response = (flags & IKE_FLAG_RESPONSE) ? 1 : 0;
    *mid = ((uint32_t)data[20] << 24) | ((uint32_t)data[21] << 16) | ((uint32_t)data[22] << 8) | data[23];
    uint32_t wire_len = ((uint32_t)data[24] << 24) | ((uint32_t)data[25] << 16) | ((uint32_t)data[26] << 8) | data[27];
    if (wire_len != len) return -1;
    *first_pl = data[IKE_HDR_LEN];   /* SK NextPayload */
    info_crypto_t ic; if (info_crypto_slot(c, s, &ic) != 0) return -1;
    const uint8_t *sk_e = sa->role_initiator ? sa->sk.sk_er : sa->sk.sk_ei;   /* the PEER's direction */
    const uint8_t *sk_a = sa->role_initiator ? sa->sk.sk_ar : sa->sk.sk_ai;
    return ike_sk_open(ic.aes, c->crypto->ctx, ic.integ, c->crypto->ctx, ic.integ_out, ic.icv,
                       sk_e, sa->sk.sk_e_len, sk_a, sa->sk.sk_a_len, data, len, WEIRDIKE_SK_PREFIX,
                       inner, inner_cap, inner_len);
}
static int sk_open(weirdike_ctx *c, uint8_t exch, const uint8_t *data, size_t len,
                   uint8_t *first_pl, uint32_t *mid, int *is_response,
                   uint8_t *inner, size_t inner_cap, size_t *inner_len) {
    return sk_open_slot(c, c->sa_active, exch, data, len, first_pl, mid, is_response, inner, inner_cap, inner_len);
}
static int info_open(weirdike_ctx *c, const uint8_t *data, size_t len,
                     uint8_t *first_pl, uint32_t *mid, int *is_response,
                     uint8_t *inner, size_t inner_cap, size_t *inner_len) {
    return sk_open(c, IKE_EXCHANGE_INFORMATIONAL, data, len, first_pl, mid, is_response, inner, inner_cap, inner_len);
}

/* Tear down after a DELETE (ours acked, or peer's IKE delete): release socket + wipe keys -> CLOSED. */
static void info_close(weirdike_ctx *c, const char *msg) {
    release_runtime(c);
    wipe_secrets(c);
    SA(c)->req_active = 0;
    c->closing = 0;
    c->disconnect_pending = 0;
    c->state = WEIRDIKE_STATE_CLOSED;
    if (msg) w_log(c, WEIRDIKE_LOG_INFO, msg);
}

/* Start our graceful IKE-SA DELETE. Caller guarantees no other local request is in flight. */
static int info_start_delete(weirdike_ctx *c, uint32_t now_ms) {
    uint8_t inner[16];
    uint8_t fp = IKE_PL_NONE;
    int n = ike_info_build_delete_ike(inner, sizeof(inner), &fp);
    if (n < 0) return -1;
    uint32_t mid = SA(c)->tx_mid++;
    if (info_send(c, 0, mid, fp, inner, (size_t)n, SAWS(c)->req, &SAWS(c)->req_len) != 0) return -1;
    SA(c)->req_active = 1;
    SA(c)->req_is_delete = 1;
    SA(c)->req_kind = REQ_DELETE_IKE;
    SA(c)->req_mid = mid;
    SA(c)->req_retransmit = 0;
    SA(c)->req_deadline_ms = now_ms + WEIRDIKE_RTO_BASE_MS;
    c->disconnect_pending = 0;
    w_log(c, WEIRDIKE_LOG_INFO, "weirdike: sent IKE SA DELETE (graceful close)");
    return 0;
}

/* AP5: after a rekey, DELETE the PREVIOUS Child SA (INFORMATIONAL, our old inbound SPI). Shares the
 * request window. On ack (or give-up) the previous SA is dropped. */
static int info_start_delete_child_prev(weirdike_ctx *c, uint32_t now_ms) {
    if (!HAVE_PREV(c) || SA(c)->req_active) return -1;
    uint8_t inner[32]; uint8_t fp = IKE_PL_NONE;
    int n = ike_info_build_delete_esp(inner, sizeof(inner), PREV(c)->spi_i, &fp);
    if (n < 0) return -1;
    uint32_t mid = SA(c)->tx_mid++;
    if (info_send(c, 0, mid, fp, inner, (size_t)n, SAWS(c)->req, &SAWS(c)->req_len) != 0) return -1;
    SA(c)->req_active = 1; SA(c)->req_is_delete = 0; SA(c)->req_kind = REQ_DELETE_CHILD;
    SA(c)->req_mid = mid; SA(c)->req_retransmit = 0; SA(c)->req_deadline_ms = now_ms + WEIRDIKE_RTO_BASE_MS;
    w_log(c, WEIRDIKE_LOG_INFO, "weirdike: sent DELETE for the previous Child SA (rekey overlap ends)");
    return 0;
}
static void handle_informational(weirdike_ctx *c, const uint8_t *data, size_t len) {
    uint8_t first_pl = 0; uint32_t mid = 0; int is_resp = 0;
    uint8_t *inner = c->ws->rx_plain; size_t ilen = 0;   /* decrypted inner payloads (this call only) */
    if (info_open(c, data, len, &first_pl, &mid, &is_resp, inner, sizeof(c->ws->rx_plain), &ilen) != 0) return;
    SA(c)->last_rx_ms = c->cur_ms; SA(c)->last_rx_armed = 1;   /* peer liveness proven */

    if (is_resp) {   /* a response to one of OUR requests (DPD probe / graceful DELETE / old-child DELETE) */
        if (SA(c)->req_active && mid == SA(c)->req_mid && SA(c)->req_kind != REQ_CHILD_REKEY) {
            int was_delete = SA(c)->req_is_delete;
            int kind = SA(c)->req_kind;
            SA(c)->req_active = 0;
            SA(c)->req_is_delete = 0;
            SA(c)->req_kind = REQ_DPD;
            if (was_delete) {
                info_close(c, "weirdike: IKE SA DELETE acknowledged -> closed");
            } else if (kind == REQ_DELETE_CHILD) {
                drop_child_prev(c);   /* AP5: overlap over -- old SA gone on both sides */
                w_log(c, WEIRDIKE_LOG_INFO, "weirdike: previous Child SA deleted (rekey complete)");
                if (c->closing && c->disconnect_pending)
                    if (info_start_delete(c, c->cur_ms) != 0) info_close(c, "weirdike: DELETE send failed -> closed locally");
            } else if (c->closing && c->disconnect_pending) {
                if (info_start_delete(c, c->cur_ms) != 0) info_close(c, "weirdike: DELETE send failed -> closed locally");
            }
        }
        return;
    }

    /* A peer-initiated REQUEST -> we MUST answer. The responder has its own Message-ID space,
     * starting at zero. Duplicate last request -> replay the cached response without side effects;
     * any other out-of-window id is ignored (window size 1). */
    if (SA(c)->rx_have && mid == SA(c)->rx_mid) {
        (void)ike_send(c, SAWS(c)->resp, SAWS(c)->resp_len);
        return;
    }
    if (mid != SA(c)->rx_next_mid) return;

    ike_info_content_t ct;
    if (ike_info_parse_inner(first_pl, ilen ? inner : NULL, ilen, &ct) != 0) return;   /* malformed -> ignore */

    uint8_t rinner[64]; size_t rlen = 0; uint8_t rfp = IKE_PL_NONE;
    int close_ike = 0;
    if (ct.delete_ike) {
        rfp = IKE_PL_NONE; rlen = 0; close_ike = 1;   /* empty ack, then tear the IKE SA down */
    } else if (ct.delete_esp) {
        /* A DELETE lists the SPI the sender receives on, i.e. our OUTBOUND SPI. Ignore an unrelated
         * SPI instead of tearing down the current Child SA. For a match, answer with our inbound SPI
         * and wipe the Child keys immediately after copying that SPI for the response. */
        int match = 0, match_prev = 0;
        for (int i = 0; i < ct.esp_spi_count; i++) {
            uint32_t s = be32_bytes(ct.esp_spi[i]);
            if (HAVE_CHILD(c) && s == CUR(c)->sa.outbound_spi) { match = 1; break; }
            if (HAVE_PREV(c) && s == PREV(c)->sa.outbound_spi) { match_prev = 1; break; }
        }
        if (match_prev) {
            /* AP5: the peer deletes the PREVIOUS Child SA after a rekey -> answer with its inbound
             * SPI (ours) and drop it; the CURRENT SA is untouched (no child_deleted). */
            int n = ike_info_build_delete_esp(rinner, sizeof(c->ws->tx_inner), PREV(c)->spi_i, &rfp);
            if (n < 0) return;
            rlen = (size_t)n;
            drop_child_prev(c);
            w_log(c, WEIRDIKE_LOG_INFO, "weirdike: peer deleted the previous Child SA (rekey complete)");
        } else if (match && HAVE_CHILD(c)) {
            uint8_t inbound_spi[4];
            memcpy(inbound_spi, c->child_spi_i, sizeof(inbound_spi));
            int n = ike_info_build_delete_esp(rinner, sizeof(c->ws->tx_inner), inbound_spi, &rfp);
            if (n < 0) return;
            rlen = (size_t)n;
            c->child_deleted = 1;
            wipe_child_sa(c);
            drop_child_prev(c);
            if (c->state == WEIRDIKE_STATE_CHILD_ESTABLISHED) c->state = WEIRDIKE_STATE_ESTABLISHED;
        } else {
            rfp = IKE_PL_NONE;
            rlen = 0;
        }
    } else {
        rfp = IKE_PL_NONE; rlen = 0;   /* empty (DPD) or tolerated-only payloads -> empty ack */
    }

    if (info_send(c, 1, mid, rfp, rlen ? rinner : NULL, rlen, SAWS(c)->resp, &SAWS(c)->resp_len) == 0) {
        SA(c)->rx_have = 1;
        SA(c)->rx_mid = mid;
        SA(c)->rx_next_mid++;
    }
    if (close_ike) info_close(c, "weirdike: peer deleted the IKE SA -> closed");
}

/* Graceful close: send an encrypted DELETE for the IKE SA and await the ack (bounded, via poll()).
 * Nothing to delete (not authenticated) -> plain deinit. On send failure -> deinit. The host keeps
 * polling until weirdike_state()==CLOSED (ack) or the info retransmits give up (then also CLOSED). */
int weirdike_disconnect(weirdike_ctx *c, uint32_t now_ms) {
    if (!c) return -1;
    c->cur_ms = now_ms;
    if (c->state != WEIRDIKE_STATE_ESTABLISHED && c->state != WEIRDIKE_STATE_CHILD_ESTABLISHED) {
        weirdike_deinit(c);
        return 0;
    }
    c->closing = 1;
    /* An IKE-SA rekey transition still in progress: the old SA is dropped locally (the peer's DPD
     * will notice; the DELETE below closes the current SA cleanly). */
    if (c->sa_old >= 0) old_slot_release(c, "weirdike: closing -> old IKE SA of the pending rekey dropped");
    /* RFC window size defaults to one: never start DELETE while our DPD request is outstanding.
     * Queue the close; its response or bounded timeout will start DELETE next. */
    if (SA(c)->req_active) {
        c->disconnect_pending = 1;
        return 0;
    }
    if (info_start_delete(c, now_ms) != 0) {
        info_close(c, "weirdike: DELETE send failed -> closed locally");
        return -1;
    }
    return 0;
}

/* Has the peer torn down our Child SA (data plane must stop)? Cleared when a new Child SA is
 * installed (rekey). */
int weirdike_child_deleted(const weirdike_ctx *c) { return c ? c->child_deleted : 1; }

/* ===================== AP5: Child-SA rekey via CREATE_CHILD_SA ================================
 * Both directions. Keys: KEYMAT = prf+(SK_d, [g^ir] | Ni | Nr) with the nonces of THIS exchange
 * (initiator's first) and the negotiated Child key lengths. Direction mapping follows who initiated
 * the CREATE_CHILD_SA: initiator->responder keys are the exchange initiator's OUTBOUND. The old SA
 * stays installed for RX (child_prev) until its DELETE is exchanged -- no packets lost. */

/* Install a freshly negotiated Child SA as CURRENT, moving the current one to child_prev.
 * we_initiated: 1 = we sent the CREATE_CHILD_SA request (i2r = our outbound). */
static int child_install_rekeyed(weirdike_ctx *c, int we_initiated,
                                 const uint8_t our_spi[4], const uint8_t peer_spi[4],
                                 uint16_t encr, uint16_t bits, uint16_t integ,
                                 const uint8_t *gir, size_t gir_len,
                                 const uint8_t *ni, size_t ni_len, const uint8_t *nr, size_t nr_len,
                                 const weirdike_ts_t *ts_ours, const weirdike_ts_t *ts_peer) {
    ike_prf_fn prf = weirdike_prf_cb(c->crypto, SA(c)->suite.prf);
    size_t prf_len = weirdike_prf_len(SA(c)->suite.prf);
    size_t enc_len = weirdike_encr_key_len((weirdike_encr_id_t)encr, bits);
    size_t integ_len = weirdike_integ_key_len((weirdike_integ_id_t)integ);
    ike_child_keys_t ck;
    if (!prf || !prf_len || !enc_len || !integ_len ||
        ike_derive_child_keys_pfs(prf, c->crypto->ctx, prf_len, SA(c)->sk.sk_d, SA(c)->sk.sk_d_len,
                                  gir, gir_len, ni, ni_len, nr, nr_len, enc_len, integ_len, &ck) != 0) return -1;
    /* current -> previous (RX-only overlap). Only the rekey INITIATOR deletes the old SA (RFC 7296
     * 2.8); when the peer initiated, we wait for its DELETE, with a local safety drop after 30 s. */
    if (HAVE_CHILD(c)) {
        drop_child_prev(c);               /* a still-lingering previous SA is superseded */
        c->child_prev = c->child_cur;     /* ROTATE slots: the current SA becomes the previous one */
        c->child_cur  = -1;
        PREV(c)->delete_ours = we_initiated;
        PREV(c)->deadline_ms = c->cur_ms + 30000u;
        PREV(c)->born_armed  = 0;
    }
    { int idx = child_slot_alloc(c); if (idx < 0) { w_zero(c->platform, &ck, sizeof(ck)); return -1; } c->child_cur = idx; }
    memcpy(CUR(c)->spi_i, our_spi, 4);
    weirdike_child_sa_t *ch = &CUR(c)->sa;
    ch->inbound_spi  = be32_bytes(our_spi);
    ch->outbound_spi = be32_bytes(peer_spi);
    ch->encr = (weirdike_encr_id_t)encr; ch->integ = (weirdike_integ_id_t)integ;
    const uint8_t *e_out = we_initiated ? ck.enc_i2r : ck.enc_r2i, *e_in = we_initiated ? ck.enc_r2i : ck.enc_i2r;
    const uint8_t *i_out = we_initiated ? ck.integ_i2r : ck.integ_r2i, *i_in = we_initiated ? ck.integ_r2i : ck.integ_i2r;
    memcpy(ch->enc_key_out, e_out, enc_len);   ch->enc_key_out_len = enc_len;
    memcpy(ch->enc_key_in,  e_in,  enc_len);   ch->enc_key_in_len  = enc_len;
    memcpy(ch->integ_key_out, i_out, integ_len); ch->integ_key_out_len = integ_len;
    memcpy(ch->integ_key_in,  i_in,  integ_len); ch->integ_key_in_len  = integ_len;
    ch->nat_detected = c->nat_detected;
    ch->local_ts = *ts_ours; ch->remote_ts = *ts_peer;
    ch->remote_ts_list[0] = *ts_peer; ch->n_remote_ts = 1;   /* E2: caller overwrites with the full set when it has one */
    memcpy(c->child_spi_i, our_spi, 4); memcpy(c->child_spi_r, peer_spi, 4);
    c->child_ts_i = *ts_ours; c->child_ts_r = *ts_peer;
    c->child_ts_r_list[0] = *ts_peer; c->n_child_ts_r = 1;
    c->have_child_sa = 1; c->child_deleted = 0;
    c->child_gen++; CUR(c)->born_ms = c->cur_ms; CUR(c)->born_armed = 1; c->child_bytes = 0;
    c->diag_child_encr = encr; c->diag_child_bits = bits; c->diag_child_integ = integ; c->diag_child_sa_ok = 1;
    if (c->state == WEIRDIKE_STATE_ESTABLISHED) c->state = WEIRDIKE_STATE_CHILD_ESTABLISHED;
    w_zero(c->platform, &ck, sizeof(ck));
    return 0;
}

static void rekey_abort(weirdike_ctx *c, const char *why) {
    if (c->rk_dh_priv && c->crypto->ke_free) c->crypto->ke_free(c->crypto->ctx, c->rk_dh_group, c->rk_dh_priv);
    c->rk_dh_priv = NULL;
    w_zero(c->platform, c->rk_ni, sizeof(c->rk_ni));
    SA(c)->req_active = 0; SA(c)->req_kind = REQ_DPD;
    if (HAVE_CHILD(c)) CUR(c)->born_ms = c->cur_ms;   /* try again after another lifetime (keeps the old SA working) */
    if (why) w_log(c, WEIRDIKE_LOG_ERROR, why);
}

/* Start OUR Child-SA rekey. Requires an installed child and a free request window. 0 = sent. */
static int start_child_rekey(weirdike_ctx *c, uint32_t now_ms) {
    if (!HAVE_CHILD(c) || SA(c)->req_active || c->closing) return -1;
    if (c->state != WEIRDIKE_STATE_CHILD_ESTABLISHED) return -1;
    const weirdike_crypto_t *cr = c->crypto;
    do { if (cr->random(cr->ctx, c->rk_spi_i, 4) != 0) return -1; }
    while (c->rk_spi_i[0] == 0 && c->rk_spi_i[1] == 0 && c->rk_spi_i[2] == 0);   /* never 0..255 */
    if (cr->random(cr->ctx, c->rk_ni, 32) != 0) return -1;
    uint8_t *ke_pub = c->ws->crypto.ke_pub; size_t kl = sizeof(c->ws->crypto.ke_pub);
    c->rk_dh_group = 0;
    if (c->pfs_group) {
        c->rk_dh_group = c->pfs_group;
        if (cr->ke_keygen(cr->ctx, c->rk_dh_group, &c->rk_dh_priv, ke_pub, &kl) != 0 || kl != weirdike_dh_pub_len(c->rk_dh_group)) {
            c->rk_dh_priv = NULL; return -1;
        }
    }
    uint8_t *inner = c->ws->tx_inner; uint8_t fp = 0;
    int n = ike_build_child_rekey_request_ex(inner, sizeof(c->ws->tx_inner), c->child_spi_i, c->rk_spi_i, &c->child_policy,
                                          c->rk_ni, 32, c->rk_dh_group, c->pfs_group ? ke_pub : NULL,
                                          c->pfs_group ? kl : 0, &c->child_ts_i, &c->child_ts_r,
                                          c->n_child_ts_r > 1 ? &c->child_ts_r_list[1] : NULL, c->n_child_ts_r > 1 ? c->n_child_ts_r - 1 : 0, &fp);   /* E2 */
    if (n < 0) { rekey_abort(c, "weirdike: rekey request build failed"); return -1; }
    uint32_t mid = SA(c)->tx_mid++;
    if (sk_send(c, IKE_EXCHANGE_CREATE_CHILD_SA, 0, mid, fp, inner, (size_t)n, SAWS(c)->req, &SAWS(c)->req_len) != 0) {
        rekey_abort(c, "weirdike: rekey request send failed"); return -1;
    }
    SA(c)->req_active = 1; SA(c)->req_is_delete = 0; SA(c)->req_kind = REQ_CHILD_REKEY;
    SA(c)->req_mid = mid; SA(c)->req_retransmit = 0; SA(c)->req_deadline_ms = now_ms + WEIRDIKE_RTO_BASE_MS;
    w_log(c, WEIRDIKE_LOG_INFO, c->pfs_group ? "weirdike: CREATE_CHILD_SA rekey sent (PFS)" : "weirdike: CREATE_CHILD_SA rekey sent");
    return 0;
}

int weirdike_rekey_child(weirdike_ctx *c, uint32_t now_ms) {
    if (!c) return -1;
    c->cur_ms = now_ms;
    return start_child_rekey(c, now_ms);
}
uint32_t weirdike_child_generation(const weirdike_ctx *c) { return c ? c->child_gen : 0; }
void weirdike_child_traffic(weirdike_ctx *c, uint32_t bytes) { if (c) c->child_bytes += bytes; }
int weirdike_get_child_sa_prev(const weirdike_ctx *c, weirdike_child_sa_t *out) {
    if (!c || !out || !HAVE_PREV(c)) return -1;
    *out = PREV(c)->sa;
    return 0;
}

/* Response to OUR CREATE_CHILD_SA request. */
/* A Child rekey response that is NOT an error notify but that we must reject means the peer has very
 * likely INSTALLED a Child SA we do not accept (e.g. it answered a PFS request without honouring the
 * D-H). Keeping our old Child SA would only look connected while the peer already moved on -- the
 * data path dies silently (HW finding 2026-09-07 vs FRITZ!Box). Honest handling: log the exact reason,
 * drop the rekey state and close the IKE SA gracefully (DELETE), so the host re-establishes a
 * consistent tunnel. An explicit ERROR notify (peer installed nothing) keeps the old Child SA. */
static void child_rekey_unrecoverable(weirdike_ctx *c, const char *why) {
    rekey_abort(c, why);
    w_log(c, WEIRDIKE_LOG_ERROR, "weirdike: rejected Child rekey response -> peer state unknown; closing the IKE SA for a clean re-establishment");
    c->closing = 1;
    if (info_start_delete(c, c->cur_ms) != 0) info_close(c, "weirdike: DELETE send failed -> closed locally");
}

/* Secrets-free wire summary of a CREATE_CHILD_SA response (what the peer actually answered). */
static void log_create_child_response(weirdike_ctx *c, const ike_create_child_msg_t *m) {
    char b[200];
    snprintf(b, sizeof(b),
             "weirdike: CREATE_CHILD_SA resp: notify=%u sa=%d ike=%d encr=%u/%u(n%u) integ=%u(n%u) esn=%d/%d dh_n=%u dh0=%u ke=%d grp=%u len=%u spi=%02x%02x%02x%02x tsi=%d tsr=%d nonce=%u rekeysa=%d",
             (unsigned)m->error_notify, m->sa_present, m->sa_is_ike,
             (unsigned)(m->n_encr ? m->encr[0].id : 0), (unsigned)(m->n_encr ? m->encr[0].key_bits : 0), (unsigned)m->n_encr,
             (unsigned)(m->n_integ ? m->integ[0] : 0), (unsigned)m->n_integ, m->esn_none, m->esn_other,
             (unsigned)m->n_dh, (unsigned)(m->n_dh ? m->dh[0] : 0), m->have_ke, (unsigned)m->ke_group, (unsigned)m->ke_len,
             m->spi[0], m->spi[1], m->spi[2], m->spi[3], m->tsi_ok, m->tsr_ok, (unsigned)m->nonce_len, m->rekey_sa);
    w_log(c, WEIRDIKE_LOG_INFO, b);
}

static void handle_create_child_response(weirdike_ctx *c, uint8_t fp, const uint8_t *inner, size_t ilen) {
    ike_create_child_msg_t m;
    if (ike_parse_create_child_inner(fp, ilen ? inner : NULL, ilen, &m) != 0) { child_rekey_unrecoverable(c, "weirdike: malformed CREATE_CHILD_SA response"); return; }
    log_create_child_response(c, &m);
    if (m.error_notify) { c->diag_last_notify = m.error_notify; rekey_abort(c, "weirdike: peer refused the Child rekey (error notify) -> old Child SA stays"); return; }
    if (!m.sa_present || m.sa_is_ike || m.n_encr != 1 || m.n_integ != 1 || !m.esn_none || !m.have_nonce || !m.tsi_ok || !m.tsr_ok) {
        child_rekey_unrecoverable(c, "weirdike: CREATE_CHILD_SA response is not a single ESP selection"); return; }
    if (!ike_policy_child_allows(&c->child_policy, m.encr[0].id, m.encr[0].key_bits, m.integ[0]) ||
        !weirdike_child_encr_supported(m.encr[0].id, m.encr[0].key_bits) || !weirdike_child_integ_supported(m.integ[0])) {
        child_rekey_unrecoverable(c, "weirdike: rekey selection outside the child policy"); return; }
    uint8_t *gir = c->ws->crypto.gir; size_t gl = 0;
    c->diag_child_rekey_dh = (uint16_t)(m.n_dh ? m.dh[0] : 0); c->diag_child_rekey_ke = m.have_ke;   /* PO item 0: rekey diagnosis */
    if (c->rk_dh_group) {
        /* PFS: RFC 7296 1.3.3/2.8 -- a request with KEi + a D-H transform must be answered with KEr of
         * that group and the D-H transform in the selection. Name the exact deviation. */
        const char *why = NULL;
        if (!m.have_ke && m.n_dh == 0) {
            c->diag_peer_pfs_rejected = 1;   /* host-visible: the PEER ignores PFS (not a client limitation) */
            why = "weirdike: PFS requested, but peer selected Child SA without DH/KE (no-PFS Child SA installed by the peer)";
        }
        else if (!m.have_ke)                      why = "weirdike: PFS rekey: peer selected the D-H transform but sent NO KE payload";
        else if (m.n_dh == 0)                     why = "weirdike: PFS rekey: peer sent KE but NO D-H transform in the selection";
        else if (m.n_dh != 1 || m.dh[0] != c->rk_dh_group) why = "weirdike: PFS rekey: peer selected a different D-H group than requested";
        else if (m.ke_group != c->rk_dh_group)   why = "weirdike: PFS rekey: KE payload group differs from the requested D-H group";
        else if (m.ke_len != weirdike_dh_pub_len(c->rk_dh_group)) why = "weirdike: PFS rekey: KE payload length does not match the D-H group";
        if (why) { child_rekey_unrecoverable(c, why); return; }
        gl = sizeof(c->ws->crypto.gir);
        if (c->crypto->ke_shared(c->crypto->ctx, c->rk_dh_group, c->rk_dh_priv, m.ke, m.ke_len, gir, &gl) != 0 || gl != weirdike_dh_shared_len(c->rk_dh_group)) {
            w_zero(c->platform, gir, sizeof(c->ws->crypto.gir)); child_rekey_unrecoverable(c, "weirdike: PFS shared secret failed"); return; }
        c->crypto->ke_free(c->crypto->ctx, c->rk_dh_group, c->rk_dh_priv); c->rk_dh_priv = NULL;
    } else if (m.have_ke || m.n_dh) { child_rekey_unrecoverable(c, "weirdike: unexpected KE / D-H transform in a no-PFS rekey response"); return; }
    /* TS: the response carries the (possibly narrowed) selectors; ours first (we initiated). */
    int rc = child_install_rekeyed(c, 1, c->rk_spi_i, m.spi, m.encr[0].id, m.encr[0].key_bits, m.integ[0],
                                   gl ? gir : NULL, gl, c->rk_ni, 32, m.nonce, m.nonce_len, &m.tsi, &m.tsr);
    if (rc == 0 && m.n_tsr) {   /* E2: keep the full narrowed TSr set of the rekeyed Child SA */
        c->n_child_ts_r = m.n_tsr; for (size_t i = 0; i < m.n_tsr; i++) c->child_ts_r_list[i] = m.tsr_list[i];
        CUR(c)->sa.n_remote_ts = m.n_tsr; for (size_t i = 0; i < m.n_tsr; i++) CUR(c)->sa.remote_ts_list[i] = m.tsr_list[i];
    }
    w_zero(c->platform, gir, sizeof(c->ws->crypto.gir));
    w_zero(c->platform, c->rk_ni, sizeof(c->rk_ni));
    SA(c)->req_active = 0; SA(c)->req_kind = REQ_DPD;
    if (rc != 0) { child_rekey_unrecoverable(c, "weirdike: rekeyed Child keymat failed"); return; }
    w_log(c, WEIRDIKE_LOG_INFO, "weirdike: Child SA rekeyed (we initiated); deleting the previous one");
    (void)info_start_delete_child_prev(c, c->cur_ms);
}

/* Peer-initiated CREATE_CHILD_SA request (mid == info_rx_next_mid, dedup handled by the caller). */
static void handle_create_child_request(weirdike_ctx *c, uint32_t mid, uint8_t fp, const uint8_t *inner, size_t ilen) {
    ike_create_child_msg_t m;
    uint8_t *rinner = c->ws->tx_inner; uint8_t rfp = IKE_PL_NONE; int n = -1;   /* response chain (rx_plain holds the request) */
    if (ike_parse_create_child_inner(fp, ilen ? inner : NULL, ilen, &m) != 0) return;   /* malformed -> ignore */
    int ike_new_slot = -1;   /* peer-initiated IKE-SA rekey: activate this slot AFTER the response went out */
    if (m.sa_present && m.sa_is_ike) {
        n = peer_ike_rekey(c, &m, rinner, sizeof(c->ws->tx_inner), &rfp, &ike_new_slot);
    } else if (!m.rekey_sa) {
        n = ike_build_notify_only(rinner, sizeof(c->ws->tx_inner), 0, NULL, 0, IKE_NOTIFY_NO_ADDITIONAL_SAS, NULL, 0, &rfp);
    } else if (!HAVE_CHILD(c) || be32_bytes(m.rekey_spi) != CUR(c)->sa.outbound_spi) {
        n = ike_build_notify_only(rinner, sizeof(c->ws->tx_inner), IKE_PROTO_ESP_ID, m.rekey_spi, 4, IKE_NOTIFY_CHILD_SA_NOT_FOUND, NULL, 0, &rfp);
    } else {
        uint16_t encr = 0, bits = 0, integ = 0, dh = 0;
        if (!ike_select_child_offer(&m, &c->child_policy, c->pfs_group, &encr, &bits, &integ, &dh) || !m.have_nonce || !m.tsi_ok || !m.tsr_ok) {
            n = ike_build_notify_only(rinner, sizeof(c->ws->tx_inner), 0, NULL, 0, 14 /* NO_PROPOSAL_CHOSEN */, NULL, 0, &rfp);
        } else {
            uint8_t our_spi[4], nr[32]; uint8_t *ke_pub = c->ws->crypto.ke_pub; size_t kl = 0; void *priv = NULL;
            uint8_t *gir = c->ws->crypto.gir; size_t gl = 0; int ok = 1;
            const weirdike_crypto_t *cr = c->crypto;
            do { if (cr->random(cr->ctx, our_spi, 4) != 0) { ok = 0; break; } } while (our_spi[0] == 0 && our_spi[1] == 0 && our_spi[2] == 0);
            if (ok && cr->random(cr->ctx, nr, 32) != 0) ok = 0;
            if (ok && dh) {
                if (!m.have_ke || m.ke_group != dh || m.ke_len != weirdike_dh_pub_len(dh)) ok = 0;
                kl = sizeof(c->ws->crypto.ke_pub);
                if (ok && (cr->ke_keygen(cr->ctx, dh, &priv, ke_pub, &kl) != 0 || kl != weirdike_dh_pub_len(dh))) ok = 0;
                gl = sizeof(c->ws->crypto.gir);
                if (ok && (cr->ke_shared(cr->ctx, dh, priv, m.ke, m.ke_len, gir, &gl) != 0 || gl != weirdike_dh_shared_len(dh))) ok = 0;
                if (priv && cr->ke_free) cr->ke_free(cr->ctx, dh, priv);
            }
            if (ok) {
                /* peer initiated: its TSi = peer side, its TSr = our side. */
                ok = child_install_rekeyed(c, 0, our_spi, m.spi, encr, bits, integ, dh ? gir : NULL, dh ? gl : 0,
                                           m.nonce, m.nonce_len, nr, 32, &m.tsr, &m.tsi) == 0;
            }
            w_zero(c->platform, gir, sizeof(c->ws->crypto.gir));
            if (ok) {
                n = ike_build_child_rekey_response(rinner, sizeof(c->ws->tx_inner), our_spi, encr, bits, integ, nr, 32,
                                                   dh, dh ? ke_pub : NULL, dh ? kl : 0, &m.tsi, &m.tsr, &rfp);
                w_log(c, WEIRDIKE_LOG_INFO, "weirdike: Child SA rekeyed (peer initiated); awaiting its DELETE of the old one");
            } else {
                n = ike_build_notify_only(rinner, sizeof(c->ws->tx_inner), 0, NULL, 0, 14, NULL, 0, &rfp);
            }
            w_zero(c->platform, nr, sizeof(nr));
        }
    }
    if (n < 0) { if (ike_new_slot >= 0) w_zero(c->platform, &c->sa[ike_new_slot], sizeof(c->sa[ike_new_slot])); return; }
    if (sk_send(c, IKE_EXCHANGE_CREATE_CHILD_SA, 1, mid, rfp, (size_t)n ? rinner : NULL, (size_t)n,
                SAWS(c)->resp, &SAWS(c)->resp_len) == 0) {
        SA(c)->rx_have = 1; SA(c)->rx_mid = mid; SA(c)->rx_next_mid++;
        /* The response (sealed and cached on the OLD SA for retransmits) is out -> the new IKE SA takes
         * over; the old one stays alive until the peer, the rekey initiator, deletes it. */
        if (ike_new_slot >= 0) {
            activate_new_ike_sa(c, ike_new_slot, 0);
            w_log(c, WEIRDIKE_LOG_INFO, "weirdike: IKE SA rekeyed (peer initiated); awaiting its DELETE of the old IKE SA");
        }
    } else if (ike_new_slot >= 0) {
        w_zero(c->platform, &c->sa[ike_new_slot], sizeof(c->sa[ike_new_slot]));   /* send failed: no new SA */
    }
}

/* ===================== IKE-SA rekey via CREATE_CHILD_SA (RFC 7296 1.3.2 / 2.18) ================
 * The new IKE SA is built in the free state slot: own SPIs, SKEYSEED = prf_old(SK_d, g^ir | Ni | Nr),
 * keys via the NEW suite's prf+, Message IDs from 0, its own request/response windows and liveness
 * clock. The initiator of the rekey exchange is the initiator of the new SA (I flag / SK direction
 * per slot). Child SAs need no change: they belong to whichever IKE SA is active. The OLD SA lives on
 * in its slot until its DELETE is exchanged (rekey initiator deletes, RFC 7296 2.8), with its own
 * keys and Message-ID space (see handle_old_sa_datagram / weirdike_poll); only then are its secrets
 * wiped. Transitions in progress are refused with TEMPORARY_FAILURE: the core holds two IKE-SA
 * slots, so a second candidate is never written over a live one.
 * KNOWN LIMITATION: simultaneous IKE-SA rekey collision resolution by nonce comparison (RFC 7296
 * 2.8.2 / 2.25.2, SHOULD) is NOT IMPLEMENTED -- a peer rekey arriving while ours is outstanding is
 * serialized with TEMPORARY_FAILURE and retry (see weirdike.h). */

/* Pick the suite from a peer's IKE proposal OFFER: first offered transform per type that this build
 * runs, then the whole selection must be inside our policy. 1 = filled, 0 = nothing acceptable. */
static int pol_has_u16(const uint16_t *v, size_t n, uint16_t x) { for (size_t i = 0; i < n && i < WEIRDIKE_POLICY_MAX; i++) if (v[i] == x) return 1; return 0; }
static int pol_has_encr(const weirdike_encr_t *v, size_t n, uint16_t id, uint16_t bits) { for (size_t i = 0; i < n && i < WEIRDIKE_POLICY_MAX; i++) if (v[i].id == id && v[i].key_bits == bits) return 1; return 0; }
/* Per transform type: the FIRST offered transform that this build implements AND the host policy
 * allows (B2/B3: with many groups implemented, "first implemented" alone would pick a group the
 * policy forbids and wrongly refuse the whole offer). */
static int select_ike_offer(const ike_create_child_msg_t *m, const weirdike_ike_policy_t *p, weirdike_ike_suite_t *sel) {
    memset(sel, 0, sizeof(*sel));
    size_t i; int ok;
    ok = 0; for (i = 0; i < m->n_encr && !ok; i++)  if (weirdike_ike_encr_supported(m->encr[i].id, m->encr[i].key_bits) && pol_has_encr(p->encr, p->n_encr, m->encr[i].id, m->encr[i].key_bits)) { sel->encr = (weirdike_encr_id_t)m->encr[i].id; sel->encr_key_bits = m->encr[i].key_bits; ok = 1; }
    if (!ok) return 0;
    ok = 0; for (i = 0; i < m->n_prf && !ok; i++)   if (weirdike_ike_prf_supported(m->prf[i]) && pol_has_u16(p->prf, p->n_prf, m->prf[i]))         { sel->prf   = (weirdike_prf_id_t)m->prf[i];     ok = 1; }
    if (!ok) return 0;
    ok = 0; for (i = 0; i < m->n_integ && !ok; i++) if (weirdike_ike_integ_supported(m->integ[i]) && pol_has_u16(p->integ, p->n_integ, m->integ[i])) { sel->integ = (weirdike_integ_id_t)m->integ[i]; ok = 1; }
    if (!ok) return 0;
    ok = 0; for (i = 0; i < m->n_dh && !ok; i++)    if (weirdike_ike_dh_supported(m->dh[i]) && pol_has_u16(p->dh, p->n_dh, m->dh[i]))               { sel->dh    = (weirdike_dh_id_t)m->dh[i];       ok = 1; }
    if (!ok) return 0;
    return ike_policy_ike_allows(p, sel) && weirdike_ike_suite_supported(sel);
}

/* Derive the NEW IKE SA's keys into slot n (SPIs/nonces in exchange order: initiator's first). */
static int ike_rekey_keys(weirdike_ctx *c, int n, const weirdike_ike_suite_t *sel,
                          const uint8_t *ni, size_t ni_len, const uint8_t *nr, size_t nr_len,
                          const uint8_t *gir, size_t gir_len, const uint8_t spi_i[8], const uint8_t spi_r[8]) {
    ike_prf_fn prf_old = weirdike_prf_cb(c->crypto, SA(c)->suite.prf);
    size_t prf_old_len = weirdike_prf_len(SA(c)->suite.prf);
    ike_prf_fn prf_new = weirdike_prf_cb(c->crypto, sel->prf);
    size_t prf_new_len = weirdike_prf_len(sel->prf);
    size_t integ_len   = weirdike_integ_key_len(sel->integ);
    size_t encr_len    = weirdike_encr_key_len(sel->encr, sel->encr_key_bits);
    if (!prf_old || !prf_new || !prf_old_len || !prf_new_len || !integ_len || !encr_len) return -1;
    if (!SA(c)->have_keys) return -1;
    if (ike_derive_keys_rekey(prf_old, prf_old_len, SA(c)->sk.sk_d, SA(c)->sk.sk_d_len,
                              prf_new, c->crypto->ctx, prf_new_len, integ_len, encr_len,
                              ni, ni_len, nr, nr_len, gir, gir_len, spi_i, spi_r, &c->sa[n].sk) != 0) return -1;
    memcpy(c->sa[n].spi_i, spi_i, 8); memcpy(c->sa[n].spi_r, spi_r, 8);
    c->sa[n].suite = *sel; c->sa[n].have_keys = 1;
    return 0;
}

/* The new IKE SA in slot n becomes the ACTIVE one; the current one becomes the OLD SA. */
static void activate_new_ike_sa(weirdike_ctx *c, int n, int we_initiated) {
    ike_sa_state_t *sa = &c->sa[n];
    sa->in_use = 1; sa->role_initiator = we_initiated ? 1 : 0; sa->is_old = 0;
    sa->tx_mid = 0; sa->rx_next_mid = 0; sa->rx_have = 0; sa->rx_mid = 0;   /* fresh Message-ID spaces */
    sa->req_active = 0; sa->req_kind = REQ_DPD; sa->req_is_delete = 0; sa->req_retransmit = 0;
    sa->retransmit_count = 0; sa->deadline_ms = 0;
    sa->last_rx_ms = c->cur_ms; sa->last_rx_armed = 1;                       /* liveness clock restarts */
    c->ws->sa[n].req_len = 0; c->ws->sa[n].resp_len = 0;
    int old = c->sa_active;
    c->sa_active = n; c->sa_old = old;
    c->sa[old].is_old = 1; c->sa[old].old_delete_ours = we_initiated;
    c->sa[old].old_deadline_ms = c->cur_ms + WEIRDIKE_IKE_OLD_SA_MAX_MS;
    c->ike_gen++; c->ike_born_ms = c->cur_ms;
    c->diag_have_ike_suite = 1;
}

/* Wipe the OLD IKE SA (its DELETE was exchanged, or it is being dropped) and free the slot. */
static void old_slot_release(weirdike_ctx *c, const char *why) {
    if (c->sa_old < 0) return;
    int s = c->sa_old;
    w_zero(c->platform, &c->sa[s], sizeof(c->sa[s]));
    w_zero(c->platform, &c->ws->sa[s], sizeof(c->ws->sa[s]));
    c->sa_old = -1;
    if (why) w_log(c, WEIRDIKE_LOG_INFO, why);
}

/* Our DELETE of the OLD IKE SA: MUST be the last request on it (RFC 7296 2.8); sealed with the old
 * keys, its own Message ID, retransmitted from the old slot's request buffer. */
static int info_start_delete_old(weirdike_ctx *c, uint32_t now_ms) {
    int s = c->sa_old; if (s < 0) return -1;
    ike_sa_state_t *sa = &c->sa[s];
    uint8_t inner[16]; uint8_t fp = IKE_PL_NONE;
    int n = ike_info_build_delete_ike(inner, sizeof(inner), &fp);
    if (n < 0) return -1;
    uint32_t mid = sa->tx_mid++;
    if (sk_send_slot(c, s, IKE_EXCHANGE_INFORMATIONAL, 0, mid, fp, inner, (size_t)n, c->ws->sa[s].req, &c->ws->sa[s].req_len) != 0) return -1;
    sa->req_active = 1; sa->req_is_delete = 1; sa->req_kind = REQ_DELETE_IKE_OLD; sa->req_mid = mid;
    sa->req_retransmit = 0; sa->req_deadline_ms = now_ms + WEIRDIKE_RTO_BASE_MS;
    return 0;
}

/* Abort OUR in-flight IKE-SA rekey: the candidate slot and D-H state go, the old IKE SA stays. */
static void ike_rekey_abort(weirdike_ctx *c, const char *why) {
    if (c->ikerk_dh_priv && c->crypto->ke_free) c->crypto->ke_free(c->crypto->ctx, c->ikerk_dh_group, c->ikerk_dh_priv);
    c->ikerk_dh_priv = NULL;
    w_zero(c->platform, c->ikerk_ni, sizeof(c->ikerk_ni));
    if (c->ikerk_active && c->ikerk_slot >= 0 && c->ikerk_slot < WEIRDIKE_IKE_SA_SLOTS && c->ikerk_slot != c->sa_active)
        w_zero(c->platform, &c->sa[c->ikerk_slot], sizeof(c->sa[c->ikerk_slot]));
    c->ikerk_active = 0;
    SA(c)->req_active = 0; SA(c)->req_kind = REQ_DPD;
    c->ike_born_ms = c->cur_ms;   /* try again after another lifetime; the current IKE SA keeps working */
    if (why) w_log(c, WEIRDIKE_LOG_ERROR, why);
}

/* Start OUR IKE-SA rekey. Needs an authenticated SA, a free request window, no transition in
 * progress and a free slot. 0 = request sent. */
static int start_ike_rekey(weirdike_ctx *c, uint32_t now_ms) {
    if (c->state != WEIRDIKE_STATE_ESTABLISHED && c->state != WEIRDIKE_STATE_CHILD_ESTABLISHED) return -1;
    if (c->closing || SA(c)->req_active || c->sa_old >= 0 || c->ikerk_active) return -1;
    int n = -1;
    for (int i = 0; i < WEIRDIKE_IKE_SA_SLOTS; i++) if (i != c->sa_active && !c->sa[i].in_use) { n = i; break; }
    if (n < 0) return -1;
    const weirdike_crypto_t *cr = c->crypto;
    ike_sa_state_t *nsa = &c->sa[n];
    memset(nsa, 0, sizeof(*nsa));
    int nz = 0;
    for (int tries = 0; tries < 8 && !nz; tries++) {
        if (cr->random(cr->ctx, nsa->spi_i, 8) != 0) return -1;
        for (int i = 0; i < 8; i++) if (nsa->spi_i[i]) nz = 1;
    }
    if (!nz) return -1;
    if (cr->random(cr->ctx, c->ikerk_ni, 32) != 0) return -1;
    c->ikerk_dh_group = c->ike_policy.dh[0];
    uint8_t *ke_pub = c->ws->crypto.ke_pub; size_t kl = sizeof(c->ws->crypto.ke_pub);
    if (cr->ke_keygen(cr->ctx, c->ikerk_dh_group, &c->ikerk_dh_priv, ke_pub, &kl) != 0 || kl != weirdike_dh_pub_len(c->ikerk_dh_group)) { c->ikerk_dh_priv = NULL; return -1; }
    uint8_t *inner = c->ws->tx_inner; uint8_t fp = 0;
    int len = ike_build_ike_rekey_request(inner, sizeof(c->ws->tx_inner), nsa->spi_i, &c->ike_policy,
                                          c->ikerk_ni, 32, ke_pub, kl, &fp);
    if (len < 0) { c->ikerk_active = 1; c->ikerk_slot = n; ike_rekey_abort(c, "weirdike: IKE-SA rekey request build failed"); return -1; }
    uint32_t mid = SA(c)->tx_mid++;
    if (sk_send(c, IKE_EXCHANGE_CREATE_CHILD_SA, 0, mid, fp, inner, (size_t)len, SAWS(c)->req, &SAWS(c)->req_len) != 0) {
        c->ikerk_active = 1; c->ikerk_slot = n; ike_rekey_abort(c, "weirdike: IKE-SA rekey request send failed"); return -1;
    }
    c->ikerk_active = 1; c->ikerk_slot = n;
    SA(c)->req_active = 1; SA(c)->req_is_delete = 0; SA(c)->req_kind = REQ_IKE_REKEY;
    SA(c)->req_mid = mid; SA(c)->req_retransmit = 0; SA(c)->req_deadline_ms = now_ms + WEIRDIKE_RTO_BASE_MS;
    w_log(c, WEIRDIKE_LOG_INFO, "weirdike: CREATE_CHILD_SA IKE-SA rekey sent");
    return 0;
}

int weirdike_rekey_ike(weirdike_ctx *c, uint32_t now_ms) {
    if (!c) return -1;
    c->cur_ms = now_ms;
    return start_ike_rekey(c, now_ms);
}

/* Response to OUR IKE-SA rekey request. */
static void handle_ike_rekey_response(weirdike_ctx *c, uint8_t fp, const uint8_t *inner, size_t ilen) {
    ike_create_child_msg_t m;
    if (ike_parse_create_child_inner(fp, ilen ? inner : NULL, ilen, &m) != 0) { ike_rekey_abort(c, "weirdike: malformed IKE-SA rekey response"); return; }
    if (m.error_notify) {
        c->diag_last_notify = m.error_notify;
        ike_rekey_abort(c, m.error_notify == IKE_NOTIFY_TEMPORARY_FAILURE
                           ? "weirdike: peer answered the IKE-SA rekey with TEMPORARY_FAILURE -> old IKE SA stays, retry later"
                           : "weirdike: peer refused the IKE-SA rekey (notify) -> old IKE SA stays");
        return;
    }
    if (!m.sa_present || !m.sa_is_ike || m.n_encr != 1 || m.n_prf != 1 || m.n_integ != 1 || m.n_dh != 1 ||
        !m.have_nonce || !m.have_ke) { ike_rekey_abort(c, "weirdike: IKE-SA rekey response is not a single IKE selection with nonce + KE"); return; }
    weirdike_ike_suite_t sel; memset(&sel, 0, sizeof(sel));
    sel.encr = (weirdike_encr_id_t)m.encr[0].id; sel.encr_key_bits = m.encr[0].key_bits;
    sel.prf = (weirdike_prf_id_t)m.prf[0]; sel.integ = (weirdike_integ_id_t)m.integ[0]; sel.dh = (weirdike_dh_id_t)m.dh[0];
    if (!ike_policy_ike_allows(&c->ike_policy, &sel) || !weirdike_ike_suite_supported(&sel)) {
        ike_rekey_abort(c, "weirdike: IKE-SA rekey selection outside the configured policy"); return; }
    if (sel.dh != c->ikerk_dh_group || m.ke_group != c->ikerk_dh_group || m.ke_len != weirdike_dh_pub_len(c->ikerk_dh_group)) {
        ike_rekey_abort(c, "weirdike: IKE-SA rekey response KE does not match the group we sent"); return; }
    int nz = 0; for (int i = 0; i < 8; i++) if (m.ike_spi[i]) nz = 1;
    if (!nz) { ike_rekey_abort(c, "weirdike: IKE-SA rekey response carries a zero SPI"); return; }
    uint8_t *gir = c->ws->crypto.gir; size_t gl = sizeof(c->ws->crypto.gir);
    if (c->crypto->ke_shared(c->crypto->ctx, c->ikerk_dh_group, c->ikerk_dh_priv, m.ke, m.ke_len, gir, &gl) != 0 || gl != weirdike_dh_shared_len(c->ikerk_dh_group)) {
        w_zero(c->platform, gir, sizeof(c->ws->crypto.gir)); ike_rekey_abort(c, "weirdike: IKE-SA rekey shared secret failed"); return; }
    c->crypto->ke_free(c->crypto->ctx, c->ikerk_dh_group, c->ikerk_dh_priv); c->ikerk_dh_priv = NULL;
    int n = c->ikerk_slot;
    uint8_t new_spi_i[8]; memcpy(new_spi_i, c->sa[n].spi_i, 8);   /* ours: we initiated the exchange */
    int rc = ike_rekey_keys(c, n, &sel, c->ikerk_ni, 32, m.nonce, m.nonce_len, gir, gl, new_spi_i, m.ike_spi);
    w_zero(c->platform, gir, sizeof(c->ws->crypto.gir));
    w_zero(c->platform, c->ikerk_ni, sizeof(c->ikerk_ni));
    if (rc != 0) { ike_rekey_abort(c, "weirdike: IKE-SA rekey key derivation failed"); return; }
    /* The old SA's request window is free again; the new SA takes over; we delete the old one. */
    SA(c)->req_active = 0; SA(c)->req_kind = REQ_DPD;
    c->ikerk_active = 0;
    activate_new_ike_sa(c, n, 1);
    w_log(c, WEIRDIKE_LOG_INFO, "weirdike: IKE SA rekeyed (we initiated); deleting the old IKE SA");
    if (info_start_delete_old(c, c->cur_ms) != 0) old_slot_release(c, "weirdike: DELETE of the old IKE SA could not be sent -> dropped locally");
    if (c->closing && c->disconnect_pending) {   /* a close queued behind the rekey: finish it on the new SA */
        old_slot_release(c, NULL);
        if (info_start_delete(c, c->cur_ms) != 0) info_close(c, "weirdike: DELETE send failed -> closed locally");
    }
}

/* PEER-initiated IKE-SA rekey request. Builds the response chain into out (>= 0 = length) and, on
 * success, prepares the new SA in *new_slot (activated by the caller once the response went out). */
static int peer_ike_rekey(weirdike_ctx *c, const ike_create_child_msg_t *m, uint8_t *out, size_t cap,
                          uint8_t *rfp, int *new_slot) {
    uint16_t err = 0; uint8_t errdata[2] = { 0, 0 }; size_t errlen = 0;
    weirdike_ike_suite_t sel; memset(&sel, 0, sizeof(sel));
    *new_slot = -1;
    if (c->closing || c->sa_old >= 0 || c->ikerk_active || (SA(c)->req_active && SA(c)->req_kind != REQ_DPD)) {
        err = IKE_NOTIFY_TEMPORARY_FAILURE;   /* closing, transition in progress, or a collision with our own rekey */
    } else if (!m->have_nonce || !m->have_ke) {
        err = IKE_NOTIFY_INVALID_SYNTAX;
    } else if (!select_ike_offer(m, &c->ike_policy, &sel)) {
        err = 14;   /* NO_PROPOSAL_CHOSEN */
    } else if (m->ke_group != sel.dh) {
        err = IKE_NOTIFY_INVALID_KE_PAYLOAD; errdata[0] = (uint8_t)(sel.dh >> 8); errdata[1] = (uint8_t)sel.dh; errlen = 2;
    } else if (m->ke_len != weirdike_dh_pub_len(sel.dh)) {
        err = IKE_NOTIFY_INVALID_SYNTAX;   /* right group, wrong KE length */
    }
    int n = -1;
    if (!err) {
        for (int i = 0; i < WEIRDIKE_IKE_SA_SLOTS; i++) if (i != c->sa_active && !c->sa[i].in_use) { n = i; break; }
        if (n < 0) err = IKE_NOTIFY_TEMPORARY_FAILURE;
    }
    if (!err) {
        int nz = 0; for (int i = 0; i < 8; i++) if (m->ike_spi[i]) nz = 1;
        if (!nz) err = IKE_NOTIFY_INVALID_SYNTAX;
    }
    if (!err) {
        const weirdike_crypto_t *cr = c->crypto;
        ike_sa_state_t *nsa = &c->sa[n]; memset(nsa, 0, sizeof(*nsa));
        uint8_t our_spi[8], nr[32]; void *priv = NULL; int ok = 1, nz = 0;
        for (int tries = 0; tries < 8 && !nz && ok; tries++) {
            if (cr->random(cr->ctx, our_spi, 8) != 0) ok = 0;
            for (int i = 0; i < 8; i++) if (our_spi[i]) nz = 1;
        }
        if (ok && !nz) ok = 0;
        if (ok && cr->random(cr->ctx, nr, 32) != 0) ok = 0;
        uint8_t *ke_pub = c->ws->crypto.ke_pub; size_t kl = sizeof(c->ws->crypto.ke_pub);
        uint8_t *gir = c->ws->crypto.gir; size_t gl = sizeof(c->ws->crypto.gir);
        if (ok && (cr->ke_keygen(cr->ctx, sel.dh, &priv, ke_pub, &kl) != 0 || kl != weirdike_dh_pub_len(sel.dh))) { priv = NULL; ok = 0; }
        if (ok && (cr->ke_shared(cr->ctx, sel.dh, priv, m->ke, m->ke_len, gir, &gl) != 0 || gl != weirdike_dh_shared_len(sel.dh))) ok = 0;
        if (priv && cr->ke_free) cr->ke_free(cr->ctx, sel.dh, priv);
        /* the peer is the initiator of the NEW SA: its SPI/nonce first */
        if (ok && ike_rekey_keys(c, n, &sel, m->nonce, m->nonce_len, nr, 32, gir, gl, m->ike_spi, our_spi) != 0) ok = 0;
        w_zero(c->platform, gir, sizeof(c->ws->crypto.gir));
        int len = -1;
        if (ok) len = ike_build_ike_rekey_response(out, cap, our_spi, &sel, nr, 32, ke_pub, kl, rfp);
        w_zero(c->platform, nr, sizeof(nr));
        if (ok && len >= 0) { *new_slot = n; return len; }
        w_zero(c->platform, nsa, sizeof(*nsa));
        err = 14;   /* NO_PROPOSAL_CHOSEN: we could not complete the exchange */
    }
    w_log(c, WEIRDIKE_LOG_INFO, err == IKE_NOTIFY_TEMPORARY_FAILURE
                                 ? "weirdike: peer IKE-SA rekey refused with TEMPORARY_FAILURE (transition/collision in progress)"
                                 : "weirdike: peer IKE-SA rekey refused (proposal/KE not acceptable)");
    return ike_build_notify_only(out, cap, 0, NULL, 0, err, errlen ? errdata : NULL, errlen, rfp);
}

/* A datagram for the OLD IKE SA during a rekey transition: only what RFC 7296 2.8 still allows there
 * -- the DELETE of the old SA (ours awaiting its ack, or the peer's), a leftover DPD/response, and
 * retransmits of the rekey exchange itself (dedup cache). New work on the old SA is refused with
 * TEMPORARY_FAILURE. Everything uses the old slot's keys, role and Message-ID space. */
static void handle_old_sa_datagram(weirdike_ctx *c, const uint8_t *data, size_t len) {
    int s = c->sa_old; if (s < 0) return;
    ike_sa_state_t *sa = &c->sa[s];
    uint8_t exch = data[18];
    if (exch != IKE_EXCHANGE_INFORMATIONAL && exch != IKE_EXCHANGE_CREATE_CHILD_SA) return;
    uint8_t fp = 0; uint32_t mid = 0; int is_resp = 0;
    uint8_t *inner = c->ws->rx_plain; size_t ilen = 0;
    if (sk_open_slot(c, s, exch, data, len, &fp, &mid, &is_resp, inner, sizeof(c->ws->rx_plain), &ilen) != 0) return;
    if (is_resp) {
        if (sa->req_active && mid == sa->req_mid) {
            int kind = sa->req_kind;
            sa->req_active = 0; sa->req_kind = REQ_DPD;
            if (kind == REQ_DELETE_IKE_OLD) old_slot_release(c, "weirdike: old IKE SA DELETE acknowledged (rekey complete)");
        }
        return;
    }
    if (sa->rx_have && mid == sa->rx_mid) { (void)ike_send(c, c->ws->sa[s].resp, c->ws->sa[s].resp_len); return; }
    if (mid != sa->rx_next_mid) return;
    uint8_t rinner[32]; size_t rlen = 0; uint8_t rfp = IKE_PL_NONE; int release = 0;
    if (exch == IKE_EXCHANGE_CREATE_CHILD_SA) {
        int n = ike_build_notify_only(rinner, sizeof(rinner), 0, NULL, 0, IKE_NOTIFY_TEMPORARY_FAILURE, NULL, 0, &rfp);
        if (n < 0) return;
        rlen = (size_t)n;
    } else {
        ike_info_content_t ct;
        if (ike_info_parse_inner(fp, ilen ? inner : NULL, ilen, &ct) != 0) return;
        if (ct.delete_ike) release = 1;   /* the peer (rekey initiator) deletes the old IKE SA */
        rfp = IKE_PL_NONE; rlen = 0;      /* empty ack: DPD on the old SA, or the IKE DELETE */
    }
    if (sk_send_slot(c, s, exch, 1, mid, rfp, rlen ? rinner : NULL, rlen, c->ws->sa[s].resp, &c->ws->sa[s].resp_len) == 0) {
        sa->rx_have = 1; sa->rx_mid = mid; sa->rx_next_mid++;
    }
    if (release) old_slot_release(c, "weirdike: peer deleted the old IKE SA (rekey complete)");
}

static void handle_create_child(weirdike_ctx *c, const uint8_t *data, size_t len) {
    uint8_t fp = 0; uint32_t mid = 0; int is_resp = 0;
    uint8_t *inner = c->ws->rx_plain; size_t ilen = 0;   /* decrypted inner payloads (this call only) */
    if (sk_open(c, IKE_EXCHANGE_CREATE_CHILD_SA, data, len, &fp, &mid, &is_resp, inner, sizeof(c->ws->rx_plain), &ilen) != 0) return;
    SA(c)->last_rx_ms = c->cur_ms; SA(c)->last_rx_armed = 1;
    if (is_resp) {
        if (SA(c)->req_active && SA(c)->req_kind == REQ_CHILD_REKEY && mid == SA(c)->req_mid)
            handle_create_child_response(c, fp, inner, ilen);
        else if (SA(c)->req_active && SA(c)->req_kind == REQ_IKE_REKEY && mid == SA(c)->req_mid)
            handle_ike_rekey_response(c, fp, inner, ilen);
        return;
    }
    if (SA(c)->rx_have && mid == SA(c)->rx_mid) { (void)ike_send(c, SAWS(c)->resp, SAWS(c)->resp_len); return; }
    if (mid != SA(c)->rx_next_mid) return;
    handle_create_child_request(c, mid, fp, inner, ilen);
}

void weirdike_input_datagram(weirdike_ctx *c, const uint8_t *data, size_t len,
                             const weirdike_endpoint_t *from) {
    if (!c || !data) return;
    /* On UDP/4500 strip the non-ESP marker for IKE; ignore keepalives/ESP (ESP is the data plane's,
     * handled by the host via esp_session, not the IKE control plane). */
    if (c->use_natt) {
        size_t off = 0;
        if (natt_classify(data, len, &off) != NATT_DATAGRAM_IKE) return;
        data += off; len -= off;
    }
    if (c->state == WEIRDIKE_STATE_SA_INIT_SENT) { handle_sa_init_response(c, data, len, from); return; }
    if (c->state == WEIRDIKE_STATE_AUTH_SENT)    { handle_auth_response(c, data, len); return; }
    /* AP4/AP5: once authenticated, the control plane is INFORMATIONAL (DPD/DELETE) and
     * CREATE_CHILD_SA (rekey). */
    if (c->state == WEIRDIKE_STATE_ESTABLISHED || c->state == WEIRDIKE_STATE_CHILD_ESTABLISHED) {
        if (len < IKE_HDR_LEN) return;
        /* IKE-SA rekey transition: a datagram addressed to the OLD SA (its SPIs) is handled with the
         * old SA's keys and Message-ID space -- never confused with the active one. */
        if (c->sa_old >= 0 && memcmp(data, c->sa[c->sa_old].spi_i, 8) == 0 && memcmp(data + 8, c->sa[c->sa_old].spi_r, 8) == 0) {
            handle_old_sa_datagram(c, data, len);
            return;
        }
        if (data[18] == IKE_EXCHANGE_INFORMATIONAL)
            handle_informational(c, data, len);
        else if (len >= IKE_HDR_LEN && data[18] == IKE_EXCHANGE_CREATE_CHILD_SA)
            handle_create_child(c, data, len);
        return;
    }
    /* any other state: no message expected right now */
}

int weirdike_poll(weirdike_ctx *c, uint32_t now_ms) {
    if (!c) return -1;
    c->cur_ms = now_ms;   /* AP4: RX handlers (called from the recv loop below) use this as "now" */
    const weirdike_transport_t *t = c->transport;
    if (t && t->recv) {
        uint8_t *buf = c->ws->rx_msg;   /* workspace, not the stack */
        weirdike_endpoint_t src;
        int n;
        while ((n = t->recv(t->ctx, &src, buf, sizeof(c->ws->rx_msg), 0)) > 0) {
            weirdike_input_datagram(c, buf, (size_t)n, &src);
        }
    }
    /* Drive the next exchange: once the IKE SA keys are ready, send IKE_AUTH. */
    if (c->state == WEIRDIKE_STATE_SA_INIT_DONE) send_ike_auth(c, now_ms);

    /* Retransmit an in-flight request on RTO. Re-sends the EXACT stored bytes (same SPI/Ni/KE, same
     * IV/ciphertext, same Message ID; NAT-T marker re-added by ike_send) -- never re-built. */
    if ((c->state == WEIRDIKE_STATE_SA_INIT_SENT || c->state == WEIRDIKE_STATE_AUTH_SENT) &&
        (int32_t)(SA(c)->deadline_ms - now_ms) <= 0) {
        if (SA(c)->retransmit_count >= WEIRDIKE_MAX_RETRANSMITS) {
            fail(c, "weirdike: IKE retransmission timeout (peer unreachable / path down)");
            return 0;
        }
        SA(c)->retransmit_count++;
        if (c->state == WEIRDIKE_STATE_SA_INIT_SENT)
            (void)ike_send(c, c->ws->sa_init_req, c->ws->sa_init_req_len);
        else
            (void)ike_send(c, SAWS(c)->req, SAWS(c)->req_len);
        SA(c)->deadline_ms = now_ms + (WEIRDIKE_RTO_BASE_MS << SA(c)->retransmit_count);
        w_log(c, WEIRDIKE_LOG_INFO, "weirdike: IKE request retransmit (RTO)");
    }

    /* AP4: INFORMATIONAL request retransmit (our DPD probe or graceful DELETE). Same exact bytes,
     * same Message ID (never re-sealed). Giving up -> if closing, force CLOSED (we tried); otherwise
     * it was a DPD probe -> peer is dead -> FAILED. */
    if (SA(c)->req_active && (int32_t)(SA(c)->req_deadline_ms - now_ms) <= 0) {
        if ((uint32_t)SA(c)->req_retransmit >= ((SA(c)->req_kind == REQ_DPD && !SA(c)->req_is_delete) ? c->dpd_retries : (uint32_t)WEIRDIKE_MAX_RETRANSMITS)) {
            if (SA(c)->req_is_delete) {
                info_close(c, "weirdike: DELETE unacknowledged -> closed locally");
            } else if (SA(c)->req_kind == REQ_DELETE_CHILD) {
                /* AP5: old-child DELETE unanswered -> drop it locally, keep going on the new SA */
                SA(c)->req_active = 0; SA(c)->req_kind = REQ_DPD;
                drop_child_prev(c);
                w_log(c, WEIRDIKE_LOG_INFO, "weirdike: previous Child SA DELETE unanswered -> dropped locally");
                if (c->closing && c->disconnect_pending)
                    if (info_start_delete(c, now_ms) != 0) info_close(c, "weirdike: DELETE send failed -> closed locally");
            } else if (SA(c)->req_kind == REQ_CHILD_REKEY) {
                /* AP5: a rekey request nobody answers = the peer is gone (same as a DPD timeout) */
                rekey_abort(c, NULL);
                fail(c, "weirdike: CREATE_CHILD_SA rekey unanswered (peer unreachable)");
            } else if (SA(c)->req_kind == REQ_IKE_REKEY) {
                ike_rekey_abort(c, NULL);
                fail(c, "weirdike: IKE-SA rekey unanswered (peer unreachable)");
            } else if (c->closing && c->disconnect_pending) {
                SA(c)->req_active = 0;
                SA(c)->req_is_delete = 0;
                if (info_start_delete(c, now_ms) != 0) info_close(c, "weirdike: DELETE send failed -> closed locally");
            } else {
                SA(c)->req_active = 0;
                fail(c, "weirdike: DPD liveness timeout (peer unreachable)");
            }
            return 0;
        }
        SA(c)->req_retransmit++;
        (void)ike_send(c, SAWS(c)->req, SAWS(c)->req_len);
        SA(c)->req_deadline_ms = now_ms + (WEIRDIKE_RTO_BASE_MS << SA(c)->req_retransmit);
        w_log(c, WEIRDIKE_LOG_INFO, "weirdike: INFORMATIONAL request retransmit (RTO)");
    }

    /* IKE-SA rekey transition: the OLD SA's own DELETE (our retransmits, exact bytes, its Message-ID
     * space) or, after a peer-initiated rekey, the safety drop if the peer never deletes it. */
    if (c->sa_old >= 0) {
        ike_sa_state_t *osa = &c->sa[c->sa_old];
        if (osa->req_active && (int32_t)(osa->req_deadline_ms - now_ms) <= 0) {
            if (osa->req_retransmit >= WEIRDIKE_MAX_RETRANSMITS) {
                old_slot_release(c, "weirdike: old IKE SA DELETE unanswered -> dropped locally");
            } else {
                osa->req_retransmit++;
                (void)ike_send(c, c->ws->sa[c->sa_old].req, c->ws->sa[c->sa_old].req_len);
                osa->req_deadline_ms = now_ms + (WEIRDIKE_RTO_BASE_MS << osa->req_retransmit);
            }
        } else if (!osa->req_active && !osa->old_delete_ours && (int32_t)(now_ms - osa->old_deadline_ms) >= 0) {
            old_slot_release(c, "weirdike: peer never deleted the old IKE SA -> dropped locally");
        }
    }

    /* AP4: DPD probe. Arm the liveness clock at establishment, then probe only after real inbound
     * silence -- not while another IKE request is already in flight, and never while closing. */
    if ((c->state == WEIRDIKE_STATE_ESTABLISHED || c->state == WEIRDIKE_STATE_CHILD_ESTABLISHED) &&
        !c->closing) {
        if (!SA(c)->last_rx_armed) { SA(c)->last_rx_ms = now_ms; SA(c)->last_rx_armed = 1; }
        /* self-initiated IKE-SA rekey at the configured soft lifetime (the exchange proves liveness) */
        if (!SA(c)->req_active && c->sa_old < 0 && c->ike_lifetime_ms &&
            (int32_t)(now_ms - c->ike_born_ms) >= (int32_t)c->ike_lifetime_ms) {
            (void)start_ike_rekey(c, now_ms);
        }
        /* AP5: soft lifetime of the CURRENT Child SA reached -> rekey (before the DPD probe check;
         * a rekey exchange proves liveness too). Also finish a pending old-child DELETE. */
        if (HAVE_PREV(c)) {
            if (PREV(c)->delete_ours) { if (!SA(c)->req_active) (void)info_start_delete_child_prev(c, now_ms); }
            else if ((int32_t)(now_ms - PREV(c)->deadline_ms) >= 0) {
                drop_child_prev(c);
                w_log(c, WEIRDIKE_LOG_INFO, "weirdike: peer never deleted its old Child SA -> dropped locally");
            }
        }
        if (!SA(c)->req_active && c->state == WEIRDIKE_STATE_CHILD_ESTABLISHED && HAVE_CHILD(c) && CUR(c)->born_armed &&
            ((int32_t)(now_ms - CUR(c)->born_ms) >= (int32_t)c->child_lifetime_ms ||
             (c->child_lifetime_bytes && c->child_bytes >= c->child_lifetime_bytes))) {
            (void)start_child_rekey(c, now_ms);
        }
        if (!c->dpd_disable && !SA(c)->req_active && (int32_t)(now_ms - SA(c)->last_rx_ms) >= (int32_t)c->dpd_idle_ms) {
            uint8_t fp = 0; (void)ike_info_build_empty(&fp);
            uint32_t mid = SA(c)->tx_mid++;
            if (info_send(c, 0, mid, fp, NULL, 0, SAWS(c)->req, &SAWS(c)->req_len) == 0) {
                SA(c)->req_active = 1; SA(c)->req_is_delete = 0; SA(c)->req_mid = mid;
                SA(c)->req_retransmit = 0; SA(c)->req_deadline_ms = now_ms + WEIRDIKE_RTO_BASE_MS;
                SA(c)->req_kind = REQ_DPD; w_log(c, WEIRDIKE_LOG_INFO, "weirdike: DPD probe (INFORMATIONAL, empty)");
            }
        }
    }

    /* NAT-T keepalive: once the SA is up behind NAT, send a single 0xFF on UDP/4500 periodically so
     * the NAT mapping (shared by IKE and ESP) stays open. Incoming 0xFF is ignored (see demux). */
    if (c->use_natt &&
        (c->state == WEIRDIKE_STATE_ESTABLISHED || c->state == WEIRDIKE_STATE_CHILD_ESTABLISHED)) {
        if (!c->keepalive_armed) {
            c->keepalive_armed = 1;
            c->keepalive_deadline_ms = now_ms + c->keepalive_ms;
        } else if ((int32_t)(c->keepalive_deadline_ms - now_ms) <= 0) {
            uint8_t ka;
            if (natt_make_keepalive(&ka, 1) == 1)
                (void)c->transport->send(c->transport->ctx, &c->peer, &ka, 1);
            c->keepalive_deadline_ms = now_ms + c->keepalive_ms;
        }
    }
    return 0;
}

uint32_t weirdike_next_deadline_ms(weirdike_ctx *c, uint32_t now_ms) {
    if (!c) return 0;
    /* Return the nearest armed timer, wrap-safe. Zero means due now (or no timer). Keep every timer
     * horizon below INT32_MAX ms so signed subtraction remains valid across millis() wrap. */
    uint32_t best = 0;
    int have = 0;
#define CONSIDER_DEADLINE(due_) do { \
        int32_t delta_ = (int32_t)((uint32_t)(due_) - now_ms); \
        uint32_t wait_ = delta_ > 0 ? (uint32_t)delta_ : 0u; \
        if (!have || wait_ < best) { best = wait_; have = 1; } \
    } while (0)
    if (c->state == WEIRDIKE_STATE_SA_INIT_SENT || c->state == WEIRDIKE_STATE_AUTH_SENT)
        CONSIDER_DEADLINE(SA(c)->deadline_ms);
    if (SA(c)->req_active)
        CONSIDER_DEADLINE(SA(c)->req_deadline_ms);
    if (c->sa_old >= 0) {   /* IKE-SA rekey transition: the old SA's DELETE retransmit / safety drop */
        const ike_sa_state_t *osa = &c->sa[c->sa_old];
        if (osa->req_active) CONSIDER_DEADLINE(osa->req_deadline_ms);
        else if (!osa->old_delete_ours) CONSIDER_DEADLINE(osa->old_deadline_ms);
    }
    if ((c->state == WEIRDIKE_STATE_ESTABLISHED || c->state == WEIRDIKE_STATE_CHILD_ESTABLISHED) &&
        !c->closing && !SA(c)->req_active && c->sa_old < 0 && c->ike_lifetime_ms)
        CONSIDER_DEADLINE(c->ike_born_ms + c->ike_lifetime_ms);   /* self-initiated IKE-SA rekey */
    if (c->state == WEIRDIKE_STATE_CHILD_ESTABLISHED && HAVE_CHILD(c) && CUR(c)->born_armed && !c->closing && !SA(c)->req_active)
        CONSIDER_DEADLINE(CUR(c)->born_ms + c->child_lifetime_ms);   /* AP5 soft lifetime */
    if ((c->state == WEIRDIKE_STATE_ESTABLISHED || c->state == WEIRDIKE_STATE_CHILD_ESTABLISHED) &&
        !c->closing && !SA(c)->req_active && SA(c)->last_rx_armed)
        { if (!c->dpd_disable) CONSIDER_DEADLINE(SA(c)->last_rx_ms + c->dpd_idle_ms); }
    if (c->use_natt && c->keepalive_armed &&
        (c->state == WEIRDIKE_STATE_ESTABLISHED || c->state == WEIRDIKE_STATE_CHILD_ESTABLISHED))
        CONSIDER_DEADLINE(c->keepalive_deadline_ms);
#undef CONSIDER_DEADLINE
    return have ? best : 0;
}

weirdike_state_t weirdike_state(const weirdike_ctx *c) {
    return c ? c->state : WEIRDIKE_STATE_CLOSED;
}

const char *weirdike_state_str(weirdike_state_t s) {
    switch (s) {
        case WEIRDIKE_STATE_IDLE:              return "IDLE";
        case WEIRDIKE_STATE_SA_INIT_SENT:      return "SA_INIT_SENT";
        case WEIRDIKE_STATE_SA_INIT_DONE:      return "SA_INIT_DONE";
        case WEIRDIKE_STATE_AUTH_SENT:         return "AUTH_SENT";
        case WEIRDIKE_STATE_ESTABLISHED:       return "IKE_SA_ESTABLISHED";
        case WEIRDIKE_STATE_CHILD_ESTABLISHED: return "CHILD_SA_ESTABLISHED";
        case WEIRDIKE_STATE_FAILED:            return "FAILED";
        case WEIRDIKE_STATE_CLOSED:            return "CLOSED";
        default:                               return "?";
    }
}

int weirdike_get_child_sa(const weirdike_ctx *c, weirdike_child_sa_t *out) {
    if (!c || !out) return -1;
    if (c->state != WEIRDIKE_STATE_CHILD_ESTABLISHED || !HAVE_CHILD(c)) return -1;
    *out = CUR(c)->sa;
    return 0;
}

int weirdike_get_cp(const struct weirdike_ctx *c, weirdike_cp_t *out) {
    if (!c || !out || !c->have_cp) return -1;
    *out = c->cp;
    return 0;
}

int weirdike_child_negotiated(const weirdike_ctx *c, uint8_t child_spi_r[4],
                              weirdike_ts_t *ts_i, weirdike_ts_t *ts_r) {
    if (!c) return -1;
    if (c->state != WEIRDIKE_STATE_ESTABLISHED && c->state != WEIRDIKE_STATE_CHILD_ESTABLISHED) return -1;
    if (!c->have_child_sa) return 0;
    if (child_spi_r) memcpy(child_spi_r, c->child_spi_r, 4);
    if (ts_i) *ts_i = c->child_ts_i;
    if (ts_r) *ts_r = c->child_ts_r;
    return 1;
}

int weirdike_get_diag(const weirdike_ctx *c, weirdike_diag_t *out) {
    if (!c || !out) return -1;
    memset(out, 0, sizeof(*out));
    out->have_ike_suite    = c->diag_have_ike_suite;   /* AP3: negotiated-suite metadata; NOT tied to the (wiped) keys */
    out->ike_encr          = SA(c)->suite.encr;
    out->ike_encr_key_bits = SA(c)->suite.encr_key_bits;
    out->ike_prf           = SA(c)->suite.prf;
    out->ike_integ         = SA(c)->suite.integ;
    out->ike_dh            = SA(c)->suite.dh;
    out->nat_t_peer        = c->nat_t_peer;
    out->nat_detected      = c->nat_detected;
    out->use_natt          = c->use_natt;
    out->auth_done         = c->diag_auth_done;
    out->ike_auth_ok       = c->diag_ike_auth_ok;
    out->child_sa_ok       = c->diag_child_sa_ok;
    out->child_notify      = c->diag_child_notify;
    out->ike_auth_rejected = c->diag_ike_auth_rejected;
    out->auth_local_fail   = c->diag_auth_local_fail;
    out->child_encr          = c->diag_child_encr;
    out->child_encr_key_bits = c->diag_child_bits;
    out->child_integ         = c->diag_child_integ;
    out->idr_type          = c->diag_idr_type;
    out->idr_len           = c->diag_idr_len;
    if (c->diag_idr_len) memcpy(out->idr, c->diag_idr, c->diag_idr_len);
    out->reached_state     = (int)c->diag_reached_state;   /* AP3 */
    out->last_notify       = c->diag_last_notify;          /* AP3 */
    out->ike_generation    = c->ike_gen;
    out->peer_pfs_rejected = c->diag_peer_pfs_rejected;
    out->child_generation  = c->child_gen;
    out->child_rekey_dh    = c->diag_child_rekey_dh;
    out->child_rekey_ke    = c->diag_child_rekey_ke;
    out->child_bytes       = c->child_bytes;
    return 0;
}

uint32_t weirdike_ike_generation(const weirdike_ctx *c) { return c ? c->ike_gen : 0; }
