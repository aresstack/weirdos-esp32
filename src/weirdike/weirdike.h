/*
 * WeirdIKE -- weirdike.h : public API of the MCU-friendly IKEv2/IPsec core.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Independent RFC 7296 implementation (CycloneIPSEC studied as reference, not copied). See PROVENANCE.md.
 *
 * Design:
 *   - Control plane (IKE) vs data plane (ESP) strictly separated: IKE hands out a
 *     weirdike_child_sa_t; a separate ESP engine consumes it.
 *   - Poll-driven, OS-agnostic: no tasks/events, time supplied explicitly (now_ms).
 *   - Crypto + UDP transport injected as adapters; memory via platform hooks (or caller-owned).
 *   - Config strings/PSK are BORROWED only during weirdike_new()/weirdike_init(); the core
 *     deep-copies them and zeroizes secrets on free.
 */
#ifndef WEIRDIKE_H
#define WEIRDIKE_H

#include <stdint.h>
#include <stddef.h>
#include "ike_crypto.h"
#include "ike_transport.h"
#include "ike_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WEIRDIKE_VERSION "0.2.0-dev"

/* Bounded copies of config strings/PSK (fixed-size context -> caller-owned placement works). */
#define WEIRDIKE_MAX_HOST 256
#define WEIRDIKE_MAX_ID   256
#define WEIRDIKE_MAX_PSK   64
/* Retained SA_INIT transcript (needed verbatim for IKE_AUTH signed octets). UDP, unfragmented. */
#define WEIRDIKE_MAX_IKE_MSG 1500

/* --- Memory model (see ike_platform.h) -----------------------------------------------------
 * The core keeps its long-lived protocol state in EXPLICIT state objects inside weirdike_ctx and
 * every large buffer in a separate WORKSPACE block. Nothing message-sized ever lives on the C
 * stack, on Linux exactly as on an MCU; only the placement of the two blocks is the host's
 * decision. "Explicit state" does NOT mean "persistent state": Message IDs, replay windows and
 * keys are inspectable/testable but MUST NOT be restored across a restart.
 *
 * Slots (compile-time capacity, code is written against the slot abstraction, not the count):
 *   WEIRDIKE_IKE_SA_SLOTS  IKE-SA state objects (SPIs, SK_*, Message-ID spaces, request window,
 *                          response cache). Two allow an old and a new IKE SA to coexist during
 *                          an IKE-SA rekey (RFC 7296 2.8/2.18). Today only slot 0 is used.
 *   WEIRDIKE_CHILD_SLOTS   Child-SA slots: the CURRENT SA plus the PREVIOUS one kept for RX
 *                          during a rekey overlap.
 * Invariant: the peer-request window size is ONE (RFC 7296 2.3, SET_WINDOW_SIZE is never sent).
 * The response to request N is cached for retransmits until request N+1 has been processed. */
#define WEIRDIKE_IKE_SA_SLOTS 2
#define WEIRDIKE_CHILD_SLOTS  2

/* IKEv2 identity, modelled on the wire form (IANA ID Types) rather than a plain string, so e.g.
 * ID_IPV4_ADDR carries 4 raw bytes and is not confused with the text "10.0.0.1". */
typedef enum {
    WEIRDIKE_ID_NONE        = 0,    /* derive from our source IP (default) */
    WEIRDIKE_ID_IPV4_ADDR   = 1,
    WEIRDIKE_ID_FQDN        = 2,
    WEIRDIKE_ID_RFC822_ADDR = 3,
    WEIRDIKE_ID_KEY_ID      = 11
} weirdike_id_type_t;

typedef struct {
    weirdike_id_type_t type;
    const uint8_t     *data;   /* borrowed; deep-copied at init */
    size_t             len;
} weirdike_id_t;

typedef enum {
    WEIRDIKE_AUTH_PSK = 0,
    WEIRDIKE_AUTH_EAP_MSCHAPV2 = 1   /* AP7/AP8: user + password; the SERVER authenticates with a
                                      * certificate that must chain to ca_pem (RFC 7296 2.16) */
    /* WEIRDIKE_AUTH_CERT (client certificate) -- later */
} weirdike_auth_t;

#define WEIRDIKE_MAX_EAP_ID   256
#define WEIRDIKE_MAX_EAP_PASS 256
#define WEIRDIKE_MAX_CA_PEM   4096   /* trust anchors (PEM) */
#define WEIRDIKE_MAX_EXTRA_PEM 4096  /* chain material, e.g. missing intermediates (PEM) */

/* An IKEv2 traffic selector (proper model, not just an address range). Milestone 1 uses IPv4,
 * protocol 0 (any) and full port range, but the type is future-proof. */
typedef struct {
    uint8_t  address_family;   /* 4 or 6 */
    uint8_t  ip_protocol;      /* 0 = any */
    uint16_t start_port;
    uint16_t end_port;
    uint8_t  start_addr[16];
    uint8_t  end_addr[16];
} weirdike_ts_t;
/* E2: several selectors per TS payload (RFC 7296 3.13). TSr may list up to WEIRDIKE_TS_MAX remote
 * networks; the responder returns its (narrowed) set. */
#define WEIRDIKE_TS_MAX 4

/* --- Proposal policy ------------------------------------------------------------------------
 * Independent ALLOW-lists per IKEv2 transform type (RFC 7296 3.3.1). An entry means "may be
 * offered AND may be accepted" -- it is NOT a priority. The core normalizes every list (ascending
 * IANA ID, duplicates removed), so the order a host happens to pass never leaks into the offer.
 *
 * Wire: ONE proposal carrying every allowed transform of each type (the canonical RFC encoding, the
 * same strongSwan uses). The responder picks one transform per type; ANY combination of allowed
 * transforms is accepted. A transform this build implements but the policy does not list is
 * REJECTED (no silent fallback, no downgrade) -- the handshake fails.
 *
 * NULL policy pointers in weirdike_config_t select the built-in default: IKE AES-CBC-256 /
 * PRF SHA-256 or SHA-512 / INTEG SHA-256-128 or SHA-512-256 / DH14; Child AES-CBC-256 /
 * HMAC-SHA2-256-128 / no ESN. The default ALLOWED algorithms are the same as before the policy
 * existed, but the negotiable set is NOT identical: the old encoder offered two coupled pairs
 * (256/256, 512/512) as separate proposals, whereas independent allow-lists also admit the
 * valid cross combinations (PRF-256 + INTEG-512-256, PRF-512 + INTEG-256-128). Every consumer
 * sizes its primitives independently, so all four are fully supported and tested.
 *
 * Hosts map their own UI names onto these IANA IDs -- the core never sees strings.
 *
 * Capacity: sized for the complete LANCOM Advanced VPN Client grid at once (13 D-H groups,
 * 8 IKE ciphers, 5 hashes, 9 Child ciphers incl. NULL, 6 Child hashes) -- lists may carry
 * algorithms this build does not implement yet; weirdike_policy_check() refuses them until they
 * are. KE note: the KE payload is generated for dh[0] (smallest allowed group after normalization).
 * Before a SECOND D-H group becomes implemented, INVALID_KE_PAYLOAD handling (re-send with the
 * group the responder demands) must exist -- until then a policy with several groups is refused by
 * the capability check, never silently misencoded. */
#define WEIRDIKE_POLICY_MAX 16         /* bounded lists (fixed-size context); >= every LANCOM group */

typedef struct { uint16_t id; uint16_t key_bits; } weirdike_encr_t;   /* key_bits 0 = no KEY_LENGTH attr */

typedef struct {
    weirdike_encr_t encr[WEIRDIKE_POLICY_MAX];  size_t n_encr;   /* transform type 1 */
    uint16_t        prf[WEIRDIKE_POLICY_MAX];   size_t n_prf;    /* transform type 2 */
    uint16_t        integ[WEIRDIKE_POLICY_MAX]; size_t n_integ;  /* transform type 3 */
    uint16_t        dh[WEIRDIKE_POLICY_MAX];    size_t n_dh;     /* transform type 4 */
} weirdike_ike_policy_t;

typedef struct {
    weirdike_encr_t encr[WEIRDIKE_POLICY_MAX];  size_t n_encr;   /* ESP transform type 1 */
    uint16_t        integ[WEIRDIKE_POLICY_MAX]; size_t n_integ;  /* ESP transform type 3 (ESN is always NO_ESN) */
} weirdike_child_policy_t;

/* Fill the built-in defaults (see above). */
void weirdike_ike_policy_default(weirdike_ike_policy_t *p);
void weirdike_child_policy_default(weirdike_child_policy_t *p);

/* Can this build honour the policy? 0 = every entry is implemented and no list is empty. Otherwise
 * a negative code naming the first offending list: -1 IKE ENCR, -2 IKE PRF, -3 IKE INTEG, -4 IKE DH,
 * -5 Child ENCR, -6 Child INTEG (an empty or oversized list yields the same code as an
 * unimplemented entry). NULL = default = always 0. weirdike_init()/weirdike_new() apply the same
 * check and return NULL on failure -- call this first for a diagnosable reason. */
int weirdike_policy_check(const weirdike_ike_policy_t *ike, const weirdike_child_policy_t *child);

typedef struct {
    const char     *server_host;   /* borrowed; deep-copied at init (<= WEIRDIKE_MAX_HOST-1 chars) */
    uint16_t        server_port;   /* usually 500 */
    weirdike_auth_t auth;          /* PSK for the first milestone */
    const uint8_t  *psk;           /* borrowed; deep-copied + zeroized on free (<= WEIRDIKE_MAX_PSK) */
    size_t          psk_len;
    weirdike_id_t   local_id;      /* our IKE identity (type NONE -> derive from source IP) */
    weirdike_id_t   remote_id;     /* expected peer identity (type NONE -> accept responder's) */
    weirdike_ts_t   local_ts;      /* TSi: the network the initiator protects (NOT just the IKE IP) */
    weirdike_ts_t   remote_ts;     /* TSr: the remote network (structured; host parses "10.0.0.0/8") */
    int             enable_nat_t;  /* negotiate/use UDP-4500 encapsulation */
    /* NOTE: no "underlay" here -- egress is the transport adapter's concern (its ctx is pre-bound). */

    /* Proposal policy (borrowed; deep-copied + normalized at init). NULL = built-in default. Appended
     * last so a memset(0) config from an older host keeps its behaviour. */
    const weirdike_ike_policy_t   *ike_policy;
    const weirdike_child_policy_t *child_policy;

    /* AP5 rekey (appended; 0 = built-in default). child_lifetime_s: we initiate a CREATE_CHILD_SA
     * rekey of the Child SA after this many seconds (default 3300 = 55 min; a peer may rekey
     * earlier). pfs_group: D-H group for Child rekeys (PFS, RFC 7296 2.8); 0 = no PFS. Must be a
     * group this build implements (MODP2048 = 14) -- weirdike_init() refuses others. */
    uint32_t child_lifetime_s;
    uint16_t pfs_group;

    /* AP7/AP8 EAP-MSCHAPv2 (auth == WEIRDIKE_AUTH_EAP_MSCHAPV2; all borrowed, deep-copied, secrets
     * zeroized on free). eap_identity is the EAP identity AND the IDi (ID_RFC822_ADDR if it holds an
     * '@', else ID_KEY_ID) unless local_id is set explicitly. ca_pem = one or more PEM CA certs the
     * server certificate MUST chain to (mandatory: no EAP without server authentication). The server
     * identity is checked against remote_id when configured (FQDN/RFC822 text vs SAN/CN), else the
     * certificate only has to chain to the CA. request_cp = ask for INTERNAL_IP4_ADDRESS/DNS/SUBNET
     * (AP6) in the first IKE_AUTH; the assigned values are readable via weirdike_get_cp(). */
    const uint8_t *eap_identity; size_t eap_identity_len;
    const uint8_t *eap_password; size_t eap_password_len;
    const char    *ca_pem;       size_t ca_pem_len;
    int            request_cp;

    /* TRUST MODEL for the EAP server certificate (appended; 0 = default = today's behaviour).
     * trust_mode (weirdike_trust_mode_t):
     *   ANCHOR_PEM           ca_pem = the explicitly trusted anchor(s). An anchor need not be
     *                        self-signed (an intermediate listed here ends the chain); a self-signed
     *                        server certificate or the exact server certificate may be an anchor too.
     *   HOST_STORE           the host's public-CA store decides (crypto->x509_host_store must exist).
     *   HOST_STORE_PLUS_PEM  host store, plus extra_pem (chain material) and/or ca_pem (extra anchors).
     *   NONE                 no chain and no certificate-identity check. The IKE_AUTH signature is
     *                        STILL verified with the presented certificate's key, and the IKE IDr
     *                        payload is still matched against remote_id. Not recommended.
     * extra_pem = certificates that only COMPLETE a chain (intermediates); they never end one. */
    int            trust_mode;
    const char    *extra_pem;    size_t extra_pem_len;

    /* IKE-SA rekey (RFC 7296 2.18; appended, 0 = default). ike_lifetime_s: WE initiate an IKE-SA rekey
     * (CREATE_CHILD_SA with a fresh D-H) after this many seconds; 0 = never self-initiated. A PEER-
     * initiated IKE-SA rekey is always answered. The host may force one with weirdike_rekey_ike(). */
    uint32_t ike_lifetime_s;

    /* D: liveness / NAT-T knobs (appended; 0 = built-in default). dpd_disable = 1 -> no self-initiated
     * DPD probes (peer probes are still answered; NOT recommended). dpd_interval_s (default 30 s of
     * inbound silence before a probe), dpd_retries (default 5 retransmits of a probe before the peer
     * counts as dead), natt_keepalive_s (default 20 s, UDP/4500 0xFF keepalive behind NAT).
     * C2: child_lifetime_kb -> soft BYTE lifetime: once the host-reported ESP traffic
     * (weirdike_child_traffic) reaches this many KiB the Child SA is rekeyed; 0 = no byte limit.
     * Time and byte limits combine (whichever comes first). */
    int      dpd_disable;
    uint32_t dpd_interval_s;
    uint32_t dpd_retries;
    uint32_t natt_keepalive_s;
    uint32_t child_lifetime_kb;

    /* E2: additional remote networks (TSr selectors 2..N; remote_ts stays the first). Each becomes its
     * own selector in the TSr payload; the responder may narrow or drop entries. 0 = only remote_ts. */
    weirdike_ts_t remote_ts_extra[WEIRDIKE_TS_MAX - 1];
    size_t        n_remote_ts_extra;
} weirdike_config_t;

typedef struct weirdike_ctx weirdike_ctx;   /* opaque; defined in src/core/weirdike.c */
/* AP6: what the gateway assigned via Configuration Payload (valid once CHILD_ESTABLISHED). */
typedef struct {
    int     have_address; uint8_t address[4]; int have_netmask; uint8_t netmask[4];
    size_t  dns_count;    uint8_t dns[4][4];
    size_t  subnet_count; uint8_t subnet[4][4]; uint8_t subnet_mask[4][4];
    char    dns_domain[65]; size_t dns_domain_len;   /* F: INTERNAL_DNS_DOMAIN (search domain), NUL-terminated */
} weirdike_cp_t;
int weirdike_get_cp(const struct weirdike_ctx *ctx, weirdike_cp_t *out);   /* <0 = none received */

/* Convenience: fill ts with "any IPv4, any protocol, any port" (0.0.0.0-255.255.255.255).
 * Hosts that need a specific selector parse "a.b.c.d/prefix" themselves and fill weirdike_ts_t. */
void weirdike_ts_any_ipv4(weirdike_ts_t *ts);

/* NAT-D hash per RFC 7296: SHA-1 over SPIi(8) | SPIr(8) | IP | Port(network byte order). ep gives
 * the IP+port (IPv4 -> 4 bytes). For the initial IKE_SA_INIT request SPIr is all-zero. out is 20
 * bytes. Uses crypto->sha1 (RFC-mandated, independent of the negotiated PRF). 0 on success. */
int weirdike_natd_hash(const weirdike_crypto_t *crypto,
                       const uint8_t spi_i[8], const uint8_t spi_r[8],
                       const weirdike_endpoint_t *ep, uint8_t out[20]);

typedef enum {
    WEIRDIKE_STATE_IDLE = 0,
    WEIRDIKE_STATE_SA_INIT_SENT,      /* IKE_SA_INIT request in flight */
    WEIRDIKE_STATE_SA_INIT_DONE,      /* valid IKE_SA_INIT response parsed (M1 acceptance) */
    WEIRDIKE_STATE_AUTH_SENT,         /* IKE_AUTH request in flight */
    WEIRDIKE_STATE_ESTABLISHED,       /* IKE SA up */
    WEIRDIKE_STATE_CHILD_ESTABLISHED, /* first CHILD SA up -> data plane can start */
    WEIRDIKE_STATE_FAILED,
    WEIRDIKE_STATE_CLOSED
} weirdike_state_t;

/* The negotiated Child SA -- the ONLY thing the data plane (ESP engine) needs from IKE.
 * Keys are per-direction. For AEAD (AES-GCM) the 4-byte salt is the implicit-nonce salt and
 * integ_* is unused (integ == WEIRDIKE_AUTH_NONE). For CBC+HMAC, integ_* holds the HMAC keys. */
typedef struct {
    uint32_t            inbound_spi;
    uint32_t            outbound_spi;
    weirdike_encr_id_t  encr;        /* WEIRDIKE_ENCR_* */
    weirdike_integ_id_t integ;       /* WEIRDIKE_AUTH_* ; WEIRDIKE_AUTH_NONE for AEAD */

    uint8_t enc_key_in[32];   size_t enc_key_in_len;
    uint8_t enc_key_out[32];  size_t enc_key_out_len;
    uint8_t enc_salt_in[4];              /* AEAD implicit-nonce salt (GCM), else unused */
    uint8_t enc_salt_out[4];
    uint8_t integ_key_in[64]; size_t integ_key_in_len;   /* HMAC keys (CBC+HMAC), else 0 */
    uint8_t integ_key_out[64];size_t integ_key_out_len;

    int           nat_detected;      /* -> ESP-in-UDP/4500 */
    weirdike_ts_t local_ts;
    weirdike_ts_t remote_ts;
    /* E2: the full (narrowed) TSr set as returned by the responder; remote_ts == remote_ts_list[0]. */
    weirdike_ts_t remote_ts_list[WEIRDIKE_TS_MAX];
    size_t        n_remote_ts;
} weirdike_child_sa_t;


/* --- Lifecycle ------------------------------------------------------------------------------ */

/* Memory requirements of ONE instance: bytes + alignment of the context block and of the
 * workspace block. Deterministic for a given config BEFORE init; the core never grows either
 * block afterwards. cfg may be NULL (-> the maximum any config needs). Returns 0. */
typedef struct {
    size_t context_bytes;   size_t context_align;
    size_t workspace_bytes; size_t workspace_align;
} weirdike_mem_req_t;
int weirdike_mem_req(const weirdike_config_t *cfg, weirdike_mem_req_t *out);

/* Convenience for the cfg-independent maxima (== weirdike_mem_req(NULL, ...)). */
size_t weirdike_context_size(void);
size_t weirdike_workspace_size(void);

/* Caller-owned placement (NO allocator involved): initialise the context inside ctx_mem and use
 * ws_mem as its workspace. Both must satisfy the size AND alignment from weirdike_mem_req() and
 * must outlive the context; the adapter structs too. Returns NULL on bad args/size/alignment.
 * Typical MCU use: two static blocks. Typical Linux use: weirdike_new(). */
weirdike_ctx *weirdike_init(void *ctx_mem, size_t ctx_len,
                            void *ws_mem,  size_t ws_len,
                            const weirdike_config_t   *cfg,
                            const weirdike_crypto_t    *crypto,
                            const weirdike_transport_t *transport,
                            const weirdike_platform_t  *platform);

/* Provider convenience: obtain both blocks from `mem` (NULL -> stdlib malloc/free) with the
 * kind/alignment from weirdike_mem_req(), then weirdike_init(). NULL on failure (nothing leaks). */
weirdike_ctx *weirdike_new(const weirdike_config_t   *cfg,
                           const weirdike_crypto_t    *crypto,
                           const weirdike_transport_t *transport,
                           const weirdike_platform_t  *platform,
                           const weirdike_mem_t       *mem);

/* Closes the transport and zeroizes ALL secret IKE state (PSK, SK_*, Child-SA keys, DH state,
 * nonces, EAP material) AND the whole workspace. Safe for caller-owned blocks too -- it does NOT
 * free anything. Use this for placement contexts. */
void weirdike_deinit(weirdike_ctx *ctx);

/* weirdike_deinit(), then returns both blocks to the provider if weirdike_new() obtained them. */
void weirdike_free(weirdike_ctx *ctx);

/* --- Run (poll-driven, time supplied by the host) ------------------------------------------- */

/* Begin as initiator: opens transport, resolves peer, sends IKE_SA_INIT. 0 on success. */
int weirdike_start(weirdike_ctx *ctx, uint32_t now_ms);

/* Feed a received UDP datagram (from transport recv, or an external RX path). */
void weirdike_input_datagram(weirdike_ctx *ctx, const uint8_t *data, size_t len,
                             const weirdike_endpoint_t *from);

/* Pump the state machine (retransmits, timeouts, next message). Call regularly. 0 on success.
 * Once the IKE SA is authenticated this also runs DPD (probe after inbound silence -> FAILED on no
 * reply) and answers peer INFORMATIONAL requests (DPD acks, Child/IKE DELETE). */
int weirdike_poll(weirdike_ctx *ctx, uint32_t now_ms);

/* Graceful disconnect (RFC 7296 1.4.1): if the IKE SA is authenticated, send an encrypted DELETE
 * for the IKE SA and await the ack via weirdike_poll(); the state goes CLOSED on ack OR after the
 * DELETE retransmits give up (bounded -- the UI never hangs). If not authenticated, this deinits
 * immediately. After it returns, keep polling until weirdike_state()==CLOSED, then weirdike_deinit/
 * free. 0 on success. */
int weirdike_disconnect(weirdike_ctx *ctx, uint32_t now_ms);

/* Data-plane signal: the peer sent a Child-SA DELETE (or the IKE SA is gone) -> the ESP engine must
 * stop using the Child SA. Returns 1 if the Child SA has been torn down, 0 if it is still valid. */
int weirdike_child_deleted(const weirdike_ctx *ctx);

/* --- AP5: Child-SA rekey (CREATE_CHILD_SA, RFC 7296 1.3.3 / 2.8) ------------------------------
 * Every installed Child SA increments the generation (1 = the first one from IKE_AUTH). When the
 * host sees a new generation it must install weirdike_get_child_sa() (the CURRENT SA, used for
 * TX + RX) and, while weirdike_get_child_sa_prev() still returns 0, keep the PREVIOUS SA for RX
 * only (overlap: packets in flight on the old SA are not lost). The previous SA disappears once
 * its DELETE has been exchanged. Rekeys happen automatically (lifetime) or on peer request; the
 * host may force one with weirdike_rekey_child() (console / tests). */
uint32_t weirdike_child_generation(const weirdike_ctx *ctx);
/* C2: the host reports ESP traffic (bytes sealed + opened) of the CURRENT Child SA; feeds the byte
 * lifetime (cfg.child_lifetime_kb). Cheap; call per packet or batched. Reset internally on rekey. */
void weirdike_child_traffic(weirdike_ctx *ctx, uint32_t bytes);
int      weirdike_get_child_sa_prev(const weirdike_ctx *ctx, weirdike_child_sa_t *out);  /* <0 = none */
int      weirdike_rekey_child(weirdike_ctx *ctx, uint32_t now_ms);   /* 0 = request sent */

/* --- IKE-SA rekey (CREATE_CHILD_SA carrying an IKE proposal, RFC 7296 1.3.2 / 2.18) -------------
 * A new IKE SA (own SPIs, keys from SKEYSEED = prf_old(SK_d, g^ir | Ni | Nr), Message IDs from 0)
 * takes over in the second state slot; the Child SAs stay installed and simply belong to the new
 * IKE SA (the data plane sees nothing). The OLD IKE SA remains fully functional until its encrypted
 * DELETE has been exchanged (the rekey initiator deletes it; retransmits and the peer's own DELETE
 * are handled with the old SA's keys and Message-ID space), then its secrets are wiped. Every
 * installed IKE SA increments the generation (1 = the IKE_AUTH one). A peer request that cannot be
 * served during a transition is answered with TEMPORARY_FAILURE -- never with a silently overwritten
 * slot. Our own request that the peer refuses (TEMPORARY_FAILURE / NO_PROPOSAL_CHOSEN /
 * INVALID_KE_PAYLOAD) is dropped and the old IKE SA keeps working.
 *
 * KNOWN LIMITATION -- simultaneous IKE-SA rekey collision resolution by nonce comparison:
 * NOT IMPLEMENTED; the current implementation serializes the collision using TEMPORARY_FAILURE and
 * retry. RFC 7296 2.8.2 / 2.25.2 recommend (SHOULD) answering both CREATE_CHILD_SA rekeys and then
 * deleting the redundant new IKE SA chosen by comparing the nonces; that needs a third IKE-SA state
 * slot. Deliberate simplification (two slots, nothing is ever overwritten); a known RFC
 * interoperability gap, not a protocol violation (SHOULD, not MUST). */
uint32_t weirdike_ike_generation(const weirdike_ctx *ctx);
int      weirdike_rekey_ike(weirdike_ctx *ctx, uint32_t now_ms);   /* 0 = request sent */

/* Milliseconds from now_ms until the next timer wants attention (0 == due now). */
uint32_t weirdike_next_deadline_ms(weirdike_ctx *ctx, uint32_t now_ms);

weirdike_state_t weirdike_state(const weirdike_ctx *ctx);
const char      *weirdike_state_str(weirdike_state_t s);

/* Copies the negotiated Child SA once state == CHILD_ESTABLISHED. Returns 0, or <0 if not ready.
 * NOTE: *out contains SECRET ESP keys (enc_key_in/out, integ_key_in/out). The caller owns this copy
 * and MUST zeroize it after use; the core keeps its own copy and wipes it on deinit. */
int weirdike_get_child_sa(const weirdike_ctx *ctx, weirdike_child_sa_t *out);

/* Once the IKE SA is ESTABLISHED (authenticated), report whether the piggybacked IKE_AUTH ALSO
 * negotiated a Child SA. RFC 7296 allows a successful mutual AUTH with a failed Child negotiation,
 * so ESTABLISHED means "IKE SA authenticated", NOT "tunnel ready". Child KEYMAT/installation is a
 * later slice -> a negotiated child is NOT yet CHILD_ESTABLISHED. On return 1, fills the responder's
 * inbound ESP SPI (our future OUTBOUND SPI) and the responder's (possibly narrowed) traffic
 * selectors; each out pointer may be NULL. Returns 0 if no child was negotiated, <0 if not
 * ESTABLISHED / bad args. */
int weirdike_child_negotiated(const weirdike_ctx *ctx, uint8_t child_spi_r[4],
                              weirdike_ts_t *ts_i, weirdike_ts_t *ts_r);

/* Read-only diagnostics snapshot (NO secrets: only negotiated algorithm IDs, NAT-T decision, the
 * AUTH outcome and the peer identity). Suite fields are IANA transform IDs so this header stays
 * independent of the internal suite type. Returns 0 (always fills *out with what is known so far). */
typedef struct {
    int      have_ike_suite;            /* the IKE-SA suite has been negotiated */
    uint16_t ike_encr, ike_encr_key_bits, ike_prf, ike_integ, ike_dh;  /* IANA transform IDs */
    int      nat_t_peer;                /* peer sent NAT-D notifies (NAT-T supported) */
    int      nat_detected;              /* a NAT-D hash mismatched (real NAT on the path) */
    int      use_natt;                  /* IKE migrated to UDP/4500 */
    int      auth_done;                 /* an IKE_AUTH response was decrypted + interpreted */
    int      ike_auth_ok;              /* AUTH_r verified */
    int      child_sa_ok;              /* a Child SA was negotiated */
    /* IKE_AUTH outcome, semantically separated (all survive FAILED):
     *   ike_auth_rejected  the peer answered our IKE_AUTH with an error notify and NO AUTH payload:
     *                      it rejected OUR authentication (PSK/ID unknown to it, policy) -> last_notify
     *   auth_local_fail    the peer's AUTH payload was present but OUR verification of it failed
     *                      (PSK mismatch on our side, IDr'/signed-octets mismatch)
     *   child_notify       IKE_AUTH succeeded, but the Child SA was rejected with this error notify
     *                      (0 = none). NEVER set for an IKE-level rejection. */
    int      ike_auth_rejected;
    int      auth_local_fail;
    uint16_t child_notify;
    uint16_t child_encr, child_encr_key_bits, child_integ;  /* the NEGOTIATED Child suite (valid iff child_sa_ok) */
    uint8_t  idr_type;                 /* authenticated peer identity (valid iff ike_auth_ok) */
    uint8_t  idr[WEIRDIKE_MAX_ID];
    size_t   idr_len;
    /* AP3: non-secret metadata retained AFTER a failure (keys are always wiped, these survive).
     * have_ike_suite above now reflects "suite negotiated", not "keys present". */
    int      reached_state;            /* weirdike_state_t: furthest successful state ever reached */
    uint16_t last_notify;              /* last error-class notify received (0 = none) */
    uint32_t ike_generation;           /* IKE-SA generation: 1 = from IKE_AUTH, +1 per IKE-SA rekey */
    /* PEER behaviour observed on the wire (capability of the peer, NOT of this client): our Child
     * rekey requested PFS (KEi + D-H transform) and the peer selected a Child SA WITHOUT a D-H
     * transform and WITHOUT KEr, i.e. it installed a no-PFS SA. The core does not downgrade: the
     * rekey is rejected and the IKE SA closed for a clean re-establishment. Survives FAILED/CLOSED. */
    int      peer_pfs_rejected;
    /* Child-SA rekey diagnosis (PO item 0): generation (1 = first Child SA, +1 per installed rekey),
     * the D-H group the peer selected in the LAST CREATE_CHILD_SA (0 = no PFS), whether its response
     * carried a KE payload, and the host-reported traffic of the current Child SA (byte lifetime). */
    uint32_t child_generation;
    uint16_t child_rekey_dh;
    int      child_rekey_ke;
    uint64_t child_bytes;
} weirdike_diag_t;
int weirdike_get_diag(const weirdike_ctx *ctx, weirdike_diag_t *out);

/* Short IANA name of an IKEv2 error-notify type (RFC 7296 3.10.1), e.g. 24 -> "AUTHENTICATION_FAILED".
 * NULL for unknown types (the host prints the number). Diagnostics only. */
const char *weirdike_notify_name(uint16_t notify_type);

#ifdef __cplusplus
}
#endif

#endif /* WEIRDIKE_H */
