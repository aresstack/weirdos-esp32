/*
 * WeirdIKE -- src/esp/esp_replay.h : ESP sequence numbers + anti-replay (RFC 4303 3.3.3/3.4.3).
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Pure logic, NO crypto. Two separate concerns:
 *   - outbound: a monotonic 32-bit sender counter (no wrap to 0).
 *   - inbound : a sliding anti-replay window over the highest AUTHENTICATED sequence number.
 *
 * The RX path is two-phase so an unauthenticated (possibly forged) sequence number can be cheaply
 * pre-screened WITHOUT moving the window, and the window only advances after the ICV verifies:
 *     seq = header;  precheck(seq)  ->  esp_open() (ICV+decrypt)  ->  commit(seq)  ->  deliver
 * commit() re-checks against the current state (never blindly trusts an earlier precheck).
 *
 * This slice implements a 32-bit sequence space (NO_ESN); seq 0 is never valid on the wire.
 */
#ifndef WEIRDIKE_ESP_REPLAY_H
#define WEIRDIKE_ESP_REPLAY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ESP_REPLAY_WINDOW 64   /* bits in the bitmap */

/* --- inbound anti-replay --- */
typedef struct {
    uint32_t highest;   /* highest authenticated seq (0 = none yet) */
    uint64_t bitmap;    /* bit d set => (highest - d) already seen; bit 0 = highest */
} esp_replay_t;

void esp_replay_init(esp_replay_t *r);

/* Would this seq be accepted right now? Does NOT change state. 0 = acceptable, -1 = reject
 * (seq 0, duplicate, or older than the window). */
int esp_replay_precheck(const esp_replay_t *r, uint32_t seq);

/* Record an authenticated seq, advancing/marking the window. Re-checks against the current state.
 * 0 = committed, -1 = reject (seq 0, duplicate, or too old). */
int esp_replay_commit(esp_replay_t *r, uint32_t seq);

/* --- outbound sequence counter --- */
typedef struct {
    uint32_t next;      /* next sequence number to hand out (starts at 1) */
    int      exhausted; /* set once 0xFFFFFFFF has been handed out */
} esp_seq_t;

void esp_seq_init(esp_seq_t *s);

/* Hand out the next sequence number. 1,2,...,0xFFFFFFFF are each valid exactly once; 0xFFFFFFFF is
 * still usable, but the following wrap to 0 is forbidden. 0 = ok (*seq set), -1 = exhausted. */
int esp_seq_take(esp_seq_t *s, uint32_t *seq);

#ifdef __cplusplus
}
#endif

#endif /* WEIRDIKE_ESP_REPLAY_H */
