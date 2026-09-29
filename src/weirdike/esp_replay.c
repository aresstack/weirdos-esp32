/*
 * WeirdIKE -- src/esp/esp_replay.c : ESP sequence numbers + anti-replay (RFC 4303).
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "esp_replay.h"

void esp_replay_init(esp_replay_t *r) {
    if (!r) return;
    r->highest = 0;
    r->bitmap  = 0;
}

int esp_replay_precheck(const esp_replay_t *r, uint32_t seq) {
    if (!r) return -1;
    if (seq == 0) return -1;                 /* NO_ESN: 0 is never a valid ESP sequence number */
    if (seq > r->highest) return 0;          /* new, higher -> acceptable (window shifts on commit) */
    uint32_t delta = r->highest - seq;
    if (delta >= ESP_REPLAY_WINDOW) return -1;         /* older than the window */
    if (r->bitmap & ((uint64_t)1 << delta)) return -1; /* already seen */
    return 0;
}

int esp_replay_commit(esp_replay_t *r, uint32_t seq) {
    if (!r) return -1;
    if (seq == 0) return -1;
    if (seq > r->highest) {                  /* advance the window to the new highest */
        uint32_t shift = seq - r->highest;
        if (shift >= ESP_REPLAY_WINDOW) r->bitmap = 1;      /* window fully past the old one */
        else r->bitmap = (r->bitmap << shift) | (uint64_t)1;
        r->highest = seq;
        return 0;
    }
    uint32_t delta = r->highest - seq;       /* in-window: mark, rejecting duplicates */
    if (delta >= ESP_REPLAY_WINDOW) return -1;
    if (r->bitmap & ((uint64_t)1 << delta)) return -1;
    r->bitmap |= ((uint64_t)1 << delta);
    return 0;
}

void esp_seq_init(esp_seq_t *s) {
    if (!s) return;
    s->next = 1;
    s->exhausted = 0;
}

int esp_seq_take(esp_seq_t *s, uint32_t *seq) {
    if (!s || !seq) return -1;
    if (s->exhausted) return -1;
    *seq = s->next;
    if (s->next == 0xFFFFFFFFu) s->exhausted = 1;   /* this value is valid; the wrap to 0 is not */
    else s->next++;
    return 0;
}
