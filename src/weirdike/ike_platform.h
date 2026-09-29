/*
 * WeirdIKE -- ike_platform.h : platform hooks (secure-zero, logging) + memory provider.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * NO OS types (no FreeRTOS/NuttX/Arduino/lwIP) and -- deliberately -- NO clock here: the core is
 * poll-driven and receives time explicitly via weirdike_start()/weirdike_poll(now_ms). That keeps
 * time deterministic (great for unit tests / fuzzing) and gives exactly one time source.
 *
 * MEMORY MODEL (identical on Linux, FreeRTOS and bare metal -- only the PLACEMENT differs):
 *   - weirdike_ctx        small, long-lived, explicit protocol state (FSM, SPIs, keys, timers).
 *   - weirdike workspace  large buffers with context lifetime but shorter LOGICAL lifetimes
 *                         (SA_INIT transcript, retransmit/dedup caches, RX plaintext, TX build
 *                         area, crypto scratch). Never on the C stack.
 *   Both blocks are CALLER-OWNED with weirdike_init() (no allocator involved at all), or obtained
 *   through the memory provider below with weirdike_new(). The provider is separate from the
 *   platform adapter on purpose: clock/log/zeroize have nothing to do with memory placement.
 *   The core does not know what PSRAM, SRAM or a static pool is -- the host decides per KIND:
 *       Linux            CONTEXT -> heap,          WORKSPACE -> heap
 *       ESP32-P4         CONTEXT -> internal RAM,  WORKSPACE -> PSRAM
 *       small MCU        CONTEXT/WORKSPACE -> two static blocks via weirdike_init()
 *   Sizes and alignment come from weirdike_mem_req() (deterministic before init, no growth later).
 */
#ifndef WEIRDIKE_PLATFORM_H
#define WEIRDIKE_PLATFORM_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    WEIRDIKE_LOG_ERROR = 0,
    WEIRDIKE_LOG_INFO  = 1,
    WEIRDIKE_LOG_DEBUG = 2
};

/* Platform adapter: zeroization + logging. All hooks OPTIONAL (NULL secure_zero -> volatile wipe,
 * NULL log -> silent). Memory is NOT here -- see weirdike_mem_t. */
typedef struct {
    void  *ctx;                                            /* opaque, passed back to callbacks */
    void  (*secure_zero)(void *ctx, void *ptr, size_t len);/* NULL -> volatile memset (wipe secrets) */
    void  (*log)(void *ctx, int level, const char *msg);   /* NULL -> silent */
} weirdike_platform_t;

/* Memory provider for weirdike_new()/weirdike_free(): one alloc/free pair with a semantic KIND so
 * the host can place each block differently. `alignment` is the value weirdike_mem_req() reports
 * for that kind; the returned pointer MUST satisfy it. Both hooks must be set (or the whole
 * provider is NULL -> stdlib malloc/free, whose alignment satisfies every requirement here). */
typedef enum {
    WEIRDIKE_MEM_CONTEXT   = 0,   /* weirdike_ctx: small, hot, long-lived protocol state */
    WEIRDIKE_MEM_WORKSPACE = 1    /* large buffers: transcript, caches, RX/TX/crypto scratch */
} weirdike_mem_kind_t;

typedef struct {
    void  *ctx;
    void *(*alloc)(void *ctx, size_t bytes, size_t alignment, weirdike_mem_kind_t kind);
    void  (*free)(void *ctx, void *ptr, weirdike_mem_kind_t kind);
} weirdike_mem_t;

#ifdef __cplusplus
}
#endif

#endif /* WEIRDIKE_PLATFORM_H */
