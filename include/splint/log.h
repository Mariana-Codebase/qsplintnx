/*
 * QSplintNX - event log. Lock-free-ish single ring of fixed-size events,
 * written by decision threads, drained by splintctl through /dev/splint/ctl.
 * No allocation after splint_log_new().
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPLINT_LOG_H
#define SPLINT_LOG_H

#include <stddef.h>
#include <stdint.h>
#include "splint/msg.h"
#include "splint/engine.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct splint_event {
    uint64_t seq;                      /* monotonically increasing, from 1 */
    uint64_t ts_ns;
    int32_t  pid;
    uint32_t dcmd;
    uint64_t len, declared;
    uint8_t  op;                       /* splint_op_t                    */
    uint8_t  action;                   /* splint_action_t                */
    uint8_t  reason;                   /* splint_reason_t                */
    uint8_t  would_block;
    uint32_t rule_line;
    uint32_t latency_ns;               /* decide()+forward, filled by splintd, 0 if unknown */
    char     client[32];               /* truncated process name         */
    char     rule_id[48];              /* truncated, "" if none          */
    char     path[64];                 /* truncated                      */
} splint_event_t;

typedef struct splint_log splint_log_t;

splint_log_t *splint_log_new(uint32_t capacity /* rounded up to pow2, min 64 */);
void          splint_log_free(splint_log_t *l);

/* Thread-safe. Oldest events are overwritten when full. */
void splint_log_push(splint_log_t *l, const splint_msg_t *m,
                     const splint_verdict_t *v, uint32_t latency_ns);

/* Copy up to max events with seq > after_seq into out, oldest first.
 * Returns number copied. Events overwritten before being read are lost;
 * caller can detect gaps through seq. */
uint32_t splint_log_read(const splint_log_t *l, uint64_t after_seq,
                         splint_event_t *out, uint32_t max);

/* One human-readable line, no trailing newline. snprintf-style return. */
size_t splint_event_format(const splint_event_t *ev, char *buf, size_t cap);

#ifdef __cplusplus
}
#endif
#endif /* SPLINT_LOG_H */
