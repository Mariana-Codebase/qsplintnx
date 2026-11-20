/*
 * QSplintNX - decision engine. C11 (atomics, _Thread_local), no allocation
 * on the hot path, no syscalls: time comes in through msg->now_ns.
 *
 * Thread model: one engine per splintd. splint_engine_decide() may be
 * called concurrently from several resmgr threads. Ruleset swap is a
 * single atomic pointer store; a decision uses whichever ruleset it loaded
 * at entry. Rate-limit state is protected internally (see engine.c).
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPLINT_ENGINE_H
#define SPLINT_ENGINE_H

#include <stdbool.h>
#include <stdint.h>
#include "splint/msg.h"
#include "splint/rules.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum splint_action { SPLINT_ALLOW = 0, SPLINT_BLOCK = 1 } splint_action_t;

typedef enum splint_reason {
    SPLINT_R_NONE = 0,      /* no rule involved (no profile, plain allow) */
    SPLINT_R_PATCH,         /* a patch matched                            */
    SPLINT_R_ALLOW,         /* a profile allow line matched               */
    SPLINT_R_DEFAULT,       /* profile default applied                    */
    SPLINT_R_RATE           /* rate limit exceeded                        */
} splint_reason_t;

typedef struct splint_verdict {
    splint_action_t action;
    splint_reason_t reason;
    bool            log;          /* caller should emit an event          */
    bool            would_block;  /* learn mode: enforce would have blocked */
    int             err;          /* errno to reply when action == BLOCK  */
    const char     *rule_id;      /* patch id, or NULL. Valid only until the
                                     same thread's next splint_engine_decide();
                                     copy or splint_log_push() it before then. */
    uint32_t        rule_line;    /* source line of deciding rule, or 0   */
} splint_verdict_t;

typedef struct splint_engine splint_engine_t;

typedef struct splint_engine_stats {
    uint64_t decided, allowed, blocked, logged, rate_limited, would_block;
} splint_engine_stats_t;

splint_engine_t *splint_engine_new(void);
void             splint_engine_free(splint_engine_t *e);

/* Takes ownership of rs. Frees the previous ruleset only after no
 * decision can still be using it (engine.c documents the scheme).
 * rs may be NULL: then every message is allowed. */
void splint_engine_set_rules(splint_engine_t *e, splint_ruleset_t *rs);

/* Decide one message. Never fails; fills *v completely. Bounded time:
 * O(npatch * SPLINT_MAX_CONDS + nallow + nrate). */
void splint_engine_decide(splint_engine_t *e, const splint_msg_t *m,
                          splint_verdict_t *v);

void splint_engine_stats(const splint_engine_t *e, splint_engine_stats_t *out);

const char *splint_reason_name(splint_reason_t r);

#ifdef __cplusplus
}
#endif
#endif /* SPLINT_ENGINE_H */
