/*
 * QSplintNX - learn mode. Observes allowed traffic and proposes a
 * profile per path (docs/RULES.md "profile blocks").
 *
 * Aggregation key: (path, client name, op, dcmd & 0xFFFF for devctl).
 * Per key it keeps count and max len. Rates are estimated per
 * (path, client) as the max messages seen in any 1-second window,
 * times a headroom factor.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPLINT_LEARN_H
#define SPLINT_LEARN_H

#include <stddef.h>
#include <stdint.h>
#include "splint/msg.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SPLINT_LEARN_MAX_KEYS 1024u

typedef struct splint_learn splint_learn_t;

typedef struct splint_learn_opts {
    uint32_t len_headroom_pct;    /* maxlen = observed max * (100+pct)/100, default 25 */
    uint32_t rate_headroom_pct;   /* default 100 (i.e. 2x observed peak)               */
    int      default_block;       /* emitted `default block` if non-zero (default 1)   */
} splint_learn_opts_t;

splint_learn_t *splint_learn_new(const splint_learn_opts_t *opts /* NULL = defaults */);
void            splint_learn_free(splint_learn_t *l);

/* Record one message. Thread-safe. Returns 0, or -1 if the key table is
 * full (message still counted in dropped). */
int  splint_learn_observe(splint_learn_t *l, const splint_msg_t *m);

/* Emit profiles as rule text (RULES.md syntax), deterministic order
 * (path, then op, then code, then client). snprintf-style return. */
size_t splint_learn_emit(const splint_learn_t *l, char *buf, size_t cap);

void splint_learn_reset(splint_learn_t *l);
uint64_t splint_learn_dropped(const splint_learn_t *l);

#ifdef __cplusplus
}
#endif
#endif /* SPLINT_LEARN_H */
