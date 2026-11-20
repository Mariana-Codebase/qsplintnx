/*
 * QSplintNX - control protocol between splintctl and splintd.
 *
 * splintd attaches a control node (default /dev/splint/ctl). splintctl
 * opens it and uses devctl() with the commands below. The control node is
 * itself protected by secpol: only the splintctl type may connect
 * (tools/secpolgen generates the rule).
 *
 * This header must compile on QNX (uses <devctl.h> macros) and on the host
 * (tests use the numeric values), hence the fallback definitions.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPLINT_CTL_H
#define SPLINT_CTL_H

#include <stdint.h>
#include "splint/log.h"
#include "splint/engine.h"

#if defined(__QNX__) || defined(__QNXNTO__)
#include <devctl.h>
#else
/* Host fallback with the same encoding as QNX <devctl.h>. */
#define _DCMD_MISC 0x05
#define __DIOF(class, cmd, data) ((sizeof(data) << 16) + ((class) << 8) + (cmd) + 0x40000000u)
#define __DIOT(class, cmd, data) ((sizeof(data) << 16) + ((class) << 8) + (cmd) + 0x80000000u)
#define __DIOTF(class, cmd, data) ((sizeof(data) << 16) + ((class) << 8) + (cmd) + 0xC0000000u)
#define __DION(class, cmd) (((class) << 8) + (cmd))
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SPLINT_CTL_DEFAULT_PATH "/dev/splint/ctl"
#define SPLINT_CTL_BASE 0xA0  /* command numbers 0xA0..0xAF, class _DCMD_MISC */

/* Reload: client writes the full rules text after this header in the
 * same devctl buffer is impractical (16 KB limit), so reload passes a
 * PATH that splintd reads itself. */
typedef struct splint_ctl_reload {
    char     path[256];        /* in: rules file path on target, NUL-terminated */
    int32_t  status;           /* out: 0 ok, -1 parse error                     */
    uint32_t err_line, err_col;/* out                                           */
    char     err_msg[160];     /* out                                           */
} splint_ctl_reload_t;

typedef struct splint_ctl_stats {
    splint_engine_stats_t engine;  /* out */
    uint64_t forward_errors;       /* out: backend replied with transport error */
    uint64_t open_clients;         /* out */
    uint32_t mode;                 /* out: splint_mode_t of active ruleset      */
    uint32_t npatch, nprofile;     /* out */
    uint64_t max_latency_ns;       /* out: worst decide+forward since start     */
    uint64_t sum_latency_ns;       /* out: for mean = sum / decided             */
} splint_ctl_stats_t;

#define SPLINT_CTL_EVENTS_BATCH 16u
typedef struct splint_ctl_events {
    uint64_t       after_seq;                         /* in  */
    uint32_t       count;                             /* out */
    uint32_t       _pad;
    splint_event_t ev[SPLINT_CTL_EVENTS_BATCH];       /* out */
} splint_ctl_events_t;

typedef struct splint_ctl_learn_dump {
    char     path[256];        /* in: file to write proposed profiles to */
    int32_t  status;           /* out: 0 ok, else errno                  */
    uint32_t bytes;            /* out: bytes written                     */
} splint_ctl_learn_dump_t;

#define SPLINT_DCMD_RELOAD     __DIOTF(_DCMD_MISC, SPLINT_CTL_BASE + 0, splint_ctl_reload_t)
#define SPLINT_DCMD_STATS      __DIOF (_DCMD_MISC, SPLINT_CTL_BASE + 1, splint_ctl_stats_t)
#define SPLINT_DCMD_EVENTS     __DIOTF(_DCMD_MISC, SPLINT_CTL_BASE + 2, splint_ctl_events_t)
#define SPLINT_DCMD_LEARN_DUMP __DIOTF(_DCMD_MISC, SPLINT_CTL_BASE + 3, splint_ctl_learn_dump_t)

#ifdef __cplusplus
}
#endif
#endif /* SPLINT_CTL_H */
