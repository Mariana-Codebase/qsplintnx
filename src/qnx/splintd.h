/*
 * QSplintNX - splintd internals (QNX only).
 *
 * splintd is a resource manager that attaches each PUBLIC path a driver
 * normally owns, and forwards every allowed message to the real driver,
 * the BACKEND. Two backend modes:
 *
 *  1. Relocated backend (default, used by the demo): the driver is started
 *     on a hidden path (e.g. /dev/.splint/vendor_can) and splintd owns the
 *     public path. secpol forbids every type except splintd_t from
 *     connecting to the driver's channel, so nobody can bypass splintd.
 *
 *  2. Shadow backend (for binary drivers with a hard-coded path): driver
 *     and splintd attach the SAME path; splintd uses _RESMGR_FLAG_BEFORE
 *     so it resolves first. When splintd itself opens that path, its
 *     io_open returns ENOENT for its own pid, so the client library moves
 *     on to the next resource manager in the chain (the real driver).
 *     This must be validated on target (spike S1 in docs/PLAN.md).
 *
 * Per client open() splintd opens its own fd on the backend and keeps it
 * in the OCB; all later I/O on the client's fd is forwarded on that fd.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPLINTD_H
#define SPLINTD_H

#include <stdint.h>

/* The QNX resmgr headers use IOFUNC_OCB_T / IOFUNC_ATTR_T (defined by each .c
 * before including this header) inside function-pointer prototypes. Forward-
 * declare the real struct tags at file scope first, so those pointers refer to
 * these types and not to ones "declared inside parameter list". */
struct splintd_ocb;
struct splintd_mapping;

#include <sys/iofunc.h>
#include <sys/dispatch.h>
#include <sys/resmgr.h>

#include "splint/msg.h"
#include "splint/engine.h"
#include "splint/log.h"
#include "splint/learn.h"
#include "splint/ctl.h"

#define SPLINTD_MAX_MAPPINGS   16
#define SPLINTD_IOBUF_MAX      (64u * 1024u)   /* largest read/write/devctl payload forwarded */

typedef enum { SPLINTD_BACKEND_RELOCATED = 0, SPLINTD_BACKEND_SHADOW } splintd_backend_mode_t;

/* One public path -> backend path. The iofunc_attr_t MUST be first so the
 * resmgr library can treat a mapping pointer as an attr pointer. */
typedef struct splintd_mapping {
    iofunc_attr_t           attr;
    char                    public_path[SPLINT_PATH_MAX];
    char                    backend_path[SPLINT_PATH_MAX];
    splintd_backend_mode_t  mode;
    int                     link_id;
} splintd_mapping_t;

/* Per-open state. iofunc_ocb_t MUST be first (library casts). */
typedef struct splintd_ocb {
    iofunc_ocb_t        hdr;
    int                 backend_fd;      /* -1 if not open             */
    splint_client_t     client;          /* resolved at open           */
    splintd_mapping_t  *map;
} splintd_ocb_t;

/* Global daemon state (single instance, defined in splintd_main.c). */
typedef struct splintd {
    dispatch_t         *dpp;
    splint_engine_t    *engine;
    splint_log_t       *log;
    /* The learn table is allocated once (lazily, with a CAS) and never freed
     * while the daemon runs, so a worker that has loaded g_splintd.learn can
     * always use it safely. learn_active (atomic) says whether learn mode is
     * on; observers check it before recording. This removes the earlier
     * free-on-reload use-after-free. */
    splint_learn_t     *learn;
    volatile int        learn_active;
    char                rules_path[256];
    char                ctl_path[SPLINT_PATH_MAX];
    int                 nmap;
    splintd_mapping_t   map[SPLINTD_MAX_MAPPINGS];
    int                 verbose;
    /* stats not kept by the engine */
    volatile uint64_t   forward_errors;
    volatile uint64_t   open_clients;
    volatile uint64_t   max_latency_ns;
    volatile uint64_t   sum_latency_ns;
} splintd_t;

extern splintd_t g_splintd;

/* ---- splintd_main.c: argv, ruleset load, attach, thread pool --------- */
/* usage: splintd -r <rules> [-m <public>=<backend>]... [-s <public>]...
 *               [-c <ctlpath>] [-t <threads>] [-v]
 *   -m  relocated mapping;  -s  shadow mapping (backend path == public) */
int  splintd_load_rules(const char *path, splint_parse_error_t *err); /* 0 ok */

/* ---- interpose.c: resmgr handlers for public paths ------------------ */
void splintd_interpose_init_funcs(resmgr_connect_funcs_t *cf, resmgr_io_funcs_t *io);
IOFUNC_OCB_T *splintd_ocb_calloc(resmgr_context_t *ctp, IOFUNC_ATTR_T *attr);
void          splintd_ocb_free(IOFUNC_OCB_T *ocb);

/* ---- backend.c: everything that talks to the real driver ------------ */
int     splintd_backend_open(splintd_ocb_t *ocb, int oflag);         /* 0 or errno */
void    splintd_backend_close(splintd_ocb_t *ocb);
ssize_t splintd_backend_read(splintd_ocb_t *ocb, void *buf, size_t n, off_t *off_inout);
ssize_t splintd_backend_write(splintd_ocb_t *ocb, const void *buf, size_t n);
/* Returns EOK or errno; *ret_val gets devctl's return_info. out buffer
 * is the same as in (devctl semantics), sized max(in_len, out_cap). */
int     splintd_backend_devctl(splintd_ocb_t *ocb, int dcmd, void *buf,
                               size_t in_len, size_t buf_cap, int *ret_val);
off_t   splintd_backend_lseek(splintd_ocb_t *ocb, off_t off, int whence);

/* ---- clientinfo.c --------------------------------------------------- */
/* Fill client identity from the connection; name = basename of the
 * client's executable (via /proc/<pid>/exefile), "?" if unknown. */
int  splintd_client_resolve(resmgr_context_t *ctp, int ioflag, splint_client_t *out);

/* ---- ctl.c: /dev/splint/ctl ---------------------------------------- */
int  splintd_ctl_attach(dispatch_t *dpp, const char *path);       /* 0 ok */

/* ---- helpers shared by interpose.c and ctl.c (in interpose.c) ------- */
uint64_t splintd_now_ns(void);
void     splintd_record_latency(uint64_t ns);

#endif /* SPLINTD_H */
