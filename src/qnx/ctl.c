/* SPDX-License-Identifier: Apache-2.0 */
/*
 * QSplintNX - ctl.c
 *
 * The control node (default /dev/splint/ctl). splintctl opens it and drives
 * splintd through four devctl commands: reload a ruleset from a path, read
 * stats, drain the event log, and dump learn-mode profiles to a file. The
 * node is attached on the same dispatch as the data paths but with its own
 * attribute and its own io_devctl handler. Every in/out length is validated
 * against the transport (srcmsglen / dstmsglen) before use.
 *
 * STATUS: cross-compiled with qcc for QNX 8.0 (gcc_ntox86_64) and validated on a QEMU/KVM target; see docs/qemu-validation.md.
 *
 * API references verified against the SDP 8.0 documentation:
 *   devctl reply layout  .../messages_Sample_IO_DEVCTL.html
 *   resmgr_msgget        .../r/resmgr_msgget.html
 *   secpol_resmgr_attach .../com.qnx.doc.security.system/topic/secpol_resmgr_attach.html
 */

#define IOFUNC_OCB_T   struct splintd_ocb
#define IOFUNC_ATTR_T  struct splintd_mapping
#include "splintd.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#ifndef SPLINT_USE_SECPOL
#define SPLINT_USE_SECPOL 1
#endif
#if SPLINT_USE_SECPOL
#include <secpol/secpol.h>
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

/* Active-ruleset summary kept by splintd_load_rules() in splintd_main.c; the
 * engine exposes no getter for mode/npatch/nprofile.  (Flag for Commander:
 * these belong in splintd_t.) */
extern volatile uint32_t g_active_mode;
extern volatile uint32_t g_active_npatch;
extern volatile uint32_t g_active_nprofile;

/* Reply data must outlive the handler (the library replies after it returns),
 * so it cannot sit on the handler's stack. One thread-local staging buffer,
 * big enough for the largest reply, serves. */
typedef union {
    splint_ctl_reload_t     reload;
    splint_ctl_stats_t      stats;
    splint_ctl_events_t     events;
    splint_ctl_learn_dump_t learn;
} splintd_ctl_reply_u;

static _Thread_local splintd_ctl_reply_u tls_reply;

/* ---- individual command handlers: fill tls_reply, set *out_nbytes ---- */

static int ctl_do_reload(const void *in, size_t in_real, size_t *out_nbytes)
{
    if (in_real < sizeof(splint_ctl_reload_t))
        return EINVAL;

    splint_ctl_reload_t req;
    memcpy(&req, in, sizeof req);
    req.path[sizeof req.path - 1] = '\0';          /* never trust NUL-termination */

    splint_parse_error_t perr;
    memset(&perr, 0, sizeof perr);
    int rc = splintd_load_rules(req.path, &perr);  /* leaves running ruleset on error */

    splint_ctl_reload_t *rep = &tls_reply.reload;
    memset(rep, 0, sizeof *rep);
    memcpy(rep->path, req.path, sizeof rep->path);
    rep->status   = (rc == 0) ? 0 : -1;
    rep->err_line = perr.line;
    rep->err_col  = perr.col;
    snprintf(rep->err_msg, sizeof rep->err_msg, "%s", perr.msg);

    *out_nbytes = sizeof *rep;
    return EOK;                                    /* a parse error is reported in-band */
}

static int ctl_do_stats(size_t *out_nbytes)
{
    splint_ctl_stats_t *rep = &tls_reply.stats;
    memset(rep, 0, sizeof *rep);

    splint_engine_stats(g_splintd.engine, &rep->engine);
    rep->forward_errors = __atomic_load_n(&g_splintd.forward_errors, __ATOMIC_RELAXED);
    rep->open_clients   = __atomic_load_n(&g_splintd.open_clients,   __ATOMIC_RELAXED);
    rep->mode           = __atomic_load_n(&g_active_mode,     __ATOMIC_RELAXED);
    rep->npatch         = __atomic_load_n(&g_active_npatch,   __ATOMIC_RELAXED);
    rep->nprofile       = __atomic_load_n(&g_active_nprofile, __ATOMIC_RELAXED);
    rep->max_latency_ns = __atomic_load_n(&g_splintd.max_latency_ns, __ATOMIC_RELAXED);
    rep->sum_latency_ns = __atomic_load_n(&g_splintd.sum_latency_ns, __ATOMIC_RELAXED);

    *out_nbytes = sizeof *rep;
    return EOK;
}

static int ctl_do_events(const void *in, size_t in_real, size_t *out_nbytes)
{
    if (in_real < sizeof(uint64_t))
        return EINVAL;

    uint64_t after_seq;
    memcpy(&after_seq, in, sizeof after_seq);      /* first field of the request */

    splint_ctl_events_t *rep = &tls_reply.events;
    memset(rep, 0, sizeof *rep);
    rep->after_seq = after_seq;
    rep->count = splint_log_read(g_splintd.log, after_seq, rep->ev, SPLINT_CTL_EVENTS_BATCH);

    *out_nbytes = sizeof *rep;
    return EOK;
}

static int ctl_do_learn_dump(const void *in, size_t in_real, size_t *out_nbytes)
{
    if (in_real < sizeof(splint_ctl_learn_dump_t))
        return EINVAL;

    splint_ctl_learn_dump_t req;
    memcpy(&req, in, sizeof req);
    req.path[sizeof req.path - 1] = '\0';

    splint_ctl_learn_dump_t *rep = &tls_reply.learn;
    memset(rep, 0, sizeof *rep);
    memcpy(rep->path, req.path, sizeof rep->path);

    /* The learn table is never freed while the daemon runs; dump what it holds
     * as long as it exists (learn mode is or was active). */
    splint_learn_t *lrn = __atomic_load_n(&g_splintd.learn, __ATOMIC_ACQUIRE);
    if (lrn == NULL) {
        rep->status = EAGAIN;                      /* learn mode never activated */
        *out_nbytes = sizeof *rep;
        return EOK;
    }

    /* Size the buffer from a first (sizing) emit, then emit for real. */
    size_t cap = (size_t)splint_learn_emit(lrn, NULL, 0) + 1;
    char *hb = malloc(cap);
    if (hb == NULL) {
        rep->status = ENOMEM;
        *out_nbytes = sizeof *rep;
        return EOK;
    }
    size_t produced = splint_learn_emit(lrn, hb, cap);
    if (produced >= cap)
        produced = cap - 1;                        /* defensive, should not happen */

    int fd = open(req.path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        rep->status = errno ? errno : EIO;
        free(hb);
        *out_nbytes = sizeof *rep;
        return EOK;
    }

    size_t off = 0;
    int    werr = 0;
    while (off < produced) {
        ssize_t w = write(fd, hb + off, produced - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            werr = errno ? errno : EIO;
            break;
        }
        if (w == 0)
            break;
        off += (size_t)w;
    }
    (void)close(fd);
    free(hb);

    rep->status = werr;
    rep->bytes  = (uint32_t)off;
    *out_nbytes = sizeof *rep;
    return EOK;
}

/* ---- the io_devctl handler for the control node ---- */

static int ctl_devctl(resmgr_context_t *ctp, io_devctl_t *msg, RESMGR_OCB_T *ocb)
{
    (void)ocb;
    uint64_t t0 = splintd_now_ns();

    unsigned udcmd = (unsigned)msg->i.dcmd;

    size_t hdr    = sizeof(msg->i);
    size_t srclen = (size_t)ctp->info.srcmsglen;
    size_t in_real = 0;
    if (srclen > ctp->offset + hdr)
        in_real = srclen - ctp->offset - hdr;

    size_t out_cap = 0;
    if ((size_t)ctp->info.dstmsglen > sizeof(msg->o))
        out_cap = (size_t)ctp->info.dstmsglen - sizeof(msg->o);

    /* Pull the request body out of the transport into a bounded local. The
     * largest request we read is a reload/learn path or an events after_seq;
     * cap it at the reply union size which comfortably covers all of them. */
    static _Thread_local uint8_t inbuf[sizeof(splintd_ctl_reply_u)];
    size_t in_take = in_real < sizeof inbuf ? in_real : sizeof inbuf;
    if (in_take > 0) {
        ssize_t rd = resmgr_msgget(ctp, inbuf, in_take, hdr);
        if (rd < 0)
            return errno ? errno : EIO;
        if ((size_t)rd < in_take)
            in_take = (size_t)rd;
    }

    size_t out_nbytes = 0;
    int    status;

    switch (udcmd) {
    case SPLINT_DCMD_RELOAD:
        status = ctl_do_reload(inbuf, in_take, &out_nbytes);
        break;
    case SPLINT_DCMD_STATS:
        status = ctl_do_stats(&out_nbytes);
        break;
    case SPLINT_DCMD_EVENTS:
        status = ctl_do_events(inbuf, in_take, &out_nbytes);
        break;
    case SPLINT_DCMD_LEARN_DUMP:
        status = ctl_do_learn_dump(inbuf, in_take, &out_nbytes);
        break;
    default:
        return ENOTTY;                             /* unknown command */
    }

    if (status != EOK)
        return status;

    /* Refuse to overrun the caller's receive buffer. */
    if (out_nbytes > out_cap)
        return EINVAL;

    memset(&msg->o, 0, sizeof msg->o);
    msg->o.ret_val = 0;
    msg->o.nbytes  = (uint32_t)out_nbytes;

    splintd_record_latency(splintd_now_ns() - t0);

    SETIOV(&ctp->iov[0], &msg->o, sizeof msg->o);
    if (out_nbytes > 0) {
        SETIOV(&ctp->iov[1], &tls_reply, out_nbytes);
        return _RESMGR_NPARTS(2);
    }
    return _RESMGR_NPARTS(1);
}

/* ---- attach ---- */

int splintd_ctl_attach(dispatch_t *dpp, const char *path)
{
    /* The control node carries its own iofunc attribute; we wrap it in a
     * splintd_mapping_t only so the handle type matches RESMGR_HANDLE_T. It
     * uses no custom OCB (no mount funcs), so default OCB allocation applies. */
    static splintd_mapping_t       ctl_map;
    static resmgr_connect_funcs_t  ctl_cf;
    static resmgr_io_funcs_t       ctl_io;
    static resmgr_attr_t           rattr;

    memset(&ctl_map, 0, sizeof ctl_map);
    ctl_map.mode = SPLINTD_BACKEND_RELOCATED;      /* unused for the ctl node */

    iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &ctl_cf, _RESMGR_IO_NFUNCS, &ctl_io);
    ctl_io.devctl = ctl_devctl;

    iofunc_attr_init(&ctl_map.attr, S_IFCHR | 0600, NULL, NULL);
    ctl_map.attr.uid = 0;                          /* owner root */
    ctl_map.attr.gid = 0;

    memset(&rattr, 0, sizeof rattr);
    rattr.nparts_max   = 2;                         /* reply header + data */
    rattr.msg_max_size = 8192;                      /* covers the largest request */

    int id;
#if SPLINT_USE_SECPOL
    /* QNX 8 recommends secpol_resmgr_attach(); with no policy file it behaves
     * exactly like resmgr_attach(). NULL handle selects the default policy. */
    bool perms_set = false;
    id = secpol_resmgr_attach(NULL, dpp, &rattr, path, _FTYPE_ANY, 0,
                              &ctl_cf, &ctl_io, &ctl_map.attr, &perms_set);
#else
    id = resmgr_attach(dpp, &rattr, path, _FTYPE_ANY, 0, &ctl_cf, &ctl_io, &ctl_map);
#endif
    if (id == -1)
        return errno ? errno : EIO;
    ctl_map.link_id = id;
    return 0;
}
