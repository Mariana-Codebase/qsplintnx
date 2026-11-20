/* SPDX-License-Identifier: Apache-2.0 */
/*
 * QSplintNX - interpose.c
 *
 * The resource-manager handlers for every PUBLIC path splintd owns. Each
 * client open() gets its own backend fd (kept in the OCB); every later
 * message is checked against the engine and, if allowed, forwarded on that
 * fd. The length of a read/write/devctl payload is always recomputed from
 * the transport (ctp->info.srcmsglen), never trusted from the client's
 * nbytes header, because this code is a security boundary.
 *
 * STATUS: written against QNX SDP 8.0 docs, not yet compiled on target.
 *
 * API references verified against the SDP 8.0 documentation:
 *   iofunc_func_init / tables  .../i/iofunc_func_init.html, .../r/resmgr_io_funcs_t.html
 *   iofunc_open_default        .../i/iofunc_open_default.html
 *   iofunc_read_verify         .../i/iofunc_read_verify.html
 *   read/write handler samples .../read_write_Sample_IO_READ.html / _IO_WRITE.html
 *   devctl handler sample      .../messages_Sample_IO_DEVCTL.html
 *   resmgr_msgget              .../r/resmgr_msgget.html
 *   ClockCycles / cycles_per_sec .../c/clockcycles.html
 */

#define IOFUNC_OCB_T   struct splintd_ocb
#define IOFUNC_ATTR_T  struct splintd_mapping
#include "splintd.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/neutrino.h>
#include <sys/syspage.h>

/* 64-bit saturating helpers for the latency accumulators. */
static inline uint32_t clamp_u32(uint64_t v) { return v > 0xFFFFFFFFu ? 0xFFFFFFFFu : (uint32_t)v; }

/* ------------------------------------------------------------------ */
/* Timing helpers (shared with ctl.c through splintd.h).               */
/* ------------------------------------------------------------------ */

uint64_t splintd_now_ns(void)
{
#if defined(__QNX__) || defined(__QNXNTO__)
    /* ClockCycles() is the cheapest monotonic source on QNX; convert with
     * the system page's cycles_per_sec. Split the division so the multiply
     * by 1e9 cannot overflow for long intervals.
     * https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/c/clockcycles.html */
    uint64_t c   = ClockCycles();
    uint64_t cps = SYSPAGE_ENTRY(qtime)->cycles_per_sec;   /* VERIFY-ON-TARGET: qtime entry present */
    if (cps == 0) return 0;
    uint64_t sec = c / cps;
    uint64_t rem = c % cps;
    return sec * 1000000000ULL + (rem * 1000000000ULL) / cps;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

void splintd_record_latency(uint64_t ns)
{
    __atomic_add_fetch(&g_splintd.sum_latency_ns, ns, __ATOMIC_RELAXED);
    uint64_t prev = __atomic_load_n(&g_splintd.max_latency_ns, __ATOMIC_RELAXED);
    while (ns > prev) {
        if (__atomic_compare_exchange_n(&g_splintd.max_latency_ns, &prev, ns,
                                        /*weak*/true, __ATOMIC_RELAXED, __ATOMIC_RELAXED))
            break;
    }
}

/* ------------------------------------------------------------------ */
/* Per-thread scratch buffer for forwarded payloads.                   */
/* ------------------------------------------------------------------ */

static _Thread_local uint8_t tls_iobuf[SPLINTD_IOBUF_MAX];

/* ------------------------------------------------------------------ */
/* Decision accounting (log/learn/latency).                            */
/* ------------------------------------------------------------------ */

/* BLOCK path: always log, record latency, return the errno to reply with.
 * The verdict's rule_id is only valid until this thread's next decide();
 * splint_log_push copies it, and nothing here calls decide() again, so the
 * pointer is still live. */
static int splintd_block_reply(const splint_msg_t *m, const splint_verdict_t *v, uint64_t t0)
{
    uint64_t lat = splintd_now_ns() - t0;
    if (g_splintd.log)
        splint_log_push(g_splintd.log, m, v, clamp_u32(lat));
    splintd_record_latency(lat);
    return v->err ? v->err : EPERM;
}

/* ALLOW path: feed learn, log only if the verdict asked for it, record
 * latency (which spans decide + forward). */
static void splintd_allow_account(const splint_msg_t *m, const splint_verdict_t *v, uint64_t t0)
{
    uint64_t lat = splintd_now_ns() - t0;
    splint_learn_t *lrn = g_splintd.learn;        /* single load; may be swapped on reload */
    if (lrn)
        splint_learn_observe(lrn, m);
    if (v->log && g_splintd.log)
        splint_log_push(g_splintd.log, m, v, clamp_u32(lat));
    splintd_record_latency(lat);
}

/* ------------------------------------------------------------------ */
/* OCB allocation. The resmgr library calls splintd_ocb_calloc through   */
/* the mount's funcs table. For an open driven by our io_open the pending */
/* identity/oflag are stashed in TLS so we can open the backend here and  */
/* surface its errno.                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    splint_client_t client;
    int             oflag;
    int             backend_err;   /* out: errno from splintd_backend_open */
    int             valid;
} splintd_pending_open_t;

static _Thread_local splintd_pending_open_t tls_pending;

/* Map a QNX resource-manager connect ioflag to a POSIX open() oflag. The
 * access mode lives in the low two bits as _IO_FLAG_RD / _IO_FLAG_WR, one
 * higher than POSIX O_RDONLY/O_WRONLY/O_RDWR; other bits (O_NONBLOCK, ...)
 * carry over unchanged. */
static int splintd_ioflag_to_oflag(unsigned ioflag)
{
    unsigned rw = ioflag & (_IO_FLAG_RD | _IO_FLAG_WR);
    if (rw == (_IO_FLAG_RD | _IO_FLAG_WR))
        return O_RDWR;
    if (rw == _IO_FLAG_WR)
        return O_WRONLY;
    return O_RDONLY;   /* _IO_FLAG_RD or none */
}

IOFUNC_OCB_T *splintd_ocb_calloc(resmgr_context_t *ctp, IOFUNC_ATTR_T *attr)
{
    (void)ctp;
    splintd_ocb_t *ocb = calloc(1, sizeof *ocb);
    if (ocb == NULL)
        return NULL;
    ocb->backend_fd = -1;
    ocb->map        = attr;        /* the handle IS the mapping (attr first) */

    if (tls_pending.valid) {
        ocb->client = tls_pending.client;
        int err = splintd_backend_open(ocb, tls_pending.oflag);
        if (err != 0) {
            tls_pending.backend_err = err;
            free(ocb);
            return NULL;           /* iofunc_open_default() -> ENFILE/ENOMEM */
        }
    }
    return ocb;
}

void splintd_ocb_free(IOFUNC_OCB_T *ocb_)
{
    splintd_ocb_t *ocb = ocb_;
    if (ocb == NULL)
        return;
    if (ocb->backend_fd >= 0)       /* defensive: close_ocb normally did this */
        splintd_backend_close(ocb);
    free(ocb);
}

/* ------------------------------------------------------------------ */
/* Handlers.                                                           */
/* ------------------------------------------------------------------ */

/* io_open: resolve the caller, honour the shadow-mode self-check, decide,
 * and only on ALLOW create the OCB + backend fd. */
static int io_open(resmgr_context_t *ctp, io_open_t *msg,
                   RESMGR_HANDLE_T *handle, void *extra)
{
    splintd_mapping_t *map = handle;
    uint64_t t0 = splintd_now_ns();

    splint_client_t client;
    (void)splintd_client_resolve(ctp, 0, &client);   /* fills "?" on failure */

    /* Shadow backend (spike S1): when splintd itself opens the shared path,
     * return ENOENT for our own pid so the open falls through to the real
     * driver attached behind us. */
    if (map->mode == SPLINTD_BACKEND_SHADOW && client.pid == (int32_t)getpid())
        return ENOENT;

    splint_msg_t m;
    memset(&m, 0, sizeof m);
    m.op     = SPLINT_OP_OPEN;
    m.path   = map->public_path;
    m.client = &client;
    m.now_ns = t0;

    splint_verdict_t v;
    splint_engine_decide(g_splintd.engine, &m, &v);

    if (v.action == SPLINT_BLOCK)
        return splintd_block_reply(&m, &v, t0);     /* no OCB, no backend fd */

    /* ALLOW: let iofunc_open_default() bind an OCB; splintd_ocb_calloc()
     * opens the backend using the identity/oflag we stash here. */
    tls_pending.client      = client;
    /* QNX connect ioflag encodes the access mode as _IO_FLAG_RD (1) /
     * _IO_FLAG_WR (2) in the low two bits, offset by one from POSIX
     * O_RDONLY/O_WRONLY/O_RDWR. Translate before handing it to open();
     * passing the raw ioflag made the backend open() fail with EACCES. */
    tls_pending.oflag       = splintd_ioflag_to_oflag(msg->connect.ioflag);
    tls_pending.backend_err = 0;
    tls_pending.valid       = 1;

    int status = iofunc_open_default(ctp, msg, &map->attr, extra);

    tls_pending.valid = 0;

    if (status == EOK) {
        __atomic_add_fetch(&g_splintd.open_clients, 1, __ATOMIC_RELAXED);
        splintd_allow_account(&m, &v, t0);
        return EOK;
    }

    /* Prefer the backend's own errno when that is why the open failed. */
    if (tls_pending.backend_err != 0)
        status = tls_pending.backend_err;
    return status;
}

static int io_read(resmgr_context_t *ctp, io_read_t *msg, RESMGR_OCB_T *ocb_)
{
    splintd_ocb_t *ocb = ocb_;

    int status = iofunc_read_verify(ctp, msg, &ocb->hdr, NULL);
    if (status != EOK)
        return status;
    if ((msg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE)
        return ENOSYS;                 /* no readcond/mount xtypes forwarded */
    if (ocb->backend_fd < 0)
        return EBADF;

    uint64_t t0   = splintd_now_ns();
    size_t   want = _IO_READ_GET_NBYTES(msg);
    if (want > SPLINTD_IOBUF_MAX)
        want = SPLINTD_IOBUF_MAX;      /* bounded by our scratch buffer */

    splint_msg_t m;
    memset(&m, 0, sizeof m);
    m.op       = SPLINT_OP_READ;
    m.path     = ocb->map->public_path;
    m.client   = &ocb->client;
    m.declared = want;                 /* bytes requested; read has no inbound payload */
    m.now_ns   = t0;

    splint_verdict_t v;
    splint_engine_decide(g_splintd.engine, &m, &v);
    if (v.action == SPLINT_BLOCK)
        return splintd_block_reply(&m, &v, t0);

    off_t   off = (off_t)ocb->hdr.offset;
    ssize_t got = splintd_backend_read(ocb, tls_iobuf, want, &off);
    if (got < 0)
        return errno ? errno : EIO;
    ocb->hdr.offset = (off_t)off;

    splintd_allow_account(&m, &v, t0);

    SETIOV(ctp->iov, tls_iobuf, (size_t)got);
    _IO_SET_READ_NBYTES(ctp, got);
    return _RESMGR_NPARTS(got > 0 ? 1 : 0);
}

static int io_write(resmgr_context_t *ctp, io_write_t *msg, RESMGR_OCB_T *ocb_)
{
    splintd_ocb_t *ocb = ocb_;

    int status = iofunc_write_verify(ctp, msg, &ocb->hdr, NULL);
    if (status != EOK)
        return status;
    if ((msg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE)
        return ENOSYS;
    if (ocb->backend_fd < 0)
        return EBADF;

    uint64_t t0       = splintd_now_ns();
    uint64_t declared = _IO_WRITE_GET_NBYTES(msg);   /* client's claim only */

    /* REAL payload length from the transport, never from nbytes. The data
     * component begins sizeof(msg->i) into the current (sub)message. */
    size_t hdr    = sizeof(msg->i);
    size_t srclen = (size_t)ctp->info.srcmsglen;
    size_t real   = 0;
    if (srclen > ctp->offset + hdr)
        real = srclen - ctp->offset - hdr;
    if (real > SPLINTD_IOBUF_MAX)
        return EMSGSIZE;               /* no chunking; a single call is bounded */

    if (real > 0) {
        ssize_t rd = resmgr_msgget(ctp, tls_iobuf, real, hdr);
        if (rd < 0)
            return errno ? errno : EIO;
        if ((size_t)rd < real)
            real = (size_t)rd;         /* only inspect/forward what truly arrived */
    }

    splint_msg_t m;
    memset(&m, 0, sizeof m);
    m.op       = SPLINT_OP_WRITE;
    m.path     = ocb->map->public_path;
    m.client   = &ocb->client;
    m.declared = declared;
    m.len      = real;
    m.data     = tls_iobuf;
    m.data_len = real < SPLINT_INSPECT_MAX ? real : SPLINT_INSPECT_MAX;
    m.now_ns   = t0;

    splint_verdict_t v;
    splint_engine_decide(g_splintd.engine, &m, &v);
    if (v.action == SPLINT_BLOCK)
        return splintd_block_reply(&m, &v, t0);

    ssize_t wr = splintd_backend_write(ocb, tls_iobuf, real);
    if (wr < 0)
        return errno ? errno : EIO;
    ocb->hdr.offset += (off_t)wr;

    splintd_allow_account(&m, &v, t0);

    _IO_SET_WRITE_NBYTES(ctp, wr);
    return _RESMGR_NPARTS(0);
}

static int io_devctl(resmgr_context_t *ctp, io_devctl_t *msg, RESMGR_OCB_T *ocb_)
{
    splintd_ocb_t *ocb = ocb_;
    if (ocb->backend_fd < 0)
        return EBADF;

    uint64_t t0       = splintd_now_ns();
    int      dcmd     = msg->i.dcmd;
    uint64_t declared = msg->i.nbytes;             /* client's claim only */

    /* Incoming (TO) length from the transport, not from nbytes. */
    size_t hdr    = sizeof(msg->i);
    size_t srclen = (size_t)ctp->info.srcmsglen;
    size_t in_real = 0;
    if (srclen > ctp->offset + hdr)
        in_real = srclen - ctp->offset - hdr;
    if (in_real > SPLINTD_IOBUF_MAX)
        return EMSGSIZE;

    /* Reply (FROM) capacity from the client's receive buffer. */
    size_t out_cap = 0;
    if ((size_t)ctp->info.dstmsglen > sizeof(msg->o))
        out_cap = (size_t)ctp->info.dstmsglen - sizeof(msg->o);
    if (out_cap > SPLINTD_IOBUF_MAX)
        out_cap = SPLINTD_IOBUF_MAX;

    /* Size hint encoded in the command (sizeof(data) field, 13 bits). */
    size_t size_hint = ((size_t)((uint32_t)dcmd >> 16)) & 0x1FFFu;

    size_t buf_cap = in_real;
    if (out_cap   > buf_cap) buf_cap = out_cap;
    if (size_hint > buf_cap) buf_cap = size_hint;
    if (buf_cap > SPLINTD_IOBUF_MAX)
        buf_cap = SPLINTD_IOBUF_MAX;

    if (in_real > 0) {
        ssize_t rd = resmgr_msgget(ctp, tls_iobuf, in_real, hdr);
        if (rd < 0)
            return errno ? errno : EIO;
        if ((size_t)rd < in_real)
            in_real = (size_t)rd;
    }

    splint_msg_t m;
    memset(&m, 0, sizeof m);
    m.op       = SPLINT_OP_DEVCTL;
    m.dcmd     = (uint32_t)dcmd;
    m.path     = ocb->map->public_path;
    m.client   = &ocb->client;
    m.declared = declared;
    m.len      = in_real;
    m.data     = tls_iobuf;
    m.data_len = in_real < SPLINT_INSPECT_MAX ? in_real : SPLINT_INSPECT_MAX;
    m.now_ns   = t0;

    splint_verdict_t v;
    splint_engine_decide(g_splintd.engine, &m, &v);
    if (v.action == SPLINT_BLOCK)
        return splintd_block_reply(&m, &v, t0);

    /* Forward. We deliberately do NOT call iofunc_devctl_default() for a
     * forwarded command: it would answer generic DCMD_ALL_* itself instead
     * of letting the real driver respond, which would make splintd lie about
     * the backend. The scratch buffer doubles as the devctl in/out area. */
    int ret_val = 0;
    int err = splintd_backend_devctl(ocb, dcmd, tls_iobuf, in_real, buf_cap, &ret_val);
    if (err != EOK)
        return err;                    /* devctl() returns an errno directly */

    /* How much FROM data to hand back: the command's declared data size,
     * clamped to what the client can receive and what we buffered. */
    size_t out_nbytes = size_hint;
    if (out_nbytes > out_cap) out_nbytes = out_cap;
    if (out_nbytes > buf_cap) out_nbytes = buf_cap;

    memset(&msg->o, 0, sizeof msg->o);
    msg->o.ret_val = ret_val;
    msg->o.nbytes  = (uint32_t)out_nbytes;

    splintd_allow_account(&m, &v, t0);

    /* Reply header + data as two IOV parts (data stays in tls_iobuf). */
    SETIOV(&ctp->iov[0], &msg->o, sizeof msg->o);
    if (out_nbytes > 0) {
        SETIOV(&ctp->iov[1], tls_iobuf, out_nbytes);
        return _RESMGR_NPARTS(2);
    }
    return _RESMGR_NPARTS(1);
}

static int io_lseek(resmgr_context_t *ctp, io_lseek_t *msg, RESMGR_OCB_T *ocb_)
{
    splintd_ocb_t *ocb = ocb_;
    uint64_t t0 = splintd_now_ns();

    splint_msg_t m;
    memset(&m, 0, sizeof m);
    m.op       = SPLINT_OP_LSEEK;
    m.path     = ocb->map->public_path;
    m.client   = &ocb->client;
    m.declared = msg->i.offset;
    m.now_ns   = t0;

    splint_verdict_t v;
    splint_engine_decide(g_splintd.engine, &m, &v);
    if (v.action == SPLINT_BLOCK)
        return splintd_block_reply(&m, &v, t0);

    /* Let the default maintain ocb->offset and build the reply, then mirror
     * the resulting absolute position onto the backend fd (best effort: a
     * character backend may not be seekable). */
    int status = iofunc_lseek_default(ctp, msg, &ocb->hdr);
    if (status == EOK && ocb->backend_fd >= 0)
        (void)splintd_backend_lseek(ocb, (off_t)ocb->hdr.offset, SEEK_SET);

    splintd_allow_account(&m, &v, t0);
    return status;
}

static int io_close_ocb(resmgr_context_t *ctp, void *reserved, RESMGR_OCB_T *ocb_)
{
    splintd_ocb_t *ocb = ocb_;
    int had = (ocb->backend_fd >= 0);
    splintd_backend_close(ocb);            /* idempotent */
    if (had)
        __atomic_sub_fetch(&g_splintd.open_clients, 1, __ATOMIC_RELAXED);
    return iofunc_close_ocb_default(ctp, reserved, &ocb->hdr);
}

/* Raw _IO_MSG passthrough is denied: splintd only speaks the POSIX I/O
 * surface it can reason about. */
static int io_deny_msg(resmgr_context_t *ctp, io_msg_t *msg, RESMGR_OCB_T *ocb)
{
    (void)ctp; (void)msg; (void)ocb;
    return ENOSYS;
}

/* ------------------------------------------------------------------ */
void splintd_interpose_init_funcs(resmgr_connect_funcs_t *cf, resmgr_io_funcs_t *io)
{
    /* iofunc_func_init() installs safe defaults for every slot; we override
     * only the operations splintd mediates.
     * https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/i/iofunc_func_init.html */
    iofunc_func_init(_RESMGR_CONNECT_NFUNCS, cf, _RESMGR_IO_NFUNCS, io);

    cf->open      = io_open;
    io->read      = io_read;
    io->write     = io_write;
    io->devctl    = io_devctl;
    io->lseek     = io_lseek;
    io->close_ocb = io_close_ocb;
    io->msg       = io_deny_msg;
}
