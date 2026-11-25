/* SPDX-License-Identifier: Apache-2.0 */
/*
 * vendor_can - a stand-in for a binary-only Tier-1 CAN gateway driver, for the
 * QSplintNX demo. It is a small QNX resource manager that answers GET_STATUS,
 * SEND_FRAME and SET_FILTER on its path.
 *
 * STATUS: cross-compiled with qcc for QNX 8.0 and validated on a QEMU/KVM target; see docs/qemu-validation.md.
 *
 * It contains ONE deliberate reliability bug (CVE-DEMO-0042): SET_FILTER copies
 * the received payload into a 64-byte filter table without checking the length.
 * The table sits immediately before a guard page with no access, so an oversized
 * payload writes past the table into the guard page and the process takes a
 * clean SIGSEGV and exits. This is a denial-of-service crash, nothing more:
 * there is no function pointer, no controlled overwrite, no code execution. It
 * stands for the kind of unpatchable supplier bug that QSplintNX shields with a
 * one-line virtual patch while the real fix is prepared.
 *
 * Everything other than that one missing check is written carefully.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/iofunc.h>
#include <sys/dispatch.h>

#include "vendor_can_api.h"

#define LOOP_RING 32u   /* loopback frames kept for io_read */

/* Driver state. filter_table points into a guard-paged allocation: the 64 bytes
 * end exactly at an inaccessible page, so a copy longer than 64 bytes faults. */
static struct {
    vcan_status_t status;
    vcan_frame_t  ring[LOOP_RING];
    uint32_t      ring_head, ring_count;
    uint8_t      *filter_table;      /* VCAN_FILTER_TABLE_BYTES usable */
    int           verbose;
} S;

/* Allocate two pages, make the second one inaccessible, and return a pointer
 * such that [p, p+want) are the last `want` bytes before the guard page. */
static uint8_t *guarded_alloc(size_t want)
{
    long pg = sysconf(_SC_PAGESIZE);
    if (pg <= 0)
        pg = 4096;
    size_t page = (size_t)pg;
    uint8_t *base = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANON, -1, 0);
    if (base == MAP_FAILED)
        return NULL;
    if (mprotect(base + page, page, PROT_NONE) != 0) {
        munmap(base, page * 2);
        return NULL;
    }
    return base + (page - want);     /* table ends where the guard page starts */
}

static void loopback_push(const vcan_frame_t *f)
{
    uint32_t idx = (S.ring_head + S.ring_count) % LOOP_RING;
    if (S.ring_count < LOOP_RING)
        S.ring_count++;
    else
        S.ring_head = (S.ring_head + 1) % LOOP_RING;
    S.ring[idx] = *f;
}

/* ------------------------------------------------------------------ */
/* devctl handling                                                     */
/* ------------------------------------------------------------------ */
static int vcan_devctl(resmgr_context_t *ctp, io_devctl_t *msg, RESMGR_OCB_T *ocb)
{
    int status = iofunc_devctl_default(ctp, msg, ocb);
    if (status != _RESMGR_DEFAULT)
        return status;       /* generic DCMD handled by the library */

    void  *data   = _DEVCTL_DATA(msg->i);  /* payload after the header */
    size_t src    = (size_t)ctp->info.srcmsglen;
    size_t in_len = src > sizeof(msg->i) ? src - sizeof(msg->i) : 0;
    int    nbytes = 0;

    switch (msg->i.dcmd) {
    case VCAN_DCMD_GET_STATUS: {
        S.status.filters = S.ring_count ? S.status.filters : S.status.filters;
        memcpy(data, &S.status, sizeof S.status);
        nbytes = sizeof S.status;
        break;
    }
    case VCAN_DCMD_SEND_FRAME: {
        if (in_len < sizeof(vcan_frame_t))
            return EINVAL;
        vcan_frame_t f;
        memcpy(&f, data, sizeof f);
        if (f.dlc > 8)
            return EINVAL;
        S.status.frames_tx++;
        loopback_push(&f);
        S.status.frames_rx++;
        break;
    }
    case VCAN_DCMD_SET_FILTER: {
        /* BUG (demo only, CVE-DEMO-0042): the length of the client's payload is
         * never checked against the 64-byte table. An oversized payload runs off
         * the end of the table into the guard page and the driver takes SIGSEGV.
         * A real driver would reject in_len > VCAN_FILTER_TABLE_BYTES here; this
         * one trusts the supplier and crashes, which is exactly what the
         * QSplintNX virtual patch prevents. */
        memcpy(S.filter_table, data, in_len);       /* <-- the whole point */
        S.status.filters = (uint32_t)(in_len / 8);
        nbytes = 0;
        break;
    }
    case VCAN_DCMD_GET_FILTER: {
        /* Return the whole 64-byte table so a test can confirm exactly what a
         * SET_FILTER forwarded through splintd wrote, including the bytes past
         * the client's payload. Not part of the vulnerable path. */
        memcpy(data, S.filter_table, VCAN_FILTER_TABLE_BYTES);
        nbytes = (int)VCAN_FILTER_TABLE_BYTES;
        break;
    }
    default:
        return ENOTTY;
    }

    memset(&msg->o, 0, sizeof msg->o);
    msg->o.ret_val = EOK;
    msg->o.nbytes  = nbytes;
    return _RESMGR_PTR(ctp, &msg->o, sizeof msg->o + (size_t)nbytes);
}

/* ------------------------------------------------------------------ */
/* read: dump queued loopback frames as text                           */
/* ------------------------------------------------------------------ */
static int vcan_read(resmgr_context_t *ctp, io_read_t *msg, RESMGR_OCB_T *ocb)
{
    int status = iofunc_read_verify(ctp, msg, ocb, NULL);
    if (status != EOK)
        return status;
    if ((msg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE)
        return ENOSYS;

    char line[64];
    int  len = 0;
    if (S.ring_count > 0 && ocb->offset == 0) {
        vcan_frame_t *f = &S.ring[S.ring_head];
        len = snprintf(line, sizeof line, "id=0x%x dlc=%u data=%02x %02x\n",
                       (unsigned)f->id, (unsigned)f->dlc,
                       f->data[0], f->data[1]);
        S.ring_head = (S.ring_head + 1) % LOOP_RING;
        S.ring_count--;
    }

    size_t want = msg->i.nbytes;
    if ((size_t)len > want)
        len = (int)want;
    _IO_SET_READ_NBYTES(ctp, len);
    if (len > 0) {
        ocb->offset += len;
        return _RESMGR_PTR(ctp, line, (size_t)len);
    }
    return _RESMGR_PTR(ctp, line, 0);
}

int main(int argc, char **argv)
{
    const char *path = VCAN_BACKEND_PATH;
    int c;
    while ((c = getopt(argc, argv, "p:v")) != -1) {
        if (c == 'p') path = optarg;
        else if (c == 'v') S.verbose = 1;
        else { fprintf(stderr, "usage: %s [-p path] [-v]\n", argv[0]); return 1; }
    }

    S.filter_table = guarded_alloc(VCAN_FILTER_TABLE_BYTES);
    if (S.filter_table == NULL) {
        fprintf(stderr, "vendor_can: guard allocation failed: %s\n", strerror(errno));
        return 1;
    }
    S.status.bus_state = 1;

    dispatch_t *dpp = dispatch_create();
    if (dpp == NULL) { perror("dispatch_create"); return 1; }

    resmgr_attr_t rattr;
    memset(&rattr, 0, sizeof rattr);
    rattr.nparts_max   = 1;
    rattr.msg_max_size = 2048;

    static resmgr_connect_funcs_t cf;
    static resmgr_io_funcs_t      io;
    iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &cf, _RESMGR_IO_NFUNCS, &io);
    io.devctl = vcan_devctl;
    io.read   = vcan_read;

    static iofunc_attr_t attr;
    iofunc_attr_init(&attr, S_IFCHR | 0666, NULL, NULL);

    if (resmgr_attach(dpp, &rattr, path, _FTYPE_ANY, 0,
                      &cf, &io, &attr) == -1) {
        fprintf(stderr, "vendor_can: attach %s failed: %s\n", path, strerror(errno));
        return 1;
    }

    printf("vendor_can: pid=%d serving %s (filter table %u bytes, guard-paged)\n",
           (int)getpid(), path, VCAN_FILTER_TABLE_BYTES);
    fflush(stdout);

    dispatch_context_t *ctp = dispatch_context_alloc(dpp);
    for (;;) {
        dispatch_context_t *cur = dispatch_block(ctp);
        if (cur == NULL) { perror("dispatch_block"); return 1; }
        dispatch_handler(cur);
    }
}
