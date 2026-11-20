/* SPDX-License-Identifier: Apache-2.0 */
/*
 * bench_ipc - round-trip latency of devctl() to vendor_can, directly on the
 * backend path and through splintd on the public path.
 *
 * STATUS: written against QNX SDP 8.0 docs, not yet compiled on target.
 *
 * usage: bench_ipc [-n iterations] [-w warmup] [-b backend|none] [-P public]
 *                  [-p priority] [-o raw.csv]
 *
 *   -n  timed calls per (path, op) series, default 100000
 *   -w  untimed warm-up calls per series, default 1000
 *   -b  backend path (default VCAN_BACKEND_PATH); "none" skips the direct
 *       series, e.g. on a secpol image where this process may not connect
 *       to the driver
 *   -P  public path served by splintd (default VCAN_PUBLIC_PATH)
 *   -p  run the calling thread SCHED_FIFO at this priority (1..255;
 *       64 and above need the PROCMGR_AID_PRIORITY ability)
 *   -o  also write every sample as CSV: path,op,iter,ns
 *
 * Ops measured per path:
 *   get_status   devctl(VCAN_DCMD_GET_STATUS), FROM-only, 16-byte reply
 *   set_filter   devctl(VCAN_DCMD_SET_FILTER) with a 32-byte payload (below
 *                the 64-byte table, so the demo patch must allow it)
 *
 * Every call is timed with ClockCycles() and converted with
 * SYSPAGE_ENTRY(qtime)->cycles_per_sec. stdout gets one summary CSV row
 * per series, then the overhead of splintd (public - backend) for each op.
 *
 * QNX references (8.0):
 *   devctl():     returns EOK or an errno value (not -1/errno)
 *     https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/d/devctl.html
 *   ClockCycles(): <sys/neutrino.h>, counter synchronised across CPUs
 *     https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/c/clockcycles.html
 *   SYSPAGE_ENTRY(): <sys/syspage.h>
 *     https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/s/syspage_entry.html
 */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <devctl.h>
#include <sys/neutrino.h>
#include <sys/syspage.h>

#include "vendor_can_api.h"

#ifndef EOK
#define EOK 0
#endif

#define FILTER_BYTES 32u

enum { OP_GET_STATUS = 0, OP_SET_FILTER, OP_COUNT };
static const char *const op_names[OP_COUNT] = { "get_status", "set_filter" };

typedef struct series {
    const char *path;
    int         op;
    uint64_t   *ns;       /* n samples, sorted after the run */
    uint32_t    n;
    uint32_t    errors;
    int         first_err;
    int         valid;
} series_t;

static uint64_t g_cps;    /* ClockCycles() increments per second */

static void usage(FILE *f)
{
    fprintf(f, "usage: bench_ipc [-n iterations] [-w warmup] [-b backend|none] "
               "[-P public] [-p priority] [-o raw.csv]\n");
}

static uint64_t cycles_to_ns(uint64_t c)
{
    /* double keeps 53 bits: exact for any single-call latency */
    return (uint64_t)((double)c * 1e9 / (double)g_cps + 0.5);
}

static int do_op(int fd, int op, uint8_t *buf)
{
    if (op == OP_GET_STATUS) {
        vcan_status_t st;
        return devctl(fd, VCAN_DCMD_GET_STATUS, &st, sizeof st, NULL);
    }
    return devctl(fd, VCAN_DCMD_SET_FILTER, buf, FILTER_BYTES, NULL);
}

static int run_series(series_t *s, uint32_t warmup)
{
    uint8_t buf[FILTER_BYTES];
    int fd;

    memset(buf, 0, sizeof buf);
    fd = open(s->path, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "bench_ipc: open %s: %s\n", s->path, strerror(errno));
        return -1;
    }
    for (uint32_t i = 0; i < warmup; i++)
        (void)do_op(fd, s->op, buf);

    for (uint32_t i = 0; i < s->n; i++) {
        uint64_t t0 = ClockCycles();
        int rc = do_op(fd, s->op, buf);
        uint64_t t1 = ClockCycles();
        s->ns[i] = cycles_to_ns(t1 - t0);
        if (rc != EOK) {
            if (s->errors++ == 0)
                s->first_err = rc;
        }
    }
    close(fd);
    s->valid = 1;
    if (s->errors > 0)
        fprintf(stderr, "bench_ipc: %s %s: %" PRIu32 " of %" PRIu32 " calls failed, first: %s\n",
                s->path, op_names[s->op], s->errors, s->n, strerror(s->first_err));
    return 0;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static uint64_t pct(const series_t *s, double p)   /* nearest rank, sorted */
{
    size_t r = (size_t)(p / 100.0 * (double)s->n + 0.999999);
    if (r < 1)
        r = 1;
    if (r > s->n)
        r = s->n;
    return s->ns[r - 1];
}

static int set_fifo(int prio)
{
    struct sched_param sp;
    int rc;

    memset(&sp, 0, sizeof sp);
    sp.sched_priority = prio;
    rc = pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);
    if (rc != EOK) {
        fprintf(stderr, "bench_ipc: SCHED_FIFO priority %d: %s\n", prio, strerror(rc));
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    uint32_t n = 100000, warmup = 1000;
    const char *backend = VCAN_BACKEND_PATH, *public_path = VCAN_PUBLIC_PATH;
    const char *raw_path = NULL;
    int prio = 0, opt, rc = 0;
    series_t ser[2][OP_COUNT];      /* [0] backend, [1] public */
    FILE *raw = NULL;

    while ((opt = getopt(argc, argv, "n:w:b:P:p:o:h")) != -1) {
        char *end = NULL;
        unsigned long v;
        switch (opt) {
        case 'n':
        case 'w':
        case 'p':
            errno = 0;
            v = strtoul(optarg, &end, 10);
            if (errno != 0 || *end != '\0' || (opt == 'n' && (v == 0 || v > 100000000ul)) ||
                (opt == 'w' && v > 100000000ul) || (opt == 'p' && (v < 1 || v > 255))) {
                fprintf(stderr, "bench_ipc: bad value for -%c: %s\n", opt, optarg);
                return 2;
            }
            if (opt == 'n')
                n = (uint32_t)v;
            else if (opt == 'w')
                warmup = (uint32_t)v;
            else
                prio = (int)v;
            break;
        case 'b': backend = optarg; break;
        case 'P': public_path = optarg; break;
        case 'o': raw_path = optarg; break;
        case 'h': usage(stdout); return 0;
        default:  usage(stderr); return 2;
        }
    }
    if (optind != argc) {
        usage(stderr);
        return 2;
    }

    g_cps = SYSPAGE_ENTRY(qtime)->cycles_per_sec;
    if (g_cps == 0) {
        fprintf(stderr, "bench_ipc: cycles_per_sec is 0\n");
        return 1;
    }
    if (prio > 0 && set_fifo(prio) != 0)
        return 1;

    memset(ser, 0, sizeof ser);
    for (int p = 0; p < 2; p++) {
        for (int o = 0; o < OP_COUNT; o++) {
            series_t *s = &ser[p][o];
            s->path = p == 0 ? backend : public_path;
            s->op = o;
            s->n = n;
            if (p == 0 && strcmp(backend, "none") == 0)
                continue;
            s->ns = malloc((size_t)n * sizeof *s->ns);
            if (s->ns == NULL) {
                fprintf(stderr, "bench_ipc: out of memory\n");
                return 1;
            }
            if (run_series(s, warmup) != 0)
                rc = 1;
        }
    }

    if (raw_path != NULL) {
        raw = fopen(raw_path, "w");
        if (raw == NULL) {
            fprintf(stderr, "bench_ipc: %s: %s\n", raw_path, strerror(errno));
            rc = 1;
        } else {
            fprintf(raw, "path,op,iter,ns\n");
        }
    }

    printf("# cycles_per_sec=%" PRIu64 " n=%" PRIu32 " warmup=%" PRIu32 " policy=%s prio=%d\n",
           g_cps, n, warmup, prio > 0 ? "SCHED_FIFO" : "inherited", prio);
    printf("path,op,n,errors,min_ns,p50_ns,p99_ns,max_ns\n");
    for (int p = 0; p < 2; p++) {
        for (int o = 0; o < OP_COUNT; o++) {
            series_t *s = &ser[p][o];
            if (!s->valid)
                continue;
            if (raw != NULL)
                for (uint32_t i = 0; i < s->n; i++)
                    fprintf(raw, "%s,%s,%" PRIu32 ",%" PRIu64 "\n", s->path, op_names[o], i, s->ns[i]);
            qsort(s->ns, s->n, sizeof *s->ns, cmp_u64);
            printf("%s,%s,%" PRIu32 ",%" PRIu32 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
                   s->path, op_names[o], s->n, s->errors, s->ns[0], pct(s, 50.0),
                   pct(s, 99.0), s->ns[s->n - 1]);
        }
    }
    if (raw != NULL && fclose(raw) != 0) {
        fprintf(stderr, "bench_ipc: %s: write error\n", raw_path);
        rc = 1;
    }

    printf("\n# overhead of splintd (public - backend), ns\n");
    for (int o = 0; o < OP_COUNT; o++) {
        const series_t *a = &ser[0][o], *b = &ser[1][o];
        if (!a->valid || !b->valid) {
            printf("# %-10s n/a (need both series)\n", op_names[o]);
            continue;
        }
        printf("# %-10s min %+" PRId64 "  p50 %+" PRId64 "  p99 %+" PRId64 "  max %+" PRId64 "\n",
               op_names[o],
               (int64_t)b->ns[0] - (int64_t)a->ns[0],
               (int64_t)pct(b, 50.0) - (int64_t)pct(a, 50.0),
               (int64_t)pct(b, 99.0) - (int64_t)pct(a, 99.0),
               (int64_t)b->ns[b->n - 1] - (int64_t)a->ns[a->n - 1]);
    }

    for (int p = 0; p < 2; p++)
        for (int o = 0; o < OP_COUNT; o++)
            free(ser[p][o].ns);
    return rc;
}
