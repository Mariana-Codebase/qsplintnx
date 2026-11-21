/* SPDX-License-Identifier: Apache-2.0 */
/*
 * splintctl - command-line client for splintd's control node.
 *
 * STATUS: cross-compiled with qcc for QNX 8.0 (gcc_ntox86_64) and validated on a QEMU/KVM target; see docs/qemu-validation.md.
 *
 *   splintctl [-c ctlpath] reload <rules-file>
 *   splintctl [-c ctlpath] stats
 *   splintctl [-c ctlpath] events [-f] [-n N]
 *   splintctl [-c ctlpath] learn-dump <out-file>
 *
 * Every command opens the control node (default SPLINT_CTL_DEFAULT_PATH)
 * and issues one or more devctl() calls with the structures declared in
 * include/splint/ctl.h. Under secpol only the ctl client type may connect
 * to splintd, see tools/secpolgen.
 *
 * devctl() (QNX 8.0 lib ref, <devctl.h>) returns EOK on success or an
 * errno value directly; it does not return -1 and set errno. All calls
 * below treat the return value as the error number.
 * https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/d/devctl.html
 *
 * Paths handed to splintd (reload, learn-dump) are made absolute here,
 * because splintd opens them itself with its own working directory and
 * its own credentials.
 *
 * Exit status: 0 success, 1 command failed (parse error, devctl error),
 * 2 usage error.
 *
 * Built by `make qnx` together with src/core/log.c (splint_event_format)
 * and src/core/msg.c (splint_op_name) only.
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if defined(__QNX__) || defined(__QNXNTO__)
#include <devctl.h>
#endif

#include "splint/ctl.h"
#include "splint/engine.h"
#include "splint/log.h"
#include "splint/rules.h"

#ifndef EOK
#define EOK 0
#endif

#define FOLLOW_PERIOD_NS (200L * 1000L * 1000L)  /* events -f poll period */
#define TAIL_MAX         100000u                 /* upper bound for -n    */

static const char *g_prog = "splintctl";
static volatile sig_atomic_t g_stop;

static void usage(FILE *f)
{
    fprintf(f,
        "usage: %s [-c ctlpath] <command> [args]\n"
        "commands:\n"
        "  reload <rules-file>      parse and activate a rules file (path is made absolute)\n"
        "  stats                    print engine and daemon counters\n"
        "  events [-f] [-n N]       print logged events; -n N shows only the last N,\n"
        "                           -f keeps polling every 200 ms until interrupted\n"
        "  learn-dump <out-file>    ask splintd to write learned profiles to out-file\n"
        "default ctlpath: %s\n",
        g_prog, SPLINT_CTL_DEFAULT_PATH);
}

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static int ctl_open(const char *ctlpath)
{
    int fd = open(ctlpath, O_RDWR);
    if (fd < 0)
        fprintf(stderr, "%s: cannot open %s: %s\n", g_prog, ctlpath, strerror(errno));
    return fd;
}

/* Thin wrapper so every call site reports errors the same way. */
static int ctl_devctl(int fd, int dcmd, void *data, size_t n, const char *what)
{
    int rc = devctl(fd, dcmd, data, n, NULL);
    if (rc != EOK)
        fprintf(stderr, "%s: %s: devctl failed: %s\n", g_prog, what, strerror(rc));
    return rc;
}

/*
 * Make `in` absolute without requiring it to exist (learn-dump targets a
 * file that may not exist yet). No normalisation of "..": splintd gets
 * the same path the user meant relative to our cwd.
 */
static int make_absolute(const char *in, char *out, size_t cap)
{
    int n;

    if (in[0] == '/') {
        n = snprintf(out, cap, "%s", in);
    } else {
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof cwd) == NULL) {
            fprintf(stderr, "%s: getcwd: %s\n", g_prog, strerror(errno));
            return -1;
        }
        n = snprintf(out, cap, "%s/%s", cwd, in);
    }
    if (n < 0 || (size_t)n >= cap) {
        fprintf(stderr, "%s: path too long (max %zu bytes): %s\n", g_prog, cap - 1, in);
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------- reload -- */
static int cmd_reload(int fd, int argc, char **argv)
{
    splint_ctl_reload_t r;

    if (argc != 1) {
        usage(stderr);
        return 2;
    }
    memset(&r, 0, sizeof r);
    if (make_absolute(argv[0], r.path, sizeof r.path) != 0)
        return 1;
    if (access(r.path, R_OK) != 0)
        fprintf(stderr, "%s: warning: %s: %s (splintd may still be able to read it)\n",
                g_prog, r.path, strerror(errno));

    if (ctl_devctl(fd, SPLINT_DCMD_RELOAD, &r, sizeof r, "reload") != EOK)
        return 1;

    if (r.status != 0) {
        r.err_msg[sizeof r.err_msg - 1] = '\0';
        printf("error at line %u col %u: %s\n", (unsigned)r.err_line,
               (unsigned)r.err_col, r.err_msg);
        return 1;
    }
    printf("OK\n");
    return 0;
}

/* -------------------------------------------------------------- stats -- */
static const char *mode_name(uint32_t mode)
{
    switch (mode) {
    case SPLINT_MODE_ENFORCE: return "enforce";
    case SPLINT_MODE_LEARN:   return "learn";
    default:                  return "?";
    }
}

static int cmd_stats(int fd, int argc, char **argv)
{
    splint_ctl_stats_t s;
    const splint_engine_stats_t *e = &s.engine;
    (void)argv;

    if (argc != 0) {
        usage(stderr);
        return 2;
    }
    memset(&s, 0, sizeof s);
    if (ctl_devctl(fd, SPLINT_DCMD_STATS, &s, sizeof s, "stats") != EOK)
        return 1;

    printf("mode            %s\n", mode_name(s.mode));
    printf("patches         %u\n", (unsigned)s.npatch);
    printf("profiles        %u\n", (unsigned)s.nprofile);
    printf("open clients    %llu\n", (unsigned long long)s.open_clients);
    printf("decided         %llu\n", (unsigned long long)e->decided);
    printf("  allowed       %llu\n", (unsigned long long)e->allowed);
    printf("  blocked       %llu\n", (unsigned long long)e->blocked);
    printf("  rate limited  %llu\n", (unsigned long long)e->rate_limited);
    printf("  would block   %llu\n", (unsigned long long)e->would_block);
    printf("logged          %llu\n", (unsigned long long)e->logged);
    printf("forward errors  %llu\n", (unsigned long long)s.forward_errors);
    if (e->decided > 0)
        printf("latency mean    %llu ns\n",
               (unsigned long long)(s.sum_latency_ns / e->decided));
    else
        printf("latency mean    n/a\n");
    printf("latency max     %llu ns\n", (unsigned long long)s.max_latency_ns);
    return 0;
}

/* ------------------------------------------------------------- events -- */
static void print_event(const splint_event_t *ev)
{
    char line[512];
    size_t n = splint_event_format(ev, line, sizeof line);
    (void)n;  /* truncated lines are still useful; format NUL-terminates */
    puts(line);
}

/* Fetch one batch with seq > *last. Returns count, or -1 on error. */
static int fetch_batch(int fd, uint64_t after, splint_ctl_events_t *b)
{
    memset(b, 0, sizeof *b);
    b->after_seq = after;
    if (ctl_devctl(fd, SPLINT_DCMD_EVENTS, b, sizeof *b, "events") != EOK)
        return -1;
    if (b->count > SPLINT_CTL_EVENTS_BATCH) {
        fprintf(stderr, "%s: events: bogus count %u from splintd\n", g_prog,
                (unsigned)b->count);
        return -1;
    }
    return (int)b->count;
}

static void report_gap(uint64_t last, uint64_t next)
{
    if (last != 0 && next > last + 1)
        printf("# %llu event(s) lost (ring overwritten)\n",
               (unsigned long long)(next - last - 1));
}

static int cmd_events(int fd, int argc, char **argv)
{
    int follow = 0;
    unsigned long tail = 0;           /* 0: print everything */
    splint_event_t *ring = NULL;      /* last `tail` events while draining */
    unsigned long ring_n = 0, ring_head = 0;
    splint_ctl_events_t b;
    uint64_t last = 0;
    int i, rc = 0;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0) {
            follow = 1;
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            char *end;
            errno = 0;
            tail = strtoul(argv[++i], &end, 10);
            if (errno != 0 || *end != '\0' || tail == 0 || tail > TAIL_MAX) {
                fprintf(stderr, "%s: -n expects 1..%u\n", g_prog, TAIL_MAX);
                return 2;
            }
        } else {
            usage(stderr);
            return 2;
        }
    }

    if (tail > 0) {
        ring = calloc(tail, sizeof *ring);
        if (ring == NULL) {
            fprintf(stderr, "%s: out of memory\n", g_prog);
            return 1;
        }
    }

    /* Phase 1: drain the backlog from after_seq = 0. */
    for (;;) {
        int n = fetch_batch(fd, last, &b);
        if (n < 0) {
            rc = 1;
            goto out;
        }
        for (i = 0; i < n; i++) {
            if (ring != NULL) {
                ring[(ring_head + ring_n) % tail] = b.ev[i];
                if (ring_n < tail)
                    ring_n++;
                else
                    ring_head = (ring_head + 1) % tail;
            } else {
                report_gap(last, b.ev[i].seq);
                print_event(&b.ev[i]);
            }
            last = b.ev[i].seq;
        }
        if ((unsigned)n < SPLINT_CTL_EVENTS_BATCH || g_stop)
            break;
    }
    for (unsigned long k = 0; k < ring_n; k++)
        print_event(&ring[(ring_head + k) % tail]);
    fflush(stdout);

    /* Phase 2 (-f): poll every 200 ms until SIGINT/SIGTERM. */
    while (follow && !g_stop) {
        struct timespec ts = { 0, FOLLOW_PERIOD_NS };
        int n = fetch_batch(fd, last, &b);
        if (n < 0) {
            rc = 1;
            break;
        }
        for (i = 0; i < n; i++) {
            report_gap(last, b.ev[i].seq);
            print_event(&b.ev[i]);
            last = b.ev[i].seq;
        }
        fflush(stdout);
        if ((unsigned)n < SPLINT_CTL_EVENTS_BATCH)
            nanosleep(&ts, NULL);  /* EINTR on signal is fine: loop checks g_stop */
    }
out:
    free(ring);
    return rc;
}

/* --------------------------------------------------------- learn-dump -- */
static int cmd_learn_dump(int fd, int argc, char **argv)
{
    splint_ctl_learn_dump_t d;

    if (argc != 1) {
        usage(stderr);
        return 2;
    }
    memset(&d, 0, sizeof d);
    if (make_absolute(argv[0], d.path, sizeof d.path) != 0)
        return 1;
    if (ctl_devctl(fd, SPLINT_DCMD_LEARN_DUMP, &d, sizeof d, "learn-dump") != EOK)
        return 1;
    if (d.status != 0) {
        fprintf(stderr, "%s: learn-dump: splintd could not write %s: %s\n",
                g_prog, d.path, strerror(d.status));
        return 1;
    }
    printf("wrote %u bytes to %s\n", (unsigned)d.bytes, d.path);
    return 0;
}

/* --------------------------------------------------------------- main -- */
int main(int argc, char **argv)
{
    const char *ctlpath = SPLINT_CTL_DEFAULT_PATH;
    const char *cmd;
    struct sigaction sa;
    int argi = 1, fd, rc;

    if (argc > 0 && argv[0] != NULL) {
        const char *slash = strrchr(argv[0], '/');
        g_prog = slash ? slash + 1 : argv[0];
    }

    /* Global options come before the command; parsed by hand so that
     * command options (-f, -n) are not reordered by getopt. */
    while (argi < argc && argv[argi][0] == '-') {
        if (strcmp(argv[argi], "-c") == 0 && argi + 1 < argc) {
            ctlpath = argv[argi + 1];
            argi += 2;
        } else if (strcmp(argv[argi], "-h") == 0 || strcmp(argv[argi], "--help") == 0) {
            usage(stdout);
            return 0;
        } else {
            usage(stderr);
            return 2;
        }
    }
    if (argi >= argc) {
        usage(stderr);
        return 2;
    }
    cmd = argv[argi++];

    if (strcmp(cmd, "reload") != 0 && strcmp(cmd, "stats") != 0 &&
        strcmp(cmd, "events") != 0 && strcmp(cmd, "learn-dump") != 0) {
        fprintf(stderr, "%s: unknown command '%s'\n", g_prog, cmd);
        usage(stderr);
        return 2;
    }

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    fd = ctl_open(ctlpath);
    if (fd < 0)
        return 1;

    if (strcmp(cmd, "reload") == 0)
        rc = cmd_reload(fd, argc - argi, argv + argi);
    else if (strcmp(cmd, "stats") == 0)
        rc = cmd_stats(fd, argc - argi, argv + argi);
    else if (strcmp(cmd, "events") == 0)
        rc = cmd_events(fd, argc - argi, argv + argi);
    else
        rc = cmd_learn_dump(fd, argc - argi, argv + argi);

    close(fd);
    return rc;
}
