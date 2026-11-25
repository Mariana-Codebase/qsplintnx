/* SPDX-License-Identifier: Apache-2.0 */
/*
 * QSplintNX - splintd_main.c
 *
 * Program entry: parse arguments, load the ruleset, attach every PUBLIC
 * mapping and the control node to one dispatch, and run a resmgr thread pool.
 * The main thread stays behind on sigwait() so SIGHUP reloads the ruleset and
 * SIGTERM/SIGINT detach cleanly.
 *
 *   splintd -r <rules> [-m <public>=<backend>]... [-s <public>]...
 *           [-c <ctlpath>] [-t <threads>] [-v]
 *     -m  relocated mapping (driver on a hidden path)
 *     -s  shadow mapping   (driver on the same path, splintd attached BEFORE)
 *
 * STATUS: cross-compiled with qcc for QNX 8.0 (gcc_ntox86_64) and validated on a QEMU/KVM target; see docs/qemu-validation.md.
 *
 * API references verified against the SDP 8.0 documentation:
 *   resmgr_attach / flags   .../r/resmgr_attach.html
 *   secpol_resmgr_attach    .../com.qnx.doc.security.system/topic/secpol_resmgr_attach.html
 *   thread_pool_create      .../t/thread_pool_create.html
 *   resmgr_detach           .../r/resmgr_detach.html
 */

#define IOFUNC_OCB_T        struct splintd_ocb
#define IOFUNC_ATTR_T       struct splintd_mapping
#define THREAD_POOL_PARAM_T dispatch_context_t
#include "splintd.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <getopt.h>
#include <pthread.h>
#include <sys/stat.h>

/* Compile-time switch: QNX 8 recommends secpol_resmgr_attach(); fall back to
 * plain resmgr_attach() when secpol is unavailable.  (Flag for Commander:
 * the `qnx` Makefile target must add -lsecpol when this is 1.) */
#ifndef SPLINT_USE_SECPOL
#define SPLINT_USE_SECPOL 1
#endif
#if SPLINT_USE_SECPOL
#include <secpol/secpol.h>
#endif

#include "splint/splint_sig.h"
#include "splint/splint_pubkey.h"   /* SPLINT_TRUSTED_PUBKEY, compiled in */
#include "splint/identity.h"

/* ------------------------------------------------------------------ */
/* Global state.                                                       */
/* ------------------------------------------------------------------ */

splintd_t g_splintd;

/* Ruleset signature enforcement. On by default: splintd refuses to activate a
 * ruleset whose detached Ed25519 signature does not verify against the
 * compiled-in trusted key. --no-verify turns it off for development only. */
int g_verify_rules = 1;

/* Active-ruleset summary (no engine getter for these); read by ctl.c. */
volatile uint32_t g_active_mode     = 0;
volatile uint32_t g_active_npatch   = 0;
volatile uint32_t g_active_nprofile = 0;

/* Connect/IO tables and the OCB mount, shared by every mapping. */
static resmgr_connect_funcs_t g_cf;
static resmgr_io_funcs_t      g_io;
/* Designated init: zero-fills attr_lock/attr_unlock/attr_trylock (library
 * defaults) and is robust to the field count across QNX header versions. */
static iofunc_funcs_t         g_ocb_funcs = {
    .nfuncs     = _IOFUNC_NFUNCS,
    .ocb_calloc = splintd_ocb_calloc,
    .ocb_free   = splintd_ocb_free,
};
static iofunc_mount_t         g_mount;

/* ------------------------------------------------------------------ */
/* Ruleset load (startup, SIGHUP, and ctl reload all land here).       */
/* ------------------------------------------------------------------ */

/*
 * Verify the detached signature <path>.sig over the loaded rules bytes with the
 * compiled-in trusted key. Returns 0 on success, -1 on any failure (missing or
 * short signature file, or a signature that does not verify). The caller leaves
 * the running ruleset in place when this fails, so an unsigned or tampered
 * ruleset can never become active.
 */
static int splintd_verify_rules_sig(const char *path, const unsigned char *buf,
                                    size_t total, splint_parse_error_t *err)
{
    char sigpath[512];
    int n = snprintf(sigpath, sizeof sigpath, "%s.sig", path);
    if (n < 0 || (size_t)n >= sizeof sigpath) {
        if (err != NULL) snprintf(err->msg, sizeof err->msg, "signature path too long");
        return -1;
    }

    int fd = open(sigpath, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (err != NULL)
            snprintf(err->msg, sizeof err->msg,
                     "no signature %s: %s (ruleset must be signed; see splint-sign)",
                     sigpath, strerror(errno));
        return -1;
    }

    unsigned char sig[SPLINT_SIG_BYTES];
    size_t got = 0;
    while (got < sizeof sig) {
        ssize_t r = read(fd, sig + got, sizeof sig - got);
        if (r < 0) { if (errno == EINTR) continue;
            if (err != NULL) snprintf(err->msg, sizeof err->msg, "read %s: %s", sigpath, strerror(errno));
            (void)close(fd); return -1; }
        if (r == 0) break;
        got += (size_t)r;
    }
    (void)close(fd);
    if (got != sizeof sig) {
        if (err != NULL) snprintf(err->msg, sizeof err->msg, "%s is not a %u-byte signature",
                                  sigpath, (unsigned)SPLINT_SIG_BYTES);
        return -1;
    }

    if (splint_sig_verify(buf, total, sig, SPLINT_TRUSTED_PUBKEY) != 0) {
        if (err != NULL)
            snprintf(err->msg, sizeof err->msg,
                     "signature verification failed for %s (wrong key or tampered ruleset)",
                     path);
        return -1;
    }
    return 0;
}

int splintd_load_rules(const char *path, splint_parse_error_t *err)
{
    if (err != NULL)
        memset(err, 0, sizeof *err);

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (err != NULL)
            snprintf(err->msg, sizeof err->msg, "open %s: %s", path, strerror(errno));
        return -1;
    }

    char *buf = malloc(SPLINT_RULES_FILE_MAX);
    if (buf == NULL) {
        (void)close(fd);
        if (err != NULL)
            snprintf(err->msg, sizeof err->msg, "out of memory");
        return -1;
    }

    size_t total = 0;
    for (;;) {
        if (total >= SPLINT_RULES_FILE_MAX)
            break;
        ssize_t r = read(fd, buf + total, SPLINT_RULES_FILE_MAX - total);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            if (err != NULL)
                snprintf(err->msg, sizeof err->msg, "read %s: %s", path, strerror(errno));
            free(buf);
            (void)close(fd);
            return -1;
        }
        if (r == 0)
            break;
        total += (size_t)r;
    }

    /* Reject a file larger than the cap rather than parsing a truncation. */
    if (total == SPLINT_RULES_FILE_MAX) {
        char probe;
        ssize_t more = read(fd, &probe, 1);
        if (more > 0) {
            if (err != NULL)
                snprintf(err->msg, sizeof err->msg,
                         "rules file exceeds %u bytes", (unsigned)SPLINT_RULES_FILE_MAX);
            free(buf);
            (void)close(fd);
            return -1;
        }
    }
    (void)close(fd);

    /* Verify the ruleset's signature before parsing it, so an unsigned or
     * tampered ruleset never reaches the engine. Skipped only with --no-verify. */
    if (g_verify_rules && splintd_verify_rules_sig(path, (const unsigned char *)buf, total, err) != 0) {
        free(buf);
        return -1;                 /* err filled; running ruleset untouched */
    }

    splint_ruleset_t *rs = NULL;
    int rc = splint_rules_parse(buf, total, &rs, err);
    free(buf);
    if (rc != 0)
        return -1;                 /* parser filled *err; running ruleset untouched */

    /* Capture the summary before the engine takes ownership. */
    uint32_t mode     = (uint32_t)rs->mode;
    uint32_t npatch   = rs->npatch;
    uint32_t nprofile = rs->nprofile;

    /* Learn-table lifecycle. The table is allocated once and never freed while
     * the daemon runs; mode changes only flip the atomic learn_active flag, so
     * a worker that already loaded g_splintd.learn can never have it freed
     * underneath it. Entering learn mode (0 -> 1) starts a clean session. */
    if (mode == SPLINT_MODE_LEARN) {
        if (__atomic_load_n(&g_splintd.learn, __ATOMIC_ACQUIRE) == NULL) {
            splint_learn_t *nl = splint_learn_new(NULL);
            splint_learn_t *expected = NULL;
            if (!__atomic_compare_exchange_n(&g_splintd.learn, &expected, nl,
                                             false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
                /* another thread installed one first; drop ours */
                splint_learn_free(nl);
            }
        }
        if (__atomic_exchange_n(&g_splintd.learn_active, 1, __ATOMIC_ACQ_REL) == 0) {
            splint_learn_t *l = __atomic_load_n(&g_splintd.learn, __ATOMIC_ACQUIRE);
            if (l != NULL)
                splint_learn_reset(l);     /* fresh session; reset is thread-safe */
        }
    } else {
        __atomic_store_n(&g_splintd.learn_active, 0, __ATOMIC_RELEASE);
    }

    splint_engine_set_rules(g_splintd.engine, rs);     /* takes ownership of rs */

    __atomic_store_n(&g_active_mode,     mode,     __ATOMIC_RELAXED);
    __atomic_store_n(&g_active_npatch,   npatch,   __ATOMIC_RELAXED);
    __atomic_store_n(&g_active_nprofile, nprofile, __ATOMIC_RELAXED);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Argument handling.                                                  */
/* ------------------------------------------------------------------ */

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage: %s -r <rules> [-m <public>=<backend>]... [-s <public>]...\n"
        "          [-c <ctlpath>] [-t <threads>] [-v] [--no-verify]\n"
        "  rulesets must carry a valid Ed25519 signature (<rules>.sig);\n"
        "  --no-verify disables signature checking (development only)\n",
        argv0);
}

static int add_mapping(const char *spec, splintd_backend_mode_t mode)
{
    if (g_splintd.nmap >= SPLINTD_MAX_MAPPINGS) {
        fprintf(stderr, "splintd: too many mappings (max %d)\n", SPLINTD_MAX_MAPPINGS);
        return -1;
    }
    splintd_mapping_t *m = &g_splintd.map[g_splintd.nmap];

    if (mode == SPLINTD_BACKEND_RELOCATED) {
        const char *eq = strchr(spec, '=');
        if (eq == NULL || eq == spec || eq[1] == '\0') {
            fprintf(stderr, "splintd: bad -m '%s' (want public=backend)\n", spec);
            return -1;
        }
        size_t plen = (size_t)(eq - spec);
        if (plen >= SPLINT_PATH_MAX || strlen(eq + 1) >= SPLINT_PATH_MAX) {
            fprintf(stderr, "splintd: path too long in '%s'\n", spec);
            return -1;
        }
        memcpy(m->public_path, spec, plen);
        m->public_path[plen] = '\0';
        snprintf(m->backend_path, sizeof m->backend_path, "%s", eq + 1);
    } else {
        if (strlen(spec) >= SPLINT_PATH_MAX) {
            fprintf(stderr, "splintd: path too long '%s'\n", spec);
            return -1;
        }
        snprintf(m->public_path,  sizeof m->public_path,  "%s", spec);
        snprintf(m->backend_path, sizeof m->backend_path, "%s", spec);   /* same path */
    }
    m->mode    = mode;
    m->link_id = -1;
    g_splintd.nmap++;
    return 0;
}

static int attach_mapping(splintd_mapping_t *m)
{
    /* 0666 character device; secpol (not the mode bits) is what actually
     * closes the bypass, see docs/PLAN.md spike S2. */
    iofunc_attr_init(&m->attr, S_IFCHR | 0666, NULL, NULL);
    m->attr.mount = &g_mount;

    unsigned flags = (m->mode == SPLINTD_BACKEND_SHADOW) ? _RESMGR_FLAG_BEFORE : 0u;

    resmgr_attr_t rattr;
    memset(&rattr, 0, sizeof rattr);
    rattr.nparts_max   = 2;        /* devctl/read reply: header + data */
    rattr.msg_max_size = 4096;     /* payloads pulled with resmgr_msgget() */

    int id;
#if SPLINT_USE_SECPOL
    bool perms_set = false;
    id = secpol_resmgr_attach(NULL, g_splintd.dpp, &rattr, m->public_path,
                              _FTYPE_ANY, flags, &g_cf, &g_io, &m->attr, &perms_set);
#else
    id = resmgr_attach(g_splintd.dpp, &rattr, m->public_path, _FTYPE_ANY,
                       flags, &g_cf, &g_io, m);
#endif
    if (id == -1)
        return -1;
    m->link_id = id;
    return 0;
}

/* Create and start a resmgr thread pool bound to dispatch dpp. Returns 0 on
 * success. flags 0 => thread_pool_start() returns and the caller continues. */
static int start_resmgr_pool(dispatch_t *dpp, const char *name,
                             unsigned lo, unsigned hi)
{
    thread_pool_attr_t pa;
    memset(&pa, 0, sizeof pa);
    pa.handle        = dpp;
    pa.context_alloc = (void *)dispatch_context_alloc;
    pa.context_free  = (void *)dispatch_context_free;
    pa.block_func    = (void *)dispatch_block;
    pa.unblock_func  = (void *)dispatch_unblock;
    pa.handler_func  = (void *)dispatch_handler;
    pa.tid_name      = name;
    pa.lo_water      = lo;
    pa.hi_water      = hi;
    pa.increment     = 1;
    pa.maximum       = hi;

    thread_pool_t *tpp = thread_pool_create(&pa, 0);
    if (tpp == NULL) {
        fprintf(stderr, "splintd: thread_pool_create (%s): %s\n", name, strerror(errno));
        return -1;
    }
    if (thread_pool_start(tpp) != 0) {
        fprintf(stderr, "splintd: thread_pool_start (%s): %s\n", name, strerror(errno));
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
int main(int argc, char **argv)
{
    const char *rules   = NULL;
    const char *ctlpath = SPLINT_CTL_DEFAULT_PATH;
    int         threads = 4;
    int         opt;

    static const struct option longopts[] = {
        { "no-verify", no_argument, NULL, 'N' },
        { "version",   no_argument, NULL, 'Q' },
        { NULL, 0, NULL, 0 }
    };
    while ((opt = getopt_long(argc, argv, "r:m:s:c:t:v", longopts, NULL)) != -1) {
        switch (opt) {
        case 'r': rules = optarg; break;
        case 'm': if (add_mapping(optarg, SPLINTD_BACKEND_RELOCATED) != 0) return 1; break;
        case 's': if (add_mapping(optarg, SPLINTD_BACKEND_SHADOW)    != 0) return 1; break;
        case 'c': ctlpath = optarg; break;
        case 't': threads = atoi(optarg); break;
        case 'v': g_splintd.verbose++; break;
        case 'N': g_verify_rules = 0; break;
        case 'Q': splint_print_version(stdout, "splintd"); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    if (rules == NULL) {
        fprintf(stderr, "splintd: -r <rules> is required\n");
        usage(argv[0]);
        return 1;
    }
    if (g_splintd.nmap == 0) {
        fprintf(stderr, "splintd: at least one -m or -s mapping is required\n");
        usage(argv[0]);
        return 1;
    }
    if (threads < 1)
        threads = 1;

    snprintf(g_splintd.rules_path, sizeof g_splintd.rules_path, "%s", rules);
    snprintf(g_splintd.ctl_path,   sizeof g_splintd.ctl_path,   "%s", ctlpath);

    g_splintd.engine = splint_engine_new();
    g_splintd.log    = splint_log_new(1024);
    if (g_splintd.engine == NULL || g_splintd.log == NULL) {
        fprintf(stderr, "splintd: engine/log init failed\n");
        return 1;
    }

    splint_parse_error_t perr;
    if (splintd_load_rules(rules, &perr) != 0) {
        fprintf(stderr, "splintd: rules %s: line %u col %u: %s\n",
                rules, perr.line, perr.col, perr.msg);
        return 1;
    }
    fprintf(stderr, "splintd: %s; ruleset %s %s\n", splint_identity(), rules,
            g_verify_rules ? "signature verified (provenance OK)"
                           : "loaded WITHOUT signature check (--no-verify)");

    g_splintd.dpp = dispatch_create();
    if (g_splintd.dpp == NULL) {
        fprintf(stderr, "splintd: dispatch_create: %s\n", strerror(errno));
        return 1;
    }

    splintd_interpose_init_funcs(&g_cf, &g_io);

    iofunc_mount_init(&g_mount, sizeof g_mount);
    g_mount.funcs = &g_ocb_funcs;

    for (int i = 0; i < g_splintd.nmap; i++) {
        if (attach_mapping(&g_splintd.map[i]) != 0) {
            fprintf(stderr, "splintd: attach %s: %s\n",
                    g_splintd.map[i].public_path, strerror(errno));
            return 1;
        }
    }

    /* The control node lives on its OWN dispatch, hence its own channel, so a
     * security policy can type that channel (splint_ctl_t) and let only
     * splintctl connect to it. Sharing splintd's data-path channel would let
     * any client of a protected device reach the control node at the channel
     * level; a separate channel removes that. */
    g_splintd.ctl_dpp = dispatch_create();
    if (g_splintd.ctl_dpp == NULL) {
        fprintf(stderr, "splintd: dispatch_create (ctl): %s\n", strerror(errno));
        return 1;
    }
    int crc = splintd_ctl_attach(g_splintd.ctl_dpp, g_splintd.ctl_path);
    if (crc != 0) {
        fprintf(stderr, "splintd: ctl attach %s: %s\n", g_splintd.ctl_path, strerror(crc));
        return 1;
    }

    /* Block the signals we act on so the worker threads inherit the mask;
     * only this thread handles them, through sigwait(). */
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGHUP);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    /* Data-path pool, and a small separate pool for the control channel. */
    if (start_resmgr_pool(g_splintd.dpp, "splintd",
                          (threads < 2) ? 1u : 2u, (unsigned)threads) != 0)
        return 1;
    if (start_resmgr_pool(g_splintd.ctl_dpp, "splintd-ctl", 1u, 2u) != 0)
        return 1;

    if (g_splintd.verbose)
        fprintf(stderr, "splintd: %d mapping(s), ctl %s, %d thread(s)\n",
                g_splintd.nmap, g_splintd.ctl_path, threads);

    for (;;) {
        int sig = 0;
        if (sigwait(&set, &sig) != 0)
            continue;
        if (sig == SIGHUP) {
            splint_parse_error_t e;
            if (splintd_load_rules(g_splintd.rules_path, &e) == 0)
                fprintf(stderr, "splintd: reloaded %s\n", g_splintd.rules_path);
            else
                fprintf(stderr, "splintd: reload %s failed: line %u: %s\n",
                        g_splintd.rules_path, e.line, e.msg);
            continue;
        }
        break;   /* SIGTERM / SIGINT: detach and exit */
    }

    for (int i = 0; i < g_splintd.nmap; i++)
        (void)resmgr_detach(g_splintd.dpp, g_splintd.map[i].link_id, _RESMGR_DETACH_ALL);

    if (g_splintd.verbose)
        fprintf(stderr, "splintd: detached, exiting\n");
    return 0;
}
