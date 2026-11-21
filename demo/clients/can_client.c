/* SPDX-License-Identifier: Apache-2.0 */
/*
 * can_client - a well-behaved ECU-like client for the QSplintNX demo.
 *
 * STATUS: cross-compiled with qcc for QNX 8.0 (gcc_ntox86_64) and validated on a QEMU/KVM target; see docs/qemu-validation.md.
 *
 * It opens the public CAN path, reads status, installs a short (legal) filter,
 * then sends frames at a steady rate and prints one status line per second.
 * This is the "normal traffic" that must keep working while splintd blocks the
 * exploit.
 *
 * devctl() returns the error code directly (0/EOK on success), not -1 with
 * errno set - see lib_ref/d/devctl.html. We treat its return value that way.
 *
 * Options:
 *   -p <path>   device path (default VCAN_PUBLIC_PATH)
 *   -r <hz>     send rate in frames/second (default 50)
 *   -n <count>  number of frames to send, 0 = forever (default 0)
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/types.h>

#if defined(__QNX__) || defined(__QNXNTO__)
#include <devctl.h>
#else
/* Host fallback so this file syntax-checks without the SDP. devctl() is only
 * really available on QNX; the fallback lets `gcc -fsyntax-only` run. */
#include <sys/ioctl.h>
static int devctl(int fd, int dcmd, void *data, size_t n, int *info)
{
    (void)fd; (void)dcmd; (void)data; (void)n; (void)info;
    return ENOSYS;
}
#endif

#include "vendor_can_api.h"

static void sleep_hz(unsigned hz)
{
    if (hz == 0u) {
        return;
    }
    long ns = 1000000000L / (long)hz;
    struct timespec ts = { .tv_sec = 0, .tv_nsec = ns };
    (void)nanosleep(&ts, NULL);
}

static void usage(const char *argv0)
{
    fprintf(stderr, "usage: %s [-p path] [-r hz] [-n count]\n", argv0);
}

int main(int argc, char **argv)
{
    const char   *path  = VCAN_PUBLIC_PATH;
    unsigned      hz     = 50u;
    unsigned long count  = 0ul;        /* 0 = forever */
    int           c;

    while ((c = getopt(argc, argv, "p:r:n:")) != -1) {
        switch (c) {
        case 'p': path  = optarg;                        break;
        case 'r': hz    = (unsigned)strtoul(optarg, NULL, 0); break;
        case 'n': count = strtoul(optarg, NULL, 0);      break;
        default:  usage(argv[0]); return 2;
        }
    }

    int fd = open(path, O_RDWR);
    if (fd == -1) {
        fprintf(stderr, "can_client: open(%s): %s\n", path, strerror(errno));
        return 1;
    }

    /* Read initial status. */
    vcan_status_t st;
    memset(&st, 0, sizeof(st));
    int rc = devctl(fd, VCAN_DCMD_GET_STATUS, &st, sizeof(st), NULL);
    if (rc != EOK) {
        fprintf(stderr, "can_client: GET_STATUS: %s\n", strerror(rc));
        close(fd);
        return 1;
    }
    printf("can_client: connected to %s (tx=%u rx=%u filters=%u)\n",
           path, st.frames_tx, st.frames_rx, st.filters);
    fflush(stdout);

    /* Install a legal 32-byte filter (<= 64-byte table, so no overflow). */
    uint8_t filter[32];
    memset(filter, 0xA5, sizeof(filter));
    rc = devctl(fd, VCAN_DCMD_SET_FILTER, filter, sizeof(filter), NULL);
    if (rc != EOK) {
        fprintf(stderr, "can_client: SET_FILTER: %s\n", strerror(rc));
        close(fd);
        return 1;
    }

    /* Steady send loop. */
    unsigned long sent     = 0ul;
    unsigned long errors   = 0ul;
    int           last_err = 0;
    time_t        last_tick = time(NULL);
    unsigned long sent_at_tick = 0ul;

    for (;;) {
        vcan_frame_t f;
        memset(&f, 0, sizeof(f));
        f.id  = 0x123u;
        f.dlc = 2u;
        f.data[0] = (uint8_t)(sent & 0xffu);
        f.data[1] = (uint8_t)((sent >> 8) & 0xffu);

        rc = devctl(fd, VCAN_DCMD_SEND_FRAME, &f, sizeof(f), NULL);
        if (rc == EOK) {
            sent++;
        } else {
            errors++;
            last_err = rc;
            /* If the device has gone away, give up with a non-zero status. */
            if (rc == EBADF || rc == ENODEV || rc == ESRCH || rc == ECONNREFUSED) {
                fprintf(stderr, "can_client: device lost: %s\n", strerror(rc));
                close(fd);
                return 1;
            }
        }

        time_t now = time(NULL);
        if (now != last_tick) {
            printf("can_client: sent=%lu (+%lu/s) errors=%lu last_errno=%d (%s)\n",
                   sent, sent - sent_at_tick, errors, last_err,
                   last_err ? strerror(last_err) : "none");
            fflush(stdout);
            last_tick    = now;
            sent_at_tick = sent;
        }

        if (count != 0ul && sent >= count) {
            break;
        }
        sleep_hz(hz);
    }

    printf("can_client: done, sent=%lu errors=%lu\n", sent, errors);
    close(fd);
    return 0;
}
