/* SPDX-License-Identifier: Apache-2.0 */
/*
 * fwdtest - on-target regression for the devctl forwarding tail (finding: the
 * reusable backend buffer was not cleared, so bytes past the inspected input
 * could reach the driver). Run it THROUGH splintd on the public path.
 *
 * VCAN_DCMD_SET_FILTER is declared with a 64-byte data type, so its dcmd size
 * hint is 64 and splintd forwards a 64-byte devctl to the driver even when the
 * client sends fewer bytes. The driver copies all 64 into its filter table.
 * So:
 *   1. SET_FILTER with 40 bytes of 0xAA  -> table[0..40) = 0xAA
 *   2. SET_FILTER with  8 bytes of 0xBB  -> table[0..8)  = 0xBB, and the tail
 *      [8..64) must be whatever splintd put there, NOT leftover 0xAA from step 1.
 *   3. GET_FILTER and check: table[0..8) == 0xBB and table[8..64) == 0x00.
 *
 * Before the fix, splintd forwarded the reused buffer, so table[8..40) came
 * back 0xAA (data from the previous request that no rule inspected). After the
 * fix splintd zeroes the tail, so [8..64) is 0x00. Exit 0 on pass, 1 on fail.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <devctl.h>

#include "vendor_can_api.h"

int main(int argc, char **argv)
{
    const char *path = VCAN_PUBLIC_PATH;
    int c;
    while ((c = getopt(argc, argv, "p:")) != -1) {
        if (c == 'p') path = optarg;
        else { fprintf(stderr, "usage: %s [-p path]\n", argv[0]); return 2; }
    }

    int fd = open(path, O_RDWR);
    if (fd < 0) { fprintf(stderr, "fwdtest: open %s: %s\n", path, strerror(errno)); return 2; }

    uint8_t buf[VCAN_FILTER_TABLE_BYTES];

    /* 1. prime the table with 0xAA over 40 bytes */
    memset(buf, 0xAA, sizeof buf);
    if (devctl(fd, VCAN_DCMD_SET_FILTER, buf, 40, NULL) != EOK) {
        fprintf(stderr, "fwdtest: SET_FILTER(0xAA,40) failed\n"); return 2;
    }

    /* 2. short SET_FILTER of 0xBB over 8 bytes */
    memset(buf, 0xBB, sizeof buf);
    if (devctl(fd, VCAN_DCMD_SET_FILTER, buf, 8, NULL) != EOK) {
        fprintf(stderr, "fwdtest: SET_FILTER(0xBB,8) failed\n"); return 2;
    }

    /* 3. read the table back */
    memset(buf, 0x11, sizeof buf);
    if (devctl(fd, VCAN_DCMD_GET_FILTER, buf, sizeof buf, NULL) != EOK) {
        fprintf(stderr, "fwdtest: GET_FILTER failed\n"); return 2;
    }
    close(fd);

    int leaked = 0, bad_head = 0;
    for (int i = 0; i < 8; i++)
        if (buf[i] != 0xBB) bad_head++;
    for (int i = 8; i < (int)VCAN_FILTER_TABLE_BYTES; i++)
        if (buf[i] != 0x00) leaked++;

    printf("fwdtest: table head[0..8)=");
    for (int i = 0; i < 8; i++) printf("%02x", buf[i]);
    printf(" tail[8..64) nonzero=%d\n", leaked);
    printf("fwdtest: first tail bytes:");
    for (int i = 8; i < 24; i++) printf(" %02x", buf[i]);
    printf("\n");

    if (bad_head) {
        printf("RESULT: FAIL (head not forwarded: expected 0xBB)\n");
        return 1;
    }
    if (leaked) {
        printf("RESULT: FAIL (%d uninspected bytes reached the driver)\n", leaked);
        return 1;
    }
    printf("RESULT: PASS (forwarded message matches the inspected input)\n");
    return 0;
}
