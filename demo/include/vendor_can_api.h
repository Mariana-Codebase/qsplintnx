/*
 * "Vendor" CAN gateway driver API used by the QSplintNX demo.
 *
 * Story: a Tier-1 supplier ships vendor_can as a binary-only resource
 * manager at /dev/vendor_can. It has a bug: VCAN_DCMD_SET_FILTER copies the
 * client's filter list into a fixed 64-byte table without checking the
 * length (planted as CVE-DEMO-0042). The OEM cannot rebuild it, so they
 * ship a QSplintNX virtual patch instead.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef VENDOR_CAN_API_H
#define VENDOR_CAN_API_H

#include <stdint.h>

#if defined(__QNX__) || defined(__QNXNTO__)
#include <devctl.h>
#else
#define _DCMD_MISC 0x05
#define __DIOF(class, cmd, data) ((sizeof(data) << 16) + ((class) << 8) + (cmd) + 0x40000000u)
#define __DIOT(class, cmd, data) ((sizeof(data) << 16) + ((class) << 8) + (cmd) + 0x80000000u)
#define __DIOTF(class, cmd, data) ((sizeof(data) << 16) + ((class) << 8) + (cmd) + 0xC0000000u)
#define __DION(class, cmd) (((class) << 8) + (cmd))
#endif

#define VCAN_PUBLIC_PATH   "/dev/vendor_can"
#define VCAN_BACKEND_PATH  "/dev/.splint/vendor_can"   /* where it runs behind splintd */

#define VCAN_FILTER_TABLE_BYTES 64u

typedef struct vcan_frame {
    uint32_t id;          /* 11- or 29-bit CAN id */
    uint8_t  dlc;         /* 0..8                 */
    uint8_t  pad[3];
    uint8_t  data[8];
} vcan_frame_t;

typedef struct vcan_status {
    uint32_t frames_tx, frames_rx, filters, bus_state;
} vcan_status_t;

/* Short codes (class _DCMD_MISC = 0x05): 0x0501.. */
#define VCAN_CMD_GET_STATUS 0x01
#define VCAN_CMD_SEND_FRAME 0x02
#define VCAN_CMD_SET_FILTER 0x05   /* vulnerable: payload len unchecked */

#define VCAN_DCMD_GET_STATUS __DIOF(_DCMD_MISC, VCAN_CMD_GET_STATUS, vcan_status_t)
#define VCAN_DCMD_SEND_FRAME __DIOT(_DCMD_MISC, VCAN_CMD_SEND_FRAME, vcan_frame_t)
/* Declared with the "nominal" 64-byte table size; the bug is that the
 * driver trusts the received length instead of this. */
#define VCAN_DCMD_SET_FILTER __DIOT(_DCMD_MISC, VCAN_CMD_SET_FILTER, uint8_t[VCAN_FILTER_TABLE_BYTES])

/* Short code as written in rules: (class << 8) | cmd */
#define VCAN_SHORT_SET_FILTER 0x0505
#define VCAN_SHORT_SEND_FRAME 0x0502
#define VCAN_SHORT_GET_STATUS 0x0501

#endif /* VENDOR_CAN_API_H */
