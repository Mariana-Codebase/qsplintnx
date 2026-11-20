/*
 * QSplintNX - portable description of one intercepted message.
 *
 * splintd (QNX) fills a splint_msg_t from a resource-manager message and
 * hands it to the engine. Host tests and benches build them by hand. Nothing
 * in this header depends on QNX headers, so the core compiles anywhere.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPLINT_MSG_H
#define SPLINT_MSG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SPLINT_INSPECT_MAX   256u  /* payload bytes visible to rules      */
#define SPLINT_NAME_MAX      64u   /* client process name incl. NUL      */
#define SPLINT_PATH_MAX      128u  /* public path incl. NUL              */

typedef enum splint_op {
    SPLINT_OP_OPEN = 0,
    SPLINT_OP_READ,
    SPLINT_OP_WRITE,
    SPLINT_OP_DEVCTL,
    SPLINT_OP_LSEEK,
    SPLINT_OP_CLOSE,
    SPLINT_OP_OTHER,
    SPLINT_OP_COUNT_         /* not an op; number of ops               */
} splint_op_t;

/* Identity of the sender, resolved once at open() time by splintd. */
typedef struct splint_client {
    int32_t  pid;
    uint32_t uid;
    uint32_t gid;
    char     name[SPLINT_NAME_MAX];   /* basename of executable, NUL-terminated */
} splint_client_t;

typedef struct splint_msg {
    splint_op_t            op;
    uint32_t               dcmd;          /* devctl only, else 0              */
    uint64_t               declared;      /* size claimed by client header    */
    uint64_t               len;           /* payload bytes really received    */
    const uint8_t         *data;          /* first min(len, INSPECT_MAX) bytes */
    size_t                 data_len;      /* <= SPLINT_INSPECT_MAX            */
    const char            *path;          /* public path, NUL-terminated      */
    const splint_client_t *client;
    uint64_t               now_ns;        /* monotonic timestamp of arrival   */
} splint_msg_t;

const char *splint_op_name(splint_op_t op);   /* "devctl", ... ; "?" if bad */

#ifdef __cplusplus
}
#endif
#endif /* SPLINT_MSG_H */
