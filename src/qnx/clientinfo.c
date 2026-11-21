/* SPDX-License-Identifier: Apache-2.0 */
/*
 * QSplintNX - clientinfo.c
 *
 * Resolve the identity of the process on the other end of a connection: pid,
 * effective uid/gid, and the basename of its executable. The name comes from
 * /proc/<pid>/exefile. Everything is bounded and must not block for long,
 * because it runs on the open() hot path.
 *
 * STATUS: cross-compiled with qcc for QNX 8.0 (gcc_ntox86_64) and validated on a QEMU/KVM target; see docs/qemu-validation.md.
 *
 * API references verified against the SDP 8.0 documentation:
 *   iofunc_client_info_ext      .../i/iofunc_client_info_ext.html
 *     int iofunc_client_info_ext(resmgr_context_t*, const int ioflag,
 *                                struct _client_info**, int flags)
 *   _client_info / _cred_info   .../c/connectclientinfo.html
 *     info->pid, info->cred->euid, info->cred->egid  (cred is a POINTER)
 */

#define IOFUNC_OCB_T   struct splintd_ocb
#define IOFUNC_ATTR_T  struct splintd_mapping
#include "splintd.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

/* Fill out->name with the basename of the client's executable, or "?" if it
 * can't be determined. Reads a bounded amount from /proc/<pid>/exefile. */
static void resolve_exe_name(int32_t pid, char *out, size_t cap)
{
    if (cap == 0)
        return;
    out[0] = '?';
    out[1] = '\0';

    if (pid < 0)
        return;

    char procpath[64];
    int np = snprintf(procpath, sizeof procpath, "/proc/%d/exefile", (int)pid);
    if (np < 0 || (size_t)np >= sizeof procpath)
        return;

    int fd = open(procpath, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return;

    char tmp[256];
    ssize_t n;
    do {
        n = read(fd, tmp, sizeof tmp - 1);
    } while (n < 0 && errno == EINTR);
    (void)close(fd);

    if (n <= 0)
        return;
    tmp[n] = '\0';

    char *nl = strchr(tmp, '\n');      /* VERIFY-ON-TARGET: exefile trailing byte */
    if (nl != NULL)
        *nl = '\0';

    char *slash = strrchr(tmp, '/');
    const char *base = (slash != NULL) ? slash + 1 : tmp;
    if (base[0] == '\0')
        base = "?";

    /* Bounded copy (not snprintf): base may be up to 255 bytes and cap is 64,
     * so truncation is expected and safe; written this way to satisfy
     * -Werror=format-truncation. */
    size_t bl = strlen(base);
    if (cap == 0)
        return;
    if (bl >= cap)
        bl = cap - 1;
    memcpy(out, base, bl);
    out[bl] = '\0';
}

int splintd_client_resolve(resmgr_context_t *ctp, int ioflag, splint_client_t *out)
{
    memset(out, 0, sizeof *out);
    out->pid = -1;
    out->name[0] = '?';
    out->name[1] = '\0';

    struct _client_info *ci = NULL;
    /* ioflag is 0 for effective ids, O_REALIDS to swap in the real ids;
     * flags 0 means don't fetch supplementary groups (we don't need them). */
    int rc = iofunc_client_info_ext(ctp, ioflag, &ci, 0);
    if (rc != EOK || ci == NULL)
        return rc != EOK ? rc : EINVAL;

    out->pid = (int32_t)ci->pid;
    /* _client_info.cred is a struct by value in QNX 8, not a pointer. */
    out->uid = (uint32_t)ci->cred.euid;
    out->gid = (uint32_t)ci->cred.egid;
    resolve_exe_name(out->pid, out->name, sizeof out->name);

    iofunc_client_info_ext_free(&ci);
    return EOK;
}
