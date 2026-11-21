/* SPDX-License-Identifier: Apache-2.0 */
/*
 * QSplintNX - backend.c
 *
 * Everything that talks to the real driver (the BACKEND). Each client open
 * owns one backend fd, stored in the OCB; these functions are the only place
 * splintd issues POSIX I/O or QNX devctl() against it. In relocated mode the
 * backend lives on a hidden path; in shadow mode splintd opens the public
 * path and relies on its own io_open returning ENOENT to its pid so the open
 * falls through to the driver behind it.
 *
 * STATUS: cross-compiled with qcc for QNX 8.0 (gcc_ntox86_64) and validated on a QEMU/KVM target; see docs/qemu-validation.md.
 *
 * API references verified against the SDP 8.0 documentation:
 *   devctl()  .../d/devctl.html  (returns EOK or an errno, NOT -1/errno;
 *             dev_info_ptr receives the driver's return value)
 */

#define IOFUNC_OCB_T   struct splintd_ocb
#define IOFUNC_ATTR_T  struct splintd_mapping
#include "splintd.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <devctl.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

static inline void count_forward_error(void)
{
    __atomic_add_fetch(&g_splintd.forward_errors, 1, __ATOMIC_RELAXED);
}

/* Path of the real driver for this OCB's mapping. */
static const char *backend_path_of(const splintd_ocb_t *ocb)
{
    return (ocb->map->mode == SPLINTD_BACKEND_RELOCATED)
         ? ocb->map->backend_path      /* hidden path */
         : ocb->map->public_path;      /* shadow: same path, ENOENT fall-through */
}

int splintd_backend_open(splintd_ocb_t *ocb, int oflag)
{
    const char *path = backend_path_of(ocb);
    int fd;
    do {
        fd = open(path, oflag | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);

    if (fd < 0) {
        count_forward_error();
        return errno ? errno : EIO;
    }
    ocb->backend_fd = fd;
    return 0;
}

void splintd_backend_close(splintd_ocb_t *ocb)
{
    if (ocb->backend_fd < 0)
        return;
    int fd = ocb->backend_fd;
    ocb->backend_fd = -1;              /* clear first so this is idempotent */
    int r;
    do {
        r = close(fd);
    } while (r < 0 && errno == EINTR);
}

/* Position the backend fd to *off (best effort), then read. A character
 * backend may reject the seek (ESPIPE/EINVAL); that is not an error, we just
 * read at the fd's current position. */
ssize_t splintd_backend_read(splintd_ocb_t *ocb, void *buf, size_t n, off_t *off_inout)
{
    if (ocb->backend_fd < 0) {
        errno = EBADF;
        return -1;
    }
    if (off_inout != NULL && *off_inout > 0)
        (void)lseek(ocb->backend_fd, *off_inout, SEEK_SET);

    ssize_t r;
    do {
        r = read(ocb->backend_fd, buf, n);
    } while (r < 0 && errno == EINTR);

    if (r < 0) {
        count_forward_error();
        return -1;
    }
    if (off_inout != NULL && *off_inout >= 0)
        *off_inout += r;
    return r;
}

ssize_t splintd_backend_write(splintd_ocb_t *ocb, const void *buf, size_t n)
{
    if (ocb->backend_fd < 0) {
        errno = EBADF;
        return -1;
    }
    if (ocb->hdr.offset > 0)
        (void)lseek(ocb->backend_fd, (off_t)ocb->hdr.offset, SEEK_SET);

    const uint8_t *p = buf;
    size_t done = 0;
    while (done < n) {
        ssize_t w = write(ocb->backend_fd, p + done, n - done);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            count_forward_error();
            return done > 0 ? (ssize_t)done : -1;
        }
        if (w == 0)
            break;
        done += (size_t)w;
    }
    return (ssize_t)done;
}

off_t splintd_backend_lseek(splintd_ocb_t *ocb, off_t off, int whence)
{
    if (ocb->backend_fd < 0) {
        errno = EBADF;
        return (off_t)-1;
    }
    off_t r = lseek(ocb->backend_fd, off, whence);
    if (r == (off_t)-1)
        count_forward_error();
    return r;
}

/*
 * Forward a devctl to the backend. devctl() uses one buffer for both the TO
 * and FROM data, so we size the transfer at buf_cap = max(in_len, reply cap,
 * command size hint). devctl() returns EOK or an errno (it does not use the
 * -1/errno convention) and may retry on EINTR by returning EINTR itself.
 * https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/d/devctl.html
 */
int splintd_backend_devctl(splintd_ocb_t *ocb, int dcmd, void *buf,
                           size_t in_len, size_t buf_cap, int *ret_val)
{
    (void)in_len;                      /* devctl transfers up to buf_cap bytes */
    if (ocb->backend_fd < 0)
        return EBADF;

    int info = 0;
    int r;
    do {
        r = devctl(ocb->backend_fd, dcmd, buf, buf_cap, &info);
    } while (r == EINTR);

    if (ret_val != NULL)
        *ret_val = info;
    if (r != EOK)
        count_forward_error();
    return r;
}
