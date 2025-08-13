/* file descriptors, for libreswan
 *
 * Copyright (C) 2018 Andrew Cagney
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <unistd.h>	/* for close() */
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>

#include "fd.h"
#include "lswalloc.h"
#include "refcnt.h"
#include "lswlog.h"		/* for pexpect() */

struct fd {
#define FD_MAGIC 0xf00d1e
	unsigned magic;
	int fd;
	refcnt_t refcnt;
};

struct fd *fd_addref_where(struct fd *fd, const struct logger *new_owner, where_t where)
{
	pexpect(fd == NULL || fd->magic == FD_MAGIC);
	return addref_where(fd, new_owner, where);
}

void fd_delref_where(struct fd **fdp, const struct logger *ex_owner, where_t where)
{
	struct fd *fd = delref_where(fdp, ex_owner, where);
	if (fd != NULL) {
		PEXPECT(ex_owner, fd->magic == FD_MAGIC);
		if (close(fd->fd) != 0) {
			if (LDBGP(DBG_BASE, ex_owner)) {
				llog_errno(DEBUG_STREAM, ex_owner, errno,
					   "freeref "PRI_FD" close() failed "PRI_WHERE": ",
					   pri_fd(fd), pri_where(where));
			}
		} else {
			ldbg(ex_owner, "freeref "PRI_FD" "PRI_WHERE"",
			     pri_fd(fd), pri_where(where));
		}
		fd->magic = ~FD_MAGIC;
		pfree(fd);
	}
}

void fd_leak(struct fd *fd, struct logger *logger, where_t where)
{
	ldbg(logger, "leaking "PRI_FD"'s FD; will be closed when pluto exits "PRI_WHERE"",
	     pri_fd(fd), pri_where(where));
	/* leave the old underlying file descriptor open */
	if (fd != NULL) {
		fd->fd = dup(fd->fd);
	}
}

ssize_t fd_sendmsg(const struct fd *fd, const struct msghdr *msg, int flags)
{
	if (fd == NULL || fd->magic != FD_MAGIC) {
		/*
		 * XXX: passert() / pexpect() would be recursive -
		 * they will call this function when trying to write
		 * to whack.
		 */
		return -EFAULT;
	}
	ssize_t s = sendmsg(fd->fd, msg, flags);
	return s < 0 ? -errno : s;
}

struct fd *fd_accept(int socket, const struct logger *owner, where_t where)
{
	struct sockaddr_un addr;
	socklen_t addrlen = sizeof(addr);

	int fd = accept(socket, (struct sockaddr *)&addr, &addrlen);
	if (fd < 0) {
		llog_errno(ERROR_STREAM, owner, errno,
			   "accept() failed in "PRI_WHERE": ",
			   pri_where(where));
		return NULL;
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
		llog_errno(ERROR_STREAM, owner, errno,
			   "failed to set CLOEXEC in "PRI_WHERE": ", pri_where(where));
		close(fd);
		return NULL;
	}

	struct fd *fdt = refcnt_alloc(struct fd, owner, where);
	fdt->fd = fd;
	fdt->magic = FD_MAGIC;
	ldbg(owner, "%s: new "PRI_FD" "PRI_WHERE"",
	     __func__, pri_fd(fdt), pri_where(where));
	return fdt;
}

ssize_t fd_read(const struct fd *fd, void *buf, size_t nbytes)
{
	if (fd == NULL || fd->magic != FD_MAGIC) {
		return -EFAULT;
	}
	ssize_t s = read(fd->fd, buf, nbytes);
	return s < 0 ? -errno : s;
}

bool fd_p(const struct fd *fd)
{
	if (fd == NULL) {
		return false;
	}
	if (fd->magic != FD_MAGIC) {
		llog_pexpect(&global_logger, HERE,
			     "wrong magic for "PRI_FD"", pri_fd(fd));
		return false;
	}
	return true;
}

bool same_fd(const struct fd *l, const struct fd *r)
{
	return fd_p(l) && fd_p(r) && l == r;
}
