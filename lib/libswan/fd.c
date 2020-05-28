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

struct fd {
#define FD_MAGIC 0xf00d1e
	unsigned magic;
	int fd;
	refcnt_t refcnt;
};

struct fd *dup_any_fd(struct fd *fd, where_t where)
{
	pexpect(fd == NULL || fd->magic == FD_MAGIC);
	ref_add(fd, where);
	return fd;
}

static void free_fd(struct fd **fdp, where_t where)
{
	struct fd *fd = *fdp;
	*fdp = NULL;
	pexpect(fd->magic == FD_MAGIC);
	if (close(fd->fd) != 0) {
		dbg("freeref "PRI_FD" close(%d) failed: "PRI_ERRNO" "PRI_WHERE"",
		    pri_fd(fd), fd->fd, pri_errno(errno), pri_where(where));
	} else {
		dbg("freeref "PRI_FD" "PRI_WHERE"",
		    pri_fd(fd), pri_where(where));
	}
	fd->magic = ~FD_MAGIC;
	pfree(fd);
}

void close_any_fd(struct fd **fd, where_t where)
{
	ref_delete(fd, free_fd, where);
}

void fd_leak(struct fd **fd, where_t where)
{
	dbg("leaking "PRI_FD"'s FD; will be closed when pluto exits "PRI_WHERE"",
	    pri_fd(*fd), pri_where(where));
	/* leave the old fd hanging */
	(*fd)->fd = dup((*fd)->fd);
	ref_delete(fd, free_fd, where);
}

ssize_t fd_sendmsg(const struct fd *fd, const struct msghdr *msg,
		   int flags, where_t where)
{
	if (fd == NULL || fd->magic != FD_MAGIC) {
		/*
		 * XXX: passert() / pexpect() / ... would be recursive
		 * - they write to whack using fd_sendsmg(), fake it.
		 */
		LSWBUF(buf) {
			jam(buf, "EXPECTATION FAILED:");
			if (fd == NULL) {
				jam(buf, " fd should not be NULL");
			} else {
				jam(buf, " fd magic is %ux, should be %ux",
				    fd->magic, FD_MAGIC);
			}
			jam(buf, " "PRI_WHERE"", pri_where(where));
			/* XXX: on BSD msg_iovlen is an INT */
			for (unsigned i = 0; i < (unsigned)msg->msg_iovlen; i++) {
				jam(buf, "; ");
				struct iovec *iov = &msg->msg_iov[i];
				jam_sanitized_bytes(buf, iov->iov_base, iov->iov_len);
			}
			log_jambuf(LOG_STREAM, null_fd, buf);
		}
		return -1;
	}
	if (fd->magic != FD_MAGIC) {
		/*
		 * XXX: passert() / pexpect() / ... would be recursive
		 * - they write to whack using fd_sendmsg(), fake it.
		 */
		LSWBUF(buf) {
			jam(buf, "EXPECTATION FAILED: fd is not magic "PRI_WHERE"",
			    pri_where(where));
			log_jambuf(LOG_STREAM, null_fd, buf);
		}
		return -1;
	}
	return sendmsg(fd->fd, msg, flags);
}

struct fd *fd_accept(int socket, where_t where)
{
	struct sockaddr_un addr;
	socklen_t addrlen = sizeof(addr);

	int fd = accept(socket, (struct sockaddr *)&addr, &addrlen);
	if (fd < 0) {
		LOG_ERRNO(errno, "accept() failed in "PRI_WHERE"",
			  pri_where(where));
		return NULL;
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
		LOG_ERRNO(errno, "failed to set CLOEXEC in "PRI_WHERE"",
			  pri_where(where));
		close(fd);
		return NULL;
	}

	struct fd *fdt = alloc_thing(struct fd, where.func);
	fdt->fd = fd;
	fdt->magic = FD_MAGIC;
	ref_init(fdt, where);
	dbg("%s: new "PRI_FD" "PRI_WHERE"",
	    __func__, pri_fd(fdt), pri_where(where));
	return fdt;
}

ssize_t fd_read(const struct fd *fd, void *buf, size_t nbytes, where_t where)
{
	if (fd == NULL) {
		log_pexpect(where, "null "PRI_FD"", pri_fd(fd));
		return -1;
	}
	if (fd->magic != FD_MAGIC) {
		log_pexpect(where, "wrong magic for "PRI_FD"", pri_fd(fd));
		return -1;
	}
	return read(fd->fd, buf, nbytes);
}

bool fd_p(const struct fd *fd)
{
	if (fd == NULL) {
		return false;
	}
	if (fd->magic != FD_MAGIC) {
		log_pexpect(HERE, "wrong magic for "PRI_FD"", pri_fd(fd));
		return false;
	}
	return true;
}

bool same_fd(const struct fd *l, const struct fd *r)
{
	return fd_p(l) && fd_p(r) && l == r;
}
