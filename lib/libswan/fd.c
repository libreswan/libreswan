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

#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

#include "lswlog.h"
#include "fd.h"

/*
 * UNIX FDs are always non-negative
 */
const fd_t null_fd = {
	.fd = -1,
};

bool fd_p(fd_t fd)
{
	return fd.fd >= 0;
}

bool same_fd(fd_t l, fd_t r)
{
	if (!fd_p(l) || !fd_p(r)) {
		return false;
	}
	struct stat l_stat;
	if (fstat(l.fd, &l_stat) != 0) {
		int e = errno;
		dbg("stat("PRI_FD") failed "PRI_ERRNO"",
		    PRI_fd(l), pri_errno(e));
		return false;
	}
	struct stat r_stat;
	if (fstat(r.fd, &r_stat) != 0) {
		int e = errno;
		dbg("stat("PRI_FD") failed "PRI_ERRNO"",
		    PRI_fd(r), pri_errno(e));
		return false;
	}
	return (l_stat.st_dev == r_stat.st_dev &&
		l_stat.st_ino == r_stat.st_ino);
}

fd_t new_fd(int fd, const char *code, where_t where)
{
	fd_t fdt = { .fd = fd, };
	int e = errno; /* don't loose 'errno' */
	bool error = fd < 0 && e != 0; /* guess */
	LSWDBGP(DBG_CONTROL, buf) {
		lswlogf(buf, "%s -> "PRI_FD, code, PRI_fd(fdt));
		if (error) {
			jam(buf, " "PRI_ERRNO, pri_errno(e));
		}
		jam(buf, " "PRI_WHERE, pri_where(where));
	}
	errno = e;
	return fdt;
}

fd_t dup_any_fd(fd_t fd, where_t where)
{
	fd_t nfd;
	bool error;
	if (fd_p(fd)) {
		nfd.fd = dup(fd.fd);
		error = nfd.fd < 0;
	} else {
		nfd = null_fd;
		error = false;
	}
	int e = errno; /* don't loose 'errno' */
	LSWDBGP(DBG_CONTROL, buf) {
		lswlogf(buf, "dup_any("PRI_FD") -> "PRI_FD,
			PRI_fd(fd), PRI_fd(nfd));
		if (error) {
			jam(buf, " "PRI_ERRNO, pri_errno(e));
		}
		jam(buf, " "PRI_WHERE, pri_where(where));
	}
	errno = e;
	return nfd;
}

void close_any_fd(fd_t *fd, where_t where)
{
	if (fd_p(*fd)) {
		bool error = (close(fd->fd) != 0);
		int e = errno; /* don't loose 'errno' */
		LSWDBGP(DBG_CONTROL, buf) {
			lswlogf(buf, "close_any("PRI_FD")", PRI_fd(*fd));
			if (error) {
				jam(buf, " "PRI_ERRNO, pri_errno(e));
			}
			jam(buf, " "PRI_WHERE, pri_where(where));
		}
		errno = e;
		*fd = null_fd;
	}
}
