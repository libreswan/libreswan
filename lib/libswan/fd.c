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

fd_t new_fd(int fd, const char *code, const char *func, const char *file, unsigned long line)

{
	fd_t fdt = { .fd = fd, };
	int e = errno; /* don't loose 'errno' */
	bool error = fd < 0 && e != 0; /* guess */
	LSWDBGP(DBG_CONTROL, buf) {
		lswlogf(buf, "%s -> "PRI_FD, code, PRI_fd(fdt));
		if (error) {
			lswlog_errno(buf, e);
		}
		lswlog_source_line(buf, func, file, line);
	}
	errno = e;
	return fdt;
}

fd_t dup_any_fd(fd_t fd, const char *func, const char *file, unsigned long line)
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
			lswlog_errno(buf, e);
		}
		lswlog_source_line(buf, func, file, line);
	}
	errno = e;
	return nfd;
}

void close_any_fd(fd_t *fd, const char *func, const char *file, unsigned long line)
{
	if (fd_p(*fd)) {
		bool error = (close(fd->fd) != 0);
		int e = errno; /* don't loose 'errno' */
		LSWDBGP(DBG_CONTROL, buf) {
			lswlogf(buf, "close_any("PRI_FD")", PRI_fd(*fd));
			if (error) {
				lswlog_errno(buf, e);
			}
			lswlog_source_line(buf, func, file, line);
		}
		errno = e;
		*fd = null_fd;
	}
}
