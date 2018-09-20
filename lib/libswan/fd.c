/* file descriptors, for libreswan
 *
 * Copyright (C) 2018 Andrew Cagney
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
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

int dup_any(int fd) {
	int nfd;
	if (fd == NULL_FD) {
		nfd = NULL_FD;
	} else {
		nfd = dup(fd);
	}
	DBGF(DBG_CONTROL, "dup_any(%d)->%d", fd, nfd);
	return nfd;
}

void close_any(int *fd)
{
	if (*fd != NULL_FD) {
		if (close(*fd) == 0) {
			DBGF(DBG_CONTROL, "close_any(%d)", *fd);
		} else {
			int e = errno;
			LSWDBGP(DBG_CONTROL, buf) {
				lswlogf(buf, "close_any(%d) failed", *fd);
				lswlog_errno(buf, e);
			}
		}
		*fd = NULL_FD;
	}
}
