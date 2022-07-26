/* wrap apple's lack of SOCK_CLOEXEC, for libreswan
 *
 * Copyright (C) 2022 Andrew Cagney
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
 *
 */

#ifndef SOCK_CLOEXEC
#include <errno.h>
#include <fcntl.h>
#endif

#include "lsw_socket.h"

/*
 * Hack to get around Darwin's (Apple's) lack of SOCK_CLOEXEC.
 */

int cloexec_socket(int domain, int type, int protocol)
{
#ifdef SOCK_CLOEXEC
	return socket(domain, type|SOCK_CLOEXEC, protocol);
#else
	int sock = socket(domain, type, protocol);
	int error = errno;
	if (sock < 0) {
		return sock;
	}
	int e = fcntl(sock, F_SETFD, FD_CLOEXEC);
	if (e < 0) {
		close(sock);
		errno = error;
		return -1;
	}
	return sock;
#endif
}
