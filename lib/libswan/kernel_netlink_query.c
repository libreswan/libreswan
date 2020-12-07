/*
 * Copyright (C) 2018-2020 Antony Antony <antony@phenome.org>
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

#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <linux/rtnetlink.h>
#include "kernel_netlink_query.h"

#include "lswlog.h"

/* returns a file descriptor on success; -1 on error */
int nl_send_query(const struct nlmsghdr *req, int protocol, struct logger *logger)
{
	int nl_fd = socket(AF_NETLINK, SOCK_DGRAM, protocol);

	if (nl_fd < 0) {
		log_errno(logger, errno, "socket() in nl_send_query() protocol %d", protocol);
		return nl_fd;	/* -1 */
	}

	if (fcntl(nl_fd, F_SETFL, O_NONBLOCK) != 0) {
		log_errno(logger, errno, "fcntl(O_NONBLOCK) in nl_send_query() protocol %d", protocol);
		close(nl_fd);
		return -1;
	}

	size_t len = req->nlmsg_len;
	ssize_t r;
	do {
		r = write(nl_fd, req, len);
	} while (r < 0 && errno == EINTR);
	if (r < 0) {
		log_errno(logger, errno, "netlink nl_send_query() write");
		close(nl_fd);
		return -1;
	} else if ((size_t)r != len) {
		llog(RC_LOG_SERIOUS, logger,
			    "ERROR: netlink write() message truncated: %zd instead of %zu",
			    r, len);
		close(nl_fd);
		return -1;
	}

	return nl_fd;
}
