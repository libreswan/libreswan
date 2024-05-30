/*
 * generic netlink receive message, for libreswan
 *
 * Copyright (C) 2024  Andrew Cagney
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

#ifndef LINUX_NETLINK_H
#define LINUX_NETLINK_H

#include <stddef.h>	/* for size_t */
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>		/* for pid_t */

#include "verbose.h"

struct nlmsghdr;
struct linux_netlink_context;
struct logger;

typedef bool linux_netlink_response_processor(struct nlmsghdr *,
					      struct linux_netlink_context *,
					      struct verbose verbose);

bool linux_netlink_query(const struct nlmsghdr *nlmsg, int netlink_protocol,
			 linux_netlink_response_processor *processor,
			 struct linux_netlink_context *context,
			 struct verbose);

/*
 * When reading data from netlink the final packet in each recvfrom()
 * will be truncated if it doesn't fit to buffer. Netlink returns up
 * to 32KiB of data so always keep that much free.
 */
#define LINUX_NETLINK_BUFSIZE 32768

#endif
