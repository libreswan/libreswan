/*
 * generic netlink receive message, for libreswan
 *
 * Copyright (C) 2012-2013 Kim B. Heino <b@bbbs.net>
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
ssize_t netlink_read_reply(int sock, char **pbuf, size_t bufsize,
				unsigned int seqnum, __u32 pid);
/*
 * When reading data from netlink the final packet in each recvfrom()
 * will be truncated if it doesn't fit to buffer. Netlink returns up
 * to 32KiB of data so always keep that much free.
 */
#define NL_BUFMARGIN 32768
