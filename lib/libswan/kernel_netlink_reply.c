/*
 * netlink_read_reply generic netlink response, for libreswan
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
 */

#include <stdio.h>
#include <linux/rtnetlink.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>

#include "lswalloc.h"
#include "kernel_netlink_reply.h"

/* ??? one caller thinks errno is meaningful after a failure */
ssize_t netlink_read_reply(int sock, char **pbuf, size_t bufsize,
			   unsigned int seqnum, __u32 pid)
{
	size_t msglen = 0;

	for (;;) {
		struct sockaddr_nl sa;
		ssize_t readlen;

		/* Read netlink message, verifying kernel origin. */
		do {
			socklen_t salen = sizeof(sa);

			readlen = recvfrom(sock, *pbuf + msglen,
					bufsize - msglen, 0,
					(struct sockaddr *)&sa, &salen);
			if (readlen <= 0 || salen != sizeof(sa))
				return -1;
		} while (sa.nl_pid != 0);

		/* Verify it's valid */
		struct nlmsghdr *nlhdr = (struct nlmsghdr *)(*pbuf + msglen);

		if (!NLMSG_OK(nlhdr, (size_t)readlen) ||
			nlhdr->nlmsg_type == NLMSG_ERROR)
			return -1;

		/* Move read pointer */
		msglen += readlen;

		/* Check if it is the last message */
		if (nlhdr->nlmsg_type == NLMSG_DONE)
			break;

		/* all done if it's not a multi part */
		if ((nlhdr->nlmsg_flags & NLM_F_MULTI) == 0)
			break;

		/* all done if this is the one we were searching for */
		if (nlhdr->nlmsg_seq == seqnum && nlhdr->nlmsg_pid == pid)
			break;

		/* Allocate more memory for buffer if needed. */
		if (msglen >= bufsize - NL_BUFMARGIN) {
			bufsize = bufsize * 2;
			char *newbuf = alloc_bytes(bufsize, "netlink query netlink query()");
			memcpy(newbuf, *pbuf, msglen);
			pfree(*pbuf);
			*pbuf = newbuf;
		}
	}

	return msglen;
}

