/*
 * netlink_read_reply generic netlink response, for libreswan
 *
 * Copyright (C) 2012-2013 Kim B. Heino <b@bbbs.net>
 * Copyright (C) 2024 Andrew Cagney
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

#include "linux_netlink.h"
#include "lsw_socket.h"

#include "lswalloc.h"
#include "lswlog.h"

/* ??? one caller thinks errno is meaningful after a failure */

static bool linux_netlink_process_response(const struct nlmsghdr *nlmsg, int sock,
					   linux_netlink_response_processor *processor,
					   struct linux_netlink_context *context,
					   struct verbose verbose)
{
	for (;;) {
		struct sockaddr_nl sa;
		ssize_t readlen; /* signed */
		union {
			struct nlmsghdr nlhdr;
			uint8_t raw[LINUX_NETLINK_BUFSIZE];
		} buf;

		/*
		 * Read netlink message, verifying kernel origin
		 * (in sa.nl_pid?)
		 */
		do {
			socklen_t salen = sizeof(sa);
			vlog("reading into %zu byte buffer", sizeof(buf));
			errno = 0;
			readlen = recvfrom(sock, &buf, sizeof(buf), 0,
					   (struct sockaddr *)&sa, &salen);
			if (errno == EAGAIN) {
				if (nlmsg->nlmsg_flags & NLM_F_ACK) {
					continue; /* try again!?! */
				}
				return true;
			}
			if (readlen <= 0 || salen != sizeof(sa)) {
				llog_errno(RC_LOG, verbose.logger, errno,
					   "read netlink socket failure: ");
				return false;
			}
		} while (sa.nl_pid != 0);

		vlog("processing %zu byte response", readlen);

		/*
		 * Now process the contents.
		 */

		struct nlmsghdr *nlhdr = &buf.nlhdr;

		verbose.level++;
		do {

			/*
			 * Check that READLEN is big enough to hold
			 * the current message.
			 */
			if (!NLMSG_OK(nlhdr, readlen)) {
				vlog("TRUNCATED %zd", readlen);
				return false;
			}

			if (nlhdr->nlmsg_type == NLMSG_ERROR) {
				vlog("ERROR");
				return false;
			}

			/*
			 * When there's a multi-part message, the last
			 * part has type NLMSG_DONE set.
			 */
			if (nlhdr->nlmsg_type == NLMSG_DONE) {
				vlog("DONE");
				return true;
			}

			/*
			 * Process this message (could be more).
			 * Processor is responsible for checking PID.
			 */
			if (nlhdr->nlmsg_seq == nlmsg->nlmsg_seq) {
				if (!processor(nlhdr, context, verbose)) {
					/* this means stop early; not
					 * a failure */
					return true;
				}
			}

			/*
			 * When NLM_F_MULTI is set there's another
			 * message following.  It could be part of
			 * this read, but it could also be in the
			 * socket waiting for a read.
			 */
			if ((nlhdr->nlmsg_flags & NLM_F_MULTI) == 0) {
				return true;
			}

			/*
			 * Advance to the next message in the buffer.
			 * If the buffer has been consumed, loop round
			 * the outer loop re-fill the buffer from the
			 * socket.
			 */
			nlhdr = NLMSG_NEXT(nlhdr, readlen);

		} while (readlen > 0);

		verbose.level--;
	}

	return true;
}

bool linux_netlink_query(const struct nlmsghdr *nlmsg, int netlink_protocol,
			 bool (*processor)(struct nlmsghdr *,
					   struct linux_netlink_context *,
					   struct verbose verbose),
			 struct linux_netlink_context *context,
			 struct verbose verbose)
{
	/*
	 * When no ACK is required; open non-blocking so that read
	 * doesn't hang.
	 */
	unsigned flags = 0;
	if (nlmsg->nlmsg_flags & NLM_F_ACK) {
		vlog("opening blocking netlink socket");
	} else {
		vlog("opening non-blocking netlink socket");
		flags |= SOCK_NONBLOCK;
	}

	int sock = cloexec_socket(PF_NETLINK, SOCK_DGRAM|flags, netlink_protocol);
	if (sock < 0) {
		llog_errno(RC_LOG, verbose.logger, errno,
			   "create netlink socket failure: ");
		return false;
	}


	if (send(sock, nlmsg, nlmsg->nlmsg_len, 0) < 0) {
		llog_errno(RC_LOG, verbose.logger, errno, "write netlink socket failure: ");
		close(sock);
		return false;
	}

	vlog("sent %d byte netlink message", (int)nlmsg->nlmsg_len);

	bool ok = linux_netlink_process_response(nlmsg, sock,
						 processor, context,
						 verbose);
	close(sock);
	return ok;
}
