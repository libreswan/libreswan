/* xfrm interface to the kernel's IPsec mechanism, for libreswan
 *
 * Copyright (C) 2003-2008 Herbert Xu
 * Copyright (C) 2006-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2006 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2007 Bart Trojanowski <bart@jukie.net>
 * Copyright (C) 2007 Ilia Sotnikov
 * Copyright (C) 2009 Carsten Schlote <c.schlote@konzeptpark.de>
 * Copyright (C) 2008 Andreas Steffen
 * Copyright (C) 2008 Neil Horman <nhorman@redhat.com>
 * Copyright (C) 2008-2010 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2006-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010-2017 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2010 Mika Ilmaranta <ilmis@foobar.fi>
 * Copyright (C) 2010 Roman Hoog Antink <rha@open.ch>
 * Copyright (C) 2010 D. Hugh Redelmeier
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2013 Kim B. Heino <b@bbbs.net>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2017 Richard Guy Briggs <rgb@tricolour.ca>
 * Copyright (C) 2016-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2019 Antony Antony <antony@phenome.org>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
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

/* system headers */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>		/* for write() */
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <stdint.h>

/*
 * GRRR:
 *
 * GLIBC/Linux and MUSL/Linux define sockaddr_in et.al. in
 * <netinet/in.h>, and the generic network code uses this.
 * Unfortunately (cough) the Linux kernel headers also provide
 * definitions of those structures in <linux/in.h> et.al. which,
 * depending on header include order can result in conflicting
 * definitions.  For instance, if sockaddr_in is not defined,
 * <linux/xfrm.h> will include the definition in <linux/in.h> but that
 * will then clash with a later include of <netinet/in.h>.
 *
 * GLIBC/Linux has hacks on hacks to work-around this, not MUSL.
 * Fortunately, including <netinet/in.h> first will force the Linux
 * kernel headers to use that definition.
 *
 * XXX: include this before any other Linux kernel headers try to
 * include the conflicting definition.
 */
#include <netinet/in.h>

#include "linux/xfrm.h"		/* local (if configured) or system copy */

#include <linux/ethtool.h>
#include <linux/sockios.h>

#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>

/* libreswan headers */

#include "lsw_socket.h"
#include "constants.h"
#include "defs.h"
#include "id.h"
#include "state.h"
#include "connections.h"
#include "kernel.h"
#include "kernel_ops.h"
#include "kernel_policy.h"
#include "server.h"
#include "nat_traversal.h"
#include "state.h"
#include "kernel_xfrm.h"
#include "netlink_attrib.h"
#include "log.h"
#include "whack.h"	/* for RC_LOG */
#include "kernel_alg.h"
#include "ike_alg.h"
#include "ike_alg_integ.h"
#include "ike_alg_encrypt.h"
#include "ip_address.h"
#include "ip_info.h"
# include "kernel_xfrm_interface.h"
#include "iface.h"
#include "ip_selector.h"
#include "ip_encap.h"
#include "acquire.h"		/* for initiate_ondemand() */
#include "labeled_ipsec.h"	/* for vet_seclabel() */
#include "ikev2_mobike.h"
#include "ip_packet.h"
#include "sparse_names.h"
#include "kernel_iface.h"

/* required for Linux 2.6.26 kernel and later */
#ifndef XFRM_STATE_AF_UNSPEC
#define XFRM_STATE_AF_UNSPEC 32
#endif

static void netlink_process_xfrm_messages(int fd, void *arg, struct logger *logger);
static void netlink_process_rtm_messages(int fd, void *arg, struct logger *logger);
static bool sendrecv_xfrm_msg(struct nlmsghdr *hdr,
			      unsigned expected_resp_type, struct nlm_resp *rbuf,
			      const char *description, const char *story,
			      int *recv_errno,
			      struct logger *logger);

static struct {
	bool icmpv6;
	bool offload;
} hyperspace_bypass;

static int nl_send_fd = NULL_FD; /* to send to NETLINK_XFRM */
static int netlink_xfrm_fd = NULL_FD; /* listen to NETLINK_XFRM broadcast */
static int netlink_rtm_fd = NULL_FD; /* listen to NETLINK_ROUTE broadcast */

#define NE(x) { .name = #x, .value = x, }	/* Name Entry -- shorthand for sparse_names */

static const struct sparse_names xfrm_type_names = {
	.list = {
		NE(NLMSG_NOOP),
		NE(NLMSG_ERROR),
		NE(NLMSG_DONE),
		NE(NLMSG_OVERRUN),

		NE(XFRM_MSG_NEWSA),
		NE(XFRM_MSG_DELSA),
		NE(XFRM_MSG_GETSA),

		NE(XFRM_MSG_NEWPOLICY),
		NE(XFRM_MSG_DELPOLICY),
		NE(XFRM_MSG_GETPOLICY),

		NE(XFRM_MSG_ALLOCSPI),
		NE(XFRM_MSG_ACQUIRE),
		NE(XFRM_MSG_EXPIRE),

		NE(XFRM_MSG_UPDPOLICY),
		NE(XFRM_MSG_UPDSA),

		NE(XFRM_MSG_POLEXPIRE),

		NE(XFRM_MSG_FLUSHSA),
		NE(XFRM_MSG_FLUSHPOLICY),

		NE(XFRM_MSG_BASE),
		NE(XFRM_MSG_MAX),

		SPARSE_NULL
	},
};

static const struct sparse_names rtm_type_names = {
	.list = {

		NE(RTM_NEWLINK),
		NE(RTM_NEWLINK),
		NE(RTM_GETLINK),
		NE(RTM_SETLINK),

		NE(RTM_NEWADDR),
		NE(RTM_DELADDR),
		NE(RTM_GETADDR),

		NE(RTM_NEWLINK),
		NE(RTM_DELLINK),
		NE(RTM_GETLINK),

		NE(RTM_NEWROUTE),
		NE(RTM_DELROUTE),
		NE(RTM_GETROUTE),

		NE(RTM_NEWNEIGH),
		NE(RTM_DELNEIGH),
		NE(RTM_GETNEIGH),

		NE(RTM_NEWRULE),
		NE(RTM_DELRULE),
		NE(RTM_GETRULE),

		/* and many more */

		NE(RTM_BASE),
		NE(RTM_MAX),

		SPARSE_NULL
	},
};
#undef NE

/*
 * xfrm_from-address - Take an IP address and convert to an xfrm.
 */
static xfrm_address_t xfrm_from_address(const ip_address *addr)
{
	xfrm_address_t xaddr;
	zero(&xaddr);

	shunk_t a = address_as_shunk(addr);
	/* .len == ipv6 len */
	chunk_t x = THING_AS_CHUNK(xaddr);
	/* x = a */
	passert(x.len >= a.len);
	memcpy(x.ptr, a.ptr, a.len);
	return xaddr;
}

#define SELECTOR_TO_XFRM(CLIENT, REQ, L)				\
	{								\
		ip_selector client_ = (CLIENT);				\
		ip_address address = selector_prefix(client_);		\
		(REQ).L##addr = xfrm_from_address(&address);		\
		(REQ).prefixlen_##L = selector_prefix_bits(client_);	\
		(REQ).L##port = nport(selector_port(client_));		\
	}

static void init_netlink_rtm_fd(struct logger *logger)
{
	netlink_rtm_fd = cloexec_socket(AF_NETLINK, SOCK_RAW|SOCK_NONBLOCK, NETLINK_ROUTE);
	if (netlink_rtm_fd < 0) {
		fatal_errno(PLUTO_EXIT_FAIL, logger, errno, "socket()");
	}

	struct sockaddr_nl addr = {
		.nl_family = AF_NETLINK,
		.nl_pid = getpid(),
		.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR |
				 RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE | RTMGRP_LINK,
	};

	if (bind(netlink_rtm_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		fatal_errno(PLUTO_EXIT_FAIL, logger, errno,
			    "failed to bind NETLINK_ROUTE bcast socket - perhaps kernel was not compiled with CONFIG_XFRM");
	}

	/* server.c will clean this up */
	add_fd_read_listener(netlink_rtm_fd, "rtm messages",
			     netlink_process_rtm_messages, NULL);
}

static void init_netlink_xfrm_fd(struct logger *logger)
{
	netlink_xfrm_fd = cloexec_socket(AF_NETLINK, SOCK_DGRAM|SOCK_NONBLOCK, NETLINK_XFRM);
	if (netlink_xfrm_fd < 0) {
		fatal_errno(PLUTO_EXIT_FAIL, logger, errno,
			    "socket() for bcast in init_netlink()");
	}

	struct sockaddr_nl addr;
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = getpid();
	addr.nl_pad = 0; /* make coverity happy */
	addr.nl_groups = XFRMGRP_ACQUIRE | XFRMGRP_EXPIRE;
	if (bind(netlink_xfrm_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		fatal_errno(PLUTO_EXIT_FAIL, logger, errno,
			    "Failed to bind bcast socket in init_netlink() - perhaps kernel was not compiled with CONFIG_XFRM");
	}

	/* server.c will clean this up */
	add_fd_read_listener(netlink_xfrm_fd, "xfrm messages",
			     netlink_process_xfrm_messages, NULL);

}

/*
 * init_netlink - Initialize the netlink interface.  Opens the sockets and
 * then binds to the broadcast socket.
 */
static void kernel_xfrm_init(struct logger *logger)
{
#define XFRM_ACQ_EXPIRES "/proc/sys/net/core/xfrm_acq_expires"
#define XFRM_STAT "/proc/net/xfrm_stat"

	struct stat buf;
	char line[255];
	ssize_t n;
	int fd = open(XFRM_ACQ_EXPIRES, O_RDONLY);
	int lifetime = 0;

	if ((fd == -1) && stat(XFRM_STAT, &buf) != 0) {
			fatal_errno(PLUTO_EXIT_KERNEL_FAIL, logger, errno,
			    "no XFRM kernel support detected, missing "XFRM_ACQ_EXPIRES" and "XFRM_STAT);
	}

	n = read(fd, line, sizeof(line));
	if (n == -1) {
		llog_error(logger, errno, "Failed to read %s - ignoring xfrmlifetime= option", XFRM_ACQ_EXPIRES);
	} else {
		close(fd);
		lifetime = atoi(line);
		if (lifetime != 0 && lifetime != pluto_xfrmlifetime) {
			fd = open(XFRM_ACQ_EXPIRES, O_WRONLY);
			if (fd == -1) {
				llog_error(logger, errno, "Failed to open %s for writing- ignoring xfrmlifetime= option", XFRM_ACQ_EXPIRES);
			} else {
				char numstr[255];

				sprintf(numstr,"%d", pluto_xfrmlifetime);
				n = write(fd, numstr, strlen(numstr));
				if (n == -1) {
					llog_error(logger, errno, "Failed to write %s - ignoring xfrmlifetime= option", XFRM_ACQ_EXPIRES);
				} else {
					ldbg(logger, "successfully set kernel xfrmlifetime=%s", numstr);
				}
			}
		}
	}

	nl_send_fd = cloexec_socket(AF_NETLINK, SOCK_DGRAM, NETLINK_XFRM);

	if (nl_send_fd < 0) {
		fatal_errno(PLUTO_EXIT_FAIL, logger, errno,
			    "socket() in init_netlink()");
	}

#ifdef SOL_NETLINK
	const int on = true;
	if (setsockopt(nl_send_fd, SOL_NETLINK, NETLINK_CAP_ACK,
		       (const void *)&on, sizeof(on)) < 0) {
		llog_errno(RC_LOG, logger, errno, "xfrm: setsockopt(NETLINK_CAP_ACK) failed: ");
	} else {
		ldbg(logger, "xfrm: setsockopt(NETLINK_CAP_ACK) ok");
	}
	if (setsockopt(nl_send_fd, SOL_NETLINK, NETLINK_EXT_ACK,
		       (const void *)&on, sizeof(on)) < 0) {
		llog_errno(RC_LOG, logger, errno, "xfrm: setsockopt(NETLINK_EXT_ACK) failed: ");
	} else {
		ldbg(logger, "xfrm: setsockopt(NETLINK_EXT_ACK) ok");
	}
#endif

	init_netlink_rtm_fd(logger);
	init_netlink_xfrm_fd(logger);

	/*
	 * Just assume any algorithm with a NETLINK_XFRM name works.
	 *
	 * Kind of lame since pluto should query the kernel for what
	 * it supports.  OTOH, the query might happen before the
	 * crypto module gets loaded.
	 */
	ldbg(logger, "Hard-wiring algorithms");
	for (const struct encrypt_desc **algp = next_encrypt_desc(NULL);
	     algp != NULL; algp = next_encrypt_desc(algp)) {
		const struct encrypt_desc *alg = *algp;
		if (alg->encrypt_netlink_xfrm_name != NULL) {
			kernel_encrypt_add(alg);
		}
	}
	for (const struct integ_desc **algp = next_integ_desc(NULL);
	     algp != NULL; algp = next_integ_desc(algp)) {
		const struct integ_desc *alg = *algp;
		if (alg->integ_netlink_xfrm_name != NULL) {
			kernel_integ_add(alg);
		}
	}
}

static void kernel_xfrm_flush(struct logger *logger)
{
	struct nlm_resp rsp;
	int recv_errno;

	struct nlmsghdr policy = {
		.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
		.nlmsg_type = XFRM_MSG_FLUSHPOLICY,
		.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(0)),
	};
	sendrecv_xfrm_msg(&policy, NLMSG_ERROR, &rsp,
			  "flush", "policy",
			  &recv_errno, logger);

	struct {
		struct nlmsghdr n;
		struct xfrm_usersa_flush f; /*protocol*/
	} state = {
		.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
		.n.nlmsg_type = XFRM_MSG_FLUSHSA,
		.n.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(state.f))),
		.f.proto = 0,
	};
	sendrecv_xfrm_msg(&state.n, NLMSG_ERROR, &rsp,
			  "flush", "state",
			  &recv_errno, logger);
}

static void llog_ext_ack(lset_t rc_flags, struct logger *logger,
			 const struct nlmsghdr *n)
{
#ifdef SOL_NETLINK
	if (n->nlmsg_type != NLMSG_ERROR ||
	    !(n->nlmsg_flags & NLM_F_ACK_TLVS)) {
		return;
	}

	struct nlmsgerr *err = (void *)n + NLMSG_HDRLEN;
	size_t offset = sizeof(*err);
	if (!(n->nlmsg_flags & NLM_F_CAPPED)) {
		offset += err->msg.nlmsg_len - NLMSG_HDRLEN;
	}

	for (const struct nlattr *attr = nl_getattr(n, &offset);
	     attr != NULL; attr = nl_getattr(n, &offset)) {
		if ((attr->nla_type & NLA_TYPE_MASK) == NLMSGERR_ATTR_MSG) {
			const char *msg = nl_getattrvalstrz(n, attr);
			if (msg) {
				llog(rc_flags, logger, "netlink ext_ack: %s",
				     msg);
			}
		}
	}
#else
	/* use the arguments */
	ldbg(logger, "ignoring "PRI_LSET" %p", rc_flags, n);
#endif
}

/*
 * sendrecv_xfrm_msg()
 *
 * @param hdr - Data to be sent.
 * @param expected_resp_type - type of message expected from netlink
 * @param rbuf - Return Buffer - contains data returned from the send.
 * @param description - String - user friendly description of what is
 *                      being attempted.  Used for diagnostics
 * @param story - String
 * @return bool True if the message was successfully sent.
 */

static bool sendrecv_xfrm_msg(struct nlmsghdr *hdr,
			      unsigned expected_resp_type, struct nlm_resp *rbuf,
			      const char *description, const char *story,
			      int *recv_errno,
			      struct logger *logger)
{
	size_t len = hdr->nlmsg_len;

	ldbg(logger, "%s() sending %d %s %s", __func__, hdr->nlmsg_type, description, story);
	if (DBGP(DBG_TMI)) {
		LDBG_dump(logger, hdr, len);
	}

	ssize_t r;
	static uint32_t seq = 0;	/* STATIC */

	*recv_errno = 0;

	hdr->nlmsg_seq = ++seq;
	do {
		r = write(nl_send_fd, hdr, len);
	} while (r < 0 && errno == EINTR);

	if (r < 0) {
		sparse_buf sb;
		llog_error(logger, errno,
			   "netlink write() of %s message for %s %s failed",
			   str_sparse(&xfrm_type_names, hdr->nlmsg_type, &sb),
			   description, story);
		return false;
	}

	if ((size_t)r != len) {
		sparse_buf sb;
		llog_error(logger, 0/*no-errno*/,
			   "netlink write() of %s message for %s %s truncated: %zd instead of %zu",
			   str_sparse(&xfrm_type_names, hdr->nlmsg_type, &sb),
			   description, story, r, len);
		return false;
	}

	struct nlm_resp rsp;
	for (;;) {
		struct sockaddr_nl addr;
		socklen_t alen = sizeof(addr);

		r = recvfrom(nl_send_fd, &rsp, sizeof(rsp), 0,
			(struct sockaddr *)&addr, &alen);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			*recv_errno = errno;
			sparse_buf sb;
			llog_error(logger, errno,
				   "netlink recvfrom() of response to our %s message for %s %s failed",
				   str_sparse(&xfrm_type_names, hdr->nlmsg_type, &sb),
				   description, story);
			return false;
		}

		ldbg(logger, "%s() recvfrom() returned %zd bytes", __func__, r);
		if (DBGP(DBG_TMI)) {
			LDBG_dump(logger, &rsp, r);
		}

		size_t l = (size_t) r; /* must be non -ve */
		if (l < sizeof(rsp.n)) {
			llog(RC_LOG, logger,
			     "netlink read truncated message: %zu bytes; ignore message", l);
			continue;
		}

		if (addr.nl_pid != 0) {
			/* not for us: ignore */
			sparse_buf sb;
			ldbg(logger, "%s() ignoring %s message from process %u",
			     __func__,
			     str_sparse(&xfrm_type_names, rsp.n.nlmsg_type, &sb),
			     addr.nl_pid);
			continue;
		}

		if (rsp.n.nlmsg_seq != seq) {
			sparse_buf sb;
			ldbg(logger, "%s() ignoring out of sequence (%u/%u) message %s",
			     __func__, rsp.n.nlmsg_seq, seq,
			     str_sparse(&xfrm_type_names, rsp.n.nlmsg_type, &sb));
			continue;
		}
		break;
	}

	if (rsp.n.nlmsg_len > (size_t) r) {
		sparse_buf sb;
		llog(RC_LOG, logger,
		     "netlink recvfrom() of response to our %s message for %s %s was truncated: %zd instead of %zu",
		     str_sparse(&xfrm_type_names, hdr->nlmsg_type, &sb),
		     description, story,
		     len, (size_t) rsp.n.nlmsg_len);
		return false;
	}

	if (rsp.n.nlmsg_type != expected_resp_type && rsp.n.nlmsg_type == NLMSG_ERROR) {
		if (rsp.u.e.error != 0) {
			llog_error(logger, -rsp.u.e.error,
				   "netlink response for %s %s", description, story);
			llog_ext_ack(RC_LOG, logger, &rsp.n);
			return false;
		}
		/*
		 * What the heck does a 0 error mean?
		 * Since the caller doesn't depend on the result
		 * we'll let it pass.
		 * This really happens for netlink_add_sa().
		 */
		if (DBGP(DBG_BASE)) {
			LDBG_log(logger, "%s() netlink response for %s %s included non-error error",
				 __func__, description, story);
			llog_ext_ack(DEBUG_STREAM, logger, &rsp.n);
		}
		/* ignore */
	}
	if (rbuf == NULL) {
		return true;
	}
	if (rsp.n.nlmsg_type != expected_resp_type) {
		sparse_buf sb1, sb2;
		llog(RC_LOG, logger,
		     "netlink recvfrom() of response to our %s message for %s %s was of wrong type (%s)",
		     str_sparse(&xfrm_type_names, hdr->nlmsg_type, &sb1),
		     description, story,
		     str_sparse(&xfrm_type_names, rsp.n.nlmsg_type, &sb2));
		return false;
	}
	memcpy(rbuf, &rsp, r);
	return true;
}

/*
 * sendrecv_xfrm_policy -
 *
 * @param hdr - Data to check
 * @param enoent_ok - Boolean - OK or not OK.
 * @param story - String
 * @return boolean
 */
static bool sendrecv_xfrm_policy(struct nlmsghdr *hdr,
				 enum expect_kernel_policy what_about_inbound,
				 const char *story, const char *adstory,
				 struct logger *logger, const char *func)
{
	struct nlm_resp rsp;

	int recv_errno;
	if (!sendrecv_xfrm_msg(hdr, NLMSG_ERROR, &rsp,
			       "policy", story,
			       &recv_errno, logger)) {
		return false;
	}

	/*
	 * Kind of surprising: we get here by success which implies an
	 * error structure!
	 */

	int error = -rsp.u.e.error;

	switch (what_about_inbound) {
	case IGNORE_KERNEL_POLICY_MISSING:
		if (error == 0) {
			/* pexpect? */
			sparse_buf sb;
			ldbg(logger,
			     "%s()   %s for flow %s %s had A policy",
			     func, str_sparse(&xfrm_type_names, hdr->nlmsg_type, &sb),
			     story, adstory);
			return true;
		}
		if (error == ENOENT) {
			/* pexpect? */
			sparse_buf sb;
			ldbg(logger,
			     "%s()   %s for flow %s %s had NO policy",
			     func, str_sparse(&xfrm_type_names, hdr->nlmsg_type, &sb),
			     story, adstory);
			return true;
		}
		break;
	case EXPECT_KERNEL_POLICY_OK:
		if (error == 0) {
			/* pexpect? */
			sparse_buf sb;
			ldbg(logger,
			     "%s()   %s for flow %s %s had A policy",
			     func, str_sparse(&xfrm_type_names, hdr->nlmsg_type, &sb),
			     story, adstory);
			return true;
		}
		break;
	case EXPECT_NO_INBOUND:
		if (error == ENOENT) {
			/* pexpect? */
			sparse_buf sb;
			ldbg(logger,
			     "%s()   %s for flow %s %s had NO policy",
			     func, str_sparse(&xfrm_type_names, hdr->nlmsg_type, &sb),
			     story, adstory);
			return true;
		}
		if (error == 0) {
			/* pexpect? */
			sparse_buf sb;
			llog(RC_LOG, logger,
			     "%s()   %s for flow %s %s encountered unexpected policy",
			     func, str_sparse(&xfrm_type_names, hdr->nlmsg_type, &sb),
			     story, adstory);
			return true;
		}
		break;
	}

	sparse_buf sb;
	llog_error(logger, error,
		   "kernel: xfrm %s %s response for flow %s",
		   str_sparse(&xfrm_type_names, hdr->nlmsg_type, &sb),
		   story, adstory);
	return false;
}

static void set_xfrm_selectors(struct xfrm_selector *sel,
			       const ip_selector *src_client,
			       const ip_selector *dst_client,
			       struct logger *logger)
{
	const struct ip_protocol *client_proto = selector_protocol(*src_client);
	pexpect(selector_protocol(*dst_client) == client_proto);

	const struct ip_info *dst_client_afi  = selector_type(dst_client);
	const int family = dst_client_afi->af;
	ldbg(logger, "%s() using family %s (%d)", __func__, dst_client_afi->ip_name, family);

	/* .[sd]addr, .prefixlen_[sd], .[sd]port */
	SELECTOR_TO_XFRM(*src_client, *sel, s);
	SELECTOR_TO_XFRM(*dst_client, *sel, d);

	/*
	 * Munge .[sd]port?
	 *
	 * As per RFC 4301/5996, icmp type is put in the most significant
	 * 8 bits and icmp code is in the least significant 8 bits of port
	 * field.
	 * Although Libreswan does not have any configuration options for
	 * icmp type/code values, it is possible to specify icmp type and code
	 * using protoport option. For example, icmp echo request
	 * (type 8/code 0) needs to be encoded as 0x0800 in the port field
	 * and can be specified as left/rightprotoport=icmp/2048. Now with
	 * XFRM, icmp type and code need to be passed as source and
	 * destination ports, respectively. Therefore, this code extracts
	 * upper 8 bits and lower 8 bits and puts into source and destination
	 * ports before passing to XFRM.
	 */
	if (client_proto == &ip_protocol_icmp ||
	    client_proto == &ip_protocol_icmpv6) {
		uint16_t tc = ntohs(sel->sport);
		uint16_t icmp_type = tc >> 8;
		uint16_t icmp_code = tc & 0xFF;

		sel->sport = htons(icmp_type);
		sel->dport = htons(icmp_code);
	}

	/* note: byte order doesn't change 0 or ~0 */
	sel->sport_mask = sel->sport == 0 ? 0 : ~0;
	sel->dport_mask = sel->dport == 0 ? 0 : ~0;
	sel->proto = client_proto->ipproto;
	sel->family = family;
}


/*
 * xfrm_raw_policy
 *
 * XXX: much of this is bogus
 *
 * @param kernel_policy_op op (operation - ie: KP_DELETE)
 * @param src_host ip_address
 * @param src_client ip_subnet
 * @param dst_host ip_address
 * @param dst_client ip_subnet
 * @param spi
 * @param sa_proto int (4=tunnel, 50=esp, 108=ipcomp, etc ...)
 * @param transport_proto unsigned int Contains protocol
 *	(6=tcp, 17=udp, etc...)
 * @param esatype int
 * @param pfkey_proto_info proto_info
 * @param use_lifetime monotime_t (Currently unused)
 * @param story char *
 * @return boolean True if successful
 */

static void add_xfrmi_marks(struct nlmsghdr *n,
			    const struct sa_marks *sa_marks,
			    const struct pluto_xfrmi *xfrmi,
			    const unsigned xfrm_dir,
			    unsigned short maxlen,
			    struct logger *logger)
{
	if (sa_marks != NULL) {
		if (xfrmi == NULL) {
			struct sa_mark sa_mark =
				(xfrm_dir == XFRM_POLICY_IN ? sa_marks->in :
				 sa_marks->out);

			if (sa_mark.val != 0 && sa_mark.mask != 0) {
				struct xfrm_mark xfrm_mark = {
					.v = sa_mark.val,
					.m = sa_mark.mask,
				};
				ldbg(logger, "%s() adding xfrm_mark %x/%x", __func__, xfrm_mark.v, xfrm_mark.m);
				/* append */
				struct rtattr *attr = (struct rtattr *)((uint8_t *)n + n->nlmsg_len);
				attr->rta_type = XFRMA_MARK;
				attr->rta_len = sizeof(xfrm_mark);
				memcpy(RTA_DATA(attr), &xfrm_mark, attr->rta_len);
				attr->rta_len = RTA_LENGTH(attr->rta_len);
				n->nlmsg_len += attr->rta_len;
			}
#ifdef USE_XFRM_INTERFACE
		} else {
			/* XXX: strange how this only looks at .out */
			ldbg(logger, "%s() adding XFRMA_IF_ID %" PRIu32 " n->nlmsg_type=%" PRIu32,
			     __func__, xfrmi->if_id, n->nlmsg_type);
			nl_addattr32(n, maxlen, XFRMA_IF_ID, xfrmi->if_id);
			if (sa_marks->out.val == 0 && sa_marks->out.mask == 0) {
				/* XFRMA_SET_MARK = XFRMA_IF_ID */
				nl_addattr32(n, maxlen, XFRMA_SET_MARK, xfrmi->if_id);
			} else {
				/* manually configured mark-out=mark/mask */
				nl_addattr32(n, maxlen, XFRMA_SET_MARK, sa_marks->out.val);
				nl_addattr32(n, maxlen, XFRMA_SET_MARK_MASK, sa_marks->out.mask);
			}
#endif
		}
	}
}

static void add_sec_label(struct nlmsghdr *n,
			  shunk_t sec_label,
			  struct logger *logger)
{
	if (sec_label.len > 0) {
		struct rtattr *attr = (struct rtattr *)((uint8_t *)n + n->nlmsg_len);
		struct xfrm_user_sec_ctx *uctx;

		passert(sec_label.len <= MAX_SECCTX_LEN);
		attr->rta_type = XFRMA_SEC_CTX;

		ldbg(logger, "%s() adding xfrm_user_sec_ctx sec_label="PRI_SHUNK" to kernel", __func__, pri_shunk(sec_label));
		attr->rta_len = RTA_LENGTH(sizeof(struct xfrm_user_sec_ctx) + sec_label.len);
		uctx = RTA_DATA(attr);
		uctx->exttype = XFRMA_SEC_CTX;
		uctx->len = sizeof(struct xfrm_user_sec_ctx) + sec_label.len;
		uctx->ctx_doi = XFRM_SC_DOI_LSM;
		uctx->ctx_alg = XFRM_SC_ALG_SELINUX;
		uctx->ctx_len = sec_label.len;
		memcpy(uctx + 1, sec_label.ptr, sec_label.len);
		n->nlmsg_len += attr->rta_len;
	}
}

static bool kernel_xfrm_policy_add(enum kernel_policy_op op,
				   enum direction dir,
				   const ip_selector *src_client,
				   const ip_selector *dst_client,
				   const struct kernel_policy *policy,
				   deltatime_t use_lifetime UNUSED,
				   struct logger *logger, const char *func)
{
	enum_buf op_str;
	enum_name_short(&kernel_policy_op_names, op, &op_str);
	enum_buf dir_str;
	enum_name_short(&direction_names, dir, &dir_str);

	const struct ip_protocol *client_proto = selector_protocol(*src_client);
	pexpect(selector_protocol(*dst_client) == client_proto);

	unsigned xfrm_action = UINT_MAX;
	const char *policy_name = NULL;
	/* shunt route */
	switch (policy->shunt) {
	case SHUNT_TRAP: /*ondemand*/
		PASSERT(logger, dir == DIRECTION_OUTBOUND);
		xfrm_action = XFRM_POLICY_ALLOW;
		policy_name = "%trap(allow)";
		break;
	case SHUNT_IPSEC:
		xfrm_action = XFRM_POLICY_ALLOW;
		policy_name = (policy->mode == KERNEL_MODE_TUNNEL ? ip_protocol_ipip.name :
			       policy->mode == KERNEL_MODE_TRANSPORT ? protocol_from_ipproto(policy->rule[policy->nr_rules-1].proto)->name :
			       "UNKNOWN");
		break;
	case SHUNT_PASS:
		xfrm_action = XFRM_POLICY_ALLOW;
		policy_name = "%pass(allow)";
		break;
	case SHUNT_DROP:
		/* used with type=passthrough - can it not use SHUNT_PASS ?? */
		xfrm_action = XFRM_POLICY_BLOCK;
		policy_name = "%drop(block)";
		break;
	case SHUNT_REJECT:
		/* used with type=passthrough - can it not use SHUNT_PASS ?? */
		xfrm_action = XFRM_POLICY_BLOCK;
		policy_name = "%reject(block)";
		break;
	case SHUNT_HOLD:
		/* used with type=passthrough - can it not use SHUNT_PASS ?? */
		xfrm_action = XFRM_POLICY_BLOCK;
		policy_name = "%hold(block)";
		break;
	case SHUNT_NONE:
		/* FAILURE=NONE should have been turned into
		 * NEGOTIATION */
		bad_case(policy->shunt);
	case SHUNT_UNSET:
		bad_case(policy->shunt);
	}
	PASSERT(logger, xfrm_action != UINT_MAX);
	PASSERT(logger, policy_name != NULL);

	const unsigned xfrm_dir =
		(op == KERNEL_POLICY_OP_ADD && dir == DIRECTION_INBOUND ? XFRM_POLICY_IN :
		 XFRM_POLICY_OUT);
	ldbg(logger, "%s()   policy=%s action=%d xfrm_dir=%d op=%s dir=%s",
	     func, policy_name, xfrm_action, xfrm_dir, op_str.buf, dir_str.buf);

	struct {
		struct nlmsghdr n;
		uint8_t data[MAX_NETLINK_DATA_SIZE];
	} req = {0};

	zero(&req);
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	const struct ip_info *dst_client_afi  = selector_type(dst_client);
	const int family = dst_client_afi->af;
	ldbg(logger, "%s() using family %s (%d)", __func__, dst_client_afi->ip_name, family);

	/*
	 * NEW will fail when an existing policy, UPD always
	 * works.  This seems to happen in cases with NAT'ed
	 * XP clients, or quick recycling/resurfacing of
	 * roadwarriors on the same IP.
	 *
	 * UPD is also needed for two separate tunnels with
	 * same end subnets.  Like A = B = C config where both
	 * A - B and B - C have tunnel A = C configured.
	 */
	req.n.nlmsg_type = XFRM_MSG_UPDPOLICY;
	req.n.nlmsg_len = NLMSG_SPACE(sizeof(struct xfrm_userpolicy_info));
	struct xfrm_userpolicy_info *info = NLMSG_DATA(&req.n);
	set_xfrm_selectors(&info->sel, src_client, dst_client, logger);

	/* The caller should have set the proper priority by now */
	info->priority = policy->priority.value;
	ldbg(logger, "%s() IPsec SA SPD priority set to %d", __func__, info->priority);

	info->action = xfrm_action;
	/* info->lft.soft_use_expires_seconds = deltasecs(use_lifetime); */
	info->lft.soft_byte_limit = XFRM_INF;
	info->lft.soft_packet_limit = XFRM_INF;
	info->lft.hard_byte_limit = XFRM_INF;
	info->lft.hard_packet_limit = XFRM_INF;
	info->dir = xfrm_dir;

	/*
	 * Add the encapsulation protocol found in proto_info[] that
	 * will carry the packets (which the kernel seems to call
	 * user_templ).
	 *
	 * This is not needed when deleting; and this is not needed
	 * when installing a PASS policy.
	 *
	 * XXX: why not just test proto_info - let caller decide if it
	 * is needed.  Lets find out.
	 */
	if (policy->nr_rules > 0 &&
	    pexpect(policy->shunt != SHUNT_PASS)) {
		struct xfrm_user_tmpl tmpls[4] = {0};

		passert(policy->nr_rules <= (int)elemsof(tmpls));
		/* only the first rule gets the worm; er tunnel flag */
		unsigned mode = (policy->mode == KERNEL_MODE_TUNNEL ? XFRM_MODE_TUNNEL :
				 XFRM_MODE_TRANSPORT);
		for (unsigned i = 0; i < policy->nr_rules; i++) {
			const struct kernel_policy_rule *rule = &policy->rule[i];
			struct xfrm_user_tmpl *tmpl = &tmpls[i];
			tmpl->reqid = rule->reqid;
			tmpl->id.proto = rule->proto;
			tmpl->optional = (rule->proto == KERNEL_PROTO_IPCOMP &&
					  xfrm_dir != XFRM_POLICY_OUT);
			tmpl->aalgos = tmpl->ealgos = tmpl->calgos = ~0;
			tmpl->family = address_type(&policy->dst.host)->af;

			/* set mode (tunnel or transport); then switch to transport */
			tmpl->mode = mode;
			if (mode == XFRM_MODE_TUNNEL) {
				/* tunnel mode needs addresses */
				tmpl->saddr = xfrm_from_address(&policy->src.host);
				tmpl->id.daddr = xfrm_from_address(&policy->dst.host);
			}
			mode = XFRM_MODE_TRANSPORT;

			address_buf sb, db;
			ldbg(logger, "%s() adding xfrm_user_tmpl reqid=%d id.proto=%d optional=%d family=%d mode=%d saddr=%s daddr=%s",
			     __func__,
			     tmpl->reqid,
			     tmpl->id.proto,
			     tmpl->optional,
			     tmpl->family,
			     tmpl->mode,
			     str_address(tmpl->mode == XFRM_MODE_TUNNEL ? &policy->src.host : &unset_address, &sb),
			     str_address(tmpl->mode == XFRM_MODE_TUNNEL ? &policy->dst.host : &unset_address, &db));
		}

		/* append  */
		struct rtattr *attr = (struct rtattr *)((char *)&req + req.n.nlmsg_len);
		attr->rta_type = XFRMA_TMPL;
		attr->rta_len = policy->nr_rules * sizeof(tmpls[0]);
		memcpy(RTA_DATA(attr), tmpls, attr->rta_len);
		attr->rta_len = RTA_LENGTH(attr->rta_len);
		req.n.nlmsg_len += attr->rta_len;

	}

	if (policy != NULL &&
	    policy->nic_offload.dev != NULL &&
	    policy->nic_offload.type == KERNEL_OFFLOAD_PACKET &&
	    (xfrm_dir == XFRM_POLICY_IN || xfrm_dir == XFRM_POLICY_OUT)) {

		const struct nic_offload *nic_offload = &policy->nic_offload;
		struct rtattr *attr = (struct rtattr *)
			((char *)&req + req.n.nlmsg_len);
		struct xfrm_user_offload *xuo;

		dbg("packet offload enabled via interface %s for IPsec policy",
			nic_offload->dev);
		attr->rta_type = XFRMA_OFFLOAD_DEV;
		attr->rta_len = RTA_LENGTH(sizeof(*xuo));
		xuo = RTA_DATA(attr);
		xuo->flags = XFRM_OFFLOAD_PACKET;
		xuo->ifindex = if_nametoindex(nic_offload->dev);
		req.n.nlmsg_len += attr->rta_len;
	}

	/*
	 * Add mark policy extension if present.
	 *
	 * XXX: again, can't the caller decide this?
	 *
	 * XXX: identical code in policy_add(), time to share?
	 */
	add_xfrmi_marks(&req.n, policy->sa_marks, policy->xfrmi, xfrm_dir, sizeof(req.data), logger);
	add_sec_label(&req.n, policy->sec_label, logger);

	enum expect_kernel_policy what_about_inbound =
		(op == KERNEL_POLICY_OP_ADD ? IGNORE_KERNEL_POLICY_MISSING :
		 EXPECT_KERNEL_POLICY_OK);
	bool ok = sendrecv_xfrm_policy(&req.n, what_about_inbound, policy_name,
				       (dir == DIRECTION_OUTBOUND ? "(out)" : "(in)"),
				       logger, func);

	/*
	 * ??? deal with any forwarding policy.
	 *
	 * For tunnel mode the inbound SA needs a add/delete a forward
	 * policy; from where, to where?  Why?
	 *
	 * XXX: and yes, the code below doesn't exactly do just that.
	 */
	if (dir == DIRECTION_INBOUND) {
		switch (op) {
		case KERNEL_POLICY_OP_ADD:
			if (!ok) {
				break;
			}
			if (policy->shunt == SHUNT_IPSEC &&
			    policy->mode == KERNEL_MODE_TRANSPORT) {
				break;
			}
			ldbg(logger, "%s() adding policy forward (suspect a tunnel)", __func__);
			info->dir = XFRM_POLICY_FWD;
			ok &= sendrecv_xfrm_policy(&req.n, what_about_inbound,
						   policy_name, "(fwd)",
						   logger, func);
			break;
		default:
			break; /*no-op*/
		}
	}
	return ok;
}

static bool kernel_xfrm_policy_del(enum direction direction,
				   enum expect_kernel_policy expect_kernel_policy,
				   const ip_selector *src_child,
				   const ip_selector *dst_child,
				   const struct sa_marks *sa_marks,
				   const struct pluto_xfrmi *xfrmi,
				   enum kernel_policy_id policy_id,
				   const shunk_t sec_label,
				   struct logger *logger, const char *func)
{
	const struct ip_protocol *child_proto = selector_protocol(*src_child);
	pexpect(selector_protocol(*dst_child) == child_proto);

	/* XXX: notice how this ignores KERNEL_OP_REPLACE!?! */
	const unsigned xfrm_dir =
		(direction == DIRECTION_INBOUND ? XFRM_POLICY_IN :
		 direction == DIRECTION_OUTBOUND ? XFRM_POLICY_OUT :
		 pexpect(0));

	struct {
		struct nlmsghdr n;
		uint8_t data[MAX_NETLINK_DATA_SIZE];
	} req = {0};

	zero(&req);
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	const struct ip_info *dst_child_afi  = selector_type(dst_child);
	const int family = dst_child_afi->af;
	ldbg(logger, "%s() using family %s (%d)", __func__, dst_child_afi->ip_name, family);

	req.n.nlmsg_type = XFRM_MSG_DELPOLICY;
	req.n.nlmsg_len = NLMSG_SPACE(sizeof(struct xfrm_userpolicy_id));
	struct xfrm_userpolicy_id *id = NLMSG_DATA(&req.n);
	id->dir = xfrm_dir;
	set_xfrm_selectors(&id->sel, src_child, dst_child, logger);
	id->index = policy_id;

	/*
	 * Add mark policy extension if present.
	 *
	 * XXX: again, can't the caller decide this?
	 *
	 * XXX: identical code in policy_add(), time to share?
	 */
	add_xfrmi_marks(&req.n, sa_marks, xfrmi, xfrm_dir, sizeof(req.data), logger);
	add_sec_label(&req.n, sec_label, logger);

	bool ok = sendrecv_xfrm_policy(&req.n, expect_kernel_policy, "delete",
				       (direction == DIRECTION_OUTBOUND ? "(out)" :
					direction == DIRECTION_INBOUND ? "(in)" :
					NULL),
				       logger, func);

	/*
	 * ??? deal with any forwarding policy.
	 *
	 * For tunnel mode the inbound SA needs a add/delete a forward
	 * policy; from where, to where?  Why?
	 *
	 * XXX: and yes, the code below doesn't exactly do just that.
	 */
	if (direction == DIRECTION_INBOUND) {
		/*
		 * ??? we will call netlink_policy even if !ok.
		 *
		 * XXX: It's also called when transport mode!
		 */
		ldbg(logger, "%s() deleting policy forward (even when there may not be one)",
		    __func__);
		id->dir = XFRM_POLICY_FWD;
		ok &= sendrecv_xfrm_policy(&req.n, IGNORE_KERNEL_POLICY_MISSING,
					   "delete", "(fwd)",
					   logger, func);
	}
	return ok;
}

struct kernel_migrate {
	struct kernel_migrate_end {
		/*
		 * For ESP/AH which is carried by raw IP packets, only an
		 * address is needed to identify an end.  However when
		 * encapsulated (in UDP or TCP) the port is also needed.
		 */
		ip_address address;
		int encap_port;
		/*
		 * This is not the subnet you're looking for: the transport
		 * selector or packet filter.
		 */
		ip_selector client;
		/*
		 * XXX: for mobike? does this need a port or is the port
		 * optional or unchanging? perhaps the port is assumed to be
		 * embedded in the address (making it an endpoint)
		 */
		ip_address new_address;
	} src, dst;

	int xfrm_dir;			/* xfrm has 3, in,out & fwd */
	ipsec_spi_t spi;
	const struct ip_protocol *proto;	/* ESP, AH, IPCOMP */
	const struct ip_encap *encap_type;	/* ESP-in-TCP, ESP-in-UDP; or NULL(transport?) */
	reqid_t reqid;

	/*
	 * size of buffer needed for "story"
	 *
	 * RFC 1886 old IPv6 reverse-lookup format is the bulkiest.
	 *
	 * Since the bufs have 2 char padding, this slightly
	 * overallocates.
	 */
	char story[16 + sizeof(said_buf) + sizeof(address_reversed_buf)];
};

static bool init_xfrm_kernel_migrate(struct child_sa *child,
				     const int xfrm_policy_dir,	/* netkey SA direction XFRM_POLICY_{IN,OUT,FWD} */
				     struct kernel_migrate *migrate)
{
	const struct connection *const c = child->sa.st_connection;
	pexpect(c->config->child_sa.encap_mode == ENCAP_MODE_TUNNEL);

	const struct ip_encap *encap_type =
		(child->sa.st_iface_endpoint->io->protocol == &ip_protocol_tcp) ? &ip_encap_esp_in_tcp :
		nat_traversal_detected(&child->sa) ? &ip_encap_esp_in_udp :
		NULL;
	ldbg_sa(child, "TCP/NAT: encap type "PRI_IP_ENCAP, pri_ip_encap(encap_type));

	const struct ip_protocol *proto;
	const struct ipsec_proto_info *proto_info;

	if (child->sa.st_esp.protocol == &ip_protocol_esp) {
		proto = &ip_protocol_esp;
		proto_info = &child->sa.st_esp;
	} else if (child->sa.st_ah.protocol == &ip_protocol_ah) {
		proto = &ip_protocol_ah;
		proto_info = &child->sa.st_ah;
	} else {
		return false;
	}

	struct spd_end_info {
		const struct spd_end *end;
		const ip_endpoint endpoint;
		const ipsec_spi_t spi;
	};

	const struct spd_end_info local = {
		.end = c->spd->local,
		.endpoint = child->sa.st_iface_endpoint->local_endpoint,
		.spi = proto_info->inbound.spi,
	};

	const struct spd_end_info remote = {
		.end = c->spd->remote,
		.endpoint = child->sa.st_remote_endpoint,
		.spi = proto_info->outbound.spi,
	};

	const struct spd_end_info *src, *dst;

	switch (xfrm_policy_dir) {
	case XFRM_POLICY_OUT:
		src = &local;
		dst = &remote;
		break;

	case XFRM_POLICY_IN:
	case XFRM_POLICY_FWD:	/* treat as inbound */
		src = &remote;
		dst = &local;
		break;

	default:
		bad_case(xfrm_policy_dir);
	}

	*migrate = (struct kernel_migrate) {
		.xfrm_dir = xfrm_policy_dir,
		.proto = proto,
		.encap_type = encap_type,
		.reqid = reqid_esp(c->child.reqid),
		.spi = dst->spi,
		.src = {
			.address = src->end->host->addr,
			.new_address = src->end->host->addr,	/* may change */
			.client = src->end->client,
			.encap_port = endpoint_hport(src->endpoint),	/* may change */
		},
		.dst = {
			.address = dst->end->host->addr,
			.new_address = dst->end->host->addr,	/* may change */
			.client = dst->end->client,
			.encap_port = endpoint_hport(dst->endpoint),	/* may change */
		},
		/* WWW what about sec_label? */
	};

	passert(endpoint_is_specified(child->sa.st_v2_mobike.local_endpoint) !=
		endpoint_is_specified(child->sa.st_v2_mobike.remote_endpoint));

	struct jambuf story_jb = ARRAY_AS_JAMBUF(migrate->story);
	const struct spd_end_info *old_ei;
	ip_endpoint new_ep;

	if (endpoint_is_specified(child->sa.st_v2_mobike.local_endpoint)) {
		jam_string(&story_jb, "initiator migrate kernel SA ");
		old_ei = &local;
		new_ep = child->sa.st_v2_mobike.local_endpoint;
	} else {
		jam_string(&story_jb, "responder migrate kernel SA ");
		old_ei = &remote;
		new_ep = child->sa.st_v2_mobike.remote_endpoint;
	}

	struct kernel_migrate_end *changing_ke = (old_ei == src) ? &migrate->src : &migrate->dst;

	changing_ke->new_address = endpoint_address(new_ep);
	changing_ke->encap_port = endpoint_hport(new_ep);

	if (encap_type == NULL)
		migrate->src.encap_port = migrate->dst.encap_port = 0;

	ip_said said = said_from_address_protocol_spi(dst->end->host->addr, proto, migrate->spi);
	jam_said(&story_jb, &said);

	endpoint_buf ra_old, ra_new;
	jam(&story_jb, ":%s to %s reqid=%u ",
	    str_endpoint(&old_ei->endpoint, &ra_old),
	    str_endpoint(&new_ep, &ra_new),
	    migrate->reqid);
	jam_enum(&story_jb, &xfrm_policy_names, xfrm_policy_dir);

	ldbg_sa(child, "%s", migrate->story);
	return true;
}

static bool migrate_xfrm_sa(const struct kernel_migrate *sa, struct logger *logger)
{
	struct {
		struct nlmsghdr n;
		struct xfrm_userpolicy_id id;
		char data[MAX_NETLINK_DATA_SIZE];
	} req;
	struct nlm_resp rsp;
	struct rtattr *attr;

	zero(&req);

	req.id.dir = sa->xfrm_dir;
	req.id.sel.family = address_info(sa->src.address)->af;
	/* .[sd]addr, .prefixlen_[sd], .[sd]port */
	SELECTOR_TO_XFRM(sa->src.client, req.id.sel, s);
	SELECTOR_TO_XFRM(sa->dst.client, req.id.sel, d);
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.n.nlmsg_type = XFRM_MSG_MIGRATE;
	req.n.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req.id)));

	/* add attrs[XFRM_MSG_MIGRATE] */
	{
		struct xfrm_user_migrate migrate;

		zero(&migrate);
		attr =  (struct rtattr *)((char *)&req + req.n.nlmsg_len);
		attr->rta_type = XFRMA_MIGRATE;
		attr->rta_len = sizeof(migrate);

		/* set the migration attributes */
		migrate.old_saddr = xfrm_from_address(&sa->src.address);
		migrate.old_daddr = xfrm_from_address(&sa->dst.address);
		migrate.new_saddr = xfrm_from_address(&sa->src.new_address);
		migrate.new_daddr = xfrm_from_address(&sa->dst.new_address);
		migrate.mode = XFRM_MODE_TUNNEL;
		migrate.proto = sa->proto->ipproto;
		migrate.reqid = sa->reqid;
		migrate.old_family = migrate.new_family = address_info(sa->src.address)->af;

		memcpy(RTA_DATA(attr), &migrate, attr->rta_len);
		attr->rta_len = RTA_LENGTH(attr->rta_len);
		req.n.nlmsg_len += attr->rta_len;
	}

	if (sa->encap_type != NULL) {
		ldbg(logger, "adding xfrm_encap_templ when migrating sa encap_type="PRI_IP_ENCAP" sport=%d dport=%d",
		     pri_ip_encap(sa->encap_type),
		     sa->src.encap_port, sa->dst.encap_port);
		attr = (struct rtattr *)((char *)&req + req.n.nlmsg_len);
		struct xfrm_encap_tmpl natt;

		natt.encap_type = sa->encap_type->encap_type;
		natt.encap_sport = ntohs(sa->src.encap_port);
		natt.encap_dport = ntohs(sa->dst.encap_port);
		zero(&natt.encap_oa);

		attr->rta_type = XFRMA_ENCAP;
		attr->rta_len = RTA_LENGTH(sizeof(natt));

		memcpy(RTA_DATA(attr), &natt, sizeof(natt));

		req.n.nlmsg_len += attr->rta_len;
	}

	/*
	 * Note: Coverity believes that req.n will be overrun
	 * but that is wrong: the type of req.n only covers the header.
	 * Maybe there is a way to write this that doesn't mislead Coverity.
	 */
	int recv_errno;
	bool r = sendrecv_xfrm_msg(&req.n, NLMSG_ERROR, &rsp,
				   "mobike", sa->story,
				   &recv_errno, logger);
	return r && rsp.u.e.error >= 0;
}

static bool xfrm_migrate_ipsec_sa(struct child_sa *child)
{
	if (child->sa.st_esp.protocol != &ip_protocol_esp) {
		llog_sa(RC_LOG, child, "mobike SA migration only support ESP SA");
		return false;
	}

	struct kernel_migrate migrate;

	return
		init_xfrm_kernel_migrate(child, XFRM_POLICY_OUT, &migrate) &&
		migrate_xfrm_sa(&migrate, child->sa.logger) &&

		init_xfrm_kernel_migrate(child, XFRM_POLICY_IN, &migrate) &&
		migrate_xfrm_sa(&migrate, child->sa.logger) &&

		init_xfrm_kernel_migrate(child, XFRM_POLICY_FWD, &migrate) &&
		migrate_xfrm_sa(&migrate, child->sa.logger);
}

/* see /usr/include/linux/ethtool.h */

enum nic_offload_state {
	NIC_OFFLOAD_UNKNOWN,
	NIC_OFFLOAD_UNSUPPORTED,
	NIC_OFFLOAD_SUPPORTED
};

static struct {
	unsigned int bit;
	unsigned int total_blocks;
	enum nic_offload_state state;
} netlink_esp_hw_offload;

static bool siocethtool(const char *ifname, void *data, const char *action, struct logger *logger)
{
	struct ifreq ifr = { .ifr_data = data };
	jam_str(ifr.ifr_name, sizeof(ifr.ifr_name), ifname);
	if (ioctl(nl_send_fd, SIOCETHTOOL, &ifr) != 0) {
		/* EOPNOTSUPP is expected if kernel doesn't support this */
		if (errno == EOPNOTSUPP) {
			ldbg(logger, "cannot offload to %s because SIOCETHTOOL %s failed: %s",
				ifname, action, strerror(errno));
		} else {
			llog_error(logger, errno, "can't offload to %s because SIOCETHTOOL %s failed",
				   ifname, action);
		}
		return false;
	} else {
		return true;
	}
}

static void netlink_find_offload_feature(const char *ifname,
					 struct logger *logger)
{
	netlink_esp_hw_offload.state = NIC_OFFLOAD_UNSUPPORTED;

	/* Determine number of device-features */

	struct ethtool_sset_info *sset_info = alloc_bytes(
		sizeof(*sset_info) + sizeof(sset_info->data[0]),
		"ethtool_sset_info");
	sset_info->cmd = ETHTOOL_GSSET_INFO;
	sset_info->sset_mask = 1ULL << ETH_SS_FEATURES;

	if (!siocethtool(ifname, sset_info, "ETHTOOL_GSSET_INFO", logger) ||
	    sset_info->sset_mask != 1ULL << ETH_SS_FEATURES) {
		pfree(sset_info);
		llog(RC_LOG, logger, "Kernel does not support NIC esp-hw-offload (ETHTOOL_GSSET_INFO failed)");
		return;
	}

	uint32_t sset_len = sset_info->data[0];

	pfree(sset_info);

	/* Retrieve names of device-features */

	struct ethtool_gstrings *cmd = alloc_bytes(
		sizeof(*cmd) + ETH_GSTRING_LEN * sset_len, "ethtool_gstrings");
	cmd->cmd = ETHTOOL_GSTRINGS;
	cmd->string_set = ETH_SS_FEATURES;

	if (siocethtool(ifname, cmd, "ETHTOOL_GSTRINGS", logger)) {
		/* Look for the ESP_HW feature bit */
		char *str = (char *)cmd->data;
		for (uint32_t i = 0; i < cmd->len; i++) {
			if (strneq(str, "esp-hw-offload", ETH_GSTRING_LEN)) {
				netlink_esp_hw_offload.bit = i;
				netlink_esp_hw_offload.total_blocks = (sset_len + 31) / 32;
				netlink_esp_hw_offload.state = NIC_OFFLOAD_SUPPORTED;
				break;
			}
			str += ETH_GSTRING_LEN;
		}
	}

	pfree(cmd);

	if (netlink_esp_hw_offload.state == NIC_OFFLOAD_SUPPORTED) {
		llog(RC_LOG, logger, "Kernel supports NIC esp-hw-offload");
	} else {
		llog(RC_LOG, logger, "Kernel does not support NIC esp-hw-offload");
	}
}

static bool xfrm_detect_nic_offload(const char *ifname, struct logger *logger)
{
	/*
	 * Kernel requires a real interface in order to query the kernel-wide
	 * capability, so we do it here on first invocation.
	 */
	if (netlink_esp_hw_offload.state == NIC_OFFLOAD_UNKNOWN)
		netlink_find_offload_feature(ifname, logger);

	if (netlink_esp_hw_offload.state == NIC_OFFLOAD_UNSUPPORTED) {
		return false;
	}

	/* Feature is supported by kernel. Query device features */

	struct ethtool_gfeatures *cmd = alloc_bytes(
		sizeof(*cmd) + sizeof(cmd->features[0]) * netlink_esp_hw_offload.total_blocks,
		"ethtool_gfeatures");

	cmd->cmd = ETHTOOL_GFEATURES;
	cmd->size = netlink_esp_hw_offload.total_blocks;

	bool ret = false;

	if (siocethtool(ifname, cmd, "ETHTOOL_GFEATURES", logger)) {
		int block = netlink_esp_hw_offload.bit / 32;
		uint32_t feature_bit = 1U << (netlink_esp_hw_offload.bit % 32);
		if (cmd->features[block].active & feature_bit)
			ret = true;
	}
	pfree(cmd);
	return ret;
}

/*
 * netlink_add_sa - Add an SA into the kernel SPDB via netlink
 *
 * @param sa Kernel SA to add/modify
 * @param replace boolean - true if this replaces an existing SA
 * @return bool True if successful
 */
static bool netlink_add_sa(const struct kernel_state *sa, bool replace,
			   struct logger *logger)
{
	struct {
		struct nlmsghdr n;
		struct xfrm_usersa_info p;
		char data[MAX_NETLINK_DATA_SIZE];
	} req;
	struct rtattr *attr;

	zero(&req);
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.n.nlmsg_type = replace ? XFRM_MSG_UPDSA : XFRM_MSG_NEWSA;

	req.p.seq = sa->state_id;

	req.p.saddr = xfrm_from_address(&sa->src.address);
	req.p.id.daddr = xfrm_from_address(&sa->dst.address);

	req.p.id.spi = sa->spi;
	req.p.id.proto = sa->proto->ipproto;
	req.p.family = address_info(sa->src.address)->af;

	/*
	 * No known hardware supports packet offload with ESPinUDP/ESPinTCP
	 */
	if (sa->encap_type != NULL && sa->nic_offload.dev != NULL &&
	    sa->nic_offload.type == KERNEL_OFFLOAD_PACKET) {
		llog(RC_LOG, logger, "connection cannot be NAT'ed and use nic-offload=packet");
		return false;
	}

	/*
	 * This requires ipv6 modules. It is required to support 6in4
	 * and 4in6 tunnels in linux 2.6.25+
	 */
	switch (sa->mode) {
	case KERNEL_MODE_TUNNEL:
		/* Only the innermost SA gets the "tunnel" flag. */
		if (sa->level == 0) {
			ldbg(logger, "%s() tunnel enabling inner-most tunnel mode", __func__);
			req.p.mode = XFRM_MODE_TUNNEL;
			req.p.flags |= XFRM_STATE_AF_UNSPEC;
		} else {
			ldbg(logger, "%s() tunnel enabling non-inner transport mode", __func__);
			req.p.mode = XFRM_MODE_TRANSPORT;
		}
		break;
	case KERNEL_MODE_TRANSPORT:
		ldbg(logger, "%s() transport enabling transport mode", __func__);
		req.p.mode = XFRM_MODE_TRANSPORT;
		break;
	default:
		bad_enum(logger, &kernel_mode_names, sa->mode);
	}

	/*
	 * We only add traffic selectors for transport mode.
	 *
	 * The problem is that Tunnel mode ipsec with ipcomp is
	 * layered so that ipcomp tunnel is protected with transport
	 * mode ipsec but in this case we shouldn't any more add
	 * traffic selectors. Caller function will inform us if we
	 * need or don't need selectors.
	 */
	if (sa->mode == KERNEL_MODE_TRANSPORT) {
		set_xfrm_selectors(&req.p.sel, &sa->src.route, &sa->dst.route, logger);
	}

	req.p.reqid = sa->reqid;
	ldbg(logger, "%s() adding IPsec SA with reqid %d", __func__, sa->reqid);

	if (sa->nic_offload.dev == NULL /* i.e., no offload */ ||
	    sa->nic_offload.type != KERNEL_OFFLOAD_PACKET) {
		req.p.lft.soft_byte_limit = sa->sa_max_soft_bytes;
		req.p.lft.hard_byte_limit = sa->sa_ipsec_max_bytes;
		req.p.lft.hard_packet_limit = sa->sa_ipsec_max_packets;
		req.p.lft.soft_packet_limit = sa->sa_max_soft_packets;
	} else {
		/* This has further FIPS implications :/ */
		req.p.lft.soft_byte_limit = XFRM_INF;
		req.p.lft.hard_byte_limit = XFRM_INF;
		req.p.lft.hard_packet_limit = XFRM_INF;
		req.p.lft.soft_packet_limit = XFRM_INF;
	}

	req.n.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req.p)));

	attr = (struct rtattr *)((char *)&req + req.n.nlmsg_len);

	/*
	 * The Linux IPv4 AH stack aligns the AH header on a 64 bit boundary
	 * (like in IPv6). This is not RFC compliant (see RFC4302, Section
	 * 3.3.3.2.1), it should be aligned on 32 bits.
	 *
	 * For most of the authentication algorithms, the ICV size is 96 bits.
	 * The AH header alignment on 32 or 64 bits gives the same results.
	 *
	 * However for SHA-256-128 for instance, the wrong 64 bit alignment results
	 * in adding useless padding in IPv4 AH, which is forbidden by the RFC.
	 *
	 * To avoid breaking backward compatibility, we use a new flag
	 * (XFRM_STATE_ALIGN4) do change original behavior.
	*/
	if (sa->proto == &ip_protocol_ah &&
	    address_info(sa->src.address) == &ipv4_info) {
		ldbg(logger, "xfrm: aligning IPv4 AH to 32bits as per RFC-4302, Section 3.3.3.2.1");
		req.p.flags |= XFRM_STATE_ALIGN4;
	}

	if (sa->proto != &ip_protocol_ipcomp) {
		if (sa->esn) {
			ldbg(logger, "%s() enabling ESN", __func__);
			req.p.flags |= XFRM_STATE_ESN;
		}
		if (sa->decap_dscp) {
			ldbg(logger, "%s() enabling Decap DSCP", __func__);
			req.p.flags |= XFRM_STATE_DECAP_DSCP;
		}
		if (!sa->encap_dscp) {
			ldbg(logger, "%s() disabling Encap DSCP", __func__);
			__u32 extra_flags = XFRM_SA_XFLAG_DONT_ENCAP_DSCP;
			attr->rta_type = XFRMA_SA_EXTRA_FLAGS;
			attr->rta_len = RTA_LENGTH(sizeof(extra_flags));
			memcpy(RTA_DATA(attr), &extra_flags, sizeof(extra_flags));
			req.n.nlmsg_len += attr->rta_len;
			attr = (struct rtattr *)((char *)&req + req.n.nlmsg_len);
		}
		if (sa->nopmtudisc) {
			ldbg(logger, "%s() disabling Path MTU Discovery", __func__);
			req.p.flags |= XFRM_STATE_NOPMTUDISC;
		}

		if (sa->replay_window <= 32 && !sa->esn) {
			/* this only works up to 32, for > 32 and for ESN, we need struct xfrm_replay_state_esn */
			req.p.replay_window = sa->replay_window;
			ldbg(logger, "%s() setting IPsec SA replay-window to %d using old-style req",
			     __func__, req.p.replay_window);
		} else {
			uint32_t bmp_size = BYTES_FOR_BITS(sa->replay_window +
				pad_up(sa->replay_window, sizeof(uint32_t) * BITS_IN_BYTE) );
			/* this is where we could fill in sequence numbers for this SA */
			struct xfrm_replay_state_esn xre = {
				/* replay_window must be multiple of 8 */
				.replay_window = sa->replay_window,
				.bmp_len = bmp_size / sizeof(uint32_t),
			};
			ldbg(logger, "%s() setting IPsec SA replay-window to %" PRIu32 " using xfrm_replay_state_esn",
			     __func__, xre.replay_window);

			attr->rta_type = XFRMA_REPLAY_ESN_VAL;
			attr->rta_len = RTA_LENGTH(sizeof(xre) + bmp_size);
			memcpy(RTA_DATA(attr), &xre, sizeof(xre));
			req.n.nlmsg_len += attr->rta_len;
			attr = (struct rtattr *)((char *)&req + req.n.nlmsg_len);
		}
	}

	if (sa->integ_key.len > 0) {
		const char *name = sa->integ->integ_netlink_xfrm_name;
		if (name == NULL) {
			llog(RC_LOG, logger,
				    "XFRM: unknown authentication algorithm: %s",
				    sa->integ->common.fqn);
			return false;
		}

		/*
		 * According to RFC-4868 the hash should be nnn/2, so
		 * 128 bits for SHA256 and 256 for SHA512.  The XFRM
		 * kernel uses a default of 96, which was the value in
		 * an earlier draft. The kernel then introduced a new
		 * struct xfrm_algo_auth to replace struct xfrm_algo
		 * to deal with this.
		 *
		 * Populate XFRM_ALGO_AUTH structure up to, but not
		 * including, .alg_key[] using the stack.  Can't
		 * populate RTA_DATA(attr) directly as it may not be
		 * correctly aligned.
		 */
		size_t alg_key_offset = offsetof(struct xfrm_algo_auth, alg_key);
		struct xfrm_algo_auth algo = {
			.alg_key_len = sa->integ->integ_keymat_size * BITS_IN_BYTE,
			.alg_trunc_len = sa->integ->integ_output_size * BITS_IN_BYTE,
		};
		fill_and_terminate(algo.alg_name, name, sizeof(algo.alg_name));

		/*
		 * Now copy all of XFRM_ALGO_AEAD structure up to, but
		 * not including, .alg_key[], to RTA_DATA(attr), and
		 * then append the encryption key at .alg_key[]'s
		 * offset.
		 */

		attr->rta_type = XFRMA_ALG_AUTH_TRUNC;
		attr->rta_len = RTA_LENGTH(alg_key_offset + sa->integ_key.len);

		memcpy(RTA_DATA(attr), &algo, alg_key_offset);
		memcpy((char *)RTA_DATA(attr) + alg_key_offset, sa->integ_key.ptr, sa->integ_key.len);

		req.n.nlmsg_len += attr->rta_len;
		attr = (struct rtattr *)((char *)attr + attr->rta_len);
	}

	/*
	 * ??? why does IPCOMP trump aead and ESP?
	 *  Shouldn't all be bundled?
	 */
	if (sa->proto == &ip_protocol_ipcomp) {

		if (!pexpect(sa->ipcomp != NULL)) {
			return false;
		}

		const char *calg_name = sa->ipcomp->kernel.xfrm_name;
		if (calg_name == NULL) {
			llog(RC_LOG, logger,
			     "unsupported compression algorithm: %s",
			     sa->ipcomp->common.fqn);
			return false;
		}

		struct xfrm_algo algo;
		fill_and_terminate(algo.alg_name, calg_name, sizeof(algo.alg_name));
		algo.alg_key_len = 0;

		/* append */
		attr->rta_type = XFRMA_ALG_COMP;
		attr->rta_len = RTA_LENGTH(sizeof(algo));
		memcpy(RTA_DATA(attr), &algo, sizeof(algo));
		req.n.nlmsg_len += attr->rta_len;
		attr = (struct rtattr *)((char *)attr + attr->rta_len);

	} else if (sa->proto == &ip_protocol_esp) {
		const char *name = sa->encrypt->encrypt_netlink_xfrm_name;

		if (name == NULL) {
			llog(RC_LOG, logger,
				    "unknown encryption algorithm: %s",
				    sa->encrypt->common.fqn);
			return false;
		}

		if (encrypt_desc_is_aead(sa->encrypt)) {
			/*
			 * Populate XFRM_ALGO_AEAD structure up to,
			 * but not including, .alg_key[] using the
			 * stack.  Can't populate RTA_DATA(attr)
			 * directly as it may not be correctly
			 * aligned.
			 */
			size_t alg_key_offset = offsetof(struct xfrm_algo_aead, alg_key);
			struct xfrm_algo_aead algo = {
				.alg_key_len = sa->encrypt_key.len * BITS_IN_BYTE,
				.alg_icv_len = sa->encrypt->aead_tag_size * BITS_IN_BYTE,
			};
			fill_and_terminate(algo.alg_name, name, sizeof(algo.alg_name));

			/*
			 * Now copy all of XFRM_ALGO_AEAD structure up
			 * to, but not including, .alg_key[], to
			 * RTA_DATA(attr), and then append the
			 * encryption key at .alg_key[]'s offset.
			 */
			attr->rta_type = XFRMA_ALG_AEAD;
			attr->rta_len = RTA_LENGTH(alg_key_offset + sa->encrypt_key.len);

			memcpy(RTA_DATA(attr), &algo, alg_key_offset);
			memcpy((char *)RTA_DATA(attr) + alg_key_offset, sa->encrypt_key.ptr, sa->encrypt_key.len);

			req.n.nlmsg_len += attr->rta_len;
			attr = (struct rtattr *)((char *)attr + attr->rta_len);

		} else {
			/*
			 * Populate XFRM_ALGO structure up to, but not
			 * including, .alg_key[] using the stack.
			 * Can't populate RTA_DATA(attr) directly as
			 * it may not be correctly aligned.
			 */
			size_t alg_key_offset = offsetof(struct xfrm_algo, alg_key);
			struct xfrm_algo algo = {
				.alg_key_len = sa->encrypt_key.len * BITS_IN_BYTE,
			};
			fill_and_terminate(algo.alg_name, name, sizeof(algo.alg_name));

			/*
			 * Now copy all of XFRM_ALGO structure up to,
			 * but not including, .alg_key[], to
			 * RTA_DATA(attr), and then append the
			 * encryption key at .alg_key[]'s offset.
			 */
			attr->rta_type = XFRMA_ALG_CRYPT;
			attr->rta_len = RTA_LENGTH(alg_key_offset + sa->encrypt_key.len);
			memcpy(RTA_DATA(attr), &algo, alg_key_offset);
			memcpy((char *)RTA_DATA(attr) + alg_key_offset, sa->encrypt_key.ptr, sa->encrypt_key.len);

			req.n.nlmsg_len += attr->rta_len;
			attr = (struct rtattr *)((char *)attr + attr->rta_len);

		}
		/*
		 * Traffic Flow Confidentiality is only for
		 * ESP tunnel mode (which is only on outer
		 * level).
		 */
		if (sa->tfcpad != 0 &&
		    sa->mode == KERNEL_MODE_TUNNEL &&
		    sa->level == 0) {
			ldbg(logger, "%s() setting TFC to %" PRIu32 " (up to PMTU)",
			     __func__, sa->tfcpad);

			attr->rta_type = XFRMA_TFCPAD;
			attr->rta_len = RTA_LENGTH(sizeof(sa->tfcpad));
			memcpy(RTA_DATA(attr), &sa->tfcpad, sizeof(sa->tfcpad));
			req.n.nlmsg_len += attr->rta_len;
			attr = (struct rtattr *)((char *)attr + attr->rta_len);

		}
	}

	if (sa->encap_type != NULL) {
		dbg("adding xfrm-encap-tmpl when adding sa encap_type="PRI_IP_ENCAP" sport=%d dport=%d",
		    pri_ip_encap(sa->encap_type),
		    sa->src.encap_port, sa->dst.encap_port);
		struct xfrm_encap_tmpl natt;

		natt.encap_type = sa->encap_type->encap_type;
		natt.encap_sport = ntohs(sa->src.encap_port);
		natt.encap_dport = ntohs(sa->dst.encap_port);
		zero(&natt.encap_oa);

		attr->rta_type = XFRMA_ENCAP;
		attr->rta_len = RTA_LENGTH(sizeof(natt));

		memcpy(RTA_DATA(attr), &natt, sizeof(natt));

		req.n.nlmsg_len += attr->rta_len;
		attr = (struct rtattr *)((char *)attr + attr->rta_len);
	}

#ifdef USE_XFRM_INTERFACE
	if (sa->xfrm_if_id != 0) {
		dbg("%s xfrm: XFRMA_IF_ID %" PRIu32 " req.n.nlmsg_type=%" PRIu32,
		    __func__, sa->xfrm_if_id, req.n.nlmsg_type);
		nl_addattr32(&req.n, sizeof(req.data), XFRMA_IF_ID, sa->xfrm_if_id);
		if (sa->mark_set.val != 0 || sa->mark_set.mask != 0) {
			/* manually configured mark-out=mark/mask */
			nl_addattr32(&req.n, sizeof(req.data), XFRMA_SET_MARK, sa->mark_set.val);
			nl_addattr32(&req.n, sizeof(req.data), XFRMA_SET_MARK_MASK, sa->mark_set.mask);
		} else {
			/* XFRMA_SET_MARK = XFRMA_IF_ID */
			nl_addattr32(&req.n, sizeof(req.data), XFRMA_SET_MARK, sa->xfrm_if_id);
		}
		attr = (struct rtattr *)((char *)&req + req.n.nlmsg_len);
	}
#endif

	if (sa->nic_offload.dev != NULL) {
		struct xfrm_user_offload xuo = {
			.ifindex = if_nametoindex(sa->nic_offload.dev),
		};

		switch (sa->direction) {
		case DIRECTION_INBOUND: xuo.flags |= XFRM_OFFLOAD_INBOUND; break;
		case DIRECTION_OUTBOUND: xuo.flags |= 0; break;
		}

		switch (sa->nic_offload.type) {
		case KERNEL_OFFLOAD_PACKET: xuo.flags |= XFRM_OFFLOAD_PACKET; break;
		case KERNEL_OFFLOAD_CRYPTO: xuo.flags |= 0; break;
		case KERNEL_OFFLOAD_NONE: bad_case(KERNEL_OFFLOAD_NONE);
		}

		switch (address_info(sa->src.address)->ip_version) {
		case IPv4: xuo.flags |= 0; break;
		case IPv6: xuo.flags |= XFRM_OFFLOAD_IPV6; break;
		}

		attr->rta_type = XFRMA_OFFLOAD_DEV;
		attr->rta_len = RTA_LENGTH(sizeof(xuo));

		memcpy(RTA_DATA(attr), &xuo, sizeof(xuo));

		req.n.nlmsg_len += attr->rta_len;
		attr = (struct rtattr *)((char *)attr + attr->rta_len);
		ldbg(logger, "%s() esp-hw-offload set via interface %s for IPsec SA, type: %s",
		     __func__, sa->nic_offload.dev,
		     sa->nic_offload.type == KERNEL_OFFLOAD_PACKET ? "Packet" : "Crypto");
	} else {
		ldbg(logger, "%s() esp-hw-offload not set for IPsec SA", __func__);
	}

	if (sa->sec_label.len != 0) {
		struct xfrm_user_sec_ctx xuctx;

		xuctx.len = sizeof(struct xfrm_user_sec_ctx) + sa->sec_label.len;
		xuctx.exttype = XFRMA_SEC_CTX;
		xuctx.ctx_alg = XFRM_SC_ALG_SELINUX; /* 1 */
		xuctx.ctx_doi = XFRM_SC_DOI_LSM; /* 1 */
		xuctx.ctx_len = sa->sec_label.len;

		attr->rta_type = XFRMA_SEC_CTX;
		attr->rta_len = RTA_LENGTH(xuctx.len);

		memcpy(RTA_DATA(attr), &xuctx, sizeof(xuctx));
		memcpy((char *)RTA_DATA(attr) + sizeof(xuctx),
			sa->sec_label.ptr, sa->sec_label.len);

		req.n.nlmsg_len += attr->rta_len;

		/* attr not subsequently used */
		attr = (struct rtattr *)((char *)attr + attr->rta_len);
	}

	int recv_errno;
	bool ret = sendrecv_xfrm_msg(&req.n, NLMSG_NOOP, NULL,
				     "Add SA", sa->story,
				     &recv_errno, logger);
	if (!ret && recv_errno == ESRCH &&
	    req.n.nlmsg_type == XFRM_MSG_UPDSA) {
		llog(RC_LOG, logger,
			    "Warning: kernel expired our reserved IPsec SA SPI - negotiation took too long? Try increasing /proc/sys/net/core/xfrm_acq_expires");
	}
	return ret;
}

/*
 * netlink_del_sa - Delete an SA from the Kernel
 *
 * @param sa Kernel SA to be deleted
 * @return bool True if successful
 */
static bool xfrm_del_ipsec_spi(ipsec_spi_t spi,
			       const struct ip_protocol *proto,
			       const ip_address *src_address,
			       const ip_address *dst_address,
			       const char *story,
			       struct logger *logger)
{
	struct {
		struct nlmsghdr n;
		struct xfrm_usersa_id id;
		char data[MAX_NETLINK_DATA_SIZE];
	} req;

	zero(&req);
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.n.nlmsg_type = XFRM_MSG_DELSA;

	req.id.daddr = xfrm_from_address(dst_address);

	req.id.spi = spi;
	req.id.family = address_type(src_address)->af;
	req.id.proto = proto->ipproto;

	req.n.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req.id)));

	int recv_errno;
	return sendrecv_xfrm_msg(&req.n, NLMSG_NOOP, NULL,
				 "Del SA", story,
				 &recv_errno, logger);
}

/*
 * Create ip_address out of xfrm_address_t.
 *
 * @param family
 * @param src xfrm formatted IP address
 * @param dst ip_address formatted destination
 * @return err_t NULL if okay, otherwise an error
 */

static struct ip_bytes bytes_from_xfrm_address(const struct ip_info *afi,
					       const xfrm_address_t *xaddr)
{
	struct ip_bytes bytes = unset_ip_bytes;
	memcpy(&bytes, xaddr, afi->ip_size);
	return bytes;
}

static ip_address address_from_xfrm(const struct ip_info *afi,
				    const xfrm_address_t *xaddr)
{
	ip_address address = unset_address;
	diag_t diag = data_to_address(xaddr, sizeof(*xaddr), afi, &address);
	if (diag != NULL) {
		llog_pexpect(&global_logger, HERE, "invalid xfrm address: %s",
			     str_diag(diag));
		pfree_diag(&diag);
		return unset_address;
	}
	return address;
}

/*
 * Create the client's ip_endpoint from xfrm_address_t:NPORT.
 */

static ip_packet packet_from_xfrm_selector(const struct ip_info *afi,
					   const struct xfrm_selector *sel)
{
	const struct ip_protocol *protocol = protocol_from_ipproto(sel->proto);
	passert(protocol != NULL); /* sel.proto is a byte, right? */

	struct ip_bytes src_bytes = bytes_from_xfrm_address(afi, &sel->saddr);
	struct ip_bytes dst_bytes = bytes_from_xfrm_address(afi, &sel->daddr);
	return packet_from_raw(HERE,
			       afi, &src_bytes, &dst_bytes,
			       protocol, ip_nport(sel->sport), ip_nport(sel->dport));
}

static const void *nlmsg_data(struct nlmsghdr *n, size_t size, struct logger *logger, where_t where)
{
	if (n->nlmsg_len < NLMSG_LENGTH(size)) {
		sparse_buf sb;
		llog(RC_LOG, logger,
		     "%s() got %s message with length %"PRIu32" < %zu bytes; ignore message",
		     where->func,
		     str_sparse(&xfrm_type_names, n->nlmsg_type, &sb),
		     n->nlmsg_len, size);
		return NULL;
	}
	dbg("xfrm netlink msg len %zu", (size_t) n->nlmsg_len);
	return NLMSG_DATA(n);
}

static void netlink_acquire(struct nlmsghdr *n, struct logger *logger)
{
	/*
	 * WARNING: netlink only guarantees 32-bit alignment.  See
	 * NLMSG_ALIGNTO in the kernel's include/uapi/linux/netlink.h.
	 * BUT some fields in struct xfrm_user_acquire are 64-bit and
	 * so access may be improperly aligned.  This will fail on a
	 * few strict architectures (it does break C rules).
	 *
	 * WARNING: this code's understanding to the XFRM netlink
	 * messages is from programs/pluto/linux26/xfrm.h.  There is
	 * no guarantee that this matches the kernel's understanding.
	 *
	 * Many things are defined to be int or unsigned int.  This
	 * isn't safe when the kernel and userland may be compiled
	 * with different models.
	 */
	const struct xfrm_user_acquire *acquire = /* insufficiently unaligned */
		nlmsg_data(n, sizeof(*acquire), logger, HERE);
	if (acquire == NULL) {
		return;
	}

	/* XXX: kernel's __u64 != uintmax_t */
	LDBGP_JAMBUF(DBG_BASE, logger, buf) {
		jam(buf, "xfrm_user_acquire ");
		jam(buf, " ");
		jam(buf, "id {");
		jam(buf, " daddr: xfrm_address_t");
		jam(buf, " spi: %jx", (uintmax_t) acquire->id.spi);
		jam(buf, " proto: %jx", (uintmax_t) acquire->id.proto);
		jam(buf, " saddr: struct xfrm_address_t");
		jam(buf, " sel: struct xfrm_selector");
		jam(buf, "}");
		jam(buf, " ");
		jam(buf, "policy {");
		jam(buf, " ");
		jam(buf, "lft {");
		/* XXX: kernel's __u64 != uint64_t */
		jam(buf, " soft_add_expires_seconds=%ju", (uintmax_t)acquire->policy.lft.soft_add_expires_seconds);
		jam(buf, " hard_add_expires_seconds=%ju", (uintmax_t)acquire->policy.lft.hard_add_expires_seconds);
		jam(buf, " soft_use_expires_seconds=%ju", (uintmax_t)acquire->policy.lft.soft_use_expires_seconds);
		jam(buf, " hard_use_expires_seconds=%ju", (uintmax_t)acquire->policy.lft.hard_use_expires_seconds);
		jam(buf, "}");
		jam(buf, " ");
		jam(buf, "curlft {");
		jam(buf, " add_time=%s", (uintmax_t)acquire->policy.curlft.add_time > 0 ? ">0" : "0");
		jam(buf, " use_time=%s", (uintmax_t)acquire->policy.curlft.use_time > 0 ? ">0" : "0");
		jam(buf, "}");
		jam(buf, " ");
		jam(buf, "}");
		jam(buf, " aalgos: %u", (unsigned) acquire->aalgos);
		jam(buf, " ealgos: %u", (unsigned) acquire->ealgos);
		jam(buf, " calgos: %u", (unsigned) acquire->calgos);
		jam(buf, " seq: %u", (unsigned) acquire->seq);
	}

	shunk_t sec_label = NULL_HUNK;
	const struct ip_info *afi = aftoinfo(acquire->policy.sel.family);
	if (afi == NULL) {
		llog(RC_LOG, logger,
		     "XFRM_MSG_ACQUIRE message from kernel malformed: family %u unknown",
		     acquire->policy.sel.family);
		return;
	}

	if (acquire->sel.prefixlen_s != afi->mask_cnt) {
		llog(RC_LOG, logger,
		     "XFRM_MSG_ACQUIRE message from kernel malformed: prefixlen_s %u invalid",
		     acquire->sel.prefixlen_s);
		return;
	}

	if (acquire->sel.prefixlen_d != afi->mask_cnt) {
		llog(RC_LOG, logger,
		     "XFRM_MSG_ACQUIRE message from kernel malformed: prefixlen_d %u invalid",
		     acquire->sel.prefixlen_d);
		return;
	}

	ip_packet packet = packet_from_xfrm_selector(afi, &acquire->sel);

	/*
	 * Run through rtattributes looking for XFRMA_SEC_CTX
	 * Instead, it should loop through all (known rtattributes
	 * and use/log them.
	 */
	struct rtattr *attr = (struct rtattr *)
		((char*) NLMSG_DATA(n) +
			NLMSG_ALIGN(sizeof(struct xfrm_user_acquire)));
	size_t remaining = n->nlmsg_len -
			NLMSG_SPACE(sizeof(struct xfrm_user_acquire));

	while (remaining > 0) {
		dbg("xfrm acquire rtattribute type %u ...", attr->rta_type);
		switch (attr->rta_type) {
		case XFRMA_TMPL:
		{
			struct xfrm_user_tmpl *tmpl = (struct xfrm_user_tmpl *) RTA_DATA(attr);
			LDBGP_JAMBUF(DBG_BASE, logger, buf) {
				jam(buf, "xfrm_user_tmpl {");
				jam(buf, " id: xfrm_id id");
				jam(buf, " family: %ju", (uintmax_t) tmpl->family);
				jam(buf, " saddr: xfrm_address_t");
				jam(buf, " reqid: %ju", (uintmax_t) tmpl->reqid);
				jam(buf, " mode: %ju", (uintmax_t) tmpl->mode);
				jam(buf, " share: %ju", (uintmax_t) tmpl->share);;
				jam(buf, " optional: %ju", (uintmax_t) tmpl->optional);
				jam(buf, " aalgos: %ju", (uintmax_t) tmpl->aalgos);
				jam(buf, " ealgos: %ju", (uintmax_t) tmpl->ealgos);
				jam(buf, " calgos: %ju", (uintmax_t) tmpl->calgos);
				jam(buf, "}");
			}
			break;
		}
		case XFRMA_POLICY_TYPE:
		{
			/* discard */
			struct xfrm_userpolicy_type *type = (struct xfrm_userpolicy_type*) RTA_DATA(attr);
			LDBGP_JAMBUF(DBG_BASE, logger, buf) {
				jam(buf, "xfrm_userpolicy_type {");
				jam(buf, " type: %ju", (uintmax_t) type->type);
				jam(buf, "}");
			}
			break;
		}
		case XFRMA_SEC_CTX:
		{
			struct xfrm_user_sec_ctx *xuctx = (struct xfrm_user_sec_ctx *) RTA_DATA(attr);
			/* length of text of label */
			size_t len = xuctx->ctx_len;

			dbg("... xfrm xuctx: exttype=%d, len=%d, ctx_doi=%d, ctx_alg=%d, ctx_len=%zu",
			    xuctx->exttype, xuctx->len,
			    xuctx->ctx_doi, xuctx->ctx_alg,
			    len);

			if (xuctx->ctx_doi != XFRM_SC_DOI_LSM) {
				llog(RC_LOG, logger,
				     "Acquire message for unknown sec_label DOI %d; ignoring Acquire message",
				     xuctx->ctx_doi);
				return;
			}
			if (xuctx->ctx_alg != XFRM_SC_ALG_SELINUX) {
				llog(RC_LOG, logger,
				     "Acquire message for unknown sec_label LSM %d; ignoring Acquire message",
				     xuctx->ctx_alg);
				return;
			}

			/*
			 * note: xuctx + 1 is tricky:
			 * first byte after header
			 */
			sec_label.ptr = (uint8_t *)(xuctx + 1);
			sec_label.len = len;

			err_t ugh = vet_seclabel(sec_label);

			if (ugh != NULL) {
				llog(RC_LOG, logger,
					"received bad %s; ignoring Acquire message", ugh);
				return;
			}

			ldbg(logger, "%s() xuctx security context value: %.*s",
			     __func__, (int)len,
			     (const char *) (xuctx + 1));
			break;
		}
		default:
			ldbg(logger, "%s() ... ignoring unknown xfrm acquire payload type %u",
			     __func__, attr->rta_type);
			break;
		}
		/* updates remaining too */
		attr = RTA_NEXT(attr, remaining);
	}

	struct kernel_acquire b = {
		.packet = packet,
		.by_acquire = true,
		.logger = logger, /*on-stack*/
		.background = true, /* no whack so doesn't matter */
		.sec_label = sec_label,
		.state_id = acquire->seq,
		.policy_id = acquire->policy.index,
	};

	initiate_ondemand(&b);
}

static void netlink_shunt_expire(struct xfrm_userpolicy_info *pol,
				 struct logger *logger)
{
	const struct ip_info *afi = aftoinfo(pol->sel.family);
	if (afi == NULL) {
		llog(RC_LOG, logger,
		     "XFRM_MSG_POLEXPIRE message from kernel malformed: address family %u unknown",
		     pol->sel.family);
		return;
	}

	/* this is assuming that bare shunts are address only */
	ip_address src_addr = address_from_xfrm(afi, &pol->sel.saddr);
	ip_address dst_addr = address_from_xfrm(afi, &pol->sel.daddr);
	const struct ip_protocol *transport_proto = protocol_from_ipproto(pol->sel.proto);
	ip_selector src = selector_from_address_protocol(src_addr, transport_proto);
	ip_selector dst = selector_from_address_protocol(dst_addr, transport_proto);
	if (DBGP(DBG_BASE)) {
		/* XXX: use packet_from_xfrm()? */
		PEXPECT(logger, pol->sel.sport == 0);
		PEXPECT(logger, pol->sel.dport == 0);
	}

	struct bare_shunt **bs_pp = bare_shunt_ptr(&src, &dst, "expire bare shunt");
	if (bs_pp == NULL) {
		selector_pair_buf sb;
		llog(RC_LOG, logger,
		     "can't find expected bare shunt to delete: %s",
		     str_selector_pair_sensitive(&src, &dst, &sb));
	} else {
		free_bare_shunt(bs_pp);
		ldbg(logger, "netlink_shunt_expire() called delete_bare_shunt() with success");
	}
}

static void process_addr_change(struct nlmsghdr *n, struct logger *logger)
{
	struct ifaddrmsg *nl_msg = NLMSG_DATA(n);
	struct rtattr *rta = IFLA_RTA(nl_msg);
	size_t msg_size = IFA_PAYLOAD (n);
	ip_address ip;

	sparse_buf sb;
	ldbg(logger, "%s() xfrm netlink address change %s msg len %zu",
	     __func__, str_sparse(&rtm_type_names, n->nlmsg_type, &sb),
	     (size_t) n->nlmsg_len);

	while (RTA_OK(rta, msg_size)) {
		diag_t diag;

		switch (rta->rta_type) {
		case IFA_LOCAL:
			diag = data_to_address(RTA_DATA(rta), RTA_PAYLOAD(rta)/*size*/,
					       aftoinfo(nl_msg->ifa_family), &ip);
			if (diag != NULL) {
				llog(RC_LOG, logger, "ERROR IFA_LOCAL invalid, %s", str_diag(diag));
				pfree_diag(&diag);
				break;
			}

			if (n->nlmsg_type == RTM_DELADDR) {
				record_deladdr(&ip, "IFA_LOCAL");
			} else if (n->nlmsg_type == RTM_NEWADDR) {
				record_newaddr(&ip, "IFA_LOCAL");
			}
			break;

		case IFA_ADDRESS:
			diag = data_to_address(RTA_DATA(rta), RTA_PAYLOAD(rta)/*size*/,
					       aftoinfo(nl_msg->ifa_family), &ip);
			if (diag != NULL) {
				llog(RC_LOG, logger, "ERROR IFA_ADDRESS invalid, %s", str_diag(diag));
				pfree_diag(&diag);
				break;
			}

			address_buf ip_str;
			ldbg(logger, "%s() XFRM IFA_ADDRESS %s IFA_ADDRESS is this PPP?",
			     __func__, str_address(&ip, &ip_str));
			break;

		default:
		{
			sparse_buf sb;
			ldbg(logger, "%s() IKEv2 received address %s type %u",
			     __func__, str_sparse(&rtm_type_names, n->nlmsg_type, &sb),
			     rta->rta_type);
			break;
		}
		}

		rta = RTA_NEXT(rta, msg_size);
	}
}
static void xfrm_kernel_sa_expire(struct nlmsghdr *n, struct logger *logger)
{
	struct xfrm_user_expire *ue = NLMSG_DATA(n);

	if (n->nlmsg_len < NLMSG_LENGTH(sizeof(*ue))) {
		llog(RC_LOG, logger,
			"netlink_expire got message with length %zu < %zu bytes; ignore message",
			(size_t) n->nlmsg_len, sizeof(*ue));
		return;
	}

	const struct ip_info *afi = aftoinfo(ue->state.family);
	if (afi == NULL) {
		llog(RC_LOG, logger,
		     "kernel: XFRM_MSG_EXPIRE message malformed: family %u unknown",
		     ue->state.family);
		return;
	}

	ip_address src = address_from_xfrm(afi, &ue->state.saddr);
	ip_address dst = address_from_xfrm(afi, &ue->state.id.daddr);
	address_buf srcb;
	address_buf dstb;
	ipsec_spi_t spi = ue->state.id.spi;
	ldbg(logger, "%s() spi "PRI_IPSEC_SPI" src %s dst %s %s mode %u proto %d bytes %"PRIu64" packets %"PRIu64,
	     __func__,
	     pri_ipsec_spi(spi),
	     str_address(&src, &srcb),
	     str_address(&dst, &dstb),
	     (ue->hard ? "hard" : "soft"),
	     ue->state.mode,
	     ue->state.id.proto,
	     /* XXX: on linux __u64 is either long, or long long
	      * conflicting with either PRIu64 or %ll */
	     (uint64_t) ue->state.curlft.bytes,
	     (uint64_t) ue->state.curlft.packets);

	if (ue->hard) {
		if (impair.ignore_hard_expire) {
			llog(RC_LOG, logger, "IMPAIR is suppress a HARD EXPIRE event");
			return;
		}
	} else {
		if (impair.ignore_soft_expire) {
			llog(RC_LOG, logger, "IMPAIR is suppress a SOFT EXPIRE event");
			return;
		}
	}

	if (spi == 0) {
		ldbg(logger, "acquire state with SPI 0x0 expired, ignore it");
		return;  /* acquire state with SPI 0x0 expired, ignore it */
	}

	/* convert IP protocol to IKE ID */
	uint8_t protoid = PROTO_RESERVED;
	switch (ue->state.id.proto) {
	case  IPPROTO_ESP:
		protoid = PROTO_IPSEC_ESP;
		break;
	case  IPPROTO_AH:
		protoid = PROTO_IPSEC_AH;
		break;
	case  IPPROTO_COMP:
		protoid = PROTO_IPCOMP;
		break;
	default:
		bad_case(ue->state.id.proto);
	}

	handle_sa_expire(spi, protoid, dst,
			 ue->hard, ue->state.curlft.bytes,
			 ue->state.curlft.packets,
			 ue->state.curlft.add_time,
			 logger);
}

static void netlink_policy_expire(struct nlmsghdr *n, struct logger *logger)
{
	/*
	 * WARNING: netlink only guarantees 32-bit alignment.
	 * See NLMSG_ALIGNTO in the kernel's include/uapi/linux/netlink.h.
	 * BUT some fields in struct xfrm_user_acquire are 64-bit and so access
	 * may be improperly aligned.  This will fail on a few strict
	 * architectures (it does break C rules).
	 *
	 * WARNING: this code's understanding to the XFRM netlink
	 * messages is from programs/pluto/linux26/xfrm.h.
	 * There is no guarantee that this matches the kernel's
	 * understanding.
	 *
	 * Many things are defined to be int or unsigned int.
	 * This isn't safe when the kernel and userland may
	 * be compiled with different models.
	 */
	const struct xfrm_user_polexpire *upe = /* insufficiently aligned */
		nlmsg_data(n, sizeof(*upe), logger, HERE);
	if (upe == NULL) {
		return;
	}

	struct {
		struct nlmsghdr n;
		struct xfrm_userpolicy_id id;
	} req;
	struct nlm_resp rsp;

	const struct ip_info *afi = aftoinfo(upe->pol.sel.family);
	if (afi == NULL) {
		llog(RC_LOG, logger,
		     "XFRM_MSG_EXPIRE message from kernel malformed: family %u unknown",
		     upe->pol.sel.family);
		return;
	}

	if (DBGP(DBG_BASE)) {
		/* XXX: use packet_from_xfrm*()? */
		PEXPECT(logger, upe->pol.sel.sport == 0);
		PEXPECT(logger, upe->pol.sel.dport == 0);
	}

	ip_address src = address_from_xfrm(afi, &upe->pol.sel.saddr);
	ip_address dst = address_from_xfrm(afi, &upe->pol.sel.daddr);
	address_buf a;
	address_buf b;
	ldbg(logger, "%s() src %s/%u dst %s/%u dir %d index %d",
	     __func__,
	     str_address(&src, &a), upe->pol.sel.prefixlen_s,
	     str_address(&dst, &b), upe->pol.sel.prefixlen_d,
	     upe->pol.dir, upe->pol.index);

	req.id.dir = upe->pol.dir;
	req.id.index = upe->pol.index;
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = XFRM_MSG_GETPOLICY;
	req.n.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req.id)));

	int recv_errno;
	if (!sendrecv_xfrm_msg(&req.n, XFRM_MSG_NEWPOLICY, &rsp,
			       "Get policy", "?",
			       &recv_errno, logger)) {
		ldbg(logger, "%s() policy died on us: dir=%d, index=%d",
		     __func__, req.id.dir, req.id.index);
	} else if (rsp.n.nlmsg_len < NLMSG_LENGTH(sizeof(rsp.u.pol))) {
		llog(RC_LOG, logger,
			    "netlink_policy_expire: XFRM_MSG_GETPOLICY returned message with length %zu < %zu bytes; ignore message",
			    (size_t) rsp.n.nlmsg_len,
			    sizeof(rsp.u.pol));
	} else if (req.id.index != rsp.u.pol.index) {
		ldbg(logger, "%s() policy was replaced: dir=%d, oldindex=%d, newindex=%d",
		     __func__, req.id.dir, req.id.index, rsp.u.pol.index);
	} else if (upe->pol.curlft.add_time != rsp.u.pol.curlft.add_time) {
		ldbg(logger, "%s() policy was replaced and you have won the lottery: dir=%d, index=%d",
		     __func__, req.id.dir, req.id.index);
	} else {
		switch (upe->pol.dir) {
		case XFRM_POLICY_OUT:
			netlink_shunt_expire(&rsp.u.pol, logger);
			break;
		}
	}
}

/* returns FALSE iff EAGAIN */
static bool netlink_get(int fd,
			void (*processor)(struct nlm_resp *resp, struct logger *logger),
			struct logger *logger)
{
	struct nlm_resp rsp;
	struct sockaddr_nl addr;
	socklen_t alen = sizeof(addr);
	ssize_t r = recvfrom(fd, &rsp, sizeof(rsp), 0,
			     (struct sockaddr *)&addr, &alen);

	if (r < 0) {
		if (errno == EAGAIN)
			return false;
		if (errno != EINTR) {
			llog_error(logger, errno, "kernel: recvfrom() failed in netlink_get");
		}
		return true;
	}

	ldbg(logger, "%s() recvfrom() returned %zd bytes", __func__, r);
	if (DBGP(DBG_TMI)) {
		LDBG_dump(logger, &rsp, r);
	}

	size_t l = (size_t)r; /* must be non -ve */
	if (l < sizeof(rsp.n)) {
		llog(RC_LOG, logger,
		     "kernel: netlink_get read truncated message: %zu bytes; ignore message",
		     l);
		return true;
	}

	if (addr.nl_pid != 0) {
		/* not for us: ignore */
		sparse_buf sb;
		ldbg(logger, "%s() ignoring %s message from process %u",
		     __func__, str_sparse(&xfrm_type_names, rsp.n.nlmsg_type, &sb),
		     addr.nl_pid);
		return true;
	}

	if (l != rsp.n.nlmsg_len) {
		llog(RC_LOG, logger,
		     "kernel: netlink_get: read message with length %zu that doesn't equal nlmsg_len %zu bytes; ignore message",
		     l, (size_t) rsp.n.nlmsg_len);
		return true;
	}

	processor(&rsp, logger);
	return true;
}

static void netlink_xfrm_message_processor(struct nlm_resp *rsp, struct logger *logger)
{
	sparse_buf xfrmb;
	ldbg(logger, "%s() got %s message with length %zu",
	     __func__,
	     str_sparse(&xfrm_type_names, rsp->n.nlmsg_type, &xfrmb),
	     (size_t) rsp->n.nlmsg_len);

	switch (rsp->n.nlmsg_type) {

	case XFRM_MSG_ACQUIRE:
		netlink_acquire(&rsp->n, logger);
		break;

	case XFRM_MSG_EXPIRE: /* SA soft and hard limit */
		xfrm_kernel_sa_expire(&rsp->n, logger);
		break;

	case XFRM_MSG_POLEXPIRE:
		netlink_policy_expire(&rsp->n, logger);
		break;

	default:
		/* ignored */
		break;
	}
}

static void netlink_rtm_message_processor(struct nlm_resp *rsp, struct logger *logger)
{

	sparse_buf rtmb;
	ldbg(logger, "%s() got %s message with length %zu",
	     __func__,
	     str_sparse(&rtm_type_names, rsp->n.nlmsg_type, &rtmb),
	     (size_t) rsp->n.nlmsg_len);

	switch (rsp->n.nlmsg_type) {

	case RTM_NEWADDR:
		process_addr_change(&rsp->n, logger);
		break;

	case RTM_DELADDR:
		process_addr_change(&rsp->n, logger);
		break;

	default:
		/* ignored */
		break;
	}

}

static void netlink_process_xfrm_messages(int fd, void *arg UNUSED, struct logger *logger)
{
	ldbg(logger, "kernel: %s() process messages", __func__);
	do {} while (netlink_get(fd, netlink_xfrm_message_processor, logger));
}

static void netlink_process_rtm_messages(int fd, void *arg UNUSED, struct logger *logger)
{
	ldbg(logger, "kernel: %s() process messages", __func__);
	do {} while (netlink_get(fd, netlink_rtm_message_processor, logger));
}

static ipsec_spi_t xfrm_get_ipsec_spi(ipsec_spi_t avoid UNUSED,
				      const ip_address *src,
				      const ip_address *dst,
				      const struct ip_protocol *proto,
				      reqid_t reqid,
				      uintmax_t min, uintmax_t max,
				      const char *story,
				      struct logger *logger)
{
	struct {
		struct nlmsghdr n;
		struct xfrm_userspi_info spi;
	} req;
	struct nlm_resp rsp;

	zero(&req);
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = XFRM_MSG_ALLOCSPI;

	req.spi.info.saddr = xfrm_from_address(src);
	req.spi.info.id.daddr = xfrm_from_address(dst);
	req.spi.info.mode = 0;/*transport mode*/
	req.spi.info.reqid = reqid;
	req.spi.info.id.proto = proto->ipproto;
	req.spi.info.family = address_type(src)->af;

	req.n.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req.spi)));

	req.spi.min = min;
	req.spi.max = max;

	int recv_errno;
	if (!sendrecv_xfrm_msg(&req.n, XFRM_MSG_NEWSA, &rsp,
			       "Get SPI", story,
			       &recv_errno, logger)) {
		return 0;
	}

	if (rsp.n.nlmsg_len < NLMSG_LENGTH(sizeof(rsp.u.sa))) {
		llog(RC_LOG, logger,
		     "xfrm: netlink_get_spi: XFRM_MSG_ALLOCSPI returned message with length %zu < %zu bytes; ignore message",
		     (size_t) rsp.n.nlmsg_len,
		     sizeof(rsp.u.sa));
		return 0;
	}

	return rsp.u.sa.id.spi;
}

/*
 * netlink_get_sa - Get SA information from the kernel
 *
 * @param sa Kernel SA to be queried
 * @param bytes octets processed by IPsec SA
 * @param add_time timestamp when IPsec SA added
 * @return bool True if successful
 */
static bool xfrm_get_kernel_state(const struct kernel_state *sa, uint64_t *bytes,
				  uint64_t *add_time, uint64_t *lastused,
				  struct logger *logger)
{
	struct {
		struct nlmsghdr n;
		struct xfrm_usersa_id id;
	} req;

	struct nlm_resp rsp;

	zero(&req);
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = XFRM_MSG_GETSA;

	req.id.daddr = xfrm_from_address(&sa->dst.address);

	req.id.spi = sa->spi;
	req.id.family = address_info(sa->src.address)->af;
	req.id.proto = sa->proto->ipproto;

	req.n.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req.id)));

	int recv_errno;
	if (!sendrecv_xfrm_msg(&req.n, XFRM_MSG_NEWSA, &rsp,
			       "Get SA", sa->story,
			       &recv_errno, logger)) {
		return false;
	}

	*bytes = rsp.u.info.curlft.bytes;
	*add_time = rsp.u.info.curlft.add_time;

	/* Run through rtattributes looking for XFRMA_LASTUSED */
	struct rtattr *attr = (struct rtattr *) ((char *) NLMSG_DATA(&rsp.n) +
			NLMSG_ALIGN(sizeof(struct xfrm_usersa_info)));
	size_t remaining = rsp.n.nlmsg_len -
				NLMSG_SPACE(sizeof(struct xfrm_usersa_info));
	while (remaining > 0) {
		ldbg(logger, "%s() rtattribute type %u ...", __func__, attr->rta_type);
		switch (attr->rta_type) {
		case XFRMA_LASTUSED:
			memcpy(lastused, RTA_DATA(attr), sizeof(uint64_t));
			break;
		default:
			break;
		}
		attr = RTA_NEXT(attr, remaining); /* updates remaining too */
	}

	return true;
}

static struct xfrm_selector icmpv6_selector(int port)
{
	/* icmp is packed into [sd]port */
	uint16_t icmp_type = port >> 8;
	uint16_t icmp_code = port & 0xFF;
	return (struct xfrm_selector) {
		.proto = IPPROTO_ICMPV6,
		.family = AF_INET6,
		/* pack icmp into ports */
		.sport = htons(icmp_type),
		.dport = htons(icmp_code),
		.sport_mask = 0xffff,
	};
}

static bool fiddle_icmpv6_bypass(struct nlmsghdr *n, uint8_t *dir,
				 const char *story, struct logger *logger)
{

	/*
	 * EXPECT_NO_INBOUND means no fail on missing and/or
	 * success.
	 */
	*dir = XFRM_POLICY_IN;
	if (!sendrecv_xfrm_policy(n, EXPECT_KERNEL_POLICY_OK,
				  story, "(in)", logger, __func__))
		return false;

	*dir = XFRM_POLICY_FWD;
	if (!sendrecv_xfrm_policy(n, EXPECT_KERNEL_POLICY_OK,
				  story, "(fwd)", logger, __func__))
		return false;

	*dir = XFRM_POLICY_OUT;
	if (!sendrecv_xfrm_policy(n, EXPECT_KERNEL_POLICY_OK,
				  story, "(out)", logger, __func__))
		return false;

	return true;
}

/* add bypass policies/holes icmp */
static bool insert_icmpv6_bypass_policy(int port, const char *story, struct logger *logger)
{
	struct {
		struct nlmsghdr n;
		struct xfrm_userpolicy_info p;
	} req = {
		.n = {
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
			.nlmsg_type = XFRM_MSG_UPDPOLICY,
			.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req.p))),
		},
		.p = {
			.priority = 1, /* give admin prio 0 as override */
			.action = XFRM_POLICY_ALLOW,
			.share = XFRM_SHARE_ANY,

			.lft.soft_byte_limit = XFRM_INF,
			.lft.soft_packet_limit = XFRM_INF,
			.lft.hard_byte_limit = XFRM_INF,
			.lft.hard_packet_limit = XFRM_INF,

			.sel = icmpv6_selector(port),
		},
	};

	return fiddle_icmpv6_bypass(&req.n, &req.p.dir, story, logger);
}

static bool insert_icmpv6_bypass_policies(struct logger *logger)
{
	bool ok = true;
	/* do both even when they fail */
	ok &= insert_icmpv6_bypass_policy(ICMP_NEIGHBOR_DISCOVERY, "neighbour discovery", logger);
	ok &= insert_icmpv6_bypass_policy(ICMP_NEIGHBOR_SOLICITATION, "neighbour solicitiation", logger);
	return ok;
}

/* add bypass policies/holes icmp */
static bool delete_icmpv6_bypass_policy(int port, const char *story, struct logger *logger)
{
	struct {
		struct nlmsghdr n;
		struct xfrm_userpolicy_id p;
	} req = {
		.n = {
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
			.nlmsg_type = XFRM_MSG_DELPOLICY,
			.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req.p))),
		},
		.p = {
			.sel = icmpv6_selector(port),
		},
	};

	return fiddle_icmpv6_bypass(&req.n, &req.p.dir, story, logger);
}

static bool delete_icmpv6_bypass_policies(struct logger *logger)
{
	bool ok = true;
	/* do both even when they fail */
	ok &= delete_icmpv6_bypass_policy(ICMP_NEIGHBOR_DISCOVERY, "neighbour discovery", logger);
	ok &= delete_icmpv6_bypass_policy(ICMP_NEIGHBOR_SOLICITATION, "neighbour solicitiation", logger);
	return ok;
}

static void kernel_xfrm_poke_holes(struct logger *logger)
{
	/* this could be per interface specific too */
	const char proc_f[] = "/proc/sys/net/ipv6/conf/all/disable_ipv6";

	struct stat sts;
	if (stat(proc_f, &sts) != 0) {
		/* not error */
		llog_errno(RC_LOG, logger, errno,
			   "kernel: starting without ipv6 support! could not stat \"%s\": ",
			   proc_f);
		/*
		 * pretend success, do not exit pluto, likely IPv6 is
		 * disabled in kernel at compile time. e.g. OpenWRT.
		 */
		return;
	}

	/*
	 * If the IPv6 enabled file is present, insist on being able
	 * to read it.
	 */

	FILE *f = fopen(proc_f, "r");
	if (f == NULL) {
		fatal_errno(PLUTO_EXIT_KERNEL_FAIL, logger, errno,
			    "kernel: could not open \"%s\"", proc_f);
	}

	char buf[64];
	if (fgets(buf, sizeof(buf), f) ==  NULL) {
		(void) fclose(f);
		fatal_errno(PLUTO_EXIT_KERNEL_FAIL, logger, errno,
			    "kernel: could not read \"%s\"", proc_f);
	}
	(void) fclose(f);

	int disable_ipv6 = atoi(buf);
	if (disable_ipv6 == 1) {
		llog(RC_LOG, logger, "kernel: %s=1 ignore ipv6 holes", proc_f);
		return;
	}

	if (!insert_icmpv6_bypass_policies(logger)) {
		fatal(PLUTO_EXIT_KERNEL_FAIL, logger, "kernel: could not insert bypass policies");
	}

	hyperspace_bypass.icmpv6 = true;
}

static void kernel_xfrm_plug_holes(struct logger *logger)
{
	if (hyperspace_bypass.icmpv6) {
		delete_icmpv6_bypass_policies(logger);
	}
}

static bool qry_xfrm_mirgrate_support(struct logger *logger)
{
	/* check the kernel */
	struct {
		struct nlmsghdr n;
		struct xfrm_userpolicy_id id;
		char data[MAX_NETLINK_DATA_SIZE];
	} req;

	zero(&req);
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = XFRM_MSG_MIGRATE;
	req.n.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req.id)));

	/* add attrs[XFRM_MSG_MIGRATE] */
	struct rtattr *attr;
	struct xfrm_user_migrate migrate;

	zero(&migrate);
	attr =  (struct rtattr *)((char *)&req + req.n.nlmsg_len);
	attr->rta_type = XFRMA_MIGRATE;
	attr->rta_len = sizeof(migrate);

	memcpy(RTA_DATA(attr), &migrate, attr->rta_len);
	attr->rta_len = RTA_LENGTH(attr->rta_len);
	req.n.nlmsg_len += attr->rta_len;

	struct nlm_resp rsp;
	size_t len;
	ssize_t r;
	struct sockaddr_nl addr;
	int nl_fd = cloexec_socket(AF_NETLINK, SOCK_DGRAM|SOCK_NONBLOCK, NETLINK_XFRM);

	if (nl_fd < 0) {
		llog_error(logger, errno,
			   "socket() in qry_xfrm_mirgrate_support()");
		return false;
	}

	/* hdr->nlmsg_seq = ++seq; */
	len = req.n.nlmsg_len;
	do {
		r = write(nl_fd, &req.n, len);
	} while (r < 0 && errno == EINTR);

	if (r < 0) {
		llog_error(logger, errno,
			   "netlink write() xfrm_migrate_support lookup");
		close(nl_fd);
		return false;
	}

	if ((size_t)r != len) {
		llog_error(logger, 0/*no-errno*/,
			   "netlink write() xfrm_migrate_support message truncated: %zd instead of %zu",
			    r, len);
		close(nl_fd);
		return false;
	}

	for (;;) {
		socklen_t alen = sizeof(addr);

		r = recvfrom(nl_fd, &rsp, sizeof(rsp), 0,
				(struct sockaddr *)&addr, &alen);
		if (r < 0) {
			if (errno == EINTR) {
				continue;
			} else if (errno == EAGAIN) {
				/* old kernel F22 - dos not return proper error ??? */
				ldbg(logger, "ignore EAGAIN in %s assume MOBIKE migration is supported", __func__);
				break;
			}
		}
		break;
	}

	close(nl_fd);

	if (rsp.n.nlmsg_type == NLMSG_ERROR && rsp.u.e.error == -ENOPROTOOPT) {
		ldbg(logger, "MOBIKE will fail got ENOPROTOOPT");
		return false;
	}

	return true;
}

static err_t xfrm_migrate_ipsec_sa_is_enabled(struct logger *logger)
{
	static enum {
		UNKNOWN, ENABLED, DISABLED,
	} state = UNKNOWN;
	static const char disabled_message[] = "requires option CONFIG_XFRM_MIGRATE";
	switch (state) {
	case UNKNOWN:
		state = (qry_xfrm_mirgrate_support(logger) ? ENABLED : DISABLED);
		return state == ENABLED ? NULL : disabled_message;
	case ENABLED:
		return NULL;
	case DISABLED:
		return disabled_message;
	default:
		bad_case(state);
	}
}

static bool netlink_poke_ipsec_offload_policy_hole(struct nic_offload *nic_offload, struct logger *logger)
{
	if (nic_offload->type != KERNEL_OFFLOAD_PACKET)
		return false;

	struct {
		struct nlmsghdr n;
		struct {
			struct xfrm_userpolicy_info p;
			struct rtattr if_id_attr;
			uint32_t if_id;
			struct rtattr attr;
			struct xfrm_user_offload uo;
		} __attribute__((packed, aligned(4))) nlmsg;
	} req = {
		.n = {
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
			.nlmsg_type = XFRM_MSG_NEWPOLICY,
			.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req.nlmsg))),
		},
		.nlmsg = {
			.p = {
				.priority = 1, /* give admin prio 0 as override */
				.action = XFRM_POLICY_ALLOW,
				.share = XFRM_SHARE_ANY,
				.dir = XFRM_POLICY_OUT,

				.lft.soft_byte_limit = XFRM_INF,
				.lft.soft_packet_limit = XFRM_INF,
				.lft.hard_byte_limit = XFRM_INF,
				.lft.hard_packet_limit = XFRM_INF,

				.sel.proto = IPPROTO_UDP,
				.sel.family = AF_INET,
				.sel.sport = htons(IKE_UDP_PORT),
				.sel.dport = htons(IKE_UDP_PORT),
				.sel.sport_mask = 0xffff,
				.sel.dport_mask = 0xffff,
			},
			.if_id_attr = {
				.rta_type = XFRMA_IF_ID,
				.rta_len = RTA_LENGTH(sizeof(uint32_t)),
			},
			.if_id = if_nametoindex(nic_offload->dev),
			.attr = {
				.rta_type = XFRMA_OFFLOAD_DEV,
				.rta_len = RTA_LENGTH(sizeof(req.nlmsg.uo)),
			},
			.uo = {
				.flags = XFRM_OFFLOAD_PACKET,
				.ifindex = if_nametoindex(nic_offload->dev),
			},
		},
	};

	char *text = "add IPv4 ike port bypass for nic-offload";

	if (!sendrecv_xfrm_policy(&req.n, EXPECT_KERNEL_POLICY_OK,
				  text, "(out)", logger, __func__))
		return false;

	text = "add IPv6 ike port bypass for nic-offload";
	req.nlmsg.p.sel.family = AF_INET6;
	if (!sendrecv_xfrm_policy(&req.n, EXPECT_KERNEL_POLICY_OK,
				  text, "(out)", logger, __func__))
		return false;

	return true;
}

static bool netlink_poke_ipsec_policy_hole(int fd, const struct ip_info *afi, struct logger *logger)
{
	int af = afi->af;
	struct xfrm_userpolicy_info policy = {
		.action = XFRM_POLICY_ALLOW,
		.sel.family = af,
	};

	int opt, sol;
	switch (af) {
	case AF_INET:
		sol = SOL_IP;
		opt = IP_XFRM_POLICY;
		break;
	case AF_INET6:
		sol = IPPROTO_IPV6;
		opt = IPV6_XFRM_POLICY;
		break;
	default:
		bad_case(af);
	}

	policy.dir = XFRM_POLICY_IN;
	if (setsockopt(fd, sol, opt, &policy, sizeof(policy)) < 0) {
		llog_error(logger, errno,
			   "setsockopt IP_XFRM_POLICY XFRM_POLICY_IN in process_kernel_ifaces()");
		return false;
	}

	policy.dir = XFRM_POLICY_OUT;
	if (setsockopt(fd, sol, opt, &policy, sizeof(policy)) < 0) {
		llog_error(logger, errno,
			   "setsockopt IP_XFRM_POLICY XFRM_POLICY_OUT in process_kernel_ifaces()");
		return false;
	}

	return true;
}

static void kernel_xfrm_shutdown(struct logger *logger)
{
#ifdef USE_XFRM_INTERFACE
	free_xfrmi_ipsec1(logger);
#else
	ldbg(logger, "%s() USE_XFRM_INTERFACE disabled", __func__);
#endif
}

static const char *xfrm_protostack_names[] = { "xfrm", "netkey", NULL, };

const struct kernel_ops xfrm_kernel_ops = {
	.protostack_names = xfrm_protostack_names,
	.interface_name = "xfrm",
	.updown_name = "xfrm",
	/* don't overflow BYTES_FOR_BITS(replay_window) * 8 */
	.max_replay_window = UINT32_MAX & ~7,
	.esn_supported = true,

	.init = kernel_xfrm_init,
	.flush = kernel_xfrm_flush,
	.poke_holes = kernel_xfrm_poke_holes,
	.plug_holes = kernel_xfrm_plug_holes,
	.shutdown = kernel_xfrm_shutdown,

	.policy_del = kernel_xfrm_policy_del,
	.policy_add = kernel_xfrm_policy_add,
	.add_sa = netlink_add_sa,
	.get_kernel_state = xfrm_get_kernel_state,
	.get_ipsec_spi = xfrm_get_ipsec_spi,
	.del_ipsec_spi = xfrm_del_ipsec_spi,
	.migrate_ipsec_sa_is_enabled = xfrm_migrate_ipsec_sa_is_enabled,
	.migrate_ipsec_sa = xfrm_migrate_ipsec_sa,
	.overlap_supported = false,
	.sha2_truncbug_support = true,
	.poke_ipsec_policy_hole = netlink_poke_ipsec_policy_hole,
	.detect_nic_offload = xfrm_detect_nic_offload,
	.poke_ipsec_offload_policy_hole = netlink_poke_ipsec_offload_policy_hole,
};
