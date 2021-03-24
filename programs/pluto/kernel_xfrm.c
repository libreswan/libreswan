/*
 * netlink interface to the kernel's IPsec mechanism
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

#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include <sys/socket.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

#include <linux/udp.h>			/* for TCP_ENCAP_ESPINTCP and UDP_ENCAP_ESPINUDP */
#ifndef TCP_ENCAP_ESPINTCP
#define TCP_ENCAP_ESPINTCP 7
#endif

#include <unistd.h>
#include <sys/stat.h>

#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>

/* work around weird combo's of glibc and kernel header conflicts */
#ifndef GLIBC_KERN_FLIP_HEADERS
# include "linux/xfrm.h" /* local (if configured) or system copy */
# include "libreswan.h"
#else
# include "libreswan.h"
# include "linux/xfrm.h" /* local (if configured) or system copy */
#endif
#include "lsw-pfkeyv2.h"	/* for SADB_X_CALG_DEFLATE et.al., grrr */

#include "sysdep.h"
#include "socketwrapper.h"
#include "constants.h"
#include "defs.h"
#include "id.h"
#include "state.h"
#include "connections.h"
#include "kernel.h"
#include "server.h"
#include "nat_traversal.h"
#include "state.h"
#include "kernel_xfrm.h"
#include "netlink_attrib.h"
#include "log.h"
#include "whack.h"	/* for RC_LOG_SERIOUS */
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

#include "labeled_ipsec.h" /* TEMP for MAX_SECCTX_LEN */
#include "security_selinux.h"	/* for vet_seclabel() */

/* required for Linux 2.6.26 kernel and later */
#ifndef XFRM_STATE_AF_UNSPEC
#define XFRM_STATE_AF_UNSPEC 32
#endif

static int nl_send_fd = NULL_FD; /* to send to NETLINK_XFRM */
static int nl_xfrm_fd = NULL_FD; /* listen to NETLINK_XFRM broadcast */
static int nl_route_fd = NULL_FD; /* listen to NETLINK_ROUTE broadcast */

static int kernel_mobike_supprt ; /* kernel xfrm_migrate_support */

#define NE(x) { x, #x }	/* Name Entry -- shorthand for sparse_names */

enum {
	IPSEC_POLICY_DISCARD    = 0,
	IPSEC_POLICY_NONE       = 1,
	IPSEC_POLICY_IPSEC      = 2,
	IPSEC_POLICY_ENTRUST    = 3,
	IPSEC_POLICY_BYPASS     = 4
};

static sparse_names xfrm_type_names = {
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

	NE(XFRM_MSG_MAX),

	{ 0, sparse_end }
};

static sparse_names rtm_type_names = {
	NE(RTM_BASE),
	NE(RTM_NEWADDR),
	NE(RTM_DELADDR),
	NE(RTM_MAX),
	{ 0, sparse_end }
};
#undef NE

#define RTA_TAIL(rta) ((struct rtattr *) (((void *) (rta)) + \
                                    RTA_ALIGN((rta)->rta_len)))

#define NLMSG_TAIL(nmsg) \
        ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

/* Compress Algs */
static sparse_names calg_list = {
	{ SADB_X_CALG_DEFLATE, "deflate" },
	{ SADB_X_CALG_LZS, "lzs" },
	{ SADB_X_CALG_LZJH, "lzjh" },
	{ 0, sparse_end }
};

/*
 * xfrm2ip - Take an xfrm and convert to an IP address
 *
 * @param xaddr xfrm_address_t
 * @param addr ip_address IPv[46] Address from addr is copied here.
 */
static void xfrm2ip(const xfrm_address_t *xaddr, ip_address *addr, const sa_family_t family)
{
	shunk_t x = THING_AS_SHUNK(*xaddr);

	const struct ip_info *afi = aftoinfo(family);
	passert(afi != NULL);

	*addr = afi->address.any; /* initialize dst type and zero */
	chunk_t a = address_as_chunk(addr);

	/* a = x */
	passert(x.len >= a.len);
	memcpy(a.ptr, x.ptr, a.len);
}

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
		ip_selector client_ = *(CLIENT);			\
		ip_address address = selector_prefix(client_);		\
		(REQ).L##addr = xfrm_from_address(&address);		\
		(REQ).prefixlen_##L = selector_prefix_bits(client_);	\
		(REQ).L##port = nport(selector_port(client_));		\
	}

static void init_netlink_route_fd(struct logger *logger)
{
	nl_route_fd = safe_socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (nl_route_fd < 0) {
		fatal_errno(PLUTO_EXIT_FAIL, logger, errno, "socket()");
	}

	if (fcntl(nl_route_fd, F_SETFD, FD_CLOEXEC) != 0) {
		fatal_errno(PLUTO_EXIT_FAIL, logger, errno,
			    "fcntl(FD_CLOEXEC) for bcast NETLINK_ROUTE ");
	}

	if (fcntl(nl_route_fd, F_SETFL, O_NONBLOCK) != 0) {
		fatal_errno(PLUTO_EXIT_FAIL, logger, errno,
			    "fcntl(O_NONBLOCK) for bcast NETLINK_ROUTE");
	}

	struct sockaddr_nl addr = {
		.nl_family = AF_NETLINK,
		.nl_pid = getpid(),
		.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR |
				 RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE | RTMGRP_LINK,
	};

	if (bind(nl_route_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		fatal_errno(PLUTO_EXIT_FAIL, logger, errno,
			    "failed to bind NETLINK_ROUTE bcast socket - Perhaps kernel was not compiled with CONFIG_XFRM");
	}
}


/*
 * init_netlink - Initialize the netlink interface.  Opens the sockets and
 * then binds to the broadcast socket.
 */
static void init_netlink(struct logger *logger)
{
#define XFRM_ACQ_EXPIRES "/proc/sys/net/core/xfrm_acq_expires"
	struct stat buf;
	if (stat(XFRM_ACQ_EXPIRES, &buf) != 0) {
		fatal_errno(PLUTO_EXIT_KERNEL_FAIL, logger, errno,
			    "no XFRM kernel support detected, missing "XFRM_ACQ_EXPIRES);
	}

	struct sockaddr_nl addr;

	nl_send_fd = safe_socket(AF_NETLINK, SOCK_DGRAM, NETLINK_XFRM);

	if (nl_send_fd < 0) {
		fatal_errno(PLUTO_EXIT_FAIL, logger, errno,
			    "socket() in init_netlink()");
	}

	if (fcntl(nl_send_fd, F_SETFD, FD_CLOEXEC) != 0) {
		fatal_errno(PLUTO_EXIT_FAIL, logger, errno,
			    "fcntl(FD_CLOEXEC) in init_netlink()");
	}

	nl_xfrm_fd = safe_socket(AF_NETLINK, SOCK_DGRAM, NETLINK_XFRM);
	if (nl_xfrm_fd < 0) {
		fatal_errno(PLUTO_EXIT_FAIL, logger, errno,
			    "socket() for bcast in init_netlink()");
	}

	if (fcntl(nl_xfrm_fd, F_SETFD, FD_CLOEXEC) != 0) {
		fatal_errno(PLUTO_EXIT_FAIL, logger, errno,
			    "fcntl(FD_CLOEXEC) for bcast in init_netlink()");
	}

	if (fcntl(nl_xfrm_fd, F_SETFL, O_NONBLOCK) != 0) {
		fatal_errno(PLUTO_EXIT_FAIL, logger, errno,
			    "fcntl(O_NONBLOCK) for bcast in init_netlink()");
	}

	addr.nl_family = AF_NETLINK;
	addr.nl_pid = getpid();
	addr.nl_pad = 0; /* make coverity happy */
	addr.nl_groups = XFRMGRP_ACQUIRE | XFRMGRP_EXPIRE;
	if (bind(nl_xfrm_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		fatal_errno(PLUTO_EXIT_FAIL, logger, errno,
			    "Failed to bind bcast socket in init_netlink() - Perhaps kernel was not compiled with CONFIG_XFRM");
	}

	init_netlink_route_fd(logger);

	/*
	 * pfkey_register_response() does not register an entry for
	 * msg->sadb_msg_satype=10 to indicate IPCOMP, so we override
	 * detection here. Seems the PF_KEY API in Linux with netkey
	 * is a joke that should be abandoned for a "linux children"
	 * native netlink query/response
	 *
	 * XXX: Given KLIPS defines K_SADB_X_SATYPE_COMP=9, and
	 * IPIP=10 which conflicts with the aboe, that might be the
	 * source of the problem?
	 */
	can_do_IPcomp = TRUE;

	/*
	 * Just assume any algorithm with a NETLINK_XFRM name works.
	 *
	 * Kind of lame since pluto should query the kernel for what
	 * it supports.  OTOH, the query might happen before the
	 * crypto module gets loaded.
	 */
	dbg("Hard-wiring algorithms");
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

/*
 * send_netlink_msg
 *
 * @param hdr - Data to be sent.
 * @param expected_resp_type - type of message expected from netlink
 * @param rbuf - Return Buffer - contains data returned from the send.
 * @param description - String - user friendly description of what is
 *                      being attempted.  Used for diagnostics
 * @param text_said - String
 * @return bool True if the message was successfully sent.
 */
static int netlink_errno;	/* side-channel result of send_netlink_msg */

static bool send_netlink_msg(struct nlmsghdr *hdr,
			     unsigned expected_resp_type, struct nlm_resp *rbuf,
			     const char *description, const char *text_said,
			     struct logger *logger)
{
	struct nlm_resp rsp;
	size_t len;
	ssize_t r;
	struct sockaddr_nl addr;
	static uint32_t seq = 0;	/* STATIC */

	netlink_errno = 0;

	hdr->nlmsg_seq = ++seq;
	len = hdr->nlmsg_len;
	do {
		r = write(nl_send_fd, hdr, len);
	} while (r < 0 && errno == EINTR);
	if (r < 0) {
		log_errno(logger, errno,
			  "netlink write() of %s message for %s %s failed",
			  sparse_val_show(xfrm_type_names,
					  hdr->nlmsg_type),
			  description, text_said);
		return FALSE;
	} else if ((size_t)r != len) {
		llog(RC_LOG_SERIOUS, logger,
			    "ERROR: netlink write() of %s message for %s %s truncated: %zd instead of %zu",
			    sparse_val_show(xfrm_type_names, hdr->nlmsg_type),
			    description, text_said, r, len);
		return FALSE;
	}

	for (;;) {
		socklen_t alen = sizeof(addr);

		r = recvfrom(nl_send_fd, &rsp, sizeof(rsp), 0,
			(struct sockaddr *)&addr, &alen);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			netlink_errno = errno;
			log_errno(logger, errno,
				  "netlink recvfrom() of response to our %s message for %s %s failed",
				  sparse_val_show(xfrm_type_names,
							hdr->nlmsg_type),
				  description, text_said);
			return FALSE;
		} else if ((size_t) r < sizeof(rsp.n)) {
			llog(RC_LOG, logger,
				    "netlink read truncated message: %zd bytes; ignore message", r);
			continue;
		} else if (addr.nl_pid != 0) {
			/* not for us: ignore */
			dbg("netlink: ignoring %s message from process %u",
			    sparse_val_show(xfrm_type_names, rsp.n.nlmsg_type),
			    addr.nl_pid);
			continue;
		} else if (rsp.n.nlmsg_seq != seq) {
			dbg("netlink: ignoring out of sequence (%u/%u) message %s",
			    rsp.n.nlmsg_seq, seq,
			    sparse_val_show(xfrm_type_names, rsp.n.nlmsg_type));
			continue;
		}
		break;
	}

	if (rsp.n.nlmsg_len > (size_t) r) {
		llog(RC_LOG_SERIOUS, logger,
			    "netlink recvfrom() of response to our %s message for %s %s was truncated: %zd instead of %zu",
			    sparse_val_show(xfrm_type_names, hdr->nlmsg_type),
			    description, text_said,
			    len, (size_t) rsp.n.nlmsg_len);
		return FALSE;
	}

	if (rsp.n.nlmsg_type != expected_resp_type && rsp.n.nlmsg_type == NLMSG_ERROR) {
		if (rsp.u.e.error != 0) {
			llog(RC_LOG_SERIOUS, logger,
				    "ERROR: netlink response for %s %s included errno %d: %s",
				    description, text_said, -rsp.u.e.error,
				    strerror(-rsp.u.e.error));
			return FALSE;
		}
		/*
		 * What the heck does a 0 error mean?
		 * Since the caller doesn't depend on the result
		 * we'll let it pass.
		 * This really happens for netlink_add_sa().
		 */
		dbg("netlink response for %s %s included non-error error",
		    description, text_said);
		/* ignore */
	}
	if (rbuf == NULL) {
		return TRUE;
	}
	if (rsp.n.nlmsg_type != expected_resp_type) {
		llog(RC_LOG_SERIOUS, logger,
			    "netlink recvfrom() of response to our %s message for %s %s was of wrong type (%s)",
			    sparse_val_show(xfrm_type_names, hdr->nlmsg_type),
			    description, text_said,
			    sparse_val_show(xfrm_type_names, rsp.n.nlmsg_type));
		return FALSE;
	}
	memcpy(rbuf, &rsp, r);
	return TRUE;
}

/*
 * netlink_policy -
 *
 * @param hdr - Data to check
 * @param enoent_ok - Boolean - OK or not OK.
 * @param text_said - String
 * @return boolean
 */
static bool netlink_policy(struct nlmsghdr *hdr, bool enoent_ok,
			   const char *text_said, struct logger *logger)
{
	struct nlm_resp rsp;

	if (!send_netlink_msg(hdr, NLMSG_ERROR, &rsp,
			      "policy", text_said, logger))
		return FALSE;

	/* kind of surprising: we get here by success which implies an error structure! */

	int error = -rsp.u.e.error;

	if (error == 0 || (error == ENOENT && enoent_ok))
		return TRUE;

	llog(RC_LOG_SERIOUS, logger,
		    "ERROR: netlink %s response for flow %s included errno %d: %s",
		    sparse_val_show(xfrm_type_names, hdr->nlmsg_type),
		    text_said, error, strerror(error));
	return FALSE;
}

/*
 * netlink_raw_eroute
 *
 * @param this_host ip_address
 * @param this_client ip_subnet
 * @param that_host ip_address
 * @param that_client ip_subnet
 * @param spi
 * @param sa_proto int (4=tunnel, 50=esp, 108=ipcomp, etc ...)
 * @param transport_proto unsigned int Contains protocol
 *	(6=tcp, 17=udp, etc...)
 * @param esatype int
 * @param pfkey_proto_info proto_info
 * @param use_lifetime monotime_t (Currently unused)
 * @param pluto_sadb_opterations sadb_op (operation - ie: ERO_DELETE)
 * @param text_said char
 * @return boolean True if successful
 */
static bool netlink_raw_eroute(const ip_address *this_host,
			       const ip_selector *this_client,
			       const ip_address *that_host,
			       const ip_selector *that_client,
			       ipsec_spi_t cur_spi,	/* current SPI */
			       ipsec_spi_t new_spi,	/* new SPI */
			       const struct ip_protocol *sa_proto,
			       unsigned int transport_proto,
			       enum eroute_type esatype,
			       const struct pfkey_proto_info *proto_info,
			       deltatime_t use_lifetime UNUSED,
			       uint32_t sa_priority,
			       const struct sa_marks *sa_marks,
			       const uint32_t xfrm_if_id,
			       enum pluto_sadb_operations sadb_op,
			       const char *text_said,
			       const chunk_t *sec_label,
			       struct logger *logger)
{
	struct {
		struct nlmsghdr n;
		union {
			struct xfrm_userpolicy_info p;
			struct xfrm_userpolicy_id id;
		} u;
		char data[MAX_NETLINK_DATA_SIZE];
	} req;

	int policy = IPSEC_POLICY_IPSEC;

	if (sadb_op == ERO_DELETE && proto_info[0].reqid == 0 &&
		(ntohl(new_spi) == SPI_PASS || ntohl(new_spi) == SPI_HOLD) &&
		strstr("IGNORE_ON_XFRM", text_said) != NULL) {
			dbg("request to delete an opportunistic bare shunt ignored - XFRM already deleted it when it installed IPsec SA, text_said:%s", text_said);
			return TRUE;
	}

	switch (esatype) {
	case ET_UNSPEC:
	case ET_AH:
	case ET_ESP:
	case ET_IPCOMP:
	case ET_IPIP:

		break;

	case ET_INT:
		/* shunt route */
		switch (ntohl(new_spi)) {
		case SPI_PASS:
			dbg("netlink_raw_eroute: SPI_PASS");
			policy = IPSEC_POLICY_NONE;
			break;
		case SPI_HOLD:
			/*
			 * We don't know how to implement %hold, but it is okay.
			 * When we need a hold, the kernel XFRM acquire state
			 * will do the job (by dropping or holding the packet)
			 * until this entry expires. See /proc/sys/net/core/xfrm_acq_expires
			 * After expiration, the underlying policy causing the original acquire
			 * will fire again, dropping further packets.
			 */
			dbg("netlink_raw_eroute: SPI_HOLD implemented as no-op");
			return TRUE; /* yes really */
		case SPI_DROP:
		case SPI_REJECT:
		case 0: /* used with type=passthrough - can it not use SPI_PASS ?? */
			policy = IPSEC_POLICY_DISCARD;
			break;
		case SPI_TRAP:
			if (sadb_op == ERO_ADD_INBOUND ||
				sadb_op == ERO_DEL_INBOUND)
				return TRUE;

			break;
		case SPI_TRAPSUBNET: /* unused in our code */
		default:
			bad_case(ntohl(new_spi));
		}
		break;

	default:
		bad_case(esatype);
	}

	const int dir = (sadb_op == ERO_ADD_INBOUND || sadb_op == ERO_DEL_INBOUND) ?
		XFRM_POLICY_IN : XFRM_POLICY_OUT;

	/*
	 * Bug #1004 fix.
	 * There really isn't "client" with XFRM and transport mode
	 * so eroute must be done to natted, visible ip. If we don't hide
	 * internal IP, communication doesn't work.
	 */
	ip_selector local_client;

	if (esatype == ET_ESP || esatype == ET_IPCOMP || sa_proto == &ip_protocol_esp) {
		/*
		 * Variable "that" should be remote, but here it's not.
		 * We must check "dir" to find out remote address.
		 */
		int local_port;

		if (dir == XFRM_POLICY_OUT) {
			local_port = selector_hport(*that_client);
			local_client = selector_from_address(*that_host);
			that_client = &local_client;
		} else {
			local_port = selector_hport(*this_client);
			local_client = selector_from_address(*this_host);
			this_client = &local_client;
		}
		update_selector_hport(&local_client, local_port);
		dbg("%s: using host address instead of client subnet", __func__);
	}

	zero(&req);
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	const int family = selector_type(that_client)->af;

	/* .[sd]addr, .prefixlen_[sd], .[sd]port */
	SELECTOR_TO_XFRM(this_client, req.u.p.sel, s);
	SELECTOR_TO_XFRM(that_client, req.u.p.sel, d);

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
	if (transport_proto == IPPROTO_ICMP ||
		transport_proto == IPPROTO_ICMPV6) {
		uint16_t icmp_type;
		uint16_t icmp_code;

		icmp_type = ntohs(req.u.p.sel.sport) >> 8;
		icmp_code = ntohs(req.u.p.sel.sport) & 0xFF;

		req.u.p.sel.sport = htons(icmp_type);
		req.u.p.sel.dport = htons(icmp_code);
	}

	req.u.p.sel.sport_mask = req.u.p.sel.sport == 0 ? 0 : ~0;
	req.u.p.sel.dport_mask = req.u.p.sel.dport == 0 ? 0 : ~0;
	req.u.p.sel.proto = transport_proto;
	req.u.p.sel.family = family;

	if (sadb_op == ERO_DELETE || sadb_op == ERO_DEL_INBOUND) {
		req.u.id.dir = dir;
		req.n.nlmsg_type = XFRM_MSG_DELPOLICY;
		req.n.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req.u.id)));
	} else {
		req.u.p.dir = dir;

		/* The caller should have set the proper priority by now */
		req.u.p.priority = sa_priority;
		dbg("IPsec SA SPD priority set to %d", req.u.p.priority);

		req.u.p.action = XFRM_POLICY_ALLOW;
		if (policy == IPSEC_POLICY_DISCARD)
			req.u.p.action = XFRM_POLICY_BLOCK;
		/* req.u.p.lft.soft_use_expires_seconds = deltasecs(use_lifetime); */
		req.u.p.lft.soft_byte_limit = XFRM_INF;
		req.u.p.lft.soft_packet_limit = XFRM_INF;
		req.u.p.lft.hard_byte_limit = XFRM_INF;
		req.u.p.lft.hard_packet_limit = XFRM_INF;

		/*
		 * NEW will fail when an existing policy, UPD always works.
		 * This seems to happen in cases with NAT'ed XP clients, or
		 * quick recycling/resurfacing of roadwarriors on the same IP.
		 *
		 * UPD is also needed for two separate tunnels with same end
		 * subnets
		 * Like A = B = C config where both A - B and B - C have
		 * tunnel A = C configured.
		 */
		req.n.nlmsg_type = XFRM_MSG_UPDPOLICY;
		if (sadb_op == ERO_REPLACE)
			req.n.nlmsg_type = XFRM_MSG_UPDPOLICY;
		req.n.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req.u.p)));
	}

	if (policy == IPSEC_POLICY_IPSEC || policy == IPSEC_POLICY_DISCARD) {
		if (sadb_op != ERO_DELETE) {
			struct rtattr *attr;

			struct xfrm_user_tmpl tmpl[4];
			int i;

			zero(&tmpl);
			for (i = 0; proto_info[i].proto; i++) {
				tmpl[i].reqid = proto_info[i].reqid;
				tmpl[i].id.proto = proto_info[i].proto;
				tmpl[i].optional = proto_info[i].proto == IPPROTO_COMP && dir != XFRM_POLICY_OUT;
				tmpl[i].aalgos = tmpl[i].ealgos = tmpl[i].calgos = ~0;
				tmpl[i].family = addrtypeof(that_host);
				tmpl[i].mode = proto_info[i].mode == ENCAPSULATION_MODE_TUNNEL;

				if (!tmpl[i].mode)
					continue;

				tmpl[i].saddr = xfrm_from_address(this_host);
				tmpl[i].id.daddr = xfrm_from_address(that_host);
			}

			attr = (struct rtattr *)((char *)&req + req.n.nlmsg_len);
			attr->rta_type = XFRMA_TMPL;
			attr->rta_len = i * sizeof(tmpl[0]);
			memcpy(RTA_DATA(attr), tmpl, attr->rta_len);
			attr->rta_len = RTA_LENGTH(attr->rta_len);
			req.n.nlmsg_len += attr->rta_len;
		}

		/* mark policy extension */
		{
			struct sa_mark sa_mark = (dir == XFRM_POLICY_IN) ? sa_marks->in : sa_marks->out;

			if (sa_mark.val != 0 && sa_mark.mask != 0 && xfrm_if_id == 0) {
				struct xfrm_mark xfrm_mark;
				struct rtattr* mark_attr;

				xfrm_mark.v = sa_mark.val;
				xfrm_mark.m = sa_mark.mask;
				mark_attr = (struct rtattr *)((char *)&req + req.n.nlmsg_len);
				mark_attr->rta_type = XFRMA_MARK;
				mark_attr->rta_len = sizeof(xfrm_mark);
				memcpy(RTA_DATA(mark_attr), &xfrm_mark, mark_attr->rta_len);
				mark_attr->rta_len = RTA_LENGTH(mark_attr->rta_len);
				req.n.nlmsg_len += mark_attr->rta_len;
			}
		}
#ifdef USE_XFRM_INTERFACE
		if (xfrm_if_id != 0) {
			dbg("%s netlink: XFRMA_IF_ID %" PRIu32 " req.n.nlmsg_type=%" PRIu32,
			    __func__, xfrm_if_id, req.n.nlmsg_type);
			nl_addattr32(&req.n, sizeof(req.data), XFRMA_IF_ID, xfrm_if_id);
			if (sa_marks->out.val == 0 && sa_marks->out.mask == 0) {
				/* XFRMA_SET_MARK = XFRMA_IF_ID */
				nl_addattr32(&req.n, sizeof(req.data), XFRMA_SET_MARK, xfrm_if_id);
			} else {
				/* manually configured mark-out=mark/mask */
				nl_addattr32(&req.n, sizeof(req.data),
					     XFRMA_SET_MARK, sa_marks->out.val);
				nl_addattr32(&req.n, sizeof(req.data),
					     XFRMA_SET_MARK_MASK, sa_marks->out.mask);
			}
		}
#endif
	}

	if (sec_label != NULL && sec_label->len > 0) {
		struct rtattr *attr = (struct rtattr *)
			((char *)&req + req.n.nlmsg_len);
		struct xfrm_user_sec_ctx *uctx;

		passert(sec_label->len <= MAX_SECCTX_LEN);
		attr->rta_type = XFRMA_SEC_CTX;

		dbg("passing security label \"%.*s\" to kernel", (int)sec_label->len, sec_label->ptr);
		attr->rta_len = RTA_LENGTH(sizeof(struct xfrm_user_sec_ctx) + sec_label->len);
		uctx = RTA_DATA(attr);
		uctx->exttype = XFRMA_SEC_CTX;
		uctx->len = sizeof(struct xfrm_user_sec_ctx) + sec_label->len;
		uctx->ctx_doi = XFRM_SC_DOI_LSM;
		uctx->ctx_alg = XFRM_SC_ALG_SELINUX;
		uctx->ctx_len = sec_label->len;
		memcpy(uctx + 1, sec_label->ptr, sec_label->len);
		req.n.nlmsg_len += attr->rta_len;
	}

	bool enoent_ok = sadb_op == ERO_DEL_INBOUND ||
		(sadb_op == ERO_DELETE && ntohl(cur_spi) == SPI_HOLD);

	bool ok = netlink_policy(&req.n, enoent_ok, text_said, logger);

	/* ??? deal with any forwarding policy */
	switch (dir) {
	case XFRM_POLICY_IN:
		if (req.n.nlmsg_type == XFRM_MSG_DELPOLICY) {
			/* ??? we will call netlink_policy even if !ok. */
			req.u.id.dir = XFRM_POLICY_FWD;
		} else if (!ok) {
			break;
		} else if (proto_info[0].mode != ENCAPSULATION_MODE_TUNNEL &&
			   esatype != ET_INT) {
			break;
		} else {
			req.u.p.dir = XFRM_POLICY_FWD;
		}
		ok &= netlink_policy(&req.n, enoent_ok, text_said, logger);
		break;
	}
	return ok;
}

static void  set_migration_attr(const struct kernel_sa *sa,
		struct xfrm_user_migrate *m)
{
	m->old_saddr = xfrm_from_address(sa->src.address);
	m->old_daddr = xfrm_from_address(sa->dst.address);
	m->new_saddr = xfrm_from_address(&sa->src.new_address);
	m->new_daddr = xfrm_from_address(&sa->dst.new_address);

	if (sa->mode == ENCAPSULATION_MODE_TUNNEL)
		m->mode = XFRM_MODE_TUNNEL;
	else
		m->mode = XFRM_MODE_TRANSPORT;
	m->proto = sa->proto->ipproto;
	m->reqid = sa->reqid;
	m->old_family = m->new_family = address_type(sa->src.address)->af;
}

static bool create_xfrm_migrate_sa(struct state *st, const int dir,
		struct kernel_sa *ret_sa, char *text_said)
{
	const struct connection *const c = st->st_connection;

	const struct ip_encap *encap_type =
		(st->st_interface->protocol == &ip_protocol_tcp) ? &ip_encap_esp_in_tcp :
		(st->hidden_variables.st_nat_traversal & NAT_T_DETECTED) ? &ip_encap_esp_in_udp :
		NULL;
	dbg("TCP/NAT: encap type "PRI_IP_ENCAP, pri_ip_encap(encap_type));

	const struct ip_protocol *proto;
	struct ipsec_proto_info *proto_info;

	if (st->st_esp.present) {
		proto = &ip_protocol_esp;
		proto_info = &st->st_esp;
	} else if (st->st_ah.present) {
		proto = &ip_protocol_ah;
		proto_info = &st->st_ah;
	} else {
		return FALSE;
	}

	struct kernel_sa sa = {
		.xfrm_dir = dir,
		.proto = proto,
		.reqid = reqid_esp(c->spd.reqid),
		.encap_type = encap_type,
		/* WWW what about sec_label? */
	};

	if (st->st_ah.attrs.mode == ENCAPSULATION_MODE_TUNNEL ||
		st->st_esp.attrs.mode == ENCAPSULATION_MODE_TUNNEL)
		sa.mode = ENCAPSULATION_MODE_TUNNEL;
	else
		sa.mode = ENCAPSULATION_MODE_TRANSPORT;

	ip_endpoint new_endpoint;
	uint16_t old_port;
	uint16_t encap_sport = 0;
	uint16_t encap_dport = 0;
	const ip_address *src, *dst;
	const ip_selector *src_client, *dst_client;

	if (endpoint_is_specified(st->st_mobike_local_endpoint)) {
		char *n = jam_str(text_said, SAMIGTOT_BUF, "initiator migrate kernel SA ");
		passert((SAMIGTOT_BUF - strlen(text_said)) > SATOT_BUF);
		old_port = endpoint_hport(st->st_interface->local_endpoint);
		new_endpoint = st->st_mobike_local_endpoint;

		if (dir == XFRM_POLICY_IN || dir == XFRM_POLICY_FWD) {
			src = &c->spd.that.host_addr;
			dst = &c->spd.this.host_addr;
			src_client = &c->spd.that.client;
			dst_client = &c->spd.this.client;
			sa.src.new_address = *src;
			sa.dst.new_address = endpoint_address(st->st_mobike_local_endpoint);
			sa.spi = proto_info->our_spi;
			set_text_said(n, dst, sa.spi, proto);
			if (encap_type != NULL) {
				encap_sport = endpoint_hport(st->st_remote_endpoint);
				encap_dport = endpoint_hport(st->st_mobike_local_endpoint);
			}
		} else {
			src = &c->spd.this.host_addr;
			dst = &c->spd.that.host_addr;
			src_client = &c->spd.this.client;
			dst_client = &c->spd.that.client;
			sa.src.new_address = endpoint_address(st->st_mobike_local_endpoint);
			sa.dst.new_address = *dst;
			sa.spi = proto_info->attrs.spi;
			set_text_said(n, src, sa.spi, proto);
			if (encap_type != NULL) {
				encap_sport = endpoint_hport(st->st_mobike_local_endpoint);
				encap_dport = endpoint_hport(st->st_remote_endpoint);
			}
		}
	} else {
		char *n = jam_str(text_said, SAMIGTOT_BUF, "responder migrate kernel SA ");
		passert((SAMIGTOT_BUF - strlen(text_said)) > SATOT_BUF);
		old_port = endpoint_hport(st->st_remote_endpoint);
		new_endpoint = st->st_mobike_remote_endpoint;

		if (dir == XFRM_POLICY_IN || dir == XFRM_POLICY_FWD) {
			src = &c->spd.that.host_addr;
			dst = &c->spd.this.host_addr;
			src_client = &c->spd.that.client;
			dst_client = &c->spd.this.client;
			sa.src.new_address = endpoint_address(st->st_mobike_remote_endpoint);
			sa.dst.new_address = c->spd.this.host_addr;
			sa.spi = proto_info->our_spi;
			set_text_said(n, src, sa.spi, proto);
			if (encap_type != NULL) {
				encap_sport = endpoint_hport(st->st_mobike_remote_endpoint);
				encap_dport = endpoint_hport(st->st_interface->local_endpoint);
			}
		} else {
			src = &c->spd.this.host_addr;
			dst = &c->spd.that.host_addr;
			src_client = &c->spd.this.client;
			dst_client = &c->spd.that.client;
			sa.src.new_address = c->spd.this.host_addr;
			sa.dst.new_address = endpoint_address(st->st_mobike_remote_endpoint);
			sa.spi = proto_info->attrs.spi;
			set_text_said(n, dst, sa.spi, proto);

			if (encap_type != NULL) {
				encap_sport = endpoint_hport(st->st_interface->local_endpoint);
				encap_dport = endpoint_hport(st->st_mobike_remote_endpoint);
			}
		}
	}

	sa.src.address = src;
	sa.dst.address = dst;
	sa.text_said = text_said;
	sa.src.client = src_client;
	sa.dst.client = dst_client;
	sa.src.encap_port = encap_sport;
	sa.dst.encap_port = encap_dport;

	char reqid_buf[ULTOT_BUF + 32];
	endpoint_buf ra;
	snprintf(reqid_buf, sizeof(reqid_buf), ":%u to %s reqid=%u %s",
			old_port,
		 str_endpoint(&new_endpoint, &ra),
			sa.reqid,
			enum_name(&netkey_sa_dir_names, dir));
	add_str(text_said, SAMIGTOT_BUF, text_said, reqid_buf);

	dbg("%s", text_said);

	*ret_sa = sa;
	return TRUE;
}

static bool migrate_xfrm_sa(const struct kernel_sa *sa,
			    struct logger *logger)
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
	req.id.sel.family = address_type(sa->src.address)->af;
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

		set_migration_attr(sa, &migrate);

		memcpy(RTA_DATA(attr), &migrate, attr->rta_len);
		attr->rta_len = RTA_LENGTH(attr->rta_len);
		req.n.nlmsg_len += attr->rta_len;
	}

	if (sa->encap_type != NULL) {
		dbg("adding xfrm_encap_templ when migrating sa encap_type="PRI_IP_ENCAP" sport=%d dport=%d",
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

	bool r = send_netlink_msg(&req.n, NLMSG_ERROR, &rsp,
				  "mobike", sa->text_said, logger);
	if (!r)
		return FALSE;

	if (rsp.u.e.error < 0) {
		/* error is already logged */
		return FALSE;
	}

	return TRUE;
}

static bool netlink_migrate_sa(struct state *st)
{
	struct kernel_sa sa;
	char mig_said[SAMIGTOT_BUF];

	return
		create_xfrm_migrate_sa(st, XFRM_POLICY_OUT, &sa, mig_said) &&
		migrate_xfrm_sa(&sa, st->st_logger) &&

		create_xfrm_migrate_sa(st, XFRM_POLICY_IN, &sa, mig_said) &&
		migrate_xfrm_sa(&sa, st->st_logger) &&

		create_xfrm_migrate_sa(st, XFRM_POLICY_FWD, &sa, mig_said) &&
		migrate_xfrm_sa(&sa, st->st_logger);
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
			dbg("cannot offload to %s because SIOCETHTOOL %s failed: %s",
				ifname, action, strerror(errno));
		} else {
			log_errno(logger, errno, "can't offload to %s because SIOCETHTOOL %s failed",
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

static bool netlink_detect_offload(const struct raw_iface *ifp, struct logger *logger)
{
	const char *ifname = ifp->name;
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
static bool netlink_add_sa(const struct kernel_sa *sa, bool replace,
			   struct logger *logger)
{
	struct {
		struct nlmsghdr n;
		struct xfrm_usersa_info p;
		char data[MAX_NETLINK_DATA_SIZE];
	} req;
	struct rtattr *attr;
	int ret;

	zero(&req);
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.n.nlmsg_type = replace ? XFRM_MSG_UPDSA : XFRM_MSG_NEWSA;

	req.p.saddr = xfrm_from_address(sa->src.address);
	req.p.id.daddr = xfrm_from_address(sa->dst.address);

	req.p.id.spi = sa->spi;
	req.p.id.proto = esatype2proto(sa->esatype);
	req.p.family = addrtypeof(sa->src.address);
	/*
	 * This requires ipv6 modules. It is required to support 6in4 and 4in6
	 * tunnels in linux 2.6.25+
	 */
	if (sa->mode == ENCAPSULATION_MODE_TUNNEL) {
		dbg("netlink: enabling tunnel mode");
		req.p.mode = XFRM_MODE_TUNNEL;
		req.p.flags |= XFRM_STATE_AF_UNSPEC;
	} else {
		dbg("netlink: enabling transport mode");
		req.p.mode = XFRM_MODE_TRANSPORT;
	}

	/*
	 * We only add traffic selectors for transport mode. The problem is
	 * that Tunnel mode ipsec with ipcomp is layered so that ipcomp
	 * tunnel is protected with transport mode ipsec but in this case we
	 * shouldn't any more add traffic selectors. Caller function will
	 * inform us if we need or don't need selectors.
	 */
	if (sa->add_selector) {
		ip_selector src = *sa->src.client;
		ip_selector dst = *sa->dst.client;
		const ip_protocol *protocol = protocol_by_ipproto(sa->transport_proto);

		/*
		 * With XFRM/NETKEY and transport mode with nat-traversal we
		 * need to change outbound IPsec SA to point to external ip of
		 * the peer. Here we substitute real client ip with NATD ip.
		 *
		 * XXX: unset_protoport is technically wrong - the
		 * protocol is sa->transport_proto(?) and .  Code
		 * further down will fix up the .sport / .dport in the
		 * xfrm structure.
		 *
		 * XXX: is .src.address / .dst.address an address or
		 * endpoint in disguise?
		 */
		if (sa->inbound) {
			/* inbound; fix this end */
			ip_port port = selector_port(*sa->src.client);
			src = selector_from_address_protocol_port(*sa->src.address,
								  protocol, port);
		} else {
			/* outbound; fix other end */
			ip_port port = selector_port(*sa->dst.client);
			dst = selector_from_address_protocol_port(*sa->dst.address,
								  protocol, port);
		}

		/* .[sd]addr, .prefixlen_[sd], .[sd]port */
		SELECTOR_TO_XFRM(&src, req.p.sel, s);
		SELECTOR_TO_XFRM(&dst, req.p.sel, d);

		/*
		 * Munge .[sd]port?
		 *
		 * As per RFC 4301/5996, icmp type is put in the most
		 * significant 8 bits and icmp code is in the least
		 * significant 8 bits of port field. Although Libreswan does
		 * not have any configuration options for
		 * icmp type/code values, it is possible to specify icmp type
		 * and code  using protoport option. For example,
		 * icmp echo request (type 8/code 0) needs to be encoded as
		 * 0x0800 in the port field and can be specified
		 * as left/rightprotoport=icmp/2048. Now with XFRM,
		 * icmp type and code  need to be passed as source and
		 * destination ports, respectively. Therefore, this code
		 * extracts upper 8 bits and lower 8 bits and puts
		 * into source and destination ports before passing to XFRM.
		 */
		if (IPPROTO_ICMP == sa->transport_proto ||
			IPPROTO_ICMPV6 == sa->transport_proto) {
			uint16_t icmp_type;
			uint16_t icmp_code;

			icmp_type = ntohs(req.p.sel.sport) >> 8;
			icmp_code = ntohs(req.p.sel.sport) & 0xFF;

			req.p.sel.sport = htons(icmp_type);
			req.p.sel.dport = htons(icmp_code);
		}

		req.p.sel.sport_mask = req.p.sel.sport == 0 ? 0 : ~0;
		req.p.sel.dport_mask = req.p.sel.dport == 0 ? 0 : ~0;
		req.p.sel.proto = sa->transport_proto;
		req.p.sel.family = selector_type(&src)->af;
	}

	req.p.reqid = sa->reqid;
	dbg("XFRM: adding IPsec SA with reqid %d", sa->reqid);

	/* TODO expose limits to kernel_sa via config */
	req.p.lft.soft_byte_limit = XFRM_INF;
	req.p.lft.soft_packet_limit = XFRM_INF;
	req.p.lft.hard_byte_limit = XFRM_INF;
	req.p.lft.hard_packet_limit = XFRM_INF;

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
	if (sa->esatype == ET_AH && addrtypeof(sa->src.address) == AF_INET) {
		dbg("netlink: aligning IPv4 AH to 32bits as per RFC-4302, Section 3.3.3.2.1");
		req.p.flags |= XFRM_STATE_ALIGN4;
	}

	if (sa->esatype != ET_IPCOMP) {
		if (sa->esn) {
			dbg("netlink: enabling ESN");
			req.p.flags |= XFRM_STATE_ESN;
		}
		if (sa->decap_dscp) {
			dbg("netlink: enabling Decap DSCP");
			req.p.flags |= XFRM_STATE_DECAP_DSCP;
		}
		if (sa->nopmtudisc) {
			dbg("netlink: disabling Path MTU Discovery");
			req.p.flags |= XFRM_STATE_NOPMTUDISC;
		}

		if (sa->replay_window <= 32 && !sa->esn) {
			/* this only works up to 32, for > 32 and for ESN, we need struct xfrm_replay_state_esn */
			req.p.replay_window = sa->replay_window;
			dbg("netlink: setting IPsec SA replay-window to %d using old-style req",
			    req.p.replay_window);
		} else {
			uint32_t bmp_size = BYTES_FOR_BITS(sa->replay_window +
				pad_up(sa->replay_window, sizeof(uint32_t) * BITS_PER_BYTE) );
			/* this is where we could fill in sequence numbers for this SA */
			struct xfrm_replay_state_esn xre = {
				/* replay_window must be multiple of 8 */
				.replay_window = sa->replay_window,
				.bmp_len = bmp_size / sizeof(uint32_t),
			};
			dbg("netlink: setting IPsec SA replay-window to %" PRIu32 " using xfrm_replay_state_esn",
			    xre.replay_window);

			attr->rta_type = XFRMA_REPLAY_ESN_VAL;
			attr->rta_len = RTA_LENGTH(sizeof(xre) + bmp_size);
			memcpy(RTA_DATA(attr), &xre, sizeof(xre));
			req.n.nlmsg_len += attr->rta_len;
			attr = (struct rtattr *)((char *)&req + req.n.nlmsg_len);
		}
	}

	if (sa->authkeylen != 0) {
		const char *name = sa->integ->integ_netlink_xfrm_name;
		if (name == NULL) {
			llog(RC_LOG_SERIOUS, logger,
				    "XFRM: unknown authentication algorithm: %s",
				    sa->integ->common.fqn);
			return FALSE;
		}

		/*
		 * According to RFC-4868 the hash should be nnn/2, so
		 * 128 bits for SHA256 and 256 for SHA512. The XFRM
		 * kernel uses a default of 96, which was the value in
		 * an earlier draft. The kernel then introduced a new struct
		 * xfrm_algo_auth to  replace struct xfrm_algo to deal with
		 * this.
		 */

		struct xfrm_algo_auth algo = {
			.alg_key_len = sa->integ->integ_keymat_size * BITS_PER_BYTE,
			.alg_trunc_len = sa->integ->integ_output_size * BITS_PER_BYTE,
		};

		attr->rta_type = XFRMA_ALG_AUTH_TRUNC;
		attr->rta_len = RTA_LENGTH(sizeof(algo) + sa->authkeylen);

		fill_and_terminate(algo.alg_name, name, sizeof(algo.alg_name));
		memcpy(RTA_DATA(attr), &algo, sizeof(algo));
		memcpy((char *)RTA_DATA(attr) + sizeof(algo),
			sa->authkey, sa->authkeylen);

		req.n.nlmsg_len += attr->rta_len;
		attr = (struct rtattr *)((char *)attr + attr->rta_len);
	}

	/*
	 * ??? why does IPCOMP trump aead and ESP?
	 *  Shouldn't all be bundled?
	 */
	if (sa->esatype == ET_IPCOMP) {
		struct xfrm_algo algo;
		const char *name = sparse_name(calg_list, sa->compalg);

		if (name == NULL) {
			llog(RC_LOG_SERIOUS, logger,
				    "unknown compression algorithm: %u",
				    sa->compalg);
			return FALSE;
		}

		fill_and_terminate(algo.alg_name, name, sizeof(algo.alg_name));
		algo.alg_key_len = 0;

		attr->rta_type = XFRMA_ALG_COMP;
		attr->rta_len = RTA_LENGTH(sizeof(algo));

		memcpy(RTA_DATA(attr), &algo, sizeof(algo));

		req.n.nlmsg_len += attr->rta_len;
		attr = (struct rtattr *)((char *)attr + attr->rta_len);
	} else if (sa->esatype == ET_ESP) {
		const char *name = sa->encrypt->encrypt_netlink_xfrm_name;

		if (name == NULL) {
			llog(RC_LOG_SERIOUS, logger,
				    "unknown encryption algorithm: %s",
				    sa->encrypt->common.fqn);
			return FALSE;
		}

		if (encrypt_desc_is_aead(sa->encrypt)) {
			struct xfrm_algo_aead algo;

			fill_and_terminate(algo.alg_name, name,
					sizeof(algo.alg_name));
			algo.alg_key_len = sa->enckeylen * BITS_PER_BYTE;
			algo.alg_icv_len = sa->encrypt->aead_tag_size * BITS_PER_BYTE;

			attr->rta_type = XFRMA_ALG_AEAD;
			attr->rta_len = RTA_LENGTH(sizeof(algo) + sa->enckeylen);

			memcpy(RTA_DATA(attr), &algo, sizeof(algo));
			memcpy((char *)RTA_DATA(attr) + sizeof(algo),
				sa->enckey, sa->enckeylen);

			req.n.nlmsg_len += attr->rta_len;
			attr = (struct rtattr *)((char *)attr + attr->rta_len);

		} else {
			struct xfrm_algo algo;

			fill_and_terminate(algo.alg_name, name,
					sizeof(algo.alg_name));
			algo.alg_key_len = sa->enckeylen * BITS_PER_BYTE;

			attr->rta_type = XFRMA_ALG_CRYPT;
			attr->rta_len = RTA_LENGTH(sizeof(algo) + sa->enckeylen);

			memcpy(RTA_DATA(attr), &algo, sizeof(algo));
			memcpy((char *)RTA_DATA(attr) + sizeof(algo),
				sa->enckey,
			sa->enckeylen);

			req.n.nlmsg_len += attr->rta_len;
			attr = (struct rtattr *)((char *)attr + attr->rta_len);

			/* Traffic Flow Confidentiality is only for ESP tunnel mode */
			if (sa->tfcpad != 0 &&
			    sa->mode == ENCAPSULATION_MODE_TUNNEL) {
				dbg("netlink: setting TFC to %" PRIu32 " (up to PMTU)",
				    sa->tfcpad);

				attr->rta_type = XFRMA_TFCPAD;
				attr->rta_len = RTA_LENGTH(sizeof(sa->tfcpad));
				memcpy(RTA_DATA(attr), &sa->tfcpad, sizeof(sa->tfcpad));
				req.n.nlmsg_len += attr->rta_len;
				attr = (struct rtattr *)((char *)attr + attr->rta_len);

			}
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
		dbg("%s netlink: XFRMA_IF_ID %" PRIu32 " req.n.nlmsg_type=%" PRIu32,
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

	if (sa->nic_offload_dev) {
		struct xfrm_user_offload xuo = {
			.flags = (sa->inbound ? XFRM_OFFLOAD_INBOUND : 0) |
				(addrtypeof(sa->src.address) == AF_INET6 ? XFRM_OFFLOAD_IPV6 : 0),
			.ifindex = if_nametoindex(sa->nic_offload_dev),
		};

		attr->rta_type = XFRMA_OFFLOAD_DEV;
		attr->rta_len = RTA_LENGTH(sizeof(xuo));

		memcpy(RTA_DATA(attr), &xuo, sizeof(xuo));

		req.n.nlmsg_len += attr->rta_len;
		attr = (struct rtattr *)((char *)attr + attr->rta_len);
		dbg("netlink: esp-hw-offload set via interface %s for IPsec SA", sa->nic_offload_dev);
	} else {
		dbg("netlink: esp-hw-offload not set for IPsec SA");
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

	ret = send_netlink_msg(&req.n, NLMSG_NOOP, NULL,
			       "Add SA", sa->text_said, logger);
	if (!ret && netlink_errno == ESRCH &&
		req.n.nlmsg_type == XFRM_MSG_UPDSA) {
		llog(RC_LOG_SERIOUS, logger,
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
static bool netlink_del_sa(const struct kernel_sa *sa,
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

	req.id.daddr = xfrm_from_address(sa->dst.address);

	req.id.spi = sa->spi;
	req.id.family = addrtypeof(sa->src.address);
	req.id.proto = sa->proto->ipproto;

	req.n.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req.id)));

	dbg("XFRM: deleting IPsec SA with reqid %d", sa->reqid);

	return send_netlink_msg(&req.n, NLMSG_NOOP, NULL,
				"Del SA", sa->text_said, logger);
}

/*
 * Create ip_address out of xfrm_address_t.
 *
 * @param family
 * @param src xfrm formatted IP address
 * @param dst ip_address formatted destination
 * @return err_t NULL if okay, otherwise an error
 */
static ip_address address_from_xfrm(const struct ip_info *afi,
				    const xfrm_address_t *xaddr)
{
	/* .len == ipv6 size */
	shunk_t x = THING_AS_SHUNK(*xaddr);

	ip_address addr = afi->address.any; /* "zero" it & set type */
	chunk_t a = address_as_chunk(&addr);

	/* a = x */
	passert(a.len <= x.len);
	memcpy(a.ptr, x.ptr, a.len);

	return addr;
}

/*
 * Create the client's ip_endpoint from xfrm_address_t:NPORT.
 */

static ip_endpoint endpoint_from_xfrm(const struct ip_info *afi,
				      const ip_protocol *protocol,
				      const xfrm_address_t *src,
				      uint16_t nport)
{
	ip_address address = address_from_xfrm(afi, src);
	ip_port port = ip_nport(nport);
	return endpoint_from_address_protocol_port(address, protocol, port);
}

static void netlink_acquire(struct nlmsghdr *n, struct logger *logger)
{
	struct xfrm_user_acquire *acquire;
	struct xfrm_user_sec_ctx_ike *uctx = NULL;
	chunk_t sec_label = {
		.ptr = NULL,
		.len = 0
	};

	dbg("xfrm netlink msg len %zu", (size_t) n->nlmsg_len);

	if (n->nlmsg_len < NLMSG_LENGTH(sizeof(*acquire))) {
		llog(RC_LOG, logger,
		     "netlink_acquire got message with length %zu < %zu bytes; ignore message",
		     (size_t) n->nlmsg_len,
		     sizeof(*acquire));
		return;
	}

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
	acquire = NLMSG_DATA(n);	/* insufficiently aligned */

	const struct ip_info *afi = aftoinfo(acquire->policy.sel.family);
	if (afi == NULL) {
		llog(RC_LOG, logger,
		     "XFRM_MSG_ACQUIRE message from kernel malformed: family %u unknown",
		     acquire->policy.sel.family);
		return;
	}
	const ip_protocol *protocol = protocol_by_ipproto(acquire->sel.proto);
	if (protocol == NULL) {
		llog(RC_LOG, logger,
		     "XFRM_MSG_ACQUIRE message from kernel malformed: protocol %u unknown",
		     acquire->policy.sel.proto);
		return;
	}
	ip_endpoint local = endpoint_from_xfrm(afi, protocol,
					      &acquire->sel.saddr,
					      acquire->sel.sport);
	ip_endpoint remote = endpoint_from_xfrm(afi, protocol,
						&acquire->sel.daddr,
						acquire->sel.dport);

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
			struct xfrm_user_tmpl* tmpl = (struct xfrm_user_tmpl *) RTA_DATA(attr);
			dbg("... xfrm template attribute with reqid:%d, spi:%d, proto:%d",
			    tmpl->reqid, tmpl->id.spi, tmpl->id.proto);
			break;
		}
		case XFRMA_POLICY_TYPE:
			/* discard */
			dbg("... xfrm policy type ignored");
			break;
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
			if (uctx != NULL) {
				llog(RC_LOG, logger,
				     "Second sec_label in a single Acquire message; ignoring Acquire message");
				return;
			}

			/*
			 * note: xuctx + 1 is tricky:
			 * first byte after header
			 */
			sec_label.ptr = (uint8_t *)(xuctx + 1);
			sec_label.len = len;

			err_t ugh = vet_seclabel(HUNK_AS_SHUNK(sec_label));

			if (ugh != NULL) {
				llog(RC_LOG, logger,
					"received bad %s; ignoring Acquire message", ugh);
				return;
			}

			dbg("xfrm: xuctx security context value: %.*s",
				(int)len,
				(const char *) (xuctx + 1));
			break;
		}
		default:
			dbg("... ignoring unknown xfrm acquire payload type %u",
			    attr->rta_type);
			break;
		}
		/* updates remaining too */
		attr = RTA_NEXT(attr, remaining);
	}
	record_and_initiate_opportunistic(&local, &remote, sec_label,
					  "%acquire-netlink");
}

static void netlink_shunt_expire(struct xfrm_userpolicy_info *pol,
				 struct logger *logger)
{
	const xfrm_address_t *srcx = &pol->sel.saddr;
	const xfrm_address_t *dstx = &pol->sel.daddr;
	unsigned transport_proto = pol->sel.proto;

	const struct ip_info *afi = aftoinfo(pol->sel.family);
	if (afi == NULL) {
		llog(RC_LOG, logger,
			    "XFRM_MSG_POLEXPIRE message from kernel malformed: address family %u unknown",
			    pol->sel.family);
		return;
	}

	ip_address src = address_from_xfrm(afi, srcx);
	ip_address dst = address_from_xfrm(afi, dstx);

	if (delete_bare_shunt(&src, &dst,
			      transport_proto, SPI_HOLD /* why spi to use? */,
			       /*skip_xfrm_raw_eroute_delete?*/false,
			      "delete expired bare shunt", logger)) {
		dbg("netlink_shunt_expire() called delete_bare_shunt() with success");
	} else {
		llog(RC_LOG, logger,
			    "netlink_shunt_expire() called delete_bare_shunt() which failed!");
	}
}

static void process_addr_chage(struct nlmsghdr *n, struct logger *logger)
{
	struct ifaddrmsg *nl_msg = NLMSG_DATA(n);
	struct rtattr *rta = IFLA_RTA(nl_msg);
	size_t msg_size = IFA_PAYLOAD (n);
	ip_address ip;

	dbg("xfrm netlink address change %s msg len %zu",
	    sparse_val_show(rtm_type_names, n->nlmsg_type),
	    (size_t) n->nlmsg_len);

	while (RTA_OK(rta, msg_size)) {
		err_t ugh;

		switch (rta->rta_type) {
		case IFA_LOCAL:
			ugh = data_to_address(RTA_DATA(rta), RTA_PAYLOAD(rta)/*size*/,
					      aftoinfo(nl_msg->ifa_family), &ip);
			if (ugh != NULL) {
				llog(RC_LOG, logger,
					    "ERROR IFA_LOCAL invalid %s", ugh);
			} else  {
				if (n->nlmsg_type == RTM_DELADDR)
					record_deladdr(&ip, "IFA_LOCAL");
				else if (n->nlmsg_type == RTM_NEWADDR)
					record_newaddr(&ip, "IFA_LOCAL");
			}
			break;

		case IFA_ADDRESS:
			ugh = data_to_address(RTA_DATA(rta), RTA_PAYLOAD(rta)/*size*/,
					      aftoinfo(nl_msg->ifa_family), &ip);
			if (ugh != NULL) {
				llog(RC_LOG, logger,
					    "ERROR IFA_ADDRESS invalid %s", ugh);
			} else  {
				address_buf ip_str;
				dbg("XFRM IFA_ADDRESS %s IFA_ADDRESS is this PPP?",
				    str_address(&ip, &ip_str));
			}
			break;

		default:
			dbg("IKEv2 received address %s type %u",
			    sparse_val_show(rtm_type_names, n->nlmsg_type),
			    rta->rta_type);
			break;
		}

		rta = RTA_NEXT(rta, msg_size);
	}
}

static void netlink_policy_expire(struct nlmsghdr *n, struct logger *logger)
{
	struct xfrm_user_polexpire *upe;
	ip_address src, dst;

	struct {
		struct nlmsghdr n;
		struct xfrm_userpolicy_id id;
	} req;
	struct nlm_resp rsp;

	if (n->nlmsg_len < NLMSG_LENGTH(sizeof(*upe))) {
		llog(RC_LOG, logger,
			    "netlink_policy_expire got message with length %zu < %zu bytes; ignore message",
			    (size_t) n->nlmsg_len,
			    sizeof(*upe));
		return;
	}

	upe = NLMSG_DATA(n);
	xfrm2ip(&upe->pol.sel.saddr, &src, upe->pol.sel.family);
	xfrm2ip(&upe->pol.sel.daddr, &dst, upe->pol.sel.family);
	address_buf a;
	address_buf b;
	dbg("%s src %s/%u dst %s/%u dir %d index %d",
	    __func__,
	    str_address(&src, &a), upe->pol.sel.prefixlen_s,
	    str_address(&dst, &b), upe->pol.sel.prefixlen_d,
	    upe->pol.dir, upe->pol.index);

	req.id.dir = upe->pol.dir;
	req.id.index = upe->pol.index;
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = XFRM_MSG_GETPOLICY;
	req.n.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req.id)));

	if (!send_netlink_msg(&req.n, XFRM_MSG_NEWPOLICY, &rsp,
			      "Get policy", "?", logger)) {
		dbg("netlink_policy_expire: policy died on us: dir=%d, index=%d",
		    req.id.dir, req.id.index);
	} else if (rsp.n.nlmsg_len < NLMSG_LENGTH(sizeof(rsp.u.pol))) {
		llog(RC_LOG, logger,
			    "netlink_policy_expire: XFRM_MSG_GETPOLICY returned message with length %zu < %zu bytes; ignore message",
			    (size_t) rsp.n.nlmsg_len,
			    sizeof(rsp.u.pol));
	} else if (req.id.index != rsp.u.pol.index) {
		dbg("netlink_policy_expire: policy was replaced: dir=%d, oldindex=%d, newindex=%d",
		    req.id.dir, req.id.index, rsp.u.pol.index);
	} else if (upe->pol.curlft.add_time != rsp.u.pol.curlft.add_time) {
		dbg("netlink_policy_expire: policy was replaced  and you have won the lottery: dir=%d, index=%d",
		    req.id.dir, req.id.index);
	} else {
		switch (upe->pol.dir) {
		case XFRM_POLICY_OUT:
			netlink_shunt_expire(&rsp.u.pol, logger);
			break;
		}
	}
}

/* returns FALSE iff EAGAIN */
static bool netlink_get(int fd, struct logger *logger)
{
	struct nlm_resp rsp;
	struct sockaddr_nl addr;
	socklen_t alen = sizeof(addr);
	ssize_t r = recvfrom(fd, &rsp, sizeof(rsp), 0,
		(struct sockaddr *)&addr, &alen);

	if (r < 0) {
		if (errno == EAGAIN)
			return FALSE;

		if (errno != EINTR) {
			log_errno(logger, errno,
				  "recvfrom() failed in netlink_get: errno(%d): %s",
				  errno, strerror(errno));
		}
		return TRUE;
	} else if ((size_t)r < sizeof(rsp.n)) {
		llog(RC_LOG, logger,
			    "netlink_get read truncated message: %zd bytes; ignore message",
			    r);
		return true;
	} else if (addr.nl_pid != 0) {
		/* not for us: ignore */
		dbg("netlink_get: ignoring %s message from process %u",
		    sparse_val_show(xfrm_type_names, rsp.n.nlmsg_type),
		    addr.nl_pid);
		return TRUE;
	} else if ((size_t)r != rsp.n.nlmsg_len) {
		llog(RC_LOG, logger,
			    "netlink_get read message with length %zd that doesn't equal nlmsg_len %zu bytes; ignore message",
			    r, (size_t) rsp.n.nlmsg_len);
		return true;
	}

	dbg("netlink_get: %s message",
	    sparse_val_show(xfrm_type_names, rsp.n.nlmsg_type));

	switch (rsp.n.nlmsg_type) {
	case XFRM_MSG_ACQUIRE:
		netlink_acquire(&rsp.n, logger);
		break;
	case XFRM_MSG_POLEXPIRE:
		netlink_policy_expire(&rsp.n, logger);
		break;

	case RTM_NEWADDR:
		process_addr_chage(&rsp.n, logger);
		break;

	case RTM_DELADDR:
		process_addr_chage(&rsp.n, logger);
		break;

	default:
		/* ignored */
		break;
	}

	return TRUE;
}

static void netlink_process_msg(int fd, struct logger *logger)
{
	do {} while (netlink_get(fd, logger));
}

static ipsec_spi_t netlink_get_spi(const ip_address *src,
				   const ip_address *dst,
				   const struct ip_protocol *proto,
				   bool tunnel_mode,
				   reqid_t reqid,
				   ipsec_spi_t min,
				   ipsec_spi_t max,
				   const char *text_said,
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
	req.spi.info.mode = tunnel_mode;
	req.spi.info.reqid = reqid;
	req.spi.info.id.proto = proto->ipproto;
	req.spi.info.family = addrtypeof(src);

	req.n.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req.spi)));

	req.spi.min = min;
	req.spi.max = max;

	if (!send_netlink_msg(&req.n, XFRM_MSG_NEWSA, &rsp,
			      "Get SPI", text_said, logger)) {
		return 0;
	}

	if (rsp.n.nlmsg_len < NLMSG_LENGTH(sizeof(rsp.u.sa))) {
		llog(RC_LOG, logger,
			    "netlink_get_spi: XFRM_MSG_ALLOCSPI returned message with length %zu < %zu bytes; ignore message",
			    (size_t) rsp.n.nlmsg_len,
			    sizeof(rsp.u.sa));
		return 0;
	}

	dbg("netlink_get_spi: allocated 0x%x for %s",
	    ntohl(rsp.u.sa.id.spi), text_said);
	return rsp.u.sa.id.spi;
}

/*
 * install or remove eroute for SA Group
 *
 * (identical to KLIPS version, but refactoring isn't waranteed yet
 */
static bool netlink_sag_eroute(const struct state *st, const struct spd_route *sr,
			unsigned op, const char *opname)
{
	struct connection *c = st->st_connection;
	enum eroute_type inner_esatype;
	ipsec_spi_t inner_spi;
	struct pfkey_proto_info proto_info[4];
	int i;
	bool tunnel;

	/*
	 * figure out the SPI and protocol (in two forms)
	 * for the innermost transformation.
	 */
	i = elemsof(proto_info) - 1;
	proto_info[i].proto = 0;
	tunnel = FALSE;

	const struct ip_protocol *inner_proto = NULL;
	inner_esatype = ET_UNSPEC;
	inner_spi = 0;

	if (st->st_ah.present) {
		inner_spi = st->st_ah.attrs.spi;
		inner_proto = &ip_protocol_ah;
		inner_esatype = ET_AH;

		i--;
		proto_info[i].proto = IPPROTO_AH;
		proto_info[i].mode = st->st_ah.attrs.mode;
		tunnel |= proto_info[i].mode ==
			ENCAPSULATION_MODE_TUNNEL;
		proto_info[i].reqid = reqid_ah(sr->reqid);
	}

	if (st->st_esp.present) {
		inner_spi = st->st_esp.attrs.spi;
		inner_proto = &ip_protocol_esp;
		inner_esatype = ET_ESP;

		i--;
		proto_info[i].proto = IPPROTO_ESP;
		proto_info[i].mode = st->st_esp.attrs.mode;
		tunnel |= proto_info[i].mode ==
			ENCAPSULATION_MODE_TUNNEL;
		proto_info[i].reqid = reqid_esp(sr->reqid);
	}

	if (st->st_ipcomp.present) {
		inner_spi = st->st_ipcomp.attrs.spi;
		inner_proto = &ip_protocol_comp;
		inner_esatype = ET_IPCOMP;

		i--;
		proto_info[i].proto = IPPROTO_COMP;
		proto_info[i].mode =
			st->st_ipcomp.attrs.mode;
		tunnel |= proto_info[i].mode ==
			ENCAPSULATION_MODE_TUNNEL;
		proto_info[i].reqid = reqid_ipcomp(sr->reqid);
	}

	/* check for no transform at all */
	passert(st->st_ipcomp.present || st->st_esp.present ||
			st->st_ah.present);

	if (tunnel) {
		int j;

		inner_spi = st->st_tunnel_out_spi;
		inner_proto = &ip_protocol_ipip;
		inner_esatype = ET_IPIP;

		proto_info[i].mode = ENCAPSULATION_MODE_TUNNEL;
		for (j = i + 1; proto_info[j].proto; j++)
			proto_info[j].mode =
				ENCAPSULATION_MODE_TRANSPORT;
	}

	uint32_t xfrm_if_id = c->xfrmi != NULL ?  c->xfrmi->if_id : 0;

	return eroute_connection(sr, inner_spi, inner_spi, inner_proto,
				 inner_esatype, proto_info + i,
				 calculate_sa_prio(c, FALSE), &c->sa_marks,
				 xfrm_if_id, op, opname, st->st_logger);
}

/* Check if there was traffic on given SA during the last idle_max
 * seconds. If TRUE, the SA was idle and DPD exchange should be performed.
 * If FALSE, DPD is not necessary. We also return TRUE for errors, as they
 * could mean that the SA is broken and needs to be replace anyway.
 *
 * note: this mutates *st by calling get_sa_info
 */
static bool netlink_eroute_idle(struct state *st, deltatime_t idle_max)
{
	deltatime_t idle_time;

	passert(st != NULL);
	return !get_sa_info(st, TRUE, &idle_time) ||
		deltatime_cmp(idle_time, >=, idle_max);
}

static bool netlink_shunt_eroute(const struct connection *c,
				 const struct spd_route *sr,
				 enum routing_t rt_kind,
				 enum pluto_sadb_operations op,
				 const char *opname,
				 struct logger *logger)
{
	ipsec_spi_t spi;

	/*
	 * We are constructing a special SAID for the eroute.
	 * The destination doesn't seem to matter, but the family does.
	 * The protocol is &ip_protocol_internal -- mark this as shunt.
	 * The satype has no meaning, but is required for PF_KEY header!
	 * The SPI signifies the kind of shunt.
	 */
	spi = shunt_policy_spi(c, rt_kind == RT_ROUTED_PROSPECTIVE);

	if (DBGP(DBG_BASE)) {
		selector_buf this_buf, that_buf;
		DBG_log("netlink_shunt_eroute for proto %d, and source %s dest %s",
			sr->this.protocol,
			str_selector(&sr->this.client, &this_buf),
			str_selector(&sr->that.client, &that_buf));
	}

	if (spi == 0) {
		/*
		 * we're supposed to end up with no eroute: rejig op and
		 * opname
		 */
		switch (op) {
		case ERO_REPLACE:
			/* replace with nothing == delete */
			op = ERO_DELETE;
			opname = "delete";
			break;
		case ERO_ADD:
			/* add nothing == do nothing */
			return TRUE;

		case ERO_DELETE:
			/* delete remains delete */
			break;

		case ERO_ADD_INBOUND:
			break;

		case ERO_DEL_INBOUND:
			break;

		default:
			bad_case(op);
		}
	}

	if (sr->routing == RT_ROUTED_ECLIPSED && c->kind == CK_TEMPLATE) {
		/*
		 * We think that we have an eroute, but we don't.
		 * Adjust the request and account for eclipses.
		 */
		passert(eclipsable(sr));
		switch (op) {
		case ERO_REPLACE:
			/* really an add */
			op = ERO_ADD;
			opname = "replace eclipsed";
			eclipse_count--;
			break;
		case ERO_DELETE:
			/*
			 * delete unnecessary:
			 * we don't actually have an eroute
			 */
			eclipse_count--;
			return TRUE;

		case ERO_ADD:
		default:
			bad_case(op);
		}
	} else if (eclipse_count > 0 && op == ERO_DELETE && eclipsable(sr)) {
		/* maybe we are uneclipsing something */
		struct spd_route *esr;
		struct connection *ue = eclipsed(c, &esr);

		if (ue != NULL) {
			esr->routing = RT_ROUTED_PROSPECTIVE;
			return netlink_shunt_eroute(ue, esr,
						    RT_ROUTED_PROSPECTIVE,
						    ERO_REPLACE,
						    "restoring eclipsed",
						    logger);
		}
	}

	char buf2[256];

	snprintf(buf2, sizeof(buf2), "eroute_connection %s", opname);

	/*
	 * XXX: the two calls below to netlink_raw_eroute() (not
	 * raw_eroute()) seems to be the only place where SA_PROTO and
	 * ESATYPE disagree - when ENCAPSULATION_MODE_TRANSPORT
	 * SA_PROTO==&ip_protocol_esp and ESATYPE==ET_INT!?!  Looking in the
	 * function there's a weird test involving both SA_PROTO and
	 * ESATYPE.
	 */
	const struct ip_protocol *sa_proto = c->ipsec_mode == ENCAPSULATION_MODE_TRANSPORT ?
		&ip_protocol_esp : &ip_protocol_internal;

	if (!netlink_raw_eroute(&sr->this.host_addr, &sr->this.client,
				&sr->that.host_addr, &sr->that.client,
				htonl(spi), htonl(spi),
				sa_proto,
				sr->this.protocol,
				ET_INT,
				null_proto_info,
				deltatime(0),
				calculate_sa_prio(c, FALSE),
				&c->sa_marks,
				(c->xfrmi != NULL) ? c->xfrmi->if_id : 0,
				op, buf2,
				&sr->this.sec_label,
				logger))
		return false;

	switch (op) {
	case ERO_ADD:
		op = ERO_ADD_INBOUND;
		break;
	case ERO_DELETE:
		op = ERO_DEL_INBOUND;
		break;
	default:
		return TRUE;
	}

	snprintf(buf2, sizeof(buf2), "eroute_connection %s inbound", opname);

	return netlink_raw_eroute(&sr->that.host_addr, &sr->that.client,
				  &sr->this.host_addr, &sr->this.client,
				  htonl(spi), htonl(spi),
				  sa_proto,
				  sr->this.protocol,
				  ET_INT,
				  null_proto_info,
				  deltatime(0),
				  calculate_sa_prio(c, FALSE),
				  &c->sa_marks,
				  0, /* xfrm_if_id needed for shunt? */
				  op, buf2,
				  &sr->this.sec_label,
				  logger);
}

static void netlink_process_raw_ifaces(struct raw_iface *rifaces, struct logger *logger)
{
	struct raw_iface *ifp;
	ip_address lip;	/* --listen filter option */

	if (pluto_listen) {
		err_t e = ttoaddress_num(shunk1(pluto_listen), NULL/*UNSPEC*/, &lip);

		if (e != NULL) {
			DBG_log("invalid listen= option ignored: %s", e);
			pluto_listen = NULL;
		}
		address_buf b;
		dbg("Only looking to listen on %s", str_address(&lip, &b));
	}

	/*
	 * Find all virtual/real interface pairs.
	 * For each real interface...
	 */
	for (ifp = rifaces; ifp != NULL; ifp = ifp->next) {
		struct raw_iface *v = NULL;	/* matching ipsecX interface */
		bool after = FALSE;	/* has vfp passed ifp on the list? */
		bool bad = FALSE;
		struct raw_iface *vfp;

		/* ignore if virtual (ipsec*) interface */
		if (startswith(ifp->name, IPSECDEVPREFIX))
			continue;

		/* ignore if virtual (mast*) interface */
		if (startswith(ifp->name, MASTDEVPREFIX))
			continue;

		for (vfp = rifaces; vfp != NULL; vfp = vfp->next) {
			if (vfp == ifp) {
				after = true;
			} else if (sameaddr(&ifp->addr, &vfp->addr)) {
				/*
				 * Different entries with matching IP
				 * addresses.
				 *
				 * Many interesting cases.
				 */
				if (startswith(vfp->name, IPSECDEVPREFIX)) {
					if (v != NULL) {
						ipstr_buf b;

						llog(RC_LOG_SERIOUS, logger,
							    "ipsec interfaces %s and %s share same address %s",
							    v->name, vfp->name,
							    ipstr(&ifp->addr, &b));
						bad = true;
					} else {
						/* current winner */
						v = vfp;
					}
				} else {
					/*
					 * ugh: a second real interface with
					 * the same IP address "after" allows
					 * us to avoid double reporting.
					 */
					/* XXX: isn't this always true? */
					if (kernel_ops->type == USE_XFRM) {
						if (after) {
							bad = TRUE;
							break;
						}
						continue;
					}
					if (after) {
						ipstr_buf b;

						llog(RC_LOG_SERIOUS, logger,
							    "IP interfaces %s and %s share address %s!",
							    ifp->name, vfp->name,
							    ipstr(&ifp->addr, &b));
					}
					bad = TRUE;
				}
			}
		}

		if (bad)
			continue;

		/* XXX: isn't this always true? */
		if (kernel_ops->type == USE_XFRM) {
			v = ifp;
		}

		/* what if we didn't find a virtual interface? */
		if (v == NULL) {
			address_buf b;
			dbg("IP interface %s %s has no matching ipsec* interface -- ignored",
			    ifp->name, str_address(&ifp->addr, &b));
			continue;
		}

		/*
		 * We've got all we need; see if this is a new thing:
		 * search old interfaces list.
		 */

		/*
		 * last check before we actually add the entry.
		 *
		 * ignore if --listen is specified and we do not match
		 */
		if (pluto_listen != NULL && !sameaddr(&lip, &ifp->addr)) {
			ipstr_buf b;

			llog(RC_LOG, logger,
				    "skipping interface %s with %s",
				    ifp->name, ipstr(&ifp->addr, &b));
			continue;
		}

		add_or_keep_iface_dev(ifp, logger);
	}

	/* delete the raw interfaces list */
	while (rifaces != NULL) {
		struct raw_iface *t = rifaces;

		rifaces = t->next;
		pfree(t);
	}
}

/*
 * netlink_get_sa - Get SA information from the kernel
 *
 * @param sa Kernel SA to be queried
 * @param bytes octets processed by IPsec SA
 * @param add_time timestamp when IPsec SA added
 * @return bool True if successful
 */
static bool netlink_get_sa(const struct kernel_sa *sa, uint64_t *bytes,
			   uint64_t *add_time, struct logger *logger)
{
	struct {
		struct nlmsghdr n;
		struct xfrm_usersa_id id;
	} req;

	struct nlm_resp rsp;

	zero(&req);
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = XFRM_MSG_GETSA;

	req.id.daddr = xfrm_from_address(sa->dst.address);

	req.id.spi = sa->spi;
	req.id.family = addrtypeof(sa->src.address);
	req.id.proto = sa->proto->ipproto;

	req.n.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req.id)));

	if (!send_netlink_msg(&req.n, XFRM_MSG_NEWSA, &rsp,
			      "Get SA", sa->text_said, logger))
		return FALSE;

	*bytes = rsp.u.info.curlft.bytes;
	*add_time = rsp.u.info.curlft.add_time;
	return TRUE;
}

/* add bypass policies/holes icmp */
static bool netlink_bypass_policy(int family, int proto, int port,
				  struct logger *logger)
{
	struct {
		struct nlmsghdr n;
		union {
			struct xfrm_userpolicy_info p;
			struct xfrm_userpolicy_id id;
		} u;
		char data[MAX_NETLINK_DATA_SIZE];
	} req;

	zero(&req);

	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	req.n.nlmsg_type = XFRM_MSG_UPDPOLICY;
	req.n.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req.u.p)));

	req.u.p.dir = XFRM_POLICY_IN;
	req.u.p.priority = 1; /* give admin prio 0 as override */
	req.u.p.action = XFRM_POLICY_ALLOW;
	req.u.p.share = XFRM_SHARE_ANY;

	req.u.p.lft.soft_byte_limit = XFRM_INF;
	req.u.p.lft.soft_packet_limit = XFRM_INF;
	req.u.p.lft.hard_byte_limit = XFRM_INF;
	req.u.p.lft.hard_packet_limit = XFRM_INF;

	req.u.p.sel.proto = proto;
	req.u.p.sel.family = family;

	const char* text = "add port bypass";

	if (proto == IPPROTO_ICMPV6) {
		uint16_t icmp_type;
		uint16_t icmp_code;

		icmp_type = port >> 8;
		icmp_code = port & 0xFF;
		req.u.p.sel.sport = htons(icmp_type);
		req.u.p.sel.dport = htons(icmp_code);
		req.u.p.sel.sport_mask = 0xffff;

		if (!netlink_policy(&req.n, 1, text, logger))
			return FALSE;

		req.u.p.dir = XFRM_POLICY_FWD;

		if (!netlink_policy(&req.n, 1, text, logger))
			return FALSE;

		req.u.p.dir  = XFRM_POLICY_OUT;

		if (!netlink_policy(&req.n, 1, text, logger))
			return FALSE;
	} else {
		req.u.p.sel.dport = htons(port);
		req.u.p.sel.dport_mask = 0xffff;

		if (!netlink_policy(&req.n, 1, text, logger))
			return FALSE;

		req.u.p.dir  = XFRM_POLICY_OUT;

		req.u.p.sel.sport = htons(port);
		req.u.p.sel.sport_mask = 0xffff;
		req.u.p.sel.dport = 0;
		req.u.p.sel.dport_mask = 0;

		if (!netlink_policy(&req.n, 1, text, logger))
			return FALSE;
	}

	return TRUE;
}

static void netlink_v6holes(struct logger *logger)
{
	/* this could be per interface specific too */
	const char proc_f[] = "/proc/sys/net/ipv6/conf/all/disable_ipv6";

	struct stat sts;
	if (stat(proc_f, &sts) != 0) {
		/* not error */
		llog(RC_LOG, logger,
			    "kernel: starting without ipv6 support! could not stat \"%s\"" PRI_ERRNO,
			    proc_f, pri_errno(errno));
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

	if (!netlink_bypass_policy(AF_INET6, IPPROTO_ICMPV6,
				   ICMP_NEIGHBOR_DISCOVERY,
				   logger)) {
		fatal(PLUTO_EXIT_KERNEL_FAIL, logger,
		      "kernel: could not insert ICMP_NEIGHBOUR_DISCOVERY bypass policy");
	}
	if (!netlink_bypass_policy(AF_INET6, IPPROTO_ICMPV6,
				   ICMP_NEIGHBOR_SOLICITATION,
				   logger)) {
		fatal(PLUTO_EXIT_KERNEL_FAIL, logger,
		      "kernel: could not insert ICMP_NEIGHBOUR_SOLICITATION bypass policy");
	}
}

static bool qry_xfrm_mirgrate_support(struct nlmsghdr *hdr, struct logger *logger)
{
	struct nlm_resp rsp;
	size_t len;
	ssize_t r;
	struct sockaddr_nl addr;
	int nl_fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_XFRM);

	if (nl_fd < 0) {
		log_errno(logger, errno,
			  "socket() in qry_xfrm_mirgrate_support()");
		return false;
	}

	if (fcntl(nl_fd, F_SETFL, O_NONBLOCK) != 0) {
		log_errno(logger, errno,
			  "fcntl(O_NONBLOCK in qry_xfrm_mirgrate_support()");
		close(nl_fd);

		return FALSE;
	}

	/* hdr->nlmsg_seq = ++seq; */
	len = hdr->nlmsg_len;
	do {
		r = write(nl_fd, hdr, len);
	} while (r < 0 && errno == EINTR);
	if (r < 0) {
		log_errno(logger, errno,
			  "netlink write() xfrm_migrate_support lookup");
		close(nl_fd);
		return FALSE;
	} else if ((size_t)r != len) {
		llog(RC_LOG_SERIOUS, logger,
			    "ERROR: netlink write() xfrm_migrate_support message truncated: %zd instead of %zu",
			    r, len);
		close(nl_fd);
		return FALSE;
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
				dbg("ignore EAGAIN in %s assume MOBIKE migration is supported", __func__);
				break;
			}
		}
		break;
	}

	close(nl_fd);

	if (rsp.n.nlmsg_type == NLMSG_ERROR && rsp.u.e.error == -ENOPROTOOPT) {
		dbg("MOBIKE will fail got ENOPROTOOPT");
		return FALSE;
	}

	return TRUE;
}

static err_t netlink_migrate_sa_check(struct logger *logger)
{
	if (kernel_mobike_supprt == 0) {
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

		bool ret = qry_xfrm_mirgrate_support(&req.n, logger);
		kernel_mobike_supprt = ret ? 1 : -1;
	}

	if (kernel_mobike_supprt > 0) {
		return NULL;
	} else {
		return "CONFIG_XFRM_MIGRATE";
	}
}

static bool netlink_poke_ipsec_policy_hole(const struct iface_dev *ifd, int fd, struct logger *logger)
{
	const struct ip_info *type = address_type(&ifd->id_address);
	struct xfrm_userpolicy_info policy = {
		.action = XFRM_POLICY_ALLOW,
		.sel = {
			.family = type->af,
		}
	};

	int opt, sol;

	if (type == &ipv6_info) {
		sol = IPPROTO_IPV6;
		opt = IPV6_XFRM_POLICY;
	} else {
		sol = SOL_IP;
		opt = IP_XFRM_POLICY;
	}

	policy.dir = XFRM_POLICY_IN;
	if (setsockopt(fd, sol, opt, &policy, sizeof(policy)) < 0) {
		log_errno(logger, errno,
			  "setsockopt IP_XFRM_POLICY XFRM_POLICY_IN in process_raw_ifaces()");
		return false;
	}

	policy.dir = XFRM_POLICY_OUT;
	if (setsockopt(fd, sol, opt, &policy, sizeof(policy)) < 0) {
		log_errno(logger, errno,
			  "setsockopt IP_XFRM_POLICY XFRM_POLICY_OUT in process_raw_ifaces()");
		return false;
	}

	return true;
}

const struct kernel_ops xfrm_kernel_ops = {
	.kern_name = "xfrm",
	.type = USE_XFRM,
	.async_fdp = &nl_xfrm_fd,
	.route_fdp = &nl_route_fd,
	.replay_window = IPSEC_SA_DEFAULT_REPLAY_WINDOW,

	.init = init_netlink,
#ifdef USE_XFRM_INTERFACE
	.shutdown = free_xfrmi_ipsec1,
#else
	.shutdown = NULL,
#endif
	.process_msg = netlink_process_msg,
	.raw_eroute = netlink_raw_eroute,
	.add_sa = netlink_add_sa,
	.del_sa = netlink_del_sa,
	.get_sa = netlink_get_sa,
	.process_queue = NULL,
	.grp_sa = NULL,
	.get_spi = netlink_get_spi,
	.exceptsocket = NULL,
	.process_raw_ifaces = netlink_process_raw_ifaces,
	.shunt_eroute = netlink_shunt_eroute,
	.sag_eroute = netlink_sag_eroute,
	.eroute_idle = netlink_eroute_idle,
	.migrate_sa_check = netlink_migrate_sa_check,
	.migrate_sa = netlink_migrate_sa,
	/*
	 * We should implement netlink_remove_orphaned_holds
	 * if netlink  specific changes are needed.
	 */
	.remove_orphaned_holds = NULL, /* only used for klips /proc scanner */
	.overlap_supported = FALSE,
	.sha2_truncbug_support = TRUE,
	.v6holes = netlink_v6holes,
	.poke_ipsec_policy_hole = netlink_poke_ipsec_policy_hole,
	.detect_offload = netlink_detect_offload,
};
