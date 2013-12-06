/* netlink interface to the kernel's IPsec mechanism
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
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2010 Mika Ilmaranta <ilmis@foobar.fi>
 * Copyright (C) 2010 Roman Hoog Antink <rha@open.ch>
 * Copyright (C) 2010 D. Hugh Redelmeier
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2013 Kim B. Heino <b@bbbs.net>
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

#if defined(linux) && defined(NETKEY_SUPPORT)

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdint.h>
#include <linux/pfkeyv2.h>
#include <unistd.h>

#include "kameipsec.h"
#include <rtnetlink.h>
#include <xfrm.h>

#include <libreswan.h>
#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>

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
#include "kernel_netlink.h"
#include "kernel_pfkey.h"
#include "log.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */
#include "kernel_alg.h"
#include "klips-crypto/aes_cbc.h"
#include "ike_alg.h"

/* required for Linux 2.6.26 kernel and later */
#ifndef XFRM_STATE_AF_UNSPEC
#define XFRM_STATE_AF_UNSPEC    32
#endif

#ifndef DEFAULT_UPDOWN
# define DEFAULT_UPDOWN "ipsec _updown"
#endif

static const struct pfkey_proto_info broad_proto_info[2] = {
	{
		.proto = IPPROTO_ESP,
		.encapsulation = ENCAPSULATION_MODE_TUNNEL,
		.reqid = 0
	},
	{
		.proto = 0,
		.encapsulation = 0,
		.reqid = 0
	}
};

/* Minimum priority number in SPD used by pluto. */
#define MIN_SPD_PRIORITY 1024

struct aead_alg {
	int id;
	int icvlen;
	const char *name;
};

static int netlinkfd = NULL_FD;
static int netlink_bcast_fd = NULL_FD;

#define NE(x) { x, #x } /* Name Entry -- shorthand for sparse_names */

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

#undef NE

/** Authentication Algs */
static sparse_names aalg_list = {
	{ SADB_X_AALG_NULL, "digest_null" },
	{ SADB_AALG_MD5HMAC, "md5" },
	{ SADB_AALG_SHA1HMAC, "sha1" },
	{ SADB_X_AALG_SHA2_256HMAC, "sha256" },
	{ SADB_X_AALG_SHA2_256HMAC_TRUNCBUG, "hmac(sha256)" },
	{ SADB_X_AALG_SHA2_384HMAC, "sha384" },
	{ SADB_X_AALG_SHA2_512HMAC, "sha512" },
	{ SADB_X_AALG_RIPEMD160HMAC, "ripemd160" },
	{ 0, sparse_end }
};

/** Encryption algs */
static sparse_names ealg_list = {
	{ SADB_EALG_NULL, "cipher_null" },
	/* { SADB_EALG_DESCBC, "des" }, obsoleted */
	{ SADB_EALG_3DESCBC, "des3_ede" },
	{ SADB_X_EALG_CASTCBC, "cast128" },
	/* { SADB_X_EALG_BLOWFISHCBC, "blowfish" }, obsoleted */
	{ SADB_X_EALG_AESCBC, "aes" },
	{ SADB_X_EALG_AESCTR, "ctr(aes)" },
	{ SADB_X_EALG_CAMELLIACBC, "cbc(camellia)" },
	{ SADB_X_EALG_SERPENTCBC, "serpent" }, /* 252 draft-ietf-ipsec-ciph-aes-cbc-00 */
	{ SADB_X_EALG_TWOFISHCBC, "twofish" }, /* 253 draft-ietf-ipsec-ciph-aes-cbc-00 */
	{ 0, sparse_end }
};

/** Compress Algs */
static sparse_names calg_list = {
	{ SADB_X_CALG_DEFLATE, "deflate" },
	{ SADB_X_CALG_LZS, "lzs" },
	{ SADB_X_CALG_LZJH, "lzjh" },
	{ 0, sparse_end }
};

static const struct aead_alg aead_algs[] =
{
	{ .id = SADB_X_EALG_AES_CCM_ICV8, .icvlen = 8, .name =
		  "rfc4309(ccm(aes))" },
	{ .id = SADB_X_EALG_AES_CCM_ICV12, .icvlen = 12, .name =
		  "rfc4309(ccm(aes))" },
	{ .id = SADB_X_EALG_AES_CCM_ICV16, .icvlen = 16, .name =
		  "rfc4309(ccm(aes))" },
	{ .id = SADB_X_EALG_AES_GCM_ICV8, .icvlen = 8, .name =
		  "rfc4106(gcm(aes))" },
	{ .id = SADB_X_EALG_AES_GCM_ICV12, .icvlen = 12, .name =
		  "rfc4106(gcm(aes))" },
	{ .id = SADB_X_EALG_AES_GCM_ICV16, .icvlen = 16, .name =
		  "rfc4106(gcm(aes))" },
};

static const struct aead_alg *get_aead_alg(int algid)
{
	unsigned int i;

	for (i = 0; i < sizeof(aead_algs) / sizeof(aead_algs[0]); i++)
		if (aead_algs[i].id == algid)
			return aead_algs + i;

	return NULL;
}

/** ip2xfrm - Take an IP address and convert to an xfrm.
 *
 * @param addr ip_address
 * @param xaddr xfrm_address_t - IPv[46] Address from addr is copied here.
 */
static void ip2xfrm(const ip_address *addr, xfrm_address_t *xaddr)
{
	/* If it's an IPv4 address */
	if (addr->u.v4.sin_family == AF_INET)
		xaddr->a4 = addr->u.v4.sin_addr.s_addr;
	else    /* Must be IPv6 */
		memcpy(xaddr->a6, &addr->u.v6.sin6_addr, sizeof(xaddr->a6));
}

/** init_netlink - Initialize the netlink inferface.  Opens the sockets and
 * then binds to the broadcast socket.
 */
static void init_netlink(void)
{
	struct sockaddr_nl addr;

	netlinkfd = safe_socket(AF_NETLINK, SOCK_DGRAM, NETLINK_XFRM);

	if (netlinkfd < 0)
		exit_log_errno((e, "socket() in init_netlink()"));

	if (fcntl(netlinkfd, F_SETFD, FD_CLOEXEC) != 0)
		exit_log_errno((e, "fcntl(FD_CLOEXEC) in init_netlink()"));

	netlink_bcast_fd = safe_socket(AF_NETLINK, SOCK_DGRAM, NETLINK_XFRM);

	if (netlink_bcast_fd < 0)
		exit_log_errno((e, "socket() for bcast in init_netlink()"));

	if (fcntl(netlink_bcast_fd, F_SETFD, FD_CLOEXEC) != 0)
		exit_log_errno((e,
				"fcntl(FD_CLOEXEC) for bcast in init_netlink()"));


	if (fcntl(netlink_bcast_fd, F_SETFL, O_NONBLOCK) != 0)
		exit_log_errno((e,
				"fcntl(O_NONBLOCK) for bcast in init_netlink()"));


	addr.nl_family = AF_NETLINK;
	addr.nl_pid = getpid();
	addr.nl_groups = XFRMGRP_ACQUIRE | XFRMGRP_EXPIRE;
	if (bind(netlink_bcast_fd, (struct sockaddr *)&addr,
		 sizeof(addr)) != 0)
		exit_log_errno((e,
				"Failed to bind bcast socket in init_netlink() - Perhaps kernel was not compiled with CONFIG_XFRM"));


	/*
	 * also open the pfkey socket, since we need it to get a list of
	 * algorithms.
	 * There is currently no netlink way to do this.
	 */
	init_pfkey();
}

/** send_netlink_msg
 *
 * @param hdr - Data to be sent.
 * @param rbuf - Return Buffer - contains data returned from the send.
 * @param rbuf_len - Length of rbuf
 * @param description - String - user friendly description of what is
 *                      being attempted.  Used for diagnostics
 * @param text_said - String
 * @return bool True if the message was succesfully sent.
 */
static bool send_netlink_msg(struct nlmsghdr *hdr, struct nlmsghdr *rbuf,
			     size_t rbuf_len,
			     const char *description, const char *text_said)
{
	struct {
		struct nlmsghdr n;
		struct nlmsgerr e;
		char data[1024];
	} rsp;
	size_t len;
	ssize_t r;
	struct sockaddr_nl addr;
	static uint32_t seq;

	if (kern_interface == NO_KERNEL)
		return TRUE;

	hdr->nlmsg_seq = ++seq;
	len = hdr->nlmsg_len;
	do
		r = write(netlinkfd, hdr, len);
	while (r < 0 && errno == EINTR);
	if (r < 0) {
		log_errno((e,
			   "netlink write() of %s message"
			   " for %s %s failed",
			   sparse_val_show(xfrm_type_names, hdr->nlmsg_type),
			   description, text_said));
		return FALSE;
	} else if ((size_t)r != len) {
		loglog(RC_LOG_SERIOUS,
		       "ERROR: netlink write() of %s message"
		       " for %s %s truncated: %ld instead of %lu",
		       sparse_val_show(xfrm_type_names, hdr->nlmsg_type),
		       description, text_said,
		       (long)r, (unsigned long)len);
		return FALSE;
	}

	for (;; ) {
		socklen_t alen;

		alen = sizeof(addr);
		r = recvfrom(netlinkfd, &rsp, sizeof(rsp), 0,
			     (struct sockaddr *)&addr, &alen);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			log_errno((e,
				   "netlink recvfrom() of response to our %s message"
				   " for %s %s failed",
				   sparse_val_show(xfrm_type_names,
						   hdr->nlmsg_type),
				   description, text_said));
			return FALSE;
		} else if ((size_t) r < sizeof(rsp.n)) {
			libreswan_log(
				"netlink read truncated message: %ld bytes; ignore message",
				(long) r);
			continue;
		} else if (addr.nl_pid != 0) {
			/* not for us: ignore */
			DBG(DBG_KERNEL,
			    DBG_log(
				    "netlink: ignoring %s message from process %u",
				    sparse_val_show(xfrm_type_names,
						    rsp.n.nlmsg_type),
				    addr.nl_pid));
			continue;
		} else if (rsp.n.nlmsg_seq != seq) {
			DBG(DBG_KERNEL,
			    DBG_log(
				    "netlink: ignoring out of sequence (%u/%u) message %s",
				    rsp.n.nlmsg_seq, seq,
				    sparse_val_show(xfrm_type_names,
						    rsp.n.nlmsg_type)));
			continue;
		}
		break;
	}

	if (rsp.n.nlmsg_len > (size_t) r) {
		loglog(RC_LOG_SERIOUS,
		       "netlink recvfrom() of response to our %s message"
		       " for %s %s was truncated: %ld instead of %lu",
		       sparse_val_show(xfrm_type_names, hdr->nlmsg_type),
		       description, text_said,
		       (long) len, (unsigned long) rsp.n.nlmsg_len);
		return FALSE;
	} else if (rsp.n.nlmsg_type != NLMSG_ERROR   &&
		   (rbuf && rsp.n.nlmsg_type != rbuf->nlmsg_type)) {
		loglog(RC_LOG_SERIOUS,
		       "netlink recvfrom() of response to our %s message"
		       " for %s %s was of wrong type (%s)",
		       sparse_val_show(xfrm_type_names, hdr->nlmsg_type),
		       description, text_said,
		       sparse_val_show(xfrm_type_names, rsp.n.nlmsg_type));
		return FALSE;
	} else if (rbuf) {
		if ((size_t) r > rbuf_len) {
			loglog(RC_LOG_SERIOUS,
			       "netlink recvfrom() of response to our %s message"
			       " for %s %s was too long: %ld > %lu",
			       sparse_val_show(xfrm_type_names,
					       hdr->nlmsg_type),
			       description, text_said,
			       (long)r, (unsigned long)rbuf_len);
			return FALSE;
		}
		memcpy(rbuf, &rsp, r);
		return TRUE;
	} else if (rsp.n.nlmsg_type == NLMSG_ERROR && rsp.e.error) {
		loglog(RC_LOG_SERIOUS,
		       "ERROR: netlink response for %s %s included errno %d: %s",
		       description, text_said,
		       -rsp.e.error,
		       strerror(-rsp.e.error));
		errno = -rsp.e.error;
		return FALSE;
	}

	return TRUE;
}

/** netlink_policy -
 *
 * @param hdr - Data to check
 * @param enoent_ok - Boolean - OK or not OK.
 * @param text_said - String
 * @return boolean
 */
static bool netlink_policy(struct nlmsghdr *hdr, bool enoent_ok,
			   const char *text_said)
{
	struct {
		struct nlmsghdr n;
		struct nlmsgerr e;
		char data[1024];
	} rsp;
	int error;

	rsp.n.nlmsg_type = NLMSG_ERROR;
	if (!send_netlink_msg(hdr, &rsp.n, sizeof(rsp), "policy", text_said))
		return FALSE;

	error = -rsp.e.error;
	if (!error)
		return TRUE;

	if (error == ENOENT && enoent_ok)
		return TRUE;

	loglog(RC_LOG_SERIOUS,
	       "ERROR: netlink %s response for flow %s included errno %d: %s",
	       sparse_val_show(xfrm_type_names, hdr->nlmsg_type),
	       text_said,
	       error,
	       strerror(error));
	return FALSE;
}

/** netlink_raw_eroute
 *
 * @param this_host ip_address
 * @param this_client ip_subnet
 * @param that_host ip_address
 * @param that_client ip_subnet
 * @param spi
 * @param proto int (4=tunnel, 50=esp, 108=ipcomp, etc ...)
 * @param transport_proto int (Currently unused) Contains protocol (u=tcp, 17=udp, etc...)
 * @param esatype int
 * @param pfkey_proto_info proto_info
 * @param use_lifetime time_t (Currently unused)
 * @param pluto_sadb_opterations sadb_op (operation - ie: ERO_DELETE)
 * @param text_said char
 * @return boolean True if successful
 */
static bool netlink_raw_eroute(const ip_address *this_host,
			       const ip_subnet *this_client,
			       const ip_address *that_host,
			       const ip_subnet *that_client,
			       ipsec_spi_t spi,
			       unsigned int proto,
			       unsigned int transport_proto,
			       enum eroute_type esatype,
			       const struct pfkey_proto_info *proto_info,
			       time_t use_lifetime UNUSED,
			       unsigned long sa_priority,
			       enum pluto_sadb_operations sadb_op,
			       const char *text_said
#ifdef HAVE_LABELED_IPSEC
			       , char *policy_label
#endif
			       )
{
	struct {
		struct nlmsghdr n;
		union {
			struct xfrm_userpolicy_info p;
			struct xfrm_userpolicy_id id;
		} u;
		char data[1024];
	} req;
	int shift;
	int dir;
	int family;
	int policy;
	bool ok;
	bool enoent_ok;
	ip_subnet local_client;
	int satype = 0;

	policy = IPSEC_POLICY_IPSEC;

	switch (esatype) {
	case ET_UNSPEC:
		satype = SADB_SATYPE_UNSPEC;
		break;

	case ET_AH:
		satype = SADB_SATYPE_AH;
		break;

	case ET_ESP:
		satype = SADB_SATYPE_ESP;
		break;

	case ET_IPCOMP:
		satype = SADB_X_SATYPE_IPCOMP;
		break;

	case ET_IPIP:
		satype = K_SADB_X_SATYPE_IPIP;
		break;

	case ET_INT:
		/* shunt route */
		switch (ntohl(spi)) {
		case SPI_PASS:
			policy = IPSEC_POLICY_NONE;
			break;
		case SPI_DROP:
		case SPI_REJECT:
		default:
			policy = IPSEC_POLICY_DISCARD;
			break;
		case SPI_TRAP:
		case SPI_TRAPSUBNET:
			if (sadb_op == ERO_ADD_INBOUND || sadb_op ==
			    ERO_DEL_INBOUND)
				return TRUE;

			break;
		/* Do we really need %hold under NETKEY? Seems not so we just ignore. */
		case SPI_HOLD:
			return TRUE;
		}
		break;
	}
	if (satype != 0) {
		DBG(DBG_KERNEL,
		    DBG_log("satype(%d) is not used in netlink_raw_eroute.",
			    satype));
	}

	if (sadb_op == ERO_ADD_INBOUND || sadb_op == ERO_DEL_INBOUND)
		dir = XFRM_POLICY_IN;
	else
		dir = XFRM_POLICY_OUT;

	/* Bug #1004 fix.
	 * There really isn't "client" with NETKEY and transport mode
	 * so eroute must be done to natted, visible ip. If we don't hide
	 * internal IP, communication doesn't work.
	 */
	if (esatype == ET_ESP || esatype == ET_IPCOMP || proto == SA_ESP) {
		/*
		 * Variable "that" should be remote, but here it's not.
		 * We must check "dir" to find out remote address.
		 */
		int local_port;

		if (dir == XFRM_POLICY_OUT) {
			local_port = portof(&that_client->addr);
			addrtosubnet(that_host, &local_client);
			that_client = &local_client;
		} else {
			local_port = portof(&this_client->addr);
			addrtosubnet(this_host, &local_client);
			this_client = &local_client;
		}
		setportof(local_port, &local_client.addr);
		DBG(DBG_KERNEL,
		    DBG_log("%s: using host address instead of client subnet",
			    __func__));
	}

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	family = that_client->addr.u.v4.sin_family;
	shift = (family == AF_INET) ? 5 : 7;

	req.u.p.sel.sport = portof(&this_client->addr);
	req.u.p.sel.dport = portof(&that_client->addr);

	/* As per RFC 4301/5996, icmp type is put in the most significant 8 bits
	 * and icmp code is in the least significant 8 bits of port field.
	 * Although Libreswan does not have any configuration options for
	 * icmp type/code values, it is possible to specify icmp type and code
	 * using protoport option. For example, icmp echo request (type 8/code 0)
	 * needs to be encoded as 0x0800 in the port field and can be specified
	 * as left/rightprotoport=icmp/2048. Now with NETKEY, icmp type and code
	 * need to be passed as source and destination ports, respectively.
	 * therefore, this code extracts upper 8 bits and lower 8 bits and puts
	 * into source and destination ports before passing to NETKEY. */

	if ( transport_proto == IPPROTO_ICMP || transport_proto ==
	     IPPROTO_ICMPV6) {
		u_int16_t icmp_type;
		u_int16_t icmp_code;

		icmp_type = ntohs(req.u.p.sel.sport) >> 8;
		icmp_code = ntohs(req.u.p.sel.sport) & 0xFF;

		req.u.p.sel.sport = htons(icmp_type);
		req.u.p.sel.dport = htons(icmp_code);

	}

	req.u.p.sel.sport_mask = (req.u.p.sel.sport) ? ~0 : 0;
	req.u.p.sel.dport_mask = (req.u.p.sel.dport) ? ~0 : 0;
	ip2xfrm(&this_client->addr, &req.u.p.sel.saddr);
	ip2xfrm(&that_client->addr, &req.u.p.sel.daddr);
	req.u.p.sel.prefixlen_s = this_client->maskbits;
	req.u.p.sel.prefixlen_d = that_client->maskbits;
	req.u.p.sel.proto = transport_proto;
	req.u.p.sel.family = family;

	if (sadb_op == ERO_DELETE || sadb_op == ERO_DEL_INBOUND) {
		req.u.id.dir = dir;
		req.n.nlmsg_type = XFRM_MSG_DELPOLICY;
		req.n.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req.u.id)));
	} else {
		int src, dst;

		req.u.p.dir = dir;

		src = req.u.p.sel.prefixlen_s;
		dst = req.u.p.sel.prefixlen_d;
		if (dir != XFRM_POLICY_OUT) {
			src = req.u.p.sel.prefixlen_d;
			dst = req.u.p.sel.prefixlen_s;
		}

		/*
		 * if the user did not specify a priority, calculate one based
		 * on 'more specific' getting a higher priority
		 */
		if (sa_priority) {
			req.u.p.priority = sa_priority;
		} else {
			req.u.p.priority = MIN_SPD_PRIORITY -
				((policy == IPSEC_POLICY_NONE) ? 512 : 0) +
				   (((2 << shift) - src) << shift) +
				    (2 << shift) - dst - ((transport_proto) ? 64 : 0)
				 	- ((req.u.p.sel.sport) ? 32 : 0 )
				 	- ((req.u.p.sel.sport) ? 32 : 0 );
		}

		req.u.p.action = XFRM_POLICY_ALLOW;
		if (policy == IPSEC_POLICY_DISCARD)
			req.u.p.action = XFRM_POLICY_BLOCK;
		req.u.p.lft.soft_use_expires_seconds = use_lifetime;
		req.u.p.lft.soft_byte_limit = XFRM_INF;
		req.u.p.lft.soft_packet_limit = XFRM_INF;
		req.u.p.lft.hard_byte_limit = XFRM_INF;
		req.u.p.lft.hard_packet_limit = XFRM_INF;

		/*
		 * NEW will fail when an existing policy, UPD always works.
		 * This seems to happen in cases with NAT'ed XP clients, or
		 * quick recycling/resurfacing of roadwarriors on the same IP.
		 *
		 * UPD is also needed for two separate tunnels with same end subnets
		 * Like A = B = C config where both A - B and B - C have tunnel A = C
		 * configured.
		 */
		req.n.nlmsg_type = XFRM_MSG_UPDPOLICY;
		if (sadb_op == ERO_REPLACE)
			req.n.nlmsg_type = XFRM_MSG_UPDPOLICY;
		req.n.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req.u.p)));
	}

	if (policy == IPSEC_POLICY_IPSEC && sadb_op != ERO_DELETE) {
		struct rtattr *attr;
		struct xfrm_user_tmpl tmpl[4];
		int i;

		memset(tmpl, 0, sizeof(tmpl));
		for (i = 0; proto_info[i].proto; i++) {
			tmpl[i].reqid = proto_info[i].reqid;
			tmpl[i].id.proto = proto_info[i].proto;
			tmpl[i].optional =
				proto_info[i].proto == IPPROTO_COMP && dir !=
				XFRM_POLICY_OUT;
			tmpl[i].aalgos = tmpl[i].ealgos = tmpl[i].calgos = ~0;
			tmpl[i].family = that_host->u.v4.sin_family;
			tmpl[i].mode =
				proto_info[i].encapsulation ==
				ENCAPSULATION_MODE_TUNNEL;

			if (!tmpl[i].mode)
				continue;

			ip2xfrm(this_host, &tmpl[i].saddr);
			ip2xfrm(that_host, &tmpl[i].id.daddr);
		}

		attr = (struct rtattr *)((char *)&req + req.n.nlmsg_len);
		attr->rta_type = XFRMA_TMPL;
		attr->rta_len = i * sizeof(tmpl[0]);
		memcpy(RTA_DATA(attr), tmpl, attr->rta_len);
		attr->rta_len = RTA_LENGTH(attr->rta_len);
		req.n.nlmsg_len += attr->rta_len;
	}

#ifdef HAVE_LABELED_IPSEC
	{
		if (policy_label) {
			struct rtattr *attr;
			struct xfrm_user_sec_ctx *uctx;
			attr =
				(struct rtattr *)((char *)&req +
						  req.n.nlmsg_len);
			attr->rta_type = XFRMA_SEC_CTX;
			/* Passing null terminated sec label (strlen + '\0') */
			DBG_log("passing security label %s (len=%zu +1) to kernel",
				policy_label, strlen(policy_label));
			attr->rta_len =
				RTA_LENGTH(sizeof(struct xfrm_user_sec_ctx) +
					   strlen(policy_label) + 1);
			uctx = RTA_DATA(attr);
			uctx->exttype = XFRMA_SEC_CTX;
			uctx->len = sizeof(struct xfrm_user_sec_ctx) + strlen(
				policy_label) + 1;
			uctx->ctx_doi = 1;
			uctx->ctx_alg = 1;
			uctx->ctx_len = strlen(policy_label) + 1;
			memcpy(uctx + 1, policy_label, uctx->ctx_len);
			req.n.nlmsg_len += attr->rta_len;
		}
	}
#endif

	enoent_ok = FALSE;
	if (sadb_op == ERO_DEL_INBOUND)
		enoent_ok = TRUE;
	else if (sadb_op == ERO_DELETE && ntohl(spi) == SPI_HOLD)
		enoent_ok = TRUE;

	ok = netlink_policy(&req.n, enoent_ok, text_said);
	switch (dir) {
	case XFRM_POLICY_IN:
		if (req.n.nlmsg_type == XFRM_MSG_DELPOLICY)
			req.u.id.dir = XFRM_POLICY_FWD;
		else if (!ok)
			break;
		else if (proto_info[0].encapsulation !=
			 ENCAPSULATION_MODE_TUNNEL &&
			 esatype != ET_INT)
			break;
		else
			req.u.p.dir = XFRM_POLICY_FWD;
		ok &= netlink_policy(&req.n, enoent_ok, text_said);
		break;
	}

	return ok;
}

/** netlink_add_sa - Add an SA into the kernel SPDB via netlink
 *
 * @param sa Kernel SA to add/modify
 * @param replace boolean - true if this replaces an existing SA
 * @return bool True if successfull
 */
static bool netlink_add_sa(struct kernel_sa *sa, bool replace)
{
	struct {
		struct nlmsghdr n;
		struct xfrm_usersa_info p;
		char data[1024];
	} req;
	struct rtattr *attr;
	const struct aead_alg *aead;
	int ret;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.n.nlmsg_type = replace ? XFRM_MSG_UPDSA : XFRM_MSG_NEWSA;

	ip2xfrm(sa->src, &req.p.saddr);
	ip2xfrm(sa->dst, &req.p.id.daddr);

	req.p.id.spi = sa->spi;
	req.p.id.proto = esatype2proto(sa->esatype);
	req.p.family = sa->src->u.v4.sin_family;
	/*
	 * This requires ipv6 modules. It is required to support 6in4 and 4in6
	 * tunnels in linux 2.6.25+
	 */
	if (sa->encapsulation == ENCAPSULATION_MODE_TUNNEL) {
		req.p.mode = XFRM_MODE_TUNNEL;
		req.p.flags |= XFRM_STATE_AF_UNSPEC;
	} else {
		req.p.mode = XFRM_MODE_TRANSPORT;
	}

	/* We only add traffic selectors for transport mode. The problem is that
	 * Tunnel mode ipsec with ipcomp is layered so that ipcomp tunnel is
	 * protected with transport mode ipsec but in this case we shouldn't any
	 * more add traffic selectors. Caller function will inform us if we
	 * need or don't need selectors. */
	if (sa->add_selector) {
		ip_subnet src_tmp;
		ip_subnet dst_tmp;
		const ip_subnet *src;
		const ip_subnet *dst;

		/* With XFRM/NETKEY and transport mode with nat-traversal we need
		 * to change outbound IPsec SA to point to exteral ip of the peer.
		 * Here we substitute real client ip with NATD ip. */
		if (sa->inbound == 0) {
			addrtosubnet(sa->dst, &dst_tmp);
			dst = &dst_tmp;
		} else {
			dst = sa->dst_client;
		}

		if (sa->inbound == 1) {
			addrtosubnet(sa->src, &src_tmp);
			src = &src_tmp;
		} else {
			src = sa->src_client;
		}

		req.p.sel.sport = portof(&sa->src_client->addr);
		req.p.sel.dport = portof(&sa->dst_client->addr);

		/* As per RFC 4301/5996, icmp type is put in the most significant 8 bits
		 * and icmp code is in the least significant 8 bits of port field.
		 * Although Openswan does not have any configuration options for
		 * icmp type/code values, it is possible to specify icmp type and code
		 * using protoport option. For example, icmp echo request (type 8/code 0)
		 * needs to be encoded as 0x0800 in the port field and can be specified
		 * as left/rightprotoport=icmp/2048. Now with NETKEY, icmp type and code
		 * need to be passed as source and destination ports, respectively.
		 * therefore, this code extracts upper 8 bits and lower 8 bits and puts
		 * into source and destination ports before passing to NETKEY. */

		if ( 1 == sa->transport_proto /*icmp*/ || 58 ==
		     sa->transport_proto /*ipv6-icmp*/) {

			u_int16_t icmp_type;
			u_int16_t icmp_code;

			icmp_type = ntohs(req.p.sel.sport) >> 8;
			icmp_code = ntohs(req.p.sel.sport) & 0xFF;

			req.p.sel.sport = htons(icmp_type);
			req.p.sel.dport = htons(icmp_code);

		}

		req.p.sel.sport_mask = (req.p.sel.sport) ? ~0 : 0;
		req.p.sel.dport_mask = (req.p.sel.dport) ? ~0 : 0;
		ip2xfrm(&src->addr, &req.p.sel.saddr);
		ip2xfrm(&dst->addr, &req.p.sel.daddr);
		req.p.sel.prefixlen_s = src->maskbits;
		req.p.sel.prefixlen_d = dst->maskbits;
		req.p.sel.proto = sa->transport_proto;
		req.p.sel.family = src->addr.u.v4.sin_family;

	}

	req.p.replay_window = sa->replay_window > 32 ? 32 : sa->replay_window;
	req.p.reqid = sa->reqid;
	/* TODO expose limits to kernel_sa via config */
	req.p.lft.soft_byte_limit = XFRM_INF;
	req.p.lft.soft_packet_limit = XFRM_INF;
	req.p.lft.hard_byte_limit = XFRM_INF;
	req.p.lft.hard_packet_limit = XFRM_INF;

	req.n.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req.p)));

	attr = (struct rtattr *)((char *)&req + req.n.nlmsg_len);

	if (sa->authkeylen) {
		const char *name;

		name = sparse_name(aalg_list, sa->authalg);
		if (!name) {
			loglog(RC_LOG_SERIOUS,
			       "unknown authentication algorithm: %u",
			       sa->authalg);
			return FALSE;
		}

		/*
		 * According to RFC-4868 the hash should be nnn/2, so 128 bits for SHA256 and 256
		 * for SHA512. The XFRM/NETKEY kernel uses a default of 96, which was the value in
		 * an earlier draft. The kernel then introduced a new struct xfrm_algo_auth to
		 * replace struct xfrm_algo to deal with this
		 */
		if ( (sa->authalg == AUTH_ALGORITHM_HMAC_SHA2_256) ||
		     (sa->authalg == AUTH_ALGORITHM_HMAC_SHA2_256_TRUNCBUG) ) {
			struct xfrm_algo_auth algo;
			    loglog(RC_LOG_SERIOUS,
				    "  using new struct xfrm_algo_auth for XFRM message with explicit truncation for sha2_256");
			algo.alg_key_len = sa->authkeylen * BITS_PER_BYTE;
			algo.alg_trunc_len =
				(sa->authalg ==
				 AUTH_ALGORITHM_HMAC_SHA2_256_TRUNCBUG) ? 96 :
				128;
			attr->rta_type = XFRMA_ALG_AUTH_TRUNC;
			attr->rta_len = RTA_LENGTH(
				sizeof(algo) + sa->authkeylen);
			sa->authalg = AUTH_ALGORITHM_HMAC_SHA2_256; /* fixup to the real number, not our private number */

			strcpy(algo.alg_name, name);
			memcpy(RTA_DATA(attr), &algo, sizeof(algo));
			memcpy((char *)RTA_DATA(
				       attr) + sizeof(algo), sa->authkey,
			       sa->authkeylen);

			req.n.nlmsg_len += attr->rta_len;
			attr = (struct rtattr *)((char *)attr + attr->rta_len);
		} else {
			struct xfrm_algo algo;
			    loglog(RC_LOG_SERIOUS,
				    "  using old struct xfrm_algo for XFRM message");
			algo.alg_key_len = sa->authkeylen * BITS_PER_BYTE;
			attr->rta_type = XFRMA_ALG_AUTH;
			attr->rta_len = RTA_LENGTH(
				sizeof(algo) + sa->authkeylen);
			strcpy(algo.alg_name, name);
			memcpy(RTA_DATA(attr), &algo, sizeof(algo));
			memcpy((char *)RTA_DATA(
				       attr) + sizeof(algo), sa->authkey,
			       sa->authkeylen);

			req.n.nlmsg_len += attr->rta_len;
			attr = (struct rtattr *)((char *)attr + attr->rta_len);
		}
	}

	aead = get_aead_alg(sa->encalg);
	if (sa->esatype == ET_IPCOMP) {
		struct xfrm_algo algo;
		const char *name;

		name = sparse_name(calg_list, sa->encalg);
		if (!name) {
			loglog(RC_LOG_SERIOUS,
			       "unknown compression algorithm: %u",
			       sa->encalg);
			return FALSE;
		}

		strcpy(algo.alg_name, name);
		algo.alg_key_len = 0;

		attr->rta_type = XFRMA_ALG_COMP;
		attr->rta_len = RTA_LENGTH(sizeof(algo));

		memcpy(RTA_DATA(attr), &algo, sizeof(algo));

		req.n.nlmsg_len += attr->rta_len;
		attr = (struct rtattr *)((char *)attr + attr->rta_len);
	} else if (aead) {
		struct xfrm_algo_aead algo;

		strcpy(algo.alg_name, aead->name);
		algo.alg_key_len = sa->enckeylen * BITS_PER_BYTE;
		algo.alg_icv_len = aead->icvlen * BITS_PER_BYTE;

		attr->rta_type = XFRMA_ALG_AEAD;
		attr->rta_len = RTA_LENGTH(sizeof(algo) + sa->enckeylen);

		memcpy(RTA_DATA(attr), &algo, sizeof(algo));
		memcpy((char *)RTA_DATA(attr) + sizeof(algo), sa->enckey,
		       sa->enckeylen);

		req.n.nlmsg_len += attr->rta_len;
		attr = (struct rtattr *)((char *)attr + attr->rta_len);
	} else if (sa->esatype == ET_ESP) {
		struct xfrm_algo algo;
		const char *name;

		name = sparse_name(ealg_list, sa->encalg);
		if (!name) {
			loglog(RC_LOG_SERIOUS,
			       "unknown encryption algorithm: %u",
			       sa->encalg);
			return FALSE;
		}

		strcpy(algo.alg_name, name);
		algo.alg_key_len = sa->enckeylen * BITS_PER_BYTE;

		attr->rta_type = XFRMA_ALG_CRYPT;
		attr->rta_len = RTA_LENGTH(sizeof(algo) + sa->enckeylen);

		memcpy(RTA_DATA(attr), &algo, sizeof(algo));
		memcpy((char *)RTA_DATA(attr) + sizeof(algo), sa->enckey,
		       sa->enckeylen);

		req.n.nlmsg_len += attr->rta_len;
		attr = (struct rtattr *)((char *)attr + attr->rta_len);
	}

	if (sa->natt_type) {
		struct xfrm_encap_tmpl natt;

		natt.encap_type = sa->natt_type;
		natt.encap_sport = ntohs(sa->natt_sport);
		natt.encap_dport = ntohs(sa->natt_dport);
		memset(&natt.encap_oa, 0, sizeof(natt.encap_oa));

		attr->rta_type = XFRMA_ENCAP;
		attr->rta_len = RTA_LENGTH(sizeof(natt));

		memcpy(RTA_DATA(attr), &natt, sizeof(natt));

		req.n.nlmsg_len += attr->rta_len;
		attr = (struct rtattr *)((char *)attr + attr->rta_len);
	}

#ifdef HAVE_LABELED_IPSEC
	if (sa->sec_ctx != NULL) {
		struct xfrm_user_sec_ctx xuctx;

		xuctx.len = sizeof(struct xfrm_user_sec_ctx) +
			    sa->sec_ctx->ctx_len;
		xuctx.exttype = XFRMA_SEC_CTX;
		xuctx.ctx_alg = 1;
		xuctx.ctx_doi = 1;
		xuctx.ctx_len = sa->sec_ctx->ctx_len;

		attr->rta_type = XFRMA_SEC_CTX;
		attr->rta_len = RTA_LENGTH(xuctx.len);

		memcpy(RTA_DATA(attr), &xuctx, sizeof(xuctx));
		memcpy((char *)RTA_DATA(
			       attr) + sizeof(xuctx), sa->sec_ctx->sec_ctx_value,
		       sa->sec_ctx->ctx_len);

		req.n.nlmsg_len += attr->rta_len;
		attr = (struct rtattr *)((char *)attr + attr->rta_len);
	}
#endif
	ret = send_netlink_msg(&req.n, NULL, 0, "Add SA", sa->text_said);
	if (ret == FALSE && errno == ESRCH &&
	    req.n.nlmsg_type == XFRM_MSG_UPDSA) {
			loglog(RC_LOG_SERIOUS, "Warning: expected to find "
			       "an existing IPsec SA - continuing as Add SA");
		return netlink_add_sa(sa, 0);
	}
	return ret;
}

/** netlink_del_sa - Delete an SA from the Kernel
 *
 * @param sa Kernel SA to be deleted
 * @return bool True if successfull
 */
static bool netlink_del_sa(const struct kernel_sa *sa)
{
	struct {
		struct nlmsghdr n;
		struct xfrm_usersa_id id;
		char data[1024];
	} req;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.n.nlmsg_type = XFRM_MSG_DELSA;

	ip2xfrm(sa->dst, &req.id.daddr);

	req.id.spi = sa->spi;
	req.id.family = sa->src->u.v4.sin_family;
	req.id.proto = sa->proto;

	req.n.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req.id)));

	return send_netlink_msg(&req.n, NULL, 0, "Del SA", sa->text_said);
}

static struct encrypt_desc algo_aes_ccm_8 =
{
	.common = {
		.name = "aes_ccm_8",
		.officname = "aes_ccm_8",
		.algo_type =    IKE_ALG_ENCRYPT,
		.algo_v2id =    IKEv2_ENCR_AES_CCM_8,
		.algo_next =    NULL,
	},
	.enc_blocksize =  AES_CBC_BLOCK_SIZE,
	/* Only 128, 192 and 256 are supported (plus 32 bits for salt) */
	.keyminlen =      AEAD_AES_KEY_MIN_LEN + 3, /* What's 3? */
	.keydeflen =      AEAD_AES_KEY_DEF_LEN + 3,
	.keymaxlen =      AEAD_AES_KEY_MAX_LEN + 3,
};

static struct encrypt_desc algo_aes_ccm_12 =
{
	.common = {
		.name = "aes_ccm_12",
		.officname = "aes_ccm_12",
		.algo_type =    IKE_ALG_ENCRYPT,
		.algo_v2id =    IKEv2_ENCR_AES_CCM_12,
		.algo_next =    NULL,
	},
	.enc_blocksize =  AES_CBC_BLOCK_SIZE,
	/* Only 128, 192 and 256 are supported (plus 32 bits for salt) */
	.keyminlen =      AEAD_AES_KEY_MIN_LEN + 3, /* What's 3? */
	.keydeflen =      AEAD_AES_KEY_DEF_LEN + 3,
	.keymaxlen =      AEAD_AES_KEY_MAX_LEN + 3,
};

static struct encrypt_desc algo_aes_ccm_16 =
{
	.common = {
		.name = "aes_ccm_16",
		.officname = "aes_ccm_16",
		.algo_type =   IKE_ALG_ENCRYPT,
		.algo_v2id =   IKEv2_ENCR_AES_CCM_16,
		.algo_next =   NULL,
	},
	.enc_blocksize = AES_CBC_BLOCK_SIZE,
	/* Only 128, 192 and 256 are supported (plus 32 bits for salt) */
	.keyminlen =     AEAD_AES_KEY_MIN_LEN + 3,
	.keydeflen =     AEAD_AES_KEY_DEF_LEN + 3,
	.keymaxlen =     AEAD_AES_KEY_MAX_LEN + 3,
};

static struct encrypt_desc algo_aes_gcm_8 =
{
	.common = {
		.name = "aes_gcm_8",
		.officname = "aes_gcm_8",
		.algo_type =   IKE_ALG_ENCRYPT,
		.algo_v2id =   IKEv2_ENCR_AES_GCM_8,
		.algo_next =   NULL,
	},
	.enc_blocksize = AES_CBC_BLOCK_SIZE,
	/* Only 128, 192 and 256 are supported (plus 32 bits for salt) */
	.keyminlen =     AEAD_AES_KEY_MIN_LEN + 3,
	.keydeflen =     AEAD_AES_KEY_DEF_LEN + 3,
	.keymaxlen =     AEAD_AES_KEY_MAX_LEN + 3,
};

static struct encrypt_desc algo_aes_gcm_12 =
{
	.common = {
		.name = "aes_gcm_12",
		.officname = "aes_gcm_12",
		.algo_type =   IKE_ALG_ENCRYPT,
		.algo_v2id =   IKEv2_ENCR_AES_GCM_12,
		.algo_next =   NULL,
	},
	.enc_blocksize = AES_CBC_BLOCK_SIZE,
	/* Only 128, 192 and 256 are supported (plus 32 bits for salt) */
	.keyminlen =     AEAD_AES_KEY_MIN_LEN + 3,
	.keydeflen =     AEAD_AES_KEY_DEF_LEN + 3,
	.keymaxlen =     AEAD_AES_KEY_MAX_LEN + 3,
};

static struct encrypt_desc algo_aes_gcm_16 =
{
	.common = {
		.name = "aes_gcm_16",
		.officname = "aes_gcm_16",
		.algo_type =  IKE_ALG_ENCRYPT,
		.algo_v2id =    IKEv2_ENCR_AES_GCM_16,
		.algo_next =  NULL,
	},
	.enc_blocksize = AES_CBC_BLOCK_SIZE,
	/* Only 128, 192 and 256 are supported (plus 32 bits for salt) */
	.keyminlen =    AEAD_AES_KEY_MIN_LEN + 3,
	.keydeflen =    AEAD_AES_KEY_DEF_LEN + 3,
	.keymaxlen =    AEAD_AES_KEY_MAX_LEN + 3,
};

static void linux_pfkey_add_aead(void)
{
	struct sadb_alg alg;

	alg.sadb_alg_reserved = 0;

	alg.sadb_alg_ivlen = 8;
	alg.sadb_alg_minbits = 128;
	alg.sadb_alg_maxbits = 256;

	alg.sadb_alg_id = SADB_X_EALG_AES_GCM_ICV8;
	if (kernel_alg_add(SADB_SATYPE_ESP, SADB_EXT_SUPPORTED_ENCRYPT, &alg) != 1)
		loglog(RC_LOG_SERIOUS, "Warning: failed to register algo_aes_gcm_8 for ESP");

	alg.sadb_alg_ivlen = 12;
	alg.sadb_alg_minbits = 128;
	alg.sadb_alg_maxbits = 256;

	alg.sadb_alg_id = SADB_X_EALG_AES_GCM_ICV12;
	if (kernel_alg_add(SADB_SATYPE_ESP, SADB_EXT_SUPPORTED_ENCRYPT, &alg) != 1)
		loglog(RC_LOG_SERIOUS, "Warning: failed to register algo_aes_gcm_12 for ESP");

	alg.sadb_alg_ivlen = 16;
	alg.sadb_alg_minbits = 128;
	alg.sadb_alg_maxbits = 256;

	alg.sadb_alg_id = SADB_X_EALG_AES_GCM_ICV16;
	if (kernel_alg_add(SADB_SATYPE_ESP, SADB_EXT_SUPPORTED_ENCRYPT, &alg) != 1)
		loglog(RC_LOG_SERIOUS, "Warning: failed to register algo_aes_gcm_16 for ESP");

	/* keeping aes-ccm behaviour intact as before */
	alg.sadb_alg_ivlen = 8;
	alg.sadb_alg_minbits = 128;
	alg.sadb_alg_maxbits = 256;

	alg.sadb_alg_id = SADB_X_EALG_AES_CCM_ICV8;
	if (kernel_alg_add(SADB_SATYPE_ESP, SADB_EXT_SUPPORTED_ENCRYPT, &alg) != 1)
		loglog(RC_LOG_SERIOUS, "Warning: failed to register algo_aes_ccm_8 for ESP");
	alg.sadb_alg_id = SADB_X_EALG_AES_CCM_ICV12;
	if (kernel_alg_add(SADB_SATYPE_ESP, SADB_EXT_SUPPORTED_ENCRYPT, &alg) != 1)
		loglog(RC_LOG_SERIOUS, "Warning: failed to register algo_aes_ccm_12 for ESP");
	alg.sadb_alg_id = SADB_X_EALG_AES_CCM_ICV16;
	if (kernel_alg_add(SADB_SATYPE_ESP, SADB_EXT_SUPPORTED_ENCRYPT, &alg) != 1)
		loglog(RC_LOG_SERIOUS, "Warning: failed to register algo_aes_ccm_16 for ESP");

	if(!ike_alg_register_enc(&algo_aes_ccm_8))
		loglog(RC_LOG_SERIOUS, "Warning: failed to register algo_aes_ccm_8 for IKE");
	if(!ike_alg_register_enc(&algo_aes_ccm_12))
		loglog(RC_LOG_SERIOUS, "Warning: failed to register algo_aes_ccm_12 for IKE");
	if(!ike_alg_register_enc(&algo_aes_ccm_16))
		loglog(RC_LOG_SERIOUS, "Warning: failed to register algo_aes_ccm_16 for IKE");
	if(!ike_alg_register_enc(&algo_aes_gcm_8))
		loglog(RC_LOG_SERIOUS, "Warning: failed to register algo_aes_gcm_8 for IKE");
	if(!ike_alg_register_enc(&algo_aes_gcm_12))
		loglog(RC_LOG_SERIOUS, "Warning: failed to register algo_aes_gcm_12 for IKE");
	if(!ike_alg_register_enc(&algo_aes_gcm_16))
		loglog(RC_LOG_SERIOUS, "Warning: failed to register algo_aes_gcm_16 for IKE");

	DBG(DBG_CONTROLMORE, DBG_log("Registered AEAD AES CCM/GCM algorithms"));
}

static void linux_pfkey_register_response(const struct sadb_msg *msg)
{
	switch (msg->sadb_msg_satype) {
	case SADB_SATYPE_ESP:
		kernel_alg_register_pfkey(msg,
					  msg->sadb_msg_len *
					  IPSEC_PFKEYv2_ALIGN);
		/* XXX Need to grab list from the kernel. */
		linux_pfkey_add_aead();
		break;
	case SADB_X_SATYPE_IPCOMP:
		can_do_IPcomp = TRUE;
		break;
	default:
		break;
	}
}

/** linux_pfkey_register - Register via PFKEY our capabilities
 *
 */
static void linux_pfkey_register(void)
{
	netlink_register_proto(SADB_SATYPE_AH, "AH");
	netlink_register_proto(SADB_SATYPE_ESP, "ESP");
	netlink_register_proto(SADB_X_SATYPE_IPCOMP, "IPCOMP");
	pfkey_close();
	DBG(DBG_CONTROLMORE, DBG_log("Registered AH, ESP and IPCOMP"));
}

/** Create ip_address out of xfrm_address_t.
 *
 * @param family
 * @param src xfrm formatted IP address
 * @param dst ip_address formatted destination
 * @return err_t NULL if okay, otherwise an error
 */
static err_t xfrm_to_ip_address(unsigned family, const xfrm_address_t *src,
				ip_address *dst)
{
	switch (family) {
	case AF_INET: /* IPv4 */
		initaddr((const void *) &src->a4, sizeof(src->a4), family,
			 dst);
		return NULL;

	case AF_INET6: /* IPv6 */
		initaddr((const void *) &src->a6, sizeof(src->a6), family,
			 dst);
		return NULL;

	default:
		return "unknown address family";
	}
}

static void netlink_acquire(struct nlmsghdr *n)
{
	struct xfrm_user_acquire *acquire;
	const xfrm_address_t *srcx, *dstx;
	int src_proto, dst_proto;
	ip_address src, dst;
	ip_subnet ours, his;
	unsigned family;
	unsigned transport_proto;
	err_t ugh = NULL;

#ifdef HAVE_LABELED_IPSEC
	struct rtattr *attr;
	int remaining;
	struct xfrm_user_sec_ctx *xuctx = NULL;
	char sec_context_value[MAX_SECCTX_LEN];
	struct xfrm_user_sec_ctx_ike *uctx = NULL;
	bool found_sec_ctx = FALSE;

	DBG(DBG_KERNEL,
	    DBG_log("xfrm netlink msg len %lu", (unsigned long) n->nlmsg_len));
#endif

	if (n->nlmsg_len < NLMSG_LENGTH(sizeof(*acquire))) {
		libreswan_log(
			"netlink_acquire got message with length %lu < %lu bytes; ignore message",
			(unsigned long) n->nlmsg_len,
			(unsigned long) sizeof(*acquire));
		return;
	}

#ifdef HAVE_LABELED_IPSEC
	DBG(DBG_KERNEL,
	    DBG_log("xfrm:nlmsghdr= %lu", sizeof(struct nlmsghdr)));
	DBG(DBG_KERNEL,
	    DBG_log("xfrm:acquire= %lu", sizeof(struct xfrm_user_acquire)));
	DBG(DBG_KERNEL, DBG_log("xfrm:rtattr= %lu", sizeof(struct rtattr)));
#endif

	/* WARNING: netlink only guarantees 32-bit alignment.
	 * See NLMSG_ALIGNTO in the kernel's include/uapi/linux/netlink.h.
	 * BUT some fields in struct xfrm_user_acquire are 64-bit and so access
	 * may be improperly aligned.  This will fail on a few strict
	 * architectures (it does break C rules).
	 */
	/* WARNING: this code's understanding to the XFRM netlink
	 * messages is from programs/pluto/linux26/xfrm.h.
	 * There is no guarantee that this matches the kernel's
	 * understanding.
	 *
	 * Many things are defined to be int or unsigned int.
	 * This isn't safe when the kernel and userland may
	 * be compiled with different models.
	 */
	acquire = NLMSG_DATA(n);	/* insufficiently aligned */

	srcx = &acquire->sel.saddr;
	dstx = &acquire->sel.daddr;
	family = acquire->policy.sel.family;
	transport_proto = acquire->sel.proto;

#ifdef HAVE_LABELED_IPSEC
	attr = (struct rtattr *)
		((char*) NLMSG_DATA(n) +
			NLMSG_ALIGN(sizeof(struct xfrm_user_acquire)));

	DBG(DBG_KERNEL, DBG_log("rtattr len= %d", attr->rta_len));

	if ( attr->rta_type == XFRMA_TMPL ) {
		DBG(DBG_KERNEL, DBG_log("xfrm: found XFRMA_TMPL"));
	} else {
		DBG(DBG_KERNEL, DBG_log("xfrm: not found XFRMA_TMPL"));
		if (attr->rta_type == XFRMA_SEC_CTX ) {
			DBG(DBG_KERNEL, DBG_log("xfrm: found XFRMA_SEC_CTX"));
			found_sec_ctx = TRUE;
		}
	}

	if (!found_sec_ctx) {
		DBG(DBG_KERNEL,
		    DBG_log(
			    "xfrm: did not found XFRMA_SEC_CTX, trying next one"));
		DBG(DBG_KERNEL, DBG_log("xfrm: rta->len=%d", attr->rta_len));

		remaining = n->nlmsg_len -
			    NLMSG_SPACE(sizeof(struct xfrm_user_acquire));
		attr = RTA_NEXT(attr, remaining);

		DBG(DBG_KERNEL,
		    DBG_log("xfrm: remaining=%d , rta->len = %d", remaining,
			    attr->rta_len));
		if (attr->rta_type == XFRMA_SEC_CTX ) {
			DBG(DBG_KERNEL, DBG_log(
				    "xfrm: found XFRMA_SEC_CTX now"));
			found_sec_ctx = TRUE;
		} else {
			if (attr->rta_type == XFRMA_POLICY_TYPE ) {
				DBG(DBG_KERNEL,
				    DBG_log("xfrm: found XFRMA_POLICY_TYPE"));
			} else {
				DBG(DBG_KERNEL,
				    DBG_log(
					    "xfrm: not found anything, seems wierd"));
				DBG(DBG_KERNEL,
				    DBG_log(
					    "xfrm: not found sec ctx still, perhaps not a labeled ipsec connection"));
			}
		}
	}

	if (found_sec_ctx) {
		xuctx = (struct xfrm_user_sec_ctx *) RTA_DATA(attr);
		DBG(DBG_KERNEL,
		    DBG_log(
			    "xfrm xuctx: exttype=%d, len=%d, ctx_doi=%d, ctx_alg=%d, ctx_len=%d",
			    xuctx->exttype, xuctx->len,
			    xuctx->ctx_doi, xuctx->ctx_alg, xuctx->ctx_len));

		if (xuctx->ctx_len <= MAX_SECCTX_LEN) {
			memcpy(sec_context_value, (xuctx + 1), xuctx->ctx_len);

			DBG(DBG_KERNEL,
			    DBG_log("xfrm: xuctx security context value: %s",
				    sec_context_value));

			uctx = alloc_thing(struct xfrm_user_sec_ctx_ike,
					   "struct xfrm_user_sec_ctx_ike");

			if (uctx != NULL) {
				uctx->len = xuctx->len;
				uctx->exttype = xuctx->exttype;
				uctx->ctx_alg = xuctx->ctx_alg;
				uctx->ctx_doi = xuctx->ctx_doi;
				uctx->ctx_len = xuctx->ctx_len; /*Length includes '\0'*/

				memcpy(uctx->sec_ctx_value, (xuctx + 1),
				       xuctx->ctx_len);
			} else {
				DBG(DBG_KERNEL,
				    DBG_log(
					    "not enough memory for struct xfrm_user_sec_ctx_ike"));
			}
		} else {
			DBG(DBG_KERNEL,
			    DBG_log(
				    "(should not reach here really) received security length=%d > MAX_SECCTX_LEN",
				    xuctx->ctx_len));
			DBG(DBG_KERNEL, DBG_log("ignoring ACQUIRE messages"));
			goto ignore_acquire;
		}
	}

#endif

	src_proto = 0;  /* XXX-MCR where to get protocol from? */
	dst_proto = 0;  /* ditto */
	src_proto = dst_proto = acquire->sel.proto;

	/* XXX also the type of src/dst should be checked to make sure
	 *     that they aren't v4 to v6 or something goofy
	 */

	if (!(ugh = xfrm_to_ip_address(family, srcx, &src)) &&
	    !(ugh = xfrm_to_ip_address(family, dstx, &dst)) &&
	    !(ugh = add_port(family, &src, acquire->sel.sport)) &&
	    !(ugh = add_port(family, &dst, acquire->sel.dport)) &&
	    !(ugh = src_proto ==
		    dst_proto ? NULL : "src and dst protocols differ") &&
	    !(ugh = addrtosubnet(&src, &ours)) &&
	    !(ugh = addrtosubnet(&dst, &his)))
		record_and_initiate_opportunistic(&ours, &his, transport_proto
#ifdef HAVE_LABELED_IPSEC
						  , uctx
#endif
						  , "%acquire-netlink");

#ifdef HAVE_LABELED_IPSEC
	pfreeany(uctx);

ignore_acquire:
#endif

	if (ugh != NULL)
		libreswan_log(
			"XFRM_MSG_ACQUIRE message from kernel malformed: %s",
			ugh);
}

static void netlink_shunt_expire(struct xfrm_userpolicy_info *pol)
{
	const xfrm_address_t *srcx, *dstx;
	ip_address src, dst;
	unsigned family;
	unsigned transport_proto;
	err_t ugh = NULL;

	srcx = &pol->sel.saddr;
	dstx = &pol->sel.daddr;
	family = pol->sel.family;
	transport_proto = pol->sel.proto;

	if ((ugh = xfrm_to_ip_address(family, srcx, &src)) ||
	    (ugh = xfrm_to_ip_address(family, dstx, &dst))) {
		libreswan_log(
			"XFRM_MSG_POLEXPIRE message from kernel malformed: %s",
			ugh);
		return;
	}

	replace_bare_shunt(&src, &dst,
			   BOTTOM_PRIO,
			   SPI_PASS,
			   FALSE,
			   transport_proto,
			   "delete expired bare shunt");
}

static void netlink_policy_expire(struct nlmsghdr *n)
{
	struct xfrm_user_polexpire *upe;

	struct {
		struct nlmsghdr n;
		struct xfrm_userpolicy_id id;
	} req;
	struct {
		struct nlmsghdr n;
		struct xfrm_userpolicy_info pol;
		char data[1024];
	} rsp;

	if (n->nlmsg_len < NLMSG_LENGTH(sizeof(*upe))) {
		libreswan_log(
			"netlink_policy_expire got message with length %lu < %lu bytes; ignore message",
			(unsigned long) n->nlmsg_len,
			(unsigned long) sizeof(*upe));
		return;
	}

	upe = NLMSG_DATA(n);
	req.id.dir = upe->pol.dir;
	req.id.index = upe->pol.index;
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = XFRM_MSG_GETPOLICY;
	req.n.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req.id)));

	rsp.n.nlmsg_type = XFRM_MSG_NEWPOLICY;
	if (!send_netlink_msg(&req.n, &rsp.n, sizeof(rsp), "Get policy",
			      "?")) {
		return;
	} else if (rsp.n.nlmsg_type == NLMSG_ERROR) {
		DBG(DBG_KERNEL,
		    DBG_log("netlink_policy_expire: policy died on us: "
			    "dir=%d, index=%d",
			    req.id.dir, req.id.index));
		return;
	} else if (rsp.n.nlmsg_len < NLMSG_LENGTH(sizeof(rsp.pol))) {
		libreswan_log(
			"netlink_policy_expire: XFRM_MSG_GETPOLICY returned message with length %lu < %lu bytes; ignore message",
			(unsigned long) rsp.n.nlmsg_len,
			(unsigned long) sizeof(rsp.pol));
		return;
	} else if (req.id.index != rsp.pol.index) {
		DBG(DBG_KERNEL,
		    DBG_log("netlink_policy_expire: policy was replaced: "
			    "dir=%d, oldindex=%d, newindex=%d",
			    req.id.dir, req.id.index, rsp.pol.index));
		return;
	} else if (upe->pol.curlft.add_time != rsp.pol.curlft.add_time) {
		DBG(DBG_KERNEL,
		    DBG_log("netlink_policy_expire: policy was replaced "
			    " and you have won the lottery: "
			    "dir=%d, index=%d",
			    req.id.dir, req.id.index));
		return;
	}

	switch (upe->pol.dir) {
	case XFRM_POLICY_OUT:
		netlink_shunt_expire(&rsp.pol);
		break;
	}
}

static bool netlink_get(void)
{
	struct {
		struct nlmsghdr n;
		char data[1024];
	} rsp;
	ssize_t r;
	struct sockaddr_nl addr;
	socklen_t alen;

	alen = sizeof(addr);
	r = recvfrom(netlink_bcast_fd, &rsp, sizeof(rsp), 0,
		     (struct sockaddr *)&addr, &alen);
	if (r < 0) {
		if (errno == EAGAIN)
			return FALSE;

		if (errno != EINTR)
			log_errno((e, "recvfrom() failed in netlink_get"));
		return TRUE;
	} else if ((size_t) r < sizeof(rsp.n)) {
		libreswan_log(
			"netlink_get read truncated message: %ld bytes; ignore message",
			(long) r);
		return TRUE;
	} else if (addr.nl_pid != 0) {
		/* not for us: ignore */
		DBG(DBG_KERNEL,
		    DBG_log("netlink_get: ignoring %s message from process %u",
			    sparse_val_show(xfrm_type_names, rsp.n.nlmsg_type),
			    addr.nl_pid));
		return TRUE;
	} else if ((size_t) r != rsp.n.nlmsg_len) {
		libreswan_log(
			"netlink_get read message with length %ld that doesn't equal nlmsg_len %lu bytes; ignore message",
			(long) r,
			(unsigned long) rsp.n.nlmsg_len);
		return TRUE;
	}

	DBG(DBG_KERNEL,
	    DBG_log("netlink_get: %s message",
		    sparse_val_show(xfrm_type_names, rsp.n.nlmsg_type)));

	switch (rsp.n.nlmsg_type) {
	case XFRM_MSG_ACQUIRE:
		netlink_acquire(&rsp.n);
		break;
	case XFRM_MSG_POLEXPIRE:
		netlink_policy_expire(&rsp.n);
		break;
	default:
		/* ignored */
		break;
	}

	return TRUE;
}

static void netlink_process_msg(void)
{
	while (netlink_get())
		;
}

static ipsec_spi_t netlink_get_spi(const ip_address *src,
				   const ip_address *dst,
				   int proto,
				   bool tunnel_mode,
				   unsigned reqid,
				   ipsec_spi_t min,
				   ipsec_spi_t max,
				   const char *text_said)
{
	struct {
		struct nlmsghdr n;
		struct xfrm_userspi_info spi;
	} req;
	struct {
		struct nlmsghdr n;
		union {
			struct nlmsgerr e;
			struct xfrm_usersa_info sa;
		} u;
		char data[1024];
	} rsp;
	static int get_cpi_bug;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = XFRM_MSG_ALLOCSPI;

	ip2xfrm(src, &req.spi.info.saddr);
	ip2xfrm(dst, &req.spi.info.id.daddr);
	req.spi.info.mode = tunnel_mode;
	req.spi.info.reqid = reqid;
	req.spi.info.id.proto = proto;
	req.spi.info.family = src->u.v4.sin_family;

	req.n.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req.spi)));

	rsp.n.nlmsg_type = XFRM_MSG_NEWSA;

retry:
	req.spi.min = get_cpi_bug ? htonl(min) : min;
	req.spi.max = get_cpi_bug ? htonl(max) : max;

	if (!send_netlink_msg(&req.n, &rsp.n, sizeof(rsp), "Get SPI",
			      text_said)) {
		return 0;
	} else if (rsp.n.nlmsg_type == NLMSG_ERROR) {
		if (rsp.u.e.error == -EINVAL && proto == IPPROTO_COMP &&
		    !get_cpi_bug) {
			get_cpi_bug = 1;
			libreswan_log("netlink_get_spi: Enabling workaround for"
				      " kernel CPI allocation bug");
			goto retry;
		}

		loglog(RC_LOG_SERIOUS,
		       "ERROR: netlink_get_spi for %s failed with errno %d: %s",
		       text_said,
		       -rsp.u.e.error,
		       strerror(-rsp.u.e.error));
		return 0;
	} else if (rsp.n.nlmsg_len < NLMSG_LENGTH(sizeof(rsp.u.sa))) {
		libreswan_log(
			"netlink_get_spi: XFRM_MSG_ALLOCSPI returned message with length %lu < %lu bytes; ignore message",
			(unsigned long) rsp.n.nlmsg_len,
			(unsigned long) sizeof(rsp.u.sa));
		return 0;
	}

	DBG(DBG_KERNEL,
	    DBG_log("netlink_get_spi: allocated 0x%x for %s",
		    ntohl(rsp.u.sa.id.spi), text_said));
	return rsp.u.sa.id.spi;
}

/* install or remove eroute for SA Group */
/* (identical to KLIPS version, but refactoring isn't waranteed yet */
static bool netlink_sag_eroute(struct state *st, struct spd_route *sr,
			       unsigned op, const char *opname)
{
	unsigned int inner_proto;
	enum eroute_type inner_esatype;
	ipsec_spi_t inner_spi;
	struct pfkey_proto_info proto_info[4];
	int i;
	bool tunnel;

	/* figure out the SPI and protocol (in two forms)
	 * for the innermost transformation.
	 */

	i = sizeof(proto_info) / sizeof(proto_info[0]) - 1;
	proto_info[i].proto = 0;
	tunnel = FALSE;

	inner_proto = 0;
	inner_esatype = ET_UNSPEC;
	inner_spi = 0;

	if (st->st_ah.present) {
		inner_spi = st->st_ah.attrs.spi;
		inner_proto = SA_AH;
		inner_esatype = ET_AH;

		i--;
		proto_info[i].proto = IPPROTO_AH;
		proto_info[i].encapsulation = st->st_ah.attrs.encapsulation;
		tunnel |= proto_info[i].encapsulation ==
			  ENCAPSULATION_MODE_TUNNEL;
		proto_info[i].reqid = sr->reqid;
	}

	if (st->st_esp.present) {
		inner_spi = st->st_esp.attrs.spi;
		inner_proto = SA_ESP;
		inner_esatype = ET_ESP;

		i--;
		proto_info[i].proto = IPPROTO_ESP;
		proto_info[i].encapsulation = st->st_esp.attrs.encapsulation;
		tunnel |= proto_info[i].encapsulation ==
			  ENCAPSULATION_MODE_TUNNEL;
		proto_info[i].reqid = (sr->reqid < IPSEC_MANUAL_REQID_MAX) ?  sr->reqid : sr->reqid + 1;
	}

	if (st->st_ipcomp.present) {
		inner_spi = st->st_ipcomp.attrs.spi;
		inner_proto = SA_COMP;
		inner_esatype = ET_IPCOMP;

		i--;
		proto_info[i].proto = IPPROTO_COMP;
		proto_info[i].encapsulation =
			st->st_ipcomp.attrs.encapsulation;
		tunnel |= proto_info[i].encapsulation ==
			  ENCAPSULATION_MODE_TUNNEL;
		proto_info[i].reqid = (sr->reqid < IPSEC_MANUAL_REQID_MAX) ?  sr->reqid : sr->reqid + 2;
	}

	/* check for no transform at all */
	passert(!(!st->st_ipcomp.present && !st->st_esp.present &&
		  !st->st_ah.present));

	if (tunnel) {
		int j;

		inner_spi = st->st_tunnel_out_spi;
		inner_proto = SA_IPIP;
		inner_esatype = ET_IPIP;

		proto_info[i].encapsulation = ENCAPSULATION_MODE_TUNNEL;
		for (j = i + 1; proto_info[j].proto; j++)
			proto_info[j].encapsulation =
				ENCAPSULATION_MODE_TRANSPORT;
	}

	return eroute_connection(sr,
				 inner_spi, inner_proto,
				 inner_esatype, proto_info + i,
				 op, opname
#ifdef HAVE_LABELED_IPSEC
				 , st->st_connection->policy_label
#endif
				 );
}

/* Check if there was traffic on given SA during the last idle_max
 * seconds. If TRUE, the SA was idle and DPD exchange should be performed.
 * If FALSE, DPD is not necessary. We also return TRUE for errors, as they
 * could mean that the SA is broken and needs to be replace anyway.
 */
static bool netlink_eroute_idle(struct state *st, time_t idle_max)
{
	time_t idle_time;

	passert(st != NULL);
	if (!get_sa_info(st, TRUE, &idle_time))
		return TRUE;
	else
		return idle_time >= idle_max;
}

static bool netlink_shunt_eroute(struct connection *c,
				 struct spd_route *sr,
				 enum routing_t rt_kind,
				 enum pluto_sadb_operations op,
				 const char *opname)
{
	ipsec_spi_t spi;

	DBG(DBG_CONTROL,
	    DBG_log(
		    "request to %s a %s policy with netkey kernel --- experimental",
		    opname,
		    enum_name(&routing_story, rt_kind)));

	/* We are constructing a special SAID for the eroute.
	 * The destination doesn't seem to matter, but the family does.
	 * The protocol is SA_INT -- mark this as shunt.
	 * The satype has no meaning, but is required for PF_KEY header!
	 * The SPI signifies the kind of shunt.
	 */
	spi = shunt_policy_spi(c, rt_kind == RT_ROUTED_PROSPECTIVE);

	if (spi == 0) {
		/* we're supposed to end up with no eroute: rejig op and opname */
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
		/* We think that we have an eroute, but we don't.
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
			/* delete unnecessary: we don't actually have an eroute */
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
						    "restoring eclipsed");
		}
	}

	{
		const ip_address *peer = &sr->that.host_addr;
		char buf2[256];
		const struct af_info *fam = aftoinfo(addrtypeof(peer));

		if (fam == NULL)
			fam = aftoinfo(AF_INET);

		snprintf(buf2, sizeof(buf2),
			 "eroute_connection %s", opname);

		if ( !netlink_raw_eroute(&sr->this.host_addr, &sr->this.client,
					 &sr->that.host_addr,
					 &sr->that.client,
					 htonl(spi),
					 c->encapsulation ==
					 ENCAPSULATION_MODE_TRANSPORT ? SA_ESP
					 :
					 SA_INT,
					 sr->this.protocol,
					 ET_INT,
					 null_proto_info, 0, c->sa_priority,
					 op, buf2
#ifdef HAVE_LABELED_IPSEC
					 , c->policy_label
#endif
					 ) )
			return FALSE;

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

		snprintf(buf2, sizeof(buf2),
			 "eroute_connection %s inbound", opname);

		return netlink_raw_eroute(&sr->this.host_addr,
					  &sr->this.client,
					  &sr->that.host_addr,
					  &sr->that.client,
					  htonl(
						  spi),
					  c->encapsulation == ENCAPSULATION_MODE_TRANSPORT ? SA_ESP : SA_INT,
					  sr->this.protocol,
					  ET_INT,
					  null_proto_info, 0, c->sa_priority,
					  op, buf2
#ifdef HAVE_LABELED_IPSEC
					  , c->policy_label
#endif
					  );
	}
}

static void netlink_process_raw_ifaces(struct raw_iface *rifaces)
{
	struct raw_iface *ifp;
	ip_address lip; /* --listen filter option */

	if (pluto_listen) {
		err_t e;
		e = ttoaddr(pluto_listen, 0, 0, &lip);
		if (e) {
			DBG_log("invalid listen= option ignored: %s\n", e);
			pluto_listen = NULL;
		}
		DBG(DBG_CONTROL,
		    DBG_log("Only looking to listen on %s\n", ip_str(&lip)));
	}

	/* Find all virtual/real interface pairs.
	 * For each real interface...
	 */
	for (ifp = rifaces; ifp != NULL; ifp = ifp->next) {
		struct raw_iface *v = NULL;     /* matching ipsecX interface */
		struct raw_iface fake_v;
		bool after = FALSE;             /* has vfp passed ifp on the list? */
		bool bad = FALSE;
		struct raw_iface *vfp;

		/* ignore if virtual (ipsec*) interface */
		if (strncmp(ifp->name, IPSECDEVPREFIX, sizeof(IPSECDEVPREFIX) -
			    1) == 0)
			continue;

		/* ignore if virtual (mast*) interface */
		if (strncmp(ifp->name, MASTDEVPREFIX, sizeof(MASTDEVPREFIX) -
			    1) == 0)
			continue;

		for (vfp = rifaces; vfp != NULL; vfp = vfp->next) {
			if (vfp == ifp) {
				after = TRUE;
			} else if (sameaddr(&ifp->addr, &vfp->addr)) {
				/* Different entries with matching IP addresses.
				 * Many interesting cases.
				 */
				if (strncmp(vfp->name, IPSECDEVPREFIX,
					    sizeof(IPSECDEVPREFIX) - 1) == 0) {
					if (v != NULL) {
						loglog(RC_LOG_SERIOUS,
						       "ipsec interfaces %s and %s share same address %s",
						       v->name, vfp->name,
						       ip_str(&ifp->addr));
						bad = TRUE;
					} else {
						v = vfp; /* current winner */
					}
				} else {
					/* ugh: a second real interface with the same IP address
					 * "after" allows us to avoid double reporting.
					 */
					if (kern_interface == USE_NETKEY) {
						if (after) {
							bad = TRUE;
							break;
						}
						continue;
					}
					if (after) {
						loglog(RC_LOG_SERIOUS,
						       "IP interfaces %s and %s share address %s!",
						       ifp->name, vfp->name,
						       ip_str(&ifp->addr));
					}
					bad = TRUE;
				}
			}
		}

		if (bad)
			continue;

		if (kern_interface == USE_NETKEY) {
			v = ifp;
			goto add_entry;
		}

		/* what if we didn't find a virtual interface? */
		if (v == NULL) {
			if (kern_interface == NO_KERNEL) {
				/* kludge for testing: invent a virtual device */
				static const char fvp[] = "virtual";
				fake_v = *ifp;
				passert(sizeof(fake_v.name) > sizeof(fvp));
				strcpy(fake_v.name, fvp);
				addrtot(&ifp->addr, 0,
					fake_v.name + sizeof(fvp) - 1,
					sizeof(fake_v.name) -
					(sizeof(fvp) - 1));
				v = &fake_v;
			} else {
				DBG(DBG_CONTROL,
				    DBG_log(
					    "IP interface %s %s has no matching ipsec* interface -- ignored",
					    ifp->name, ip_str(&ifp->addr)));
				continue;
			}
		}

		/* We've got all we need; see if this is a new thing:
		 * search old interfaces list.
		 */
add_entry:
		/* last check before we actually add the entry due to ugly goto code */
		/* ignore if --listen is specified and we do not match */
		if (pluto_listen != NULL) {
			if (!sameaddr(&lip, &ifp->addr)) {
				libreswan_log("skipping interface %s with %s",
					      ifp->name, ip_str(&ifp->addr));
				continue;
			}
		}

		{
			struct iface_port **p = &interfaces;

			for (;; ) {
				struct iface_port *q = *p;
				struct iface_dev *id = NULL;

				/* search is over if at end of list */
				if (q == NULL) {
					/* matches nothing -- create a new entry */
					int fd = create_socket(ifp, v->name,
							       pluto_port);

					if (fd < 0)
						break;

					if (nat_traversal_support_non_ike &&
					    addrtypeof(&ifp->addr) == AF_INET)
						nat_traversal_espinudp_socket(
							fd, "IPv4",
							ESPINUDP_WITH_NON_IKE);

					q = alloc_thing(struct iface_port,
							"struct iface_port");
					id = alloc_thing(struct iface_dev,
							 "struct iface_dev");

					LIST_INSERT_HEAD(&interface_dev, id,
							 id_entry);

					q->ip_dev = id;
					id->id_rname = clone_str(ifp->name,
								 "real device name");
					id->id_vname = clone_str(v->name,
								 "virtual device name netlink");
					id->id_count++;

					q->ip_addr = ifp->addr;
					q->fd = fd;
					q->next = interfaces;
					q->change = IFN_ADD;
					q->port = pluto_port;
					q->ike_float = FALSE;

					interfaces = q;

					libreswan_log(
						"adding interface %s/%s %s:%d",
						q->ip_dev->id_vname,
						q->ip_dev->id_rname,
						ip_str(&q->ip_addr),
						q->port);

					/*
					 * right now, we do not support NAT-T on IPv6, because
					 * the kernel did not support it, and gave an error
					 * it one tried to turn it on.
					 */
					if (nat_traversal_support_port_floating
					    &&
					    addrtypeof(&ifp->addr) ==
					    AF_INET) {
						fd = create_socket(ifp,
								   v->name,
								   pluto_natt_float_port);
						if (fd < 0)
							break;
						nat_traversal_espinudp_socket(
							fd, "IPv4",
							ESPINUDP_WITH_NON_ESP);
						q = alloc_thing(
							struct iface_port,
							"struct iface_port");
						q->ip_dev = id;
						id->id_count++;

						q->ip_addr = ifp->addr;
						setportof(htons(
								  pluto_natt_float_port),
							  &q->ip_addr);
						q->port =
							pluto_natt_float_port;
						q->fd = fd;
						q->next = interfaces;
						q->change = IFN_ADD;
						q->ike_float = TRUE;
						interfaces = q;
						libreswan_log(
							"adding interface %s/%s %s:%d",
							q->ip_dev->id_vname, q->ip_dev->id_rname,
							ip_str(&q->
							       ip_addr),
							q->port);
					}

					break;
				}

				/* search over if matching old entry found */
				if (streq(q->ip_dev->id_rname, ifp->name) &&
				    streq(q->ip_dev->id_vname, v->name) &&
				    sameaddr(&q->ip_addr, &ifp->addr)) {
					/* matches -- rejuvinate old entry */
					q->change = IFN_KEEP;

					/* look for other interfaces to keep (due to NAT-T) */
					for (q = q->next; q; q = q->next) {
						if (streq(q->ip_dev->id_rname,
							  ifp->name) &&
						    streq(q->ip_dev->id_vname,
							  v->name) &&
						    sameaddr(&q->ip_addr,
							     &ifp->addr))
							q->change = IFN_KEEP;
					}

					break;
				}

				/* try again */
				p = &q->next;
			} /* for (;;) */
		}
	}

	/* delete the raw interfaces list */
	while (rifaces != NULL) {
		struct raw_iface *t = rifaces;

		rifaces = t->next;
		pfree(t);
	}
}

/* netlink_get_sa - Get SA information from the kernel
 *
 * @param sa Kernel SA to be queried
 * @return bool True if successful
 */
static bool netlink_get_sa(const struct kernel_sa *sa, u_int *bytes)
{
	struct {
		struct nlmsghdr n;
		struct xfrm_usersa_id id;
	} req;

	struct {
		struct nlmsghdr n;
		struct xfrm_usersa_info info;
		char data[1024];
	} rsp;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = XFRM_MSG_GETSA;

	ip2xfrm(sa->dst, &req.id.daddr);

	req.id.spi = sa->spi;
	req.id.family = sa->src->u.v4.sin_family;
	req.id.proto = sa->proto;

	req.n.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req.id)));
	rsp.n.nlmsg_type = XFRM_MSG_NEWSA;

	if (!send_netlink_msg(&req.n, &rsp.n, sizeof(rsp), "Get SA",
			      sa->text_said))
		return FALSE;

	*bytes = (u_int) rsp.info.curlft.bytes;
	return TRUE;
}

static bool netkey_do_command(struct connection *c, struct spd_route *sr,
			      const char *verb, struct state *st)
{
	char cmd[2048]; /* arbitrary limit on shell command length */
	char common_shell_out_str[2048];
	const char *verb_suffix;

	/* figure out which verb suffix applies */
	{
		const char *hs, *cs;

		switch (addrtypeof(&sr->this.host_addr)) {
		case AF_INET:
			hs = "-host";
			cs = "-client";
			break;
		case AF_INET6:
			hs = "-host-v6";
			cs = "-client-v6";
			break;
		default:
			loglog(RC_LOG_SERIOUS, "unknown address family");
			return FALSE;
		}
		verb_suffix = subnetisaddr(&sr->this.client,
					   &sr->this.host_addr) ?
			      hs : cs;
	}

	if (fmt_common_shell_out(common_shell_out_str,
				 sizeof(common_shell_out_str), c, sr,
				 st) == -1) {
		loglog(RC_LOG_SERIOUS, "%s%s command too long!", verb,
		       verb_suffix);
		return FALSE;
	}

	if (-1 == snprintf(cmd, sizeof(cmd),
			   "2>&1 "      /* capture stderr along with stdout */
			   "PLUTO_VERB='%s%s' "
			   "%s"         /* other stuff   */
			   "%s",        /* actual script */
			   verb, verb_suffix,
			   common_shell_out_str,
			   sr->this.updown ==
			   NULL ? DEFAULT_UPDOWN : sr->this.updown)) {
		loglog(RC_LOG_SERIOUS, "%s%s command too long!", verb,
		       verb_suffix);
		return FALSE;
	}

	return invoke_command(verb, verb_suffix, cmd);
}

const struct kernel_ops netkey_kernel_ops = {
	.kern_name = "netkey",
	.type = USE_NETKEY,
	.inbound_eroute =  TRUE,
	.policy_lifetime = TRUE,
	.async_fdp = &netlink_bcast_fd,
	.replay_window = 32,

	.init = init_netlink,
	.pfkey_register = linux_pfkey_register,
	.pfkey_register_response = linux_pfkey_register_response,
	.process_msg = netlink_process_msg,
	.raw_eroute = netlink_raw_eroute,
	.add_sa = netlink_add_sa,
	.del_sa = netlink_del_sa,
	.get_sa = netlink_get_sa,
	.process_queue = NULL,
	.grp_sa = NULL,
	.get_spi = netlink_get_spi,
	.exceptsocket = NULL,
	.docommand = netkey_do_command,
	.process_ifaces = netlink_process_raw_ifaces,
	.shunt_eroute = netlink_shunt_eroute,
	.sag_eroute = netlink_sag_eroute,
	.eroute_idle = netlink_eroute_idle,
	.set_debug = NULL, /* pfkey_set_debug, */
	/* We should implement netlink_remove_orphaned_holds
	 * if netlink  specific changes are needed.
	 */
	.remove_orphaned_holds = pfkey_remove_orphaned_holds,
	.overlap_supported = FALSE,
	.sha2_truncbug_support = TRUE,
};
#endif /* linux && NETKEY_SUPPORT */
