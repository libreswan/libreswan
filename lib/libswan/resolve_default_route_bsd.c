/* BSD route resolution, for libreswan
 *
 * Copyright (C) 2017 Antony Antony
 * Copyright (C) 2018 Paul Wouters
 * Copyright (C) 2022 Andrew Cagney

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

#include <net/if.h>
#include <net/if_dl.h>
#include <unistd.h>
#include <errno.h>

#include <net/route.h>

#include "lsw_socket.h"

/* NetBSD defines RT_ADVANCE(); FreeBSD SA_SIZE(); OpenBSD nada */
#ifndef RT_ADVANCE
# if defined __FreeBSD__
#  define RT_ADVANCE(AP, SA) AP += SA_SIZE(SA)
# elif defined __OpenBSD__
#  define RT_ADVANCE(AP, SA) AP += (1 + (((SA)->sa_len - 1) | (sizeof(long) - 1)))
# elif defined __APPLE__
#  define RT_ADVANCE(AP, SA) AP += (1 + (((SA)->sa_len - 1) | (sizeof(long) - 1)))
# else
#  error RT_ADVANCE
# endif
#endif

#include "addr_lookup.h"
#include "constants.h"
#include "ipsecconf/confread.h"
#include "lswlog.h"		/* for fatal() */
#include "ip_sockaddr.h"
#include "ip_info.h"
#include "sparse_names.h"

static const struct sparse_names rta_names = {
	.list = {
#define E(N) { #N, N, }
		E(RTA_DST),
		E(RTA_IFP),
		E(RTA_IFA),
		E(RTA_GATEWAY),
		E(RTA_NETMASK),
		E(RTA_GENMASK),
#undef E
		SPARSE_NULL,
	},
};

void resolve_default_route(struct starter_end *host,
			   struct starter_end *peer,
			   lset_t verbose_rc_flags UNUSED,
			   struct logger *logger)
{
	/* What kind of result are we seeking? */
	bool seeking_src = (host->addrtype == KH_DEFAULTROUTE ||
			    peer->addrtype == KH_DEFAULTROUTE);
	bool seeking_gateway = (host->nexttype == KH_DEFAULTROUTE ||
				peer->nexttype == KH_DEFAULTROUTE);
	if (!seeking_src && !seeking_gateway)
		return;	/* this end already figured out */

	fatal(PLUTO_EXIT_FAIL, logger,
	      "addcon: without XFRM, cannot resolve_defaultroute()");
}

static enum route_status get_route_1(int s, ip_address dst,
				     const struct ip_info *afi,
				     struct ip_route *route,
				     struct logger *logger)
{
	struct {
		struct rt_msghdr hdr;
		uint8_t buf[512/*something big*/];
	} msg = {
		.hdr = {
			.rtm_version = RTM_VERSION,
			.rtm_type = RTM_GET,
			.rtm_seq = 1,
			.rtm_flags = RTF_UP|RTF_GATEWAY|RTF_HOST|RTF_STATIC,
		},
	};

	uint8_t *ap = msg.buf;

	/* append dst */
	msg.hdr.rtm_addrs |= RTA_DST;
	ip_sockaddr sa = sockaddr_from_address(dst);
	memcpy(ap, &sa.sa, sa.len);
	RT_ADVANCE(ap, (&sa.sa.sa));

	/* append IFP */
	msg.hdr.rtm_addrs |= RTA_IFP;
	struct sockaddr *ifp = (void*)ap;
	ifp->sa_family = AF_LINK,
	ifp->sa_len = sizeof(struct sockaddr_dl),
	RT_ADVANCE(ap, ifp);

	/* final length */
	msg.hdr.rtm_msglen = ap - (uint8_t*)&msg;

	/* send */
	int w = write(s, &msg, msg.hdr.rtm_msglen);
	if (w < 0) {
		llog_errno(ERROR_FLAGS, logger, errno, "write failed: ");
		return ROUTE_FATAL;
	}

	/* recv */
	int r = read(s, &msg, sizeof(msg));
	if (r < 0) {
		llog_errno(ERROR_FLAGS, logger, errno, "write failed: ");
		return ROUTE_FATAL;
	}

	/* verify */
	if (sizeof(msg.hdr.rtm_msglen) > (unsigned)r) {
		llog(ERROR_FLAGS, logger, "response of %d bytes way too small", r);
		return ROUTE_FATAL;
	}
	if (msg.hdr.rtm_msglen > r) {
		llog(ERROR_FLAGS, logger, "response of %d bytes was truncated", r);
		return ROUTE_FATAL;
	}
	if (msg.hdr.rtm_version != RTM_VERSION) {
		llog(ERROR_FLAGS, logger, "response version %d wrong",
		     msg.hdr.rtm_version);
		return ROUTE_FATAL;
	}
	if (msg.hdr.rtm_errno != 0) {
		llog(ERROR_FLAGS, logger, "response failed: %s", strerror(errno));
		return ROUTE_FATAL;
	}
	if (msg.hdr.rtm_type != RTM_GET) {
		llog(ERROR_FLAGS, logger, "response type %d wrong",
		     msg.hdr.rtm_type);
		return ROUTE_FATAL;
	}

	/* go through bits lsb->msb; match payload */
	ap = msg.buf;
	unsigned a = msg.hdr.rtm_addrs;
	for (unsigned b = 0; a != 0; b++) {
		unsigned m = 1 << b;
		if (a & m) {
			sparse_buf eb;
			dbg("found %s", str_sparse(&rta_names, m, &eb));
			a &= ~m;
			struct sockaddr *sa = (void*)ap;
			RT_ADVANCE(ap, sa);
			if (sa->sa_family != afi->af) {
				continue;
			}
			err_t e = NULL;
			switch (m) {
			case RTA_DST:		/* destination sockaddr present */
				break;
			case RTA_GATEWAY:	/* gateway sockaddr present */
				e = sockaddr_to_address_port(sa, sa->sa_len,
							     &route->gateway, NULL);
				break;
			case RTA_NETMASK:	/* netmask sockaddr present */
			case RTA_GENMASK:	/* cloning mask sockaddr present */
			case RTA_IFP:		/* interface name sockaddr present */
				break;
			case RTA_IFA:		/* interface addr sockaddr present */
				e = sockaddr_to_address_port(sa, sa->sa_len,
							     &route->source, NULL);
				break;
			case RTA_AUTHOR:	/* sockaddr for author of redirect */
			case RTA_BRD:		/* for NEWADDR, broadcast or p-p dest addr */
#ifdef RTA_TAG
			case RTA_TAG:		/* route tag */
#endif
				break;
			}
			if (e != NULL) {
				llog(ERROR_FLAGS, logger,
				     "invalid %s", e);
				return ROUTE_FATAL;
			}
		}
	}

	/* unpack */
	return ROUTE_SUCCESS;
}

enum route_status get_route(ip_address dst, struct ip_route *route, struct logger *logger)
{
	zero(route);
	const struct ip_info *afi = address_type(&dst);
	int s = cloexec_socket(PF_ROUTE, SOCK_RAW, afi->af);
	if (s < 0) {
		llog_errno(ERROR_FLAGS, logger, errno,
			   "cloexec_socket(PF_ROUTE, SOCK_RAW, %s) failed: ",
			   afi->ip_name);
		return ROUTE_FATAL;
	}

	enum route_status status = get_route_1(s, dst, afi, route, logger);
	close(s);
	return status;
}
