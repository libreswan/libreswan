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

#include "constants.h"
#include "defaultroute.h"
#include "constants.h"
#include "ipsecconf/confread.h"
#include "lswlog.h"		/* for fatal() */
#include "ip_sockaddr.h"
#include "ip_info.h"
#include "sparse_names.h"

static const struct sparse_names rta_names = {
	.list = {
#define E(N) { .name = #N, .value = N, }
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

void resolve_default_route(struct resolve_end *host,
			   struct resolve_end *peer,
                           const struct ip_info *host_afi UNUSED,
			   struct verbose verbose UNUSED)
{
	/* What kind of result are we seeking? */
	bool seeking_src = (host->host.type == KH_DEFAULTROUTE ||
			    peer->host.type == KH_DEFAULTROUTE);
	bool seeking_gateway = (host->nexthop.type == KH_DEFAULTROUTE ||
				peer->nexthop.type == KH_DEFAULTROUTE);
	if (!seeking_src && !seeking_gateway)
		return;	/* this end already figured out */

	vfatal(PLUTO_EXIT_FAIL, 0, "addcon: without XFRM, cannot resolve_defaultroute()");
}

static bool parse_address(const struct ip_info *afi,
			  ip_address *out,
			  const char *what,
			  const struct sockaddr *sa,
			  struct verbose verbose)
{
	if (sa->sa_family != afi->af) {
		verbose("%s: ignored, %d is wrong family", what, sa->sa_family);
		return true;
	}

	err_t e = sockaddr_to_address_port(sa, sa->sa_len,
					   out, NULL);
	if (e != NULL) {
		verror(0, "%s: sockaddr to address failed: %s", what, e);
		return false;
	}

	address_buf ob;
	verbose("%s: %s", what, str_address(out, &ob));
	return true;
}

static enum route_status get_route_1(int s,
				     ip_address dest,
				     const struct ip_info *afi,
				     struct ip_route *route,
				     struct verbose verbose)
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

	/*
	 * Build the request.
	 */
	{
		uint8_t *ap = msg.buf;

		/* append dst */
		msg.hdr.rtm_addrs |= RTA_DST;
		ip_sockaddr sa = sockaddr_from_address(dest);
		memcpy(ap, &sa.sa, sa.len);
		RT_ADVANCE(ap, (&sa.sa.sa));

		/* append IFP */
		msg.hdr.rtm_addrs |= RTA_IFP;
		struct sockaddr *ifp = (void*)ap;
		ifp->sa_family = AF_LINK;
		ifp->sa_len = sizeof(struct sockaddr_dl);
		RT_ADVANCE(ap, ifp);

		/* final length */
		msg.hdr.rtm_msglen = ap - (uint8_t*)&msg;

		/* send */
		int w = write(s, &msg, msg.hdr.rtm_msglen);
		if (w < 0) {
			verror(errno, "write failed: ");
			return ROUTE_FATAL;
		}

	}

	/* recv */
	int r = read(s, &msg, sizeof(msg));
	if (r < 0) {
		verror(errno, "write failed: ");
		return ROUTE_FATAL;
	}

	/* verify */
	if (sizeof(msg.hdr.rtm_msglen) > (unsigned)r) {
		verror(0, "response of %d bytes way too small", r);
		return ROUTE_FATAL;
	}

	if (msg.hdr.rtm_msglen > r) {
		verror(0, "response of %d bytes was truncated", r);
		return ROUTE_FATAL;
	}

	if (msg.hdr.rtm_version != RTM_VERSION) {
		verror(0, "response version %d wrong", msg.hdr.rtm_version);
		return ROUTE_FATAL;
	}

	if (msg.hdr.rtm_errno != 0) {
		verror(msg.hdr.rtm_errno, "response failed: ");
		return ROUTE_FATAL;
	}

	if (msg.hdr.rtm_type != RTM_GET) {
		verror(0, "response type %d wrong", msg.hdr.rtm_type);
		return ROUTE_FATAL;
	}

	/* go through bits lsb->msb; match payload */
	ip_address gateway = unset_address;
	ip_address ifa = unset_address;
	ip_address netmask = unset_address;
	ip_address genmask = unset_address;
	ip_address dst = unset_address;
	unsigned interface_index = 0;
	char interface_name[IFNAMSIZ] = {0};

	/*
	 * Iterate through the bitmask .rtm_addrs.
	 */
	uint8_t *ap = msg.buf;
	unsigned a = msg.hdr.rtm_addrs;
	for (unsigned b = 0; a != 0; b++) {
		unsigned m = 1 << b;
		if (a & m) {
			a &= ~m;
			const struct sockaddr *sa = (void*)ap;
			RT_ADVANCE(ap, sa);
			switch (m) {

			case RTA_DST:		/* destination sockaddr present */
				if (!parse_address(afi, &dst, "RTA_DST", sa, verbose)) {
					return ROUTE_FATAL;
				}
				break;
			case RTA_GATEWAY:	/* gateway sockaddr present */
				if (!parse_address(afi, &gateway, "RTA_GATEWAY", sa, verbose)) {
					return ROUTE_FATAL;
				}
				break;
			case RTA_IFA:		/* interface addr sockaddr present */
				if (!parse_address(afi, &ifa, "RTA_IFA", sa, verbose)) {
					return ROUTE_FATAL;
				}
				break;
			case RTA_NETMASK:	/* netmask sockaddr present */
				if (!parse_address(afi, &netmask, "RTA_NETMASK", sa, verbose)) {
					return ROUTE_FATAL;
				}
				break;
			case RTA_GENMASK:	/* cloning mask sockaddr present */
				if (!parse_address(afi, &genmask, "RTA_GENMASK", sa, verbose)) {
					return ROUTE_FATAL;
				}
				break;

			case RTA_IFP:		/* interface name sockaddr present */
			{
				if (sa->sa_family != AF_LINK) {
					verbose("RTA_IFP: ignored, need AF_LINK");
					break;
				}
				const struct sockaddr_dl *sdl = (struct sockaddr_dl *)sa;
				if (sdl->sdl_nlen == 0) {
					verbose("RTA_IFP: ignored, .sdl_nlen == 0");
					break;
				}
				interface_index = sdl->sdl_index;
				if_indextoname(interface_index, interface_name);
				verbose("RTA_IFP: %s (%d)", interface_name, interface_index);
				break;
			}

			case RTA_AUTHOR:	/* sockaddr for author of redirect */
			case RTA_BRD:		/* for NEWADDR, broadcast or p-p dest addr */
#ifdef RTA_TAG
			case RTA_TAG:		/* route tag */
#endif
			{
				name_buf eb;
				verbose("%s: ignored", str_sparse_long(&rta_names, m, &eb));
				break;
			}
			default:
			{
				verbose("unrecognized %d", m);
				break;
			}
			}
		}
	}

	route->gateway = gateway;
	route->source = ifa;

	/* unpack */
	return ROUTE_SUCCESS;
}

enum route_status get_route(ip_address dst, struct ip_route *route, struct logger *logger)
{
	struct verbose verbose = VERBOSE(DEBUG_STREAM, logger, NULL);

	zero(route);
	const struct ip_info *afi = address_info(dst);
	int s = cloexec_socket(PF_ROUTE, SOCK_RAW, afi->af);
	if (s < 0) {
		verror(errno, "cloexec_socket(PF_ROUTE, SOCK_RAW, %s) failed: ",
		       afi->ip_name);
		return ROUTE_FATAL;
	}

	enum route_status status = get_route_1(s, dst, afi, route, verbose);
	close(s);
	return status;
}
