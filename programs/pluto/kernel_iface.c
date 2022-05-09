/* iface, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002, 2013,2016 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
 * Copyright (C) 2016-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 D. Hugh Redelmeier <hugh@mimosa.com>
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
 *
 */

#include <stdlib.h>		/* for malloc() free() UGH! */
#include <sys/ioctl.h>

#include "socketwrapper.h"		/* for safe_sock() */

#include "kernel_iface.h"
#include "ip_info.h"

#include "defs.h"
#include "log.h"

struct raw_iface *find_raw_ifaces4(struct logger *logger)
{
	/* Get a UDP socket */

	int udp_sock = safe_socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (udp_sock == -1) {
		fatal_errno(PLUTO_EXIT_FAIL, logger, errno,
			    "socket() failed in find_raw_ifaces4()");
	}

	/* get list of interfaces with assigned IPv4 addresses from system */

	/*
	 * Without SO_REUSEADDR, bind() of udp_sock will cause
	 * 'address already in use?
	 */
	static const int on = true;     /* by-reference parameter; constant, we hope */
	if (setsockopt(udp_sock, SOL_SOCKET, SO_REUSEADDR,
		       (const void *)&on, sizeof(on)) < 0) {
		fatal_errno(PLUTO_EXIT_FAIL, logger, errno,
			    "setsockopt(SO_REUSEADDR) in find_raw_ifaces4()");
	}

	/*
	 * bind the socket; somewhat convoluted as BSD as size field.
	 */
	{
		ip_endpoint any_ep = endpoint_from_address_protocol_port(ipv4_info.address.unspec,
									 &ip_protocol_udp,
									 ip_hport(IKE_UDP_PORT));
		ip_sockaddr any_sa = sockaddr_from_endpoint(any_ep);
		if (bind(udp_sock, &any_sa.sa.sa, any_sa.len) < 0) {
			endpoint_buf eb;
			fatal_errno(PLUTO_EXIT_FAIL, logger, errno,
				    "bind(%s) failed in %s()",
				    str_endpoint(&any_ep, &eb), __func__);
		}
	}

	/*
	 * Load buf with array of raw interfaces from kernel.
	 *
	 * We have to guess at the upper bound (num).
	 * If we guess low, double num and repeat.
	 * But don't go crazy: stop before 1024**2.
	 *
	 * Tricky: num is a static so that we won't have to start from
	 * 64 in subsequent calls to find_raw_ifaces4.
	 */
	static int num = 64;
	struct ifconf ifconf;
	struct ifreq *buf = NULL;	/* for list of interfaces -- arbitrary limit */
	for (; num < (1024 * 1024); num *= 2) {
		/* Get num local interfaces.  See netdevice(7). */
		ifconf.ifc_len = num * sizeof(struct ifreq);

		free(buf);
		buf = malloc(ifconf.ifc_len);
		if (buf == NULL) {
			fatal_errno(PLUTO_EXIT_FAIL, logger, errno,
				    "malloc of %d in find_raw_ifaces4()",
				    ifconf.ifc_len);
		}
		memset(buf, 0xDF, ifconf.ifc_len);	/* stomp */
		ifconf.ifc_buf = (void *) buf;

		if (ioctl(udp_sock, SIOCGIFCONF, &ifconf) == -1) {
			fatal_errno(PLUTO_EXIT_FAIL, logger, errno,
				    "ioctl(SIOCGIFCONF) in find_raw_ifaces4()");
		}

		/* if we got back less than we asked for, we have them all */
		if (ifconf.ifc_len < (int)(sizeof(struct ifreq) * num))
			break;
	}

	/* Add an entry to rifaces for each interesting interface. */
	struct raw_iface *rifaces = NULL;
	for (int j = 0; (j + 1) * sizeof(struct ifreq) <= (size_t)ifconf.ifc_len; j++) {
		struct raw_iface ri;
		const struct sockaddr_in *rs =
			(struct sockaddr_in *) &buf[j].ifr_addr;
		struct ifreq auxinfo;

		/* build a NUL-terminated copy of the rname field */
		memcpy(ri.name, buf[j].ifr_name, IFNAMSIZ-1);
		ri.name[IFNAMSIZ-1] = '\0';
		dbg("Inspecting interface %s ", ri.name);

		/* ignore all but AF_INET interfaces */
		if (rs->sin_family != AF_INET) {
			dbg("Ignoring non AF_INET interface %s ", ri.name);
			continue; /* not interesting */
		}

		/* Find out stuff about this interface.  See netdevice(7). */
		zero(&auxinfo); /* paranoia */
		memcpy(auxinfo.ifr_name, buf[j].ifr_name, IFNAMSIZ-1);
		/* auxinfo.ifr_name[IFNAMSIZ-1] already '\0' */
		if (ioctl(udp_sock, SIOCGIFFLAGS, &auxinfo) == -1) {
			log_errno(logger, errno,
				  "Ignored interface %s - ioctl(SIOCGIFFLAGS) failed in find_raw_ifaces4()",
				  ri.name);
			continue; /* happens when using device with label? */
		}
		if (!(auxinfo.ifr_flags & IFF_UP)) {
			dbg("Ignored interface %s - it is not up", ri.name);
			continue; /* ignore an interface that isn't UP */
		}
#ifdef IFF_SLAVE
		/* only linux ... */
		if (auxinfo.ifr_flags & IFF_SLAVE) {
			dbg("Ignored interface %s - it is a slave interface", ri.name);
			continue; /* ignore slave interfaces; they share IPs with their master */
		}
#endif
		/* ignore unconfigured interfaces */
		if (rs->sin_addr.s_addr == 0) {
			dbg("Ignored interface %s - it is unconfigured", ri.name);
			continue;
		}

		ri.addr = address_from_in_addr(&rs->sin_addr);
		ipstr_buf b;
		dbg("found %s with address %s", ri.name, ipstr(&ri.addr, &b));
		ri.next = rifaces;
		rifaces = clone_thing(ri, "struct raw_iface");
	}

	free(buf);	/* was allocated via malloc() */
	close(udp_sock);
	return rifaces;
}

/* Called to handle --interface <ifname>
 * Semantics: if specified, only these (real) interfaces are considered.
 */

static const char *pluto_ifn[10];
static int pluto_ifn_roof = 0;

bool use_interface(const char *rifn)
{
	if (pluto_ifn_roof >= (int)elemsof(pluto_ifn)) {
		return false;
	} else {
		pluto_ifn[pluto_ifn_roof++] = rifn;
		return true;
	}
}
