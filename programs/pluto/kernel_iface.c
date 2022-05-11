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
 */

#include <sys/ioctl.h>
#include <net/if.h>

#include "socketwrapper.h"		/* for safe_sock() */

#include "ip_info.h"

#include "defs.h"
#include "log.h"
#include "kernel_iface.h"

/*
 * Process the updated list of interfaces.
 *
 * On linux, see netdevice(7) (and note that it clearly documents that
 * the below code only works with IPv4).
 *
 * On BSD, see netintro(4).  On BSD, <<struct ifreq>> includes
 * sockaddr_storage in its union of addresses and that is big enough
 * for any address so this should also work for IPv6.
 */

/*
 * Process the updated list of interfaces.
 *
 * On linux, see netdevice(7) (and note that it clearly documents that
 * the below code only works with IPv4).
 *
 * On BSD, see netintro(4).  On BSD, <<struct ifreq>> includes
 * sockaddr_storage in its union of addresses and that is big enough
 * for any address so this should also work for IPv6.
 */

struct raw_iface *find_raw_ifaces(struct logger *logger)
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
	 * We have to guess at the upper bound (num).  If we guess
	 * low, double num and repeat.  But don't go crazy: stop
	 * before 1024**2.
	 *
	 * Tricky: num is a static so that we won't have to start from
	 * 64 in subsequent calls to find_raw_ifaces4.
	 */
	static int num = 64;
	struct ifconf ifconf = { .ifc_len = 0, };
	void *buf = NULL;	/* for list of interfaces -- arbitrary limit */
	for (; num < (1024 * 1024); num *= 2) {
		/* Get num local interfaces.  See netdevice(7). */
		int len = num * sizeof(struct ifreq);
		realloc_bytes(&buf, ifconf.ifc_len, len, "ifreq");

		ifconf = (struct ifconf) {
			.ifc_len = len,
			.ifc_buf = (void*)buf,
		};

		if (ioctl(udp_sock, SIOCGIFCONF, &ifconf) == -1) {
			fatal_errno(PLUTO_EXIT_FAIL, logger, errno,
				    "ioctl(SIOCGIFCONF) in find_raw_ifaces4()");
		}

		/* if we got back less than we asked for, we have them all */
		if (ifconf.ifc_len < len) {
			break;
		}
	}

	/* Add an entry to rifaces for each interesting interface. */
	struct raw_iface *rifaces = NULL;
	for (const struct ifreq *ifr = ifconf.ifc_req;
	     ifr < ifconf.ifc_req + (ifconf.ifc_len / sizeof(struct ifreq));
	     ifr++) {

		/* build a NUL-terminated copy of the rname field */
		char ifname[IFNAMSIZ + 1];
		memcpy(ifname, ifr->ifr_name, IFNAMSIZ);
		ifname[IFNAMSIZ] = '\0';
		dbg("Inspecting interface %s ", ifname);

		/* ignore all but AF_INET interfaces */
		if (ifr->ifr_addr.sa_family != AF_INET) {
			dbg("Ignoring non AF_INET interface %s ", ifname);
			continue; /* not interesting */
		}

		/* Find out stuff about this interface.  See netdevice(7). */
		struct ifreq auxinfo = {0};
		passert(sizeof(auxinfo.ifr_name) == sizeof(ifr->ifr_name)); /* duh! */
		memcpy(auxinfo.ifr_name, ifr->ifr_name, IFNAMSIZ);
		if (ioctl(udp_sock, SIOCGIFFLAGS, &auxinfo) == -1) {
			log_errno(logger, errno,
				  "Ignored interface %s - ioctl(SIOCGIFFLAGS) failed in find_raw_ifaces4()",
				  ifname);
			continue; /* happens when using device with label? */
		}
		if (!(auxinfo.ifr_flags & IFF_UP)) {
			dbg("Ignored interface %s - it is not up", ifname);
			continue; /* ignore an interface that isn't UP */
		}
#ifdef IFF_SLAVE
		/* only linux ... */
		if (auxinfo.ifr_flags & IFF_SLAVE) {
			dbg("Ignored interface %s - it is a slave interface", ifname);
			continue; /* ignore slave interfaces; they share IPs with their master */
		}
#endif
		/* ignore unconfigured interfaces */
		const struct sockaddr_in *rs = (const struct sockaddr_in *) &ifr->ifr_addr;
		if (rs->sin_addr.s_addr == 0) {
			dbg("Ignored interface %s - it is unconfigured", ifname);
			continue;
		}

		struct raw_iface *ri = overalloc_thing(struct raw_iface,
						       strlen(ifname) + 1,
						       "iface");
		ri->addr = address_from_in_addr(&rs->sin_addr);
		strcpy(ri->name, ifname);
		ri->next = rifaces;
		rifaces = ri;
		ipstr_buf b;
		dbg("found %s with address %s", ri->name, ipstr(&ri->addr, &b));
	}

	pfree(buf);
	close(udp_sock);
	return rifaces;
}
