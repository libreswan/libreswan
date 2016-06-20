/*
 * routines that are OSX/darwin specific
 *
 * Copyright (C) 2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
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
 *
 *
 */

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libreswan.h>

#include "sysdep.h"
#include "socketwrapper.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
#include "rnd.h"
#include "id.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "timer.h"
#include "kernel.h"
#include "kernel_netlink.h"
#include "kernel_pfkey.h"
#include "kernel_noklips.h"
#include "packet.h"
#include "x509.h"
#include "log.h"
#include "server.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */
#include "keys.h"

/* for CIRCLEQ_ENTRY */
#include <sys/queue.h>

/* invoke the updown script to do the routing and firewall commands required
 *
 * The user-specified updown script is run.  Parameters are fed to it in
 * the form of environment variables.  All such environment variables
 * have names starting with "PLUTO_".
 *
 * The operation to be performed is specified by PLUTO_VERB.  This
 * verb has a suffix "-host" if the client on this end is just the
 * host; otherwise the suffix is "-client".  If the address family
 * of the host is IPv6, an extra suffix of "-v6" is added.
 *
 * "prepare-host" and "prepare-client" are used to delete a route
 * that may exist (due to forces outside of Pluto).  It is used to
 * prepare for pluto creating a route.
 *
 * "route-host" and "route-client" are used to install a route.
 * Since routing is based only on destination, the PLUTO_MY_CLIENT_*
 * values are probably of no use (using them may signify a bug).
 *
 * "unroute-host" and "unroute-client" are used to delete a route.
 * Since routing is based only on destination, the PLUTO_MY_CLIENT_*
 * values are probably of no use (using them may signify a bug).
 *
 * "up-host" and "up-client" are run when an eroute is added (not replaced).
 * They are useful for adjusting a firewall: usually for adding a rule
 * to let processed packets flow between clients.  Note that only
 * one eroute may exist for a pair of client subnets but inbound
 * IPsec SAs may persist without an eroute.
 *
 * "down-host" and "down-client" are run when an eroute is deleted.
 * They are useful for adjusting a firewall.
 */

#ifndef DEFAULT_UPDOWN
# define DEFAULT_UPDOWN "ipsec _updown"
#endif

static const char *pluto_ifn[10];
static int pluto_ifn_roof = 0;

struct raw_iface *find_raw_ifaces4(void)
{
	static const int on = TRUE;	/* by-reference parameter; constant, we hope */
	int j;	/* index into buf */
	struct ifconf ifconf;
	struct ifreq *buf = NULL;	/* for list of interfaces -- arbitrary limit */
	struct ifreq *bp;	/* cursor into buf */
	struct raw_iface *rifaces = NULL;
	int master_sock = safe_socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);        /* Get a UDP socket */

	/*
	 * Current upper bound on number of interfaces.
	 * Tricky: because this is a static, we won't have to start from
	 * 64 in subsequent calls.
	 */
	static int num = 64;	/* number of interfaces */

	/* get list of interfaces with assigned IPv4 addresses from system */

	if (master_sock == -1)
		exit_log_errno((e, "socket() failed in find_raw_ifaces4()"));

	if (setsockopt(master_sock, SOL_SOCKET, SO_REUSEADDR,
		       (const void *)&on, sizeof(on)) < 0)
		exit_log_errno((e, "setsockopt() in find_raw_ifaces4()"));

	/* bind the socket */
	{
		ip_address any;

		happy(anyaddr(AF_INET, &any));
		setportof(htons(pluto_port), &any);
		if (bind(master_sock, sockaddrof(&any),
			 sockaddrlenof(&any)) < 0)
			exit_log_errno((e,
					"bind() failed in find_raw_ifaces4()"));
	}

	/* a million interfaces is probably the maximum, ever... */
	for (; num < (1024 * 1024); num *= 2) {
		/* Get num local interfaces.  See netdevice(7). */
		ifconf.ifc_len = num * sizeof(struct ifreq);

		struct ifreq *tmpbuf = realloc(buf, ifconf.ifc_len);

		if (tmpbuf == NULL) {
			free(buf);
			exit_log_errno((e,
					"realloc of %d in find_raw_ifaces4()",
					ifconf.ifc_len));
		}
		buf = tmpbuf;
		memset(buf, 0xDF, ifconf.ifc_len);	/* stomp */
		ifconf.ifc_buf = (void *) buf;

		if (ioctl(master_sock, SIOCGIFCONF, &ifconf) == -1)
			exit_log_errno((e,
					"ioctl(SIOCGIFCONF) in find_raw_ifaces4()"));


		/* if we got back less than we asked for, we have them all */
		if (ifconf.ifc_len < (int)(sizeof(struct ifreq) * num))
			break;
	}

	/* Add an entry to rifaces for each interesting interface.
	   On Apple, the size of struct ifreq depends on the contents of
	   the union. See if.h */
	for (bp = buf, j = 0;
	     bp < (unsigned char *)buf + (size_t)ifconf.ifc_len;
	     bp = (struct ifreq *)
		((unsigned char *)bp +_SIZEOF_ADDR_IFREQ(*bp)),
	     j++) {
		struct raw_iface ri;
		const struct sockaddr_in *rs =
			(struct sockaddr_in *) &bp->ifr_addr;
		struct ifreq auxinfo;

		/* ignore all but AF_INET interfaces */
		if (rs->sin_family != AF_INET)
			continue; /* not interesting */

		/* build a NUL-terminated copy of the rname field */
		memcpy(ri.name, bp->ifr_name, IFNAMSIZ);
		ri.name[IFNAMSIZ] = '\0';

		/* ignore if our interface names were specified, and this isn't one */
		if (pluto_ifn_roof != 0) {
			int i;

			for (i = 0; i != pluto_ifn_roof; i++)
				if (streq(ri.name, pluto_ifn[i]))
					break;
			if (i == pluto_ifn_roof)
				continue; /* not found -- skip */
		}

		/* Find out stuff about this interface.  See netdevice(7). */
		zero(&auxinfo); /* paranoia */
		memcpy(auxinfo.ifr_name, bp->ifr_name, IFNAMSIZ);
		if (ioctl(master_sock, SIOCGIFFLAGS, &auxinfo) == -1) {
			exit_log_errno((e,
					"ioctl(SIOCGIFFLAGS) for %s in find_raw_ifaces4()",
					ri.name));
		}
		if (!(auxinfo.ifr_flags & IFF_UP))
			continue; /* ignore an interface that isn't UP */

		/* ignore unconfigured interfaces */
		if (rs->sin_addr.s_addr == 0)
			continue;

		happy(initaddr((const void *)&rs->sin_addr,
			       sizeof(struct in_addr),
			       AF_INET, &ri.addr));

		DBG(DBG_CONTROL, {
			ipstr_buf b;
			DBG_log("found %s with address %s",
				ri.name, ipstr(&ri.addr, &b));
		});
		ri.next = rifaces;
		rifaces = clone_thing(ri, "struct raw_iface");
	}

	free(buf);	/* was allocated via realloc() */
	close(master_sock);
	return rifaces;
}

/*
 * there is a BSD way to do this, probably SIOCGCONF
 */
struct raw_iface *find_raw_ifaces6(void)
{
	return NULL;
}

/* Called to handle --interface <ifname>
 * Semantics: if specified, only these (real) interfaces are considered.
 */
bool use_interface(const char *rifn)
{
	if (pluto_ifn_inst[0] == '\0')
		pluto_ifn_inst = clone_str(rifn, "genifn");

	if (pluto_ifn_roof >= (int)elemsof(pluto_ifn)) {
		return FALSE;
	} else {
		pluto_ifn[pluto_ifn_roof++] = rifn;
		return TRUE;
	}
}
