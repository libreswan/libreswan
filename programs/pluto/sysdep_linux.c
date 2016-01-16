/*
 * routines that are Linux specific
 *
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2005-2006 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 David McCullough <david_mccullough@securecomputing.com>
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

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/if_addr.h>

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

#ifdef HAVE_BROKEN_POPEN
/*
 * including this may be acceptable on a system without a working popen
 * but a normal system should not need this, <errno.h> should cover it ;-)
 */
#include <asm-generic/errno.h>
#endif

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
	struct raw_iface *rifaces = NULL;
	int master_sock = safe_socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);        /* Get a UDP socket */

	/*
	 * Current upper bound on number of interfaces.
	 * Tricky: because this is a static, we won't have to start from
	 * 64 in subsequent calls.
	 */
	static int num = 64;

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

	/* Add an entry to rifaces for each interesting interface. */
	for (j = 0; (j + 1) * sizeof(struct ifreq) <= (size_t)ifconf.ifc_len;
	     j++) {
		struct raw_iface ri;
		const struct sockaddr_in *rs =
			(struct sockaddr_in *) &buf[j].ifr_addr;
		struct ifreq auxinfo;

		/* build a NUL-terminated copy of the rname field */
		memcpy(ri.name, buf[j].ifr_name, IFNAMSIZ);
		ri.name[IFNAMSIZ] = '\0';
		DBG(DBG_CONTROLMORE,
		    DBG_log("Inspecting interface %s ", ri.name));

		/* ignore all but AF_INET interfaces */
		if (rs->sin_family != AF_INET) {
			DBG(DBG_CONTROLMORE,
			    DBG_log("Ignoring non AF_INET interface %s ",
				    ri.name));
			continue; /* not interesting */
		}

		/* ignore if our interface names were specified, and this isn't one - for KLIPS/MAST only */
		if (pluto_ifn_roof != 0 &&
		    (kern_interface == USE_MASTKLIPS ||
		     kern_interface == USE_KLIPS)) {
			int i;

			DBG(DBG_CONTROLMORE,
			    DBG_log("interfaces= specified, applying filter"));

			for (i = 0; i != pluto_ifn_roof; i++)
				if (streq(ri.name, pluto_ifn[i])) {
					DBG(DBG_CONTROLMORE,
					    DBG_log("interface name '%s' found in interfaces= line",
						    ri.name));
					break;
				}

			if (i == pluto_ifn_roof) {
				DBG(DBG_CONTROLMORE,
				    DBG_log("interface name '%s' not present in interfaces= line - skipped",
					    ri.name));
				continue; /* not found -- skip */
			}
		}
		/* Find out stuff about this interface.  See netdevice(7). */
		zero(&auxinfo); /* paranoia */
		memcpy(auxinfo.ifr_name, buf[j].ifr_name, IFNAMSIZ);
		if (ioctl(master_sock, SIOCGIFFLAGS, &auxinfo) == -1) {
			exit_log_errno((e,
					"ioctl(SIOCGIFFLAGS) for %s in find_raw_ifaces4()",
					ri.name));
		}
		if (!(auxinfo.ifr_flags & IFF_UP)) {
			DBG(DBG_CONTROLMORE,
			    DBG_log("Ignored interface %s - it is not up",
				    ri.name));
			continue; /* ignore an interface that isn't UP */
		}
		if (auxinfo.ifr_flags & IFF_SLAVE) {
			DBG(DBG_CONTROLMORE,
			    DBG_log("Ignored interface %s - it is a slave interface",
				    ri.name));
			continue; /* ignore slave interfaces; they share IPs with their master */
		}

		/* ignore unconfigured interfaces */
		if (rs->sin_addr.s_addr == 0) {
			DBG(DBG_CONTROLMORE,
			    DBG_log("Ignored interface %s - it is unconfigured",
				    ri.name));
			continue;
		}

		happy(initaddr((const void *)&rs->sin_addr,
			       sizeof(struct in_addr),
			       AF_INET, &ri.addr));

		DBG(DBG_CONTROLMORE, {
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

struct raw_iface *find_raw_ifaces6(void)
{

	/* Get list of interfaces with IPv6 addresses from system from /proc/net/if_inet6).
	 *
	 * Documentation of format?
	 * RTFS: linux-2.2.16/net/ipv6/addrconf.c:iface_proc_info()
	 *       linux-2.4.9-13/net/ipv6/addrconf.c:iface_proc_info()
	 *
	 * Sample from Gerhard's laptop:
	 *	00000000000000000000000000000001 01 80 10 80       lo
	 *	30490009000000000000000000010002 02 40 00 80   ipsec0
	 *	30490009000000000000000000010002 07 40 00 80     eth0
	 *	fe80000000000000025004fffefd5484 02 0a 20 80   ipsec0
	 *	fe80000000000000025004fffefd5484 07 0a 20 80     eth0
	 *
	 * Each line contains:
	 * - IPv6 address: 16 bytes, in hex, no punctuation
	 * - ifindex: 1-4 bytes, in hex
	 * - prefix_len: 1 byte, in hex
	 * - scope (e.g. global, link local): 1 byte, in hex
	 * - flags: 1 byte, in hex
	 * - device name: string, followed by '\n'
	 */
	struct raw_iface *rifaces = NULL;
	static const char proc_name[] = "/proc/net/if_inet6";
	FILE *proc_sock = fopen(proc_name, "r");

	if (proc_sock == NULL) {
		DBG(DBG_CONTROL, DBG_log("could not open %s", proc_name));
	} else {
		for (;; ) {
			struct raw_iface ri;
			unsigned short xb[8];           /* IPv6 address as 8 16-bit chunks */
			char sb[8 * 5];                 /* IPv6 address as string-with-colons */
			unsigned int if_idx;            /* proc field, not used */
			unsigned int plen;              /* proc field, not used */
			unsigned int scope;             /* proc field, used to exclude link-local */
			unsigned int dad_status;        /* proc field */
			/* ??? I hate and distrust scanf -- DHR */
			int r = fscanf(proc_sock,
				       "%4hx%4hx%4hx%4hx%4hx%4hx%4hx%4hx"
				       " %x %02x %02x %02x %20s\n",
				       xb + 0, xb + 1, xb + 2, xb + 3, xb + 4,
				       xb + 5, xb + 6, xb + 7,
				       &if_idx, &plen, &scope, &dad_status,
				       ri.name);

			/* ??? we should diagnose any problems */
			if (r != 13)
				break;

			/* ignore addresses with link local scope.
			 * From linux-2.4.9-13/include/net/ipv6.h:
			 * IPV6_ADDR_LINKLOCAL	0x0020U
			 * IPV6_ADDR_SCOPE_MASK	0x00f0U
			 */
			if ((scope & 0x00f0U) == 0x0020U)
				continue;

			if (dad_status & (IFA_F_TENTATIVE | IFA_F_DADFAILED))
				continue;

			snprintf(sb, sizeof(sb),
				 "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
				 xb[0], xb[1], xb[2], xb[3], xb[4], xb[5],
				 xb[6], xb[7]);

			happy(ttoaddr(sb, 0, AF_INET6, &ri.addr));

			if (!isunspecaddr(&ri.addr)) {
				DBG(DBG_CONTROL,
				    DBG_log("found %s with address %s",
					    ri.name, sb));
				ri.next = rifaces;
				rifaces = clone_thing(ri, "struct raw_iface");
			}
		}
		fclose(proc_sock);
	}

	return rifaces;
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

