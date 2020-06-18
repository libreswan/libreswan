/*
 * routines that are Linux specific
 *
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2005-2006 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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


#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
#include "rnd.h"
#include "id.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "timer.h"
#include "kernel.h"
#include "kernel_xfrm.h"
#include "packet.h"
#include "x509.h"
#include "log.h"
#include "server.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */
#include "keys.h"
#include "ip_address.h"
#include "ip_sockaddr.h"
#include "ip_info.h"
#include "iface.h"

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

static const char *pluto_ifn[10];
static int pluto_ifn_roof = 0;

static int cmp_iface(const void *lv, const void *rv)
{
	const struct raw_iface *const *ll = lv;
	const struct raw_iface *const *rr = rv;
	const struct raw_iface *l = *ll;
	const struct raw_iface *r = *rr;
	/* return l - r */
	int i;
	/* protocol */
	i = addrtypeof(&l->addr) - addrtypeof(&r->addr);
	if (i != 0) {
		return i;
	}
	/* loopback=0 < addr=1 < any=2 < invalid */
#define SCORE(I) (address_is_loopback(&I->addr) ? 0			\
		  : address_is_specified(&I->addr) ? 1			\
		  : address_is_any(&I->addr) ? 2			\
		  : 3/*invalid*/)
	i = SCORE(l) - SCORE(r);
	if (i != 0) {
		return i;
	}
#undef SCORE
	/* name */
	i = strcmp(l->name, r->name);
	if (i != 0) {
		return i;
	}
	/* address */
	i = addrcmp(&l->addr, &r->addr);
	if (i != 0) {
		return i;
	}
	/* Interface addresses don't have ports. */
	/* what else */
	dbg("interface sort not stable or duplicate");
	return 0;
}

static void sort_ifaces(struct raw_iface **rifaces)
{
	/* how many? */
	unsigned nr_ifaces = 0;
	for (struct raw_iface *i = *rifaces; i != NULL; i = i->next) {
		nr_ifaces++;
	}
	if (nr_ifaces == 0) {
		dbg("no interfaces to sort");
		return;
	}
	/* turn the list into an array */
	struct raw_iface **ifaces = alloc_things(struct raw_iface *, nr_ifaces,
						 "ifaces for sorting");
	ifaces[0] = *rifaces;
	for (unsigned i = 1; i < nr_ifaces; i++) {
		ifaces[i] = ifaces[i-1]->next;
	}
	/* sort */
	dbg("sorting %u interfaces", nr_ifaces);
	qsort(ifaces, nr_ifaces, sizeof(ifaces[0]), cmp_iface);
	/* turn the array back into a list */
	for (unsigned i = 0; i < nr_ifaces - 1; i++) {
		ifaces[i]->next = ifaces[i+1];
	}
	ifaces[nr_ifaces-1]->next = NULL;
	/* clean up and return */
	*rifaces = ifaces[0];
	pfree(ifaces);
}

struct raw_iface *find_raw_ifaces6(void)
{
	/* Get list of interfaces with IPv6 addresses from system from /proc/net/if_inet6).
	 *
	 * Documentation of format?
	 * RTFS: linux-2.2.16/net/ipv6/addrconf.c:iface_proc_info()
	 *       linux-2.4.9-13/net/ipv6/addrconf.c:iface_proc_info()
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
		dbg("could not open %s", proc_name);
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

			if (dad_status & (IFA_F_TENTATIVE
#ifdef IFA_F_DADFAILED
						| IFA_F_DADFAILED
#endif
				))
				continue;

			snprintf(sb, sizeof(sb),
				 "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
				 xb[0], xb[1], xb[2], xb[3], xb[4], xb[5],
				 xb[6], xb[7]);

			happy(ttoaddr_num(sb, 0, AF_INET6, &ri.addr));

			if (address_is_specified(&ri.addr)) {
				dbg("found %s with address %s",
				    ri.name, sb);
				ri.next = rifaces;
				rifaces = clone_thing(ri, "struct raw_iface");
			}
		}
		fclose(proc_sock);
		/*
		 * Sort the list by IPv6 address in assending order.
		 *
		 * XXX: The code then inserts these interfaces in
		 * _reverse_ order (why I don't know) - the loop-back
		 * interface ends up last.  Should the insert code
		 * (scattered between kernel_*.c files) instead
		 * maintain the "interfaces" structure?
		 */
		sort_ifaces(&rifaces);
	}

	return rifaces;
}

/* Called to handle --interface <ifname>
 * Semantics: if specified, only these (real) interfaces are considered.
 */
bool use_interface(const char *rifn)
{
	if (pluto_ifn_roof >= (int)elemsof(pluto_ifn)) {
		return FALSE;
	} else {
		pluto_ifn[pluto_ifn_roof++] = rifn;
		return TRUE;
	}
}

