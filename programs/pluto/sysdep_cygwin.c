/*
 * routines that are WIN2K specific
 *
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
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
 */

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/utsname.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libreswan.h>

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
#include "kernel_netlink.h"
#include "kernel_pfkey.h"
#include "kernel_noklips.h"
#include "packet.h"
#include "x509.h"
#include "log.h"
#include "server.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */
#include "keys.h"

/*
 * invoke the updown script to do the routing and firewall commands required
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

/* Called to handle --interface <ifname>
 * Semantics: if specified, only these (real) interfaces are considered.
 */
bool use_interface(const char *rifn)
{
	struct raw_iface *ri;
	static int ifnum = 0;
	err_t e;

	if (pluto_ifn_inst[0] == '\0')
		pluto_ifn_inst = clone_str(rifn, "genifn");

	ri = alloc_thing(*ri, "static interface");

	e = ttoaddr(rifn, strlen(rifn), AF_UNSPEC, &ri->addr);
	if (e != NULL) {
		fprintf(stderr, "--interface failed: %s\n", e);
		exit(10);
	}
	snprintf(ri->name, sizeof(ri->name), "ifn%d", ifnum++);

	ri->next = static_ifn;
	static_ifn = ri;

	return TRUE;
}

