/*
 * routines that are FreeBSD specific
 *
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
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

#include "defs.h"
#include "iface.h"			/* for add_or_keep_iface_dev() */
#include "kernel_iface.h"
#include "log.h"

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

/*
 * there is a BSD way to do this, probably SIOCGCONF
 */
struct raw_iface *find_raw_ifaces6(struct logger *logger UNUSED)
{
	return NULL;
}

/*
 * XXX: the BSD and Linux versions of this function are close to
 * identical.
 *
 * Notable differences:
 *
 * - linux honours --listen
 */

void process_raw_ifaces(struct raw_iface *rifaces, struct logger *logger)
{
	struct raw_iface *ifp;

	for (ifp = rifaces; ifp != NULL; ifp = ifp->next) {
		bool after = false;	/* has vfp passed ifp on the list? */
		bool bad = false;
		struct raw_iface *vfp;

		for (vfp = rifaces; vfp != NULL; vfp = vfp->next) {
			if (vfp == ifp) {
				after = true;
			} else if (sameaddr(&ifp->addr, &vfp->addr)) {
				if (after) {
					ipstr_buf b;

					llog(RC_LOG_SERIOUS, logger,
					            "IP interfaces %s and %s share address %s!",
					       ifp->name, vfp->name,
					       ipstr(&ifp->addr, &b));
				}
				bad = true;
				/* continue just to find other duplicates */
			}
		}

		if (bad)
			continue;

		/*
		 * We've got all we need; see if this is a new thing:
		 * search old interfaces list.
		 */
		add_or_keep_iface_dev(ifp, logger);
	}

	/* delete the raw interfaces list */
	while (rifaces != NULL) {
		struct raw_iface *t = rifaces;

		rifaces = t->next;
		pfree(t);
	}
}
