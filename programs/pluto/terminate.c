/* shutdown connections: IKEv1/IKEv2
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2008 Michael Richardson <mcr@xelerance.com>
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

#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libreswan.h>
#include <libreswan/ipsec_policy.h>
#include "libreswan/pfkeyv2.h"
#include "kameipsec.h"

#include "sysdep.h"
#include "constants.h"
#include "lswalloc.h"
#include "lswtime.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "secrets.h"

#include "defs.h"
#include "ac.h"
#ifdef XAUTH_HAVE_PAM
#include <security/pam_appl.h>
#endif
#include "connections.h"        /* needs id.h */
#include "pending.h"
#include "foodgroups.h"
#include "packet.h"
#include "demux.h"      /* needs packet.h */
#include "state.h"
#include "timer.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "server.h"
#include "kernel.h"     /* needs connections.h */
#include "log.h"
#include "keys.h"
#include "adns.h"       /* needs <resolv.h> */
#include "dnskey.h"     /* needs keys.h and adns.h */
#include "whack.h"
#include "alg_info.h"
#include "spdb.h"
#include "ike_alg.h"
#include "kernel_alg.h"
#include "plutoalg.h"
#include "xauth.h"
#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif

#include "virtual.h"

#include "hostpair.h"

static int terminate_a_connection(struct connection *c, void *arg UNUSED)
{
	set_cur_connection(c);
	libreswan_log("terminating SAs using this connection");
	c->policy &= ~POLICY_UP;
	flush_pending_by_connection(c);
	delete_states_by_connection(c, FALSE);
	reset_cur_connection();

	return 1;
}

void terminate_connection(const char *nm)
{
	/* Loop because more than one may match (master and instances)
	 * But at least one is required (enforced by con_by_name).
	 */
	struct connection *c, *n;
	int count;

	passert(nm != NULL);
	c = con_by_name(nm, TRUE);

	if (c) {
		for (; c != NULL; c = n) {
			n = c->ac_next; /* grab this before c might disappear */
			if (streq(c->name, nm) &&
			    c->kind >= CK_PERMANENT &&
			    !NEVER_NEGOTIATE(c->policy))
				(void) terminate_a_connection(c, NULL);
		}
		return;
	}

	loglog(RC_COMMENT, "terminating all conns with alias='%s'\n", nm);
	count = foreach_connection_by_alias(nm, terminate_a_connection, NULL);

	if (count == 0) {
		whack_log(RC_UNKNOWN_NAME,
			  "no connection named \"%s\"", nm);
	}
}
