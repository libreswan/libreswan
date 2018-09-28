/* shutdown connections: IKEv1/IKEv2
 *
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Paul Wouters <pwouters@redhat.com>
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
#include "libreswan/pfkeyv2.h"

#include "sysdep.h"
#include "constants.h"
#include "lswalloc.h"
#include "id.h"
#include "x509.h"
#include "certs.h"

#include "defs.h"
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
#include "whack.h"
#include "alg_info.h"
#include "spdb.h"
#include "ike_alg.h"
#include "kernel_alg.h"
#include "plutoalg.h"
#include "ikev1_xauth.h"
#include "nat_traversal.h"

#include "virtual.h"	/* needs connections.h */

#include "hostpair.h"

static int terminate_a_connection(struct connection *c, void *arg UNUSED)
{
	set_cur_connection(c);
	libreswan_log("terminating SAs using this connection");
	c->policy &= ~POLICY_UP;
	flush_pending_by_connection(c);

	if (shared_phase1_connection(c)) {
		libreswan_log("IKE SA is shared - only terminating IPsec SA");
		if (c->newest_ipsec_sa != SOS_NOBODY) {
			struct state *st = state_with_serialno(c->newest_ipsec_sa);
			set_cur_state(st);
			delete_state(st);
		}
	} else {
		DBG(DBG_CONTROL, DBG_log("connection not shared - terminating IKE and IPsec SA"));
		delete_states_by_connection(c, FALSE);
	}

	reset_cur_connection();

	return 1;
}

void terminate_connection(const char *name)
{
	/*
	 * Loop because more than one may match (master and instances)
	 * But at least one is required (enforced by conn_by_name).
	 * Don't log an error if not found before we checked aliases
	 */
	struct connection *c = conn_by_name(name, TRUE, TRUE);

	if (c != NULL) {
		while (c != NULL) {
			struct connection *n = c->ac_next; /* grab this before c might disappear */

			if (streq(c->name, name) &&
			    c->kind >= CK_PERMANENT &&
			    !NEVER_NEGOTIATE(c->policy))
				(void) terminate_a_connection(c, NULL);
			c = n;
		}
	} else {
		int count = foreach_connection_by_alias(name, terminate_a_connection, NULL);
		if (count == 0) {
			loglog(RC_UNKNOWN_NAME,
				  "no such connection or aliased connection named \"%s\"", name);
		} else {
			loglog(RC_COMMENT, "terminated %d connections from aliased connection \"%s\"",
				count, name);
		}
	}
}
