/* shutdown connections: IKEv1/IKEv2
 *
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013-2019 Paul Wouters <pwouters@redhat.com>
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
#include "ike_alg.h"
#include "kernel_alg.h"
#include "plutoalg.h"
#include "ikev1_xauth.h"
#include "nat_traversal.h"


#include "host_pair.h"

static int terminate_a_connection(struct connection *c, void *unused_arg UNUSED, struct logger *logger)
{
	/* XXX: something better? */
	fd_delref(&c->logger->global_whackfd);
	c->logger->global_whackfd = fd_addref(logger->global_whackfd);

	llog(RC_LOG, c->logger,
	     "terminating SAs using this connection");
	dbg("%s() connection '%s' -POLICY_UP", __func__, c->name);
	c->policy &= ~POLICY_UP;
	remove_connection_from_pending(c);

	if (shared_phase1_connection(c)) {
		llog(RC_LOG, c->logger,
		     "IKE SA is shared - only terminating IPsec SA");
		if (c->newest_ipsec_sa != SOS_NOBODY) {
			struct state *st = state_by_serialno(c->newest_ipsec_sa);
			/* XXX: something better? */
			fd_delref(&st->st_logger->global_whackfd);
			st->st_logger->global_whackfd = fd_addref(logger->global_whackfd);
			delete_state(st);
		}
	} else {
		/*
		 * CK_INSTANCE is deleted simultaneous to deleting
		 * state :-/
		 */
		dbg("connection not shared - terminating IKE and IPsec SA");
		delete_states_by_connection(&c);
	}

	if (c != NULL) {
		/* XXX: something better? */
		fd_delref(&c->logger->global_whackfd);
	}

	return 1;
}

void terminate_connections_by_name(const char *name, bool quiet, struct logger *logger)
{
	/*
	 * Loop because more than one may match (template and
	 * instances).  But at least one is required (enforced by
	 * conn_by_name).  Don't log an error if not found before we
	 * checked aliases
	 */

	if (foreach_concrete_connection_by_name(name, terminate_a_connection, NULL, logger) >= 0) {
		/* logged by terminate_a_connection() */
		return;
	}

	int count = foreach_connection_by_alias(name, terminate_a_connection, NULL, logger);
	if (count == 0) {
		if (!quiet)
			llog(RC_UNKNOWN_NAME, logger,
			     "no such connection or aliased connection named \"%s\"", name);
	} else {
		llog(RC_COMMENT, logger,
			     "terminated %d connections from aliased connection \"%s\"",
		     count, name);
	}
}
