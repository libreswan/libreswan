/* shutdown connections: IKEv1/IKEv2
 *
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2019-2023 Andrew Cagney <cagney@gnu.org>
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
#include "terminate.h"
#include "host_pair.h"

static int terminate_a_connection(struct connection *c, struct logger *logger)
{
	connection_attach(c, logger);

	llog(RC_LOG, c->logger,
	     "terminating SAs using this connection");
	del_policy(c, POLICY_UP);
	remove_connection_from_pending(c);

	if (shared_phase1_connection(c)) {
		llog(RC_LOG, c->logger,
		     "IKE SA is shared - only terminating IPsec SA");
		if (c->newest_ipsec_sa != SOS_NOBODY) {
			struct state *st = state_by_serialno(c->newest_ipsec_sa);
			state_attach(st, logger);
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

	connection_detach(c, logger); /* C could be NULL */

	return 1;
}

static bool terminate_connections_by_name(const char *name,
					  struct logger *logger)
{
	/*
	 * Find all the permenant/instance connections and terminate
	 * them.  This means skipping over group and template
	 * connections.
	 */

	struct connection_filter cq = {
		.name = name,
		.where = HERE,
	};
	bool found = false;
	while (next_connection_old2new(&cq)) {
		struct connection *c = cq.c;
		if (never_negotiate(c)) {
			continue;
		}
		if (!is_permanent(c) && !is_instance(c)) {
			/* something real */
			continue;
		}
		found = true;
		terminate_a_connection(c, logger);
	}
	return found;
}

static int terminate_connections_by_alias(const char *alias, struct logger *logger)
{
	int count = 0;

	struct connection_filter by_alias = {
		.alias = alias,
		.where = HERE,
	};
	while (next_connection_new2old(&by_alias)) {
		struct connection *p = by_alias.c;
		count += terminate_a_connection(p, logger);
	}

	if (count > 0) {
		llog(RC_COMMENT, logger,
		     "terminated %d connections from aliased connection \"%s\"",
		     count, alias);
	}

	return count;
}

void terminate_connections_by_name_or_alias(const char *name, struct logger *logger)
{
	/*
	 * Loop because more than one may match (template and
	 * instances).  But at least one is required (enforced by
	 * conn_by_name).  Don't log an error if not found before we
	 * checked aliases
	 */
	if (terminate_connections_by_name(name, logger)) {
		/* logged by terminate_a_connection() */
		return;
	}

	terminate_connections_by_alias(name, logger);
}

static void terminate_connection(struct connection **c, struct logger *logger)
{
	connection_attach(*c, logger);

	llog(RC_LOG, (*c)->logger, "terminating SAs using this connection");
	del_policy(*c, POLICY_UP);
	remove_connection_from_pending(*c);

	switch ((*c)->config->ike_version) {
	case IKEv1:
		if (shared_phase1_connection(*c)) {
			llog(RC_LOG, (*c)->logger,
			     "IKE SA is shared - only terminating IPsec SA");
			if ((*c)->newest_ipsec_sa != SOS_NOBODY) {
				struct state *st = state_by_serialno((*c)->newest_ipsec_sa);
				state_attach(st, logger);
				delete_state(st);
			}
		} else {
			/*
			 * CK_INSTANCE is deleted simultaneous to deleting
			 * state :-/
			 */
			dbg("connection not shared - terminating IKE and IPsec SA");
			delete_states_by_connection(c);
		}
		break;
	case IKEv2:
		if (shared_phase1_connection(*c)) {
			llog(RC_LOG, (*c)->logger,
			     "IKE SA is shared - only terminating IPsec SA");
			struct child_sa *child = child_sa_by_serialno((*c)->newest_ipsec_sa);
			if (child != NULL) {
				state_attach(&child->sa, logger);
				connection_delete_child(ike_sa(&child->sa, HERE),
							&child, HERE);
			}
		} else {
			/*
			 * CK_INSTANCE is deleted simultaneous to deleting
			 * state :-/
			 */
			dbg("connection not shared - terminating IKE and IPsec SA");
			delete_states_by_connection(c);
		}
		break;
	}

	connection_detach(*c, logger);
}

void terminate_connections(struct connection **c, struct logger *logger, where_t where)
{

	switch ((*c)->local->kind) {
	case CK_PERMANENT:
		if ((*c)->config->ike_version == IKEv1) {
			terminate_a_connection(*c, logger); /* could delete C! */
			return;
		}
		terminate_connection(c, logger);
		return;
	case CK_INSTANCE:
	case CK_LABELED_PARENT:
	case CK_LABELED_CHILD: /* should not happen? */
		terminate_connection(c, logger); /* could delete C! */
		return;
	case CK_TEMPLATE:
	case CK_GROUP:
	case CK_LABELED_TEMPLATE:
	{
		struct connection_filter cq = {
			.clonedfrom = *c,
			.where = HERE,
		};
		while (next_connection_old2new(&cq)) {
			terminate_connections(&cq.c, logger, where);
		}
		return;
	}
	case CK_INVALID:
		break;
	}
	bad_case((*c)->local->kind);
}
