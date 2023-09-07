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

#include <stdbool.h>

#include "whack_down.h"
#include "whack_delete.h"
#include "connections.h"
#include "show.h"
#include "log.h"
#include "pending.h"
#include "whack_connection.h"
#include "ikev2_delete.h"

/*
 * Is a connection in use by some state?
 */

static bool shared_phase1_connection(const struct connection *c)
{
	so_serial_t serial_us = c->newest_ike_sa;

	if (serial_us == SOS_NOBODY)
		return false;

	struct state_filter sf = { .where = HERE, };
	while (next_state_new2old(&sf)) {
		struct state *st = sf.st;
		if (st->st_connection != c && st->st_clonedfrom == serial_us)
			return true;
	}

	return false;
}

static void down_connection(struct connection **cp, struct logger *logger)
{
	connection_attach((*cp), logger);

	llog(RC_LOG, (*cp)->logger, "terminating SAs using this connection");
	del_policy((*cp), POLICY_UP);

	remove_connection_from_pending((*cp));
	if (shared_phase1_connection((*cp))) {
		llog(RC_LOG, (*cp)->logger, "%s is shared - only terminating %s",
		     (*cp)->config->ike_info->parent_sa_name,
		     (*cp)->config->ike_info->child_sa_name);
		/*
		 * XXX: should "down" down the routing_sa when
		 * ipsec_sa is NULL?
		 */
		struct child_sa *child = child_sa_by_serialno((*cp)->newest_ipsec_sa);
		if (child != NULL) {
			state_attach(&child->sa, logger);
			switch ((*cp)->config->ike_version) {
			case IKEv1:
				delete_state(&child->sa);
				break;
			case IKEv2:
				submit_v2_delete_exchange(ike_sa(&child->sa, HERE), child);
				break;
			}
		}
	} else {
		dbg("connection not shared - terminating IKE and IPsec SA");
		whack_delete_connection_states((*cp), HERE);
	}

	/*
	 * XXX: hack so that when the caller delref()s the connection
	 * the magical deleting instance message appears on the
	 * console.
	 */
	if (is_instance((*cp)) && refcnt_peek(&(*cp)->refcnt) == 1) {
		ldbg((*cp)->logger, "hack attack: skipping detach so that caller can log deleting instance");
		return;
	}

	connection_detach((*cp), logger);
}

static unsigned whack_down_connections(const struct whack_message *m UNUSED,
				       struct show *s, struct connection *c)
{
	struct logger *logger = show_logger(s);
	connection_buf cb;
	switch (c->local->kind) {
	case CK_PERMANENT:
	case CK_INSTANCE:
	case CK_LABELED_PARENT:
		/* can delref C; caller still holds a ref */
		down_connection(&c, logger);
		return 1; /* the connection counts */
	case CK_TEMPLATE:
	case CK_GROUP:
	case CK_LABELED_TEMPLATE:
	case CK_LABELED_CHILD:
		ldbg(logger, "skipping "PRI_CONNECTION,
		     pri_connection(c, &cb));
		return 0; /* the connection doesn't count */
	case CK_INVALID:
		break;
	}
	bad_case(c->local->kind);
}

void whack_down(const struct whack_message *m, struct show *s)
{
	if (m->name == NULL) {
		/* leave bread crumb */
		whack_log(RC_FATAL, s,
			  "received command to terminate connection, but did not receive the connection name - ignored");
		return;
	}

	whack_connections_bottom_up(m, s, whack_down_connections,
				    (struct each) {
					    .future_tense = "terminating",
					    .past_tense = "terminated",
					    .log_unknown_name = true,
				    });
}
