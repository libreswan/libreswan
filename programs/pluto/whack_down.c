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

static bool shared_phase1_connection(struct ike_sa *ike)
{
	if (ike == NULL) {
		/* can't share what doesn't exist? */
		return false;
	}

	struct state_filter sf = {
		.clonedfrom = ike->sa.st_serialno,
		.where = HERE,
	};
	while (next_state_new2old(&sf)) {
		struct state *st = sf.st;
		if (st->st_connection != ike->sa.st_connection)
			return true;
	}

	return false;
}

static void down_connection(struct connection *c, struct logger *logger)
{
	connection_attach(c, logger);

	llog(RC_LOG, c->logger, "terminating SAs using this connection");
	del_policy(c, POLICY_UP);
	remove_connection_from_pending(c);

	/*
	 * Danger:
	 * Either of IKE and CHILD could be NULL.
	 *
	 * For IKEv1, when IKE is NULL the CHILD could have some other
	 * parent.
	 *
	 * XXX: should "down" down the routing_sa when ipsec_sa is
	 * NULL?
	 */
	struct ike_sa *ike = ike_sa_by_serialno(c->newest_ike_sa);
	struct child_sa *child = child_sa_by_serialno(c->newest_ipsec_sa);

	if (shared_phase1_connection(ike)) {
		llog(RC_LOG, c->logger, "%s is shared - only terminating %s",
		     c->config->ike_info->parent_sa_name,
		     c->config->ike_info->child_sa_name);
		if (child != NULL) {
			state_attach(&child->sa, logger);
			switch (c->config->ike_version) {
			case IKEv1:
				delete_state(&child->sa);
				break;
			case IKEv2:
				/* apparently not!?! */
				PEXPECT(c->logger, ike->sa.st_serialno == child->sa.st_clonedfrom);
				submit_v2_delete_exchange(ike_sa(&child->sa, HERE), child);
				break;
			}
		}
	} else {
		dbg("connection not shared - terminating IKE and IPsec SA");
		whack_delete_connection_states(c, HERE);
	}

	/*
	 * XXX: hack so that when the caller delref()s the connection
	 * the magical deleting instance message appears on the
	 * console.
	 */
	if (is_instance(c) && refcnt_peek(&c->refcnt) == 1) {
		ldbg(c->logger, "hack attack: skipping detach so that caller can log deleting instance");
		return;
	}

	connection_detach(c, logger);
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
		down_connection(c, logger);
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
