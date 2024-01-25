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
#include "ikev1.h"			/* for established_isakmp_for_state() */
#include "ikev1_delete.h"		/* for llog_n_maybe_send_v1_delete() */
#include "terminate.h"			/* for terminate_connection_states() */

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
	while (next_state(NEW2OLD, &sf)) {
		struct state *st = sf.st;
		if (st->st_connection != ike->sa.st_connection)
			return true;
	}

	return false;
}

static unsigned down_connection(struct connection *c, struct logger *logger)
{
	connection_attach(c, logger);

	/*
	 * Danger:
	 *
	 * Either of IKE and CHILD could be NULL.
	 *
	 * For IKEv1, when IKE is NULL the CHILD could have some other
	 * parent.
	 *
	 * XXX: should "down" down the routing_sa when ipsec_sa is
	 * NULL?
	 */
	struct ike_sa *ike = ike_sa_by_serialno(c->established_ike_sa);
	struct child_sa *child = child_sa_by_serialno(c->newest_ipsec_sa);

	if (shared_phase1_connection(ike)) {
		del_policy(c, policy.up);
		remove_connection_from_pending(c);
		llog(RC_LOG, c->logger, "%s is shared - only terminating %s",
		     c->config->ike_info->parent_sa_name,
		     c->config->ike_info->child_sa_name);
		if (child != NULL) {
			state_attach(&child->sa, logger);
			switch (c->config->ike_version) {
			case IKEv1:
			{
				/*
				 * IKE, above, may not be the best
				 * ISAKMP SA for this child!
				 */
				struct ike_sa *isakmp =
					established_isakmp_sa_for_state(&child->sa, /*viable-parent*/false);
				llog_n_maybe_send_v1_delete(isakmp, &child->sa, HERE);
				connection_delete_child(&child, HERE);
				break;
			}
			case IKEv2:
				/* apparently not!?! */
				PEXPECT(c->logger, ike->sa.st_serialno == child->sa.st_clonedfrom);
				submit_v2_delete_exchange(ike_sa(&child->sa, HERE), child);
				break;
			}
		}
	} else if (ike != NULL && ike->sa.st_ike_version == IKEv2) {
		llog(RC_LOG, c->logger, "terminating SAs using this connection");
		del_policy(c, policy.up);
		remove_connection_from_pending(c);
		PEXPECT(ike->sa.logger, IS_PARENT_SA_ESTABLISHED(&ike->sa));
		state_attach(&ike->sa, logger);
		submit_v2_delete_exchange(ike, NULL);
	} else {
		dbg("connection not shared - terminating IKE and IPsec SA");
		del_policy(c, policy.up);
		remove_connection_from_pending(c);
		terminate_all_connection_states(c, HERE);
	}

	/*
	 * XXX: hack so that when the caller delref()s the connection
	 * the magical deleting instance message appears on the
	 * console.
	 */
	if (is_instance(c) && refcnt_peek(c, c->logger) == 1) {
		ldbg(c->logger, "hack attack: skipping detach so that caller can log deleting instance");
		return 1;
	}

	connection_detach(c, logger);
	return 1;
}

static unsigned whack_down_connection(const struct whack_message *m UNUSED,
				      struct show *s, struct connection *c)
{
	del_policy(c, policy.up); /* XXX: where to put this? */

	unsigned nr = 0;
	switch (c->local->kind) {

	case CK_PERMANENT:
	case CK_INSTANCE:
	case CK_LABELED_PARENT:
		/* can delref C; caller still holds a ref */
		nr += down_connection(c, show_logger(s));
		return nr; /* the connection counts */

	case CK_LABELED_TEMPLATE:
	case CK_TEMPLATE:
	case CK_GROUP:
		nr += whack_connection_instance_new2old(m, s, c, whack_down_connection);
		return nr;

	case CK_LABELED_CHILD:
	{
		connection_buf cb;
		ldbg(show_logger(s), "skipping "PRI_CONNECTION,
		     pri_connection(c, &cb));
		return 0; /* the connection doesn't count */
	}

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

	/*
	 * Down aliases NEW2OLD.
	 *
	 * For subnets= the generated connections are brought up in
	 * the order they are generated (OLD2NEW).  This means that
	 * the first generated connection is made the IKE SA and
	 * further generated connections create Child SAs hanging off
	 * that IKE SA.  To ensure that the IKE SA is stripped of
	 * these Child SAs when it is taken down, the aliases are
	 * taken down in reverse order so that when the first
	 * generated connection is reached there is only that
	 * connection's IKE and Child SAs left.
	 *
	 * It seems to work ...
	 *
	 * What should happen is for the last Child SA to see that the
	 * IKE SA has -UP and initiate an IKE SA delete.
	 */

	whack_connection(m, s, whack_down_connection,
			 /*alias_order*/NEW2OLD,
			 (struct each) {
				 .future_tense = "terminating",
				 .past_tense = "terminated",
				 .log_unknown_name = true,
			 });
}
