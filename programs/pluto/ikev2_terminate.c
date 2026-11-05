/* shutdown connections: IKEv2
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

#include "ikev2_terminate.h"

#include "defs.h"
#include "verbose.h"
#include "log.h"
#include "state.h"
#include "connections.h"
#include "ikev2_delete.h"
#include "terminate.h"		/* for terminate_ike_family() */
#include "visit_connection.h"

extern connection_state_visitor terminate_ikev2_connection_states;

struct connection_state_visitor_context {
	unsigned count;
};

void terminate_ikev2_connection_states(struct connection *c,
					      struct ike_sa **ike,
					      struct child_sa **child,
					      enum connection_visit_kind visit_kind,
					      struct connection_state_visitor_context *context,
					      struct verbose verbose)
{
	if (context->count == 0) {
		vlog("terminating SAs using this connection");
	}
	context->count++;

	switch (visit_kind) {
	case NUDGE_CONNECTION_PRINCIPAL_IKE_SA:
	case NUDGE_CONNECTION_CROSSED_IKE_SA:
		/*
		 * Prepare the IKE SA for deletion.
		 *
		 * IKEv2 announces the death first.
		 */
		whack_attach(&(*ike)->sa, c->logger);
		(*ike)->sa.st_viable_parent = false;
		record_n_send_n_log_v2_delete(*ike, HERE);
		return;

	case VISIT_CONNECTION_CHILD_OF_PRINCIPAL_IKE_SA:
	case VISIT_CONNECTION_CHILD_OF_CROSSED_IKE_SA:
		PEXPECT(c->logger, ike != NULL);
		whack_attach(&(*child)->sa, c->logger);
		connection_teardown_child(child, REASON_DELETED, HERE);
		return;
	case VISIT_CONNECTION_CHILD_OF_CUCKOLD_IKE_SA:
		/*
		 * The IKE SA's state will become scrambled when the
		 * Cuckoo is deleted; hence delete the IKE SA.
		 */
		PEXPECT(c->logger, ike != NULL);
		whack_attach(&(*ike)->sa, c->logger);
		whack_attach(&(*child)->sa, c->logger);
		record_n_send_n_log_v2_delete(*ike, HERE);
		terminate_ike_family(ike, REASON_DELETED, verbose);
		return;

	case VISIT_CONNECTION_CHILD_OF_NONE:
		llog_pexpect(c->logger, HERE, "trying to teardown an orphan child");
		whack_attach(&(*child)->sa, c->logger);
		connection_teardown_child(child, REASON_DELETED, HERE);
		return;

	case VISIT_CONNECTION_LURKING_CHILD_SA:
		whack_attach(&(*child)->sa, c->logger);
		delete_child_sa(child);
		return;
	case VISIT_CONNECTION_LURKING_IKE_SA:
		/*
		 * For instance, a larval IKE SA, either stuck waiting
		 * for IKE_SA_INIT response crossed by the peer
		 * establishing the IKE SA.
		 *
		 * This will strip the connection of the IKE SA.  If
		 * the IKE SA has children then they too are deleted,
		 * but when would this be the case?
		 */
		whack_attach(&(*ike)->sa, c->logger);
		terminate_ike_family(ike, REASON_DELETED, verbose);
		return;

	case VISIT_CONNECTION_CUCKOO_OF_PRINCIPAL_IKE_SA:
		whack_attach(&(*child)->sa, c->logger);
		connection_teardown_child(child, REASON_DELETED, HERE);
		return;
	case VISIT_CONNECTION_CHILDLESS_PRINCIPAL_IKE_SA:
	{
		/*
		 * Since connection_teardown_child() was not
		 * dispatched the IKE SA gets to to the teardown.
		 *
		 * At this point the IKE SA should have no children.
		 */
		struct state_filter child = {
			.clonedfrom = (*ike)->sa.st_serialno,
			.search = {
				.order = NEW2OLD,
				.verbose.logger = c->logger,
				.where = HERE,
			},
		};
		if (next_state(&child)) {
			llog_pexpect(c->logger, child.search.where,
				     "IKE SA "PRI_SO" has unexpected Child SA "PRI_SO,
				     pri_so((*ike)->sa.st_serialno),
				     pri_so(child.st->st_serialno));
			/* get out of Dodge! */
			return;
		}
		connection_teardown_ike(ike, REASON_DELETED, HERE);
		return;
	}

	case FINISH_CONNECTION_PRINCIPAL_IKE_SA:
		delete_ike_sa(ike);
		return;
	}

	bad_case(visit_kind);
}

void terminate_all_ikev2_connection_states(struct connection *c, where_t where)
{
	struct connection_state_visitor_context context = {0};
	visit_connection_states(c, terminate_ikev2_connection_states, &context, where);
	/* caller must hold a reference */
	pmemory(c);
}
