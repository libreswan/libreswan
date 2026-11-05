/* shutdown connections: IKEv1
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

#include "ikev1_terminate.h"

#include "defs.h"
#include "log.h"
#include "state.h"
#include "connections.h"
#include "ikev1.h"
#include "ikev1_delete.h"
#include "visit_connection.h"

extern connection_state_visitor terminate_ikev1_connection_states;

struct connection_state_visitor_context {
	unsigned count;
};

void terminate_ikev1_connection_states(struct connection *c,
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
		 * IKEv1 announces the death of the ISAKMP SA after
		 * all the children have gone (reverse of IKEv2).
		 */
		whack_attach(&(*ike)->sa, c->logger);
		(*ike)->sa.st_viable_parent = false;
		return;

	case VISIT_CONNECTION_CHILD_OF_PRINCIPAL_IKE_SA: /* ignore IKE */
	case VISIT_CONNECTION_CHILD_OF_CUCKOLD_IKE_SA:
	case VISIT_CONNECTION_CHILD_OF_NONE:
	case VISIT_CONNECTION_CHILD_OF_CROSSED_IKE_SA:
	{
		/*
		 * Can't always assume IKE is suitable for sending
		 * deletes: for CHILD it probably is; and for CUCKOO
		 * it is NULL.
		 *
		 * Hence just always re-compute it.
		 */
		whack_attach(&(*child)->sa, c->logger);
		struct ike_sa *isakmp = /* could be NULL */
			established_isakmp_sa_for_state(&(*child)->sa, /*viable-parent*/false);
		/* IKEv1 has cuckoos */
		llog_n_maybe_send_v1_delete(isakmp, &(*child)->sa, HERE);
		connection_teardown_child(child, REASON_DELETED, HERE);
		return;
	}

	case VISIT_CONNECTION_LURKING_CHILD_SA:
		whack_attach(&(*child)->sa, c->logger);
		connection_teardown_child(child, REASON_DELETED, HERE);
		return;
	case VISIT_CONNECTION_LURKING_IKE_SA:
		whack_attach(&(*ike)->sa, c->logger);
		delete_ike_sa(ike);
		return;

	case VISIT_CONNECTION_CUCKOO_OF_PRINCIPAL_IKE_SA:
		/*
		 * When IKEv1 deletes an IKE SA any siblings are
		 * orphaned.
		 */
		return;
	case VISIT_CONNECTION_CHILDLESS_PRINCIPAL_IKE_SA:
		/*
		 * When IKEv1 deletes an IKE SA it always sends a
		 * delete notify; hence handle this in
		 * FINISH_CONNECTION_PRINCIPAL_IKE_SA.
		 */
		return;

	case FINISH_CONNECTION_PRINCIPAL_IKE_SA:
	{
		struct ike_sa *isakmp =
			established_isakmp_sa_for_state(&(*ike)->sa, /*viable-parent*/false);
		llog_n_maybe_send_v1_delete(isakmp, &(*ike)->sa, HERE);
		connection_teardown_ike(ike, REASON_DELETED, HERE);
		return;
	}

	}
	bad_case(visit_kind);
}

void terminate_all_ikev1_connection_states(struct connection *c, where_t where)
{
	struct connection_state_visitor_context context = {0};
	visit_connection_states(c, terminate_ikev1_connection_states, &context, where);
	/* caller must hold a reference */
	pmemory(c);
}
