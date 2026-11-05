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
#include "pluto_stats.h"

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
		terminate_ikev2_family(ike, REASON_DELETED, verbose);
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
		terminate_ikev2_family(ike, REASON_DELETED, verbose);
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

static void terminate_v2_child(struct ike_sa **ike, struct child_sa *child,
			       enum terminate_reason reason,
			       struct verbose verbose)
{

	/*
	 * With IKEv2, deleting an IKE SA deletes all children; the
	 * only question is how.
	 *
	 * If the child owns the connection's routing then it needs to
	 * be dispatched; else it can simply be deleted.
	 */
	whack_attach(&child->sa, (*ike)->sa.logger);

	/* redundant */
	on_delete(&child->sa, skip_send_delete);
	on_delete(&child->sa, skip_log_message);
	struct connection *cc = child->sa.st_connection;

	if (cc->established_child_sa == child->sa.st_serialno) {
		PEXPECT((*ike)->sa.logger, IS_IPSEC_SA_ESTABLISHED(&child->sa));
		/* will delete child and its logger */
		vdbg("teardown established Child SA "PRI_SO,
		     pri_so(child->sa.st_serialno));
		connection_teardown_child(&child, reason, verbose.where);
		return;
	}

	if (IS_IPSEC_SA_ESTABLISHED(&child->sa)) {
		/*
		 * Presumably the Child SA lost ownership; or never
		 * gained it.
		 */
		llog_sa(RC_LOG, child, "deleting lingering %s",
			child->sa.st_connection->config->ike_info->parent_sa_name);
		delete_child_sa(&child);
		return;
	}

	if (cc->negotiating_child_sa == child->sa.st_serialno) {
		/* will delete child and its logger */
		vdbg("teardown larval Child SA "PRI_SO,
		     pri_so(child->sa.st_serialno));
		connection_teardown_child(&child, reason, verbose.where);
		return;
	}

	if (IS_IKE_SA_ESTABLISHED(&(*ike)->sa)) {
		/*
		 * The IKE SA is established; log any larval children
		 * (presumably from a CREATE_CHILD_SA exchange).
		 */
		llog_sa(RC_LOG, child, "deleting larval %s",
			child->sa.st_connection->config->ike_info->child_sa_name);
		delete_child_sa(&child);
		return;
	}

	vdbg("delete Child SA "PRI_SO,
	     pri_so(child->sa.st_serialno));
	delete_child_sa(&child);
}

void terminate_ikev2_family(struct ike_sa **ike,
			    enum terminate_reason reason,
			    struct verbose verbose)
{
	vdbg("%s()", __func__);
	verbose.level++;
	pstat_sa_failed(&(*ike)->sa, reason);

	vdbg("IKE SA "PRI_SO" is no longer viable",
	     pri_so((*ike)->sa.st_serialno));
	(*ike)->sa.st_viable_parent = false;

	/*
	 * When the IKE SA's connection has a direct Child SA (i.e.,
	 * shares connection) that owns the route then teardown that
	 * Child SA first.
	 *
	 * This way the IKE SA's connection can jump to the front of
	 * the revival queue (without this an IKE SA with multiple
	 * children ends up with its children squabbling over which SA
	 * should be revived first).
	 *
	 * When this isn't the case, the for-each-child will instead
	 * do the terminating.
	 */

	struct child_sa *connection_child = child_sa_by_serialno((*ike)->sa.st_connection->negotiating_child_sa);
	if (connection_child == NULL) {
		vdbg("IKE SA "PRI_SO"'s connection has no Child SA "PRI_SO,
		     pri_so((*ike)->sa.st_serialno),
		     pri_so((*ike)->sa.st_connection->negotiating_child_sa));
	} else if (connection_child->sa.st_clonedfrom != (*ike)->sa.st_serialno) {
		vdbg("IKE SA "PRI_SO"' is not the parent of the connection's Child SA "PRI_SO,
		     pri_so((*ike)->sa.st_serialno),
		     pri_so(connection_child->sa.st_serialno));
		connection_child = NULL;
	} else {
		vdbg("dispatching delete to IKE SA "PRI_SO"'s Child SA "PRI_SO,
		     pri_so((*ike)->sa.st_serialno),
		     pri_so(connection_child->sa.st_serialno));
		whack_attach(&connection_child->sa, (*ike)->sa.logger);
		/* will delete child and its logger */
		connection_teardown_child(&connection_child, reason,
					  verbose.where); /* always dispatches here*/
		PEXPECT((*ike)->sa.logger, connection_child == NULL); /*gone!*/
		PEXPECT((*ike)->sa.logger, (*ike)->sa.st_connection->negotiating_child_sa == SOS_NOBODY);
		PEXPECT((*ike)->sa.logger, (*ike)->sa.st_connection->established_child_sa == SOS_NOBODY);
	}

	/*
	 * We are a parent: prune any remaining children and then
	 * prepare to delete ourself.
	 */

	struct state_filter cf = {
		.clonedfrom = (*ike)->sa.st_serialno,
		.search = {
			.order = NEW2OLD,
			.verbose.logger = (*ike)->sa.logger,
			.where = HERE,
		},
	};
	while(next_state(&cf)) {
		struct child_sa *child = pexpect_child_sa(cf.st);
		terminate_v2_child(ike, child, reason, verbose);
	}

	/* delete self */
	connection_teardown_ike(ike, reason, verbose.where);
}
