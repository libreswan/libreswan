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
#include "pluto_stats.h"

void terminate_all_ikev1_connection_states(struct connection *c, where_t where)
{
	struct verbose verbose = VERBOSE(DEBUG_STREAM, c->logger, NULL);
	verbose.where = where;

	/*
	 * Pass 1: mark all ISAKMP SAs as non-viable.
	 *
	 * This is to stop the Child SAs trying to use the IKE SA when
	 * it finds it's been taken down.  Shouldn't happen as the
	 * connection is "down" but play it safe.
	 */

	struct state_filter viable_parent = {
		.kind = IKE_SA,
		.connection_serialno = c->serialno,
		.search = {
			.order = NEW2OLD,
			.verbose = verbose,
			.where = HERE,
		},
	};
	while (next_state(&viable_parent)) {
		whack_attach(viable_parent.st, c->logger);
		viable_parent.st->st_viable_parent = false;
	}

	/*
	 * Pass 2: terminate children.
	 *
	 * With IKEv1, IPsec and ISAKMP SAs are deleted separately.
	 * Children go first so that they can use the parent to send
	 * the delete notification.
	 *
	 * Because code can't assume order of states, pick away at the
	 * list.
	 */

	bool logged_child = false;
	while (true) {
		struct state_filter child = {
			.kind = CHILD_SA,
			.connection_serialno = c->serialno,
			.search = {
				.order = NEW2OLD,
				.verbose = verbose,
				.where = HERE,
			},
		};
		if (!next_state(&child)) {
			break;
		}

		if (!logged_child) {
			vlog("terminating %ss using this connection",
			     c->config->ike_info->child_sa_name);
		}

		struct child_sa *ipsec = pexpect_child_sa(child.st);
		whack_attach(&ipsec->sa, c->logger);
		struct ike_sa *isakmp = /* could be NULL */
			established_isakmp_sa_for_state(&ipsec->sa,
							/*viable-parent*/false);
		/* IKEv1 has cuckoos; call handles NULL */
		llog_n_maybe_send_v1_delete(isakmp, &ipsec->sa, HERE);
		connection_teardown_child(&ipsec, REASON_DELETED, HERE);
		vassert(ipsec == NULL);
	}

	/*
	 * Pass 3: terminate parents.
	 *
	 * With IKEv1, IPsec and ISAKMP SAs are deleted separately.
	 * Children go first so that they can use the parent to send
	 * the delete notification.
	 *
	 * Because code can't assume order of states, pick away at the
	 * list.
	 */

	bool logged_parent = false;
	while (true) {
		struct state_filter parent = {
			.kind = IKE_SA,
			.connection_serialno = c->serialno,
			.search = {
				.order = NEW2OLD,
				.verbose = verbose,
				.where = HERE,
			},
		};
		if (!next_state(&parent)) {
			break;
		}

		if (!logged_parent) {
			vlog("terminating %ss using this connection",
			     c->config->ike_info->parent_sa_name);
		}

		struct ike_sa *isakmp = pexpect_parent_sa(parent.st);
		struct ike_sa *transport =
			established_isakmp_sa_for_state(parent.st,
							/*viable-parent*/false);
		llog_n_maybe_send_v1_delete(transport, parent.st, HERE);
		connection_teardown_ike(&isakmp, REASON_DELETED, HERE);
		vassert(isakmp == NULL);
	}

	/* caller must hold a reference */
	pmemory(c);
}

static void terminate_v1_child(struct ike_sa **ike, struct child_sa *child,
			       struct verbose verbose)
{
	/*
	 * With IKEv1, deleting an ISAKMP SA only deletes larval
	 * children.  Any established children are released to the
	 * wild.
	 */
	if (IS_IPSEC_SA_ESTABLISHED(&child->sa)) {
		vdbg("letting established IPsec SA "PRI_SO" go wild",
		     pri_so(child->sa.st_serialno));
	} else {
		/*
		 * Attach the IKE SA's whack to the child so that the
		 * child can also log its demise.
		 */
		vdbg("deleting larval IPsec SA "PRI_SO,
		     pri_so(child->sa.st_serialno));
		whack_attach(&child->sa, (*ike)->sa.logger);
		delete_child_sa(&child);
	}
}

void terminate_ikev1_family(struct ike_sa **ike,
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
		terminate_v1_child(ike, child, verbose);
	}

	/* delete self */
	connection_teardown_ike(ike, reason, verbose.where);
}

void connection_delete_v1_state(struct state **st, where_t where)
{
	PEXPECT((*st)->logger, (*st)->st_ike_version == IKEv1);
	if (IS_PARENT_SA(*st)) {
		struct ike_sa *ike = pexpect_parent_sa(*st);
		connection_teardown_ike(&ike, REASON_DELETED, where);
	} else {
		struct child_sa *child = pexpect_child_sa(*st);
		connection_teardown_child(&child, REASON_DELETED, where);
	}
	(*st) = NULL;
}
