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
#include "whack_connection.h"		/* for whack_connection() */
#include "ikev1_delete.h"
#include "ikev2_delete.h"
#include "pluto_stats.h"
#include "revival.h"

static void terminate_v1_states(struct connection *c,
				struct ike_sa **ike,
				struct child_sa **child,
				enum whack_state whacamole)
{
	switch (whacamole) {
	case WHACK_START_IKE:
		/*
		 * IKEv1 announces the death of the ISAKMP SA after
		 * all the children have gone (reverse of IKEv2).
		 */
		state_attach(&(*ike)->sa, c->logger);
		(*ike)->sa.st_viable_parent = false;
		return;
	case WHACK_LURKING_CHILD:
		state_attach(&(*child)->sa, c->logger);
		connection_teardown_child(child, REASON_DELETED, HERE);
		return;
	case WHACK_LURKING_IKE:
		state_attach(&(*ike)->sa, c->logger);
		delete_ike_sa(ike);
		return;
	case WHACK_CHILD:
	case WHACK_CUCKOO:
	{
		/*
		 * Can't always assume IKE is suitable for sending
		 * deletes: for CHILD it probably is; and for CUCKOO
		 * it is NULL.
		 *
		 * Hence just always re-compute it.
		 */
		state_attach(&(*child)->sa, c->logger);
		struct ike_sa *isakmp = /* could be NULL */
			established_isakmp_sa_for_state(&(*child)->sa, /*viable-parent*/false);
		/* IKEv1 has cuckoos */
		llog_n_maybe_send_v1_delete(isakmp, &(*child)->sa, HERE);
		connection_teardown_child(child, REASON_DELETED, HERE);
		return;
	}
	case WHACK_ORPHAN:
		/* IKEv1 has orphans */
		state_attach(&(*child)->sa, c->logger);
		PEXPECT(c->logger, ike == NULL);
		connection_teardown_child(child, REASON_DELETED, HERE);
		return;
	case WHACK_SIBLING:
		/*
		 * When IKEv1 deletes an IKE SA any siblings are
		 * orphaned.
		 */
		return;
	case WHACK_IKE:
		/*
		 * When IKEv1 deletes an IKE SA it always sends a
		 * delete notify; hence handle this in WHACK_STOP_IKE.
		 */
		return;
	case WHACK_STOP_IKE:
	{
		struct ike_sa *isakmp =
			established_isakmp_sa_for_state(&(*ike)->sa, /*viable-parent*/false);
		llog_n_maybe_send_v1_delete(isakmp, &(*ike)->sa, HERE);
		connection_teardown_ike(ike, REASON_DELETED, HERE);
		return;
	}
	}
	bad_case(whacamole);
}

static void terminate_v2_states(struct connection *c,
				struct ike_sa **ike,
				struct child_sa **child,
				enum whack_state whacamole)
{
	switch (whacamole) {
	case WHACK_START_IKE:
		/* announce to the world */
		state_attach(&(*ike)->sa, c->logger);
		(*ike)->sa.st_viable_parent = false;
		record_n_send_n_log_v2_delete(*ike, HERE);
		return;
	case WHACK_LURKING_CHILD:
		state_attach(&(*child)->sa, c->logger);
		delete_child_sa(child);
		return;
	case WHACK_LURKING_IKE:
		state_attach(&(*ike)->sa, c->logger);
		connection_terminate_ike_family(ike, REASON_DELETED, HERE);
		return;
	case WHACK_CHILD:
		state_attach(&(*child)->sa, c->logger);
		connection_teardown_child(child, REASON_DELETED, HERE);
		return;
	case WHACK_CUCKOO:
		state_attach(&(*child)->sa, c->logger);
		PEXPECT(c->logger, ike == NULL);
		connection_teardown_child(child, REASON_DELETED, HERE);
		return;
	case WHACK_ORPHAN:
		state_attach(&(*child)->sa, c->logger);
		llog_pexpect(c->logger, HERE, "unexpected orphan Child SA "PRI_SO,
			     (*child)->sa.st_serialno);
		PEXPECT(c->logger, ike == NULL);
		delete_child_sa(child);
		return;
	case WHACK_SIBLING:
		state_attach(&(*child)->sa, c->logger);
		connection_teardown_child(child, REASON_DELETED, HERE);
		return;
	case WHACK_IKE:
		connection_terminate_ike_family(ike, REASON_DELETED, HERE);
		return;
	case WHACK_STOP_IKE:
		delete_ike_sa(ike);
		return;
	}
	bad_case(whacamole);
}

struct whack_state_context {
	unsigned count;
};

static void terminate_connection_states(struct connection *c,
					struct ike_sa **ike,
					struct child_sa **child,
					enum whack_state whacamole,
					struct whack_state_context *context)
{
	if (context->count == 0) {
		llog(RC_LOG, c->logger, "terminating SAs using this connection");
	}
	context->count++;
	switch (c->config->ike_version) {
	case IKEv1:
		terminate_v1_states(c, ike, child, whacamole);
		return;
	case IKEv2:
		terminate_v2_states(c, ike, child, whacamole);
		return;
	}
	bad_case(c->config->ike_version);
}

void terminate_all_connection_states(struct connection *c, where_t where)
{
	struct whack_state_context context = {0};
	whack_connection_states(c, terminate_connection_states, &context, where);
	/* caller must hold a reference */
	pmemory(c);
}

/*
 * Caller must hold a reference; hence all the pmemory(C) calls.
 *
 * Caller must have stripped the +UP and +KEEP bits; else revival will
 * happen only to then be stomped on.
 */

void terminate_connection(struct connection *c, where_t where)
{
	if (never_negotiate(c)) {
		/*
		 * Suppress message as there are no SAs; only unroute
		 * is really needed.
		 */
		PEXPECT(c->logger, c->local->kind == CK_PERMANENT);
		pdbg(c->logger, "terminating and downing never-negotiate connection");
	} else {
		pdbg(c->logger, "terminating SAs using this connection");
	}

	/* see callers */
	PEXPECT(c->logger, (c->local->kind == CK_INSTANCE ||
			    c->local->kind == CK_PERMANENT ||
			    c->local->kind == CK_LABELED_PARENT));

	PEXPECT(c->logger, !c->policy.up);
	PEXPECT(c->logger, !c->policy.keep);

	/*
	 * If there are states, delete them.
	 *
	 * Since the +UP and +KEEP bits have been stripped, deleting
	 * states won't trigger a revival.  However, when there are no
	 * states, the connection may be on the revival queue.  That
	 * is handled below.
	 */
	terminate_all_connection_states(c, HERE);
	pmemory(c); /* should not disappear; caller holds ref */

	/*
	 * Remove any kernel policy.
	 *
	 * For instance, a connection with no states that is on the
	 * pending or revival queue can have on-demand or negotiating
	 * kernel policy installed (else this call is a no-op).
	 */
	connection_unroute(c, where);
	pmemory(c); /* should not disappear; caller holds ref */

	/*
	 * Remove connection from revival queue.
	 */
	flush_unrouted_revival(c);
	pmemory(c); /* should not disappear; caller holds ref */

	/*
	 * Remove the connection from the pending queue.
	 *
	 * For instance, conn/1x1 and conn/1x2 where the latter is on
	 * the former's pending queue (i.e., no states).
	 */
	remove_connection_from_pending(c);
	pmemory(c); /* should not disappear; caller holds ref */
}

static void terminate_and_unroute_connection(struct connection *c, where_t where)
{
	/*
	 * Strip the +UP bit so that the connection (when its state is
	 * deleted say) doesn't end up on the revival queue.
	 *
	 * Note that the connection could already be lurking on the
	 * pending / revival queue.  That's handled once the states
	 * are deleted (although the order shouldn't matter)..
	 */
	del_policy(c, policy.up);
	del_policy(c, policy.keep);
	del_policy(c, policy.route);
	terminate_connection(c, where);
}

void terminate_and_down_and_unroute_connections(struct connection *c, where_t where)
{
	switch (c->local->kind) {
	case CK_INSTANCE:
	case CK_PERMANENT:
	case CK_LABELED_PARENT:
		/* caller holds ref; whack already attached */
		terminate_and_unroute_connection(c, where);
		pmemory(c); /* should not disappear; caller holds ref */
		return;

	case CK_TEMPLATE:
	case CK_LABELED_TEMPLATE:
	{
		/*
		 * Template should remaining, however, terminating and
		 * downing instances will make them go away.
		 *
		 * Worse, terminating and downing an IKE cuckold could
		 * cause Child SA cuckoo connection to be deleted.
		 * Hence, the loop picks away at the first instance.
		 */
		del_policy(c, policy.up);
		/*
		 * Pick away at instances.
		 */
		const struct connection *last = NULL;
		while (true) {
			struct connection_filter cq = {
				.clonedfrom = c,
				.ike_version = c->config->ike_version,
				.search = {
					.order = OLD2NEW,
					.verbose.logger = c->logger,
					.where = where,
				},
			};
			if (!next_connection(&cq)) {
				break;
			}
			/* log first actual delete */
			if (last == NULL) {
				llog(RC_LOG, c->logger, "deleting template instances");
			}
			/* always going forward */
			PASSERT(c->logger, last != cq.c);
			last = cq.c;
			/* stop it disappearing */
			connection_addref(cq.c, c->logger);
			connection_attach(cq.c, c->logger);
			terminate_and_unroute_connection(cq.c, where);
			/* leave whack attached during death */
			delete_connection(&cq.c);
		}
		pmemory(c); /* should not disappear */
		/* to be sure */
		connection_unroute(c, where);
		return;
	}

	case CK_GROUP:
	{
		/* should not disappear */
		del_policy(c, policy.up);
		struct connection_filter cq = {
			.clonedfrom = c,
			.ike_version = c->config->ike_version,
			.search = {
				.order = OLD2NEW,
				.verbose.logger = c->logger,
				.where = where,
			},
		};
		if (next_connection(&cq)) {
			llog(RC_LOG, c->logger, "terminating group instances");
			do {
				connection_attach(cq.c, c->logger); /* propagate whack */
				terminate_and_down_and_unroute_connections(cq.c, where);
				pmemory(cq.c); /* should not disappear */
				connection_detach(cq.c, c->logger); /* propagate whack */
			} while (next_connection(&cq));
		}
		pmemory(c); /* should not disappear */
		return;
	}

	case CK_LABELED_CHILD: /* should not happen? */
	case CK_INVALID:
		break;
	}
	bad_enum(c->logger, &connection_kind_names, c->local->kind);
}

void terminate_and_delete_connections(struct connection **cp,
				      struct logger *logger, where_t where)
{
	switch ((*cp)->local->kind) {
	case CK_LABELED_PARENT:
	case CK_PERMANENT:
	case CK_TEMPLATE:
	case CK_LABELED_TEMPLATE:
		/*
		 * Template should remaining, however, terminating and
		 * downing instances will make them go away.
		 *
		 * Worse, terminating and downing an IKE cuckold could
		 * cause Child SA cuckoo connection to be deleted.
		 * Hence, the keep getting first loop.
		 */
		connection_attach((*cp), logger);
		terminate_and_down_and_unroute_connections((*cp), where);
		/* leave whack attached during death */
		delete_connection(cp);
		return;

	case CK_GROUP:
	{
		/* should not disappear */
		connection_attach((*cp), logger);
		struct connection_filter cq = {
			.clonedfrom = (*cp),
			.ike_version = (*cp)->config->ike_version,
			.search = {
				.order = OLD2NEW,
				.verbose.logger = logger,
				.where = where,
			},
		};
		if (next_connection(&cq)) {
			llog(RC_LOG, (*cp)->logger, "deleting group instances");
			do {
				terminate_and_delete_connections(&cq.c, logger, where);
			} while (next_connection(&cq));
		}
		pmemory((*cp)); /* should not disappear */
		/* leave whack attached during death */
		delete_connection(cp);
		return;
	}

	case CK_LABELED_CHILD: /* should not happen? */
	case CK_INSTANCE:
	case CK_INVALID:
		break;
	}
	bad_enum((*cp)->logger, &connection_kind_names, (*cp)->local->kind);
}

static void terminate_v1_child(struct ike_sa **ike, struct child_sa *child)
{
	/*
	 * With IKEv1, deleting an ISAKMP SA only deletes larval
	 * children.  Any established children are released to the
	 * wild.
	 */
	if (IS_IPSEC_SA_ESTABLISHED(&child->sa)) {
		ldbg_routing((*ike)->sa.logger, "    letting established IPsec SA "PRI_SO" go wild",
			     pri_so(child->sa.st_serialno));
	} else {
		/*
		 * Attach the IKE SA's whack to the child so that the
		 * child can also log its demise.
		 */
		ldbg_routing((*ike)->sa.logger, "    deleting larval IPsec SA "PRI_SO,
			     pri_so(child->sa.st_serialno));
		state_attach(&child->sa, (*ike)->sa.logger);
		delete_child_sa(&child);
	}
}

static void terminate_v2_child(struct ike_sa **ike, struct child_sa *child,
			       enum terminate_reason reason,
			       where_t where)
{

	/*
	 * With IKEv2, deleting an IKE SA deletes all children; the
	 * only question is how.
	 *
	 * If the child owns the connection's routing then it needs to
	 * be dispatched; else it can simply be deleted.
	 */
	state_attach(&child->sa, (*ike)->sa.logger);

	/* redundant */
	on_delete(&child->sa, skip_send_delete);
	on_delete(&child->sa, skip_log_message);
	struct connection *cc = child->sa.st_connection;

	if (cc->established_child_sa == child->sa.st_serialno) {
		PEXPECT((*ike)->sa.logger, IS_IPSEC_SA_ESTABLISHED(&child->sa));
		/* will delete child and its logger */
		ldbg_routing((*ike)->sa.logger, "    teardown established Child SA "PRI_SO,
			     pri_so(child->sa.st_serialno));
		connection_teardown_child(&child, reason, where);
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
		ldbg_routing((*ike)->sa.logger, "    teardown larval Child SA "PRI_SO,
			     pri_so(child->sa.st_serialno));
		connection_teardown_child(&child, reason, where);
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

	ldbg_routing((*ike)->sa.logger, "    delete Child SA "PRI_SO,
		     pri_so(child->sa.st_serialno));
	delete_child_sa(&child);
}

void connection_terminate_ike_family(struct ike_sa **ike,
				     enum terminate_reason reason,
				     where_t where)
{
	ldbg_routing((*ike)->sa.logger, "%s()", __func__);
	pstat_sa_failed(&(*ike)->sa, reason);

	ldbg((*ike)->sa.logger, "  IKE SA is no longer viable");
	(*ike)->sa.st_viable_parent = false;

	/*
	 * When the IKE SA's connection has a direct Child SA (i.e.,
	 * shares connection) that owns the route then teardown that
	 * Child SA first.
	 *
	 * This way the IKE SA's connection can jump to the front of
	 * the revival queue (without this an IKE SA with multiple
	 * children ends up with its chilren squabbling over which SA
	 * should be revived first).
	 *
	 * When this isn't the case, the for-each-child will instead
	 * do the terminating.
	 */

	struct child_sa *connection_child = child_sa_by_serialno((*ike)->sa.st_connection->negotiating_child_sa);
	if (connection_child == NULL) {
		ldbg_routing((*ike)->sa.logger, "  IKE SA's connection has no Child SA "PRI_SO,
			     pri_so((*ike)->sa.st_connection->negotiating_child_sa));
	} else if (connection_child->sa.st_clonedfrom != (*ike)->sa.st_serialno) {
		ldbg_routing((*ike)->sa.logger, "  IKE SA is not the parent of the connection's Child SA "PRI_SO,
			     pri_so(connection_child->sa.st_serialno));
		connection_child = NULL;
	} else {
		ldbg_routing((*ike)->sa.logger, "  dispatching delete to Child SA "PRI_SO,
			     pri_so(connection_child->sa.st_serialno));
		state_attach(&connection_child->sa, (*ike)->sa.logger);
		/* will delete child and its logger */
		connection_teardown_child(&connection_child, reason, where); /* always dispatches here*/
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

		switch (child->sa.st_ike_version) {
		case IKEv1:
			terminate_v1_child(ike, child);
			break;
		case IKEv2:
			terminate_v2_child(ike, child, reason, where);
			break;
		}
	}

	/* delete self */
	connection_teardown_ike(ike, reason, where);
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
