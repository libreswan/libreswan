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
#include "whack_connection.h"		/* for whack_connection() */
#include "ikev1_delete.h"
#include "ikev2_delete.h"
#include "pluto_stats.h"
#include "revival.h"

static void delete_v1_states(struct connection *c,
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
		connection_delete_child(child, HERE);
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
		connection_delete_child(child, HERE);
		return;
	}
	case WHACK_ORPHAN:
		/* IKEv1 has orphans */
		state_attach(&(*child)->sa, c->logger);
		PEXPECT(c->logger, ike == NULL);
		connection_delete_child(child, HERE);
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
		connection_delete_ike(ike, HERE);
		return;
	}
	}
	bad_case(whacamole);
}

static void delete_v2_states(struct connection *c,
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
		connection_delete_ike_family(ike, HERE);
		return;
	case WHACK_CHILD:
		state_attach(&(*child)->sa, c->logger);
		connection_delete_child(child, HERE);
		return;
	case WHACK_CUCKOO:
		state_attach(&(*child)->sa, c->logger);
		PEXPECT(c->logger, ike == NULL);
		connection_delete_child(child, HERE);
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
		connection_delete_child(child, HERE);
		return;
	case WHACK_IKE:
		connection_delete_ike_family(ike, HERE);
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

static void delete_states(struct connection *c,
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
		delete_v1_states(c, ike, child, whacamole);
		return;
	case IKEv2:
		delete_v2_states(c, ike, child, whacamole);
		return;
	}
	bad_case(c->config->ike_version);
}

void terminate_all_connection_states(struct connection *c, where_t where)
{
	struct whack_state_context context = {0};
	whack_connection_states(c, delete_states, &context, where);
}

/*
 * Caller must hold a reference; hence all the pmemory(C) calls.
 */

void terminate_and_down_connection(struct connection *c,
				   bool strip_route_bit,
				   where_t where)
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

	/*
	 * Strip the +UP bit so that the connection (when its state is
	 * deleted say) doesn't end up on the revival queue.
	 *
	 * Note that the connection could already be lurking on the
	 * pending / revival queue.  That's handled once the states
	 * are deleted (although the order shouldn't matter)..
	 */
	del_policy(c, policy.up);
	if (strip_route_bit) {
		del_policy(c, policy.route);
	}
	/*
	 * If there are states, delete them.  Since the +UP bit is
	 * stripped, this won't trigger a revival.  However, this
	 * doesn't preclude the connection already sitting on the
	 * pending or revival queue.
	 */
	terminate_all_connection_states(c, HERE);
	pmemory(c); /* should not disappear; caller holds ref */
	/*
	 * For instance, a connection with no states but waiting on
	 * revival or pending can have on-demand or negotiating kernel
	 * policy installed (else it is a no-op).
	 */
	connection_unroute(c, where);
	pmemory(c); /* should not disappear; caller holds ref */
	/*
	 * For instance, a connection with no states when trying to
	 * terminate a connection that is trying to revive (i.e., no
	 * states).
	 */
	flush_unrouted_revival(c);
	pmemory(c); /* should not disappear; caller holds ref */
	/*
	 * For instance, conn/1x1 and conn/1x2 where the latter is on
	 * the former's pending queue (i.e., no states).
	 */
	remove_connection_from_pending(c);
	pmemory(c); /* should not disappear; caller holds ref */
}

void terminate_and_down_connections(struct connection *c,
				    bool strip_route_bit,
				    where_t where)
{
	switch (c->local->kind) {
	case CK_INSTANCE:
	case CK_PERMANENT:
	case CK_LABELED_PARENT:
		/* caller holds ref; whack already attached */
		terminate_and_down_connection(c, strip_route_bit, where);
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
				.where = where,
			};
			if (!next_connection(OLD2NEW, &cq)) {
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
			terminate_and_down_connection(cq.c, strip_route_bit, where);
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
			.where = where,
		};
		if (next_connection(OLD2NEW, &cq)) {
			llog(RC_LOG, c->logger, "terminating group instances");
			do {
				connection_attach(cq.c, c->logger); /* propogate whack */
				terminate_and_down_connections(cq.c, strip_route_bit, where);
				pmemory(cq.c); /* should not disappear */
				connection_detach(cq.c, c->logger); /* propogate whack */
			} while (next_connection(OLD2NEW, &cq));
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
		terminate_and_down_connections((*cp), /*strip-route-bit*/true, where);
		/* leave whack attached during death */
		delete_connection(cp);
		return;

	case CK_GROUP:
	{
		/* should not disappear */
		connection_attach((*cp), logger);
		struct connection_filter cq = {
			.clonedfrom = (*cp),
			.where = where,
		};
		if (next_connection(OLD2NEW, &cq)) {
			llog(RC_LOG, (*cp)->logger, "deleting group instances");
			do {
				terminate_and_delete_connections(&cq.c, logger, where);
			} while (next_connection(OLD2NEW, &cq));
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

/*
 * If the IKE SA's connection has a direct Child SA (shares
 * connection) that owns the route then send a delete/timeout to that
 * Child SA first.
 *
 * This way the IKE SA's connection can jump to the front of the
 * revival queue (without this an IKE SA with multiple children ends
 * up with its chilren sqabbling over which SA should be revived
 * first).
 *
 * Also remember if there was a direct child.  The event only gets
 * dispatched to the IKE SA when there wasn't a child (such as during
 * IKE_SA_INIT).
 */

static bool zap_connection_child(struct ike_sa **ike,
				 void (*zap_child)(struct child_sa **child, where_t where),
				 struct child_sa **child, where_t where)
{

	bool dispatched_to_child;
	(*child) = child_sa_by_serialno((*ike)->sa.st_connection->newest_routing_sa);
	if ((*child) == NULL) {
		dispatched_to_child = false;
		ldbg_routing((*ike)->sa.logger, "  IKE SA's connection has no Child SA "PRI_SO,
			     pri_so((*ike)->sa.st_connection->newest_routing_sa));
	} else if ((*child)->sa.st_clonedfrom != (*ike)->sa.st_serialno) {
		dispatched_to_child = false;
		ldbg_routing((*ike)->sa.logger, "  IKE SA is not the parent of the connection's Child SA "PRI_SO,
			     pri_so((*child)->sa.st_serialno));
	} else {
		ldbg_routing((*ike)->sa.logger, "  dispatching delete to Child SA "PRI_SO,
			     pri_so((*child)->sa.st_serialno));
		state_attach(&(*child)->sa, (*ike)->sa.logger);
		/* will delete child and its logger */
		dispatched_to_child = true;
		zap_child(child, where); /* always dispatches here*/
		PEXPECT((*ike)->sa.logger, dispatched_to_child);
		PEXPECT((*ike)->sa.logger, (*child) == NULL); /*gone!*/
		PEXPECT((*ike)->sa.logger, (*ike)->sa.st_connection->newest_routing_sa == SOS_NOBODY);
		PEXPECT((*ike)->sa.logger, (*ike)->sa.st_connection->established_child_sa == SOS_NOBODY);
	}
	return dispatched_to_child;
}

static void zap_v1_child(struct ike_sa **ike, struct child_sa *child)
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

static void zap_v2_child(struct ike_sa **ike, struct child_sa *child,
			 void (*zap_child)(struct child_sa **child, where_t where),
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
		ldbg_routing((*ike)->sa.logger, "    zapping established Child SA "PRI_SO,
			     pri_so(child->sa.st_serialno));
		zap_child(&child, where);
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

	if (cc->newest_routing_sa == child->sa.st_serialno) {
		/* will delete child and its logger */
		ldbg_routing((*ike)->sa.logger, "    zapping larval Child SA "PRI_SO,
			     pri_so(child->sa.st_serialno));
		zap_child(&child, where);
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

	ldbg_routing((*ike)->sa.logger, "    zapping Child SA "PRI_SO,
		     pri_so(child->sa.st_serialno));
	delete_child_sa(&child);
}

static void connection_zap_ike_family(struct ike_sa **ike,
				      void (*zap_ike)(struct ike_sa **ike, where_t where),
				      void (*zap_child)(struct child_sa **child, where_t where),
				      where_t where)
{
	ldbg_routing((*ike)->sa.logger, "%s()", __func__);

	ldbg((*ike)->sa.logger, "  IKE SA is no longer viable");
	(*ike)->sa.st_viable_parent = false;

	struct child_sa *connection_child = NULL;
	zap_connection_child(ike, zap_child, &connection_child, where);

	/*
	 * We are a parent: prune any remaining children and then
	 * prepare to delete ourself.
	 */

	struct state_filter cf = {
		.clonedfrom = (*ike)->sa.st_serialno,
		.where = HERE,
	};
	while(next_state(NEW2OLD, &cf)) {
		struct child_sa *child = pexpect_child_sa(cf.st);

		switch (child->sa.st_ike_version) {
		case IKEv1:
			zap_v1_child(ike, child);
			break;
		case IKEv2:
			zap_v2_child(ike, child, zap_child, where);
			break;
		}
	}

	/* delete self */
	zap_ike(ike, where);
}

void connection_timeout_ike_family(struct ike_sa **ike, where_t where)
{
	pstat_sa_failed(&(*ike)->sa, REASON_TOO_MANY_RETRANSMITS);
	connection_zap_ike_family(ike, connection_timeout_ike, connection_timeout_child, where);
}

void connection_delete_ike_family(struct ike_sa **ike, where_t where)
{
	connection_zap_ike_family(ike, connection_delete_ike, connection_delete_child, where);
}

void connection_delete_v1_state(struct state **st, where_t where)
{
	PEXPECT((*st)->logger, (*st)->st_ike_version == IKEv1);
	if (IS_PARENT_SA(*st)) {
		struct ike_sa *ike = pexpect_parent_sa(*st);
		connection_delete_ike(&ike, where);
	} else {
		struct child_sa *child = pexpect_child_sa(*st);
		connection_delete_child(&child, where);
	}
	(*st) = NULL;
}
