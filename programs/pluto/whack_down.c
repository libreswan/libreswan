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
#include "visit_connection.h"
#include "ikev2_delete.h"
#include "ikev1.h"			/* for established_isakmp_for_state() */
#include "ikev1_delete.h"		/* for llog_n_maybe_send_v1_delete() */

/*
 * Must the IKE SA remain up?
 *
 * Either because it has +UP or is shared with other connections.
 *
 * When the IKE SA stays up, log two messages: first announcing Child
 * SA's death; and second announcing IKE SA's survival.
 */

static bool shared_phase1_connection(struct connection *c,
				     struct ike_sa *ike,
				     struct child_sa *child)
{
	/*
	 * Check the IKE SA to see if it has children from other
	 * connections (i.e., not C).
	 *
	 * Always check so all reasons to keep the IKE SA up can be
	 * logged.
	 */

	struct state_filter sf = {
		.clonedfrom = ike->sa.st_serialno,
		.search = {
			.order = NEW2OLD,
			.verbose.logger = &global_logger,
			.where = HERE,
		},
	};

	while (next_state(&sf)) {
		if (sf.st->st_connection != c) {
			break;
		}
	}

	/*
	 * Does the IKE SA need to stay up?
	 */

	if (ike->sa.st_connection->policy.up) {
		/*
		 * Yes, a +UP IKE SA can never be taken down.
		 *
		 * Since +UP as been stripped from the connection C,
		 * the IKE SA can only have +UP when it's for another
		 * connection (i.e., CUCKOLD).
		 */
		PEXPECT(c->logger, ike->sa.st_connection != c);
		PEXPECT(c->logger, (child != NULL &&
				    child->sa.st_connection->policy.up == false));
	} else if (sf.st == NULL) {
		/*
		 * No: The IKE SA isn't +UP and has no other children.
		 * It doesn't need to stay up.
		 */
		return false;
	}

	/*
	 * Note: IKE SA could have no Child SAs from the connection C,
	 * leading to CHILD being NULL.
	 */

	if (child != NULL) {
		LLOG_JAMBUF(RC_LOG, c->logger, buf) {
			jam_string(buf, "initiating delete of connection's ");
			jam_string(buf, c->config->ike_info->child_sa_name);
			jam_string(buf, " ");
			jam_so(buf, child->sa.st_serialno);
			jam_string(buf, " using ");
			if (ike->sa.st_connection == c) {
				jam_string(buf, c->config->ike_info->parent_sa_name);
				jam_string(buf, " ");
				jam_so(buf, ike->sa.st_serialno);
			} else {
				jam_string(buf, c->config->ike_info->parent_sa_name);
				jam_string(buf, " ");
				jam_state(buf, &ike->sa);
			}
		}
	} else {
		llog(RC_LOG, c->logger, "marking connection down");
	}

	LLOG_JAMBUF(RC_LOG, c->logger, buf) {
		jam_string(buf, "note: ");
		if (ike->sa.st_connection == c) {
			jam_string(buf, "connection's ");
			jam_string(buf, c->config->ike_info->parent_sa_name);
			jam_string(buf, " ");
			jam_so(buf, ike->sa.st_serialno);
		} else {
			jam_string(buf, c->config->ike_info->parent_sa_name);
			jam_string(buf, " ");
			jam_state(buf, &ike->sa);
		}
		jam_string(buf, " will remain up");
		char *sep = ":";
		if (ike->sa.st_connection->policy.up) {
			jam_string(buf, sep); sep = ";";
			jam_string(buf, " required by UP policy");
		}
		if (sf.st != NULL) {
			jam_string(buf, sep); sep = "";
			jam_string(buf, " in-use by");
			do {
				if (sf.st->st_connection != c) {
					jam_string(buf, sep); sep = ",";
					jam_string(buf, " ");
					jam_state(buf, sf.st);
				}
			} while (next_state(&sf));
		}
	}

	return true;
}

static void delete_ikev1_child(struct connection *c, struct child_sa **child, where_t where)
{
	/*
	 * Can't assume the IKE SA is the best available for the
	 * Child.
	 */
	state_attach(&(*child)->sa, c->logger);
	struct ike_sa *ike = established_isakmp_sa_for_state(&(*child)->sa,
							     /*viable-parent*/false);
	llog_n_maybe_send_v1_delete(ike, &(*child)->sa, where);
	connection_teardown_child(child, REASON_DELETED, where);
}

static void delete_ikev1_ike(struct connection *c, struct ike_sa **ike, where_t where)
{
	/*
	 * Assume the established IKE SA can delete itself.
	 */
	state_attach(&(*ike)->sa, c->logger);
	llog_n_maybe_send_v1_delete((*ike), &(*ike)->sa, HERE);
	connection_teardown_ike(ike, REASON_DELETED, where);
}

static void down_ikev1_connection_state(struct connection *c,
					struct ike_sa **ike,
					struct child_sa **child,
					enum connection_visit_kind visit_kind,
					struct connection_state_visitor_context *context UNUSED)
{
	switch (visit_kind) {

	case NUDGE_CONNECTION_PRINCIPAL_IKE_SA:
	case NUDGE_CONNECTION_CROSSED_IKE_SA:
		/*
		 * Since the connection is down, the IKE SA is off
		 * limits for anything trying to establish or revive.
		 */
		(*ike)->sa.st_viable_parent = false;
		return;

	case VISIT_CONNECTION_CHILD_OF_PRINCIPAL_IKE_SA:
	case VISIT_CONNECTION_CHILD_OF_CROSSED_IKE_SA:
	case VISIT_CONNECTION_CHILD_OF_CUCKOLD_IKE_SA:
		if (shared_phase1_connection(c, (*ike), (*child))) {
			delete_ikev1_child(c, child, HERE);
			(*ike) = NULL; /* hands off IKE */
			return;
		}

		/* log in the order that they will be deleted */
		llog(RC_LOG, c->logger, "initiating delete of connection's %s "PRI_SO" and %s "PRI_SO,
		     c->config->ike_info->child_sa_name,
		     pri_so((*child)->sa.st_serialno),
		     c->config->ike_info->parent_sa_name,
		     pri_so((*ike)->sa.st_serialno));
		delete_ikev1_child(c, child, HERE);
		delete_ikev1_ike(c, ike, HERE);
		return;

	case VISIT_CONNECTION_CHILD_OF_NONE:
		llog(RC_LOG, c->logger, "initiating delete of connection's %s "PRI_SO,
		     c->config->ike_info->child_sa_name,
		     pri_so((*child)->sa.st_serialno));
		delete_ikev1_child(c, child, HERE);
		return;

	case VISIT_CONNECTION_LURKING_CHILD_SA:
		state_attach(&(*child)->sa, c->logger);
		connection_teardown_child(child, REASON_DELETED, HERE);
		return;

	case VISIT_CONNECTION_LURKING_IKE_SA:
		state_attach(&(*ike)->sa, c->logger);
		connection_teardown_ike(ike, REASON_DELETED, HERE);
		return;

	case VISIT_CONNECTION_CUCKOO_OF_PRINCIPAL_IKE_SA:
		/* IKEv1 orphans siblings */
		return;

	case VISIT_CONNECTION_CHILDLESS_PRINCIPAL_IKE_SA:
		if (shared_phase1_connection(c, (*ike), NULL)) {
			/* nothing to do! */
			return;
		}

		llog(RC_LOG, c->logger, "initiating delete of connection's %s "PRI_SO,
		     c->config->ike_info->parent_sa_name,
		     pri_so((*ike)->sa.st_serialno));
		delete_ikev1_ike(c, ike, HERE);
		return;

	case FINISH_CONNECTION_PRINCIPAL_IKE_SA:
		return;

	}

	bad_case(visit_kind);
}

static void down_ikev2_connection_state(struct connection *c UNUSED,
					struct ike_sa **ike,
					struct child_sa **child,
					enum connection_visit_kind visit_kind,
					struct connection_state_visitor_context *context UNUSED)
{
	switch (visit_kind) {

	case NUDGE_CONNECTION_PRINCIPAL_IKE_SA:
	case NUDGE_CONNECTION_CROSSED_IKE_SA:
		/*
		 * Since the connection is down, the IKE SA is off
		 * limits for anything trying to establish or revive.
		 */
		(*ike)->sa.st_viable_parent = false;
		return;

	case VISIT_CONNECTION_CHILD_OF_PRINCIPAL_IKE_SA:
	case VISIT_CONNECTION_CHILD_OF_CROSSED_IKE_SA:
		if (shared_phase1_connection(c, (*ike), (*child))) {
			/*
			 * The IKE SA is shared so just delete the
			 * Child SA.  Also zap the IKE SA.  When the
			 * IKE is principal this helps stop the visit
			 * code making further callbacks.
			 */
			state_attach(&(*child)->sa, c->logger);
			submit_v2_delete_exchange((*ike), (*child));
			(*ike) = NULL;
			return;
		}

		/* remember, deleting the IKE SA deletes the child */
		llog(RC_LOG, c->logger, "initiating delete of connection's %s "PRI_SO" (and %s "PRI_SO")",
		     c->config->ike_info->parent_sa_name, pri_so((*ike)->sa.st_serialno),
		     c->config->ike_info->child_sa_name, pri_so((*child)->sa.st_serialno));
		state_attach(&(*ike)->sa, c->logger);
		submit_v2_delete_exchange((*ike), NULL);
		return;

	case VISIT_CONNECTION_CHILD_OF_CUCKOLD_IKE_SA:
		if (shared_phase1_connection(c, (*ike), (*child))) {
			/*
			 * The cuckold is shared.  Just delete this
			 * Child SA.
			 */
			state_attach(&(*child)->sa, c->logger);
			submit_v2_delete_exchange((*ike), (*child));
			(*ike) = NULL;
			return;
		}

		state_buf ib;
		llog(RC_LOG, c->logger, "initiating delete of "PRI_STATE" which has connection's %s "PRI_SO,
		     pri_state(&(*ike)->sa, &ib),
		     c->config->ike_info->child_sa_name, pri_so((*child)->sa.st_serialno));

		/* zap the cuckold's IKE SA which will delete the Child */
		state_attach(&(*ike)->sa, c->logger);
		submit_v2_delete_exchange((*ike), NULL);
		return;

	case VISIT_CONNECTION_CHILD_OF_NONE:
		llog_pexpect(c->logger, HERE,
			     "attempting delete of connection's %s "PRI_SO" using %s "PRI_SO,
			     c->config->ike_info->child_sa_name,
			     pri_so((*child)->sa.st_serialno),
			     c->config->ike_info->parent_sa_name,
			     pri_so((*child)->sa.st_clonedfrom));
		return;

	case VISIT_CONNECTION_LURKING_CHILD_SA:
		state_attach(&(*child)->sa, c->logger);
		connection_teardown_child(child, REASON_DELETED, HERE);
		return;

	case VISIT_CONNECTION_LURKING_IKE_SA:
		state_attach(&(*ike)->sa, c->logger);
		connection_teardown_ike(ike, REASON_DELETED, HERE);
		return;

	case VISIT_CONNECTION_CUCKOO_OF_PRINCIPAL_IKE_SA:
		/* ignore - siblings mean that the IKE SA is shared */
		return;

	case VISIT_CONNECTION_CHILDLESS_PRINCIPAL_IKE_SA:
		if (shared_phase1_connection(c, (*ike), NULL)) {
			/* nothing to do! */
			return;
		}

		llog(RC_LOG, c->logger, "initiating delete of connection's %s "PRI_SO,
		     c->config->ike_info->parent_sa_name,
		     pri_so((*ike)->sa.st_serialno));
		state_attach(&(*ike)->sa, c->logger);
		submit_v2_delete_exchange((*ike), NULL);
		return;

	case FINISH_CONNECTION_PRINCIPAL_IKE_SA:
		return;

	}

	bad_case(visit_kind);
}

static unsigned down_connection(struct connection *c, struct logger *logger)
{
	connection_attach(c, logger);

	switch (c->config->ike_version) {
	case IKEv1:
		visit_connection_states(c, down_ikev1_connection_state, NULL, HERE);
		break;
	case IKEv2:
		visit_connection_states(c, down_ikev2_connection_state, NULL, HERE);
		break;
	default:
		bad_case(c->config->ike_version);
	}

	if (is_instance(c) && refcnt_peek(c) == 1) {
		/*
		 * XXX: hack don't detach the console.  This way when
		 * the caller delref()s the connection's last
		 * reference the magical deleting instance message can
		 * appear on the still attached console.
		 */
		ldbg(c->logger, "hack attack: skipping detach so that caller can log deleting instance");
		return 1;
	}

	connection_detach(c, logger);
	return 1;
}

static unsigned whack_down_connection(const struct whack_message *m UNUSED,
				      struct show *s, struct connection *c)
{
	/*
	 * Stop the connection coming back.
	 *
	 * While only PERMANENT, INSTANCE and LABELED_PARENT can be
	 * pending, just call regardless.
	 */
	del_policy(c, policy.up);
	remove_connection_from_pending(c);

	switch (c->local->kind) {

	case CK_PERMANENT:
	case CK_INSTANCE:
	case CK_LABELED_PARENT:
		/* can delref C; caller still holds a ref */
		return down_connection(c, show_logger(s));

	case CK_LABELED_TEMPLATE:
	case CK_TEMPLATE:
	case CK_GROUP:
		return whack_connection_instance_new2old(m, s, c, whack_down_connection);

	case CK_LABELED_CHILD:
		ldbg(show_logger(s), "skipping %s", c->name);
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
		show_rc(RC_FATAL, s,
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

	whack_connection_roots(m, s, /*alias_order*/NEW2OLD,
			       whack_down_connection,
			       (struct each) {
				       .future_tense = "terminating",
				       .past_tense = "terminated",
				       .log_unknown_name = true,
			       });
}
