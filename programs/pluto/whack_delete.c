/* <<ipsec delete <connection> >>, for libreswan
 *
 * Copyright (C) 2023 Andrew Cagney
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

#include "whack_connection.h"
#include "whack_delete.h"
#include "show.h"
#include "log.h"
#include "connections.h"
#include "pending.h"
#include "ikev2_delete.h"

/* order here matters */

enum whack_state {
	/*
	 * When connection has an established IKE SA.
	 */
	WHACK_START_IKE,
	/*
	 * Random stuff that gets in the way; typically just blown
	 * away.  These are returned in no particular order.
	 *
	 * The lurking IKE includes the larval IKE SA from a failed
	 * establish.
	 */
	WHACK_LURKING_IKE,
	WHACK_LURKING_CHILD,
	/*
	 * The connection's Child SA.
	 *
	 * A child still has its IKE SA.  An orphan lost its IKE SA
	 * (IKEv1) and a cuckoo is the child of someother IKE SA
	 * (which may or may not exist).
	 *
	 * This is returned before any siblings so that it gets
	 * priority for things like revival.
	 */
	WHACK_CHILD,
	WHACK_ORPHAN,
	WHACK_CUCKOO,
	/*
	 * Any other children of the IKE SA.
	 */
	WHACK_SIBLING,
	/*
	 * When there's no Child SA, or the Child SA is for another
	 * IKE SA (ever the case?).  The IKE SA.
	 */
	WHACK_IKE,
	/* finally */
	WHACK_STOP_IKE,
};

static void whack_states(struct connection *c,
			 void (whack_state)(struct connection *c,
					    struct ike_sa **ike,
					    struct child_sa **child,
					    enum whack_state),
			 where_t where)
{
	struct ike_sa *ike = ike_sa_by_serialno(c->newest_ike_sa); /* could be NULL */
	if (ike != NULL) {
		ldbg(c->logger, "%s() dispatching START to "PRI_SO,
		     __func__, pri_so(ike->sa.st_serialno));
		whack_state(c, &ike, NULL, WHACK_START_IKE);
	} else {
		ldbg(c->logger, "%s() skipping START, no IKE", __func__);
	}

	/*
	 * Weed out any larval or lingering SAs.
	 *
	 * These are SAs that are using the connection yet are not the
	 * owner (newest IKE SA or Child SA).  For instance:
	 *
	 * + an IKE SA that failed to establish
	 *
	 * + an IKE SA that was replaced but hasn't yet expired
	 *
	 * + children that are part way through an IKE_AUTH or
	 *   CREATE_CHILD_SA exchange and don't yet own their
	 *   connection's route.
	 *
	 * Typically these states can be deleted outright.
	 */

	ldbg(c->logger, "%s()  weeding out larval and lingering SAs", __func__);
	struct state_filter weed = {
		.connection_serialno = c->serialno,
		.where = where,
	};
	while (next_state_new2old(&weed)) {
		if (weed.st->st_serialno == c->newest_ike_sa) {
			ldbg(c->logger, "%s()    skipping "PRI_SO" as newest IKE SA",
			     __func__, pri_so(weed.st->st_serialno));
			continue;
		}
		if (weed.st->st_serialno == c->newest_ipsec_sa) {
			ldbg(c->logger, "%s()    skipping "PRI_SO" as newest Child SA",
			     __func__, pri_so(weed.st->st_serialno));
			continue;
		}
		if (weed.st->st_serialno == c->child.newest_routing_sa) {
			ldbg(c->logger, "%s()    skipping "PRI_SO" as newest routing SA",
			     __func__, pri_so(weed.st->st_serialno));
			continue;
		}
		if (IS_PARENT_SA(weed.st)) {
			ldbg(c->logger, "%s()    dispatch lurking IKE SA to "PRI_SO,
			     __func__, pri_so(weed.st->st_serialno));
			struct ike_sa *lingering_ike = pexpect_ike_sa(weed.st);
			whack_state(c, &lingering_ike, NULL, WHACK_LURKING_IKE);
		} else {
			ldbg(c->logger, "%s()    dispatch lurking Child SA to "PRI_SO,
			     __func__, pri_so(weed.st->st_serialno));
			struct child_sa *lingering_child = pexpect_child_sa(weed.st);
			/* may not have IKE as parent? */
			whack_state(c, NULL, &lingering_child, WHACK_LURKING_CHILD);
		}
	}

	/*
	 * Notify the connection's child.
	 *
	 * Do this before any siblings.  If this isn't done, the IKE
	 * SAs children constantly swap the revival pole position.
	 */

	bool whack_ike;
	struct child_sa *connection_child =
		child_sa_by_serialno(c->child.newest_routing_sa);
	if (connection_child == NULL) {
		whack_ike = true;
		ldbg(c->logger, "%s()   skipping Child SA, as no "PRI_SO,
		     __func__, pri_so(c->child.newest_routing_sa));
	} else if (connection_child->sa.st_clonedfrom != c->newest_ike_sa) {
		/* st_clonedfrom can't be be SOS_NOBODY */
		whack_ike = true;
		ldbg(c->logger, "%s()   dispatch cuckoo Child SA "PRI_SO,
		     __func__,
		     pri_so(connection_child->sa.st_serialno));
		whack_state(c, NULL, &connection_child, WHACK_CUCKOO);
	} else if (ike == NULL) {
		ldbg(c->logger, "%s()   dispatch orphaned Child SA "PRI_SO,
		     __func__,
		     pri_so(connection_child->sa.st_serialno));
		whack_ike = false;
		whack_state(c, &ike, &connection_child, WHACK_ORPHAN);
	} else {
		ldbg(c->logger, "%s()   dispatch Child SA "PRI_SO,
		     __func__,
		     pri_so(connection_child->sa.st_serialno));
		whack_ike = false;
		whack_state(c, &ike, &connection_child, WHACK_CHILD);
	}

	/*
	 * Now go through any remaining children.
	 *
	 * This could include children of the first IKE SA that are
	 * been replaced.
	 */

	if (ike != NULL) {
		struct state_filter child_filter = {
			.ike = ike,
			.where = where,
		};
		while (next_state_new2old(&child_filter)) {
			struct child_sa *child = pexpect_child_sa(child_filter.st);
			if (!PEXPECT(c->logger,
				     child->sa.st_connection->child.newest_routing_sa ==
				     child->sa.st_serialno)) {
				continue;
			}
			ldbg(c->logger, "%s()   dispatching to sibling Child SA "PRI_SO,
			     __func__, pri_so(child->sa.st_serialno));
			whack_state(c, &ike, &child, WHACK_SIBLING);
		}
	}

	/*
	 * With everything cleaned up decide what to do with the IKE
	 * SA.
	 */

	if (ike != NULL && whack_ike) {
		ldbg(c->logger, "%s()  dispatch to IKE SA "PRI_SO" as child skipped",
		     __func__, pri_so(ike->sa.st_serialno));
		whack_state(c, &ike, NULL, WHACK_IKE);
	}

	if (ike != NULL) {
		ldbg(c->logger, "%s() dispatch STOP as reached end", __func__);
		whack_state(c, &ike, NULL, WHACK_STOP_IKE);
	} else {
		ldbg(c->logger, "%s() skipping STOP, no IKE", __func__);
	}
}

static void whack_v2_states(struct connection *c,
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
		delete_ike_sa(ike);
		return;
	case WHACK_CHILD:
		state_attach(&(*child)->sa, c->logger);
		connection_delete_child(*ike, child, HERE);
		return;
	case WHACK_CUCKOO:
		state_attach(&(*child)->sa, c->logger);
		llog_pexpect(c->logger, HERE, "unexpected Child SA cuckoo"PRI_SO,
			     (*child)->sa.st_serialno);
		connection_delete_child(*ike, child, HERE);
		return;
	case WHACK_ORPHAN:
		state_attach(&(*child)->sa, c->logger);
		llog_pexpect(c->logger, HERE, "unexpected orphan Child SA "PRI_SO,
			     (*child)->sa.st_serialno);
		connection_delete_child(*ike, child, HERE);
		return;
	case WHACK_SIBLING:
		state_attach(&(*child)->sa, c->logger);
		connection_delete_child(*ike, child, HERE);
		return;
	case WHACK_IKE:
		connection_delete_ike(ike, HERE);
		return;
	case WHACK_STOP_IKE:
		delete_ike_sa(ike);
		return;
	}
	bad_case(whacamole);
}

/*
 * Terminate and then delete connections with the specified name.
 */

static bool whack_delete_connection(struct show *s, struct connection **c,
				    const struct whack_message *m UNUSED)
{
	struct logger *logger = show_logger(s);
	connection_attach(*c, logger);

	/*
	 * Let code know of intent.
	 *
	 * Functions such as connection_unroute() don't fiddle policy
	 * bits as they are called as part of unroute/route sequences.
	 */

	del_policy(*c, POLICY_UP);
	del_policy(*c, POLICY_ROUTE);

	if (never_negotiate(*c)) {
		ldbg((*c)->logger, "skipping as never-negotiate");
		PEXPECT(logger, (is_permanent(*c) || is_template(*c)));

		connection_unroute(*c, HERE);
		delete_connection(c);
		return false;
	}

	switch ((*c)->local->kind) {

	case CK_PERMANENT:
		llog(RC_LOG, (*c)->logger, "terminating SAs using this connection");
		switch ((*c)->config->ike_version) {
		case IKEv1:
			remove_connection_from_pending(*c);
			delete_v1_states_by_connection(*c);
			connection_unroute(*c, HERE);
			delete_connection(c);
			return true;
		case IKEv2:
			remove_connection_from_pending(*c);
			switch ((*c)->child.routing) {
			case RT_ROUTED_INBOUND:
			case RT_ROUTED_TUNNEL:
			case RT_ROUTED_NEGOTIATION:
				whack_states(*c, whack_v2_states, HERE);
				break;

			case RT_UNROUTED_INBOUND:
			case RT_UNROUTED_TUNNEL:
				whack_states(*c, whack_v2_states, HERE);
				break;
			case RT_UNROUTED_NEGOTIATION:
				whack_states(*c, whack_v2_states, HERE);
				connection_unroute(*c, HERE);
				break;

			case RT_ROUTED_FAILURE:
			case RT_ROUTED_ONDEMAND:
			case RT_ROUTED_REVIVAL:
			case RT_ROUTED_NEVER_NEGOTIATE:
				connection_unroute(*c, HERE);
				break;
			case RT_UNROUTED_REVIVAL:
				connection_unroute(*c, HERE);
				break;
			case RT_UNROUTED_ONDEMAND:
			case RT_UNROUTED_FAILURE:
				connection_unroute(*c, HERE);
				break;
			case RT_UNROUTED:
				break;
			}
			delete_connection(c);
			return true;
		}
		break;

	case CK_GROUP:
		/* little left to do */
		connection_unroute(*c, HERE);
		delete_connection(c);
		return true;

	case CK_TEMPLATE:
		/* also need to unroute */
		connection_unroute(*c, HERE);
		delete_connection(c);
		return true;

	case CK_INSTANCE:
		/*
		 * For CK_INSTANCE, this could also delete the *C
		 * connection.
		 */
		llog(RC_LOG, (*c)->logger, "terminating SAs using this connection");

		connection_terminate(*c, logger, HERE);
		delete_connection(c);
		return true;

	case CK_LABELED_TEMPLATE:
		/* also need to unroute */

		connection_terminate(*c, logger, HERE);
		delete_connection(c);
		return true;

	case CK_LABELED_PARENT:
		llog(RC_LOG, (*c)->logger, "terminating SAs using this connection");

		connection_terminate(*c, logger, HERE);
		delete_connection(c);
		return true;

	case CK_LABELED_CHILD:
		/*
		 * Let the labeled parent, called later, terminate the
		 * entire IKE SA and unroute everything.
		 *
		 * XXX: does this need to stop delete_connection()
		 * deleting the child?
		 */
		PEXPECT(logger, (*c)->config->ike_version == IKEv2);

		connection_terminate(*c, logger, HERE);
		delete_connection(c);
		return true;

	case CK_INVALID:
		break;
	}
	bad_case((*c)->local->kind);
}

void whack_delete(const struct whack_message *m, struct show *s)
{
	if (m->name == NULL) {
		whack_log(RC_FATAL, s,
			  "received command to delete a connection, but did not receive the connection name - ignored");
		return;
	}

	/*
	 * This is new-to-old which means that instances are processed
	 * before templates.
	 */
	whack_connections_bottom_up(m, s, whack_delete_connection,
				    (struct each) {
					    .log_unknown_name = false,
				    });
}
