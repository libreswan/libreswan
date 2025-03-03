/* routines to visit connections, for libreswan
 *
 * Copyright (C) 2023-2025  Andrew Cagney
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
 */

#ifndef VISIT_CONNECTION_H
#define VISIT_CONNECTION_H

#include <stdbool.h>

#include "where.h"

struct child_sa;
struct ike_sa;
struct connection;
struct whack_message;
struct show;
struct visit_connection_state_context;
enum chrono;

struct each {
	const char *future_tense;
	const char *past_tense;
	bool log_unknown_name;
};

/*
 * Returns a count of the applicable connections.
 *
 * XXX: strange code indentation is to stop emacs indent getting
 * confused.
 *
 */
typedef unsigned (whack_connection_visitor_cb)
(const struct whack_message *m,
 struct show *s,
 struct connection *c);

/*
 * Sort all connections then call-back WHACK_CONNECTION() for each.
 *
 * DO NOT USE THIS IF CONNECTIONS ARE EXPECTED TO BE DELETED.
 */
void whack_all_connections_sorted(const struct whack_message *m, struct show *s,
				  whack_connection_visitor_cb *visit_connection);

/*
 * Visit the connection "root" identified by M (for aliases there may
 * be multiple "root" connections and they are processed in chrono
 * order)
 *
 * Danger:
 *
 * When deleting connections, ALIAS_ORDER should be NEW2OLD so that
 * when the alias root is a template all instances are deleted before
 * the template (instances are always newer than their templates).
 *
 * This way deleting an alias connection tree can't corrupt the search
 * list.
 */

void whack_connection(const struct whack_message *m, struct show *s,
		      whack_connection_visitor_cb *visit_connection,
		      enum chrono alias_order,
		      struct each each);

unsigned whack_connection_instance_new2old(const struct whack_message *m, struct show *s,
					   struct connection *c,
					   whack_connection_visitor_cb *visit_connection);

/*
 * Visit all the connections matching M, bottom up.
 *
 * This means that an instance is visited before it's template; and
 * group templates are visited before the matching group.
 *
 * Caller of whack_connection() takes a reference so never needs to
 * worry about connection disappearing.
 */
void whack_connections_bottom_up(const struct whack_message *m, struct show *s,
				 whack_connection_visitor_cb *visit_connection,
				 struct each each);

/*
 * Visit each of a connection's states in turn.
 *
 * The callback is presented with each of the connection's states
 * (when there are no states) there's no callback.
 */

enum connection_visit_kind {
	/*
	 * The connection's established IKE SA (if there is one).
	 *
	 * The termnate's callback use this to PREPARE the IKE SA for
	 * deletion, for instance clearing the .st_viable_parent bit
	 * thus preventing Child SAs from trying to use the IKE SA for
	 * revival.
	 *
	 * This callback MUST NOT delete the IKE SA.  IKEv1 needs it
	 * to send Child SA deletes, and IKEv2 never creates orphans.
	 */
	CONNECTION_IKE_PREP,
	/*
	 * The connection's negotiating / established Child SA (if
	 * there is one).
	 *
	 * This is visited before any siblings, thus ensuring that it
	 * gets gets in first for things like revival (without this,
	 * siblings and their connections would jump the queue and get
	 * revived first causing connection flip-flops).
	 *
	 * It comes in three flavours:
	 *
	 * IKE_CHILD: the connection's Child SA is using the same
	 * connection for its IKE SA and both exist.
	 *
	 * ORPHAN_CHILD: the connection has a Child SA but no IKE SA.
	 *
	 * CUCKOO_CHILD: the connection's Child SA isn't for the IKE
	 * SA.
	 */
	CONNECTION_IKE_CHILD,
	CONNECTION_ORPHAN_CHILD,
	CONNECTION_CUCKOO_CHILD,
	/*
	 * Random states that get in the way; typically just blown
	 * away.  These are returned in no particular order.
	 *
	 * For instance, a larval IKE or Child SA.  In the case of an
	 * IKE SA, it may have further children.
	 */
	CONNECTION_LURKING_IKE,
	CONNECTION_LURKING_CHILD,
	/*
	 * Children of other connections that have hitched a lift on
	 * the connection's IKE SA (i.e., the IKE SA is a cuckold, and
	 * these are the cuckoos).
	 */
	CONNECTION_CHILD_SIBLING,
	/*
	 * When the connection has an IKE SA but no Child SA.
	 *
	 * For instance, all the IKE SA's children are for other
	 * connections (i.e., the IKE SA is a cuckold), or the
	 * connection's Child SA is using some other connection's IKE
	 * SA (i.e., the Child SA is a cuckoo).
	 *
	 * Since there's no Child SA, it's the IKE SA that is
	 * responsible for cleaning up the connection.
	 */
	CONNECTION_CHILDLESS_IKE,

	/*
	 * Perform any post processing (when there's still an IKE SA).
	 */
	CONNECTION_IKE_POST,
};

typedef void (visit_connection_state_cb)
	(struct connection *c,
	 struct ike_sa **ike,
	 struct child_sa **child,
	 enum connection_visit_kind visit_kind,
	 struct visit_connection_state_context *context);

void visit_connection_states(struct connection *c,
			     visit_connection_state_cb *visitor,
			     struct visit_connection_state_context *context,
			     where_t where);

#endif
