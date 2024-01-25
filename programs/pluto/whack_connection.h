/* whack receive routines, for libreswan
 *
 * Copyright (C) 2023  Andrew Cagney
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

#ifndef WHACK_CONNECTION_H
#define WHACK_CONNECTION_H

#include <stdbool.h>

#include "where.h"

struct child_sa;
struct ike_sa;
struct connection;
struct whack_message;
struct show;
struct whack_state_context;
enum chrono;

struct each {
	const char *future_tense;
	const char *past_tense;
	bool log_unknown_name;
};

/*
 * XXX: strange indentation is to stop emacs indent getting confused.
 *
 * Returns a count of the applicable connections.
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
 * Whack each of a connection's states in turn.
 */

enum whack_state {
	/*
	 * When connection has an established IKE SA.
	 */
	WHACK_START_IKE,
	/*
	 * The connection's Child SA.
	 *
	 * A CHILD still has its IKE SA.  An ORPHAN lost its IKE SA
	 * (IKEv1).  A CUCKOO is the Child SA of some other connection
	 * and may (IKEv2) or may not (IKEv1) have an IKE SA.
	 *
	 * This is returned before any siblings so that it gets
	 * priority for things like revival.
	 */
	WHACK_CHILD,
	WHACK_ORPHAN,
	WHACK_CUCKOO,
	/*
	 * Any IKE SA children that are not for the current
	 * connection.
	 *
	 * This is the reverse of a CUCKOO.
	 */
	WHACK_SIBLING,
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
	 * When the connection has no Child SA, or the connection's
	 * Child SA is for another IKE SA (ever the case?).
	 */
	WHACK_IKE,
	/* finally */
	WHACK_STOP_IKE,
};

void whack_connection_states(struct connection *c,
			     void (whack)(struct connection *c,
					  struct ike_sa **ike,
					  struct child_sa **child,
					  enum whack_state,
					  struct whack_state_context *context),
			     struct whack_state_context *context,
			     where_t where);

#endif
