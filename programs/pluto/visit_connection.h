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
enum chrono;

struct each {
	const char *future_tense;
	const char *past_tense;
	bool log_unknown_name;
};

/*
 * Called for each connection.  Returns a count of the applicable
 * connections.
 *
 * XXX: strange code indentation is to stop emacs indent getting
 * confused.
 *
 */

typedef unsigned (connection_visitor)
	(const struct whack_message *m,
	 struct show *s,
	 struct connection *c);

/*
 * Find and visit "root" connection matching WM.name.
 *
 * A lookup by NAME, ALIAS, $CO_SERIAL, and #SO_SERIAL until there's a
 * match.  Note that for ALIAS there can be multiple matches and each
 * is called back in turn.
 *
 * Danger:
 *
 * When performing an operation that can delete a connection, ORDER
 * must be NEW2OLD.  This is so that ALIAS instances are processed
 * (and deleted) before the ALIAS root (instances are always newer
 * than their templates).  Deleting the TEMPLATE and then the
 * INSTANCES would corrupt the search list.
 */

void whack_connection_roots(const struct whack_message *wm,
			    struct show *s,
			    enum chrono order,
			    connection_visitor *visitor,
			    struct each each);

/*
 * Visit the connection "tree" matching WM.name.
 *
 * A lookup by NAME, ALIAS, $CO_SERIAL, and #SO_SERIAL until there's a
 * match is used to find the connection "root" and then the
 * connection's tree is walked in ORDER.  Note that for ALIAS there
 * can be multiple matches and, hence, multiple trees.
 *
 * Danger:
 *
 * When performing an operation that can delete a connection, ORDER
 * must be NEW2OLD.  This is so that ALIAS instances are processed
 * (and deleted) before the ALIAS root (instances are always newer
 * than their templates).  Deleting the TEMPLATE and then the
 * INSTANCES would corrupt the search list.
 */

void whack_connection_trees(const struct whack_message *wm,
			    struct show *s,
			    enum chrono order,
			    connection_visitor *visitor,
			    struct each each);

unsigned whack_connection_instance_new2old(const struct whack_message *m, struct show *s,
					   struct connection *c,
					   connection_visitor *visitor);

/*
 * Visit each of a connection's states in turn.
 *
 * The callback is presented with each of the connection's states
 * (when there are no states) there's no callback.
 */

enum connection_visit_kind {
	/*
	 * Nuge all of the connection's established IKE SAs (if there
	 * are any).  First the established IKE SA, and then any
	 * lurking SAs.
	 *
	 * The terminate callback uses this to the IKE SA for
	 * deletion: clearing the .st_viable_parent bit thus
	 * preventing Child SAs from trying to use the IKE SA for
	 * revival; and for IKEv2 sending out a record-n-send delete
	 * notification (IKEv1 sends out the delete notification after
	 * all the children are gone).
	 *
	 * This callback MUST NOT delete the IKE SA: IKEv1 needs the
	 * IKE SA so it can send out the Child SA deletes; and IKEv2
	 * never creates orphans.
	 *
	 * A CROSSSED IKE SA, while established, isn't the
	 * connection's owner (principal).  Presumably because its
	 * been double-CROSSED by some other IKE SA that
	 * crossed-streams.
	 */
	NUDGE_CONNECTION_PRINCIPAL_IKE_SA,
	NUDGE_CONNECTION_CROSSED_IKE_SA,

	/*
	 * Visit the connection's negotiating / established Child SA
	 * (if there is one).
	 *
	 * In all cases, the callback is passed the Child SA's IKE SA
	 * (and not the connection's IKE SA).
	 *
	 * This is visited before any siblings, thus ensuring that it
	 * gets gets in first for things like revival (without this,
	 * siblings and their connections would jump the queue and get
	 * revived first causing connection flip-flops).
	 *
	 * It comes in three flavours:
	 *
	 * CHILD_OF_PRINCIPAL_IKE_SA: the connection's principal Child
	 * SA is using the connection principal (established) IKE SA
	 *
	 * CHILD_OF_CROSSED_IKE_SA: the connection's principal Child
	 * SA is using an established IKE SA that shares the
	 * connection, however that IKE SA is not principal (aka
	 * owner); most likely because the current principal IKE SA
	 * double-CROSSED it
	 *
	 * CHILD_OF_CUCKOLD_IKE_SA: the connection's principal Child
	 * SA's established IKE SA is for some other connection that
	 * has found itself the (unwitting) parent
	 *
	 * CHILD_OF_NONE: the connection's Child SA has no IKE SA (or
	 * it was deleted); this is IKEv1 only.
	 */
	VISIT_CONNECTION_CHILD_OF_PRINCIPAL_IKE_SA,
	VISIT_CONNECTION_CHILD_OF_CROSSED_IKE_SA,
	VISIT_CONNECTION_CHILD_OF_CUCKOLD_IKE_SA,
	VISIT_CONNECTION_CHILD_OF_NONE,

	/*
	 * Random states that get in the way; typically just blown
	 * away.  These are returned in no particular order.
	 *
	 * For instance, a larval IKE or Child SA.  In the case of an
	 * IKE SA, it may have further children.
	 */
	VISIT_CONNECTION_LURKING_IKE_SA,
	VISIT_CONNECTION_LURKING_CHILD_SA,

	/*
	 * Children of other connections that have hitched a lift on
	 * the connection's established and principal IKE SA (i.e.,
	 * the connection's IKE SA is a cuckold, and these are the
	 * cuckoos).
	 */
	VISIT_CONNECTION_CUCKOO_OF_PRINCIPAL_IKE_SA,

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
	VISIT_CONNECTION_CHILDLESS_PRINCIPAL_IKE_SA,

	/*
	 * Perform any post processing (when there's still an IKE SA).
	 */
	FINISH_CONNECTION_PRINCIPAL_IKE_SA,
};

struct connection_state_visitor_context;

typedef void (connection_state_visitor)
	(struct connection *c,
	 struct ike_sa **ike,
	 struct child_sa **child,
	 enum connection_visit_kind visit_kind,
	 struct connection_state_visitor_context *context);

void visit_connection_states(struct connection *c,
			     connection_state_visitor *state_visitor,
			     struct connection_state_visitor_context *context,
			     where_t where);

#endif
