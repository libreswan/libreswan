/* terminate connection, for libreswan
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
 */

#ifndef TERMINATE_H
#define TERMINATE_H

#include "where.h"

struct connection;
struct logger;
struct ike_sa;

void terminate_all_connection_states(struct connection *c, where_t where);

/*
 * Traverse the connection tree DOWN-ing all connections (remove +UP
 * bit), delete states, and eliminate anything on either the pending
 * or revival queue.
 *
 * Caller must take a reference C to stop it being deleted - as will
 * happen when C is an INSTANCE or LABELED_PARENT.
 *
 * If C is a TEMPLATE or LABELED_TEMPLATE this will delete any
 * INSTANCE, LABELED_PARENT or LABELED_CHILD.
 *
 * Whack is attached to C; whack will be propagated to instances.
 */
void terminate_and_down_connections(struct connection *c,
				    bool strip_route,
				    where_t where);
/* ditto, but don't recurse; again, whack is attached to C */
void terminate_and_down_connection(struct connection *c,
				   bool strip_route_bit,
				   where_t where);

void terminate_and_delete_connections(struct connection **cp, struct logger *logger, where_t where);

void connection_timeout_ike_family(struct ike_sa **ike, where_t where);
void connection_delete_ike_family(struct ike_sa **ike, where_t where);

void connection_delete_v1_state(struct state **st, where_t where);

#endif
