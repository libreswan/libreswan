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

void terminate_all_connection_states(struct connection *c, where_t where);
void terminate_and_down_connections(struct connection **cp, struct logger *logger, where_t where);

void connection_timeout_ike_family(struct ike_sa **ike, where_t where);
void connection_delete_ike_family(struct ike_sa **ike, where_t where);

void connection_delete_v1_state(struct state **st, where_t where);

#endif
