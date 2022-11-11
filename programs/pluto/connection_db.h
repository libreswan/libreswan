/* Connection Database, for libreswan
 *
 * Copyright (C) 2020 Andrew Cagney <cagney@gnu.org>
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

#ifndef CONNECTION_DB_H
#define CONNECTION_DB_H

#include "where.h"
#include "connections.h"

/* connections */

void init_connection_db(struct logger *logger);
void check_connection_db(struct logger *logger);

struct connection *alloc_connection(const char *name,
				    lset_t debugging, struct fd *whackfd,
				    where_t where);
struct connection *clone_connection(const char *name, struct connection *template, where_t where);
struct spd_route *append_spd_route(struct connection *c, struct spd_route ***last);

void init_db_connection(struct connection *c);
void check_db_connection(struct connection *c, struct logger *logger, where_t where);

void add_db_connection(struct connection *c);
void del_db_connection(struct connection *c, bool valid);

/* spd route */

void init_spd_route_db(struct logger *logger);
void check_spd_route_db(struct logger *logger);

struct spd_route *clone_spd_route(struct connection *c, where_t where);

void init_db_spd_route(struct spd_route *sr);
void check_db_spd_route(struct spd_route *sr, struct logger *logger, where_t where);

void add_db_spd_route(struct spd_route *sr);
void del_db_spd_route(struct spd_route *sr, bool valid);

#endif
