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

#ifndef SPD_ROUTE_DB_H
#define SPD_ROUTE_DB_H

#include "where.h"

struct spd_route;
struct logger;

/* spd route */

void spd_route_db_init(struct logger *logger);
void spd_route_db_check(struct logger *logger);

void spd_route_db_init_spd_route(struct spd_route *sr);
void spd_route_db_check_spd_route(struct spd_route *sr, struct logger *logger, where_t where);

void spd_route_db_add(struct spd_route *sr);
void spd_route_db_del(struct spd_route *sr);

#endif
