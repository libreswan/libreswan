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

struct connection;
struct logger;

void connection_db_init(struct logger *logger);
void connection_db_check(const struct logger *logger, where_t where);

void connection_db_init_connection(struct connection *c);

void connection_db_add(struct connection *c);
void connection_db_del(struct connection *c);

#endif
