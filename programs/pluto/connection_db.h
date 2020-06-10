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

typedef struct { unsigned long co; } co_serial_t;

#define PRI_CO "$%lu"
#define pri_co(CO) ((CO).co)

extern const co_serial_t unset_co_serial;

#define co_serial_is_unset(CO) ((CO).co == 0)
#define co_serial_is_set !co_serial_is_unset
#define co_serial_eq(L, R) ((L).co == (R).co)

void init_connection_db(void);

struct connection *alloc_connection(where_t where);
struct connection *clone_connection(struct connection *template, where_t where);
/* void rehash_connection_in_db(struct connection *c); */
void remove_connection_from_db(struct connection *c);

struct connection *connection_by_serialno(co_serial_t serialno);

/*
 * All the hash tables states are stored in.
 */
enum connection_hash_tables {
	CONNECTION_SERIALNO_HASH_TABLE,
	/* add tables here */
	CONNECTION_HASH_TABLES_ROOF,
};

#endif
