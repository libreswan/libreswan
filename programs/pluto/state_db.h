/* State table indexed by serialno, for libreswan
 *
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
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

#ifndef STATE_DB_H
#define STATE_DB_H

#include "ike_spi.h"
#include "reqid.h"

struct state;
struct connection;
struct list_entry;
enum sa_role;

void state_db_init(struct logger *logger);
void state_db_check(struct logger *logger);

void state_db_init_state(struct state *st);

void state_db_add(struct state *st);
void state_db_del(struct state *st);

/*
 * Lookup and generic search functions.
 */

struct state *state_by_ike_initiator_spi(enum ike_version ike_version,
					 const so_serial_t *clonedfrom,
					 const msgid_t *v1_msgid, /* optional */
					 const enum sa_role *role, /*optional*/
					 const ike_spi_t *ike_initiator_spi,
					 const char *reason);

typedef bool (state_by_predicate)(struct state *st, void *context);

struct state *state_by_ike_spis(enum ike_version ike_version,
				const so_serial_t *clonedfrom,
				const msgid_t *v1_msgid, /*optional*/
				const enum sa_role *role, /*optional*/
				const ike_spis_t *ike_spis,
				state_by_predicate *predicate /*optional*/,
				void *predicate_context,
				const char *reason);

void state_db_rehash_connection_serialno(struct state *st);

struct state *state_by_reqid(reqid_t reqid,
			     state_by_predicate *predicate /*optional*/,
			     void *predicate_context,
			     const char *reason);
void state_db_rehash_reqid(struct state *st);

#endif
