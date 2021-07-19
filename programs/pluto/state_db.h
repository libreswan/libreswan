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

void init_state_db(void);

void add_state_to_db(struct state *st);
void rehash_state_cookies_in_db(struct state *st);
void del_state_from_db(struct state *st);

struct state *state_by_serialno(so_serial_t serialno);
struct ike_sa *ike_sa_by_serialno(so_serial_t serialno);
struct child_sa *child_sa_by_serialno(so_serial_t serialno);

/*
 * List of all valid states; can be iterated in old-to-new and
 * new-to-old order.
 */

extern struct list_head state_serialno_list_head;

#define FOR_EACH_STATE_NEW2OLD(ST)				\
	FOR_EACH_LIST_ENTRY_NEW2OLD(&state_serialno_list_head, ST)

#define FOR_EACH_STATE_OLD2NEW(ST)				\
	FOR_EACH_LIST_ENTRY_OLD2NEW(&state_serialno_list_head, ST)

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

struct state *state_by_connection(struct connection *c,
				  state_by_predicate *predicate /*optional*/,
				  void *predicate_context,
				  const char *reason);

void rehash_state_connection(struct state *st);

struct state *state_by_reqid(reqid_t reqid,
			     state_by_predicate *predicate /*optional*/,
			     void *predicate_context,
			     const char *reason);
void rehash_state_reqid(struct state *st);

/*
 * For querying and iterating over the state DB.
 *
 * - calling with NULL ST returns first match
 * - re-calling with non-NULL ST returns next match
 *
 * Also:
 *
 * - option parameters are only matched when non-NULL
 * - ST can be deleted between two calls
 * - certain queries, such as using IKE_SPIs, are faster
 */

struct state_query {
	/* required */
	where_t where;
	enum ike_version ike_version;
	/* optional; non-NULL implies must match */
	const ike_spis_t *ike_spis;
	const struct ike_sa *ike;
	/* internal */
	struct {
		struct list_entry *next;
	} internal;
};

struct state *next_state(struct state *st, struct state_query *query);

#endif
