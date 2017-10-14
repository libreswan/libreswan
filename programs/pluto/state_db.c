/* State table indexed by serialno, for libreswan
 *
 * Copyright (C) 2015,2017 Andrew Cagney
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "defs.h"

#include "state_db.h"
#include "state_entry.h"
#include "state.h"
#include "lswlog.h"
#include "cookie.h"

struct state_entry **hash_by_state_cookies(struct state_hash_table *table,
					   const uint8_t *icookie,
					   const uint8_t *rcookie)
{
	DBG(DBG_RAW | DBG_CONTROL, {
			DBG_log("finding hash chain in %s", table->name);
			DBG_dump("  ICOOKIE:", icookie, COOKIE_SIZE);
			DBG_dump("  RCOOKIE:", rcookie, COOKIE_SIZE);
		});

	/* XXX the following hash is pretty pathetic */
	unsigned i = 0;
	unsigned j;
	for (j = 0; j < COOKIE_SIZE; j++)
		i = i * 407 + icookie[j] + rcookie[j];
	return state_entries_by_hash(table, i);
}

void insert_by_state_cookies(struct state_hash_table *table,
			     struct state_entry *entry,
			     const uint8_t *icookie,
			     const uint8_t *rcookie)
{
	struct state_entry **chain = hash_by_state_cookies(table, icookie, rcookie);
	insert_state_entry(chain, entry);
}

/*
 * Hash table indexed by just the ICOOKIE.
 *
 * This is set up to work with any cookie hash table, so, eventually
 * the code can be re-used on the old hash table.
 *
 * Access using hash_entry_common and unhash_entry above.
 */

static struct state_hash_table icookie_hash_table = {
	.name = "icookie hash table",
};

void hash_icookie(struct state *st)
{
	insert_by_state_cookies(&icookie_hash_table, &st->st_icookie_hash_entry,
				st->st_icookie, zero_cookie);
}

struct state_entry *icookie_chain(const u_char *icookie)
{
	return *hash_by_state_cookies(&icookie_hash_table, icookie, zero_cookie);
}

/*
 * State Table Functions
 *
 * The statetable is organized as a hash table.
 * The hash is purely based on the icookie and rcookie.
 * Each has chain is a doubly linked list.
 *
 * The phase 1 initiator does does not at first know the
 * responder's cookie, so the state will have to be rehashed
 * when that becomes known.
 *
 * In IKEv2, cookies are renamed IKE SA SPIs.
 *
 * In IKEv2, all children have the same cookies as their parent.
 * This means that you can look along that single chain for
 * your relatives.
 */

struct state_hash_table statetable = {
	.name = "state hash table",
};
