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

/*
 * A table hashed by serialno.
 */

static struct state_hash_table serialno_hash_table = {
	.name = "serialno table",
};

static struct state_entry *serialno_chain(so_serial_t serialno)
{

	struct state_entry *head = state_entries_by_hash(&serialno_hash_table,
							 serialno);
	DBG(DBG_RAW | DBG_CONTROL,
	    DBG_log("%s: hash serialno #%lu to head %p",
		    serialno_hash_table.name,
		    serialno, head));
	return head;
}

struct state *state_by_serialno(so_serial_t serialno)
{
	struct state *st;
	FOR_EACH_STATE_ENTRY(st, serialno_chain(serialno), {
			if (st->st_serialno == serialno) {
				return st;
			}
		});
	return NULL;
}

/*
 * A table hashed by icookie+rcookie.
 */

static struct state_entry *hash_by_state_cookies(struct state_hash_table *table,
						 const uint8_t *icookie,
						 const uint8_t *rcookie)
{
	/* XXX the following hash is pretty pathetic */
	unsigned i = 0;
	unsigned j;
	for (j = 0; j < COOKIE_SIZE; j++)
		i = i * 407 + icookie[j] + rcookie[j];
	struct state_entry *head = state_entries_by_hash(table, i);
	LSWDBGP(DBG_RAW | DBG_CONTROL, buf) {
		lswlogf(buf, "%s: hash", table->name);
		lswlogs(buf, " icookie ");
		lswlog_bytes(buf, icookie, COOKIE_SIZE);
		lswlogs(buf, " rcookie ");
		lswlog_bytes(buf, rcookie, COOKIE_SIZE);
		lswlogf(buf, " to %u head %p", i, head);
	};
	return head;
}

/*
 * Hash table indexed by just the ICOOKIE.
 */

static struct state_hash_table icookie_hash_table = {
	.name = "icookie table",
};

struct state_entry *icookie_chain(const u_char *icookie)
{
	return hash_by_state_cookies(&icookie_hash_table, icookie, zero_cookie);
}

/*
 * Hash table indexed by both ICOOKIE and RCOOKIE.
 */

struct state_hash_table cookies_hash_table = {
	.name = "cookies table",
};

struct state_entry *cookies_chain(const u_char *icookie,
				  const u_char *rcookie)
{
	return hash_by_state_cookies(&cookies_hash_table, icookie, rcookie);
}

/*
 * Add/remove just the cookie tables.  Unlike serialno, these can
 * change over time.
 */

static void add_to_cookie_tables(struct state *st)
{
	insert_state_entry(cookies_hash_table.name,
			   cookies_chain(st->st_icookie, st->st_rcookie),
			   &st->st_cookies_hash_entry);
	insert_state_entry(icookie_hash_table.name,
			   icookie_chain(st->st_icookie),
			   &st->st_icookie_hash_entry);
}

static void del_from_cookie_tables(struct state *st)
{
	remove_state_entry(cookies_hash_table.name,
			   &st->st_cookies_hash_entry);
	remove_state_entry(icookie_hash_table.name,
			   &st->st_icookie_hash_entry);
}

/*
 * State Table Functions
 *
 * The statetable is organized as a hash table.
 * The hash is purely based on the icookie and rcookie.
 * Each has chain is a doubly linked list.
 *
 * The IKEv2 initial initiator not know the responder's cookie, so the
 * state will have to be rehashed when that becomes known.
 *
 * In IKEv2, cookies are renamed IKE SA SPIs.
 *
 * In IKEv2, all children have the same cookies as their parent.
 * This means that you can look along that single chain for
 * your relatives.
 */

void add_state_to_db(struct state *st)
{
	/* back-link the hash entry.  */
	st->st_serialno_hash_entry.state = st;
	st->st_cookies_hash_entry.state = st;
	st->st_icookie_hash_entry.state = st;

	insert_state_entry(serialno_hash_table.name,
			   serialno_chain(st->st_serialno),
			   &st->st_serialno_hash_entry);

	add_to_cookie_tables(st);
}

void rehash_state_cookies_in_db(struct state *st)
{
	DBG(DBG_CONTROLMORE,
	    DBG_log("%s: %s: re-hashing state #%lu cookies",
		    icookie_hash_table.name, cookies_hash_table.name,
		    st->st_serialno));
	del_from_cookie_tables(st);
	add_to_cookie_tables(st);
}

void del_state_from_db(struct state *st)
{
	remove_state_entry(serialno_hash_table.name,
			   &st->st_serialno_hash_entry);

	del_from_cookie_tables(st);
}
