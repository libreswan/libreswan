/* State table indexed by serialno, for libreswan
 *
 * Copyright (C) 2015,2017 Andrew Cagney
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

#include "defs.h"

#include "state_db.h"
#include "state.h"
#include "lswlog.h"
#include "cookie.h"
#include "hash_table.h"

#define STATE_TABLE_SIZE 499

static size_t log_state(struct lswlog *buf, void *data)
{
	if (data == NULL) {
		return lswlogf(buf, "state #0");
	} else {
		struct state *st = (struct state*) data;
		return lswlogf(buf, "state #%lu", st->st_serialno);
	}
}

/*
 * A table ordered by serialno.
 */

struct list_info serialno_list_info = {
	.debug = DBG_CONTROLMORE,
	.name = "serialno list",
	.log = log_state,
};

struct list_head serialno_list_head;

/*
 * A table hashed by serialno.
 */

static size_t serialno_hash(void *data)
{
	struct state *st = data;
	return st->st_serialno;
}

static struct list_head serialno_hash_slots[STATE_TABLE_SIZE];
static struct hash_table serialno_hash_table = {
	.info = {
		.debug = DBG_CONTROLMORE,
		.name = "serialno table",
		.log = log_state,
	},
	.hash = serialno_hash,
	.nr_slots = STATE_TABLE_SIZE,
	.slots = serialno_hash_slots,
};

static struct list_head *serialno_chain(so_serial_t serialno)
{
	struct list_head *head = hash_table_slot_by_hash(&serialno_hash_table,
							 serialno);
	DBG(DBG_RAW | DBG_CONTROL,
	    DBG_log("%s: hash serialno #%lu to head %p",
		    serialno_hash_table.info.name,
		    serialno, head));
	return head;
}

struct state *state_by_serialno(so_serial_t serialno)
{
	/*
	 * Note that since SOS_NOBODY is never hashed, a lookup of
	 * SOS_NOBODY always returns NULL.
	 */
	struct state *st;
	FOR_EACH_LIST_ENTRY_NEW2OLD(serialno_chain(serialno), st) {
		if (st->st_serialno == serialno) {
			return st;
		}
	}
	return NULL;
}

/*
 * Hash table indexed by just the ICOOKIE.
 */

static size_t icookie_hasher(const uint8_t *icookie)
{
	/*
	 * 251 is a prime close to 256 (so like <<8).
	 *
	 * There's no real rationale for doing this.
	 */
	size_t hash = 0;
	for (unsigned j = 0; j < COOKIE_SIZE; j++) {
		hash = hash * 251 + icookie[j];
	}
	return hash;
}

static size_t icookie_hash(void *data)
{
	struct state *st = (struct state*) data;
	return icookie_hasher(st->st_icookie);
}

static size_t icookie_log(struct lswlog *buf, void *data)
{
	struct state *st = (struct state *) data;
	size_t size = 0;
	size += log_state(buf, st);
	size += lswlogs(buf, ": ");
	size += lswlog_bytes(buf, st->st_icookie, COOKIE_SIZE);
	return size;
}

static struct list_head icookie_hash_slots[STATE_TABLE_SIZE];
static struct hash_table icookie_hash_table = {
	.info = {
		.name = "icookie table",
		.log = icookie_log,
	},
	.hash = icookie_hash,
	.nr_slots = STATE_TABLE_SIZE,
	.slots = icookie_hash_slots,
};

struct list_head *icookie_slot(const u_char *icookie)
{
	size_t hash = icookie_hasher(icookie);
	struct list_head *slot = hash_table_slot_by_hash(&icookie_hash_table, hash);
	LSWDBGP(DBG_RAW | DBG_CONTROL, buf) {
		lswlogf(buf, "%s: hash icookie ", icookie_hash_table.info.name);
		lswlog_bytes(buf, icookie, COOKIE_SIZE);
		lswlogf(buf, " to %zu slot %p", hash, slot);
	};
	return slot;
}

/*
 * Hash table indexed by both ICOOKIE and RCOOKIE.
 */

/*
 * A table hashed by icookie+rcookie.
 */

static size_t cookies_hasher(const uint8_t *icookie,
			     const uint8_t *rcookie)
{
	/*
	 * 251 is a prime close to 256 aka <<8.  65521 is a prime
	 * close to 65536 aka <<16.
	 *
	 * There's no real rationale for doing this.
	 */
	size_t hash = 0;
	for (unsigned j = 0; j < COOKIE_SIZE; j++) {
		hash = hash * 65521 + icookie[j] * 251 + rcookie[j];
	}
	return hash;
}

static size_t cookies_hash(void *data)
{
	struct state *st = (struct state *)data;
	return cookies_hasher(st->st_icookie, st->st_rcookie);
}

static size_t cookies_log(struct lswlog *buf, void *data)
{
	struct state *st = (struct state *) data;
	size_t size = 0;
	size += log_state(buf, st);
	size += lswlogs(buf, ": ");
	size += lswlog_bytes(buf, st->st_icookie, COOKIE_SIZE);
	size += lswlogs(buf, "  ");
	size += lswlog_bytes(buf, st->st_rcookie, COOKIE_SIZE);
	return size;
}

static struct list_head cookies_hash_slots[STATE_TABLE_SIZE];
static struct hash_table cookies_hash_table = {
	.info = {
		.name = "cookies table",
		.log = cookies_log,
	},
	.hash = cookies_hash,
	.nr_slots = STATE_TABLE_SIZE,
	.slots = cookies_hash_slots,
};

struct list_head *cookies_slot(const u_char *icookie,
			       const u_char *rcookie)
{
	size_t hash = cookies_hasher(icookie, rcookie);
	struct list_head *slot = hash_table_slot_by_hash(&cookies_hash_table, hash);
	LSWDBGP(DBG_RAW | DBG_CONTROL, buf) {
		lswlogf(buf, "%s: hash icookie ", cookies_hash_table.info.name);
		lswlog_bytes(buf, icookie, COOKIE_SIZE);
		lswlogs(buf, " rcookie ");
		lswlog_bytes(buf, rcookie, COOKIE_SIZE);
		lswlogf(buf, " to %zu slot %p", hash, slot);
	};
	return slot;
}

/*
 * Add/remove just the cookie tables.  Unlike serialno, these can
 * change over time.
 */

static void add_to_cookie_tables(struct state *st)
{
	add_hash_table_entry(&cookies_hash_table, st,
			     &st->st_cookies_hash_entry);
	add_hash_table_entry(&icookie_hash_table, st,
			     &st->st_icookie_hash_entry);
}

static void del_from_cookie_tables(struct state *st)
{
	del_hash_table_entry(&cookies_hash_table,
			     &st->st_cookies_hash_entry);
	del_hash_table_entry(&icookie_hash_table,
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
	passert(st->st_serialno != SOS_NOBODY);
	/* serial NR list, entries are only added */
	st->st_serialno_list_entry = list_entry(&serialno_list_info, st);
	insert_list_entry(&serialno_list_head,
			  &st->st_serialno_list_entry);

	/* serial NR to state hash table */
	add_hash_table_entry(&serialno_hash_table, st,
			     &st->st_serialno_hash_entry);

	add_to_cookie_tables(st);
}

void rehash_state_cookies_in_db(struct state *st)
{
	DBG(DBG_CONTROLMORE,
	    DBG_log("%s: %s: re-hashing state #%lu cookies",
		    icookie_hash_table.info.name, cookies_hash_table.info.name,
		    st->st_serialno));
	del_from_cookie_tables(st);
	add_to_cookie_tables(st);
}

void del_state_from_db(struct state *st)
{
	remove_list_entry(&st->st_serialno_list_entry);
	del_hash_table_entry(&serialno_hash_table,
			     &st->st_serialno_hash_entry);
	del_from_cookie_tables(st);
}

void init_state_db(void)
{
	init_list(&serialno_list_info, &serialno_list_head);
	init_hash_table(&serialno_hash_table);
	init_hash_table(&cookies_hash_table);
	init_hash_table(&icookie_hash_table);
}
