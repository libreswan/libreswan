/* State table indexed by serialno, for libreswan
 *
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
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

static const struct list_info serialno_list_info = {
	.name = "serialno list",
	.log = log_state,
};

struct list_head serialno_list_head;

/*
 * A table hashed by serialno.
 */

static shunk_t serialno_key(const so_serial_t *serialno)
{
	return shunk2(serialno, sizeof(*serialno));
}

static shunk_t serialno_state_key(const void *data)
{
	const struct state *st = data;
	return serialno_key(&st->st_serialno);
}

static struct list_head serialno_hash_slots[STATE_TABLE_SIZE];
static struct hash_table serialno_hash_table = {
	.info = {
		.name = "serialno table",
		.log = log_state,
	},
	.key = serialno_state_key,
	.nr_slots = STATE_TABLE_SIZE,
	.slots = serialno_hash_slots,
};

struct state *state_by_serialno(so_serial_t serialno)
{
	/*
	 * Note that since SOS_NOBODY is never hashed, a lookup of
	 * SOS_NOBODY always returns NULL.
	 */
	struct state *st;
	shunk_t key = serialno_key(&serialno);
	struct list_head *bucket = hash_table_bucket(&serialno_hash_table, key);
	FOR_EACH_LIST_ENTRY_NEW2OLD(bucket, st) {
		if (st->st_serialno == serialno) {
			return st;
		}
	}
	return NULL;
}

struct ike_sa *ike_sa_by_serialno(so_serial_t serialno)
{
	return pexpect_ike_sa(state_by_serialno(serialno));
}

struct child_sa *child_sa_by_serialno(so_serial_t serialno)
{
	return pexpect_child_sa(state_by_serialno(serialno));
}

/*
 * Hash table indexed by just the IKE SPIi.
 */

static shunk_t ike_initiator_spi_key(const ike_spi_t *ike_initiator_spi)
{
	return shunk2(ike_initiator_spi, sizeof(*ike_initiator_spi));
}

static shunk_t ike_initiator_spi_state_key(const void *data)
{
	const struct state *st = data;
	return ike_initiator_spi_key(&st->st_ike_spis.initiator);
}

static size_t ike_initiator_spi_log(struct lswlog *buf, void *data)
{
	struct state *st = (struct state *) data;
	size_t size = 0;
	size += log_state(buf, st);
	size += lswlogs(buf, ": ");
	size += lswlog_bytes(buf, st->st_ike_spis.initiator.bytes,
			     sizeof(st->st_ike_spis.initiator.bytes));
	return size;
}

static struct list_head ike_initiator_spi_hash_slots[STATE_TABLE_SIZE];
static struct hash_table ike_initiator_spi_hash_table = {
	.info = {
		.name = "IKE SPIi table",
		.log = ike_initiator_spi_log,
	},
	.key = ike_initiator_spi_state_key,
	.nr_slots = STATE_TABLE_SIZE,
	.slots = ike_initiator_spi_hash_slots,
};

/*
 * Hash table indexed by both IKE_INITIATOR_SPI and IKE_RESPONDER_SPI.
 */

/*
 * A table hashed by IKE SPIi+SPIr.
 */

static shunk_t ike_spis_key(const ike_spis_t *ike_spis)
{
	return shunk2(ike_spis, sizeof(*ike_spis));
}

static shunk_t ike_spis_state_key(const void *data)
{
	const struct state *st = data;
	return ike_spis_key(&st->st_ike_spis);
}

static size_t ike_spis_log(struct lswlog *buf, void *data)
{
	struct state *st = (struct state *) data;
	size_t size = 0;
	size += log_state(buf, st);
	size += lswlogs(buf, ": ");
	size += lswlog_bytes(buf, st->st_ike_spis.initiator.bytes,
			     sizeof(st->st_ike_spis.initiator.bytes));
	size += lswlogs(buf, "  ");
	size += lswlog_bytes(buf, st->st_ike_spis.responder.bytes,
			     sizeof(st->st_ike_spis.responder.bytes));
	return size;
}

static struct list_head ike_spis_hash_slots[STATE_TABLE_SIZE];
static struct hash_table ike_spis_hash_table = {
	.info = {
		.name = "IKE SPIi:SPIr table",
		.log = ike_spis_log,
	},
	.key = ike_spis_state_key,
	.nr_slots = STATE_TABLE_SIZE,
	.slots = ike_spis_hash_slots,
};

/*
 * Add/remove just the SPI[ir] tables.  Unlike serialno, these can
 * change over time.
 */

static void add_to_ike_spi_tables(struct state *st)
{
	add_hash_table_entry(&ike_spis_hash_table, st,
			     &st->st_ike_spis_hash_entry);
	add_hash_table_entry(&ike_initiator_spi_hash_table, st,
			     &st->st_ike_initiator_spi_hash_entry);
}

static void del_from_ike_spi_tables(struct state *st)
{
	del_hash_table_entry(&ike_spis_hash_table,
			     &st->st_ike_spis_hash_entry);
	del_hash_table_entry(&ike_initiator_spi_hash_table,
			     &st->st_ike_initiator_spi_hash_entry);
}

static bool state_plausable(struct state *st,
			    enum ike_version ike_version,
			    const so_serial_t *clonedfrom,
			    const msgid_t *v1_msgid,
			    const enum sa_role *role)
{
	if (st->st_ike_version != ike_version) {
		return false;
	}
	if (v1_msgid != NULL && st->st_msgid != *v1_msgid) {
		return false;
	}
	if (role != NULL && st->st_sa_role != *role) {
		return false;
	}
	if (clonedfrom != NULL && st->st_clonedfrom != *clonedfrom) {
		return false;
	}
	return true;
}

struct state *state_by_ike_initiator_spi(enum ike_version ike_version,
					 const so_serial_t *clonedfrom, /*optional*/
					 const msgid_t *v1_msgid, /*optional*/
					 const enum sa_role *role, /*optional*/
					 const ike_spi_t *ike_initiator_spi,
					 const char *name)
{
	shunk_t key = ike_initiator_spi_key(ike_initiator_spi);
	struct list_head *bucket = hash_table_bucket(&ike_initiator_spi_hash_table, key);
	struct state *st = NULL;
	FOR_EACH_LIST_ENTRY_NEW2OLD(bucket, st) {
		if (!state_plausable(st, ike_version, clonedfrom, v1_msgid, role)) {
			continue;
		}
		if (!ike_spi_eq(&st->st_ike_spis.initiator, ike_initiator_spi)) {
			continue;
		}
		dbg("State DB: found %s state #%lu in %s (%s)",
		    enum_name(&ike_version_names, ike_version),
		    st->st_serialno, st->st_state->short_name, name);
		return st;
	}
	dbg("State DB: %s state not found (%s)",
	    enum_name(&ike_version_names, ike_version), name);
	return NULL;
}

struct state *state_by_ike_spis(enum ike_version ike_version,
				const so_serial_t *clonedfrom,
				const msgid_t *v1_msgid, /*optional*/
				const enum sa_role *sa_role, /*optional*/
				const ike_spis_t *ike_spis,
				state_by_predicate *predicate,
				void *predicate_context,
				const char *name)
{
	shunk_t key = ike_spis_key(ike_spis);
	struct list_head *bucket = hash_table_bucket(&ike_spis_hash_table, key);
	struct state *st = NULL;
	FOR_EACH_LIST_ENTRY_NEW2OLD(bucket, st) {
		if (!state_plausable(st, ike_version, clonedfrom, v1_msgid, sa_role)) {
			continue;
		}
		if (!ike_spis_eq(&st->st_ike_spis, ike_spis)) {
			continue;
		}
		if (predicate != NULL) {
			if (!predicate(st, predicate_context)) {
				continue;
			}
		}
		dbg("State DB: found %s state #%lu in %s (%s)",
		    enum_name(&ike_version_names, ike_version),
		    st->st_serialno, st->st_state->short_name, name);
		return st;
	}
	dbg("State DB: %s state not found (%s)",
	    enum_name(&ike_version_names, ike_version), name);
	return NULL;
}

/*
 * State Table Functions
 *
 * The statetable is organized as a hash table.
 *
 * The hash is purely based on the SPIi and SPIr.  Each has chain is a
 * doubly linked list.
 *
 * The IKEv2 initial initiator not know the responder's SPIr, so the
 * state will have to be rehashed when that becomes known.
 *
 * In IKEv2, all CHILD SAs have the same SPIi:SPIr as their parent IKE
 * SA.  This means that you can look along that single chain for your
 * relatives.
 *
 * In IKEv1, SPIs are renamed cookies.
 */

void add_state_to_db(struct state *st)
{
	dbg("State DB: adding %s state #%lu in %s",
	    enum_name(&ike_version_names, st->st_ike_version),
	    st->st_serialno, st->st_state->short_name);
	passert(st->st_serialno != SOS_NOBODY);
	/* serial NR list, entries are only added */
	st->st_serialno_list_entry = list_entry(&serialno_list_info, st);
	insert_list_entry(&serialno_list_head,
			  &st->st_serialno_list_entry);

	/* serial NR to state hash table */
	add_hash_table_entry(&serialno_hash_table, st,
			     &st->st_serialno_hash_entry);

	add_to_ike_spi_tables(st);
}

void rehash_state_cookies_in_db(struct state *st)
{
	dbg("State DB: re-hashing %s state #%lu IKE SPIs",
	    enum_name(&ike_version_names, st->st_ike_version),
	    st->st_serialno);
	del_from_ike_spi_tables(st);
	add_to_ike_spi_tables(st);
}

void del_state_from_db(struct state *st)
{
	dbg("State DB: deleting %s state #%lu in %s",
	    enum_name(&ike_version_names, st->st_ike_version),
	    st->st_serialno, st->st_state->short_name);
	remove_list_entry(&st->st_serialno_list_entry);
	del_hash_table_entry(&serialno_hash_table,
			     &st->st_serialno_hash_entry);
	del_from_ike_spi_tables(st);
}

void init_state_db(void)
{
	init_list(&serialno_list_info, &serialno_list_head);
	init_hash_table(&serialno_hash_table);
	init_hash_table(&ike_spis_hash_table);
	init_hash_table(&ike_initiator_spi_hash_table);
}
