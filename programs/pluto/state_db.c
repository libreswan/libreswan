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

static struct hash_table state_hashes[];

static size_t log_state(struct lswlog *buf, void *data)
{
	if (data == NULL) {
		return lswlogf(buf, "state #0");
	} else {
		struct state *st = (struct state*) data;
		return lswlogf(buf, "state #%lu", st->st_serialno);
	}
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

static struct list_entry *serialno_state_entry(void *data)
{
	struct state *st = data;
	return &st->st_hash_entries[SERIALNO_STATE_HASH];
}

static struct list_head serialno_hash_slots[STATE_TABLE_SIZE];

struct state *state_by_serialno(so_serial_t serialno)
{
	/*
	 * Note that since SOS_NOBODY is never hashed, a lookup of
	 * SOS_NOBODY always returns NULL.
	 */
	struct state *st;
	shunk_t key = serialno_key(&serialno);
	struct list_head *bucket = hash_table_bucket(&state_hashes[SERIALNO_STATE_HASH], key);
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
 *
 * The response to an IKE_SA_INIT contains an as yet unknown SPIr
 * value.  Hence, when looking for the initiator of an IKE_SA_INIT
 * response, only the SPIi key is used.
 *
 * When a CHILD SA is emancipated creating a new IKE SA its IKE SPIs
 * are replaced, hence a rehash is required.
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

static struct list_entry *ike_initiator_spi_state_entry(void *data)
{
	struct state *st = data;
	return &st->st_hash_entries[IKE_INITIATOR_SPI_STATE_HASH];
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

struct state *state_by_ike_initiator_spi(enum ike_version ike_version,
					 const so_serial_t *clonedfrom, /*optional*/
					 const msgid_t *v1_msgid, /*optional*/
					 const enum sa_role *role, /*optional*/
					 const ike_spi_t *ike_initiator_spi,
					 const char *name)
{
	shunk_t key = ike_initiator_spi_key(ike_initiator_spi);
	struct list_head *bucket = hash_table_bucket(&state_hashes[IKE_INITIATOR_SPI_STATE_HASH], key);
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

/*
 * Hash table indexed by both both IKE SPIi+SPIr.
 *
 * Note that these values change over time and when this happens a
 * rehash is required:
 *
 * - initially SPIr=0, but then when the first response is received
 *   SPIr changes to the value in that response
 *
 * - when a CHILD SA is emancipated creating a new IKE SA, the IKE
 *   SPIs of the child change to those from the CREATE_CHILD_SA
 *   exchange
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

static struct list_entry *ike_spis_state_entry(void *data)
{
	struct state *st = data;
	return &st->st_hash_entries[IKE_SPIS_STATE_HASH];
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
	struct list_head *bucket = hash_table_bucket(&state_hashes[IKE_SPIS_STATE_HASH], key);
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
 * Maintain the contents of the hash tables.
 *
 * Unlike serialno, the IKE SPI[ir] keys can change over time.
 */
static struct hash_table state_hashes[STATE_HASH_ROOF] = {
	[SERIALNO_STATE_HASH] = {
		.info = {
			.name = "serialno",
			.log = log_state,
		},
		.key = serialno_state_key,
		.entry = serialno_state_entry,
		.nr_slots = STATE_TABLE_SIZE,
		.slots = serialno_hash_slots,
	},
	[IKE_INITIATOR_SPI_STATE_HASH] = {
		.info = {
			.name = "IKE SPIi",
			.log = ike_initiator_spi_log,
		},
		.key = ike_initiator_spi_state_key,
		.entry = ike_initiator_spi_state_entry,
		.nr_slots = STATE_TABLE_SIZE,
		.slots = ike_initiator_spi_hash_slots,
	},
	[IKE_SPIS_STATE_HASH] = {
		.info = {
			.name = "IKE SPIi:SPIr",
			.log = ike_spis_log,
		},
		.key = ike_spis_state_key,
		.entry = ike_spis_state_entry,
		.nr_slots = STATE_TABLE_SIZE,
		.slots = ike_spis_hash_slots,
	},
};

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

	for (unsigned h = 0; h < elemsof(state_hashes); h++) {
		add_hash_table_entry(&state_hashes[h], st);
	}
}

void rehash_state_cookies_in_db(struct state *st)
{
	dbg("State DB: re-hashing %s state #%lu IKE SPIi and SPI[ir]",
	    enum_name(&ike_version_names, st->st_ike_version),
	    st->st_serialno);

	rehash_table_entry(&state_hashes[IKE_SPIS_STATE_HASH], st);
	rehash_table_entry(&state_hashes[IKE_INITIATOR_SPI_STATE_HASH], st);
}

void del_state_from_db(struct state *st)
{
	dbg("State DB: deleting %s state #%lu in %s",
	    enum_name(&ike_version_names, st->st_ike_version),
	    st->st_serialno, st->st_state->short_name);
	remove_list_entry(&st->st_serialno_list_entry);
	for (unsigned h = 0; h < elemsof(state_hashes); h++) {
		del_hash_table_entry(&state_hashes[h], st);
	}
}

void init_state_db(void)
{
	init_list(&serialno_list_info, &serialno_list_head);
	for (unsigned h = 0; h < elemsof(state_hashes); h++) {
		init_hash_table(&state_hashes[h]);
	}
}
