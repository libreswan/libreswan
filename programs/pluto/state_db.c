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
#include "log.h"
#include "state_db.h"
#include "state.h"
#include "connections.h"
#include "hash_table.h"

static struct hash_table *const state_hash_tables[];

static void state_serialno_jam_hash(struct jambuf *buf, const void *data);

static void jam_state_serialno(struct jambuf *buf, const struct state *st)
{
	jam(buf, PRI_SO, st->st_serialno);
}

static bool state_plausable(struct state *st,
			    enum ike_version ike_version,
			    const so_serial_t *clonedfrom,
			    const msgid_t *v1_msgid
#ifndef USE_IKEv1
			    UNUSED
#endif
			    , const enum sa_role *role)
{
	if (ike_version != st->st_connection->ike_version) {
		return false;
	}
#ifdef USE_IKEv1
	if (v1_msgid != NULL && st->st_v1_msgid.id != *v1_msgid) {
		return false;
	}
#endif
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

static const struct list_info state_serialno_list_info = {
	.name = "serialno list",
	.jam = state_serialno_jam_hash,
};

struct list_head state_serialno_list_head = INIT_LIST_HEAD(&state_serialno_list_head,
							   &state_serialno_list_info);

/*
 * A table hashed by serialno.
 */

static hash_t serialno_hasher(const so_serial_t *serialno)
{
	return hash_table_hash_thing(*serialno, zero_hash);
}

HASH_TABLE(state, serialno, .st_serialno, STATE_TABLE_SIZE);

struct state *state_by_serialno(so_serial_t serialno)
{
	/*
	 * Note that since SOS_NOBODY is never hashed, a lookup of
	 * SOS_NOBODY always returns NULL.
	 */
	struct state *st;
	hash_t hash = serialno_hasher(&serialno);
	struct list_head *bucket = hash_table_bucket(&state_serialno_hash_table, hash);
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
 * A table hashed by the connection's serial no.
 */

static hash_t connection_serialno_hasher(const co_serial_t *connection_serial)
{
	return hash_table_hash_thing(*connection_serial, zero_hash);
}

static void jam_state_connection_serialno(struct jambuf *buf, const struct state *st)
{
	jam(buf, PRI_CO, st->st_connection->serialno);
}

HASH_TABLE(state, connection_serialno, .st_connection->serialno, STATE_TABLE_SIZE);

void rehash_state_connection(struct state *st)
{
	rehash_table_entry(&state_connection_serialno_hash_table, st);
}

/*
 * A table hashed by reqid.
 */

static hash_t reqid_hasher(const reqid_t *reqid)
{
	return hash_table_hash_thing(*reqid, zero_hash);
}

static void jam_state_reqid(struct jambuf *buf, const struct state *st)
{
	jam_state(buf, st);
	jam(buf, ": reqid=%u", st->st_reqid);
}

HASH_TABLE(state, reqid, .st_reqid, STATE_TABLE_SIZE);

struct state *state_by_reqid(reqid_t reqid,
			     state_by_predicate *predicate /*optional*/,
			     void *predicate_context,
			     const char *reason)
{
	/*
	 * Note that since SOS_NOBODY is never hashed, a lookup of
	 * SOS_NOBODY always returns NULL.
	 */
	struct state *st;
	hash_t hash = reqid_hasher(&reqid);
	struct list_head *bucket = hash_table_bucket(&state_reqid_hash_table, hash);
	FOR_EACH_LIST_ENTRY_NEW2OLD(bucket, st) {
		if (st->st_reqid != reqid) {
			continue;
		}
		if (predicate != NULL &&
		    !predicate(st, predicate_context)) {
			continue;
		}
		dbg("State DB: found state #%lu in %s (%s)",
		    st->st_serialno, st->st_state->short_name, reason);
		return st;
	}
	dbg("State DB: state not found (%s)", reason);
	return NULL;
}

void rehash_state_reqid(struct state *st)
{
	rehash_table_entry(&state_reqid_hash_table, st);
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

static hash_t ike_initiator_spi_hasher(const ike_spi_t *ike_initiator_spi)
{
	return hash_table_hash_thing(*ike_initiator_spi, zero_hash);
}

static void jam_state_ike_initiator_spi(struct jambuf *buf, const struct state *st)
{
	jam_state(buf, st);
	jam(buf, ": ");
	jam_dump_bytes(buf, st->st_ike_spis.initiator.bytes,
		       sizeof(st->st_ike_spis.initiator.bytes));
}

HASH_TABLE(state, ike_initiator_spi, .st_ike_spis.initiator, STATE_TABLE_SIZE);

struct state *state_by_ike_initiator_spi(enum ike_version ike_version,
					 const so_serial_t *clonedfrom, /*optional*/
					 const msgid_t *v1_msgid, /*optional*/
					 const enum sa_role *role, /*optional*/
					 const ike_spi_t *ike_initiator_spi,
					 const char *name)
{
	hash_t hash = ike_initiator_spi_hasher(ike_initiator_spi);
	struct list_head *bucket = hash_table_bucket(&state_ike_initiator_spi_hash_table, hash);
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

static hash_t ike_spis_hasher(const ike_spis_t *ike_spis)
{
	return hash_table_hash_thing(*ike_spis, zero_hash);
}

static void jam_state_ike_spis(struct jambuf *buf, const struct state *st)
{
	jam_state(buf, st);
	jam(buf, ": ");
	jam_dump_bytes(buf, st->st_ike_spis.initiator.bytes,
		       sizeof(st->st_ike_spis.initiator.bytes));
	jam(buf, "  ");
	jam_dump_bytes(buf, st->st_ike_spis.responder.bytes,
		       sizeof(st->st_ike_spis.responder.bytes));
}

HASH_TABLE(state, ike_spis, .st_ike_spis, STATE_TABLE_SIZE);

struct state *state_by_ike_spis(enum ike_version ike_version,
				const so_serial_t *clonedfrom,
				const msgid_t *v1_msgid, /* optional */
				const enum sa_role *sa_role, /* optional */
				const ike_spis_t *ike_spis,
				state_by_predicate *predicate,
				void *predicate_context,
				const char *name)
{
	hash_t hash = ike_spis_hasher(ike_spis);
	struct list_head *bucket = hash_table_bucket(&state_ike_spis_hash_table, hash);
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
 * See also {next,prev}_connection()
 */

static struct list_head *filter_head(struct state_filter *filter)
{
	/* select list head */
	struct list_head *bucket;
	if (filter->ike_spis != NULL) {
		hash_t hash = ike_spis_hasher(filter->ike_spis);
		bucket = hash_table_bucket(&state_ike_spis_hash_table, hash);
	} else if (filter->ike != NULL) {
		hash_t hash = ike_spis_hasher(&filter->ike->sa.st_ike_spis);
		bucket = hash_table_bucket(&state_ike_spis_hash_table, hash);
	} else if (filter->connection_serialno != 0) {
		hash_t hash = connection_serialno_hasher(&filter->connection_serialno);
		bucket = hash_table_bucket(&state_connection_serialno_hash_table, hash);
	} else {
		/* else other queries? */
		dbg("FOR_EACH_STATE_... in "PRI_WHERE, pri_where(filter->where));
		bucket = &state_serialno_list_head;
	}
	return bucket;
}

static bool matches_filter(struct state *st, struct state_filter *filter)
{
	if (filter->ike_version != 0 &&
	    st->st_ike_version != filter->ike_version) {
		return false;
	}
	if (filter->ike_spis != NULL &&
	    !ike_spis_eq(&st->st_ike_spis, filter->ike_spis)) {
		return false;
	}
	if (filter->ike != NULL &&
	    filter->ike->sa.st_serialno != st->st_clonedfrom) {
		return false;
	}
	if (filter->connection_serialno != 0 &&
	    filter->connection_serialno != st->st_connection->serialno) {
		return false;
	}
	return true;
}

bool next_state_old2new(struct state_filter *filter)
{
#define ADV newer /* old-to-new */
	if (filter->internal == NULL) {
		/*
		 * Advance to first entry of the circular list (if the
		 * list is entry it ends up back on HEAD which has no
		 * data).
		 */
		filter->internal = filter_head(filter)->head.ADV;
	}
	filter->st = NULL;
	/* Walk list until an entry matches */
	for (struct list_entry *entry = filter->internal;
	     entry->data != NULL /* head has DATA == NULL */;
	     entry = entry->ADV) {
		struct state *st = (struct state *) entry->data;
		if (matches_filter(st, filter)) {
			/* save state; but step off current entry */
			filter->internal = entry->ADV;
			dbg("found "PRI_SO" for "PRI_WHERE,
			    pri_so(st->st_serialno), pri_where(filter->where));
			filter->st = st;
			return true;
		}
	}
	dbg("no match for "PRI_WHERE, pri_where(filter->where));
	return false;
#undef ADV
}

bool next_state_new2old(struct state_filter *filter)
{
#define ADV older /* old-to-new */
	if (filter->internal == NULL) {
		/*
		 * Advance to first entry of the circular list (if the
		 * list is entry it ends up back on HEAD which has no
		 * data).
		 */
		filter->internal = filter_head(filter)->head.ADV;
	}
	filter->st = NULL;
	/* Walk list until an entry matches */
	for (struct list_entry *entry = filter->internal;
	     entry->data != NULL /* head has DATA == NULL */;
	     entry = entry->ADV) {
		struct state *st = (struct state *) entry->data;
		if (matches_filter(st, filter)) {
			/* save state; but step off current entry */
			filter->internal = entry->ADV;
			dbg("found "PRI_SO" for "PRI_WHERE,
			    pri_so(st->st_serialno), pri_where(filter->where));
			filter->st = st;
			return true;
		}
	}
	dbg("no match for "PRI_WHERE, pri_where(filter->where));
	return false;
#undef ADV
}

/*
 * Maintain the contents of the hash tables.
 *
 * Unlike serialno, the IKE SPI[ir] keys can change over time.
 */

static struct hash_table * const state_hash_tables[] = {
	&state_serialno_hash_table,
	&state_connection_serialno_hash_table,
	&state_reqid_hash_table,
	&state_ike_initiator_spi_hash_table,
	&state_ike_spis_hash_table,
};

void add_state_to_db(struct state *st)
{
	dbg("State DB: adding %s state #%lu in %s",
	    enum_name(&ike_version_names, st->st_connection->ike_version),
	    st->st_serialno, st->st_state->short_name);
	passert(st->st_serialno != SOS_NOBODY);

	/* serial NR list, entries are only added */
	st->st_serialno_list_entry = list_entry(&state_serialno_list_info, st);
	insert_list_entry(&state_serialno_list_head,
			  &st->st_serialno_list_entry);

	for (unsigned h = 0; h < elemsof(state_hash_tables); h++) {
		add_hash_table_entry(state_hash_tables[h], st);
	}
}

void rehash_state_cookies_in_db(struct state *st)
{
	dbg("State DB: re-hashing %s state #%lu IKE SPIi and SPI[ir]",
	    enum_name(&ike_version_names, st->st_connection->ike_version),
	    st->st_serialno);
	rehash_table_entry(&state_ike_spis_hash_table, st);
	rehash_table_entry(&state_ike_initiator_spi_hash_table, st);
}

void del_state_from_db(struct state *st)
{
	dbg("State DB: deleting %s state #%lu in %s",
	    enum_name(&ike_version_names, st->st_connection->ike_version),
	    st->st_serialno, st->st_state->short_name);
	remove_list_entry(&st->st_serialno_list_entry);
	for (unsigned h = 0; h < elemsof(state_hash_tables); h++) {
		del_hash_table_entry(state_hash_tables[h], st);
	}
}

void init_state_db(void)
{
	for (unsigned h = 0; h < elemsof(state_hash_tables); h++) {
		init_hash_table(state_hash_tables[h]);
	}
}
