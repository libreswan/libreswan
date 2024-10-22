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
#include "connection_db.h"
#include "state.h"
#include "connections.h"
#include "hash_table.h"

/*
 * Legacy search functions.
 */

static bool state_plausable(struct state *st,
			    enum ike_version ike_version,
			    const so_serial_t *clonedfrom,
			    const msgid_t *v1_msgid
#ifndef USE_IKEv1
			    UNUSED
#endif
			    , const enum sa_role *role)
{
	if (ike_version != st->st_ike_version) {
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
 * A table hashed by serialno.
 */

static hash_t hash_state_serialno(const so_serial_t *serialno)
{
	return hash_thing(*serialno, zero_hash);
}

HASH_TABLE(state, serialno, .st_serialno, STATE_TABLE_SIZE);

/*
 * Find the state object with this serial number.  This allows state
 * object references that don't turn into dangerous dangling pointers:
 * reference a state by its serial number.  Returns NULL if there is
 * no such state.
 */

struct state *state_by_serialno(so_serial_t serialno)
{
	/*
	 * Note that since SOS_NOBODY is never hashed, a lookup of
	 * SOS_NOBODY always returns NULL.
	 */
	struct state *st;
	hash_t hash = hash_state_serialno(&serialno);
	struct list_head *bucket = hash_table_bucket(&state_serialno_hash_table, hash);
	FOR_EACH_LIST_ENTRY_NEW2OLD(st, bucket) {
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

static hash_t hash_state_connection_serialno(const co_serial_t *connection_serial)
{
	return hash_thing(*connection_serial, zero_hash);
}

HASH_TABLE(state, connection_serialno, .st_connection->serialno, STATE_TABLE_SIZE);

REHASH_DB_ENTRY(state, connection_serialno, .st_connection->serialno);

/*
 * A table hashed by reqid.
 */

static hash_t hash_state_reqid(const reqid_t *reqid)
{
	return hash_thing(*reqid, zero_hash);
}

HASH_TABLE(state, reqid, .st_reqid, STATE_TABLE_SIZE);
REHASH_DB_ENTRY(state, reqid, .st_reqid);

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
	hash_t hash = hash_state_reqid(&reqid);
	struct list_head *bucket = hash_table_bucket(&state_reqid_hash_table, hash);
	FOR_EACH_LIST_ENTRY_NEW2OLD(st, bucket) {
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

static hash_t hash_state_ike_initiator_spi(const ike_spi_t *ike_initiator_spi)
{
	return hash_thing(*ike_initiator_spi, zero_hash);
}

HASH_TABLE(state, ike_initiator_spi, .st_ike_spis.initiator, STATE_TABLE_SIZE);
static REHASH_DB_ENTRY(state, ike_initiator_spi, .st_ike_spis.initiator);

struct state *state_by_ike_initiator_spi(enum ike_version ike_version,
					 const so_serial_t *clonedfrom, /*optional*/
					 const msgid_t *v1_msgid, /*optional*/
					 const enum sa_role *role, /*optional*/
					 const ike_spi_t *ike_initiator_spi,
					 const char *name)
{
	hash_t hash = hash_state_ike_initiator_spi(ike_initiator_spi);
	struct list_head *bucket = hash_table_bucket(&state_ike_initiator_spi_hash_table, hash);
	struct state *st = NULL;
	FOR_EACH_LIST_ENTRY_NEW2OLD(st, bucket) {
		if (!state_plausable(st, ike_version, clonedfrom, v1_msgid, role)) {
			continue;
		}
		if (!ike_spi_eq(&st->st_ike_spis.initiator, ike_initiator_spi)) {
			continue;
		}
		dbg("State DB: found %s state #%lu in %s (%s)",
		    st->st_connection->config->ike_info->version_name,
		    st->st_serialno, st->st_state->short_name, name);
		return st;
	}
	enum_buf vb;
	dbg("State DB: %s state not found (%s)",
	    str_enum(&ike_version_names, ike_version, &vb), name);
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

static hash_t hash_state_ike_spis(const ike_spis_t *ike_spis)
{
	return hash_thing(*ike_spis, zero_hash);
}

static void jam_ike_spis(struct jambuf *buf, const ike_spis_t *ike_spis)
{
	jam_dump_bytes(buf, ike_spis->initiator.bytes,
		       sizeof(ike_spis->initiator.bytes));
	jam(buf, "  ");
	jam_dump_bytes(buf, ike_spis->responder.bytes,
		       sizeof(ike_spis->responder.bytes));
}

HASH_TABLE(state, ike_spis, .st_ike_spis, STATE_TABLE_SIZE);
static REHASH_DB_ENTRY(state, ike_spis, .st_ike_spis);

struct state *state_by_ike_spis(enum ike_version ike_version,
				const so_serial_t *clonedfrom,
				const msgid_t *v1_msgid, /* optional */
				const enum sa_role *sa_role, /* optional */
				const ike_spis_t *ike_spis,
				state_by_predicate *predicate,
				void *predicate_context,
				const char *name)
{
	hash_t hash = hash_state_ike_spis(ike_spis);
	struct list_head *bucket = hash_table_bucket(&state_ike_spis_hash_table, hash);
	struct state *st = NULL;
	FOR_EACH_LIST_ENTRY_NEW2OLD(st, bucket) {
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
		    st->st_connection->config->ike_info->version_name,
		    st->st_serialno, st->st_state->short_name, name);
		return st;
	}
	enum_buf vb;
	dbg("State DB: %s state not found (%s)",
	    str_enum(&ike_version_names, ike_version, &vb), name);
	return NULL;
}

/*
 * Child hash table.
 */

static hash_t hash_state_clonedfrom(const so_serial_t *clonedfrom)
{
	return hash_thing(*clonedfrom, zero_hash);
}

HASH_TABLE(state, clonedfrom, .st_clonedfrom, STATE_TABLE_SIZE);
static REHASH_DB_ENTRY(state, clonedfrom, .st_clonedfrom);

/*
 * ST could be either an IKE or Child SA.
 *
 * Used to converting a new state into a Child SA (SOS_NOBODY -> IKE),
 * migrating a Child SA to a new IKE SA (old-IKE -> new-IKE), and
 * emancipate a Child SA (IKE -> SOS_NOBODY).
 */

void update_st_clonedfrom(struct state *st, so_serial_t clonedfrom)
{
	st->st_clonedfrom = clonedfrom;
	state_db_rehash_clonedfrom(st);
}

/*
 * Maintain the contents of the hash tables.
 *
 * Unlike serialno, the IKE SPI[ir] keys can change over time.
 */

HASH_DB(state,
	&state_clonedfrom_hash_table,
	&state_serialno_hash_table,
	&state_connection_serialno_hash_table,
	&state_reqid_hash_table,
	&state_ike_initiator_spi_hash_table,
	&state_ike_spis_hash_table);

/*
 * The IKE SA has received the responder's SPI.  Update it and then
 * rehash the DB entries.
 */

void update_st_ike_spis_responder(struct ike_sa *ike,
			       const ike_spi_t *ike_responder_spi)
{
	/* update the responder's SPI */
	ike->sa.st_ike_spis.responder = *ike_responder_spi;
	/* now, update the state */
	ldbg_sa(ike, "State DB: re-hashing %s state #%lu IKE SPIr",
		ike->sa.st_connection->config->ike_info->version_name,
		ike->sa.st_serialno);
	state_db_rehash_ike_spis(&ike->sa);
	/* just logs change */
	binlog_refresh_state(&ike->sa);
}

/*
 * Re-insert the state in the database after updating the RCOOKIE, and
 * possibly the ICOOKIE.
 *
 * ICOOKIE is only updated if icookie != NULL
 */

void update_st_ike_spis(struct child_sa *new_ike, const ike_spis_t *ike_spis)
{
	/* update the responder's SPI */
	new_ike->sa.st_ike_spis = *ike_spis;
	/* now, update the state */
	ldbg_sa(new_ike, "State DB: re-hashing %s state #%lu IKE SPI[ir]",
		new_ike->sa.st_connection->config->ike_info->version_name,
		new_ike->sa.st_serialno);
	state_db_rehash_ike_spis(&new_ike->sa);
	state_db_rehash_ike_initiator_spi(&new_ike->sa);
	/* just logs change */
	binlog_refresh_state(&new_ike->sa);
}

/*
 * See also {next,prev}_connection()
 */

static struct list_head *state_filter_head(struct state_filter *filter)
{
	struct verbose verbose = filter->search.verbose;
	/* select list head */
	struct list_head *bucket;
	if (filter->ike_spis != NULL) {
		LDBGP_JAMBUF(DBG_BASE, verbose.logger, buf) {
			jam(buf, PRI_VERBOSE, pri_verbose);
			jam(buf, "FOR_EACH_STATE[ike_spis=");
			jam_ike_spis(buf, filter->ike_spis);
			jam_string(buf, "]... in ");
			jam_where(buf, filter->search.where);
		}
		hash_t hash = hash_state_ike_spis(filter->ike_spis);
		bucket = hash_table_bucket(&state_ike_spis_hash_table, hash);
	} else if (filter->clonedfrom != SOS_NOBODY) {
		vdbg("FOR_EACH_STATE[clonedfrom="PRI_SO"]... in "PRI_WHERE,
		     pri_so(filter->clonedfrom), pri_where(filter->search.where));
		hash_t hash = hash_state_clonedfrom(&filter->clonedfrom);
		bucket = hash_table_bucket(&state_clonedfrom_hash_table, hash);
	} else if (filter->connection_serialno != 0) {
		vdbg("FOR_EACH_STATE[connection_serialno="PRI_CO"]... in "PRI_WHERE,
		     pri_co(filter->connection_serialno), pri_where(filter->search.where));
		hash_t hash = hash_state_connection_serialno(&filter->connection_serialno);
		bucket = hash_table_bucket(&state_connection_serialno_hash_table, hash);
	} else {
		/* else other queries? */
		vdbg("FOR_EACH_STATE_... in "PRI_WHERE, pri_where(filter->search.where));
		bucket = &state_db_list_head;
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
	if (filter->clonedfrom != SOS_NOBODY &&
	    filter->clonedfrom != st->st_clonedfrom) {
		return false;
	}
	if (filter->connection_serialno != 0 &&
	    filter->connection_serialno != st->st_connection->serialno) {
		return false;
	}
	return true;
}

bool next_state(struct state_filter *filter)
{
	if (filter->internal == NULL) {
		/*
		 * Advance to first entry of the circular list (if the
		 * list is entry it ends up back on HEAD which has no
		 * data).
		 */
		filter->internal = state_filter_head(filter)->
			head.next[filter->search.order];
		filter->search.verbose.level++;
	}
	struct verbose verbose = filter->search.verbose;

	filter->st = NULL;
	/* Walk list until an entry matches */
	for (struct list_entry *entry = filter->internal;
	     entry->data != NULL /* head has DATA == NULL */;
	     entry = entry->next[filter->search.order]) {
		struct state *st = (struct state *) entry->data;
		if (matches_filter(st, filter)) {
			/* save state; but step off current entry */
			filter->internal = entry->next[filter->search.order];
			filter->count++;
			LDBGP_JAMBUF(DBG_BASE, verbose.logger, buf) {
				jam(buf, PRI_VERBOSE, pri_verbose);
				jam_string(buf, "  found ");
				jam_state(buf, st);
			}
			filter->st = st;
			return true;
		}
	}
	vdbg("matches: %d", filter->count);
	return false;
}
