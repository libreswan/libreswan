/* Connection database indexed by serialno, for libreswan
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

#include "connection_db.h"
#include "connections.h"
#include "log.h"
#include "hash_table.h"
#include "refcnt.h"

static void connection_serialno_jam_hash(struct jambuf *buf, const void *data);

static void jam_connection_serialno(struct jambuf *buf, const struct connection *c)
{
	jam(buf, PRI_CO, pri_co(c->serialno));
}

/*
 * A table ordered by serialno.
 */

static const struct list_info connection_serialno_list_info = {
	.name = "serialno list",
	.jam = connection_serialno_jam_hash,
};

static struct list_head connection_serialno_list_head = INIT_LIST_HEAD(&connection_serialno_list_head,
								       &connection_serialno_list_info);

/*
 * A table hashed by serialno.
 */

static hash_t serialno_hasher(const co_serial_t *serialno)
{
	return hash_table_hash_thing(*serialno, zero_hash);
}

HASH_TABLE(connection, serialno, .serialno, STATE_TABLE_SIZE);

struct connection *connection_by_serialno(co_serial_t serialno)
{
	/*
	 * Note that since SOS_NOBODY is never hashed, a lookup of
	 * SOS_NOBODY always returns NULL.
	 */
	struct connection *c;
	hash_t hash = serialno_hasher(&serialno);
	struct list_head *bucket = hash_table_bucket(&connection_serialno_hash_table, hash);
	FOR_EACH_LIST_ENTRY_NEW2OLD(bucket, c) {
		if (c->serialno == serialno) {
			return c;
		}
	}
	return NULL;
}

/*
 * An ID hash table.
 */

static hash_t that_id_hasher(const struct id *id)
{
	hash_t hash = zero_hash;
	if (id->kind != ID_NONE) {
		shunk_t body;
		enum ike_id_type type = id_to_payload(id, &unset_address/*ignored*/, &body);
		hash = hash_table_hash_thing(type, hash);
		hash = hash_table_hash_hunk(body, hash);
	}
	return hash;
}

static void jam_connection_that_id(struct jambuf *buf, const struct connection *c)
{
	jam_connection_serialno(buf, c);
	jam(buf, ": that_id=");
	jam_id_bytes(buf, &c->spd.that.id, jam_sanitized_bytes);
}

HASH_TABLE(connection, that_id, .spd.that.id, STATE_TABLE_SIZE);

void rehash_connection_that_id(struct connection *c)
{
	id_buf idb;
	dbg("%s() rehashing "PRI_CO" that_id=%s",
	    __func__, pri_co(c->serialno), str_id(&c->spd.that.id, &idb));
	rehash_table_entry(&connection_that_id_hash_table, c);
}

/*
 * See also {new2old,old2new}_state()
 */

static struct list_head *connection_filter_head(struct connection_filter *filter)
{
	struct list_head *bucket;
	if (filter->that_id_eq != NULL) {
		hash_t hash = that_id_hasher(filter->that_id_eq);
		bucket = hash_table_bucket(&connection_that_id_hash_table, hash);
	} else {
		bucket = &connection_serialno_list_head;
		dbg("FOR_EACH_CONNECTION_.... in "PRI_WHERE, pri_where(filter->where));
	}
	return bucket;
}

static bool matches_connection_filter(struct connection *c, struct connection_filter *filter)
{
	if (filter->kind != 0 && filter->kind != c->kind) {
		return false;
	}
	if (filter->name != NULL && !streq(filter->name, c->name)) {
		return false;
	}
	if (filter->this_id_eq != NULL && !id_eq(filter->this_id_eq, &c->spd.this.id)) {
		return false;
	}
	if (filter->that_id_eq != NULL && !id_eq(filter->that_id_eq, &c->spd.that.id)) {
		return false;
	}
	return true; /* sure */
}

static bool next_connection(enum chrono adv, struct connection_filter *filter)
{
	if (filter->internal == NULL) {
		/*
		 * Advance to first entry of the circular list (if the
		 * list is entry it ends up back on HEAD which has no
		 * data).
		 */
		filter->internal = connection_filter_head(filter)->head.next[adv];
	}
	/* Walk list until an entry matches */
	filter->c = NULL;
	for (struct list_entry *entry = filter->internal;
	     entry->data != NULL /* head has DATA == NULL */;
	     entry = entry->next[adv]) {
		struct connection *c = (struct connection *) entry->data;
		if (matches_connection_filter(c, filter)) {
			/* save connection; but step off current entry */
			filter->internal = entry->next[adv];
			dbg("found "PRI_CO" for "PRI_WHERE,
			    pri_co(c->serialno), pri_where(filter->where));
			filter->c = c;
			return true;
		}
	}
	dbg("no match for "PRI_WHERE, pri_where(filter->where));
	return false;
}

bool next_connection_old2new(struct connection_filter *filter)
{
	return next_connection(OLD2NEW, filter);
}

bool next_connection_new2old(struct connection_filter *filter)
{
	return next_connection(NEW2OLD, filter);
}

/*
 * Maintain the contents of the hash tables.
 *
 * Unlike serialno, the IKE SPI[ir] keys can change over time.
 */

static struct hash_table *const connection_hash_tables[] = {
	&connection_serialno_hash_table,
	&connection_that_id_hash_table,
};

static void add_connection_to_db(struct connection *c)
{
	dbg("Connection DB: adding connection \"%s\" "PRI_CO"", c->name, pri_co(c->serialno));
	passert(c->serialno != UNSET_CO_SERIAL);

	/* serial NR list, entries are only added */
	c->serialno_list_entry = list_entry(&connection_serialno_list_info, c);
	insert_list_entry(&connection_serialno_list_head,
			  &c->serialno_list_entry);

	for (unsigned h = 0; h < elemsof(connection_hash_tables); h++) {
		add_hash_table_entry(connection_hash_tables[h], c);
	}

	for (struct spd_route *sr = &c->spd; sr != NULL; sr = sr->spd_next) {
		add_spd_route_to_db(sr);
	}

}

void remove_connection_from_db(struct connection *c)
{
	dbg("Connection DB: deleting connection "PRI_CO, pri_co(c->serialno));
	remove_list_entry(&c->serialno_list_entry);
	for (unsigned h = 0; h < elemsof(connection_hash_tables); h++) {
		del_hash_table_entry(connection_hash_tables[h], c);
	}
}

/*
 * SPD_ROUTE database.
 */

static void spd_route_jam(struct jambuf *buf, const void *data)
{
	const struct spd_route *spd = data;
	jam(buf, PRI_CO" SPD_ROUTE", pri_co(spd->connection->serialno));
}

static const struct list_info spd_route_list_info = {
	.name = "spd_route list",
	.jam = spd_route_jam,
};

static struct list_head spd_route_list_head = INIT_LIST_HEAD(&spd_route_list_head,
							     &spd_route_list_info);

void add_spd_route_to_db(struct spd_route *sr)
{
	sr->spd_route_list_entry = list_entry(&spd_route_list_info, sr);
	insert_list_entry(&spd_route_list_head,
			  &sr->spd_route_list_entry);
}

void remove_spd_route_from_db(struct spd_route *spd)
{
	remove_list_entry(&spd->spd_route_list_entry);
}

void rehash_spd_route(struct spd_route *sr UNUSED)
{
}

static struct list_head *spd_route_filter_head(struct spd_route_filter *filter UNUSED)
{
	return &spd_route_list_head;
}

static bool matches_spd_route_filter(struct spd_route *spd, struct spd_route_filter *filter)
{
	if (filter->remote_client_range != NULL &&
	    !selector_range_eq_selector_range(*filter->remote_client_range, spd->that.client)) {
		return false;
	}
	return true;
}

bool next_spd_route(enum chrono order, struct spd_route_filter *filter)
{
	if (filter->internal == NULL) {
		/*
		 * Advance to first entry of the circular list (if the
		 * list is entry it ends up back on HEAD which has no
		 * data).
		 */
		filter->internal = spd_route_filter_head(filter)->head.next[order];
	}
	/* Walk list until an entry matches */
	filter->spd = NULL;
	for (struct list_entry *entry = filter->internal;
	     entry->data != NULL /* head has DATA == NULL */;
	     entry = entry->next[order]) {
		struct spd_route *spd = (struct spd_route *) entry->data;
		if (matches_spd_route_filter(spd, filter)) {
			/* save connection; but step off current entry */
			filter->internal = entry->next[order];
			dbg("found "PRI_CO" SPD_ROUTE for "PRI_WHERE,
			    pri_co(spd->connection->serialno), pri_where(filter->where));
			filter->spd = spd;
			return true;
		}
	}
	dbg("no match for "PRI_WHERE, pri_where(filter->where));
	return false;
}

struct spd_route *clone_spd_route(struct connection *c, where_t where)
{
	/* always first!?! */
	struct spd_route *sr = clone_thing(c->spd, where->func);
	sr->spd_next = NULL;
	pexpect(sr->connection == c);
	/* unshare pointers */
	sr->this.host_addr_name = NULL;
	sr->this.id.name = EMPTY_CHUNK;
	sr->that.id.name = EMPTY_CHUNK;
	sr->this.virt = NULL;
	sr->that.virt = NULL;
	unshare_connection_end(&sr->this);
	unshare_connection_end(&sr->that);
	add_spd_route_to_db(sr);
	return sr;
}

/*
 * Allocate connections.
 */

static struct connection *finish_connection(struct connection *c, const char *name, where_t where)
{
	c->name = clone_str(name, __func__);
	c->logger = alloc_logger(c, &logger_connection_vec, where);
	/* logger is GO! */
	static co_serial_t connection_serialno;
	/* first save old SERIALNO (0 for new connection) ... */
	c->serial_from = c->serialno;
	/* ... then update to new value */
	connection_serialno++;
	c->serialno = connection_serialno;
	add_connection_to_db(c);
	dbg_alloc(name, c, where);
	return c;
}

struct connection *alloc_connection(const char *name, where_t where)
{
	struct connection *c = alloc_thing(struct connection, where->func);
	return finish_connection(c, name, where);
}

struct connection *clone_connection(const char *name, struct connection *t, where_t where)
{
	struct connection *c = clone_thing(*t, where->func);
	return finish_connection(c, name, where);
}

void init_connection_db(void)
{
	for (unsigned h = 0; h < elemsof(connection_hash_tables); h++) {
		init_hash_table(connection_hash_tables[h]);
	}
}
