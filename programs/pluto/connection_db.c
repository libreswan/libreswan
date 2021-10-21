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

static void init_connection_hash_table_entries(struct connection *c);
static void hash_table_jam_connection_serialno(struct jambuf *buf, const void *data);

static void jam_connection_serialno(struct jambuf *buf, const struct connection *c)
{
	jam(buf, PRI_CO, pri_co(c->serialno));
}

/*
 * A table ordered by serialno.
 */

static const struct list_info connection_serialno_list_info = {
	.name = "serialno list",
	.jam = hash_table_jam_connection_serialno,
};

static struct list_head connection_serialno_list_head = INIT_LIST_HEAD(&connection_serialno_list_head,
								       &connection_serialno_list_info);

/*
 * A table hashed by serialno.
 */

static hash_t hash_connection_serialno(const co_serial_t *serialno)
{
	return hash_thing(*serialno, zero_hash);
}

HASH_TABLE(connection, serialno, .serialno, STATE_TABLE_SIZE);

struct connection *connection_by_serialno(co_serial_t serialno)
{
	/*
	 * Note that since SOS_NOBODY is never hashed, a lookup of
	 * SOS_NOBODY always returns NULL.
	 */
	struct connection *c;
	hash_t hash = hash_connection_serialno(&serialno);
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

static hash_t hash_connection_that_id(const struct id *id)
{
	hash_t hash = zero_hash;
	if (id->kind != ID_NONE) {
		shunk_t body;
		enum ike_id_type type = id_to_payload(id, &unset_address/*ignored*/, &body);
		hash = hash_thing(type, hash);
		hash = hash_hunk(body, hash);
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

void rehash_db_connection_that_id(struct connection *c)
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
	if (filter->that_id_eq != NULL) {
		id_buf idb;
		dbg("FOR_EACH_CONNECTION[that_id_eq=%s].... in "PRI_WHERE,
		    str_id(filter->that_id_eq, &idb), pri_where(filter->where));
		hash_t hash = hash_connection_that_id(filter->that_id_eq);
		return hash_table_bucket(&connection_that_id_hash_table, hash);
	}

	dbg("FOR_EACH_CONNECTION_.... in "PRI_WHERE, pri_where(filter->where));
	return &connection_serialno_list_head;
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
 * SPD_ROUTE database.
 */

static void hash_table_jam_spd_route_remote_client(struct jambuf *buf, const void *data);

static void jam_spd_route_remote_client(struct jambuf *buf, const struct spd_route *sr)
{
	jam(buf, PRI_CO".", pri_co(sr->connection->serialno));
	jam_selectors(buf, &sr->this.client, &sr->that.client);
}

static const struct list_info spd_route_list_info = {
	.name = "spd_route list",
	.jam = hash_table_jam_spd_route_remote_client,
};

static struct list_head spd_route_list_head = INIT_LIST_HEAD(&spd_route_list_head,
							     &spd_route_list_info);

static hash_t hash_spd_route_remote_client(const ip_selector *sr)
{
	return hash_thing(sr->bytes, zero_hash);
}

HASH_TABLE(spd_route, remote_client, .that.client, STATE_TABLE_SIZE);

HASH_DB(spd_route, &spd_route_list_info, spd_route_list_entry,
	&spd_route_remote_client_hash_table);

void rehash_db_spd_route_remote_client(struct spd_route *sr)
{
	rehash_table_entry(&spd_route_remote_client_hash_table, sr);
}

static struct list_head *spd_route_filter_head(struct spd_route_filter *filter)
{
	/* select list head */
	if (filter->remote_client_range != NULL) {
		selector_buf sb;
		dbg("FOR_EACH_SPD_ROUTE[remote_client_range=%s]... in "PRI_WHERE,
		    str_selector(filter->remote_client_range, &sb), pri_where(filter->where));
		hash_t hash = hash_spd_route_remote_client(filter->remote_client_range);
		return hash_table_bucket(&spd_route_remote_client_hash_table, hash);
	}

	/* else other queries? */
	dbg("FOR_EACH_SPD_ROUTE_... in "PRI_WHERE, pri_where(filter->where));
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

	init_spd_route_hash_table_entries(sr);
	insert_list_entry(&spd_route_list_head, &sr->spd_route_list_entry);

	unshare_connection_end(&sr->this);
	unshare_connection_end(&sr->that);

	add_spd_route_to_db(sr);
	return sr;
}

/*
 * Allocate connections.
 */

static void finish_connection(struct connection *c, const char *name,
			      co_serial_t serial_from, where_t where)
{
	c->name = clone_str(name, __func__);
	c->logger = alloc_logger(c, &logger_connection_vec, where);
	/* logger is GO! */

	/* needed by jam_spd_route_*() */
	c->spd.connection = c;

	init_connection_hash_table_entries(c);
	init_spd_route_hash_table_entries(&c->spd);

	/*
	 * Update counter, set serialno and add to serialno list.
	 *
	 * The connection will be hashed after the caller has finished
	 * populating it.
	 */
	static co_serial_t connection_serialno;
	connection_serialno++;
	passert(connection_serialno > 0); /* can't overflow */
	c->serialno = connection_serialno;

	insert_list_entry(&connection_serialno_list_head, &c->serialno_list_entry);
	insert_list_entry(&spd_route_list_head, &c->spd.spd_route_list_entry);

	c->serial_from = serial_from;
	/* announce it */
	dbg_alloc(name, c, where);
}

struct connection *alloc_connection(const char *name, where_t where)
{
	struct connection *c = alloc_thing(struct connection, where->func);
	finish_connection(c, name, 0/*no template*/, where);
	return c;
}

struct connection *clone_connection(const char *name, struct connection *t, where_t where)
{
	struct connection *c = clone_thing(*t, where->func);
	finish_connection(c, name, t->serialno, where);
	return c;
}

/*
 * Maintain the contents of the hash tables.
 */

HASH_DB(connection, &connection_serialno_list_info, serialno_list_entry,
	&connection_serialno_hash_table,
	&connection_that_id_hash_table);
