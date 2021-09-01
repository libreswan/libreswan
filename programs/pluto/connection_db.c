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

static struct hash_table connection_hash_tables[];

static void jam_connection_serialno(struct jambuf *buf, const void *data)
{
	if (data == NULL) {
		jam(buf, PRI_CO, UNSET_CO_SERIAL);
	} else {
		const struct connection *c = data;
		jam(buf, PRI_CO, pri_co(c->serialno));
	}
}

/*
 * A table ordered by serialno.
 */

static const struct list_info connection_serialno_list_info = {
	.name = "serialno list",
	.jam = jam_connection_serialno,
};

static struct list_head connection_serialno_list_head = INIT_LIST_HEAD(&connection_serialno_list_head,
								       &connection_serialno_list_info);

/*
 * A table hashed by serialno.
 */

static hash_t serialno_hasher(const co_serial_t *serialno)
{
	return hash_table_hasher(shunk2(serialno, sizeof(*serialno)), zero_hash);
}

static hash_t connection_serialno_hasher(const void *data)
{
	const struct connection *c = data;
	return serialno_hasher(&c->serialno);
}

static struct list_entry *connection_serialno_entry(void *data)
{
	struct connection *c = data;
	return &c->hash_table_entries[CONNECTION_SERIALNO_HASH_TABLE];
}

struct connection *connection_by_serialno(co_serial_t serialno)
{
	/*
	 * Note that since SOS_NOBODY is never hashed, a lookup of
	 * SOS_NOBODY always returns NULL.
	 */
	struct connection *c;
	hash_t hash = serialno_hasher(&serialno);
	struct list_head *bucket = hash_table_bucket(&connection_hash_tables[CONNECTION_SERIALNO_HASH_TABLE], hash);
	FOR_EACH_LIST_ENTRY_NEW2OLD(bucket, c) {
		if (c->serialno == serialno) {
			return c;
		}
	}
	return NULL;
}

/*
 * See also {new2old,old2new}_state()
 */

static struct list_head *filter_head(struct connection_filter *filter)
{
	struct list_head *bucket = &connection_serialno_list_head;
	dbg("FOR_EACH_CONNECTION_.... in "PRI_WHERE, pri_where(filter->where));
	return bucket;
}

static bool matches_filter(struct connection *c, struct connection_filter *filter)
{
	if (filter->kind != 0 && filter->kind != c->kind) {
		return false;
	}
	if (filter->name != NULL && !streq(filter->name, c->name)) {
		return false;
	}
	if (filter->this_id != NULL && !same_id(filter->this_id, &c->spd.this.id)) {
		return false;
	}
	if (filter->that_id != NULL && !same_id(filter->that_id, &c->spd.that.id)) {
		return false;
	}
	return true; /* sure */
}

bool next_connection_old2new(struct connection_filter *filter)
{
#define ADV newer
	if (filter->internal == NULL) {
		/*
		 * Advance to first entry of the circular list (if the
		 * list is entry it ends up back on HEAD which has no
		 * data).
		 */
		filter->internal = filter_head(filter)->head.ADV;
	}
	/* Walk list until an entry matches */
	filter->c = NULL;
	for (struct list_entry *entry = filter->internal;
	     entry->data != NULL /* head has DATA == NULL */;
	     entry = entry->ADV) {
		struct connection *c = (struct connection *) entry->data;
		if (matches_filter(c, filter)) {
			/* save connection; but step off current entry */
			filter->internal = entry->ADV;
			dbg("found "PRI_CO" for "PRI_WHERE,
			    pri_co(c->serialno), pri_where(filter->where));
			filter->c = c;
			return true;
		}
	}
	dbg("no match for "PRI_WHERE, pri_where(filter->where));
	return false;
#undef ADV
}

bool next_connection_new2old(struct connection_filter *filter)
{
#define ADV older
	if (filter->internal == NULL) {
		/*
		 * Advance to first entry of the circular list (if the
		 * list is entry it ends up back on HEAD which has no
		 * data).
		 */
		filter->internal = filter_head(filter)->head.ADV;
	}
	/* Walk list until an entry matches */
	filter->c = NULL;
	for (struct list_entry *entry = filter->internal;
	     entry->data != NULL /* head has DATA == NULL */;
	     entry = entry->ADV) {
		struct connection *c = (struct connection *) entry->data;
		if (matches_filter(c, filter)) {
			/* save connection; but step off current entry */
			filter->internal = entry->ADV;
			dbg("found "PRI_CO" for "PRI_WHERE,
			    pri_co(c->serialno), pri_where(filter->where));
			filter->c = c;
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

static struct list_head hash_slots[CONNECTION_HASH_TABLES_ROOF][STATE_TABLE_SIZE];

static struct hash_table connection_hash_tables[] = {
	[CONNECTION_SERIALNO_HASH_TABLE] = {
		.info = {
			.name = "st_serialno table",
			.jam = jam_connection_serialno,
		},
		.hasher = connection_serialno_hasher,
		.entry = connection_serialno_entry,
		.nr_slots = elemsof(hash_slots[CONNECTION_SERIALNO_HASH_TABLE]),
		.slots = hash_slots[CONNECTION_SERIALNO_HASH_TABLE],
	},
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
		add_hash_table_entry(&connection_hash_tables[h], c);
	}
}

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

void remove_connection_from_db(struct connection *c)
{
	dbg("Connection DB: deleting connection "PRI_CO, pri_co(c->serialno));
	remove_list_entry(&c->serialno_list_entry);
	for (unsigned h = 0; h < elemsof(connection_hash_tables); h++) {
		del_hash_table_entry(&connection_hash_tables[h], c);
	}
}

void init_connection_db(void)
{
	for (unsigned h = 0; h < elemsof(connection_hash_tables); h++) {
		init_hash_table(&connection_hash_tables[h]);
	}
}
