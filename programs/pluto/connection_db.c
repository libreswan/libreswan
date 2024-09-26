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
#include "spd_db.h"
#include "connections.h"
#include "log.h"
#include "hash_table.h"
#include "refcnt.h"
#include "virtual_ip.h"		/* for virtual_ip_addref() */
#include "orient.h"
#include "iface.h"

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
	FOR_EACH_LIST_ENTRY_NEW2OLD(c, bucket) {
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

HASH_TABLE(connection, that_id, .remote->host.id, STATE_TABLE_SIZE);

REHASH_DB_ENTRY(connection, that_id, .remote->host.id);

void replace_connection_that_id(struct connection *c, const struct id *src)
{
	struct id *dst = &c->remote->host.id;
	passert(dst->name.ptr == NULL || dst->name.ptr != src->name.ptr);
	free_id_content(dst);
	*dst = clone_id(src, "replaing connection id");
	connection_db_rehash_that_id(c);
}

/*
 * A serial_from table.
 */

static hash_t hash_connection_clonedfrom(struct connection *const *cpp)
{
	so_serial_t serial = (*cpp == NULL ? 0 : (*cpp)->serialno);
	return hash_thing(serial, zero_hash);
}

HASH_TABLE(connection, clonedfrom, .clonedfrom, STATE_TABLE_SIZE);

/*
 * Host-pair hash table.
 */

static hash_t hash_host_pair(const ip_address *local,
			     const ip_address *remote)
{
	hash_t hash = zero_hash;
	FOR_EACH_THING(a, local, remote) {
		/*
		 * Don't include NULL, unset, ::0, and 0.0.0.0 in the
		 * hash so that they all hash to the same bucket.
		 */
		if (a != NULL && address_is_specified(*a)) {
			hash = hash_hunk(address_as_shunk(a), hash);
		}
	}
	return hash;
}

static hash_t hash_connection_host_pair(const struct connection *c)
{
	address_buf lb, rb;
	pdbg(c->logger, "%s->%s oriented=%s",
	     str_address(&c->local->host.addr, &lb),
	     str_address(&c->remote->host.addr, &rb),
	     bool_str(oriented(c)));
	if (oriented(c)) {
		PEXPECT(c->logger, address_eq_address(c->local->host.addr,
						      c->iface->local_address));
		return hash_host_pair(&c->local->host.addr, &c->remote->host.first_addr);
	} else {
		return hash_host_pair(&unset_address, &unset_address);
	}
}

HASH_TABLE(connection, host_pair, , STATE_TABLE_SIZE);

REHASH_DB_ENTRY(connection, host_pair, );

/*
 * Maintain the contents of the hash tables.
 */

HASH_DB(connection,
	&connection_clonedfrom_hash_table,
	&connection_serialno_hash_table,
	&connection_that_id_hash_table,
	&connection_host_pair_hash_table);

/*
 * See also {new2old,old2new}_state()
 */

static struct list_head *connection_filter_head(struct connection_filter *filter)
{
	const struct logger *logger = filter->search.logger;
	if (filter->that_id_eq != NULL) {
		id_buf idb;
		ldbg(logger, "FOR_EACH_CONNECTION[that_id_eq=%s].... in "PRI_WHERE,
		     str_id(filter->that_id_eq, &idb), pri_where(filter->search.where));
		hash_t hash = hash_connection_that_id(filter->that_id_eq);
		return hash_table_bucket(&connection_that_id_hash_table, hash);
	}

	if (filter->clonedfrom != NULL) {
		ldbg(logger, "FOR_EACH_CONNECTION[clonedfrom="PRI_CO"].... in "PRI_WHERE,
		     pri_connection_co(filter->clonedfrom), pri_where(filter->search.where));
		hash_t hash = hash_connection_clonedfrom(&filter->clonedfrom);
		return hash_table_bucket(&connection_clonedfrom_hash_table, hash);
	}

	if (filter->host_pair.local != NULL) {
		passert(filter->host_pair.remote != NULL);
		address_buf lb, rb;
		ldbg(logger, "FOR_EACH_CONNECTION[local=%s,remote=%s].... in "PRI_WHERE,
		     str_address(filter->host_pair.local, &lb),
		     str_address(filter->host_pair.remote, &rb),
		     pri_where(filter->search.where));
		hash_t hash = hash_host_pair(filter->host_pair.local,
					     filter->host_pair.remote);
		return hash_table_bucket(&connection_host_pair_hash_table, hash);
	}

	ldbg(logger, "FOR_EACH_CONNECTION_.... in "PRI_WHERE, pri_where(filter->search.where));
	return &connection_db_list_head;
}

static bool matches_connection_filter(struct connection *c,
				      struct connection_filter *filter)
{
	if (filter->kind != 0) {
		if (filter->kind != c->local->kind) {
			return false;
		}
	}
	if (filter->ike_version != 0) {
		if (filter->ike_version != c->config->ike_version) {
			return false;
		}
	}
	if (filter->clonedfrom != NULL) {
		if (filter->clonedfrom != c->clonedfrom) {
			return false;
		}
	}
	if (filter->name != NULL) {
		if (!streq(filter->name, c->name)) {
			return false;
		}
	}
	if (filter->alias_root != NULL) {
		if (c->root_config == NULL) {
			return false;
		}
		if (!lsw_alias_cmp(filter->alias_root, c->config->connalias)) {
			return false;
		}
	}
	if (filter->this_id_eq != NULL) {
		if (!id_eq(filter->this_id_eq, &c->local->host.id)) {
			return false;
		}
	}
	if (filter->that_id_eq != NULL) {
		if (!id_eq(filter->that_id_eq, &c->remote->host.id)) {
			return false;
		}
	}
	if (filter->host_pair.local != NULL) {
		passert(filter->host_pair.remote != NULL);
		if (is_group(c)) {
			return false;
		}
		if (never_negotiate(c)) {
			return false;
		}
		if (address_is_unset(filter->host_pair.local)) {
			if (oriented(c)) {
				return false;
			}
		} else {
			if (!oriented(c)) {
				return false;
			}
			if (!address_eq_address(c->local->host.addr, *filter->host_pair.local)) {
				return false;
			}
		}
		if (address_is_specified(*filter->host_pair.remote)) {
			/* not any */
			if (!address_eq_address(c->remote->host.addr, *filter->host_pair.remote)) {
				return false;
			}
		} else {
			/* %any */
			if (address_is_specified(c->remote->host.addr)) {
				return false;
			}
			PEXPECT_WHERE(c->logger, filter->search.where, is_template(c));
		}
	}

	return true; /* sure */
}

bool next_connection(struct connection_filter *filter)
{
	const struct logger *logger = filter->search.logger;
	/* try to stop all_connections() calls */
	passert(filter->connections == NULL);
	if (filter->internal == NULL) {
		/*
		 * First time.
		 *
		 * Some sanity checks.  Only simple and name checks
		 * can leave out .ike_version.
		 */
		if (filter->ike_version == 0) {
#if 0
			/* foodgroups searches for just CK_GROUP */
			PEXPECT_WHERE(logger, filter->search.where, filter->kind == 0);
#endif
			PEXPECT_WHERE(logger, filter->search.where, filter->clonedfrom == NULL);
			PEXPECT_WHERE(logger, filter->search.where, filter->host_pair.local == NULL);
			PEXPECT_WHERE(logger, filter->search.where, filter->host_pair.remote == NULL);
			PEXPECT_WHERE(logger, filter->search.where, filter->this_id_eq == NULL);
			PEXPECT_WHERE(logger, filter->search.where, filter->that_id_eq == NULL);
		}
		/*
		 * Advance to first entry of the circular list (if the
		 * list is entry it ends up back on HEAD which has no
		 * data).
		 */
		filter->internal = connection_filter_head(filter)->head.next[filter->search.order];
	}
	/* Walk list until an entry matches */
	filter->c = NULL;
	for (struct list_entry *entry = filter->internal;
	     entry->data != NULL /* head has DATA == NULL */;
	     entry = entry->next[filter->search.order]) {
		struct connection *c = (struct connection *) entry->data;
		if (matches_connection_filter(c, filter)) {
			/* save connection; but step off current entry */
			filter->internal = entry->next[filter->search.order];
			filter->count++;
			LDBGP_JAMBUF(DBG_BASE, logger, buf) {
				jam_string(buf, "  found ");
				jam_connection(buf, c);
			}
			filter->c = c;
			return true;
		}
	}
	ldbg(logger, "  matches: %d", filter->count);
	return false;
}

bool all_connections(struct connection_filter *filter)
{
	const struct logger *logger = filter->search.logger;
	/* try to stop next_connection() calls */
	PASSERT_WHERE(logger, filter->search.where, filter->internal == NULL);

	if (filter->connections == NULL) {

		unsigned count = 0;
		{
			struct connection_filter iterator = *filter;
			while (next_connection(&iterator)) {
				count++;
			}
		}

		if (count == 0) {
			return false; /* nothing to see */
		}

		/*
		 * Over allocate array so that it is NULL terminated.  Since
		 * next_connection() passerts .connections==NULL, hold off on
		 * saving connections.
		 */
		struct connection **connections =
			alloc_things(struct connection*, count+1, __func__);

		{
			struct connection_filter iterator = iterator = *filter;
			unsigned i = 0;
			while (next_connection(&iterator)) {
				PASSERT(logger, refcnt_peek(iterator.c, logger) >= 1);
				connections[i++] = connection_addref(iterator.c, logger);
				PASSERT(logger, refcnt_peek(iterator.c, logger) > 1);
			}
			PASSERT(logger, i == count);
			PASSERT(logger, connections[i] == NULL);
		}
		filter->connections = connections;
	}

	/*
	 * Delete and skip any connections that have somehow been
	 * reduced to one reference.
	 *
	 * XXX: refcnt_peek() returns 0 for NULL.
	 */

	while (refcnt_peek(filter->connections[filter->count], logger) == 1) {
		connection_delref(&filter->connections[filter->count], logger);
		filter->count++;
	}

	/*
	 * Save/return the connection.
	 */
	filter->c = filter->connections[filter->count];
	if (filter->c != NULL) {
		PASSERT(logger, refcnt_peek(filter->c, logger) > 1);
		connection_delref(&filter->connections[filter->count], logger);
		filter->count++;
		return true;
	}

	/* all done */
	pfreeany(filter->connections);
	return false;
}
