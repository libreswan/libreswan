/* State lists and hash tables, for libreswan
 *
 * Copyright (C) 2015 Andrew Cagney <andrew.cagney@gmail.com>
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

#include <stdint.h>

#include "defs.h"
#include "hash_table.h"

#include "log.h"

const hash_t zero_hash = { 0 };

void init_hash_table(struct hash_table *table, struct logger *logger)
{
	ldbg(logger, "initialize %s hash table", table->info->name);
	for (unsigned i = 0; i < table->nr_slots; i++) {
		struct list_head *slot = &table->slots[i];
		*slot = (struct list_head) INIT_LIST_HEAD(slot, table->info);
	}
}

hash_t hash_bytes(const void *ptr, size_t len, hash_t hash)
{
	/*
	 * 251 is a prime close to 256 (so like <<8).
	 *
	 * There's no real rationale for doing this.
	 */
	const uint8_t *bytes = ptr;
	for (unsigned j = 0; j < len; j++) {
		hash.hash = hash.hash * 251 + bytes[j];
	}
	return hash;
}

struct list_head *hash_table_bucket(struct hash_table *table, hash_t hash)
{
	return &table->slots[hash.hash % table->nr_slots];
}

void init_hash_table_entry(struct hash_table *table, void *data)
{
	LDBGP_JAMBUF(DBG_TMI, &global_logger, buf) {
		jam(buf, "entry %s@%p ", table->info->name, data);
		table->info->jam(buf, data);
		jam(buf, " initialized");
	}
	struct list_entry *entry = table->entry(data);
	init_list_entry(table->info, data, entry);
}

void add_hash_table_entry(struct hash_table *table, void *data)
{
	struct list_entry *entry = table->entry(data);
	hash_t hash = table->hasher(data);
	struct list_head *bucket = hash_table_bucket(table, hash);
	insert_list_entry(bucket, entry);
	table->nr_entries++;
	LDBGP_JAMBUF(DBG_TMI, &global_logger, buf) {
		jam(buf, "entry %s@%p ", table->info->name, data);
		table->info->jam(buf, data);
		jam(buf, " added to hash table bucket %p", bucket);
	}
}

void del_hash_table_entry(struct hash_table *table, void *data)
{
	LDBGP_JAMBUF(DBG_TMI, &global_logger, buf) {
		jam(buf, "entry %s@%p ", table->info->name, data);
		table->info->jam(buf, data);
		/* HEAD AKA BUCKET isn't directly known */
		jam(buf, " deleted from hash table");
	}
	struct list_entry *entry = table->entry(data);
	remove_list_entry(entry);
	table->nr_entries--;
}

/*
 * Check that the data hashes to the correct bucket.
 *
 * (Remember, since there's only one list entry, the data can be in
 * at-most one bucket at a time).
 */

static void check_hash_table_entry(struct hash_table *table, void *data,
				   const struct logger *logger, where_t where)
{
	hash_t hash = table->hasher(data);
	/* not inserted (might passert) */
	if (detached_list_entry(table->entry(data))) {
		return;
	}
	/* hope for the best ... */
	{
		struct list_head *data_bucket = hash_table_bucket(table, hash);
		void *bucket_data;
		FOR_EACH_LIST_ENTRY_NEW2OLD(bucket_data, data_bucket) {
			if (data == bucket_data) {
				return;
			}
		}
	}
	/* ... but plan for the worst */
	for (unsigned n = 0; n < table->nr_slots; n++) {
		const struct list_head *table_bucket = &table->slots[n];
		void *bucket_data;
		FOR_EACH_LIST_ENTRY_NEW2OLD(bucket_data, table_bucket) {
			if (data == bucket_data) {
				LLOG_PEXPECT_JAMBUF(logger, where, buf) {
					jam(buf, "entry %s@%p ", table->info->name, data);
					table->info->jam(buf, data);
					jam_string(buf, " is in the wrong bucket");
				}
				return;
			}
		}
	}
	LLOG_PEXPECT_JAMBUF(logger, where, buf) {
		jam(buf, "entry %s@%p ", table->info->name, data);
		table->info->jam(buf, data);
		jam_string(buf, " is missing");
	}
}

void check_hash_table(struct hash_table *table, const struct logger *logger, where_t where)
{
	for (unsigned n = 0; n < table->nr_slots; n++) {
		const struct list_head *table_bucket = &table->slots[n];
		void *bucket_data;
		FOR_EACH_LIST_ENTRY_NEW2OLD(bucket_data, table_bucket) {
			/* overkill */
			check_hash_table_entry(table, bucket_data, logger, where);
		}
	}
}
