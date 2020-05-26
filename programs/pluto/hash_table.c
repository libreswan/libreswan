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

#include "lswlog.h"

#include "defs.h"
#include "hash_table.h"

const hash_t zero_hash = { 0 };

void init_hash_table(struct hash_table *table)
{
	for (unsigned i = 0; i < table->nr_slots; i++) {
		struct list_head *slot = &table->slots[i];
		*slot = (struct list_head) INIT_LIST_HEAD(slot, &table->info);
	}
}

hash_t hash_table_hasher(shunk_t data, hash_t hash)
{
	/*
	 * 251 is a prime close to 256 (so like <<8).
	 *
	 * There's no real rationale for doing this.
	 */
	const uint8_t *bytes = data.ptr;
	for (unsigned j = 0; j < data.len; j++) {
		hash.hash = hash.hash * 251 + bytes[j];
	}
	return hash;
}

struct list_head *hash_table_bucket(struct hash_table *table, hash_t hash)
{
	return &table->slots[hash.hash % table->nr_slots];
}

void add_hash_table_entry(struct hash_table *table, void *data)
{
	struct list_entry *entry = table->entry(data);
	*entry = list_entry(&table->info, data);
	hash_t hash = table->hasher(data);
	struct list_head *bucket = hash_table_bucket(table, hash);
	table->nr_entries++;
	insert_list_entry(bucket, entry);
}

void del_hash_table_entry(struct hash_table *table, void *data)
{
	struct list_entry *entry = table->entry(data);
	table->nr_entries--;
	remove_list_entry(entry);
}

void rehash_table_entry(struct hash_table *table, void *data)
{
	del_hash_table_entry(table, data);
	add_hash_table_entry(table, data);
}
