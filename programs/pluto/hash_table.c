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

void init_hash_table(struct hash_table *table)
{
	for (unsigned i = 0; i < table->nr_slots; i++) {
		init_list(&table->info, &table->slots[i]);
	}
}

struct list_head *hash_table_bucket(struct hash_table *table, shunk_t key)
{
	/*
	 * 251 is a prime close to 256 (so like <<8).
	 *
	 * There's no real rationale for doing this.
	 */
	size_t hash = 0;
	const uint8_t *bytes = key.ptr;
	for (unsigned j = 0; j < key.len; j++) {
		hash = hash * 251 + bytes[j];
	}
	return &table->slots[hash % table->nr_slots];
}

void add_hash_table_entry(struct hash_table *table, void *data)
{
	struct list_entry *entry = table->entry(data);
	*entry = list_entry(&table->info, data);
	shunk_t key = table->key(data);
	struct list_head *bucket = hash_table_bucket(table, key);
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
