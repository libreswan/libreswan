/* hash table and linked lists, for libreswan
 *
 * Copyright (C) 2015, 2017, 2019 Andrew Cagney
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

#ifndef _hash_table_h_
#define _hash_table_h_

#include "list_entry.h"
#include "shunk.h"		/* has constant ptr */

/*
 * Generic hash table.
 */

typedef struct { unsigned hash; } hash_t;
extern const hash_t zero_hash;

struct hash_table {
	const struct list_info info;
	hash_t (*hasher)(const void *data);
	struct list_entry *(*entry)(void *data);
	long nr_entries; /* approx? */
	unsigned long nr_slots;
	struct list_head *slots;
};

void init_hash_table(struct hash_table *table);

hash_t hash_table_hasher(shunk_t data, hash_t hash);

/*
 * Maintain the table.
 *
 * Use the terms "add" and "del" as this table has no implied
 * ordering.  rehash does "del" then "add".
 */
void add_hash_table_entry(struct hash_table *table, void *data);
void del_hash_table_entry(struct hash_table *table, void *data);
void rehash_table_entry(struct hash_table *table, void *data);

/*
 * Return the head of the list entries that match HASH.
 *
 * Use this, in conjunction with FOR_EACH_LIST_ENTRY, when searching.
 *
 * Don't forget to also check that the object itself matches - more
 * than one hash can map to the same list of entries.
 */

struct list_head *hash_table_bucket(struct hash_table *table, hash_t hash);

#endif
