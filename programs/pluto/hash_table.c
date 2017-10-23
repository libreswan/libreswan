/* State lists and hash tables, for libreswan
 *
 * Copyright (C) 2015 Andrew Cagney <andrew.cagney@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
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

struct list_entry *hash_table_slot_by_hash(struct hash_table *table,
					   unsigned long hash)
{
	/* let caller do logging */
	return &table->slots[hash % table->nr_slots];
}

void add_hash_table_entry(struct hash_table *table,
			  void *data, struct list_entry *entry)
{
	entry->data = data;
	struct list_entry *slot =
		hash_table_slot_by_hash(table, table->hash(data));
	table->nr_entries++;
	insert_list_entry(&table->info, slot, entry);
}

void del_hash_table_entry(struct hash_table *table,
			  struct list_entry *entry)
{
	table->nr_entries--;
	remove_list_entry(&table->info, entry);
}
