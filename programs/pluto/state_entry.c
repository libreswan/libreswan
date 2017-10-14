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

#include "state_entry.h"
#include "log.h"

struct state_entry **state_entries_by_hash(struct state_hash_table *table,
					   unsigned long hash)
{
	hash = hash % STATE_TABLE_SIZE;
	DBG(DBG_CONTROL, DBG_log("found hash chain %lu", hash));
	return &(table->entries[hash]);
}

static void log_inserted_entry(const char *prefix, struct state_entry *entry,
			       const char *suffix)
{
	if (entry == NULL) {
		DBG(DBG_CONTROL, DBG_log("%sentry is (nil)%s", prefix, suffix));
	} else {
		DBG(DBG_CONTROL,
		    DBG_log("%sstate %p entry %p next %p prev-next %p%s",
			    prefix,
			    entry->state, entry,
			    entry->next, entry->prev_next,
			    suffix));
		passert(*entry->prev_next != NULL);
		passert(*entry->prev_next == entry);
		passert(entry->next == NULL
			|| entry->next->prev_next == &entry->next);
	}
}

void insert_state_entry(struct state_entry **list,
			struct state_entry *entry)
{
	DBG(DBG_CONTROL,
	    DBG_log("list %p first entry %p", list, *list));
	passert(entry->next == NULL && entry->prev_next == NULL);
	/* insert at the front */
	entry->next = *list;
	entry->prev_next = list;
	*list = entry;
	/* point next at us */
	if (entry->next != NULL) {
		entry->next->prev_next = &entry->next;
	}
	log_inserted_entry("inserted ", entry, " into list");
	log_inserted_entry("updated next ", entry->next, "");
}

void remove_state_entry(struct state_entry *entry)
{
	log_inserted_entry("removing ", entry, " from list");
	*entry->prev_next = entry->next;
	/* point next at prev */
	if (entry->next != NULL) {
		entry->next->prev_next = entry->prev_next;
		passert(*entry->next->prev_next == entry->next);
	}
	log_inserted_entry("updated next ", *entry->prev_next, "");
	/* reset */
	entry->next = NULL;
	entry->prev_next = NULL;
}
