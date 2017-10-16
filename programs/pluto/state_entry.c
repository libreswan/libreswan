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
#include "state.h"
#include "state_entry.h"

struct state_entry **state_entries_by_hash(struct state_hash_table *table,
					   unsigned long hash)
{
	/* let caller do logging */
	return &(table->entries[hash % STATE_TABLE_SIZE]);
}

static void log_entry(const char *table_name,
		      const char *op, struct state_entry *entry)
{
	if (entry == NULL) {
		DBG(DBG_CONTROLMORE,
		    DBG_log("%s: %s entry is NULL", table_name, op));
	} else {
		DBG(DBG_CONTROLMORE,
		    DBG_log("%s: %s state #%lu entry (prev %p) %p (next %p)",
			    table_name, op,
			    (entry->state != NULL ? entry->state->st_serialno : 0LU),
			    entry->prev_next, entry, entry->next));
		passert(*entry->prev_next != NULL);
		passert(*entry->prev_next == entry);
		passert(entry->next == NULL
			|| entry->next->prev_next == &entry->next);
	}
}

void insert_state_entry(const char *table_name,
			struct state_entry **head,
			struct state_entry *entry)
{
	DBG(DBG_CONTROL,
	    DBG_log("%s: inserting state #%lu entry %p into chain %p (head %p)",
		    table_name,
		    (entry->state != NULL ? entry->state->st_serialno : 0LU),
		    entry, head, *head));
	passert(entry->next == NULL && entry->prev_next == NULL);
	/* insert at the front */
	entry->next = *head;
	entry->prev_next = head;
	*head = entry;
	/* point next at us */
	if (entry->next != NULL) {
		entry->next->prev_next = &entry->next;
	}
	log_entry(table_name, "inserted", entry);
}

void remove_state_entry(const char *table_name,
			struct state_entry *entry)
{
	log_entry(table_name, "removing", entry);
	*entry->prev_next = entry->next;
	/* point next at prev */
	if (entry->next != NULL) {
		entry->next->prev_next = entry->prev_next;
		passert(*entry->next->prev_next == entry->next);
	}
	/* reset */
	entry->next = NULL;
	entry->prev_next = NULL;
}
