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

void init_state_chain(struct state_entry *head)
{
	passert(head->state == NULL);
	if (head->next == NULL) {
		passert(head->prev == NULL);
		/* virgin list: initialize circularity */
		head->prev = head->next = head;
		DBG(DBG_CONTROL, DBG_log("initializing state chain %p", head));
	}
	passert(head->next != NULL && head->prev != NULL);
}

/* ??? this code assumes all hash tables are sized by STATE_TABLE_SIZE */
struct state_entry *state_entries_by_hash(struct state_hash_table *table,
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
	} else if (entry->prev == NULL && entry->next == NULL &&
		   entry->state == NULL) {
		DBG(DBG_CONTROL,
		    DBG_log("%s: %s entry is uninitialized HEAD %p",
			table_name, op, entry));
	} else {
		DBG(DBG_CONTROLMORE,
		    DBG_log("%s: %s state #%lu entry (prev %p) %p (next %p)",
			    table_name, op,
			    (entry->state != NULL ? entry->state->st_serialno : 0LU),
			    entry->prev, entry, entry->next));
		passert(entry->prev != NULL);
		passert(entry->prev->next == entry);
		passert(entry->next != NULL);
		passert(entry->next->prev == entry);
	}
}

void insert_state_entry(const char *table_name,
			struct state_entry *head,
			struct state_entry *entry)
{
	init_state_chain(head);

	DBG(DBG_CONTROL,
	    DBG_log("%s: inserting state #%lu entry %p into chain %p",
		    table_name,
		    entry->state->st_serialno,
		    entry,
		    head));

	passert(entry->next == NULL && entry->prev == NULL);

	/* insert at the front (between head and head->next) */
	entry->next = head->next;
	head->next = entry;

	entry->prev = head;
	entry->next->prev = entry;

	log_entry(table_name, "inserted", entry);
}

void remove_state_entry(const char *table_name,
			struct state_entry *entry)
{
	log_entry(table_name, "removing", entry);
	/* unlink */
	struct state_entry *prev = entry->prev;
	struct state_entry *next = entry->next;
	passert(entry != prev && entry != next);
	entry->next = NULL;
	entry->prev = NULL;

	prev->next = next;
	next->prev = prev;
	log_entry(table_name, "updated prev", prev);
	log_entry(table_name, "updated next ", next);
}
