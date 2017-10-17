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
		    DBG_log("%s: %s entry is HEAD", table_name, op));
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
	DBG(DBG_CONTROL,
	    DBG_log("%s: inserting state #%lu entry %p into chain (prev %p) %p (next %p)",
		    table_name,
		    (entry->state != NULL ? entry->state->st_serialno : 0LU),
		    entry,
		    head->prev, head, head->next));
	passert(entry->next == NULL && entry->prev == NULL);
	if (head->prev == NULL && head->next == NULL) {
		entry->prev = head;
		entry->next = head;
		head->prev = entry;
		head->next = entry;
	} else {
		/* insert at the front */
		entry->next = head->next;
		entry->next->prev = entry;
		entry->prev = head;
		head->next = entry;
		/* head->prev = head->prev; */
	}
	log_entry(table_name, "inserted", entry);
}

void remove_state_entry(const char *table_name,
			struct state_entry *entry)
{
	log_entry(table_name, "removing", entry);
	/* unlink */
	struct state_entry *prev = entry->prev;
	struct state_entry *next = entry->next;
	entry->next = NULL;
	entry->prev = NULL;
	/* kill loop if empty.  Needed? */
	if (prev == next) {
		/* the head */
		prev->next = NULL;
		next->prev = NULL;
		DBG(DBG_CONTROL, DBG_log("%s: empty", table_name));
	} else {
		prev->next = next;
		next->prev = prev;
		log_entry(table_name, "updated prev", prev);
		log_entry(table_name, "updated next ", next);
	}
}
