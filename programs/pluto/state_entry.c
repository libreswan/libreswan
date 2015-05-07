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

struct state_entry **hash_by_state_cookies(struct state_hash_table *table,
					   const uint8_t *icookie,
					   const uint8_t *rcookie)
{
	DBG(DBG_RAW | DBG_CONTROL, {
			DBG_log("finding hash chain in %s", table->name);
			DBG_dump("  ICOOKIE:", icookie, COOKIE_SIZE);
			DBG_dump("  RCOOKIE:", rcookie, COOKIE_SIZE);
		});

	/* XXX the following hash is pretty pathetic */
	unsigned i = 0;
	unsigned j;
	for (j = 0; j < COOKIE_SIZE; j++)
		i = i * 407 + icookie[j] + rcookie[j];
	i = i % STATE_TABLE_SIZE;

	DBG(DBG_CONTROL, DBG_log("found hash chain %d", i));
	return &(table->entries[i]);
}

void insert_by_state_cookies(struct state_hash_table *table,
			     struct state_entry *entry,
			     const uint8_t *icookie,
			     const uint8_t *rcookie)
{
	struct state_entry **chain = hash_by_state_cookies(table, icookie, rcookie);
	insert_state_entry(chain, entry);
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
