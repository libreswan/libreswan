/* State lists, for libreswan
 *
 * Copyright (C) 2015, 2017 Andrew Cagney
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

#ifndef _state_entry_h_
#define _state_entry_h_

struct state;

/*
 * Double linked list of states.
 *
 * These can be stored directly in the "struct state" object avoiding
 * any need to deal with memory management.
 *
 * The list proper should be declared as a pointer to this
 * structure. I.e., "struct state_entry *list" or "struct state_entry
 * *table[10]".
 */

struct state_entry {
	struct state_entry *next;
	struct state_entry *prev;
	struct state *state;
};

/*
 * Generic state hash table.
 *
 * The functions that follow assume it is being hashed by ICOOKIE and
 * RCOOKIE.
 */

#define STATE_TABLE_SIZE 32

struct state_hash_table {
	const char *name; /* for logging */
	struct state_entry entries[STATE_TABLE_SIZE];
};

/*
 * Return the linked list of states that match ICOOKIE+RCOOKIE hash.
 */
struct state_entry *state_entries_by_hash(struct state_hash_table *table,
					  unsigned long hash);

/*
 * Insert (at front) or remove the state from the linked list.
 */

void insert_state_entry(const char *table_name,
			struct state_entry *head,
			struct state_entry *entry);

void remove_state_entry(const char *table_name,
			struct state_entry *entry);

/*
 * Iterate through all the states in a list.
 *
 * So that the current state can be deleted keep the entry pointer one
 * step ahead.
 *
 * So that a search failure can be detected leave ST=NULL if the loop
 * exits normally.
 *
 * So that 'continue' and 'break' both behave as expected from within
 * CODE, CODE must be placed at the end of the loop (at one point ST
 * was being cleared after CODE leading to a 'continue' on the final
 * entry skipping that line leaving ST non-NULL).
 */
#define FOR_EACH_STATE_ENTRY(ST, CHAIN, CODE)				\
	do {								\
		struct state_entry *ST##entry = (CHAIN)->next;		\
		(ST) = NULL;						\
		if (ST##entry != NULL) {				\
			while (true) {					\
				(ST) = ST##entry->state;		\
				if ((ST) == NULL) break;		\
				ST##entry = ST##entry->next;		\
				CODE;					\
			}						\
		}							\
	} while (0)

#endif
