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
 * structure. I.e., "struct state_list_entry *list" or "struct
 * state_entry *table[10]".
 */

struct state_entry {
	struct state_entry *next;
	struct state_entry **prev_next;
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
	struct state_entry *entries[STATE_TABLE_SIZE];
};

/*
 * Return the linked list of states that match ICOOKIE+RCOOKIE hash.
 */
struct state_entry **hash_by_state_cookies(struct state_hash_table *table,
					   const uint8_t *icookie,
					   const uint8_t *rcookie);

/*
 * Insert the state into the hash table using cookies as the hash.
 */
void insert_by_state_cookies(struct state_hash_table *table,
			     struct state_entry *entry,
			     const uint8_t *icookie, const uint8_t *rcookie);

/*
 * Iterate through all entries that match the cookie hash.
 */
#define FOR_EACH_HASH_BY_STATE_COOKIES_ENTRY(ST, TABLE, ICOOKIE,	\
					     RCOOKIE, CODE)		\
	do {								\
		struct state_entry *ST##list;				\
		ST##list = *hash_by_state_cookies(&(TABLE),		\
						  ICOOKIE, RCOOKIE);	\
		FOR_EACH_STATE_ENTRY(ST, ST##list, CODE);		\
	} while (0)

/*
 * Insert (at front) or remove the state from the linked list.
 */

void insert_state_entry(struct state_entry **list,
			struct state_entry *entry);

void remove_state_entry(struct state_entry *entry);

/*
 * Iterate through all the states in a list.
 *
 * So that the current state can be deleted keep the entry pointer one
 * step ahead.  So that a search failure can be detected leave ST=NULL
 * if the loop exits normally.
 */
#define FOR_EACH_STATE_ENTRY(ST, LIST, CODE)				\
	do {								\
		struct state_entry *ST##entry = (LIST);			\
		while (1) {						\
			if (ST##entry == NULL) {			\
				(ST) = NULL;				\
				break;					\
			}						\
			(ST) = ST##entry->state;			\
			ST##entry = ST##entry->next;			\
			CODE						\
		}							\
	} while (0)

#endif
