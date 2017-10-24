/* State table indexed by serialno, for libreswan
 *
 * Copyright (C) 2017 Andrew Cagney
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

#ifndef _state_db_h_
#define _state_db_h_

#include "state_entry.h"

void add_state_to_db(struct state *st);
void rehash_state_cookies_in_db(struct state *st);
void del_state_from_db(struct state *st);

struct state *state_by_serialno(so_serial_t serialno);

/*
 * List of all valid states; can be iterated in old-to-new and
 * new-to-old order.
 */

extern struct list_entry serialno_list_head;

#define FOR_EACH_STATE_NEW2OLD(ST)				\
	FOR_EACH_LIST_ENTRY_NEW2OLD(&serialno_list_head, ST)

#define FOR_EACH_STATE_OLD2NEW(ST)				\
	FOR_EACH_LIST_ENTRY_OLD2NEW(&serialno_list_head, ST)


/*
 * Return the hash chain for the given value.  It will contain may
 * entries, not just the specified value.  Extra filtering is
 * required!
 */

/* ICOOKIE chain */
extern struct state_entry *icookie_chain(const uint8_t *icookie);
/* ICOOKIE:RCOOKIE chain */
struct state_entry *cookies_chain(const uint8_t *icookie,
				  const uint8_t *rcookie);

#endif
