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
 * Return the hash chain for the given value.  It will contain may
 * entries, not just the specified value.  Extra filtering is
 * required!
 */

/* ICOOKIE chain */
extern struct state_entry *icookie_chain(const uint8_t *icookie);
/* ICOOKIE:RCOOKIE chain */
struct state_entry *cookies_chain(const uint8_t *icookie,
				  const uint8_t *rcookie);

/* XXX: should not be public */
extern struct state_hash_table cookies_hash_table;

#endif
