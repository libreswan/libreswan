/* State table indexed by serialno, for libreswan
 *
 * Copyright (C) 2017-2019 Andrew Cagney
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#ifndef STATE_DB_H
#define STATE_DB_H

#include "ike_spi.h"

struct state;
struct list_entry;

void init_state_db(void);

void add_state_to_db(struct state *st);
void rehash_state_cookies_in_db(struct state *st);
void del_state_from_db(struct state *st);

struct state *state_by_serialno(so_serial_t serialno);

/*
 * List of all valid states; can be iterated in old-to-new and
 * new-to-old order.
 */

extern struct list_head serialno_list_head;

#define FOR_EACH_STATE_NEW2OLD(ST)				\
	FOR_EACH_LIST_ENTRY_NEW2OLD(&serialno_list_head, ST)

#define FOR_EACH_STATE_OLD2NEW(ST)				\
	FOR_EACH_LIST_ENTRY_OLD2NEW(&serialno_list_head, ST)


/*
 * Return the slot for the given hash value.  It will contain may
 * entries, not just the specified value.  Extra filtering is
 * required!
 *
 * XXX: being replace by ...
 */

struct list_head *ike_spis_slot(const ike_spis_t *spis);
struct list_head *ike_spi_slot(const ike_spi_t *initiator,
			       const ike_spi_t *responder);

/*
 * Lookup and generic search functions.
 */

struct state *state_by_ike_initiator_spi(enum ike_version ike_version,
					 so_serial_t clonedfrom,
					 const msgid_t *msgid, /* optional */
					 const ike_spi_t *ike_initiator_spi);

#endif
