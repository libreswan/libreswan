/* information about connections between hosts and clients
 *
 * Copyright (C) 1998-2002,2013,2015 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2011 Anthony Tong <atong@TrustedCS.com>
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

#ifndef PENDING_H
#define PENDING_H

#include "monotime.h"
#include "fd.h"
#include "lset.h"
#include "chunk.h"

struct state;
struct show;

/*
 * struct pending, the structure representing IPsec SA negotiations
 * delayed until a Keying Channel (IKE SA) has been negotiated.
 * Essentially, a pending call to quick_outI1 or ikev2 child initiate
 */

struct pending {
	struct logger *logger;
	struct ike_sa *ike;
	struct connection *connection;
	lset_t policy;
	so_serial_t replacing;
	monotime_t pend_time;
	shunk_t sec_label;
	struct pending *next;
};

void append_pending(struct ike_sa *ike,
		    struct connection *c, /*has whack*/
		    lset_t policy,
		    so_serial_t replacing,
		    shunk_t sec_label,
		    bool part_of_initiating_ike_sa,
		    bool detach_whack);

void unpend(struct ike_sa *ike, struct connection *cc);
void release_pending_whacks(struct state *st, err_t story);
void move_pending(struct ike_sa *old, struct ike_sa *new);

void remove_connection_from_pending(const struct connection *c);
void flush_pending_by_state(struct ike_sa *ike);

bool connection_is_pending(const struct connection *c);

extern struct connection *first_pending(const struct ike_sa *ike);

#endif
