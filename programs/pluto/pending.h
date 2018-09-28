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

#include "monotime.h"
#include "fd.h"

void flush_pending_by_connection(const struct connection *c);
bool in_pending_use(const struct connection *c);
void show_pending_phase2(const struct connection *c, const struct state *st);
bool pending_check_timeout(const struct connection *c);

extern struct connection *first_pending(const struct state *st,
					lset_t *policy,
					fd_t *p_whack_sock);

/* struct pending, the structure representing IPsec SA
 * negotiations delayed until a Keying Channel has been negotiated.
 * Essentially, a pending call to quick_outI1 or ikev2 child initiate
 */

struct pending {
	fd_t whack_sock;
	struct state *isakmp_sa;
	struct connection *connection;
	lset_t policy;
	unsigned long try;
	so_serial_t replacing;
	monotime_t pend_time;

#ifdef HAVE_LABELED_IPSEC
	struct xfrm_user_sec_ctx_ike *uctx;
#endif

	struct pending *next;
};
