/* IPsec DOI and Oakley resolution routines
 * Copyright (C) 1998-2002,2010-2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2007,2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012-2018 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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

#ifndef IPSEC_DOI_H
#define IPSEC_DOI_H

#include "pluto_timing.h"

struct fd;
struct payload_digest;
struct state;
struct jambuf;

extern void init_phase2_iv(struct state *st, const msgid_t *msgid);

extern stf_status send_isakmp_notification(struct state *st,
					   uint16_t type, const void *data,
					   size_t len);
extern void jam_child_sa_details(struct jambuf *buf, struct state *st);
extern void jam_parent_sa_details(struct jambuf *buf, struct state *st);

struct child_policy capture_child_rekey_policy(struct state *st);

#endif
