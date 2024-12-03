/*
 * IPsec DOI and Oakley resolution routines
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2008 Ilia Sotnikov
 * Copyright (C) 2009 Seong-hun Lim
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010-2019 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
 * Copyright (C) 2013-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
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

#ifndef IKEV1_DELETE_H
#define IKEV1_DELETE_H

#include <stdbool.h>

#include "where.h"

struct ike_sa;
struct state;
struct msg_digest;
struct payload_digest;

void send_v1_delete(struct ike_sa *isakmp, struct state *st, where_t where);
void llog_n_maybe_send_v1_delete(struct ike_sa *isakmp, struct state *st, where_t where);

void handle_v1_delete_payloads(struct ike_sa **ike_or_null,
			       struct msg_digest *md);

#endif
