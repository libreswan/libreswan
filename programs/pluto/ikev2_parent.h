/* IKEv2 IKE SA (parent) creation routines, for Libreswan
 *
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010-2019 Tuomo Soini <tis@foobar.fi
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012-2018 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017-2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2017-2018 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
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
 *
 */

#ifndef IKEV2_PARENT_H
#define IKEV2_PARENT_H

#include <stdbool.h>

#include "chunk.h"

struct pbs_in;
struct pbs_out;
struct ike_sa;
struct msg_digest;
enum ikev2_auth_method;
struct child_sa;
struct dh_desc;
struct state;

bool negotiate_hash_algo_from_notification(const struct pbs_in *payload_pbs,
					   struct ike_sa *ike);
bool accept_v2_nonce(struct logger *logger, struct msg_digest *md,
		     chunk_t *dest, const char *name);
void process_v2_request_no_skeyseed(struct ike_sa *ike, struct msg_digest *md);
void llog_v2_ike_sa_established(struct ike_sa *ike, struct child_sa *larval);
void v2_ike_sa_established(struct ike_sa *ike);
bool id_ipseckey_allowed(struct ike_sa *ike, enum ikev2_auth_method atype);
bool emit_v2KE(chunk_t g, const struct dh_desc *group, struct pbs_out *outs);
void ikev2_rekey_expire_predecessor(const struct child_sa *larval_sa, so_serial_t pred);
void schedule_v2_replace_event(struct state *st);
bool v2_state_is_expired(struct state *st, const char *verb);

#endif
