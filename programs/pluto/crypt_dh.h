/*
 * DH crypto functions, for libreswan
 *
 * Copyright (C) 2007-2008 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2015 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
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

#ifndef crypt_dh_h
#define crypt_dh_h

#include <pk11pub.h>

#include "chunk.h"
#include "ike_spi.h"

struct kem_desc;
struct state;
struct msg_digest;
struct logger;
struct ike_sa;
struct child_sa;

/*
 * The DH secret (opaque, but we all know it is implemented using
 * NSS).
 */
struct dh_local_secret;

struct dh_local_secret *calc_dh_local_secret(const struct kem_desc *group, struct logger *logger);
shunk_t dh_local_secret_ke(struct dh_local_secret *local_secret);
const struct kem_desc *dh_local_secret_desc(struct dh_local_secret *local_secret);

struct dh_local_secret *dh_local_secret_addref(struct dh_local_secret *local_secret, where_t where);
void dh_local_secret_delref(struct dh_local_secret **local_secret, where_t where);

/*
 * Compute dh using .st_dh_local_secret and REMOTE_KE, storing result
 * in .st_dh_shared_secret.
 */

typedef stf_status (dh_shared_secret_cb)(struct state *st,
					 struct msg_digest *md);

extern void submit_dh_shared_secret(struct state *task_st,
				    struct state *dh_st,
				    struct msg_digest *md,
				    chunk_t remote_ke,
				    dh_shared_secret_cb *callback, where_t where);

/* internal */

struct crypt_mac calc_v1_skeyid_and_iv(struct ike_sa *ike);

void calc_v2_ike_keymat(struct state *larval_ike,
			PK11SymKey *skeyseed,
			const ike_spis_t *ike_spis);

#endif
