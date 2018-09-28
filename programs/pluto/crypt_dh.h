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
 * Copyright (C) 2015,2017 Andrew Cagney <cagney@gnu.org>
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

struct oakley_group_desc;
struct state;

/*
 * The DH secret (opaque, but we all know it is implemented using
 * NSS).
 */
struct dh_secret;

struct dh_secret *calc_dh_secret(const struct oakley_group_desc *group,
				 chunk_t *ke);

PK11SymKey *calc_dh_shared(struct dh_secret *secret,
			   chunk_t remote_ke);

void transfer_dh_secret_to_state(const char *helper, struct dh_secret **secret,
				 struct state *st);

void transfer_dh_secret_to_helper(struct state *st,
				  const char *helper, struct dh_secret **secret);

void free_dh_secret(struct dh_secret **secret);

#endif
