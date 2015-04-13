/*
 * prf and keying material helper functions, for libreswan
 *
 * Copyright (C) 2007 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2015 Andrew Cagney <cagney@gnu.org>
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

#ifndef crypt_prf_h
#define crypt_prf_h

#include <pk11pub.h>

/* Implement PRF described in rfc2104. */
PK11SymKey *crypt_prf(const struct hash_desc *hasher,
		      PK11SymKey *key, PK11SymKey *seed);

/* Implement PRF+ described in RFC 7296. */
PK11SymKey *crypt_prfplus(const struct hash_desc *hasher,
			  PK11SymKey *key, PK11SymKey *seed,
			  size_t required_keymat);

#endif
