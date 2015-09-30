/*
 * Calculate IKEv1 prf and keying material, for libreswan
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

#ifndef ikev1_prf_h
#define ikev1_prf_h

/*
 * IKE SA SKEYID for authentication
 *
 * Be warned, this is not DSS (even though NIST call it Digital
 * Signature Algorithm).  It is used by RSA-SIG.
 */
PK11SymKey *ikev1_signature_skeyid(const struct hash_desc *hasher,
				   const chunk_t Ni_b, const chunk_t Nr_b,
				   PK11SymKey *dh_secret);

PK11SymKey *ikev1_pre_shared_key_skeyid(const struct hash_desc *hasher,
					chunk_t pre_shared_key,
					chunk_t Ni_b, chunk_t Nr_b,
					PK11SymKey *scratch);

/*
 * Authenticated keying material.
 *
 *  Perhaps this should just return a struct?
 */

PK11SymKey *ikev1_skeyid_d(const struct hash_desc *hasher,
			   PK11SymKey *skeyid,
			   PK11SymKey *dh_secret,
			   chunk_t cky_i, chunk_t cky_r);

PK11SymKey *ikev1_skeyid_a(const struct hash_desc *hasher,
			   PK11SymKey *skeyid,
			   PK11SymKey *skeyid_d, PK11SymKey *dh_secret,
			   chunk_t cky_i, chunk_t cky_r);

PK11SymKey *ikev1_skeyid_e(const struct hash_desc *hasher,
			   PK11SymKey *skeyid,
			   PK11SymKey *skeyid_a, PK11SymKey *dh_secret,
			   chunk_t cky_i, chunk_t cky_r);

/*
 * Old way.
 */
struct pluto_crypto_req;

void calc_dh_iv(struct pluto_crypto_req *r);

#endif
