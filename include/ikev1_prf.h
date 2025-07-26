/*
 * Calculate IKEv1 prf and keying material, for libreswan
 *
 * Copyright (C) 2007 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
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

#ifndef ikev1_prf_h
#define ikev1_prf_h

#include "lswnss.h"
#include "chunk.h"

struct prf_desc;
struct encrypt_desc;

/*
 * IKE SA SKEYID for authentication
 *
 * Be warned, this is not DSS (even though NIST call it Digital
 * Signature Algorithm).  It is used by RSA-SIG.
 */
PK11SymKey *ikev1_signature_skeyid(const struct prf_desc *prf_desc,
				   const chunk_t Ni_b, const chunk_t Nr_b,
				   PK11SymKey *ke_secret,
				   struct logger *logger);

PK11SymKey *ikev1_pre_shared_key_skeyid(const struct prf_desc *prf_desc,
					const struct secret_preshared_stuff *pre_shared_key,
					chunk_t Ni_b, chunk_t Nr_b,
					struct logger *logger);

/*
 * Authenticated keying material.
 *
 *  Perhaps this should just return a struct?
 */

PK11SymKey *ikev1_skeyid_d(const struct prf_desc *prf_desc,
			   PK11SymKey *skeyid,
			   PK11SymKey *ke_secret,
			   chunk_t cky_i, chunk_t cky_r,
			   struct logger *logger);

PK11SymKey *ikev1_skeyid_a(const struct prf_desc *prf_desc,
			   PK11SymKey *skeyid,
			   PK11SymKey *skeyid_d, PK11SymKey *ke_secret,
			   chunk_t cky_i, chunk_t cky_r,
			   struct logger *logger);

PK11SymKey *ikev1_skeyid_e(const struct prf_desc *prf_desc,
			   PK11SymKey *skeyid,
			   PK11SymKey *skeyid_a, PK11SymKey *ke_secret,
			   chunk_t cky_i, chunk_t cky_r,
			   struct logger *logger);

PK11SymKey *ikev1_appendix_b_keymat_e(const struct prf_desc *prf_desc,
				      const struct encrypt_desc *encrypter,
				      PK11SymKey *skeyid_e,
				      unsigned required_keymat,
				      struct logger *logger);

chunk_t ikev1_section_5_keymat(const struct prf_desc *prf,
			       PK11SymKey *SKEYID_d,
			       PK11SymKey *g_xy,
			       uint8_t protocol,
			       shunk_t SPI,
			       chunk_t NI_b, chunk_t Nr_b,
			       unsigned required_keymat,
			       struct logger *logger);

#endif
