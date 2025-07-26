/* Calculate IKEv2 prf and keying material, for libreswan
 *
 * Copyright (C) 2007 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
 * Copyright (C) 2020 Nupur Agrawal <nupur202000@gmail.com>
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

#ifndef _IKEV2_PRF_H
#define _IKEV2_PRF_H

#include "lswnss.h"
#include "ike_spi.h"
#include "chunk.h"
#include "shunk.h"

struct prf_desc;

/*
 * IKE SA
 */
PK11SymKey *ikev2_prfplus(const struct prf_desc *prf_desc,
			  PK11SymKey *key, PK11SymKey *seed,
			  size_t required_keymat,
			  struct logger *logger);

PK11SymKey *ikev2_ike_sa_skeyseed(const struct prf_desc *prf_desc,
				  const chunk_t Ni, const chunk_t Nr,
				  PK11SymKey *ke_secret,
				  struct logger *logger);

PK11SymKey *ikev2_ike_sa_rekey_skeyseed(const struct prf_desc *prf_desc,
					PK11SymKey *old_SK_d,
					PK11SymKey *new_ke_secret,
					const chunk_t Ni, const chunk_t Nr,
					struct logger *logger);

PK11SymKey *ikev2_ike_sa_keymat(const struct prf_desc *prf_desc,
				PK11SymKey *skeyseed,
				const chunk_t Ni, const chunk_t Nr,
				const ike_spis_t *ike_spis,
				size_t required_bytes,
				struct logger *logger);

PK11SymKey *ikev2_ike_sa_ppk_interm_skeyseed(const struct prf_desc *prf_desc,
					     PK11SymKey *old_SK_d,
					     shunk_t ppk,
					     struct logger *logger);

PK11SymKey *ikev2_ike_sa_resume_skeyseed(const struct prf_desc *prf_desc,
					 PK11SymKey *old_SK_d,
					 const chunk_t Ni, const chunk_t Nr,
					 struct logger *logger);

/*
 * Child SA
 */
PK11SymKey *ikev2_child_sa_keymat(const struct prf_desc *prf_desc,
				  PK11SymKey *SK_d,
				  PK11SymKey *new_ke_secret,
				  const chunk_t Ni, const chunk_t Nr,
				  size_t required_bytes,
				  struct logger *logger);

/*
 * Authentication.
 */

struct crypt_mac ikev2_psk_auth(const struct prf_desc *prf_desc, shunk_t pss,
				chunk_t first_packet, chunk_t nonce,
				const struct crypt_mac *id_hash,
				chunk_t intermediate_packet,
				struct logger *logger);

struct crypt_mac ikev2_psk_resume(const struct prf_desc *prf_desc,
				  PK11SymKey *SK_px,
				  chunk_t first_packet,
				  struct logger *logger);

#endif
