/* prf and keying material helper functions, for libreswan
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

#ifndef crypt_prf_h
#define crypt_prf_h

#include <pk11pub.h>

#include "chunk.h"
#include "crypt_mac.h"

struct hash_desc;
struct crypt_prf;

/*
 * FIPS requires a minimum key size.  In FIPS mode, when the key is
 * less than this, the init will fail.  Here the "floor" is the
 * minimum of all the fips algorithms so failing this is really bad.
 */
size_t crypt_prf_fips_key_size_min(const struct prf_desc *prf_desc);
size_t crypt_prf_fips_key_size_floor(void);

/*
 * Primitives implementing IKE PRFs.
 *
 * Some PRFs are implemented using the HMAC algorithm (described in
 * rfc2104) and an underlying MAC (hash) function.  Others are (at
 * least in theory) implemented directly.
 *
 * This implementation tries to keep all the input and output material
 * secure inside SymKeys.  To that end, it should be good for
 * generating keying material.
 *
 * The slightly clunky, interface is described in-line below.
 */

/*
 * Using KEY, create a PRF.
 */
struct crypt_prf *crypt_prf_init_symkey(const char *prf_name,
					const struct prf_desc *prf_desc,
					const char *key_name, PK11SymKey *key,
					struct logger *logger);

struct crypt_prf *crypt_prf_init_bytes(const char *prf_name,
				       const struct prf_desc *prf_desc,
				       const char *key_name, const void *key, size_t sizeof_key,
				       struct logger *logger);
#define crypt_prf_init_hunk(PRF_NAME, PRF, KEY_NAME, KEY, LOGGER)	\
	crypt_prf_init_bytes(PRF_NAME, PRF, KEY_NAME, (KEY).ptr, (KEY).len, LOGGER)

/*
 * Call these to accumulate the seed/data/text.
 */

void crypt_prf_update_symkey(struct crypt_prf *prf,
			     const char *update_name, PK11SymKey *update);
void crypt_prf_update_byte(struct crypt_prf *prf,
			   const char *update_name, uint8_t update);
void crypt_prf_update_bytes(struct crypt_prf *prf,
			    const char *update_name, const void *update, size_t update_size);
#define crypt_prf_update_hunk(PRF, UPDATE_NAME, HUNK)			\
	{								\
		typeof(HUNK) hunk_ = HUNK; /* evaluate once */		\
		crypt_prf_update_bytes(PRF, UPDATE_NAME,		\
				       hunk_.ptr, hunk_.len);		\
	}
#define crypt_prf_update_thing(PRF, NAME, THING)			\
	crypt_prf_update_bytes(PRF, NAME, &(THING), sizeof(THING))

/*
 * Finally ...
 *
 * This will free PRF and blat the pointer.
 */
PK11SymKey *crypt_prf_final_symkey(struct crypt_prf **prfp);
void crypt_prf_final_bytes(struct crypt_prf **prfp,
			   void *bytes, size_t sizeof_bytes);

struct crypt_mac crypt_prf_final_mac(struct crypt_prf **prfp, const struct integ_desc *integ);

#endif
