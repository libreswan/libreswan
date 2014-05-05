/*
 * mechanisms for preshared keys (public, private, and preshared secrets)
 *
 * this is the library for reading (and later, writing!) the ipsec.secrets
 * files.
 *
 * Copyright (C) 1998-2004  D. Hugh Redelmeier.
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>

#include <gmp.h>
#include <libreswan.h>

#include "sysdep.h"
#include "lswlog.h"
#include "constants.h"
#include "lswalloc.h"
#include "mpzfuncs.h"

/*
 * Convert MP_INT to network form (binary octets, big-endian).
 * We do the malloc; caller must eventually do free.
 */
static chunk_t mpz_to_n(const MP_INT *mp, size_t bytes)
{
	chunk_t r;
	MP_INT temp1, temp2;
	int i;

	r.len = bytes;
	r.ptr = alloc_bytes(r.len, "host representation of large integer");

	mpz_init(&temp1);
	mpz_init(&temp2);

	mpz_set(&temp1, mp);

	for (i = r.len - 1; i >= 0; i--) {
		r.ptr[i] = mpz_mdivmod_ui(&temp2, NULL, &temp1,
					1 << BITS_PER_BYTE);
		mpz_set(&temp1, &temp2);
	}

	passert(mpz_sgn(&temp1) == 0);	/* we must have done all the bits */
	mpz_clear(&temp1);
	mpz_clear(&temp2);

	return r;
}

chunk_t mpz_to_n_autosize(const MP_INT *mp)
{
	int bytes = (mpz_sizeinbase(mp, 2) + 7) / 8;

	return mpz_to_n(mp, bytes);
}

/*
 * Convert network form (binary bytes, big-endian) to MP_INT.
 * The *mp must not be previously mpz_inited.
 */
void n_to_mpz(MP_INT *mp, const u_char *nbytes, size_t nlen)
{
	size_t i;

	mpz_init_set_ui(mp, 0);

	for (i = 0; i != nlen; i++) {
		mpz_mul_ui(mp, mp, 1 << BITS_PER_BYTE);
		mpz_add_ui(mp, mp, nbytes[i]);
	}
}
