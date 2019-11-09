/*
 * crypto-class pseudorandom number generator
 * currently uses same algorithm as RC4(TM), from Schneier 2nd ed p397
 * Copyright (C) 2002  Henry Spencer.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/lgpl-2.1.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 */
#include "libreswan.h"
#ifndef __KERNEL__
#ifndef SWAN_TESTING
#error This file should only be used for building KLIPS
#endif
#endif

#include "libreswan/ipsec_proto.h"

/* for local_bh_disable() on older kernels without linux/asm/softirq.h */
#include <linux/interrupt.h>

/*
 * A horrible locking hack,  we ride on tdb_lock for now since it
 * is basically what we want.  Since all calls into prng_bytes pass in
 * a pointer to ipsec_prng, there is contention on the data in ipsec_prng
 * as it is not always locked.  To make sure we never mess up the PRNG, just
 * locked it if we don't already have the tdb_lock
 */

/* ??? what's with the dangling else? */
#define LOCK_PRNG() \
	int ul = 0; \
	if (spin_trylock_bh(&tdb_lock)) { \
		ul = 1; \
	} else

/* ??? what's with the dangling else? */
#define UNLOCK_PRNG() \
	if (ul) { \
		ul = 0; \
		spin_unlock_bh(&tdb_lock); \
	} else

/*
   - prng_init - initialize PRNG from a key
 */
void prng_init(prng, key, keylen)
struct prng *prng;
const unsigned char *key;
size_t keylen;
{
	unsigned char k[256];
	int i, j;
	const unsigned char *p;
	const unsigned char *keyend = key + keylen;
	unsigned char t;

	for (i = 0; i <= 255; i++)
		prng->sbox[i] = i;
	p = key;
	for (i = 0; i <= 255; i++) {
		k[i] = *p++;
		if (p >= keyend)
			p = key;
	}
	j = 0;
	for (i = 0; i <= 255; i++) {
		j = (j + prng->sbox[i] + k[i]) & 0xff;
		t = prng->sbox[i];
		prng->sbox[i] = prng->sbox[j];
		prng->sbox[j] = t;
		k[i] = 0;       /* clear out key memory */
	}
	prng->i = 0;
	prng->j = 0;
	prng->count = 0;
}

/*
   - prng_bytes - get some pseudorandom bytes from PRNG
 */
void prng_bytes(prng, dst, dstlen)
struct prng *prng;
unsigned char *dst;
size_t dstlen;
{
	int i, j, t;
	unsigned char *p = dst;
	size_t remain = dstlen;
#       define  MAXCOUNT        4000000000ul

	LOCK_PRNG();

	while (remain > 0) {
		i = (prng->i + 1) & 0xff;
		prng->i = i;
		j = (prng->j + prng->sbox[i]) & 0xff;
		prng->j = j;
		t = prng->sbox[i];
		prng->sbox[i] = prng->sbox[j];
		prng->sbox[j] = t;
		t = (t + prng->sbox[i]) & 0xff;
		*p++ = prng->sbox[t];
		remain--;
	}
	if (prng->count < MAXCOUNT - dstlen)
		prng->count += dstlen;
	else
		prng->count = MAXCOUNT;

	UNLOCK_PRNG();
}

/*
   - prnt_count - how many bytes have been extracted from PRNG so far?
 */
unsigned long prng_count(prng)
struct prng *prng;
{
	unsigned long c;
	LOCK_PRNG();
	c = prng->count;
	UNLOCK_PRNG();
	return c;
}

/*
   - prng_final - clear out PRNG to ensure nothing left in memory
 */
void prng_final(prng)
struct prng *prng;
{
	int i;

	for (i = 0; i <= 255; i++)
		prng->sbox[i] = 0;
	prng->i = 0;
	prng->j = 0;
	prng->count = 0;        /* just for good measure */
}

