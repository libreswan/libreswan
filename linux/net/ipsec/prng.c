/*
 * crypto-class pseudorandom number generator
 * currently uses same algorithm as RC4(TM), from Schneier 2nd ed p397
 * Copyright (C) 2002  Henry Spencer.
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/lgpl.txt>.
 * 
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 *
 * RCSID $Id: prng.c,v 1.8 2005/08/25 01:20:21 paul Exp $
 */
#include "openswan.h"

#ifdef __KERNEL__
#include "openswan/ipsec_proto.h"

/* for local_bh_disable() on older kernels without linux/asm/softirq.h */
#include <linux/interrupt.h>

/*
 * A horrible locking hack,  we ride on tdb_lock for now since it
 * is basically what we want.  Since all calls into prng_bytes pass in
 * a pointer to ipsec_prng,  there is contention on the data in ipsec_prng
 * as it is not always locked.  TO make sure we never messup the PRNG, just
 * locked it if we don't already have the tdb_lock
 */

#define LOCK_PRNG() \
	int ul = 0; \
	if (!spin_is_locked(&tdb_lock)) { \
		spin_lock_bh(&tdb_lock); \
		ul = 1; \
	} else

#define UNLOCK_PRNG() \
	if (ul) { \
		spin_unlock_bh(&tdb_lock); \
		ul = 0; \
	} else

#else

#define LOCK_PRNG()
#define UNLOCK_PRNG()

#endif


/*
 - prng_init - initialize PRNG from a key
 */
void
prng_init(prng, key, keylen)
struct prng *prng;
const unsigned char *key;
size_t keylen;
{
	unsigned char k[256];
	int i, j;
	unsigned const char *p;
	unsigned const char *keyend = key + keylen;
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
		k[i] = 0;	/* clear out key memory */
	}
	prng->i = 0;
	prng->j = 0;
	prng->count = 0;
}

/*
 - prng_bytes - get some pseudorandom bytes from PRNG
 */
void
prng_bytes(prng, dst, dstlen)
struct prng *prng;
unsigned char *dst;
size_t dstlen;
{
	int i, j, t;
	unsigned char *p = dst;
	size_t remain = dstlen;
#	define	MAXCOUNT	4000000000ul

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
unsigned long
prng_count(prng)
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
void
prng_final(prng)
struct prng *prng;
{
	int i;

	for (i = 0; i <= 255; i++)
		prng->sbox[i] = 0;
	prng->i = 0;
	prng->j = 0;
	prng->count = 0;	/* just for good measure */
}



#ifdef PRNG_MAIN

#include <stdio.h>
#include <stdlib.h>

void regress();

int
main(argc, argv)
int argc;
char *argv[];
{
	struct prng pr;
	unsigned char buf[100];
	unsigned char *p;
	size_t n;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s {key|-r}\n", argv[0]);
		exit(2);
	}

	if (strcmp(argv[1], "-r") == 0) {
		regress();
		fprintf(stderr, "regress() returned?!?\n");
		exit(1);
	}

	prng_init(&pr, argv[1], strlen(argv[1]));
	prng_bytes(&pr, buf, 32);
	printf("0x");
	for (p = buf, n = 32; n > 0; p++, n--)
		printf("%02x", *p);
	printf("\n%lu bytes\n", prng_count(&pr));
	prng_final(&pr);
	exit(0);
}

void
regress()
{
	struct prng pr;
	unsigned char buf[100];
	unsigned char *p;
	size_t n;
	/* somewhat non-random sample key */
	unsigned char key[] = "here we go gathering nuts in May";
	/* first thirty bytes of output from that key */
	unsigned char good[] = "\x3f\x02\x8e\x4a\x2a\xea\x23\x18\x92\x7c"
				"\x09\x52\x83\x61\xaa\x26\xce\xbb\x9d\x71"
				"\x71\xe5\x10\x22\xaf\x60\x54\x8d\x5b\x28";
	int nzero, none;
	int show = 0;

	prng_init(&pr, key, strlen(key));
	prng_bytes(&pr, buf, sizeof(buf));
	for (p = buf, n = sizeof(buf); n > 0; p++, n--) {
		if (*p == 0)
			nzero++;
		if (*p == 255)
			none++;
	}
	if (nzero > 3 || none > 3) {
		fprintf(stderr, "suspiciously non-random output!\n");
		show = 1;
	}
	if (memcmp(buf, good, strlen(good)) != 0) {
		fprintf(stderr, "incorrect output!\n");
		show = 1;
	}
	if (show) {
		fprintf(stderr, "0x");
		for (p = buf, n = sizeof(buf); n > 0; p++, n--)
			fprintf(stderr, "%02x", *p);
		fprintf(stderr, "\n");
		exit(1);
	}
	if (prng_count(&pr) != sizeof(buf)) {
		fprintf(stderr, "got %u bytes, but count is %lu\n",
					sizeof(buf), prng_count(&pr));
		exit(1);
	}
	prng_final(&pr);
	exit(0);
}

#endif /* PRNG_MAIN */
