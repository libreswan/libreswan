/* 
 * Interface to the Open Cryptographic Framework (OCF) 
 * Daniel Djamaludin <ddjamaludin@cyberguard.com>
 * Copyright (C) 2004-2005 Intel Corporation.  All Rights Reserved.
 *
 * The code was developed with source from the file: hw_cryptodev.c
 * in the openssl package, and the file: ipsec_doi.c from the 
 * openswan package.
 * 
 * hw_cryptodev.c, openssl package:
 * Copyright (c) 2002 Bob Beck <beck@openbsd.org>
 * Copyright (c) 2002 Theo de Raadt
 * Copyright (c) 2002 Markus Friedl
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * ipsec_doi.c, openswan package:
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2003 Michael Richardson <mcr@xelerance.com>
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
 *
 */

#include <sys/types.h>
#include <crypto/cryptodev.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdlib.h>
#include <sys/time.h>
#include <errno.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "constants.h"
#include "defs.h"
#include "id.h"
#include "pgp.h"
#include "x509.h"
#include "certs.h"
#include "keys.h"
#include "log.h"
#include "ocf_cryptodev.h"
#include "pluto_crypt.h"

u_int32_t cryptodev_asymfeat = 0;
struct cryptodev_meth cryptodev;

#undef DEBUG

#if 0
/*
 * Convert a BIGNUM to the representation that /dev/crypto needs.
 *
 * BIGNUMs are stored in arrays of "BN_BITS2" chunks, in little-endian
 *         format, a->top is last used chunk, a->dmax is size of array,
 *         a->neg if negative.
 *         Each *chunk* are in native endian format.
 *
 * CRYPTODEV expects big nums to be stored in an array of bytes, in
 *           little endian byte format.
 *
 */
static int
bn2crparam(const BIGNUM *a, struct crparam *crp)
{
	int i, j, k;
	ssize_t bytes, bits;
	char *b;

	crp->crp_p = NULL;
	crp->crp_nbits = 0;

	bits = BN_num_bits(a);
	bytes = (bits + 7) / 8;

	b = malloc(bytes);
	if (b == NULL)
		return (1);
	memset(b, 0, bytes);

	crp->crp_p = b;
	crp->crp_nbits = bits;

	for (i = 0, j = 0; i < a->top; i++) {
		for (k = 0; k < BN_BITS2 / 8; k++) {
			if ((j + k) >= bytes)
				return (0);
			b[j + k] = a->d[i] >> (k * 8);
		}
		j += BN_BITS2 / 8;
	}
	return (0);
}

/* Convert a /dev/crypto parameter to a BIGNUM */
static int
crparam2bn(struct crparam *crp, BIGNUM *a)
{
	u_int8_t *pd;
	int i, bytes;

	bytes = (crp->crp_nbits + 7) / 8;

	if (bytes == 0)
		return (-1);

	if ((pd = (u_int8_t *) malloc(bytes)) == NULL)
		return (-1);

	for (i = 0; i < bytes; i++)
		pd[i] = crp->crp_p[bytes - i - 1];

	BN_bin2bn(pd, bytes, a);
	free(pd);

	return (0);
}
#endif

#if 0
/* Convert from MP_INT to BIGNUM */
static int
mp2bn(const MP_INT *mp, BIGNUM *a)
{
	a->dmax = mp->_mp_alloc;
	if (mp->_mp_size < 0) {
		a->top = -(mp->_mp_size);
		a->neg = 1;
	} else {
		a->top = mp->_mp_size;
		a->neg = 0;
	}
	a->d = mp->_mp_d;
	return 1;
}

/* Convert from BIGNUM to MP_INT */
int
bn2mp(const BIGNUM *a, MP_INT *mp)
{
	mp->_mp_alloc = a->dmax;
	if (a->neg == 1) {
		mp->_mp_size = -(a->top);
	} else {
		mp->_mp_size = a->top;
	}
	mp->_mp_d = a->d;
	return 1;
}
#endif

/*
 * Return a fd if /dev/crypto seems usable, 0 otherwise.
 */
static int
open_dev_crypto(void)
{
	static int fd = -1;

	if (fd == -1) {
		if ((fd = open("/dev/crypto", O_RDWR, 0)) == -1)
			return (-1);
		/* close on exec */
		if (fcntl(fd, F_SETFD, 1) == -1) {
			close(fd);
			fd = -1;
			return (-1);
		}
	}
	return (fd);
}

/*
 * Get a /dev/crypto file descriptor
 */
static int
get_dev_crypto(void)
{
	int fd, retfd;

	if ((fd = open_dev_crypto()) == -1)
		return (-1);
	if (ioctl(fd, CRIOGET, &retfd) == -1)
		return (-1);

	/* close on exec */
	if (fcntl(retfd, F_SETFD, 1) == -1) {
		close(retfd);
		return (-1);
	}
	return (retfd);
}

/* Caching version for asym operations */
static int get_asym_dev_crypto(void)
{
	static int fd = -1;

	if (fd == -1)
		fd = get_dev_crypto();
	return fd;
}

/*
 * Perform the ioctl 
 */
int cryptodev_asym(struct crypt_kop *kop)
{
	int fd, ret = -1;
	
	if ((fd = get_asym_dev_crypto()) < 0)
		return (ret);
	
	if (ioctl(fd, CIOCKEY, kop) == 0) {
		ret = 0;
	}

	return (ret);
}

#if 0
/*
 * Do the modular exponentiatin without Chinese Remainder Theorem in hardware
 */
static int cryptodev_rsa_mod_exp_nocrt(const struct RSA_private_key *k, mpz_t *t1, BIGNUM *r0)
{
	BIGNUM I, d, n;
	BN_CTX *ctx; 
	int r;

	ctx = BN_CTX_new();
	mp2bn((MP_INT *) t1, &I);
	mp2bn(&k->d, &d);
	mp2bn(&k->pub.n, &n);
	r = cryptodev_mod_exp_setup(r0, &I, &d, &n, ctx);
	BN_CTX_free(ctx);

	return (r);
}

/*
 * Do the modular exponentiation with Chinese Remainder Theorem in sofware
 */
static int cryptodev_rsa_mod_exp_crt_sw(const struct RSA_private_key *k, mpz_t *t1, BIGNUM *r0)
{
	mpz_t t2;

	mpz_init(t2);

	mpz_powm(t2, *t1, &k->dP, &k->p);    /* m1 = c^dP mod p */

	mpz_powm(*t1, *t1, &k->dQ, &k->q);    /* m2 = c^dQ mod Q */

	mpz_sub(t2, t2, *t1);	    /* h = qInv (m1 - m2) mod p */
	mpz_mod(t2, t2, &k->p);
	mpz_mul(t2, t2, &k->qInv);
	mpz_mod(t2, t2, &k->p);

	mpz_mul(t2, t2, &k->q);     /* m = m2 + h q */
	mpz_add(*t1, *t1, t2);
	mp2bn((MP_INT *) t1, r0);
	mpz_clear(t2);
	return 1;
}

/*
 * Compute mod exp in software
 */
static int
cryptodev_mod_exp_sw(BIGNUM *r0, MP_INT *mp_g
		     , const MP_INT *secret
		     , const MP_INT *modulus)
{
	mpz_t shared;
	
	mpz_init(shared);
	mpz_powm(shared, mp_g, secret, modulus);
	mp2bn((MP_INT *) shared, r0);
	return 1;
}

/*
 * Compute mod exp in hardware
 */
static int
cryptodev_mod_exp(BIGNUM *r0, MP_INT *mp_g
		  , const MP_INT *secret
		  , const MP_INT *modulus)
{

	BIGNUM a, p, m;
	int r;
	BN_CTX *ctx;
	
	ctx = BN_CTX_new();
	mp2bn(mp_g, &a);
	mp2bn(secret, &p);
	mp2bn(modulus, &m);
	r = cryptodev_mod_exp_setup(r0, &a, &p, &m, ctx);
	BN_CTX_free(ctx);

	return (r);
}
#endif

/* reverse order of bytes in the number */
void chunk2le(chunk_t c)
{
	int b,e;

	b=0; e=c.len-1;
	while(b < e) {
		unsigned char tmp;
		tmp = c.ptr[b];
		c.ptr[b]=c.ptr[e];
		c.ptr[e]=tmp;
		b++;
		e--;
	}
}

/*
 * Find out what we can support and use it.
 */
void load_cryptodev(void)
{
	int fd;

#if 0
	cryptodev.rsa_mod_exp_crt = cryptodev_rsa_mod_exp_crt_sw;
	cryptodev.mod_exp = cryptodev_mod_exp_sw;
#endif

	if((fd = get_dev_crypto()) < 0) {
		return;
	}

	/* find out what asymmetric crypto algorithms we support */
	if (ioctl(fd, CIOCASYMFEAT, &cryptodev_asymfeat) == -1) {
		close(fd);
		return;
	}
	close(fd);

	if (cryptodev_asymfeat & CRF_MOD_EXP) {
		/* Use modular exponentiation */
#if 0		
		cryptodev.mod_exp = cryptodev_mod_exp;
		cryptodev.rsa_mod_exp_crt = cryptodev_rsa_mod_exp_nocrt;
#endif
		cryptodev.calc_dh_shared = calc_dh_shared_ocf;
		openswan_log("Performing modular exponentiation acceleration in hardware");
	}
}
