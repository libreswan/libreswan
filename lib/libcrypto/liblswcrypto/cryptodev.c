/****************************************************************************/
/*
 * Interface to the Open Cryptographic Framework (OCF)
 *
 * Copyright (C) 2008 David McCullough <david_mccullough@securecomputing.com>
 *
 * Daniel Djamaludin
 * Copyright (C) 2004-2005 Intel Corporation.  All Rights Reserved.
 *
 * The code was developed with source from the file: hw_cryptodev.c
 * in the openssl package, and the file: ipsec_doi.c from the
 * libreswan package.
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
 * ipsec_doi.c, libreswan package:
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
 */
/****************************************************************************/

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
#include <linux/errno.h>

#include <libreswan.h>

#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>

#include "lswlog.h"
#include "lswalloc.h"
#include "lswcrypto.h"
#include "mpzfuncs.h"

/****************************************************************************/

static int cryptodev_fd = -1;

/*
 * save a copy of the SW versions in case we get a HW error, we can revert
 * to running SW instead.
 */
static struct lswcrypto_meth soft_meth;
static int soft_meth_loaded = 0;

/****************************************************************************/
/*
 * Convert a BIGNUM to the representation that /dev/crypto needs.
 */
static int bn2crparam(const BIGNUM *a, struct crparam *crp)
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
		return 1;

	memset(b, 0, bytes);

	crp->crp_p = b;
	crp->crp_nbits = bits;

	for (i = 0, j = 0; i < a->top; i++) {
		for (k = 0; k < BN_BITS2 / 8; k++) {
			if ((j + k) >= bytes)
				return 0;

			b[j + k] = a->d[i] >> (k * 8);
		}
		j += BN_BITS2 / 8;
	}
	return 0;
}

/* Convert a /dev/crypto parameter to a BIGNUM */
static int crparam2bn(struct crparam *crp, BIGNUM *a)
{
	u_int8_t *pd;
	int i, bytes;

	bytes = (crp->crp_nbits + 7) / 8;

	if (bytes == 0)
		return -1;

	if ((pd = (u_int8_t *) malloc(bytes)) == NULL)
		return -1;

	for (i = 0; i < bytes; i++)
		pd[i] = crp->crp_p[bytes - i - 1];

	BN_bin2bn(pd, bytes, a);
	free(pd);

	return 0;
}

static void zapparams(struct crypt_kop *kop)
{
	int i;

	for (i = 0; i < kop->crk_iparams + kop->crk_oparams; i++) {
		if (kop->crk_param[i].crp_p)
			free(kop->crk_param[i].crp_p);
		kop->crk_param[i].crp_p = NULL;
		kop->crk_param[i].crp_nbits = 0;
	}
}

/* Convert from MP_INT to BIGNUM */
static int mp2bn(const MP_INT *mp, BIGNUM *a)
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
int bn2mp(const BIGNUM *a, MP_INT *mp)
{
	mp->_mp_alloc = a->dmax;
	if (a->neg == 1)
		mp->_mp_size = -(a->top);
	else
		mp->_mp_size = a->top;
	mp->_mp_d = a->d;
	return 1;
}

/****************************************************************************/
/*
 * Return a fd if /dev/crypto seems usable, 0 otherwise.
 */
static int open_dev_crypto(void)
{
	static int fd = -1;

	if (fd == -1) {
		if ((fd = open("/dev/crypto", O_RDWR, 0)) == -1)
			return -1;

		/* close on exec */
		if (fcntl(fd, F_SETFD, 1) == -1) {
			close(fd);
			fd = -1;
			return -1;
		}
	}
	return fd;
}

/*
 * Get a /dev/crypto file descriptor
 */
static int get_dev_crypto(void)
{
	int fd, retfd;

	if ((fd = open_dev_crypto()) == -1)
		return -1;

	if (ioctl(fd, CRIOGET, &retfd) == -1)
		return -1;

	/* close on exec */
	if (fcntl(retfd, F_SETFD, 1) == -1) {
		close(retfd);
		return -1;
	}

	return retfd;
}

/****************************************************************************/
/* mod-exp routines */
/****************************************************************************/
/*
 * Perform the ioctl
 */
static int cryptodev_asym(struct crypt_kop *kop, int rlen, BIGNUM *r, int slen,
			  BIGNUM *s)
{
	int ret = -1;

	if (r) {
		kop->crk_param[kop->crk_iparams].crp_p =
			calloc(rlen, sizeof(char));
		kop->crk_param[kop->crk_iparams].crp_nbits = rlen * 8;
		kop->crk_oparams++;
	}
	if (s) {
		kop->crk_param[kop->crk_iparams + 1].crp_p = calloc(slen,
								    sizeof(char));
		kop->crk_param[kop->crk_iparams + 1].crp_nbits = slen * 8;
		kop->crk_oparams++;
	}

	if (ioctl(cryptodev_fd, CIOCKEY, kop) == 0) {
		if (r)
			crparam2bn(&kop->crk_param[kop->crk_iparams], r);
		if (s)
			crparam2bn(&kop->crk_param[kop->crk_iparams + 1], s);
		ret = 0;
	}

	return ret;
}

/*
 * Do the modular exponentiation without Chinese Remainder Theorem in hardware
 */
static void cryptodev_rsa_mod_exp_crt(mpz_t dst, const mpz_t src,
				      const mpz_t p, const mpz_t dP,
				      const mpz_t q, const mpz_t dQ,
				      const mpz_t qInv)
{
	struct crypt_kop kop;
	BIGNUM D, S, P, DP, Q, DQ, QI;
	BN_CTX *ctx;

	memset(&kop, 0, sizeof kop);
	kop.crk_op = CRK_MOD_EXP;

	ctx = BN_CTX_new();

	mp2bn(dst, &D);
	mp2bn(src, &S);
	mp2bn(p, &P);
	mp2bn(dP, &DP);
	mp2bn(q, &Q);
	mp2bn(dQ, &DQ);
	mp2bn(qInv, &QI);

	/* inputs: a^p % m */
	if (bn2crparam(&P, &kop.crk_param[0]))
		goto err;
	if (bn2crparam(&Q, &kop.crk_param[1]))
		goto err;
	if (bn2crparam(&S, &kop.crk_param[2]))
		goto err;
	if (bn2crparam(&DP, &kop.crk_param[3]))
		goto err;
	if (bn2crparam(&DQ, &kop.crk_param[4]))
		goto err;
	if (bn2crparam(&QI, &kop.crk_param[5]))
		goto err;
	kop.crk_iparams = 6;

	if (cryptodev_asym(&kop, BN_num_bytes(&D), &D, 0, NULL) == -1) {
		libreswan_log("OCF CRK_MOD_EXP_CRT failed %d, using SW\n",
			      errno);
		goto err;
	}

	bn2mp(&D, dst);
	zapparams(&kop);
	BN_CTX_free(ctx);
	return;

err:
	zapparams(&kop);
	BN_CTX_free(ctx);
	soft_meth.rsa_mod_exp_crt(dst, src, p, dP, q, dQ, qInv);
}

/*
 * Compute mod exp in hardware
 */
static void cryptodev_mod_exp(mpz_t dst, const mpz_t mp_g, const mpz_t secret,
			      const mpz_t modulus)
{
	struct crypt_kop kop;
	BIGNUM r0, a, p, m;
	BN_CTX *ctx;

	memset(&kop, 0, sizeof kop);
	kop.crk_op = CRK_MOD_EXP;

	ctx = BN_CTX_new();
	mp2bn(mp_g, &a);
	mp2bn(secret, &p);
	mp2bn(modulus, &m);
	mp2bn(dst, &r0);

	/* inputs: a^p % m */
	if (bn2crparam(&a, &kop.crk_param[0]))
		goto err;
	if (bn2crparam(&p, &kop.crk_param[1]))
		goto err;
	if (bn2crparam(&m, &kop.crk_param[2]))
		goto err;
	kop.crk_iparams = 3;

	if (cryptodev_asym(&kop, BN_num_bytes(&m), &r0, 0, NULL) == -1) {
		libreswan_log("OCF CRK_MOD_EXP failed %d, using SW\n", errno);
		goto err;
	}

	bn2mp(&r0, dst);

	zapparams(&kop);
	BN_CTX_free(ctx);
	return;

err:
	zapparams(&kop);
	BN_CTX_free(ctx);
	soft_meth.mod_exp(dst, mp_g, secret, modulus);
}

/****************************************************************************/
/* DES routines */
/****************************************************************************/

static int cryptodev_des_set_key(des_cblock (*key), des_key_schedule schedule)
{
	if (cryptodev_fd != -1) {
		memcpy(schedule, key, sizeof(*key));
		return 0;
	}
	return -1;
}

/****************************************************************************/

static void cryptodev_des_cryptodev_internal(u_int32_t cipher,
					     char (*key),
					     u_int32_t operation,
					     des_cblock (*src),
					     des_cblock (*dst),
					     u_int32_t len,
					     des_cblock (*iv),
					     u_int32_t iv_len)
{
	struct session_op sop;
	struct crypt_op cop;
	u_int32_t fixed_len = len;
	des_cblock new_iv;
	des_cblock *fixed_src = NULL;

	/* always make fixed_len a multiple of 8 - otherwise the CIOCCRYPT fails */
	fixed_len = (len + 7) & ~7;

	/* if the input stream's length is not a multiple of 8, copy and zero pad */
	if ((len & 7) && operation == COP_ENCRYPT) {
		/* slow but safe */
		fixed_src = (des_cblock *)malloc(fixed_len);
		if (!fixed_src)
			return;

		memset((char *)fixed_src + fixed_len - 8, 0, 8);
		memcpy((char *)fixed_src, (char *)src, len);
	} else {
		fixed_src = src;
	}

	/* need to calculate the new iv before decrypting, as if we are decrypting
	 * in place then the operation will destroy the last block of cipher text */
	if (operation != COP_ENCRYPT) {
		/* ciphertext will be in src */
		memcpy((char *)new_iv, (char *)fixed_src + fixed_len - iv_len,
		       iv_len);
	}

	/*
	 * XXX
	 * cryptodev enforces the concept of a crypto session
	 * in which you perform operations. This cryptodev_assist stuff
	 * doesn't currently support that. So for now I'm creating sessions
	 * for each operation.
	 */

	/* create a session */
	bzero(&sop, sizeof(sop));
	sop.cipher = cipher;

	if (cipher == CRYPTO_DES_CBC)
		sop.keylen = 8;
	else if (cipher == CRYPTO_3DES_CBC)
		sop.keylen = 24;
	sop.key = key;

	if (ioctl(cryptodev_fd, CIOCGSESSION, &sop) < 0) {
		/* fatal error condition - bail out */
		goto failed;
	}

	/* perform the operation */
	bzero(&cop, sizeof(cop));
	cop.ses = sop.ses;
	cop.op = operation;
	cop.src = (char *)fixed_src;
	cop.dst = (char *)dst;
	cop.len = fixed_len;
	cop.iv = (char *)iv;
	if (ioctl(cryptodev_fd, CIOCCRYPT, &cop) < 0) {
		/* fprintf(stderr, "%s CIOCCRYPT failed\n", __FUNCTION__); */
		goto failed;
	}

	/* it doesn't look like cryptodev updates the iv in the cop
	 * to allow manual chaining of several blocks, cbc style :(
	 * so we need to manually set this iv to the last block of ciphertext
	 */
	if (operation == COP_ENCRYPT) {
		/* ciphertext will be in dst */
		memcpy((char *)iv, cop.dst + fixed_len - iv_len, iv_len);
	} else {
		/* have to copy out the saved iv from new_iv */
		memcpy((char *)iv, new_iv, iv_len);
	}

	if (ioctl(cryptodev_fd, CIOCFSESSION, &sop.ses) == -1)
		goto failed;

	if (fixed_src != src)
		free(fixed_src);
	return;

failed:
	if (fixed_src != src)
		free(fixed_src);
	memset(dst, 0, len);
}

/****************************************************************************/

static void cryptodev_des_cbc_encrypt(des_cblock (*input),
				      des_cblock (*output),
				      long length,
				      des_key_schedule schedule,
				      des_cblock (*ivec),
				      int enc)
{
	if (cryptodev_fd != -1) {
		char key[8];
		des_cblock iv;

		memcpy(key, schedule, 8);
		memcpy(&iv, ivec, sizeof(des_cblock));
		cryptodev_des_cryptodev_internal(
			CRYPTO_DES_CBC,
			key,
			enc ? COP_ENCRYPT : COP_DECRYPT,
			input,
			output,
			length,
			&iv,
			sizeof(des_cblock));
		/* intentionally do NOT copy out the iv into ivec, this is the
		 * ONLY difference between the cbc and ncbc versions
		 */
	}
}

/****************************************************************************/

#define c2l(c, l)        (l = ((DES_LONG)(*((c)++))), \
			  l |= ((DES_LONG)(*((c)++))) << 8L, \
			  l |= ((DES_LONG)(*((c)++))) << 16L, \
			  l |= ((DES_LONG)(*((c)++))) << 24L)

#define l2c(l, c)        (*((c)++) = (unsigned char)(((l)     ) & 0xff), \
			  *((c)++) = (unsigned char)(((l) >> 8L) & 0xff), \
			  *((c)++) = (unsigned char)(((l) >> 16L) & 0xff), \
			  *((c)++) = (unsigned char)(((l) >> 24L) & 0xff))

static void cryptodev_des_encrypt(DES_LONG *data,
				  des_key_schedule ks,
				  int enc)
{
	if (cryptodev_fd != -1) {
		char key[8];
		des_cblock iv;
		des_cblock datac;
		register DES_LONG l;
		unsigned char *p;

		p = &datac[0];
		l = data[0];
		l2c(l, p);
		l = data[1];
		l2c(l, p);

		memcpy(key, ks, 8);
		memset(&iv, 0, sizeof(des_cblock));
		/* single block ecb == single block cbc with iv=0 */
		cryptodev_des_cryptodev_internal(
			CRYPTO_DES_CBC,
			key,
			enc ? COP_ENCRYPT : COP_DECRYPT,
			&datac,
			&datac,
			sizeof(des_cblock),
			&iv,
			sizeof(des_cblock));

		p = datac;
		c2l(p, l);
		data[0] = l;
		c2l(p, l);
		data[1] = l;
	}
}

/****************************************************************************/

static void cryptodev_des_ede3_cbc_encrypt(des_cblock (*input),
					   des_cblock (*output),
					   long length,
					   des_key_schedule ks1,
					   des_key_schedule ks2,
					   des_key_schedule ks3,
					   des_cblock (*ivec),
					   int enc)
{
	if (cryptodev_fd != -1) {
		char key[8 * 3];
		des_cblock iv;

		memcpy(key, ks1, 8);
		memcpy(key + 8, ks2, 8);
		memcpy(key + 16, ks3, 8);
		memcpy(&iv, ivec, sizeof(des_cblock));
		cryptodev_des_cryptodev_internal(
			CRYPTO_3DES_CBC,
			key,
			enc ? COP_ENCRYPT : COP_DECRYPT,
			input,
			output,
			length,
			&iv,
			sizeof(des_cblock));
		memcpy(ivec, &iv, sizeof(des_cblock));
	}
}

/****************************************************************************/

static void cryptodev_des_ncbc_encrypt(des_cblock (*input),
				       des_cblock (*output),
				       long length,
				       des_key_schedule schedule,
				       des_cblock (*ivec),
				       int enc)
{
	if (cryptodev_fd != -1) {
		char key[8];
		des_cblock iv;

		memcpy(key, schedule, 8);
		memcpy(&iv, ivec, sizeof(des_cblock));
		cryptodev_des_cryptodev_internal(
			CRYPTO_DES_CBC,
			key,
			enc ? COP_ENCRYPT : COP_DECRYPT,
			input,
			output,
			length,
			&iv,
			sizeof(des_cblock));
		memcpy(ivec, &iv, sizeof(des_cblock));
	}
}

/****************************************************************************/

static void cryptodev_des_ecb_encrypt(des_cblock (*input),
				      des_cblock (*output),
				      des_key_schedule ks,
				      int enc)
{
	if (cryptodev_fd != -1) {
		char key[8];
		des_cblock iv;

		memcpy(key, ks, 8);
		memset(&iv, 0, sizeof(des_cblock));
		/* single block ecb == single block cbc with iv=0 */
		cryptodev_des_cryptodev_internal(
			CRYPTO_DES_CBC,
			key,
			enc ? COP_ENCRYPT : COP_DECRYPT,
			input,
			output,
			sizeof(des_cblock),
			&iv,
			sizeof(des_cblock));
	}
}

/****************************************************************************/
/* AES routines */
/****************************************************************************/

static int cryptodev_aes_set_key(aes_context (*cx),
				 const unsigned char in_key[],
				 int length)
{
#if defined(AES_BLOCK_SIZE)
#define nc   (AES_BLOCK_SIZE / 4)
#else
#define nc   (cx->aes_Ncol)
#endif

	switch (length) {
	case 32:                        /* bytes */
	case 256:                       /* bits */
		cx->aes_Nkey = 8;
		break;
	case 24:                        /* bytes */
	case 192:                       /* bits */
		cx->aes_Nkey = 6;
		break;
	case 16:                        /* bytes */
	case 128:                       /* bits */
	default:
		cx->aes_Nkey = 4;
		break;
	}
	cx->aes_Nrnd = (cx->aes_Nkey > nc ? cx->aes_Nkey : nc) + 6;
	memcpy(cx->aes_e_key, in_key, cx->aes_Nkey * 4);
	return 0;
}

/****************************************************************************/

static void cryptodev_aes_cryptodev_internal(u_int32_t cipher,
					     char (*key),
					     u_int32_t keylen,
					     u_int32_t operation,
					     const u_int8_t *src,
					     u_int8_t *dst,
					     long len,
					     const u_int8_t *iv,
					     u_int32_t iv_len)
{
	struct session_op sop;
	struct crypt_op cop;
	u_int32_t fixed_len = len;
	u_int8_t *fixed_src = NULL;

	/* always make fixed_len a multiple of 16 - otherwise the CIOCCRYPT fails */
	fixed_len = (len + 15) & ~15;

	/*
	 * if the input stream's length is not a multiple of 16, copy and zero pad
	 */
	if ((len & 15) && operation == COP_ENCRYPT) {
		/* slow but safe */
		fixed_src = (u_int8_t *)malloc(fixed_len);
		if (!fixed_src)
			return;

		memset(fixed_src + fixed_len - 15, 0, 15);
		memcpy(fixed_src, src, len);
	} else {
		*((const u_int8_t **)&fixed_src) = src; /* bypass const checking */
	}

	/*
	 * XXX
	 * cryptodev enforces the concept of a crypto session
	 * in which you perform operations. This cryptodev_assist stuff
	 * doesn't currently support that. So for now I'm creating sessions
	 * for each operation.
	 */

	/* create a session */
	bzero(&sop, sizeof(sop));
	sop.cipher = cipher;
	sop.keylen = keylen;
	sop.key = key;

	if (ioctl(cryptodev_fd, CIOCGSESSION, &sop) < 0) {
		/* fatal error condition - bail out */
		goto failed;
	}

	/* perform the operation */
	bzero(&cop, sizeof(cop));
	cop.ses = sop.ses;
	cop.op = operation;
	cop.src = (char *)fixed_src;
	cop.dst = (char *)dst;
	cop.len = fixed_len;
	*((const char **)cop.iv) = (const char *)iv; /* bypass const checking */
	if (ioctl(cryptodev_fd, CIOCCRYPT, &cop) < 0) {
		/* fprintf(stderr, "%s CIOCCRYPT failed\n", __FUNCTION__);  */
		goto failed;
	}

	if (ioctl(cryptodev_fd, CIOCFSESSION, &sop.ses) == -1)
		goto failed;

	if (fixed_src != src)
		free(fixed_src);
	return;

failed:
	memset(dst, 0, len);
	if (fixed_src != src)
		free(fixed_src);
	return;
}

/****************************************************************************/

static int cryptodev_aes_cbc_encrypt(aes_context *ctx,
				     const u_int8_t *input,
				     u_int8_t *output,
				     int length,
				     const u_int8_t *ivec,
				     int enc)
{
	if (cryptodev_fd != -1) {
		cryptodev_aes_cryptodev_internal(
			CRYPTO_AES_CBC,
		        /* ctx->aes_d_key isn't used here, just aes_e_key ??? */
		        /* enc ? ctx->aes_e_key : ctx->aes_d_key, */
			(char *) ctx->aes_e_key,
			ctx->aes_Nkey * 4,
			enc ? COP_ENCRYPT : COP_DECRYPT,
			input,
			output,
			length,
			ivec,
			(u_int32_t)16);
		return length;
	}
	return length;
}

/****************************************************************************/
/* our init function */
/****************************************************************************/
/*
 * Find out what we can support and use it.
 */
void load_cryptodev(void)
{
	struct session_op ses;
	int assisted = 0;
	u_int32_t feat;
	struct lswcrypto_meth old_meth = lswcrypto;

	if ((cryptodev_fd = get_dev_crypto()) == -1) {
		libreswan_log(
			"OCF assist for IKE disabled: is the cryptodev module loaded ?");
		return;
	}

	/* find out what asymmetric crypto algorithms we support */
	if (ioctl(cryptodev_fd, CIOCASYMFEAT, &feat) != -1) {
		if (feat & CRF_MOD_EXP) {
			/* Use modular exponentiation */
			lswcrypto.mod_exp = cryptodev_mod_exp;
			libreswan_log(
				"OCF assist for IKE for modular exponentiation enabled");
			assisted++;
		}
		if (feat & CRF_MOD_EXP_CRT) {
			lswcrypto.rsa_mod_exp_crt = cryptodev_rsa_mod_exp_crt;
			libreswan_log(
				"OCF assist for IKE for modular exponentiation (CRT) enabled");
			assisted++;
		}
	}

	/* test we can do AES */
	memset(&ses, 0, sizeof(ses));
	ses.key = (caddr_t)"12345678901234567890123456789012";
	ses.cipher = CRYPTO_AES_CBC;
	ses.keylen = 16;
	if (ioctl(cryptodev_fd, CIOCGSESSION, &ses) != -1 &&
	    ioctl(cryptodev_fd, CIOCFSESSION, &ses.ses) != -1) {
		libreswan_log("OCF assist for IKE for AES crypto enabled");
		lswcrypto.aes_set_key     = cryptodev_aes_set_key;
		lswcrypto.aes_cbc_encrypt = cryptodev_aes_cbc_encrypt;
		assisted++;
	}

	/* test we can do DES */
	memset(&ses, 0, sizeof(ses));
	ses.key = (caddr_t)"123456789012345678901234";
	ses.cipher = CRYPTO_DES_CBC;
	ses.keylen = 8;
	if (ioctl(cryptodev_fd, CIOCGSESSION, &ses) != -1 &&
	    ioctl(cryptodev_fd, CIOCFSESSION, &ses.ses) != -1) {
		libreswan_log("OCF assist for IKE for DES crypto enabled");
		lswcrypto.des_set_key      = cryptodev_des_set_key;
		lswcrypto.des_cbc_encrypt  = cryptodev_des_cbc_encrypt;
		lswcrypto.des_encrypt      = cryptodev_des_encrypt;
		lswcrypto.des_ncbc_encrypt = cryptodev_des_ncbc_encrypt;
		lswcrypto.des_ecb_encrypt  = cryptodev_des_ecb_encrypt;
		assisted++;
		/* test we can do 3DES */
		ses.cipher = CRYPTO_3DES_CBC;
		ses.keylen = 24;
		if (ioctl(cryptodev_fd, CIOCGSESSION, &ses) != -1 &&
		    ioctl(cryptodev_fd, CIOCFSESSION, &ses.ses) != -1) {
			libreswan_log(
				"OCF assist for IKE for 3DES crypto enabled");
			lswcrypto.des_ede3_cbc_encrypt =
				cryptodev_des_ede3_cbc_encrypt;
			//DAVIDM 3des setkey is technically needed if HW can only do DES
			assisted++;
		}
	}

	if (assisted == 0) {
		close(cryptodev_fd);
		cryptodev_fd = -1;
	} else if (!soft_meth_loaded) {
		soft_meth_loaded = 1;
		soft_meth = old_meth;
	}
}

/****************************************************************************/
