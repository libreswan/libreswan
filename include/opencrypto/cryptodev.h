/*	$FreeBSD: src/sys/opencrypto/cryptodev.h,v 1.23 2006/06/04 22:15:13 pjd Exp $	*/
/*	$OpenBSD: cryptodev.h,v 1.31 2002/06/11 11:14:29 beck Exp $	*/

/*
 * This file is the userland (ioctl) interface of the
 * Open Cryptographic Framework.  All kernel specific things have been
 * moved to opencrypto/crypto.h. This file should be includeable by
 * kernel and userspace. Split by mcr@xelerance.com, 2006-11-20.
 */

/*-
 * Many additions by Michael Richardson <mcr@xelerance.com> and
 *                   Bart Trojanowski <bart@jukie.net> in 2006 under
 *                   contract with Hifn inc.
 *
 * Linux port done by David McCullough <dmccullough@cyberguard.com>
 * Copyright (C) 2004-2005 Intel Corporation.  All Rights Reserved.
 * The license and original author are listed below.
 *
 * The author of this code is Angelos D. Keromytis (angelos@cis.upenn.edu)
 *
 * This code was written by Angelos D. Keromytis in Athens, Greece, in
 * February 2000. Network Security Technologies Inc. (NSTI) kindly
 * supported the development of this code.
 *
 * Copyright (c) 2000 Angelos D. Keromytis
 *
 * Permission to use, copy, and modify this software with or without fee
 * is hereby granted, provided that this entire notice is included in
 * all source code copies of any software which is or includes a copy or
 * modification of this software.
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTY. IN PARTICULAR, NONE OF THE AUTHORS MAKES ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE
 * MERCHANTABILITY OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR
 * PURPOSE.
 *
 * Copyright (c) 2001 Theo de Raadt
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Effort sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F30602-01-2-0537.
 *
 */

#ifndef _CRYPTO_CRYPTODEV_H_
#define _CRYPTO_CRYPTODEV_H_

#include <sys/ioccom.h>

/* Hash values */
#define	NULL_HASH_LEN		16
#define	MD5_HASH_LEN		16
#define	SHA1_HASH_LEN		20
#define	RIPEMD160_HASH_LEN	20
#define	SHA2_256_HASH_LEN	32
#define	SHA2_384_HASH_LEN	48
#define	SHA2_512_HASH_LEN	64
#define	MD5_KPDK_HASH_LEN	16
#define	SHA1_KPDK_HASH_LEN	20
/* Maximum hash algorithm result length */
#define	HASH_MAX_LEN		SHA2_512_HASH_LEN /* Keep this updated */

/* HMAC values */
#define	NULL_HMAC_BLOCK_LEN		64
#define	MD5_HMAC_BLOCK_LEN		64
#define	SHA1_HMAC_BLOCK_LEN		64
#define	RIPEMD160_HMAC_BLOCK_LEN	64
#define	SHA2_256_HMAC_BLOCK_LEN		64
#define	SHA2_384_HMAC_BLOCK_LEN		128
#define	SHA2_512_HMAC_BLOCK_LEN		128
/* Maximum HMAC block length */
#define	HMAC_MAX_BLOCK_LEN		SHA2_512_HMAC_BLOCK_LEN /* Keep this updated */
#define	HMAC_IPAD_VAL			0x36
#define	HMAC_OPAD_VAL			0x5C

/* Encryption algorithm block sizes */
#define NULL_BLOCK_LEN		4
#define DES_BLOCK_LEN		8
#define DES3_BLOCK_LEN		8
#define BLOWFISH_BLOCK_LEN	8
#define SKIPJACK_BLOCK_LEN	8
#define CAST128_BLOCK_LEN	8
#define RIJNDAEL128_BLOCK_LEN	16
#define AES_BLOCK_LEN		RIJNDAEL128_BLOCK_LEN

#define EALG_MAX_BLOCK_LEN	16 /* Keep this updated */

/* Maximum hash algorithm result length */
#define AALG_MAX_RESULT_LEN	64 /* Keep this updated */

#define	CRYPTO_ALGORITHM_MIN	1
#define CRYPTO_DES_CBC		1
#define CRYPTO_3DES_CBC		2
#define CRYPTO_BLF_CBC		3
#define CRYPTO_CAST_CBC		4
#define CRYPTO_SKIPJACK_CBC	5
#define CRYPTO_MD5_HMAC		6
#define CRYPTO_SHA1_HMAC	7
#define CRYPTO_RIPEMD160_HMAC	8
#define CRYPTO_MD5_KPDK		9
#define CRYPTO_SHA1_KPDK	10
#define CRYPTO_RIJNDAEL128_CBC	11 /* 128 bit blocksize */
#define CRYPTO_AES_CBC		11 /* 128 bit blocksize -- the same as above */
#define CRYPTO_ARC4		12
#define	CRYPTO_MD5		13
#define	CRYPTO_SHA1		14
#define	CRYPTO_NULL_HMAC	15
#define	CRYPTO_NULL_CBC		16
#define	CRYPTO_DEFLATE_COMP	17 /* Deflate compression algorithm */
#define	CRYPTO_SHA2_256_HMAC	18
#define	CRYPTO_SHA2_384_HMAC	19
#define	CRYPTO_SHA2_512_HMAC	20
#define	CRYPTO_LZS_COMP	        21 /* LZS compression algorithm */
#define	CRYPTO_ALGORITHM_MAX	21 /* Keep updated - see below */

/* Algorithm flags */
#define	CRYPTO_ALG_FLAG_SUPPORTED	0x01 /* Algorithm is supported */
#define	CRYPTO_ALG_FLAG_RNG_ENABLE	0x02 /* Has HW RNG for DH/DSA */
#define	CRYPTO_ALG_FLAG_DSA_SHA		0x04 /* Can do SHA on msg */

#define CRYPTO_NAME_LEN 16		/* driver + '#" + index + NUL */
#define CRYPTO_NAME_BASE_LEN 12		/* strlen(drivername) */

// these strings are passed in session_op::crypto_device_name to select the 
// hardware device to use; see crypto_find_driverid()
#define CRYPTO_ANYDEVICE_STRING   "anydevice"  
#define CRYPTO_ANYHARDWARE_STRING "anyhardware"
#define CRYPTO_ANYSOFTWARE_STRING "anysoftware"
#define CRYPTO_SOFTWARE_STRING    "software"   

struct session_op {
	u_int32_t	cipher;		/* ie. CRYPTO_DES_CBC */
	u_int32_t	mac;		/* ie. CRYPTO_MD5_HMAC */

	u_int32_t	keylen;		/* cipher key */
	caddr_t		key;
	int		mackeylen;	/* mac key */
	caddr_t		mackey;

  	u_int32_t	ses;		/* returns: session # */ 
	char            crypto_device_name[CRYPTO_NAME_LEN];  /* name of engine used */
};

struct crypt_op {
	u_int32_t	ses;
	u_int16_t	op;		/* i.e. COP_ENCRYPT */
#define COP_ENCRYPT	1
#define COP_DECRYPT	2
	u_int16_t	flags;
#define	COP_F_BATCH	0x0008		/* Batch op if possible */
#define COP_LOG_DEBUG   0x8000          /* detail any EINVAL */
	u_int		slen,dlen;
	caddr_t		src, dst;	/* become iov[] inside kernel */
	caddr_t		mac;		/* must be big enough for chosen MAC */
	caddr_t		iv;
};

#define CRYPTO_MAX_MAC_LEN	20

/* bignum parameter, in packed bytes, ... */
struct crparam {
	caddr_t		crp_p;
	u_int		crp_nbits;
};

#define CRK_MAXPARAM	8

struct crypt_kop {
	u_int		crk_op;		/* ie. CRK_MOD_EXP or other */
	u_int		crk_status;	/* return status */
	u_short		crk_iparams;	/* # of input parameters */
	u_short		crk_oparams;	/* # of output parameters */
	struct crparam	crk_param[CRK_MAXPARAM];
	char            crypto_device_name[CRYPTO_NAME_LEN];  /* name of engine used */
};
#define	CRK_ALGORITM_MIN	0
#define CRK_MOD_EXP		0
#define CRK_MOD_EXP_CRT		1
#define CRK_DSA_SIGN		2
#define CRK_DSA_VERIFY		3
#define CRK_DH_COMPUTE_KEY	4
#define CRK_MOD_ADD             5
#define CRK_ADD                 6
#define CRK_ALGORITHM_MAX	6 /* Keep updated - see below */

#define CRF_MOD_EXP		(1 << CRK_MOD_EXP)
#define CRF_MOD_EXP_CRT		(1 << CRK_MOD_EXP_CRT)
#define CRF_DSA_SIGN		(1 << CRK_DSA_SIGN)
#define CRF_DSA_VERIFY		(1 << CRK_DSA_VERIFY)
#define CRF_DH_COMPUTE_KEY	(1 << CRK_DH_COMPUTE_KEY)
#define CRF_MOD_ADD             (1 << CRK_MOD_ADD)
#define CRF_ADD                 (1 << CRK_ADD)

/* parameters for MOD_EXP operation */
#define	CRK_MOD_PARAM_BASE	0
#define	CRK_MOD_PARAM_EXP	1
#define	CRK_MOD_PARAM_MOD	2
#define	CRK_MOD_PARAM_RECIP	3

#define CRK_MOD_PARAM_RES       0  /* relative to oparams */


/*
 * done against open of /dev/crypto, to get a cloned descriptor.
 * Please use F_SETFD against the cloned descriptor.
 */
#define	CRIOGET		_IOWR('c', 100, u_int32_t)

/* the following are done against the cloned descriptor */
#define	CIOCGSESSION	_IOWR('c', 101, struct session_op)
#define	CIOCFSESSION	_IOW('c', 102, u_int32_t)
#define CIOCCRYPT	_IOWR('c', 103, struct crypt_op)
#define CIOCKEY		_IOWR('c', 104, struct crypt_kop)

#define CIOCASYMFEAT	_IOR('c', 105, u_int32_t)


struct cryptotstat {
	struct timespec	acc;		/* total accumulated time */
	struct timespec	min;		/* min time */
	struct timespec	max;		/* max time */
	u_int32_t	count;		/* number of observations */
};

struct cryptostats {
	u_int32_t	cs_ops;		/* symmetric crypto ops submitted */
	u_int32_t	cs_errs;	/* symmetric crypto ops that failed */
	u_int32_t	cs_kops;	/* asymetric/key ops submitted */
	u_int32_t	cs_kerrs;	/* asymetric/key ops that failed */
	u_int32_t	cs_intrs;	/* crypto swi thread activations */
	u_int32_t	cs_rets;	/* crypto return thread activations */
	u_int32_t	cs_blocks;	/* symmetric op driver block */
	u_int32_t	cs_kblocks;	/* symmetric op driver block */
	/*
	 * When CRYPTO_TIMING is defined at compile time and the
	 * sysctl debug.crypto is set to 1, the crypto system will
	 * accumulate statistics about how long it takes to process
	 * crypto requests at various points during processing.
	 */
	struct cryptotstat cs_invoke;	/* crypto_dipsatch -> crypto_invoke */
	struct cryptotstat cs_done;	/* crypto_invoke -> crypto_done */
	struct cryptotstat cs_cb;	/* crypto_done -> callback */
	struct cryptotstat cs_finis;	/* callback -> callback return */

	u_int32_t	cs_drops;		/* crypto ops dropped due to congestion */
};

#endif /* _CRYPTO_CRYPTODEV_H_ */
