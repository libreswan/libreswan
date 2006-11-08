/****************************************************************************/
/*
 * Use OCF/cryptodev interface for DES processing
 * written by Toby Smith <toby@snapgear.com>
 * Copyright (C) 2004-2005 Intel Corporation.  All Rights Reserved.
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

#include <fcntl.h>
#include <sys/ioctl.h>
#include "sysdep.h"
#include "crypto/des.h"
#include "des/des_locl.h"
#include "crypto/ocf_assist.h"

/****************************************************************************/

#include <crypto/cryptodev.h>
#include <unistd.h>
#include <stdlib.h>

static int crypto_fd = -1;
static int crypto_tested = 0;

/* have we found a functional ocf_assist method */
static int have_assist = 0;

/****************************************************************************/
/*
 *	return provides flags if both DES and 3DES are present.
 *	We need both as set_key cannot determine what we will call.
 */

int
ocf_des_assist(void)
{
	if (!crypto_tested && !have_assist) {
		struct session_op ses;
		crypto_fd = open("/dev/crypto", O_RDWR);

		/* set the close-on-exec flag */
		if ((crypto_fd < 0) || (fcntl(crypto_fd, F_SETFD, 1) < 0)) {
			close(crypto_fd);
			crypto_fd = -1;
		}

		memset(&ses, 0, sizeof(ses));
		ses.key = (caddr_t)"123456789012345678901234";

		/* test we can do des ... */
		if (crypto_fd != -1) {
			crypto_tested = 1;
			ses.cipher = CRYPTO_DES_CBC;
			ses.keylen = 8;
			if (ioctl(crypto_fd, CIOCGSESSION, &ses) != -1 &&
					ioctl(crypto_fd, CIOCFSESSION, &ses.ses) != -1) {
				/* ... and test we can do 3des */
				ses.cipher = CRYPTO_3DES_CBC;
				ses.keylen = 24;
				if (ioctl(crypto_fd, CIOCGSESSION, &ses) != -1 &&
						ioctl(crypto_fd, CIOCFSESSION, &ses.ses) != -1)
					have_assist |= OCF_PROVIDES_DES_3DES;
			}

			if (!have_assist) {
				close(crypto_fd);
				crypto_fd = -1;
			}
		}
	}
	return(have_assist);
}

/****************************************************************************/

int
ocf_des_set_key(des_cblock (*key), des_key_schedule schedule)
{
	if (crypto_fd >= 0) {
		memcpy(schedule, key, sizeof(*key));
		return(0);
	}
	return(-1);
}

/****************************************************************************/

static void
ocf_des_cryptodev_internal(
	u_int32_t cipher,
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
		if (!fixed_src) return;
		memset((char *)fixed_src + fixed_len - 8, 0, 8);
		memcpy((char *)fixed_src, (char *)src, len);
	} else {
		fixed_src = src;
	}

	/* need to calculate the new iv before decrypting, as if we are decrypting
	 * in place then the operation will destroy the last block of cipher text */
	if (operation != COP_ENCRYPT) {
		/* ciphertext will be in src */
		memcpy((char *)new_iv, (char *)fixed_src + fixed_len - iv_len, iv_len);
	}

	/*
	 * XXX
	 * cryptodev enforces the concept of a crypto session
	 * in which you perform operations. This ocf_assist stuff doesn't currently
	 * support that. So for now I'm creating sessions for each operation. 
	 */

	/* create a session */
	bzero(&sop, sizeof(sop));
	sop.cipher = cipher;

	if (cipher == CRYPTO_DES_CBC) {
		sop.keylen = 8;
	} else if (cipher == CRYPTO_3DES_CBC) {
		sop.keylen = 24;
	}
	sop.key = key;

	if (ioctl(crypto_fd, CIOCGSESSION, &sop) < 0) {
		/* fatal error condition - bail out */
		goto failed;
	}

	/* perform the operation */
	bzero(&cop, sizeof(cop));
	cop.ses = sop.ses;
	cop.op = operation;
	cop.src = (char *)fixed_src; 
	cop.dst = (char *)dst;
	cop.slen = fixed_len;
	cop.dlen = fixed_len;
	cop.iv = (char *)iv;
	if (ioctl(crypto_fd, CIOCCRYPT, &cop) < 0) {
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

	if (ioctl(crypto_fd, CIOCFSESSION, &sop.ses) == -1)
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
	
void
ocf_des_cbc_encrypt(
	des_cblock (*input),
	des_cblock (*output),
	long length,
	des_key_schedule schedule,
	des_cblock (*ivec),
	int enc)
{
	if (crypto_fd != -1) {
		char key[8];
		des_cblock iv;

		memcpy(key, schedule, 8);
		memcpy(&iv, ivec, sizeof(des_cblock));
		ocf_des_cryptodev_internal(
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

void
ocf_des_encrypt(
	DES_LONG *data,
	des_key_schedule ks,
	int enc)
{
	if (crypto_fd != -1) {
		char key[8];
		des_cblock iv;
		des_cblock datac;
		register DES_LONG l;
		unsigned char *p;

		p=&datac[0];
		l=data[0]; l2c(l,p);
		l=data[1]; l2c(l,p);

		memcpy(key, ks, 8);
		memset(&iv, 0, sizeof(des_cblock));
		/* single block ecb == single block cbc with iv=0 */
		ocf_des_cryptodev_internal(
			CRYPTO_DES_CBC,
			key,
			enc ? COP_ENCRYPT : COP_DECRYPT,
			&datac,
			&datac,
			sizeof(des_cblock),
			&iv,
			sizeof(des_cblock));

		p=datac;
		c2l(p,l); data[0]=l;
		c2l(p,l); data[1]=l;
	}
}

/****************************************************************************/

void
ocf_des_ede3_cbc_encrypt(
	des_cblock (*input),
	des_cblock (*output),
	long length,
	des_key_schedule ks1,
	des_key_schedule ks2,
	des_key_schedule ks3,
	des_cblock (*ivec),
	int enc)
{
	if (crypto_fd != -1) {
		char key[8*3];
		des_cblock iv;

		memcpy(key, ks1, 8);
		memcpy(key+8, ks2, 8);
		memcpy(key+16, ks3, 8);
		memcpy(&iv, ivec, sizeof(des_cblock));
		ocf_des_cryptodev_internal(
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

void
ocf_des_ncbc_encrypt(
	des_cblock (*input),
	des_cblock (*output),
	long length,
	des_key_schedule schedule,
	des_cblock (*ivec),
	int enc)
{
	if (crypto_fd != -1) {
		char key[8];
		des_cblock iv;

		memcpy(key, schedule, 8);
		memcpy(&iv, ivec, sizeof(des_cblock));
		ocf_des_cryptodev_internal(
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

void
ocf_des_ecb_encrypt(
	des_cblock (*input),
	des_cblock (*output),
	des_key_schedule ks,
	int enc)
{
	if (crypto_fd != -1) {
		char key[8];
		des_cblock iv;

		memcpy(key, ks, 8);
		memset(&iv, 0, sizeof(des_cblock));
		/* single block ecb == single block cbc with iv=0 */
		ocf_des_cryptodev_internal(
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
