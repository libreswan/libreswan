/****************************************************************************/
/*
 * Use OCF/cryptodev interface for AES processing
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
#include <sys/types.h>
#include <string.h>
#include <sys/ioctl.h>
#include "sysdep.h"
#include "crypto/aes.h"
#include "crypto/aes_cbc.h"
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
 *	return true if HW aes is present
 *  The return value can also be used to determine which ocf_assist engine
 *  has been detected. See the values in ocf_assist.h
 */

int
ocf_aes_assist(void)
{
    if (!crypto_tested && !have_assist) {
        crypto_fd = open("/dev/crypto", O_RDWR);

        /* set the close-on-exec flag */
        if ((crypto_fd < 0) || (fcntl(crypto_fd, F_SETFD, 1) < 0)) {
            close(crypto_fd);
            crypto_fd = -1;
        }

		if (crypto_fd != -1) {
			struct session_op ses;
			/* we have opened /dev/crypto */

			/* test we can do aes */
			memset(&ses, 0, sizeof(ses));
			ses.key = (caddr_t)"12345678901234567890123456789012";
			ses.cipher = CRYPTO_AES_CBC;
			ses.keylen = 16;
			if (ioctl(crypto_fd, CIOCGSESSION, &ses) != -1 &&
				ioctl(crypto_fd, CIOCFSESSION, &ses.ses) != -1) {
				/* fprintf(stderr, "AES_CBC capable\n"); */
				have_assist |= OCF_PROVIDES_AES;
			} else {
				/* fprintf(stderr, "NOT AES_CBC capable\n"); */
				close(crypto_fd);
				crypto_fd = -1;
			}

			crypto_tested = 1;
		}
    }
    return(have_assist);
}

/****************************************************************************/

void
ocf_aes_set_key(
	aes_context (*cx),
	const unsigned char in_key[],
	int length,
	const int f)
{  
#if defined(AES_BLOCK_SIZE)
#define nc   (AES_BLOCK_SIZE / 4)
#else
#define nc   (cx->aes_Ncol)
#endif

    switch(length) {
    case 32:			/* bytes */
    case 256:			/* bits */
		cx->aes_Nkey = 8;
		break;
    case 24:			/* bytes */
    case 192:			/* bits */
		cx->aes_Nkey = 6;
		break;
    case 16:			/* bytes */
    case 128:			/* bits */
    default:
		cx->aes_Nkey = 4;
		break;
    }
    cx->aes_Nrnd = (cx->aes_Nkey > nc ? cx->aes_Nkey : nc) + 6;
    memcpy (cx->aes_e_key, in_key, cx->aes_Nkey*4);
}

/****************************************************************************/

static void
ocf_aes_cryptodev_internal(
    u_int32_t cipher,
    char (*key),
    u_int32_t keylen,
    u_int32_t operation,
    __u8 (*src),
    __u8 (*dst),
    long len,
    __u8 (*iv),
    u_int32_t iv_len)
{
    struct session_op sop;
    struct crypt_op cop;
    u_int32_t fixed_len = len;
    __u8 *fixed_src = NULL;

    /* always make fixed_len a multiple of 16 - otherwise the CIOCCRYPT fails */
    fixed_len = (len + 15) & ~15;

    /*
	 * if the input stream's length is not a multiple of 16, copy and zero pad
	 */ 
	if ((len & 15) && operation == COP_ENCRYPT) {
        /* slow but safe */
        fixed_src = (__u8 *)malloc(fixed_len);
        if (!fixed_src) return;
        memset(fixed_src + fixed_len - 15, 0, 15);
        memcpy(fixed_src, src, len);
    } else {
        fixed_src = (__u8 *) src;
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
	sop.keylen = keylen;
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
    cop.len = fixed_len;
    cop.iv = (char *)iv;
    if (ioctl(crypto_fd, CIOCCRYPT, &cop) < 0) {
        /* fprintf(stderr, "%s CIOCCRYPT failed\n", __FUNCTION__);  */
		goto failed;
    }

    if (ioctl(crypto_fd, CIOCFSESSION, &sop.ses) == -1)
		goto failed;

    if (fixed_src != src) free(fixed_src);
	return;

failed:
	memset(dst, 0, len);
    if (fixed_src != src) free(fixed_src);
    return;
}

/****************************************************************************/

int
ocf_aes_cbc_encrypt(
	aes_context *ctx,
	__u8 (*input),
	__u8 (*output),
	long length,
	__u8 (*ivec),
	int enc)
{
	if (crypto_fd != -1) {
		ocf_aes_cryptodev_internal(	
			CRYPTO_AES_CBC,
			/* ctx->aes_d_key isn't used here, just aes_e_key ??? */
			/* enc ? ctx->aes_e_key : ctx->aes_d_key, */
			(char *) ctx->aes_e_key,
			ctx->aes_Nkey*4,
			enc ? COP_ENCRYPT : COP_DECRYPT,
			input,
			output,
			length,
			ivec,
			16);
		return length;
	}
	return length;
}

/****************************************************************************/
