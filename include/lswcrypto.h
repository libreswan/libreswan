/* 
 * Pluto interface to crypto/pk operations
 *
 * Copyright (C) 2008 David McCullough <david_mccullough@securecomputing.com>
 * Daniel Djamaludin <ddjamaludin@cyberguard.com>
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

#include <mpzfuncs.h>
#include <klips-crypto/aes.h>
#include <klips-crypto/aes_cbc.h>
#include <klips-crypto/des.h>

struct lswcrypto_meth {
	void (*rsa_mod_exp_crt)(mpz_t dst, const mpz_t src, const mpz_t p,
							const mpz_t dP, const mpz_t q, const mpz_t qP,
							const mpz_t qInv);
	void (*mod_exp)(mpz_t r0, const mpz_t mp_g, const mpz_t secret,
							const mpz_t modulus);


	int  (*aes_set_key)(aes_context *cx, const u_int8_t *in_key, int length);
	int  (*aes_cbc_encrypt)(aes_context *ctx, const u_int8_t *input,
							u_int8_t *output, int length, const u_int8_t *ivec,
							int enc);


	int  (*des_set_key)(des_cblock (*key), des_key_schedule schedule);
	void (*des_cbc_encrypt)(des_cblock (*input), des_cblock (*output),
							long length, des_key_schedule schedule,
							des_cblock (*ivec), int enc);
	void (*des_encrypt)(DES_LONG *data, des_key_schedule ks, int enc);
	void (*des_ede3_cbc_encrypt)(des_cblock (*input), des_cblock (*output),
							long length, des_key_schedule ks1,
							des_key_schedule ks2, des_key_schedule ks3,
							des_cblock (*ivec), int enc);
	void (*des_ncbc_encrypt)(des_cblock (*input), des_cblock (*output),
							long length, des_key_schedule schedule,
							des_cblock (*ivec), int enc);
	void (*des_ecb_encrypt)(des_cblock (*input), des_cblock (*output),
							des_key_schedule ks, int enc);

};

extern struct lswcrypto_meth lswcrypto;

extern void load_lswcrypto(void);
#ifdef HAVE_OCF
extern void load_cryptodev(void);
#endif

