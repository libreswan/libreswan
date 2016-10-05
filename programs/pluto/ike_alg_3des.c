/* 3des, for libreswan
 *
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>

#include <libreswan.h>

#include <errno.h>

#include "constants.h"
#include "defs.h"
#include "state.h"
#include "log.h"
#include "md5.h"
#include "sha1.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "alg_info.h"
#include "ike_alg.h"
#include "test_buffer.h"

#include "pem.h"

#include "lswfips.h"

/* encrypt or decrypt part of an IKE message using 3DES
 * See RFC 2409 "IKE" Appendix B
 */
static void do_3des(u_int8_t *buf, size_t buf_len,
		    PK11SymKey *key, u_int8_t *iv, bool enc)
{
	passert(key != NULL);
	do_3des_nss(buf, buf_len, key, iv, enc);
}

struct encrypt_desc ike_alg_encrypt_3des_cbc =
{
	.common = { .name = "oakley_3des_cbc",
		    .officname =     "3des",
		    .algo_type =     IKE_ALG_ENCRYPT,
		    .algo_id =       OAKLEY_3DES_CBC,
		    .algo_v2id =     IKEv2_ENCR_3DES,
		    .algo_next =     NULL,
		    .fips =          TRUE,
	},
	.enc_ctxsize =      8 * 16 * 3, /* sizeof(des_key_schedule) * 3 */
	.enc_blocksize =    DES_CBC_BLOCK_SIZE,
	.pad_to_blocksize = TRUE,
	.wire_iv_size =           DES_CBC_BLOCK_SIZE,
	.keydeflen =        DES_CBC_BLOCK_SIZE * 3 * BITS_PER_BYTE,
	.keyminlen =        DES_CBC_BLOCK_SIZE * 3 * BITS_PER_BYTE,
	.keymaxlen =        DES_CBC_BLOCK_SIZE * 3 * BITS_PER_BYTE,
	.do_crypt =         do_3des,
};
