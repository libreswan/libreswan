/* NULL IKE encryption, for libreswan
 *
 * Copyright (C) 2023  Andrew Cagney
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <stdio.h>
#include <stdlib.h>

#include "lswlog.h"
#include "prmem.h"
#include "prerror.h"

#include "constants.h"
#include "ike_alg.h"
#include "crypt_cipher.h"
#include "ike_alg_encrypt_ops.h"
#include "lswnss.h"		/* for llog_nss_error() */

static void cipher_op_null(const struct encrypt_desc *cipher UNUSED,
			   struct cipher_op_context *context UNUSED,
			   enum cipher_op op UNUSED,
			   enum cipher_iv_source iv_source UNUSED,
			   PK11SymKey *symkey UNUSED,
			   shunk_t salt UNUSED,
			   chunk_t in_buf UNUSED,
			   chunk_t iv UNUSED,
			   struct logger *logger UNUSED)
{
	/* nothing happens */
}

static void cipher_check_null(const struct encrypt_desc *encrypt,
			      struct logger *logger)
{
	const struct ike_alg *alg = &encrypt->common;
	pexpect_ike_alg(logger, alg, encrypt->nss.mechanism == 0);
}

const struct encrypt_ops ike_alg_encrypt_null_ops = {
	.backend = "NULL",
	.cipher_check = cipher_check_null,
	.cipher_op_normal = cipher_op_null,
};
