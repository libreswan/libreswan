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
#include "ike_alg_encrypt_ops.h"
#include "lswnss.h"		/* for llog_nss_error() */

static void ike_alg_encrypt_null_do_crypt(const struct encrypt_desc *alg,
					  uint8_t *in_buf, size_t in_buf_len,
					  PK11SymKey *symkey,
					  uint8_t *iv, bool enc,
					  struct logger *logger)
{
	LDBGF(DBG_CRYPT, logger, "%s() %s - enter %p %zu bytes iv %p enc=%s key=%p",
	      __func__, alg->common.fqn, in_buf, in_buf_len,
	      iv, bool_str(enc), symkey);
	/* nothing happens */
	LDBGF(DBG_CRYPT, logger, "NSS ike_alg_nss_cbc: %s - exit", alg->common.fqn);
}

static void ike_alg_encrypt_null_check(const struct encrypt_desc *encrypt, struct logger *logger)
{
	const struct ike_alg *alg = &encrypt->common;
	pexpect_ike_alg(logger, alg, encrypt->nss.mechanism == 0);
}

const struct encrypt_ops ike_alg_encrypt_null_ops = {
	.backend = "NSS(CBC)",
	.check = ike_alg_encrypt_null_check,
	.do_crypt = ike_alg_encrypt_null_do_crypt,
};
