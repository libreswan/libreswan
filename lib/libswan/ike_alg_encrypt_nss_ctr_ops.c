/*
 * Copyright (C) 2005-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2014 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2014-2016 Andrew Cagney <andrew.cagney@gmail.com>
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
#include <string.h>
#include <stddef.h>
#include <sys/types.h>

#include <pk11pub.h>
#include <prmem.h>
#include <prerror.h>
#include <blapit.h>

#include "constants.h"
#include "lswlog.h"
#include "ike_alg.h"
#include "lswnss.h"
#include "ike_alg_encrypt_ops.h"

static void do_nss_ctr(const struct encrypt_desc *alg UNUSED,
		       chunk_t buf, chunk_t counter_block,
		       PK11SymKey *sym_key, bool encrypt,
		       struct logger *logger)
{
	ldbgf(DBG_CRYPT, logger, "do_aes_ctr: enter");

	passert(sym_key);
	if (sym_key == NULL) {
		llog_passert(logger, HERE, "%s", "NSS derived enc key in NULL");
	}

	CK_AES_CTR_PARAMS counter_param;
	counter_param.ulCounterBits = sizeof(uint32_t) * 8;/* Per RFC 3686 */
	PEXPECT(logger, counter_block.len == sizeof(counter_param.cb));
	memcpy(counter_param.cb, counter_block.ptr, sizeof(counter_param.cb));
	SECItem param;
	param.type = siBuffer;
	param.data = (void*)&counter_param;
	param.len = sizeof(counter_param);

	/* Output buffer for transformed data. */
	uint8_t *out_buf = PR_Malloc((PRUint32)buf.len);
	unsigned int out_len = 0;

	if (encrypt) {
		SECStatus rv = PK11_Encrypt(sym_key, CKM_AES_CTR, &param,
					    out_buf, &out_len, buf.len,
					    buf.ptr, buf.len);
		if (rv != SECSuccess) {
			passert_nss_error(logger, HERE, "PK11_Encrypt failure");
		}
	} else {
		SECStatus rv = PK11_Decrypt(sym_key, CKM_AES_CTR, &param,
					    out_buf, &out_len, buf.len,
					    buf.ptr, buf.len);
		if (rv != SECSuccess) {
			passert_nss_error(logger, HERE, "PK11_Decrypt failure");
		}
	}

	memcpy(buf.ptr, out_buf, buf.len);
	PR_Free(out_buf);

	/*
	 * Finally update the counter located at the end of the
	 * counter_block. It is incremented by 1 for every full or
	 * partial block encoded/decoded.
	 *
	 * There's a portability assumption here that the IV buffer is
	 * at least sizeof(uint32_t) (4-byte) aligned.
	 */
	uint32_t *counter = (uint32_t*)(counter_block.ptr + AES_BLOCK_SIZE
					- sizeof(uint32_t));
	uint32_t old_counter = ntohl(*counter);
	size_t increment = (buf.len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
	uint32_t new_counter = old_counter + increment;
	ldbgf(DBG_CRYPT, logger, "do_aes_ctr: counter-block updated from 0x%" PRIx32 " to 0x%" PRIx32 " for %zd bytes",
	      old_counter, new_counter, buf.len);
	/* Wrap ... */
	passert(new_counter >= old_counter);
	*counter = htonl(new_counter);

	ldbgf(DBG_CRYPT, logger, "do_aes_ctr: exit");
}

static void nss_ctr_check(const struct encrypt_desc *alg UNUSED, struct logger *unused_logger UNUSED)
{
}

const struct encrypt_ops ike_alg_encrypt_nss_ctr_ops = {
	.backend = "NSS(CTR)",
	.check = nss_ctr_check,
	.do_crypt = do_nss_ctr,
};
