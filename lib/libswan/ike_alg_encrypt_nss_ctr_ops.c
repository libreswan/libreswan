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
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
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
#include <libreswan.h>

#include "constants.h"
#include "klips-crypto/aes_cbc.h"
#include "lswlog.h"
#include "ike_alg.h"

#include <pk11pub.h>
#include <prmem.h>
#include <prerror.h>
#include <blapit.h>

#include "ike_alg_encrypt_nss_ctr_ops.h"
#include "ike_alg_encrypt_nss_gcm_ops.h"

static void do_nss_ctr(const struct encrypt_desc *alg UNUSED,
		       u_int8_t *buf, size_t buf_len, PK11SymKey *sym_key,
		       u_int8_t *counter_block, bool encrypt)
{
	DBG(DBG_CRYPT, DBG_log("do_aes_ctr: enter"));

	passert(sym_key);
	if (sym_key == NULL) {
		PASSERT_FAIL("%s", "NSS derived enc key in NULL");
	}

	CK_AES_CTR_PARAMS counter_param;
	counter_param.ulCounterBits = sizeof(u_int32_t) * 8;/* Per RFC 3686 */
	memcpy(counter_param.cb, counter_block, sizeof(counter_param.cb));
	SECItem param;
	param.type = siBuffer;
	param.data = (void*)&counter_param;
	param.len = sizeof(counter_param);

	/* Output buffer for transformed data.  */
	u_int8_t *out_buf = PR_Malloc((PRUint32)buf_len);
	unsigned int out_len = 0;

	if (encrypt) {
		SECStatus rv = PK11_Encrypt(sym_key, CKM_AES_CTR, &param,
					    out_buf, &out_len, buf_len,
					    buf, buf_len);
		if (rv != SECSuccess) {
			PASSERT_FAIL("PK11_Encrypt failure (err %d)", PR_GetError());
		}
	} else {
		SECStatus rv = PK11_Decrypt(sym_key, CKM_AES_CTR, &param,
					    out_buf, &out_len, buf_len,
					    buf, buf_len);
		if (rv != SECSuccess) {
			PASSERT_FAIL("PK11_Decrypt failure (err %d)", PR_GetError());
		}
	}

	memcpy(buf, out_buf, buf_len);
	PR_Free(out_buf);

	/*
	 * Finally update the counter located at the end of the
	 * counter_block. It is incremented by 1 for every full or
	 * partial block encoded/decoded.
	 *
	 * There's a portability assumption here that the IV buffer is
	 * at least sizeof(u_int32_t) (4-byte) aligned.
	 */
	u_int32_t *counter = (u_int32_t*)(counter_block + AES_BLOCK_SIZE
					  - sizeof(u_int32_t));
	u_int32_t old_counter = ntohl(*counter);
	size_t increment = (buf_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
	u_int32_t new_counter = old_counter + increment;
	DBG(DBG_CRYPT, DBG_log("do_aes_ctr: counter-block updated from 0x%lx to 0x%lx for %zd bytes",
			       (unsigned long)old_counter, (unsigned long)new_counter, buf_len));
	if (new_counter < old_counter) {
		/* Wrap ... */
		loglog(RC_LOG_SERIOUS,
		       "do_aes_ctr: counter wrapped");
		/* what next??? */
	}
	*counter = htonl(new_counter);

	DBG(DBG_CRYPT, DBG_log("do_aes_ctr: exit"));
}

static void nss_ctr_check(const struct encrypt_desc *alg UNUSED)
{
}

const struct encrypt_ops ike_alg_encrypt_nss_ctr_ops = {
	.check = nss_ctr_check,
	.do_crypt = do_nss_ctr,
};
