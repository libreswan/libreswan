/*
 * Copyright (C) 2017 Andrew Cagney <cagney@gnu.org>
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

#include <stddef.h>
#include <stdint.h>

#include "nspr.h"
#include "pk11pub.h"
#include "keyhi.h"

#include "constants.h"
#include "lswalloc.h"
#include "lswnss.h"
#include "lswlog.h"

#include "ike_alg.h"
#include "ike_alg_dh_ops.h"
#include "crypt_symkey.h"

static void nss_modp_calc_local_secret(const struct dh_desc *group,
				       SECKEYPrivateKey **privk,
				       SECKEYPublicKey **pubk,
				       struct logger *logger)
{
	chunk_t prime = chunk_from_hex(group->modp, group->modp);
	chunk_t base = chunk_from_hex(group->gen, group->gen);

	if (DBGP(DBG_CRYPT)) {
		DBG_dump_hunk("NSS: Value of Prime:", prime);
		DBG_dump_hunk("NSS: Value of base:", base);
	}

	SECKEYDHParams dh_params = {
		.prime = {
			.data = prime.ptr,
			.len = prime.len,
		},
		.base = {
			.data = base.ptr,
			.len = base.len,
		},
	};

	/*
	 * Keep trying until enough bytes are generated.  Should this
	 * be limited, and why?
	 */
	*privk = NULL;
	do {
		if (*privk != NULL) {
			DBGF(DBG_CRYPT, "NSS: re-generating dh keys (pubkey %d did not match %zu)",
			     (*pubk)->u.dh.publicValue.len,
			     group->bytes);
			SECKEY_DestroyPrivateKey(*privk);
			SECKEY_DestroyPublicKey(*pubk);
		}
		*privk = SECKEY_CreateDHPrivateKey(&dh_params, pubk,
						   lsw_nss_get_password_context(logger));
		if (*pubk == NULL || *privk == NULL) {
			passert_nss_error(logger, HERE,
					  "DH MODP private key creation failed");
		}
	} while (group->bytes != (*pubk)->u.dh.publicValue.len);

	free_chunk_content(&prime);
	free_chunk_content(&base);
}

static chunk_t nss_modp_clone_local_secret_ke(const struct dh_desc *group,
					      const SECKEYPublicKey *local_pubk)
{
	/* clone secitem as chunk()? */
	pexpect(local_pubk->u.dh.publicValue.len == group->bytes);
	return clone_bytes_as_chunk(local_pubk->u.dh.publicValue.data, group->bytes, "MODP KE");
}

static PK11SymKey *nss_modp_calc_shared_secret(const struct dh_desc *group,
					       SECKEYPrivateKey *local_privk,
					       const SECKEYPublicKey *local_pubk,
					       uint8_t *remote_ke,
					       size_t sizeof_remote_ke,
					       struct logger *logger)
{
	DBGF(DBG_CRYPT, "Started DH shared-secret computation in NSS:");

	/*
	 * See NSS's SSL code for how this gets constructed on the
	 * stack.
	 */
	SECKEYPublicKey remote_pubk = {
		.keyType = dhKey,
		.u.dh = {
			.prime = local_pubk->u.dh.prime,
			.base = local_pubk->u.dh.base,
			.publicValue = {
				.data = remote_ke,
				.len = sizeof_remote_ke,
				.type = siBuffer
			},
		},
	};

	PK11SymKey *g_ir = PK11_PubDerive(local_privk, &remote_pubk,
					  PR_FALSE, NULL, NULL,
					  /* what to do */
					  CKM_DH_PKCS_DERIVE,
					  /* type of result (anything) */
					  CKM_CONCATENATE_DATA_AND_BASE,
					  CKA_DERIVE, group->bytes,
					  lsw_nss_get_password_context(logger));
	if (DBGP(DBG_BASE)) {
		DBG_symkey(logger, "newref ", "g_ir", g_ir);
	}

	return g_ir;
}

static void nss_modp_check(const struct dh_desc *dhmke, struct logger *logger)
{
	const struct ike_alg *alg = &dhmke->common;
	pexpect_ike_alg(logger, alg, dhmke->gen != NULL);
	pexpect_ike_alg(logger, alg, dhmke->modp != NULL);
}

const struct dh_ops ike_alg_dh_nss_modp_ops = {
	.backend = "NSS(MODP)",
	.check = nss_modp_check,
	.calc_local_secret = nss_modp_calc_local_secret,
	.clone_local_secret_ke = nss_modp_clone_local_secret_ke,
	.calc_shared_secret = nss_modp_calc_shared_secret,
};
