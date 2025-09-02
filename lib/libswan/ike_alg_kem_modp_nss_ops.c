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
#include "ike_alg_kem_ops.h"
#include "crypt_symkey.h"

static void nss_modp_calc_local_secret(const struct kem_desc *group,
				       SECKEYPrivateKey **privk,
				       SECKEYPublicKey **pubk,
				       struct logger *logger)
{
	chunk_t prime = chunk_from_hex(group->nss.modp.prime, group->nss.modp.prime);
	chunk_t base = chunk_from_hex(group->nss.modp.base, group->nss.modp.base);

	if (LDBGP(DBG_CRYPT, logger)) {
		LDBG_log(logger, "NSS: Value of Prime:"); LDBG_hunk(logger, prime);
		LDBG_log(logger, "NSS: Value of base:"); LDBG_hunk(logger, base);
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
			ldbgf(DBG_CRYPT, logger,
			      "NSS: re-generating dh keys (pubkey %d did not match %zu)",
			      (*pubk)->u.dh.publicValue.len,
			      group->bytes);
			SECKEY_DestroyPrivateKey(*privk);
			SECKEY_DestroyPublicKey(*pubk);
		}
		*privk = SECKEY_CreateDHPrivateKey(&dh_params, pubk,
						   lsw_nss_get_password_context(logger));
		if (*pubk == NULL || *privk == NULL) {
			passert_nss_error(logger, HERE, "MODP private key creation failed");
		}
	} while (group->bytes != (*pubk)->u.dh.publicValue.len);

	free_chunk_content(&prime);
	free_chunk_content(&base);
}

static shunk_t nss_modp_local_secret_ke(const struct kem_desc *group,
					const SECKEYPublicKey *local_pubk)
{
	/* clone secitem as chunk()? */
	passert(local_pubk->u.dh.publicValue.len == group->bytes);
	return shunk2(local_pubk->u.dh.publicValue.data, group->bytes);
}

static diag_t nss_modp_calc_shared_secret(const struct kem_desc *group,
					  SECKEYPrivateKey *local_privk,
					  const SECKEYPublicKey *local_pubk,
					  shunk_t remote_ke,
					  PK11SymKey **shared_secret,
					  struct logger *logger)
{
	ldbgf(DBG_CRYPT, logger, "NSS: started MODP shared-secret computation");

	/*
	 * See NSS's SSL code for how this gets constructed on the
	 * stack.
	 */
	SECKEYPublicKey remote_pubk = {
		.keyType = dhKey,
		.u.dh = {
			.prime = local_pubk->u.dh.prime,
			.base = local_pubk->u.dh.base,
			.publicValue = same_shunk_as_secitem(remote_ke, siBuffer), /*NSS-doesn't do const*/
		},
	};

	*shared_secret = PK11_PubDerive(local_privk, &remote_pubk,
					PR_FALSE, NULL, NULL,
					/* what to do */
					CKM_DH_PKCS_DERIVE,
					/* type of result (anything) */
					CKM_CONCATENATE_DATA_AND_BASE,
					CKA_DERIVE, group->bytes,
					lsw_nss_get_password_context(logger));
	if (*shared_secret == NULL) {
		return diag_nss_error("shared key calculation using MODP failed");
	}

	symkey_newref(logger, "shared-key", *shared_secret);
	return NULL;
}

static void nss_modp_check(const struct kem_desc *kem, struct logger *logger)
{
	const struct ike_alg *alg = &kem->common;
	pexpect_ike_alg(logger, alg, kem->nss.modp.base != NULL);
	pexpect_ike_alg(logger, alg, kem->nss.modp.prime != NULL);
	pexpect_ike_alg(logger, alg, kem->ikev1_oakley_id > 0);
	pexpect_ike_alg(logger, alg, kem->ikev1_ipsec_id > 0);
	pexpect_ike_alg(logger, alg, kem->ikev1_ipsec_id == kem->ikev1_oakley_id);
	pexpect_ike_alg(logger, alg, kem->bytes > 0);
	pexpect_ike_alg(logger, alg, kem->initiator_bytes == kem->bytes);
	pexpect_ike_alg(logger, alg, kem->responder_bytes == kem->bytes);
}

const struct kem_ops ike_alg_kem_modp_nss_ops = {
	.backend = "NSS(MODP)",
	.check = nss_modp_check,
	.calc_local_secret = nss_modp_calc_local_secret,
	.local_secret_ke = nss_modp_local_secret_ke,
	.calc_shared_secret = nss_modp_calc_shared_secret,
};
