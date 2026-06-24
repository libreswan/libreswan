/* mechanisms for preshared keys (public, private, and preshared secrets)
 * definitions: lib/libswan/secrets.c
 *
 * Copyright (C) 2026 Andrew Cagney
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

#include "secrets.h"
#include "lswlog.h"

#include "ike_alg_hash.h"		/* impair uses sha1 */ 

struct hash_signature pubkey_sign_hash(const struct pubkey_signer *signer,
				       const struct secret_pubkey_stuff *pks,
				       const struct crypt_mac *hash_to_sign,
				       const struct hash_desc *hash_alg,
				       struct logger *logger)
{
 	if (LDBGP(DBG_BASE, logger)) {
		LDBG_log(logger, "NSS: %s: signing the %s hash using %s:",
			 pks->content.type->name,
			 hash_alg->common.fqn,
			 signer->name);
 		LDBG_hunk(logger, hash_to_sign);
	}

	if (!PEXPECT(logger, pks->private_key != NULL)) {
		return (struct hash_signature) { .len = 0, };
	}

	if (!PEXPECT(logger, signer->type == pks->content.type)) {
		return (struct hash_signature) { .len = 0, };
	}

	if (impair.truncate_signed_hash.enabled) {
		PASSERT(logger, impair.truncate_signed_hash.value <= elemsof(hash_to_sign->ptr/*array*/));
		PEXPECT(logger, impair.truncate_signed_hash.value != hash_to_sign->len);
		llog(IMPAIR_STREAM, logger,
		     "NSS: %s: hash truncated from %zu to %u",
		     pks->content.type->name,
		     hash_to_sign->len, impair.truncate_signed_hash.value);
		struct crypt_mac tmp_hash = {
			.len = impair.truncate_signed_hash.value,
		};
		size_t len = min((size_t)impair.truncate_signed_hash.value,
				 hash_to_sign->len);
		memcpy(tmp_hash.ptr/*array*/ + tmp_hash.len - len,
		       hash_to_sign->ptr/*array*/, len);
		if (LDBGP(DBG_BASE, logger)) {
			llog_hunk(DEBUG_STREAM, logger, &tmp_hash);
		}
		/*
		 * Force RAW RSA as other signers are too smart and
		 * reject the hash.
		 */
		return pubkey_signer_raw_rsa.sign_hash(pks, &tmp_hash, &ike_alg_hash_sha1, logger);
	}

	return signer->sign_hash(pks, hash_to_sign,
				 hash_alg, logger);
}
