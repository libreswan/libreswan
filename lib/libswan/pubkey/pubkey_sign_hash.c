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

	return signer->sign_hash(pks, hash_to_sign,
				 hash_alg, logger);
}
