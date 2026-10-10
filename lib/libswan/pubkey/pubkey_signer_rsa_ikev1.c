/*
 * mechanisms for preshared keys (public, private, and preshared secrets)
 *
 * this is the library for reading (and later, writing!) the ipsec.secrets
 * files.
 *
 * Copyright (C) 1998-2004  D. Hugh Redelmeier.
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2015 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2016-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2019 D. Hugh Redelmeier <hugh@mimosa.com>
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

#include <cryptohi.h>
#include <keyhi.h>

#include "lswnss.h"
#include "lswlog.h"
#include "secrets.h"
#include "ike_alg.h"
#include "ike_alg_hash.h"

/* returns the length of the result on success; 0 on failure */
static struct hash_signature RSA_raw_sign_hash(const struct secret_pubkey_stuff *pks,
					       const struct crypt_mac *hash_to_sign,
					       const struct hash_desc *hash_algo,
					       struct logger *logger)
{
	if (!pexpect(hash_algo == &ike_alg_hash_sha1)) {
		return (struct hash_signature) { .len = 0, };
	}

	SECItem data = same_shunk_as_secitem(HUNK_AS_SHUNK(hash_to_sign), siBuffer);

	struct hash_signature sig = { .len = PK11_SignatureLen(pks->private_key), };
	passert(sig.len <= sizeof(sig.ptr/*array*/));
	SECItem signature = {
		.type = siBuffer,
		.len = sig.len,
		.data = sig.ptr,
	};

	SECStatus s = PK11_Sign(pks->private_key, &signature, &data);
	if (s != SECSuccess) {
		/* PR_GetError() returns the thread-local error */
		llog_nss_error(RC_LOG, logger,
			       "PK11_Sign() function failed");
		return (struct hash_signature) { .len = 0, };
	}

	ldbg(logger, "%s: ended using NSS", __func__);
	return sig;
}

static bool RSA_authenticate_hash_signature_raw_rsa(const struct pubkey_signer *signer,
						    const struct crypt_mac *expected_hash,
						    shunk_t signature,
						    struct pubkey *pubkey,
						    const struct hash_desc *unused_hash_algo UNUSED,
						    diag_t *fatal_diag,
						    struct logger *logger)
{
	SECKEYPublicKey *seckey_public = pubkey->content.public_key;

	/* decrypt the signature -- reversing RSA_sign_hash */
	if (signature.len != (size_t)seckey_public->u.rsa.modulus.len) {
		/* XXX notification: INVALID_KEY_INFORMATION */
		*fatal_diag = NULL;
		return false;
	}

 	if (LDBGP(DBG_BASE, logger)) {
		LDBG_log(logger, "NSS: %s: verifying that signature (once decrypted):", signer->name);
		LDBG_hunk(logger, &signature);
		LDBG_log(logger, "matches hash:");
 		LDBG_hunk(logger, expected_hash);
	}

	/* NSS doesn't do const */
	const SECItem signature_secitem =
		same_shunk_as_secitem(signature, siBuffer);
	const SECItem expected_hash_secitem =
		same_shunk_as_secitem(HUNK_AS_SHUNK(expected_hash), siBuffer);

	if (PK11_Verify(seckey_public, &signature_secitem, &expected_hash_secitem,
			lsw_nss_get_password_context(logger)) != SECSuccess) {
		ldbg(logger, "NSS RSA verify: decrypting signature is failed");
		*fatal_diag = NULL;
		return false;
	}

	*fatal_diag = NULL;
	return true;
}

static size_t RSA_raw_jam_auth_method(struct jambuf *buf,
				      const struct pubkey_signer *signer,
				      const struct pubkey *pubkey,
				      const struct hash_desc *hash)
{
	return jam(buf, "%d-bit %s with %s",
		   SECKEY_PublicKeyStrengthInBits(pubkey->content.public_key),
		   signer->name, hash->common.fqn);
}

const struct pubkey_signer signer_pubkey_rsa_ikev1 = {
	.name = "raw RSA",
	.digital_signature_blob = DIGITAL_SIGNATURE_BLOB_ROOF,
	.authby = { AUTHBY_RSASIG_IKEv1, },
	.type = &pubkey_type_rsa,
	.sign_hash = RSA_raw_sign_hash,
	.authenticate_hash_signature = RSA_authenticate_hash_signature_raw_rsa,
	.jam_auth_method = RSA_raw_jam_auth_method,
};
