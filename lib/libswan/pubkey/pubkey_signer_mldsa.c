/*
 * ML-DSA digital signature signer for IKEv2
 *
 * FIPS 204, draft-ietf-ipsecme-ikev2-pqc-auth
 *
 * Copyright (C) 2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2026 Sahana Prasad <sahana@redhat.com>
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

#ifdef USE_MLDSA

#include <pk11pub.h>
#include <cryptohi.h>
#include <keyhi.h>

#include "lswnss.h"
#include "lswlog.h"
#include "secrets.h"
#include "crypt_hash.h"

static size_t MLDSA_jam_auth_method(struct jambuf *buf,
				    const struct pubkey_signer *signer,
				    const struct pubkey *pubkey UNUSED,
				    const struct hash_desc *hash)
{
	return jam(buf, "%s with %s",
		   signer->name,
		   hash->common.fqn);
}

static chunk_t concat_hunks(const struct hash_hunks *hunks)
{
	chunk_t message = {0};
	for (const struct hash_hunk *hunk = hunks->hunk;
	     hunk < hunks->hunk + hunks->len; hunk++) {
		append_chunk_hunk("message", &message, *hunk);
	}
	return message;
}

static struct hash_signature MLDSA_sign_message_1(const struct pubkey_signer *signer UNUSED,
						  const struct secret_pubkey_stuff *pks,
						  chunk_t message,
						  struct logger *logger)
{
	if (!pexpect(pks->private_key != NULL)) {
		ldbg(logger, "no private key!");
		return (struct hash_signature) { .len = 0, };
	}

	ldbgf(DBG_CRYPT, logger, "MLDSA_sign_message: Started using NSS");

	SECItem data_to_sign = same_hunk_as_secitem(&message, siBuffer);

	uint8_t raw_signature_data[sizeof(struct hash_signature)];
	SECItem raw_signature = {
		.type = siBuffer,
		.len = PK11_SignatureLen(pks->private_key),
		.data = raw_signature_data,
	};
	ldbg(logger, "ML-DSA signature length is %d", raw_signature.len);
	PASSERT(logger, raw_signature.len <= sizeof(raw_signature_data));

	if (LDBGP(DBG_BASE, logger)) {
		LDBG_log(logger, "ML-DSA message of %zu bytes:", message.len);
		LDBG_hunk(logger, &message);
	}

	SECStatus s = PK11_Sign(pks->private_key, &raw_signature, &data_to_sign);
	if (LDBGP(DBG_CRYPT, logger)) {
		LDBG_log(logger, "PK11_Sign() returned:");
		LDBG_dump(logger, raw_signature.data, raw_signature.len);
	}
	if (s != SECSuccess) {
		llog_nss_error(RC_LOG, logger,
			       "ML-DSA sign function failed");
		return (struct hash_signature) { .len = 0, };
	}

	/*
	 * ML-DSA signatures are raw byte arrays (FIPS 204),
	 * not DER-encoded like ECDSA/EdDSA.
	 */
	struct hash_signature signature = {
		.len = raw_signature.len,
	};
	passert(raw_signature.len <= sizeof(signature.ptr/*an-array*/));
	memcpy(signature.ptr, raw_signature.data, raw_signature.len);

	if (LDBGP(DBG_BASE, logger)) {
		LDBG_log(logger, "ML-DSA auth signature of %zu bytes:", signature.len);
		LDBG_hunk(logger, &signature);
	}

	return signature;
}

static struct hash_signature MLDSA_sign_message(const struct pubkey_signer *signer,
						const struct secret_pubkey_stuff *pks,
						const struct hash_hunks *hunks,
						struct logger *logger)
{
	chunk_t message = concat_hunks(hunks); /* must free_chunk_content() */
	struct hash_signature signature = MLDSA_sign_message_1(signer, pks, message, logger);
	free_chunk_content(&message);
	return signature;
}

static bool MLDSA_authenticate_message_signature_1(const struct pubkey_signer *signer UNUSED,
						   chunk_t message,
						   shunk_t signature,
						   struct pubkey *pubkey,
						   diag_t *fatal_diag,
						   struct logger *logger)
{
	if (LDBGP(DBG_BASE, logger)) {
		LDBG_log(logger, "ML-DSA signature of %zu bytes:", signature.len);
		LDBG_hunk(logger, &signature);
		LDBG_log(logger, "ML-DSA message of %zu bytes:", message.len);
		LDBG_hunk(logger, &message);
	}

	/*
	 * ML-DSA signatures are raw byte arrays (FIPS 204),
	 * not DER-encoded.  Pass directly to PK11_Verify().
	 */
	SECItem sig_item = {
		.type = siBuffer,
		.data = DISCARD_CONST(unsigned char *, signature.ptr),/*NSS doesn't do const*/
		.len = signature.len,
	};

	SECItem data_item = same_hunk_as_secitem(&message, siBuffer);

	if (PK11_Verify(pubkey->content.public_key, &sig_item, &data_item,
			lsw_nss_get_password_context(logger)) != SECSuccess) {
		llog_nss_error(DEBUG_STREAM, logger,
			       "verifying AUTH hash using PK11_Verify() failed:");
		*fatal_diag = NULL;
		return false;
	}

	*fatal_diag = NULL;
	return true;
}

static bool MLDSA_authenticate_message_signature(const struct pubkey_signer *signer UNUSED,
						 const struct hash_hunks *hunks,
						 shunk_t signature,
						 struct pubkey *pubkey,
						 diag_t *fatal_diag,
						 struct logger *logger)
{
	chunk_t message = concat_hunks(hunks); /* must free_chunk_content() */
	bool ok = MLDSA_authenticate_message_signature_1(signer, message,
							 signature,
							 pubkey, fatal_diag, logger);
	free_chunk_content(&message);
	return ok;
}

const struct pubkey_signer pubkey_signer_digsig_mldsa_44 = {
	.name = "ML-DSA-44",
	.type = &pubkey_type_mldsa,
	.digital_signature_blob = DIGITAL_SIGNATURE_MLDSA_IDENTITY_44_BLOB,
	.sign_message = MLDSA_sign_message,
	.authenticate_message_signature = MLDSA_authenticate_message_signature,
	.jam_auth_method = MLDSA_jam_auth_method,
};

const struct pubkey_signer pubkey_signer_digsig_mldsa_65 = {
	.name = "ML-DSA-65",
	.type = &pubkey_type_mldsa,
	.digital_signature_blob = DIGITAL_SIGNATURE_MLDSA_IDENTITY_65_BLOB,
	.sign_message = MLDSA_sign_message,
	.authenticate_message_signature = MLDSA_authenticate_message_signature,
	.jam_auth_method = MLDSA_jam_auth_method,
};

const struct pubkey_signer pubkey_signer_digsig_mldsa_87 = {
	.name = "ML-DSA-87",
	.type = &pubkey_type_mldsa,
	.digital_signature_blob = DIGITAL_SIGNATURE_MLDSA_IDENTITY_87_BLOB,
	.sign_message = MLDSA_sign_message,
	.authenticate_message_signature = MLDSA_authenticate_message_signature,
	.jam_auth_method = MLDSA_jam_auth_method,
};

#endif /* USE_MLDSA */
