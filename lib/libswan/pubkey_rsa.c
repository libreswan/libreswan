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
					       const uint8_t *hash_val, size_t hash_len,
					       const struct hash_desc *hash_algo,
					       struct logger *logger)
{
	ldbg(logger, "%s: started using NSS", __func__);

	if (!pexpect(hash_algo == &ike_alg_hash_sha1)) {
		return (struct hash_signature) { .len = 0, };
	}

	if (!pexpect(pks->private_key != NULL)) {
		ldbg(logger, "no private key!");
		return (struct hash_signature) { .len = 0, };
	}

	SECItem data = {
		.type = siBuffer,
		.len = hash_len,
		.data = DISCARD_CONST(uint8_t *, hash_val),
	};

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

static bool RSA_authenticate_hash_signature_raw_rsa(const struct pubkey_signer *signer UNUSED,
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
		LDBG_log(logger, "NSS RSA: verifying that decrypted signature matches hash:");
		LDBG_hunk(logger, expected_hash);
	}

	/*
	 * Use the same space used by the out going hash.
	 */

	SECItem decrypted_signature = {
		.type = siBuffer,
	};

	if (SECITEM_AllocItem(NULL, &decrypted_signature, signature.len) == NULL) {
		llog_nss_error(RC_LOG, logger, "allocating space for decrypted RSA signature");
		return false;
	}

	/* NSS doesn't do const */
	const SECItem encrypted_signature = {
		.type = siBuffer,
		.data = DISCARD_CONST(unsigned char *, signature.ptr),
		.len  = signature.len,
	};

	if (PK11_VerifyRecover(seckey_public, &encrypted_signature, &decrypted_signature,
			       lsw_nss_get_password_context(logger)) != SECSuccess) {
		SECITEM_FreeItem(&decrypted_signature, PR_FALSE/*not-pointer*/);
		ldbg(logger, "NSS RSA verify: decrypting signature is failed");
		*fatal_diag = NULL;
		return false;
	}

	if (LDBGP(DBG_CRYPT, logger)) {
		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
			jam_string(buf, "NSS RSA verify: decrypted sig: ");
			jam_nss_secitem(buf, &decrypted_signature);
		}
	}

	/*
	 * Expect the matching hash to appear at the end.  See above
	 * for length check.  It may, or may not, be prefixed by a
	 * PKCS#1 1.5 RSA ASN.1 blob.
	 */
	passert(decrypted_signature.len >= expected_hash->len);
	uint8_t *start = (decrypted_signature.data
			  + decrypted_signature.len
			  - expected_hash->len);
	if (!memeq(start, expected_hash->ptr, expected_hash->len)) {
		ldbg(logger, "RSA Signature NOT verified");
		SECITEM_FreeItem(&decrypted_signature, PR_FALSE/*not-pointer*/);
		*fatal_diag = NULL;
		return false;
	}

	SECITEM_FreeItem(&decrypted_signature, PR_FALSE/*not-pointer*/);
	*fatal_diag = NULL;
	return true;
}

static size_t RSA_jam_auth_method(struct jambuf *buf,
				  const struct pubkey_signer *signer,
				  const struct pubkey *pubkey,
				  const struct hash_desc *hash)
{
	return jam(buf, "%d-bit %s with %s",
		   SECKEY_PublicKeyStrengthInBits(pubkey->content.public_key),
		   signer->name, hash->common.fqn);
}

const struct pubkey_signer pubkey_signer_raw_rsa = {
	.name = "RSA",
	.digital_signature_blob = DIGITAL_SIGNATURE_BLOB_ROOF,
	.type = &pubkey_type_rsa,
	.sign = pubkey_hash_then_sign,
	.sign_hash = RSA_raw_sign_hash,
	.authenticate_hash_signature = RSA_authenticate_hash_signature_raw_rsa,
	.jam_auth_method = RSA_jam_auth_method,
};

/* returns the length of the result on success; 0 on failure */
static struct hash_signature RSA_pkcs1_1_5_sign_hash(const struct secret_pubkey_stuff *pks,
						     const uint8_t *hash_val, size_t hash_len,
						     const struct hash_desc *hash_algo,
						     struct logger *logger)
{
	ldbg(logger, "%s: started using NSS", __func__);

	if (!pexpect(pks->private_key != NULL)) {
		ldbg(logger, "no private key!");
		return (struct hash_signature) { .len = 0, };
	}

	SECItem digest = {
		.type = siBuffer,
		.len = hash_len,
		.data = DISCARD_CONST(uint8_t *, hash_val),
	};

	/*
	 * XXX: the call expects the OID TAG for the hash algorithm
	 * used to generate the signature.
	 */
	SECItem signature_result = {0};
	SECStatus s = SGN_Digest(pks->private_key,
				 hash_algo->nss.oid_tag,
				 &signature_result, &digest);
	if (s != SECSuccess) {
		/* PR_GetError() returns the thread-local error */
		name_buf tb;
		llog_nss_error(RC_LOG, logger,
			       "SGN_Digest(%s) function failed",
			       str_nss_oid(hash_algo->nss.oid_tag, &tb));
		return (struct hash_signature) { .len = 0, };
	}

	/* save the signature, free the returned pointer */

	struct hash_signature signature = {
		.len = PK11_SignatureLen(pks->private_key),
	};
	passert(signature.len <= sizeof(signature.ptr/*array*/));
	memcpy(signature.ptr, signature_result.data, signature.len);
	PORT_Free(signature_result.data);

	ldbg(logger, "%s: ended using NSS", __func__);
	return signature;
}

static bool RSA_authenticate_hash_signature_pkcs1_1_5_rsa(const struct pubkey_signer *signer UNUSED,
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
		LDBG_log(logger, "NSS RSA: verifying that decrypted signature matches hash:");
		LDBG_hunk(logger, expected_hash);
	}

	/*
	 * Use the same space used by the out going hash.
	 */

	SECItem decrypted_signature = {
		.type = siBuffer,
	};

	if (SECITEM_AllocItem(NULL, &decrypted_signature, signature.len) == NULL) {
		llog_nss_error(RC_LOG, logger, "allocating space for decrypted RSA signature");
		return false;
	}

	/* NSS doesn't do const */
	const SECItem encrypted_signature = {
		.type = siBuffer,
		.data = DISCARD_CONST(unsigned char *, signature.ptr),
		.len  = signature.len,
	};

	if (PK11_VerifyRecover(seckey_public, &encrypted_signature, &decrypted_signature,
			       lsw_nss_get_password_context(logger)) != SECSuccess) {
		SECITEM_FreeItem(&decrypted_signature, PR_FALSE/*not-pointer*/);
		ldbg(logger, "NSS RSA verify: decrypting signature is failed");
		*fatal_diag = NULL;
		return false;
	}

	if (LDBGP(DBG_CRYPT, logger)) {
		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
			jam_string(buf, "NSS RSA verify: decrypted sig: ");
			jam_nss_secitem(buf, &decrypted_signature);
		}
	}

	/*
	 * Expect the matching hash to appear at the end.  See above
	 * for length check.  It may, or may not, be prefixed by a
	 * PKCS#1 1.5 RSA ASN.1 blob.
	 */
	passert(decrypted_signature.len >= expected_hash->len);
	uint8_t *start = (decrypted_signature.data
			  + decrypted_signature.len
			  - expected_hash->len);
	if (!memeq(start, expected_hash->ptr, expected_hash->len)) {
		ldbg(logger, "RSA Signature NOT verified");
		SECITEM_FreeItem(&decrypted_signature, PR_FALSE/*not-pointer*/);
		*fatal_diag = NULL;
		return false;
	}

	SECITEM_FreeItem(&decrypted_signature, PR_FALSE/*not-pointer*/);
	*fatal_diag = NULL;
	return true;
}

const struct pubkey_signer pubkey_signer_raw_pkcs1_1_5_rsa = {
	.name = "PKCS#1 1.5 RSA", /* name from RFC 7427 */
	.digital_signature_blob = DIGITAL_SIGNATURE_BLOB_ROOF,
	.type = &pubkey_type_rsa,
	.sign = pubkey_hash_then_sign,
	.sign_hash = RSA_pkcs1_1_5_sign_hash,
	.authenticate_hash_signature = RSA_authenticate_hash_signature_pkcs1_1_5_rsa,
	.jam_auth_method = RSA_jam_auth_method,
};

const struct pubkey_signer pubkey_signer_digsig_pkcs1_1_5_rsa = {
	.name = "PKCS#1 1.5 RSA", /* name from RFC 7427 */
	.digital_signature_blob = DIGITAL_SIGNATURE_PKCS1_1_5_RSA_BLOB,
	.type = &pubkey_type_rsa,
	.sign = pubkey_hash_then_sign,
	.sign_hash = RSA_pkcs1_1_5_sign_hash,
	.authenticate_hash_signature = RSA_authenticate_hash_signature_pkcs1_1_5_rsa,
	.jam_auth_method = RSA_jam_auth_method,
};

/* returns the length of the result on success; 0 on failure */
static struct hash_signature RSA_rsassa_pss_sign_hash(const struct secret_pubkey_stuff *pks,
						      const uint8_t *hash_val, size_t hash_len,
						      const struct hash_desc *hash_algo,
						      struct logger *logger)
{
	ldbg(logger, "%s: started using NSS", __func__);

	if (!pexpect(pks->private_key != NULL)) {
		ldbg(logger, "no private key!");
		return (struct hash_signature) { .len = 0, };
	}

	SECItem data = {
		.type = siBuffer,
		.len = hash_len,
		.data = DISCARD_CONST(uint8_t *, hash_val),
	};

	struct hash_signature sig = { .len = PK11_SignatureLen(pks->private_key), };
	passert(sig.len <= sizeof(sig.ptr/*array*/));
	SECItem signature = {
		.type = siBuffer,
		.len = sig.len,
		.data = sig.ptr,
	};

	const CK_RSA_PKCS_PSS_PARAMS *mech = hash_algo->nss.rsa_pkcs_pss_params;
	if (mech == NULL) {
		llog(RC_LOG, logger,
		     "digital signature scheme not supported for hash algorithm %s",
		     hash_algo->common.fqn);
		return (struct hash_signature) { .len = 0, };
	}

	SECItem mech_item = {
		.type = siBuffer,
		.data = (void*)mech, /* strip const */
		.len = sizeof(*mech),
	};
	SECStatus s = PK11_SignWithMechanism(pks->private_key, CKM_RSA_PKCS_PSS,
					     &mech_item, &signature, &data);
	if (s != SECSuccess) {
		/* PR_GetError() returns the thread-local error */
		llog_nss_error(RC_LOG, logger,
			       "RSA DSS sign function failed");
		return (struct hash_signature) { .len = 0, };
	}

	ldbg(logger, "%s: ended using NSS", __func__);
	return sig;
}

static bool RSA_authenticate_hash_signature_rsassa_pss(const struct pubkey_signer *signer UNUSED,
						       const struct crypt_mac *expected_hash,
						       shunk_t signature,
						       struct pubkey *pubkey,
						       const struct hash_desc *hash_algo,
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
		LDBG_log(logger, "NSS RSA: verifying that decrypted signature matches hash:");
		LDBG_hunk(logger, expected_hash);
	}

	/*
	 * Convert the signature into raw form (NSS doesn't do const).
	 */

	const SECItem encrypted_signature = {
		.type = siBuffer,
		.data = DISCARD_CONST(unsigned char *, signature.ptr),
		.len  = signature.len,
	};

	/*
	 * Digital signature scheme with RSA-PSS
	 */
	const CK_RSA_PKCS_PSS_PARAMS *mech = hash_algo->nss.rsa_pkcs_pss_params;
	if (!pexpect(mech != NULL)) {
		ldbg(logger, "NSS RSA verify: hash algorithm not supported");
		/* internal error? */
		*fatal_diag = NULL;
		return false;
	}

	const SECItem hash_mech_item = {
		.type = siBuffer,
		.data = (void*)mech, /* strip const */
		.len = sizeof(*mech),
	};

	struct crypt_mac hash_data = *expected_hash; /* cast away const */
	const SECItem expected_hash_item = {
		.len = hash_data.len,
		.data = hash_data.ptr,
		.type = siBuffer,
	};

	if (PK11_VerifyWithMechanism(seckey_public, CKM_RSA_PKCS_PSS,
				     &hash_mech_item, &encrypted_signature,
				     &expected_hash_item,
				     lsw_nss_get_password_context(logger)) != SECSuccess) {
		ldbg(logger, "NSS RSA verify: decrypting signature is failed");
		*fatal_diag = NULL;
		return false;
	}

	*fatal_diag = NULL;
	return true;
}

const struct pubkey_signer pubkey_signer_digsig_rsassa_pss = {
	.name = "RSASSA-PSS", /* name from RFC 7427 */
	.type = &pubkey_type_rsa,
	.digital_signature_blob = DIGITAL_SIGNATURE_RSASSA_PSS_BLOB,
	.sign = pubkey_hash_then_sign,
	.sign_hash = RSA_rsassa_pss_sign_hash,
	.authenticate_hash_signature = RSA_authenticate_hash_signature_rsassa_pss,
	.jam_auth_method = RSA_jam_auth_method,
};
