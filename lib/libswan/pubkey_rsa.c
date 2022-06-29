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

/*
 * Note: e and n will point int rr.
 *
 * See https://www.rfc-editor.org/rfc/rfc3110#section-2
 */
static err_t pubkey_dnssec_pubkey_to_rsa_pubkey(chunk_t rr, chunk_t *e, chunk_t *n)
{
	*e = EMPTY_CHUNK;
	*n = EMPTY_CHUNK;

	/*
	 * Step 1: find the bounds of the exponent and modulus within
	 * the resource record and verify that they are sane.
	 */

	chunk_t exponent;
	if (rr.len >= 2 && rr.ptr[0] != 0x00) {
		/*
		 * Exponent length is one-byte, followed by that many
		 * exponent bytes
		 */
		exponent = (chunk_t) {
			.ptr = rr.ptr + 1,
			.len = rr.ptr[0]
		};
	} else if (rr.len >= 3 && rr.ptr[0] == 0x00) {
		/*
		 * Exponent length is 0x00 followed by 2 bytes of
		 * length (big-endian), followed by that many exponent
		 * bytes
		 */
		exponent = (chunk_t) {
			.ptr = rr.ptr + 3,
			.len = (rr.ptr[1] << BITS_PER_BYTE) + rr.ptr[2],
		};
	} else {
		/* not even room for length! */
		return "RSA public key resource record way too short";
	}

	/*
	 * Does the exponent fall off the end of the resource record?
	 */
	uint8_t *const exponent_end = exponent.ptr + exponent.len;
	uint8_t *const rr_end = rr.ptr + rr.len;
	if (exponent_end > rr_end) {
		return "truncated RSA public key resource record exponent";
	}

	/*
	 * What is left over forms the modulus.
	 */
	chunk_t modulus = {
		.ptr = exponent_end,
		.len = rr_end - exponent_end,
	};

	if (modulus.len < RSA_MIN_OCTETS_RFC) {
		return "RSA public key resource record modulus too short";
	}
	if (modulus.len < RSA_MIN_OCTETS) {
		return RSA_MIN_OCTETS_UGH;
	}
	if (modulus.len > RSA_MAX_OCTETS) {
		return RSA_MAX_OCTETS_UGH;
	}

	/*
	 * Step 2: all looks good, export the slices
	 */
	*e = exponent;
	*n = modulus;
	return NULL;
}

static err_t unpack_RSA_dnssec_pubkey(struct RSA_public_key *rsa,
				      keyid_t *keyid, ckaid_t *ckaid, size_t *size,
				      chunk_t dnssec_pubkey)
{
	/* unpack */
	chunk_t exponent;
	chunk_t modulus;
	err_t rrerr = pubkey_dnssec_pubkey_to_rsa_pubkey(dnssec_pubkey, &exponent, &modulus);
	if (rrerr != NULL) {
		return rrerr;
	}

	err_t ckerr = form_ckaid_rsa(modulus, ckaid);
	if (ckerr != NULL) {
		return ckerr;
	}

	err_t e = keyblob_to_keyid(dnssec_pubkey.ptr, dnssec_pubkey.len, keyid);
	if (e != NULL) {
		return e;
	}

	*size = modulus.len;
	rsa->e = clone_hunk(exponent, "e");
	rsa->n = clone_hunk(modulus, "n");

	/* generate the CKAID */

	if (DBGP(DBG_BASE)) {
		/* pubkey information isn't DBG_PRIVATE */
		DBG_log("keyid: *%s", str_keyid(*keyid));
		DBG_log("  size: %zu", *size);
		DBG_dump_hunk("  n", rsa->n);
		DBG_dump_hunk("  e", rsa->e);
		DBG_dump_hunk("  CKAID", *ckaid);
	}

	return NULL;
}

static err_t RSA_dnssec_pubkey_to_pubkey_content(chunk_t dnssec_pubkey,
						 union pubkey_content *u,
						 keyid_t *keyid, ckaid_t *ckaid, size_t *size)
{
	return unpack_RSA_dnssec_pubkey(&u->rsa, keyid, ckaid, size, dnssec_pubkey);
}

static void RSA_free_public_content(struct RSA_public_key *rsa)
{
	free_chunk_content(&rsa->n);
	free_chunk_content(&rsa->e);
}

static void RSA_free_pubkey_content(union pubkey_content *u)
{
	RSA_free_public_content(&u->rsa);
}

static void RSA_extract_public_key(struct RSA_public_key *pub,
				   keyid_t *keyid, ckaid_t *ckaid, size_t *size,
				   SECKEYPublicKey *pubk,
				   SECItem *cert_ckaid)
{
	pub->e = clone_bytes_as_chunk(pubk->u.rsa.publicExponent.data,
					   pubk->u.rsa.publicExponent.len, "e");
	pub->n = clone_bytes_as_chunk(pubk->u.rsa.modulus.data,
					   pubk->u.rsa.modulus.len, "n");
	*ckaid = ckaid_from_secitem(cert_ckaid);
	form_keyid(pub->e, pub->n, keyid, size);
}

static void RSA_extract_pubkey_content(union pubkey_content *pkc,
				       keyid_t *keyid, ckaid_t *ckaid, size_t *size,
				       SECKEYPublicKey *pubkey_nss,
				       SECItem *ckaid_nss)
{
	RSA_extract_public_key(&pkc->rsa, keyid, ckaid, size, pubkey_nss, ckaid_nss);
}

static void RSA_extract_private_key_pubkey_content(struct private_key_stuff *pks,
						   keyid_t *keyid, ckaid_t *ckaid, size_t *size,
						   SECKEYPublicKey *pubkey_nss,
						   SECItem *ckaid_nss)
{
	struct RSA_public_key *pubkey = &pks->u.pubkey.rsa;
	RSA_extract_public_key(pubkey, keyid, ckaid, size,
			       pubkey_nss, ckaid_nss);
}

static void RSA_free_secret_content(struct private_key_stuff *pks)
{
	SECKEY_DestroyPrivateKey(pks->private_key);
	struct RSA_public_key *pubkey = &pks->u.pubkey.rsa;
	RSA_free_public_content(pubkey);
}

static err_t RSA_secret_sane(struct private_key_stuff *pks)
{
	/*
	 * PKCS#1 1.5 section 6 requires modulus to have at least 12 octets.
	 *
	 * We actually require more (for security).
	 */
	if (pks->size < RSA_MIN_OCTETS)
		return RSA_MIN_OCTETS_UGH;

	/* we picked a max modulus size to simplify buffer allocation */
	if (pks->size > RSA_MAX_OCTETS)
		return RSA_MAX_OCTETS_UGH;

	return NULL;
}

const struct pubkey_type pubkey_type_rsa = {
	.alg = PUBKEY_ALG_RSA,
	.name = "RSA",
	.private_key_kind = PKK_RSA,
	.free_pubkey_content = RSA_free_pubkey_content,
	.dnssec_pubkey_to_pubkey_content = RSA_dnssec_pubkey_to_pubkey_content,
	.extract_pubkey_content = RSA_extract_pubkey_content,
	.extract_private_key_pubkey_content = RSA_extract_private_key_pubkey_content,
	.free_secret_content = RSA_free_secret_content,
	.secret_sane = RSA_secret_sane,
	.digital_signature_signer = {
		[DIGITAL_SIGNATURE_RSASSA_PSS_BLOB] = &pubkey_signer_rsassa_pss,
		[DIGITAL_SIGNATURE_PKCS1_1_5_RSA_BLOB] = &pubkey_signer_pkcs1_1_5_rsa,
	},
};

/* returns the length of the result on success; 0 on failure */
static struct hash_signature RSA_sign_hash_raw_rsa(const struct private_key_stuff *pks,
						   const uint8_t *hash_val, size_t hash_len,
						   const struct hash_desc *hash_algo,
						   struct logger *logger)
{
	dbg("%s: started using NSS", __func__);

	if (!pexpect(hash_algo == &ike_alg_hash_sha1)) {
		return (struct hash_signature) { .len = 0, };
	}

	if (!pexpect(pks->private_key != NULL)) {
		dbg("no private key!");
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
		llog_nss_error(RC_LOG_SERIOUS, logger,
			       "PK11_Sign() function failed");
		return (struct hash_signature) { .len = 0, };
	}

	dbg("%s: ended using NSS", __func__);
	return sig;
}

/* returns the length of the result on success; 0 on failure */
static struct hash_signature RSA_sign_hash_pkcs1_1_5_rsa(const struct private_key_stuff *pks,
							 const uint8_t *hash_val, size_t hash_len,
							 const struct hash_desc *hash_algo,
							 struct logger *logger)
{
	dbg("%s: started using NSS", __func__);

	if (!pexpect(pks->private_key != NULL)) {
		dbg("no private key!");
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
		enum_buf tb;
		llog_nss_error(RC_LOG_SERIOUS, logger,
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

	dbg("%s: ended using NSS", __func__);
	return signature;
}

static bool RSA_authenticate_signature_raw_rsa(const struct crypt_mac *expected_hash,
					       shunk_t signature,
					       struct pubkey *kr,
					       const struct hash_desc *unused_hash_algo UNUSED,
					       diag_t *fatal_diag,
					       struct logger *logger)
{
	const struct RSA_public_key *k = &kr->u.rsa;

	/* decrypt the signature -- reversing RSA_sign_hash */
	if (signature.len != kr->size) {
		/* XXX notification: INVALID_KEY_INFORMATION */
		*fatal_diag = NULL;
		return false;
	}

	SECStatus retVal;
	if (DBGP(DBG_BASE)) {
		DBG_dump_hunk("NSS RSA: verifying that decrypted signature matches hash: ",
			      *expected_hash);
	}

	/*
	 * Create a public key storing all keying material in an
	 * arena.  The arena's lifetime is tied to and released by the
	 * key.
	 *
	 * Danger:
	 *
	 * Need to use SECKEY_DestroyPublicKey() to release any
	 * allocated memory; not SECITEM_FreeArena(); and not both!
	 *
	 * A look at SECKEY_DestroyPublicKey()'s source shows that it
	 * releases the allocated public key by freeing the arena,
	 * hence only that is needed.
	 */

	PRArenaPool *arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	if (arena == NULL) {
		*fatal_diag = diag_nss_error("allocating RSA arena");
		return false;
	}

	SECKEYPublicKey *publicKey = PORT_ArenaZAlloc(arena, sizeof(SECKEYPublicKey));
	if (publicKey == NULL) {
		*fatal_diag = diag_nss_error("allocating RSA pubkey");
		PORT_FreeArena(arena, PR_FALSE);
		return false;
	}

	publicKey->arena = arena;
	publicKey->keyType = rsaKey;
	publicKey->pkcs11Slot = NULL;
	publicKey->pkcs11ID = CK_INVALID_HANDLE;

	/*
	 * Convert n and e to form the public key in the
	 * SECKEYPublicKey data structure
	 */

	const SECItem nss_n = same_chunk_as_secitem(k->n, siBuffer);
	retVal = SECITEM_CopyItem(publicKey->arena, &publicKey->u.rsa.modulus, &nss_n);
	if (retVal != SECSuccess) {
		llog_nss_error(RC_LOG, logger, "copying 'n' (modulus) to RSA public key");
		SECKEY_DestroyPublicKey(publicKey);
		return false;
	}

	const SECItem nss_e = same_chunk_as_secitem(k->e, siBuffer);
	retVal = SECITEM_CopyItem(publicKey->arena, &publicKey->u.rsa.publicExponent, &nss_e);
	if (retVal != SECSuccess) {
		llog_nss_error(RC_LOG, logger, "copying 'e' (exponent) to RSA public key");
		SECKEY_DestroyPublicKey(publicKey);
		return false;
	}

	/*
	 * Convert the signature into raw form (NSS doesn't do const).
	 */

	const SECItem encrypted_signature = {
		.type = siBuffer,
		.data = DISCARD_CONST(unsigned char *, signature.ptr),
		.len  = signature.len,
	};

	SECItem decrypted_signature = {
		.type = siBuffer,
	};
	if (SECITEM_AllocItem(publicKey->arena, &decrypted_signature,
			      signature.len) == NULL) {
		llog_nss_error(RC_LOG, logger, "allocating space for decrypted RSA signature");
		SECKEY_DestroyPublicKey(publicKey);
		return false;
	}

	if (PK11_VerifyRecover(publicKey, &encrypted_signature, &decrypted_signature,
			       lsw_nss_get_password_context(logger)) != SECSuccess) {
		dbg("NSS RSA verify: decrypting signature is failed");
		SECKEY_DestroyPublicKey(publicKey);
		*fatal_diag = NULL;
		return false;
	}

	if (DBGP(DBG_CRYPT)) {
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
		dbg("RSA Signature NOT verified");
		SECKEY_DestroyPublicKey(publicKey);
		*fatal_diag = NULL;
		return false;
	}

	SECKEY_DestroyPublicKey(publicKey);
	*fatal_diag = NULL;
	return true;
}

const struct pubkey_signer pubkey_signer_raw_rsa = {
	.name = "RSA",
	.digital_signature_blob = DIGITAL_SIGNATURE_BLOB_ROOF,
	.type = &pubkey_type_rsa,
	.sign_hash = RSA_sign_hash_raw_rsa,
	.authenticate_signature = RSA_authenticate_signature_raw_rsa,
};

const struct pubkey_signer pubkey_signer_pkcs1_1_5_rsa = {
	.name = "PKCS#1 1.5 RSA", /* name from RFC 7427 */
	.digital_signature_blob = DIGITAL_SIGNATURE_PKCS1_1_5_RSA_BLOB,
	.type = &pubkey_type_rsa,
	.sign_hash = RSA_sign_hash_pkcs1_1_5_rsa,
	.authenticate_signature = RSA_authenticate_signature_raw_rsa,
};

/* returns the length of the result on success; 0 on failure */
static struct hash_signature RSA_sign_hash_rsassa_pss(const struct private_key_stuff *pks,
						      const uint8_t *hash_val, size_t hash_len,
						      const struct hash_desc *hash_algo,
						      struct logger *logger)
{
	dbg("%s: started using NSS", __func__);

	if (!pexpect(pks->private_key != NULL)) {
		dbg("no private key!");
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
		llog(RC_LOG_SERIOUS, logger,
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
		llog_nss_error(RC_LOG_SERIOUS, logger,
			       "RSA DSS sign function failed");
		return (struct hash_signature) { .len = 0, };
	}

	dbg("%s: ended using NSS", __func__);
	return sig;
}

static bool RSA_authenticate_signature_rsassa_pss(const struct crypt_mac *expected_hash,
						  shunk_t signature,
						  struct pubkey *kr,
						  const struct hash_desc *hash_algo,
						  diag_t *fatal_diag,
						  struct logger *logger)
{
	const struct RSA_public_key *k = &kr->u.rsa;

	/* decrypt the signature -- reversing RSA_sign_hash */
	if (signature.len != kr->size) {
		/* XXX notification: INVALID_KEY_INFORMATION */
		*fatal_diag = NULL;
		return false;
	}

	SECStatus retVal;
	if (DBGP(DBG_BASE)) {
		DBG_dump_hunk("NSS RSA: verifying that decrypted signature matches hash: ",
			      *expected_hash);
	}

	/*
	 * Create a public key storing all keying material in an
	 * arena.  The arena's lifetime is tied to and released by the
	 * key.
	 *
	 * Danger:
	 *
	 * Need to use SECKEY_DestroyPublicKey() to release any
	 * allocated memory; not SECITEM_FreeArena(); and not both!
	 *
	 * A look at SECKEY_DestroyPublicKey()'s source shows that it
	 * releases the allocated public key by freeing the arena,
	 * hence only that is needed.
	 */

	PRArenaPool *arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	if (arena == NULL) {
		*fatal_diag = diag_nss_error("allocating RSA arena");
		return false;
	}

	SECKEYPublicKey *publicKey = PORT_ArenaZAlloc(arena, sizeof(SECKEYPublicKey));
	if (publicKey == NULL) {
		*fatal_diag = diag_nss_error("allocating RSA pubkey");
		PORT_FreeArena(arena, PR_FALSE);
		return false;
	}

	publicKey->arena = arena;
	publicKey->keyType = rsaKey;
	publicKey->pkcs11Slot = NULL;
	publicKey->pkcs11ID = CK_INVALID_HANDLE;

	/*
	 * Convert n and e to form the public key in the
	 * SECKEYPublicKey data structure
	 */

	const SECItem nss_n = same_chunk_as_secitem(k->n, siBuffer);
	retVal = SECITEM_CopyItem(publicKey->arena, &publicKey->u.rsa.modulus, &nss_n);
	if (retVal != SECSuccess) {
		llog_nss_error(RC_LOG, logger, "copying 'n' (modulus) to RSA public key");
		SECKEY_DestroyPublicKey(publicKey);
		return false;
	}

	const SECItem nss_e = same_chunk_as_secitem(k->e, siBuffer);
	retVal = SECITEM_CopyItem(publicKey->arena, &publicKey->u.rsa.publicExponent, &nss_e);
	if (retVal != SECSuccess) {
		llog_nss_error(RC_LOG, logger, "copying 'e' (exponent) to RSA public key");
		SECKEY_DestroyPublicKey(publicKey);
		return false;
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
		dbg("NSS RSA verify: hash algorithm not supported");
		SECKEY_DestroyPublicKey(publicKey);
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

	if (PK11_VerifyWithMechanism(publicKey, CKM_RSA_PKCS_PSS,
				     &hash_mech_item, &encrypted_signature,
				     &expected_hash_item,
				     lsw_nss_get_password_context(logger)) != SECSuccess) {
		dbg("NSS RSA verify: decrypting signature is failed");
		SECKEY_DestroyPublicKey(publicKey);
		*fatal_diag = NULL;
		return false;
	}

	SECKEY_DestroyPublicKey(publicKey);
	*fatal_diag = NULL;
	return true;
}

const struct pubkey_signer pubkey_signer_rsassa_pss = {
	.name = "RSASSA-PSS", /* name from RFC 7427 */
	.type = &pubkey_type_rsa,
	.digital_signature_blob = DIGITAL_SIGNATURE_RSASSA_PSS_BLOB,
	.sign_hash = RSA_sign_hash_rsassa_pss,
	.authenticate_signature = RSA_authenticate_signature_rsassa_pss,
};
