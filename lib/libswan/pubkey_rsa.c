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
 * Deal with RFC Resource Records as defined in rfc3110 (nee rfc2537).
 */

static err_t RSA_pubkey_content_to_ipseckey_rdata(const struct pubkey_content *pkc,
						  chunk_t *ipseckey_pubkey,
						  enum ipseckey_algorithm_type *ipseckey_algorithm)
{
	SECKEYRSAPublicKey *rsa = &pkc->public_key->u.rsa;
	chunk_t exponent = same_secitem_as_chunk(rsa->publicExponent);
	chunk_t modulus = same_secitem_as_chunk(rsa->modulus);
	*ipseckey_pubkey = EMPTY_CHUNK;
	*ipseckey_algorithm = 0;

	/*
	 * Since exponent length field is either 1 or 3 bytes in size,
	 * just allocate 3 extra bytes.
	 */
	size_t rrlen = exponent.len + modulus.len + 3;
	uint8_t *buf = alloc_bytes(rrlen, "buffer for rfc3110");
	uint8_t *p = buf;

	if (exponent.len <= 255) {
		*p++ = exponent.len;
	} else if (exponent.len <= 0xffff) {
		*p++ = 0;
		*p++ = (exponent.len >> 8) & 0xff;
		*p++ = exponent.len & 0xff;
	} else {
		pfree(buf);
		return "RSA public key exponent too long for resource record";
	}

	memcpy(p, exponent.ptr, exponent.len);
	p += exponent.len;
	memcpy(p, modulus.ptr, modulus.len);
	p += modulus.len;

	*ipseckey_algorithm = IPSECKEY_ALGORITHM_RSA;
	*ipseckey_pubkey = (chunk_t) {
		.ptr = buf,
		.len = p - buf,
	};

	return NULL;
}

/*
 * Note: e and n will point int rr.
 *
 * See https://www.rfc-editor.org/rfc/rfc3110#section-2
 */
static diag_t pubkey_ipseckey_rdata_to_rsa_pubkey(shunk_t rr, shunk_t *e, shunk_t *n)
{
	*e = null_shunk;
	*n = null_shunk;

	/*
	 * Step 1: find the bounds of the exponent and modulus within
	 * the resource record and verify that they are sane.
	 *
	 * XXX: this isn't an ASN.1 encoded length so what is it?
	 */

	shunk_t exponent = null_shunk;
	const uint8_t *const rr_ptr = rr.ptr;
	if (rr.len >= 2 && rr_ptr[0] != 0x00) {
		/*
		 * Exponent length is one-byte, followed by that many
		 * exponent bytes
		 */
		exponent = shunk2(rr_ptr + 1, rr_ptr[0]);
	} else if (rr.len >= 3 && rr_ptr[0] == 0x00) {
		/*
		 * Exponent length is 0x00 followed by 2 bytes of
		 * length (big-endian), followed by that many exponent
		 * bytes
		 */
		exponent = shunk2(rr_ptr + 3, (rr_ptr[1] << BITS_IN_BYTE) + rr_ptr[2]);
	} else {
		/* not even room for length! */
		return diag("%zu byte raw RSA public is way too short",
			    rr.len);
	}

	/*
	 * Does the exponent fall off the end of the resource record?
	 */
	const uint8_t *const exponent_end = exponent.ptr + exponent.len;
	const uint8_t *const rr_end = rr_ptr + rr.len;
	if (exponent_end > rr_end) {
		return diag("%zu byte raw RSA public key is too short for exponent of length %zu",
			    rr.len, exponent.len);
	}

	/*
	 * What is left over forms the modulus.
	 *
	 * XXX: This overlaps RSA_secret_sane.
	 */
	shunk_t modulus = shunk2(exponent_end, rr_end - exponent_end);

	if (modulus.len < RSA_MIN_OCTETS_RFC) {
		return diag("%zu byte raw RSA public key %zu byte modulus is shorter than RFC minimum %d",
			    rr.len, modulus.len, RSA_MIN_OCTETS_RFC);
	}
	if (modulus.len < RSA_MIN_OCTETS) {
		return diag("%zu byte raw RSA public key %zu byte modulus is shorter than minimum %d",
			    rr.len, modulus.len, RSA_MIN_OCTETS);
	}
	struct hash_signature scratch_signature;
	size_t max_hash_size = sizeof(scratch_signature.ptr/*array*/);
	if (modulus.len > max_hash_size) {
		return diag("%zu byte raw RSA public key %zu byte modulus is longer than maximum %zu",
			    rr.len, modulus.len, max_hash_size);
	}

	/*
	 * Step 2: all looks good, export the slices
	 */
	*e = exponent;
	*n = modulus;
	return NULL;
}

static diag_t RSA_ipseckey_rdata_to_pubkey_content(shunk_t ipseckey_pubkey,
						   struct pubkey_content *pkc)
{
	/* unpack */
	shunk_t exponent;
	shunk_t modulus;
	diag_t d = pubkey_ipseckey_rdata_to_rsa_pubkey(ipseckey_pubkey, &exponent, &modulus);
	if (d != NULL) {
		return d;
	}

	/*
	 * Allocate the public key, giving it its own arena.
	 *
	 * Since the arena contains everything allocated to the
	 * seckey, error recovery just requires freeing that.
	 */

	PRArenaPool *arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	if (arena == NULL) {
		return diag_nss_error("allocating RSA arena");
	}

	SECKEYPublicKey *seckey = PORT_ArenaZNew(arena, SECKEYPublicKey);
	if (seckey == NULL) {
		diag_t d = diag_nss_error("allocating RSA SECKEYPublicKey");
		PORT_FreeArena(arena, /*zero?*/PR_TRUE);
		return d;
	}

	seckey->arena = arena;
	seckey->keyType = rsaKey;
	seckey->pkcs11Slot = NULL;
	seckey->pkcs11ID = CK_INVALID_HANDLE;
	SECKEYRSAPublicKey *rsa = &seckey->u.rsa;

	/*
	 * Copy n and e to form the public key in the SECKEYPublicKey
	 * data structure
	 */

	if (SECITEM_MakeItem(arena, &rsa->modulus, modulus.ptr, modulus.len) != SECSuccess) {
		diag_t d = diag_nss_error("copying 'n' (modulus) to RSA SECKEYPublicKey");
		PORT_FreeArena(arena, /*zero?*/PR_TRUE);
		return d;
	}

	if (SECITEM_MakeItem(arena, &rsa->publicExponent, exponent.ptr, exponent.len) != SECSuccess) {
		diag_t d = diag_nss_error("copying 'e' (exponent) to RSA public key");
		PORT_FreeArena(arena, /*zero?*/PR_TRUE);
		return d;
	}

	/* ckaid */
	SECItem *nss_ckaid = PK11_MakeIDFromPubKey(&rsa->modulus);
	if (nss_ckaid == NULL) {
		diag_t d = diag_nss_error("unable to compute 'CKAID' from modulus");
		PORT_FreeArena(arena, /*zero?*/PR_TRUE);
		return d;
	}
	if (DBGP(DBG_BASE)) {
		DBG_dump("computed rsa CKAID",
			 nss_ckaid->data, nss_ckaid->len);
	}
	pkc->ckaid = ckaid_from_secitem(nss_ckaid);
	SECITEM_FreeItem(nss_ckaid, PR_TRUE);

	err_t kberr = keyblob_to_keyid(ipseckey_pubkey.ptr, ipseckey_pubkey.len, &pkc->keyid);
	if (kberr != NULL) {
		diag_t d = diag("%s", kberr);
		PORT_FreeArena(arena, /*zero?*/PR_TRUE);
		return d;
	}

	pkc->type = &pubkey_type_rsa;
	pkc->public_key = seckey;
	dbg_alloc("rsa->public_key", pkc->public_key, HERE);

	/* generate the CKAID */

	if (DBGP(DBG_BASE)) {
		/* pubkey information isn't DBG_PRIVATE */
		DBG_log("keyid: *%s", str_keyid(pkc->keyid));
		DBG_dump_hunk("  n", modulus);
		DBG_dump_hunk("  e", exponent);
		DBG_dump_hunk("  CKAID", pkc->ckaid);
	}

	return NULL;
}

static void RSA_free_pubkey_content(struct pubkey_content *rsa)
{
	SECKEY_DestroyPublicKey(rsa->public_key);
	dbg_free("rsa->public_key", rsa->public_key, HERE);
	rsa->public_key = NULL;
}

static err_t RSA_extract_pubkey_content(struct pubkey_content *pkc,
					SECKEYPublicKey *seckey_public,
					SECItem *cert_ckaid)
{
	chunk_t exponent = same_secitem_as_chunk(seckey_public->u.rsa.publicExponent);
	chunk_t modulus = same_secitem_as_chunk(seckey_public->u.rsa.modulus);
	size_t size;
	form_keyid(exponent, modulus, &pkc->keyid, &size);
	/* up to this point nothing has been allocated */

	/*
	 * PKCS#1 1.5 section 6 requires modulus to have at least 12
	 * octets.
	 *
	 * We actually require more (for security).
	 */
	if (size < RSA_MIN_OCTETS)
		return RSA_MIN_OCTETS_UGH;
	/*
	 * We picked a max modulus size to simplify buffer allocation.
	 */
	struct hash_signature scratch_signature;
	size_t max_hash_size = sizeof(scratch_signature.ptr/*array*/);
	if (modulus.len > max_hash_size) {
		return "RSA modulus too large for signature buffer";
	}

	/* now allocate */
	pkc->type = &pubkey_type_rsa;
	pkc->public_key = SECKEY_CopyPublicKey(seckey_public);
	dbg_alloc("rsa->public_key", pkc->public_key, HERE);
	pkc->ckaid = ckaid_from_secitem(cert_ckaid);
	return NULL;
}

static bool RSA_pubkey_same(const struct pubkey_content *lhs,
			    const struct pubkey_content *rhs)
{
	/*
	 * The "adjusted" length of modulus n in octets:
	 * [RSA_MIN_OCTETS, RSA_MAX_OCTETS].
	 *
	 * According to form_keyid() this is the modulus length less
	 * any leading byte added by DER encoding.
	 *
	 * The adjusted length is used in sign_hash() as the signature
	 * length - wouldn't PK11_SignatureLen be better?
	 *
	 * The adjusted length is used in same_RSA_public_key() as
	 * part of comparing two keys - but wouldn't that be
	 * redundant?  The direct n==n test would pick up the
	 * difference.
	 */
	bool e = hunk_eq(same_secitem_as_shunk(lhs->public_key->u.rsa.publicExponent),
			 same_secitem_as_shunk(rhs->public_key->u.rsa.publicExponent));
	bool n = hunk_eq(same_secitem_as_shunk(lhs->public_key->u.rsa.modulus),
			 same_secitem_as_shunk(rhs->public_key->u.rsa.modulus));
	if (DBGP(DBG_CRYPT)) {
		DBG_log("n did %smatch", n ? "" : "NOT ");
		DBG_log("e did %smatch", e ? "" : "NOT ");
	}

	return lhs == rhs || (e && n);
}

static size_t RSA_strength_in_bits(const struct pubkey *pubkey)
{
	return SECKEY_PublicKeyStrengthInBits(pubkey->content.public_key);
}

const struct pubkey_type pubkey_type_rsa = {
	.name = "RSA",
	.private_key_kind = SECRET_RSA, /* XXX: delete field */
	.free_pubkey_content = RSA_free_pubkey_content,
	.ipseckey_rdata_to_pubkey_content = RSA_ipseckey_rdata_to_pubkey_content,
	.pubkey_content_to_ipseckey_rdata = RSA_pubkey_content_to_ipseckey_rdata,
	.extract_pubkey_content = RSA_extract_pubkey_content,
	.pubkey_same = RSA_pubkey_same,
	.strength_in_bits = RSA_strength_in_bits,
};

/* returns the length of the result on success; 0 on failure */
static struct hash_signature RSA_raw_sign_hash(const struct secret_stuff *pks,
					       const uint8_t *hash_val, size_t hash_len,
					       const struct hash_desc *hash_algo,
					       struct logger *logger)
{
	dbg("%s: started using NSS", __func__);

	if (!pexpect(hash_algo == &ike_alg_hash_sha1)) {
		return (struct hash_signature) { .len = 0, };
	}

	if (!pexpect(pks->u.pubkey.private_key != NULL)) {
		dbg("no private key!");
		return (struct hash_signature) { .len = 0, };
	}

	SECItem data = {
		.type = siBuffer,
		.len = hash_len,
		.data = DISCARD_CONST(uint8_t *, hash_val),
	};

	struct hash_signature sig = { .len = PK11_SignatureLen(pks->u.pubkey.private_key), };
	passert(sig.len <= sizeof(sig.ptr/*array*/));
	SECItem signature = {
		.type = siBuffer,
		.len = sig.len,
		.data = sig.ptr,
	};

	SECStatus s = PK11_Sign(pks->u.pubkey.private_key, &signature, &data);
	if (s != SECSuccess) {
		/* PR_GetError() returns the thread-local error */
		llog_nss_error(RC_LOG, logger,
			       "PK11_Sign() function failed");
		return (struct hash_signature) { .len = 0, };
	}

	dbg("%s: ended using NSS", __func__);
	return sig;
}

static bool RSA_authenticate_signature_raw_rsa(const struct crypt_mac *expected_hash,
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

	if (DBGP(DBG_BASE)) {
		DBG_dump_hunk("NSS RSA: verifying that decrypted signature matches hash: ",
			      *expected_hash);
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
		dbg("NSS RSA verify: decrypting signature is failed");
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
	.sign_hash = RSA_raw_sign_hash,
	.authenticate_signature = RSA_authenticate_signature_raw_rsa,
	.jam_auth_method = RSA_jam_auth_method,
};

/* returns the length of the result on success; 0 on failure */
static struct hash_signature RSA_pkcs1_1_5_sign_hash(const struct secret_stuff *pks,
						     const uint8_t *hash_val, size_t hash_len,
						     const struct hash_desc *hash_algo,
						     struct logger *logger)
{
	dbg("%s: started using NSS", __func__);

	if (!pexpect(pks->u.pubkey.private_key != NULL)) {
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
	SECStatus s = SGN_Digest(pks->u.pubkey.private_key,
				 hash_algo->nss.oid_tag,
				 &signature_result, &digest);
	if (s != SECSuccess) {
		/* PR_GetError() returns the thread-local error */
		enum_buf tb;
		llog_nss_error(RC_LOG, logger,
			       "SGN_Digest(%s) function failed",
			       str_nss_oid(hash_algo->nss.oid_tag, &tb));
		return (struct hash_signature) { .len = 0, };
	}

	/* save the signature, free the returned pointer */

	struct hash_signature signature = {
		.len = PK11_SignatureLen(pks->u.pubkey.private_key),
	};
	passert(signature.len <= sizeof(signature.ptr/*array*/));
	memcpy(signature.ptr, signature_result.data, signature.len);
	PORT_Free(signature_result.data);

	dbg("%s: ended using NSS", __func__);
	return signature;
}

static bool RSA_authenticate_signature_pkcs1_1_5_rsa(const struct crypt_mac *expected_hash,
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

	if (DBGP(DBG_BASE)) {
		DBG_dump_hunk("NSS RSA: verifying that decrypted signature matches hash: ",
			      *expected_hash);
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
		dbg("NSS RSA verify: decrypting signature is failed");
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
	.sign_hash = RSA_pkcs1_1_5_sign_hash,
	.authenticate_signature = RSA_authenticate_signature_pkcs1_1_5_rsa,
	.jam_auth_method = RSA_jam_auth_method,
};

const struct pubkey_signer pubkey_signer_digsig_pkcs1_1_5_rsa = {
	.name = "PKCS#1 1.5 RSA", /* name from RFC 7427 */
	.digital_signature_blob = DIGITAL_SIGNATURE_PKCS1_1_5_RSA_BLOB,
	.type = &pubkey_type_rsa,
	.sign_hash = RSA_pkcs1_1_5_sign_hash,
	.authenticate_signature = RSA_authenticate_signature_pkcs1_1_5_rsa,
	.jam_auth_method = RSA_jam_auth_method,
};

/* returns the length of the result on success; 0 on failure */
static struct hash_signature RSA_rsassa_pss_sign_hash(const struct secret_stuff *pks,
						      const uint8_t *hash_val, size_t hash_len,
						      const struct hash_desc *hash_algo,
						      struct logger *logger)
{
	dbg("%s: started using NSS", __func__);

	if (!pexpect(pks->u.pubkey.private_key != NULL)) {
		dbg("no private key!");
		return (struct hash_signature) { .len = 0, };
	}

	SECItem data = {
		.type = siBuffer,
		.len = hash_len,
		.data = DISCARD_CONST(uint8_t *, hash_val),
	};

	struct hash_signature sig = { .len = PK11_SignatureLen(pks->u.pubkey.private_key), };
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
	SECStatus s = PK11_SignWithMechanism(pks->u.pubkey.private_key, CKM_RSA_PKCS_PSS,
					     &mech_item, &signature, &data);
	if (s != SECSuccess) {
		/* PR_GetError() returns the thread-local error */
		llog_nss_error(RC_LOG, logger,
			       "RSA DSS sign function failed");
		return (struct hash_signature) { .len = 0, };
	}

	dbg("%s: ended using NSS", __func__);
	return sig;
}

static bool RSA_authenticate_signature_rsassa_pss(const struct crypt_mac *expected_hash,
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

	if (DBGP(DBG_BASE)) {
		DBG_dump_hunk("NSS RSA: verifying that decrypted signature matches hash: ",
			      *expected_hash);
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
		dbg("NSS RSA verify: decrypting signature is failed");
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
	.sign_hash = RSA_rsassa_pss_sign_hash,
	.authenticate_signature = RSA_authenticate_signature_rsassa_pss,
	.jam_auth_method = RSA_jam_auth_method,
};
