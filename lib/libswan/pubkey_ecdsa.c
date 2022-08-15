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

#include <pk11pub.h>
#include <cryptohi.h>
#include <keyhi.h>
/*
 * In addition to EC_POINT_FORM_UNCOMPRESSED, <blapit.h> defines
 * things like AES_BLOCK_SIZE which conflicts with "ietf_constants.h".
 */
#if 0
#include <blapit.h>
#else
#define EC_POINT_FORM_UNCOMPRESSED 0x04
#endif

#include "lswnss.h"
#include "lswlog.h"
#include "secrets.h"
#include "ike_alg_dh.h"		/* for OID and size of EC algorithms */
#include "refcnt.h"		/* for dbg_{alloc,free}() */

static diag_t ECDSA_ipseckey_rdata_to_pubkey_content(const shunk_t ipseckey_pubkey,
						    struct ECDSA_public_key *ecdsa,
						    keyid_t *keyid, ckaid_t *ckaid, size_t *size)
{
	static const struct dh_desc *dh[] = {
		&ike_alg_dh_secp256r1,
		&ike_alg_dh_secp384r1,
		&ike_alg_dh_secp521r1,
	};

	/*
	 * Look for an EC curve with the same length as
	 * ipseckey_pubkey.
	 *
	 * Raw EC pubkeys contain the EC point (or points).
	 */

	const struct dh_desc *group = NULL;
	shunk_t raw = null_shunk;
	const uint8_t *const ipseckey_pubkey_ptr = ipseckey_pubkey.ptr;
	FOR_EACH_ELEMENT(e, dh) {
		/*
		 * A simple match, the buffer cnotains just the key.
		 */
		if (ipseckey_pubkey.len == (*e)->bytes) {
			raw = HUNK_AS_SHUNK(ipseckey_pubkey);
			group = (*e);
			break;
		}
		/*
		 * The raw IPSECKEY_PUBKEY, which could come from the
		 * internet or a config file, can include the
		 * EC_POINT_FORM_UNCOMPRESSED prefix.
		 *
		 * Allow for and strip that off when necessary.
		 */
		if (group->nss_adds_ec_point_form_uncompressed &&
		    ipseckey_pubkey.len == (*e)->bytes + 1 &&
		    ipseckey_pubkey_ptr[0] == EC_POINT_FORM_UNCOMPRESSED) {
			/* ignore prefix */
			raw = shunk2(ipseckey_pubkey_ptr + 1, ipseckey_pubkey.len - 1);
			group = (*e);
			break;
		}
	}
	if (group == NULL) {
		return diag("unrecognized EC Public Key with length %zu", ipseckey_pubkey.len);
	}

	passert(raw.ptr != NULL && raw.len > 0);

	/*
	 * Allocate the public key, giving it its own NSS arena.
	 *
	 * Since the arena contains everything allocated to the
	 * seckey, error recovery just requires freeing that.
	 */

	PRArenaPool *arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	if (arena == NULL) {
		return diag_nss_error("allocating ECDSA arena");
	}

	SECKEYPublicKey *seckey = PORT_ArenaZNew(arena, SECKEYPublicKey);
	if (seckey == NULL) {
		diag_t d = diag_nss_error("allocating ECDSA SECKEYPublicKey");
		PORT_FreeArena(arena, /*zero?*/PR_TRUE);
		return d;
	}

	seckey->arena = arena;
	seckey->keyType = ecKey;
	seckey->pkcs11Slot = NULL;
	seckey->pkcs11ID = CK_INVALID_HANDLE;
	SECKEYECPublicKey *ec = &seckey->u.ec;

	/*
	 * Copy the RAW EC point(s) into the arena, adding them to the
	 * public key.
	 */

	if (SECITEM_AllocItem(arena, &ec->publicValue, raw.len + 1) == NULL) {
		diag_t d = diag_nss_error("copying 'k' to EDSA public key");
		PORT_FreeArena(arena, /*zero?*/PR_TRUE);
		return d;
	}
	ec->publicValue.data[0] = EC_POINT_FORM_UNCOMPRESSED;
	memcpy(ec->publicValue.data + 1, raw.ptr, raw.len);

	/*
	 * Copy the OID (wrapped in ASN.1 ObjectID template) into the
	 * arena, adding it to the public key.
	 *
	 * See also DH code.
	 */
	const SECOidData *ec_oid = SECOID_FindOIDByTag(group->nss_oid); /*static*/
	if (ec_oid == NULL) {
		diag_t d = diag_nss_error("lookup of EC OID failed");
		PORT_FreeArena(arena, /*zero?*/PR_TRUE);
		return d;
	}

	if (SEC_ASN1EncodeItem(arena, &ec->DEREncodedParams,
			       &ec_oid->oid, SEC_ObjectIDTemplate) == NULL) {
		diag_t d = diag_nss_error("ASN.1 encoding of EC OID failed");
		PORT_FreeArena(arena, /*zero?*/PR_TRUE);
		return d;
	}

	/*
	 * Maintain magic values.
	 */

	/* should this include EC? */
	SECItem *nss_ckaid = PK11_MakeIDFromPubKey(&ec->publicValue);
	if (nss_ckaid == NULL) {
		diag_t d = diag_nss_error("unable to compute 'CKAID' from public value");
		PORT_FreeArena(arena, /*zero?*/PR_TRUE);
		return d;
	}
	*ckaid = ckaid_from_secitem(nss_ckaid);
	SECITEM_FreeItem(nss_ckaid, PR_TRUE);

	/*
	 * Use the ckaid since that digested the entire pubkey (this
	 * is made up)
	 */
	err_t e = keyblob_to_keyid(ckaid->ptr, ckaid->len, keyid);
	if (e != NULL) {
		diag_t d = diag("%s", e);
		PORT_FreeArena(arena, /*zero?*/PR_TRUE);
		return d;
	}

	ecdsa->seckey_public = seckey;
	dbg_alloc("ecdsa->seckey_public", seckey, HERE);

	*size = ec->publicValue.len;

	if (DBGP(DBG_BASE)) {
		/* pubkey information isn't DBG_PRIVATE */
		DBG_log("ECDSA Key:");
		DBG_log("keyid: *%s", str_keyid(*keyid));
		DBG_log("  size: %zu", *size);
		DBG_dump("pub", ec->publicValue.data, ec->publicValue.len);
		DBG_dump_hunk("CKAID", *ckaid);
	}

	return NULL;
}

static diag_t ipseckey_rdata_to_pubkey_content(shunk_t ipseckey_pubkey,
					      union pubkey_content *u,
					      keyid_t *keyid, ckaid_t *ckaid, size_t *size)
{
	return ECDSA_ipseckey_rdata_to_pubkey_content(ipseckey_pubkey, &u->ecdsa, keyid, ckaid, size);
}

static err_t ECDSA_pubkey_content_to_ipseckey_rdata(const struct ECDSA_public_key *ecdsa,
						    chunk_t *ipseckey_pubkey,
						    enum ipseckey_algorithm_type *ipseckey_algorithm)
{
	const SECKEYECPublicKey *ec = &ecdsa->seckey_public->u.ec;
	passert((ec->publicValue.len & 1) == 1);
	passert(ec->publicValue.data[0] == EC_POINT_FORM_UNCOMPRESSED);
	*ipseckey_pubkey = clone_bytes_as_chunk(ec->publicValue.data + 1, ec->publicValue.len - 1, "EC POINTS (even)");
	*ipseckey_algorithm = IPSECKEY_ALGORITHM_ECDSA;
	return NULL;
}

static err_t pubkey_content_to_ipseckey_rdata(const union pubkey_content *u,
					      chunk_t *ipseckey_pubkey,
					      enum ipseckey_algorithm_type *ipseckey_algorithm)
{
	return ECDSA_pubkey_content_to_ipseckey_rdata(&u->ecdsa, ipseckey_pubkey, ipseckey_algorithm);
}

static void ECDSA_free_pubkey_content(struct ECDSA_public_key *ecdsa)
{
	dbg_free("ecdsa->seckey_public", ecdsa->seckey_public, HERE);
	SECKEY_DestroyPublicKey(ecdsa->seckey_public);
	ecdsa->seckey_public = NULL;
}

static void free_pubkey_content(union pubkey_content *u)
{
	ECDSA_free_pubkey_content(&u->ecdsa);
}

static void ECDSA_extract_pubkey_content(struct ECDSA_public_key *ecdsa,
					 keyid_t *keyid, ckaid_t *ckaid, size_t *size,
					 SECKEYPublicKey *seckey_public,
					 SECItem *ckaid_nss)
{
	ecdsa->seckey_public = SECKEY_CopyPublicKey(seckey_public);
	SECKEYECPublicKey *ec = &ecdsa->seckey_public->u.ec;
	dbg_alloc("ecdsa->seckey_public", ecdsa->seckey_public, HERE);
	*size = ec->publicValue.len;
	*ckaid = ckaid_from_secitem(ckaid_nss);
	/* keyid; make this up */
	err_t e = keyblob_to_keyid(ckaid->ptr, ckaid->len, keyid);
	passert(e == NULL);

	if (DBGP(DBG_BASE)) {
		ckaid_buf cb;
		DBG_log("ECDSA keyid *%s", str_keyid(*keyid));
		DBG_log("ECDSA keyid *%s", str_ckaid(ckaid, &cb));
		DBG_log("ECDSA size: %zu", *size);
	}
}

static void extract_pubkey_content(union pubkey_content *pkc,
				   keyid_t *keyid, ckaid_t *ckaid, size_t *size,
				   SECKEYPublicKey *seckey_public,
				   SECItem *ckaid_nss)
{
	ECDSA_extract_pubkey_content(&pkc->ecdsa, keyid, ckaid, size, seckey_public, ckaid_nss);
}

static void ECDSA_extract_private_key_pubkey_content(struct private_key_stuff *pks,
						     keyid_t *keyid, ckaid_t *ckaid, size_t *size,
						     SECKEYPublicKey *seckey_public,
						     SECItem *ckaid_nss)
{
	struct ECDSA_public_key *pubkey = &pks->u.pubkey.ecdsa;
	ECDSA_extract_pubkey_content(pubkey, keyid, ckaid, size,
				     seckey_public, ckaid_nss);
}

static void ECDSA_free_secret_content(struct private_key_stuff *pks)
{
	SECKEY_DestroyPrivateKey(pks->private_key);
	struct ECDSA_public_key *pubkey = &pks->u.pubkey.ecdsa;
	ECDSA_free_pubkey_content(pubkey);
}

/*
 * The only unsafe (according to FIPS) curve is p192, and NSS does not
 * implement this, so there is no ECDSA curve that libreswan needs to
 * disallow for security reasons
 */
static err_t ECDSA_secret_sane(struct private_key_stuff *pks_unused UNUSED)
{
	dbg("ECDSA is assumed to be sane");
	return NULL;
}

static bool ECDSA_pubkey_same(const union pubkey_content *lhs,
			    const union pubkey_content *rhs)
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
	bool e = hunk_eq(same_secitem_as_shunk(lhs->ecdsa.seckey_public->u.ec.publicValue),
			 same_secitem_as_shunk(rhs->ecdsa.seckey_public->u.ec.publicValue));
	if (DBGP(DBG_CRYPT)) {
		DBG_log("e did %smatch", e ? "" : "NOT ");
	}

	return lhs == rhs || e;
}

const struct pubkey_type pubkey_type_ecdsa = {
	.name = "ECDSA",
	.private_key_kind = PKK_ECDSA,
	.ipseckey_rdata_to_pubkey_content = ipseckey_rdata_to_pubkey_content,
	.pubkey_content_to_ipseckey_rdata = pubkey_content_to_ipseckey_rdata,
	.free_pubkey_content = free_pubkey_content,
	.extract_private_key_pubkey_content = ECDSA_extract_private_key_pubkey_content,
	.free_secret_content = ECDSA_free_secret_content,
	.secret_sane = ECDSA_secret_sane,
	.extract_pubkey_content = extract_pubkey_content,
	.pubkey_same = ECDSA_pubkey_same,
};

static struct hash_signature ECDSA_raw_sign_hash(const struct private_key_stuff *pks,
						 const uint8_t *hash_val, size_t hash_len,
						 const struct hash_desc *hash_algo_unused UNUSED,
						 struct logger *logger)
{
	DBGF(DBG_CRYPT, "%s: started using NSS", __func__);

	if (!pexpect(pks->private_key != NULL)) {
		dbg("no private key!");
		return (struct hash_signature) { .len = 0, };
	}


	/* point HASH to sign at HASH_VAL */
	SECItem hash_to_sign = {
		.type = siBuffer,
		.len = hash_len,
		.data = DISCARD_CONST(uint8_t *, hash_val),
	};

	/* point signature at the SIG_VAL buffer */
	struct hash_signature signature = {0};
	SECItem raw_signature = {
		.type = siBuffer,
		.len = PK11_SignatureLen(pks->private_key),
		.data = signature.ptr/*array*/,
	};
	passert(raw_signature.len <= sizeof(signature.ptr/*array*/));
	dbg("ECDSA signature.len %d", raw_signature.len);

	/* create the raw signature */
	SECStatus s = PK11_Sign(pks->private_key, &raw_signature, &hash_to_sign);
	if (DBGP(DBG_CRYPT)) {
		DBG_dump("PK11_Sign()", raw_signature.data, raw_signature.len);
	}
	if (s != SECSuccess) {
		/* PR_GetError() returns the thread-local error */
		llog_nss_error(RC_LOG_SERIOUS, logger,
			       "ECDSA sign function failed");
		return (struct hash_signature) { .len = 0, };
	}

	passert(sizeof(signature.ptr/*array*/) >= raw_signature.len);
	signature.len = raw_signature.len;

	dbg("%s: signed hash", __func__);
	return signature;
}

static bool ECDSA_raw_authenticate_signature(const struct crypt_mac *hash, shunk_t signature,
					     struct pubkey *kr,
					     const struct hash_desc *unused_hash_algo UNUSED,
					     diag_t *fatal_diag,
					     struct logger *logger)
{
	const struct ECDSA_public_key *ecdsa = &kr->u.ecdsa;

	/*
	 * Turn the signature and hash into SECItem/s (NSS doesn't do
	 * const, but it does pretend).
	 */
	const SECItem raw_signature = {
		.type = siBuffer,
		.data = DISCARD_CONST(uint8_t *, signature.ptr),/*NSS doesn't do const*/
		.len = signature.len
	};

	const SECItem hash_item = {
		.type = siBuffer,
		.data = DISCARD_CONST(uint8_t *, hash->ptr),/*NSS doesn't do const*/
		.len = hash->len,
	};

	if (DBGP(DBG_CRYPT)) {
		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
			jam(buf, "%d-byte raw ESCSA signature: ",
			    raw_signature.len);
			jam_nss_secitem(buf, &raw_signature);
		}

		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
			jam(buf, "%d-byte hash: ",
			    hash_item.len);
			jam_nss_secitem(buf, &hash_item);
		}
	}

	if (PK11_Verify(ecdsa->seckey_public, &raw_signature, &hash_item,
			lsw_nss_get_password_context(logger)) != SECSuccess) {
		llog_nss_error(DEBUG_STREAM, logger,
			       "verifying AUTH hash using PK11_Verify() failed:");
		*fatal_diag = NULL;
		return false;
	}

	dbg("%s: verified signature", __func__);

	*fatal_diag = NULL;
	return true;
}

static size_t ECDSA_jam_auth_method(struct jambuf *buf,
				    const struct pubkey_signer *signer,
				    const struct pubkey *pubkey,
				    const struct hash_desc *hash)
{
	return jam(buf, "P-%d %s with %s",
		   SECKEY_PublicKeyStrengthInBits(pubkey->u.ecdsa.seckey_public),
		   signer->name,
		   hash->common.fqn);
}

const struct pubkey_signer pubkey_signer_raw_ecdsa = {
	.name = "ECDSA", /* name from RFC 7427 */
	.type = &pubkey_type_ecdsa,
	.digital_signature_blob = DIGITAL_SIGNATURE_BLOB_ROOF,
	.sign_hash = ECDSA_raw_sign_hash,
	.authenticate_signature = ECDSA_raw_authenticate_signature,
	.jam_auth_method = ECDSA_jam_auth_method,
};

static struct hash_signature ECDSA_digsig_sign_hash(const struct private_key_stuff *pks,
						    const uint8_t *hash_val, size_t hash_len,
						    const struct hash_desc *hash_algo_unused UNUSED,
						    struct logger *logger)
{

	if (!pexpect(pks->private_key != NULL)) {
		dbg("no private key!");
		return (struct hash_signature) { .len = 0, };
	}

	DBGF(DBG_CRYPT, "ECDSA_sign_hash: Started using NSS");

	/* point HASH to sign at HASH_VAL */
	SECItem hash_to_sign = {
		.type = siBuffer,
		.len = hash_len,
		.data = DISCARD_CONST(uint8_t *, hash_val),
	};

	/* point signature at the SIG_VAL buffer */
	uint8_t raw_signature_data[sizeof(struct hash_signature)];
	SECItem raw_signature = {
		.type = siBuffer,
		.len = PK11_SignatureLen(pks->private_key),
		.data = raw_signature_data,
	};
	passert(raw_signature.len <= sizeof(raw_signature_data));
	dbg("ECDSA signature.len %d", raw_signature.len);

	/* create the raw signature */
	SECStatus s = PK11_Sign(pks->private_key, &raw_signature, &hash_to_sign);
	if (DBGP(DBG_CRYPT)) {
		DBG_dump("sig_from_nss", raw_signature.data, raw_signature.len);
	}
	if (s != SECSuccess) {
		/* PR_GetError() returns the thread-local error */
		llog_nss_error(RC_LOG_SERIOUS, logger,
			       "ECDSA sign function failed");
		return (struct hash_signature) { .len = 0, };
	}

	SECItem encoded_signature = {0,};	/* must be initialized*/
	if (DSAU_EncodeDerSigWithLen(&encoded_signature, &raw_signature,
				     raw_signature.len) != SECSuccess) {
		/* PR_GetError() returns the thread-local error */
		llog_nss_error(RC_LOG, logger,
			       "NSS: constructing DER encoded ECDSA signature using DSAU_EncodeDerSigWithLen() failed:");
		return (struct hash_signature) { .len = 0, };
	}
	struct hash_signature signature = {
		.len = encoded_signature.len,
	};
	passert(encoded_signature.len <= sizeof(signature.ptr/*an-array*/));
	memcpy(signature.ptr, encoded_signature.data, encoded_signature.len);
	SECITEM_FreeItem(&encoded_signature, PR_FALSE);

	DBGF(DBG_CRYPT, "ECDSA_sign_hash: Ended using NSS");
	return signature;
}

static bool ECDSA_digsig_authenticate_signature(const struct crypt_mac *hash, shunk_t signature,
						struct pubkey *kr,
						const struct hash_desc *unused_hash_algo UNUSED,
						diag_t *fatal_diag,
						struct logger *logger)
{
	const struct ECDSA_public_key *ecdsa = &kr->u.ecdsa;

	/*
	 * Convert the signature into raw form (NSS doesn't do const).
	 */
	SECItem der_signature = {
		.type = siBuffer,
		.data = DISCARD_CONST(unsigned char *, signature.ptr),/*NSS doesn't do const*/
		.len = signature.len
	};
	if (DBGP(DBG_BASE)) {
		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
			jam(buf, "%d-byte DER encoded ECDSA signature: ",
			    der_signature.len);
			jam_nss_secitem(buf, &der_signature);
		}
	}

	SECItem *raw_signature = DSAU_DecodeDerSigToLen(&der_signature,
							SECKEY_SignatureLen(ecdsa->seckey_public));
	if (raw_signature == NULL) {
		/* not fatal as dependent on key being tried */
		llog_nss_error(DEBUG_STREAM, logger,
			       "unpacking DER encoded ECDSA signature using DSAU_DecodeDerSigToLen()");
		*fatal_diag = NULL;
		return false;
	}

	if (DBGP(DBG_BASE)) {
		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
			jam(buf, "%d-byte raw ESCSA signature: ",
			    raw_signature->len);
			jam_nss_secitem(buf, raw_signature);
		}
	}

	/*
	 * put the hash somewhere writable; so it can later be logged?
	 *
	 * XXX: cast away const?
	 */
	struct crypt_mac hash_data = *hash;
	SECItem hash_item = {
		.type = siBuffer,
		.data = hash_data.ptr,
		.len = hash_data.len,
	};

	if (PK11_Verify(ecdsa->seckey_public, raw_signature, &hash_item,
			lsw_nss_get_password_context(logger)) != SECSuccess) {
		llog_nss_error(DEBUG_STREAM, logger,
			       "verifying AUTH hash using PK11_Verify() failed:");
		SECITEM_FreeItem(raw_signature, PR_TRUE/*and-pointer*/);
		*fatal_diag = NULL;
		return false;
	}

	dbg("NSS: verified signature");
	SECITEM_FreeItem(raw_signature, PR_TRUE);

	*fatal_diag = NULL;
	return true;
}

const struct pubkey_signer pubkey_signer_digsig_ecdsa = {
	.name = "ECDSA", /* name from RFC 7427 */
	.type = &pubkey_type_ecdsa,
	.digital_signature_blob = DIGITAL_SIGNATURE_ECDSA_BLOB,
	.sign_hash = ECDSA_digsig_sign_hash,
	.authenticate_signature = ECDSA_digsig_authenticate_signature,
	.jam_auth_method = ECDSA_jam_auth_method,
};
