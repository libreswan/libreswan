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

static err_t ECDSA_dnssec_pubkey_to_pubkey_content(struct ECDSA_public_key *ecdsa,
						   keyid_t *keyid, ckaid_t *ckaid, size_t *size,
						   const chunk_t dnssec_pubkey)
{
	err_t e;

	static const struct dh_desc *dh[] = {
		&ike_alg_dh_secp256r1,
		&ike_alg_dh_secp384r1,
		&ike_alg_dh_secp521r1,
	};

	/*
	 * The raw DNSSEC_PUBKEY, fed to us by a user, could include
	 * the EC_POINT_FORM_UNCOMPRESSED prefix.  Strip that off.
	 */

	const struct dh_desc *group = NULL;
	shunk_t raw = {0};
	FOR_EACH_ELEMENT(e, dh) {
		if (dnssec_pubkey.len == (*e)->bytes) {
			group = (*e);
			raw = HUNK_AS_SHUNK(dnssec_pubkey);
			break;
		}
		if (group->nss_adds_ec_point_form_uncompressed &&
		    dnssec_pubkey.len == (*e)->bytes + 1 &&
		    dnssec_pubkey.ptr[0] == EC_POINT_FORM_UNCOMPRESSED) {
			group = (*e);
			/* ignore prefix */
			raw = shunk2(dnssec_pubkey.ptr + 1, dnssec_pubkey.len - 1);
			break;
		}
	}
	if (group == NULL) {
		return "unrecognized EC pubkey";
	}

	/*
	 * Allocate the public key, giving it its own arena.
	 *
	 * Since the arena contains everything allocated to the
	 * seckey, error recovery just requires freeing that.
	 */

	PRArenaPool *arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	if (arena == NULL) {
		return "allocating ECDSA arena";
	}

	SECKEYPublicKey *seckey = (SECKEYPublicKey *) PORT_ArenaZAlloc(arena, sizeof(SECKEYPublicKey));
	if (seckey == NULL) {
		PORT_FreeArena(arena, /*zero?*/PR_FALSE);
		return "allocating ECDSA pubkey arena";
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
		PORT_FreeArena(arena, /*zero?*/PR_FALSE);
		return "copying 'k' to EDSA public key";
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
		PORT_FreeArena(arena, /*zero?*/PR_FALSE);
		return "lookup of EC OID failed";
	}

	if (SEC_ASN1EncodeItem(arena, &ec->DEREncodedParams,
			       &ec_oid->oid, SEC_ObjectIDTemplate) == NULL) {
		PORT_FreeArena(arena, /*zero?*/PR_FALSE);
		return "ASN.1 encoding of EC OID failed";
	}

	/*
	 * Maintain old fields.
	 */

	ecdsa->ecParams = clone_secitem_as_chunk(ec->DEREncodedParams, "EC param");
	ecdsa->pub = clone_secitem_as_chunk(ec->publicValue, "EC key");

	/* should this include EC? */
	e = form_ckaid_ecdsa(ecdsa->pub, ckaid);
	if (e != NULL) {
		PORT_FreeArena(arena, /*zero?*/PR_FALSE);
		return e;
	}

	/*
	 * Use the ckaid since that digested the entire pubkey (this
	 * is made up)
	 */
	e = keyblob_to_keyid(ckaid->ptr, ckaid->len, keyid);
	if (e != NULL) {
		PORT_FreeArena(arena, /*zero?*/PR_FALSE);
		return e;
	}

	ecdsa->seckey_public = seckey;
	dbg_alloc("ecdsa->seckey_public", seckey, HERE);

	*size = ecdsa->pub.len;

	if (DBGP(DBG_BASE)) {
		/* pubkey information isn't DBG_PRIVATE */
		DBG_log("ECDSA Key:");
		DBG_log("keyid: *%s", str_keyid(*keyid));
		DBG_log("  size: %zu", *size);
		DBG_dump_hunk("pub", ecdsa->pub);
		DBG_dump_hunk("ecParams", ecdsa->ecParams);
		DBG_dump_hunk("CKAID", *ckaid);
	}

       return NULL;
}

static err_t dnssec_pubkey_to_pubkey_content(chunk_t dnssec_pubkey,
						   union pubkey_content *u,
						   keyid_t *keyid, ckaid_t *ckaid, size_t *size)
{
	return ECDSA_dnssec_pubkey_to_pubkey_content(&u->ecdsa, keyid, ckaid, size, dnssec_pubkey);
}

static err_t ECDSA_pubkey_content_to_dnssec_pubkey(const struct ECDSA_public_key *ecdsa,
						   chunk_t *dnssec_pubkey)
{
	passert((ecdsa->pub.len & 1) == 1);
	passert(ecdsa->pub.ptr[0] == EC_POINT_FORM_UNCOMPRESSED);
	*dnssec_pubkey = clone_bytes_as_chunk(ecdsa->pub.ptr + 1, ecdsa->pub.len - 1, "EC POINTS (even)");
	return NULL;
}

static err_t pubkey_content_to_dnssec_pubkey(const union pubkey_content *u,
					     chunk_t *dnssec_pubkey)
{
	return ECDSA_pubkey_content_to_dnssec_pubkey(&u->ecdsa, dnssec_pubkey);
}

static void ECDSA_free_pubkey_content(struct ECDSA_public_key *ecdsa)
{
	free_chunk_content(&ecdsa->pub);
	free_chunk_content(&ecdsa->ecParams);
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
	ecdsa->pub = clone_secitem_as_chunk(seckey_public->u.ec.publicValue, "ECDSA pub");
	ecdsa->ecParams = clone_secitem_as_chunk(seckey_public->u.ec.DEREncodedParams, "ECDSA ecParams");
	ecdsa->seckey_public = SECKEY_CopyPublicKey(seckey_public);
	dbg_alloc("ecdsa->seckey_public", ecdsa->seckey_public, HERE);
	*size = seckey_public->u.ec.publicValue.len;
	*ckaid = ckaid_from_secitem(ckaid_nss);
	/* keyid; make this up */
	err_t e = keyblob_to_keyid(ckaid->ptr, ckaid->len, keyid);
	passert(e == NULL);

	if (DBGP(DBG_BASE)) {
		ckaid_buf cb;
		DBG_log("ECDSA keyid *%s", str_keyid(*keyid));
		DBG_log("ECDSA keyid *%s", str_ckaid(ckaid, &cb));
		DBG_log("ECDSA size: %zu", *size);
		DBG_dump_hunk("pub", ecdsa->pub);
		DBG_dump_hunk("ecParams", ecdsa->ecParams);
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

const struct pubkey_type pubkey_type_ecdsa = {
	.alg = PUBKEY_ALG_ECDSA,
	.name = "ECDSA",
	.private_key_kind = PKK_ECDSA,
	.dnssec_pubkey_to_pubkey_content = dnssec_pubkey_to_pubkey_content,
	.pubkey_content_to_dnssec_pubkey = pubkey_content_to_dnssec_pubkey,
	.free_pubkey_content = free_pubkey_content,
	.extract_private_key_pubkey_content = ECDSA_extract_private_key_pubkey_content,
	.free_secret_content = ECDSA_free_secret_content,
	.secret_sane = ECDSA_secret_sane,
	.extract_pubkey_content = extract_pubkey_content,
	.digital_signature_signer = {
		[DIGITAL_SIGNATURE_ECDSA_BLOB] = &pubkey_signer_ecdsa,
	}
};

static struct hash_signature ECDSA_sign_hash(const struct private_key_stuff *pks,
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

static bool ECDSA_authenticate_signature(const struct crypt_mac *hash, shunk_t signature,
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

const struct pubkey_signer pubkey_signer_ecdsa = {
	.name = "ECDSA", /* name from RFC 7427 */
	.type = &pubkey_type_ecdsa,
	.digital_signature_blob = DIGITAL_SIGNATURE_ECDSA_BLOB,
	.sign_hash = ECDSA_sign_hash,
	.authenticate_signature = ECDSA_authenticate_signature,
};
