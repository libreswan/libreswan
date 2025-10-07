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
#include "ike_alg_kem.h"		/* for OID and size of EC algorithms */
#include "refcnt.h"		/* for dbg_{alloc,free}() */

static struct hash_signature ECDSA_raw_sign_hash(const struct secret_pubkey_stuff *pks,
						 const uint8_t *hash_val, size_t hash_len,
						 const struct hash_desc *hash_alg,
						 struct logger *logger)
{
	ldbgf(DBG_CRYPT, logger, "%s: started using NSS", __func__);

	if (!pexpect(pks->private_key != NULL)) {
		ldbg(logger, "no private key!");
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
	SECItem raw_signature;
	SECStatus s = SGN_Digest(pks->private_key,
				 hash_alg->nss.oid_tag,
				 &raw_signature, &hash_to_sign);
	if (s != SECSuccess) {
		/* PR_GetError() returns the thread-local error */
		llog_nss_error(RC_LOG, logger,
			       "ECDSA SGN_Digest function failed");
		return (struct hash_signature) { .len = 0, };
	}
	if (LDBGP(DBG_CRYPT, logger)) {
		LDBG_log(logger, "SGN_Digest() returned:");
		LDBG_dump(logger, raw_signature.data, raw_signature.len);
	}
	passert(sizeof(signature.ptr/*array*/) >= raw_signature.len);
	memcpy(signature.ptr, raw_signature.data, raw_signature.len);
	signature.len = raw_signature.len;
	SECITEM_FreeItem(&raw_signature, PR_FALSE/*only-data*/);

	if (LDBGP(DBG_CRYPT, logger)) {
		LDBG_log(logger, "signed hash:");
		LDBG_hunk(logger, &signature);
	}

	ldbg(logger, "%s: signed hash", __func__);
	return signature;
}

static bool ECDSA_raw_authenticate_hash_signature(const struct pubkey_signer *signer UNUSED,
						  const struct crypt_mac *hash, shunk_t signature,
						  struct pubkey *kr,
						  const struct hash_desc *unused_hash_algo UNUSED,
						  diag_t *fatal_diag,
						  struct logger *logger)
{
	const struct pubkey_content *ecdsa = &kr->content;

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

	if (LDBGP(DBG_BASE, logger)) {
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

	/*
	 * PK11_Verify() expects a raw signature like supplied here;
	 * VFY_Verify*() also expects a der encoded prefix so doesn't
	 * work.
	 */
	if (PK11_Verify(ecdsa->public_key, &raw_signature, &hash_item,
			lsw_nss_get_password_context(logger)) != SECSuccess) {
		llog_nss_error(DEBUG_STREAM, logger,
			       "verifying AUTH hash using PK11_Verify() failed:");
		*fatal_diag = NULL;
		return false;
	}

	ldbg(logger, "%s: verified signature", __func__);

	*fatal_diag = NULL;
	return true;
}

static size_t ECDSA_jam_auth_method(struct jambuf *buf,
				    const struct pubkey_signer *signer,
				    const struct pubkey *pubkey,
				    const struct hash_desc *hash)
{
	return jam(buf, "P-%d %s with %s",
		   SECKEY_PublicKeyStrengthInBits(pubkey->content.public_key),
		   signer->name,
		   hash->common.fqn);
}

const struct pubkey_signer pubkey_signer_raw_ecdsa = {
	.name = "ECDSA", /* name from RFC 7427 */
	.type = &pubkey_type_ecdsa,
	.digital_signature_blob = DIGITAL_SIGNATURE_BLOB_ROOF,
	.sign = pubkey_hash_then_sign,
	.sign_hash = ECDSA_raw_sign_hash,
	.authenticate_hash_signature = ECDSA_raw_authenticate_hash_signature,
	.jam_auth_method = ECDSA_jam_auth_method,
};

static struct hash_signature ECDSA_digsig_sign_hash(const struct secret_pubkey_stuff *pks,
						    const uint8_t *hash_val, size_t hash_len,
						    const struct hash_desc *hash_algo_unused UNUSED,
						    struct logger *logger)
{

	if (!pexpect(pks->private_key != NULL)) {
		ldbg(logger, "no private key!");
		return (struct hash_signature) { .len = 0, };
	}

	ldbgf(DBG_CRYPT, logger, "ECDSA_sign_hash: Started using NSS");

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
	ldbg(logger, "ECDSA signature.len %d", raw_signature.len);

	/* create the raw signature */
	SECStatus s = PK11_Sign(pks->private_key, &raw_signature, &hash_to_sign);
	if (LDBGP(DBG_CRYPT, logger)) {
		LDBG_log(logger, "PK11_Sign() returned:");
		LDBG_dump(logger, raw_signature.data, raw_signature.len);
	}
	if (s != SECSuccess) {
		/* PR_GetError() returns the thread-local error */
		llog_nss_error(RC_LOG, logger,
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

	ldbgf(DBG_CRYPT, logger, "ECDSA_sign_hash: Ended using NSS");
	return signature;
}

static bool ECDSA_digsig_authenticate_hash_signature(const struct pubkey_signer *signer UNUSED,
						     const struct crypt_mac *hash, shunk_t signature,
						     struct pubkey *pubkey,
						     const struct hash_desc *hash_alg,
						     diag_t *fatal_diag,
						     struct logger *logger)
{
	const struct pubkey_content *ecdsa = &pubkey->content;

	SECItem signature_item = {
		.type = siBuffer,
		.data = DISCARD_CONST(unsigned char *, signature.ptr),/*NSS doesn't do const*/
		.len = signature.len
	};

	const SECItem hash_item = {
		.type = siBuffer,
		.data = DISCARD_CONST(uint8_t *, hash->ptr),/*NSS doesn't do const*/
		.len = hash->len,
	};

	if (LDBGP(DBG_BASE, logger)) {
		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
			jam(buf, "%d-byte DER encoded ECDSA signature: ",
			    signature_item.len);
			jam_nss_secitem(buf, &signature_item);
		}
		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
			jam(buf, "%d-byte hash: ",
			    hash_item.len);
			jam_nss_secitem(buf, &hash_item);
		}
	}

	if (VFY_VerifyDigestDirect(&hash_item, ecdsa->public_key, &signature_item,
				   /*pubkey algorithm*/SEC_OID_ANSIX962_EC_PUBLIC_KEY,
				   /*signature hash algorithm*/hash_alg->nss.oid_tag,
				   lsw_nss_get_password_context(logger)) != SECSuccess) {
		llog_nss_error(DEBUG_STREAM, logger,
			       "verifying AUTH hash using VFY_VerifyDigestDirect(%s,%s) failed: ",
			       ecdsa->type->name,
			       hash_alg->common.fqn);
 		*fatal_diag = NULL;
 		return false;
 	}

	*fatal_diag = NULL;
	return true;
}

const struct pubkey_signer pubkey_signer_digsig_ecdsa = {
	.name = "ECDSA", /* name from RFC 7427 */
	.type = &pubkey_type_ecdsa,
	.digital_signature_blob = DIGITAL_SIGNATURE_ECDSA_BLOB,
	.sign = pubkey_hash_then_sign,
	.sign_hash = ECDSA_digsig_sign_hash,
	.authenticate_hash_signature = ECDSA_digsig_authenticate_hash_signature,
	.jam_auth_method = ECDSA_jam_auth_method,
};
