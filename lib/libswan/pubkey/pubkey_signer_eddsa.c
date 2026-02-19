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

#include "lswnss.h"
#include "lswlog.h"
#include "secrets.h"
#include "ike_alg_kem.h"		/* for OID and size of EC algorithms */
#include "refcnt.h"		/* for dbg_{alloc,free}() */
#include "crypt_hash.h"

static size_t EDDSA_jam_auth_method(struct jambuf *buf,
				    const struct pubkey_signer *signer,
				    const struct pubkey *pubkey,
				    const struct hash_desc *hash)
{
	return jam(buf, "P-%d %s with %s",
		   SECKEY_PublicKeyStrengthInBits(pubkey->content.public_key),
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

static struct hash_signature EDDSA_sign_message_1(const struct pubkey_signer *signer UNUSED,
						  const struct secret_pubkey_stuff *pks,
						  chunk_t message,
						  struct logger *logger)
{
	if (!pexpect(pks->private_key != NULL)) {
		ldbg(logger, "no private key!");
		return (struct hash_signature) { .len = 0, };
	}

	ldbgf(DBG_CRYPT, logger, "EDDSA_sign_message_hash: Started using NSS");

	/* point HASH to sign at HASH_VAL */
	SECItem hash_to_sign = same_hunk_as_secitem(&message, siBuffer);

	/* point signature at the SIG_VAL buffer */
	uint8_t raw_signature_data[sizeof(struct hash_signature)];
	SECItem raw_signature = {
		.type = siBuffer,
		.len = PK11_SignatureLen(pks->private_key),
		.data = raw_signature_data,
	};
	ldbg(logger, "signature length is %d", raw_signature.len);
	PASSERT(logger, raw_signature.len <= sizeof(raw_signature_data));

	if (LDBGP(DBG_BASE, logger)) {
		LDBG_log(logger, "EDDSA message of %zu bytes:", message.len);
		LDBG_hunk(logger, &message);
	}

	/* create the raw signature */
	SECStatus s = PK11_Sign(pks->private_key, &raw_signature, &hash_to_sign);
	if (LDBGP(DBG_CRYPT, logger)) {
		LDBG_log(logger, "PK11_Sign() returned:");
		LDBG_dump(logger, raw_signature.data, raw_signature.len);
	}
	if (s != SECSuccess) {
		/* PR_GetError() returns the thread-local error */
		llog_nss_error(RC_LOG, logger,
			       "EDDSA sign function failed");
		return (struct hash_signature) { .len = 0, };
	}

	SECItem encoded_signature = {0,};	/* must be initialized*/
	if (DSAU_EncodeDerSigWithLen(&encoded_signature, &raw_signature,
				     raw_signature.len) != SECSuccess) {
		/* PR_GetError() returns the thread-local error */
		llog_nss_error(RC_LOG, logger,
			       "NSS: constructing DER encoded EDDSA signature using DSAU_EncodeDerSigWithLen() failed:");
		return (struct hash_signature) { .len = 0, };
	}
	struct hash_signature signature = {
		.len = encoded_signature.len,
	};
	passert(encoded_signature.len <= sizeof(signature.ptr/*an-array*/));
	memcpy(signature.ptr, encoded_signature.data, encoded_signature.len);
	SECITEM_FreeItem(&encoded_signature, PR_FALSE);

	if (LDBGP(DBG_BASE, logger)) {
		LDBG_log(logger, "ECDSA auth signature of %zu bytes:", signature.len);
		LDBG_hunk(logger, &signature);
	}

	return signature;
}

static struct hash_signature EDDSA_sign_message(const struct pubkey_signer *signer,
					const struct secret_pubkey_stuff *pks,
					const struct hash_hunks *hunks,
					struct logger *logger)
{
	chunk_t message = concat_hunks(hunks); /* must free_chunk_content() */
	struct hash_signature signature = EDDSA_sign_message_1(signer, pks, message, logger);
	free_chunk_content(&message);
	return signature;
}

static bool EDDSA_authenticate_message_signature_1(const struct pubkey_signer *signer UNUSED,
						   chunk_t message,
						   shunk_t signature,
						   struct pubkey *pubkey,
						   diag_t *fatal_diag,
						   struct logger *logger)
{
	if (LDBGP(DBG_BASE, logger)) {
		LDBG_log(logger, "EDDSA signature of %zu bytes:", signature.len);
		LDBG_hunk(logger, &signature);
		LDBG_log(logger, "EDDSA message of %zu bytes:", message.len);
		LDBG_hunk(logger, &message);
	}

	PRArenaPool *arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	if (arena == NULL) {
		*fatal_diag = diag_nss_error("allocating EDDSA arena");
		return false;
	}

	/*
	 * convert K(R) into a public key
	 */

	/*
	 * Convert the signature into raw form (NSS doesn't do const).
	 */
	SECItem der_signature = {
		.type = siBuffer,
		.data = DISCARD_CONST(unsigned char *, signature.ptr),/*NSS doesn't do const*/
		.len = signature.len
	};

	SECItem *raw_signature = DSAU_DecodeDerSigToLen(&der_signature,
							SECKEY_SignatureLen(pubkey->content.public_key));
	if (raw_signature == NULL) {
		/* not fatal as dependent on key being tried */
		llog_nss_error(DEBUG_STREAM, logger,
			       "unpacking DER encoded EDDSA signature using DSAU_DecodeDerSigToLen()");
		PORT_FreeArena(arena, PR_FALSE);
		*fatal_diag = NULL;
		return false;
	}

	/*
	 * put the hash somewhere writable; so it can later be logged?
	 *
	 * XXX: cast away const?
	 */
	SECItem hash_item = same_hunk_as_secitem(&message, siBuffer);

	if (PK11_Verify(pubkey->content.public_key, raw_signature, &hash_item,
			lsw_nss_get_password_context(logger)) != SECSuccess) {
		llog_nss_error(DEBUG_STREAM, logger,
			       "verifying AUTH hash using PK11_Verify() failed:");
		PORT_FreeArena(arena, PR_FALSE);
		SECITEM_FreeItem(raw_signature, PR_TRUE);
		*fatal_diag = NULL;
		return false;
	}

	SECITEM_FreeItem(raw_signature, PR_TRUE);

	*fatal_diag = NULL;
	return true;
}

static bool EDDSA_authenticate_message_signature(const struct pubkey_signer *signer UNUSED,
						 const struct hash_hunks *hunks,
						 shunk_t signature,
						 struct pubkey *pubkey,
						 diag_t *fatal_diag,
						 struct logger *logger)
{
	chunk_t message = concat_hunks(hunks); /* must free_chunk_content() */
	bool ok = EDDSA_authenticate_message_signature_1(signer, message,
							 signature,
							 pubkey, fatal_diag, logger);
	free_chunk_content(&message);
	return ok;
}

const struct pubkey_signer pubkey_signer_digsig_eddsa_ed25519 = {
	.name = "EDDSA", /* name from RFC 7427 */
	.type = &pubkey_type_eddsa,
	.digital_signature_blob = DIGITAL_SIGNATURE_EDDSA_IDENTITY_ED25519_BLOB,
	.sign_message = EDDSA_sign_message,
	.authenticate_message_signature = EDDSA_authenticate_message_signature,
	.jam_auth_method = EDDSA_jam_auth_method,
};
