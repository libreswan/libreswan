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
#include <keyhi.h>

#include "lswnss.h"
#include "lswlog.h"
#include "secrets.h"
#include "ike_alg.h"
#include "ike_alg_hash.h"

static err_t RSA_unpack_pubkey_content(union pubkey_content *u,
				       keyid_t *keyid, ckaid_t *ckaid, size_t *size,
				       chunk_t pubkey)
{
	return unpack_RSA_public_key(&u->rsa, keyid, ckaid, size, &pubkey);
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
	struct RSA_private_key *rsak = &pks->u.RSA_private_key;
	RSA_extract_public_key(&rsak->pub, keyid, ckaid, size,
			       pubkey_nss, ckaid_nss);
}

static void RSA_free_secret_content(struct private_key_stuff *pks)
{
	SECKEY_DestroyPrivateKey(pks->private_key);
	struct RSA_private_key *rsak = &pks->u.RSA_private_key;
	RSA_free_public_content(&rsak->pub);
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

/* returns the length of the result on success; 0 on failure */
static struct hash_signature RSA_sign_hash(const struct private_key_stuff *pks,
					   const uint8_t *hash_val, size_t hash_len,
					   const struct hash_desc *hash_algo,
					   struct logger *logger)
{
	dbg("RSA_sign_hash: Started using NSS");
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

	if (hash_algo == NULL /* ikev1*/ ||
	    hash_algo == &ike_alg_hash_sha1 /* old style rsa with SHA1*/) {
		SECStatus s = PK11_Sign(pks->private_key, &signature, &data);
		if (s != SECSuccess) {
			/* PR_GetError() returns the thread-local error */
			llog_nss_error(RC_LOG_SERIOUS, logger,
				       "RSA sign function failed");
			return (struct hash_signature) { .len = 0, };
		}
	} else { /* Digital signature scheme with rsa-pss*/
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
	}

	dbg("RSA_sign_hash: Ended using NSS");
	return sig;
}

const struct pubkey_type pubkey_type_rsa = {
	.alg = PUBKEY_ALG_RSA,
	.name = "RSA",
	.private_key_kind = PKK_RSA,
	.free_pubkey_content = RSA_free_pubkey_content,
	.unpack_pubkey_content = RSA_unpack_pubkey_content,
	.extract_pubkey_content = RSA_extract_pubkey_content,
	.extract_private_key_pubkey_content = RSA_extract_private_key_pubkey_content,
	.free_secret_content = RSA_free_secret_content,
	.secret_sane = RSA_secret_sane,
	.sign_hash = RSA_sign_hash,
};
