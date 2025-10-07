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

static err_t RSA_pubkey_content_to_ipseckey(const struct pubkey_content *pkc,
					    chunk_t *ipseckey,
					    enum ipseckey_algorithm_type *ipseckey_algorithm)
{
	SECKEYRSAPublicKey *rsa = &pkc->public_key->u.rsa;
	chunk_t exponent = same_secitem_as_chunk(rsa->publicExponent);
	chunk_t modulus = same_secitem_as_chunk(rsa->modulus);
	*ipseckey = EMPTY_CHUNK;
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
	*ipseckey = (chunk_t) {
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

static diag_t RSA_extract_pubkey_content_from_ipseckey(shunk_t ipseckey,
						       struct pubkey_content *pkc,
						       const struct logger *logger)
{
	PEXPECT(logger, pkc->type == &pubkey_type_rsa);

	/* unpack */
	shunk_t exponent;
	shunk_t modulus;
	diag_t d = pubkey_ipseckey_rdata_to_rsa_pubkey(ipseckey, &exponent, &modulus);
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
	if (LDBGP(DBG_BASE, logger)) {
		LDBG_log(logger, "computed rsa CKAID");
		LDBG_dump(logger, nss_ckaid->data, nss_ckaid->len);
	}
	pkc->ckaid = ckaid_from_secitem(nss_ckaid);
	SECITEM_FreeItem(nss_ckaid, PR_TRUE);

	err_t kberr = keyblob_to_keyid(ipseckey.ptr, ipseckey.len, &pkc->keyid);
	if (kberr != NULL) {
		diag_t d = diag("%s", kberr);
		PORT_FreeArena(arena, /*zero?*/PR_TRUE);
		return d;
	}

	pkc->type = &pubkey_type_rsa;
	pkc->public_key = seckey;
	ldbg_newref(logger, pkc->public_key);

	/* generate the CKAID */

	if (LDBGP(DBG_BASE, logger)) {
		/* pubkey information isn't DBG_PRIVATE */
		LDBG_log(logger, "keyid: *%s", str_keyid(pkc->keyid));
		LDBG_log_hunk(logger, "  n:", &modulus);
		LDBG_log_hunk(logger, "  e:", &exponent);
		LDBG_log_hunk(logger, "  CKAID:", &pkc->ckaid);
	}

	return NULL;
}

static void RSA_free_pubkey_content(struct pubkey_content *rsa,
				    const struct logger *logger)
{
	SECKEY_DestroyPublicKey(rsa->public_key);
	ldbg_delref(logger, rsa->public_key);
	rsa->public_key = NULL;
}

static err_t RSA_extract_pubkey_content_from_SECKEYPublicKey(struct pubkey_content *pkc,
							     SECKEYPublicKey *seckey_public,
							     SECItem *cert_ckaid,
							     const struct logger *logger)
{
	PEXPECT(logger, pkc->type == &pubkey_type_rsa);

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

	/* now fill in */
	pkc->public_key = SECKEY_CopyPublicKey(seckey_public);
	ldbg_newref(logger, pkc->public_key);
	pkc->ckaid = ckaid_from_secitem(cert_ckaid);
	return NULL;
}

static bool RSA_pubkey_same(const struct pubkey_content *lhs,
			    const struct pubkey_content *rhs,
			    const struct logger *logger)
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
	bool e = SECITEM_ItemsAreEqual(&lhs->public_key->u.rsa.publicExponent,
				       &rhs->public_key->u.rsa.publicExponent);
	bool n = SECITEM_ItemsAreEqual(&lhs->public_key->u.rsa.modulus,
				       &rhs->public_key->u.rsa.modulus);
	if (LDBGP(DBG_CRYPT, logger)) {
		LDBG_log(logger, "n did %smatch", n ? "" : "NOT ");
		LDBG_log(logger, "e did %smatch", e ? "" : "NOT ");
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
	.ipseckey_algorithm = IPSECKEY_ALGORITHM_RSA,
	.free_pubkey_content = RSA_free_pubkey_content,
	.extract_pubkey_content_from_ipseckey = RSA_extract_pubkey_content_from_ipseckey,
	.pubkey_content_to_ipseckey = RSA_pubkey_content_to_ipseckey,
	.extract_pubkey_content_from_SECKEYPublicKey = RSA_extract_pubkey_content_from_SECKEYPublicKey,
	.pubkey_same = RSA_pubkey_same,
	.strength_in_bits = RSA_strength_in_bits,
};
