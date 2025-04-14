/* Convert a private key to a Subect Public Key Info DER, for libreswan
 *
 * Copyright (C) 2022 Andrew Cagney
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

#include <keyhi.h>

#include "lswnss.h"
#include "secrets.h"
#include "global_logger.h"


static diag_t seckey_to_pubkey_content(SECKEYPublicKey *seckey,
				       struct pubkey_content *pkc)
{
	KeyType key_type = seckey->keyType;
	switch (key_type) {
	case rsaKey:
	{
		chunk_t exponent = same_secitem_as_chunk(seckey->u.rsa.publicExponent);
		chunk_t modulus = same_secitem_as_chunk(seckey->u.rsa.modulus);
		SECItem *nss_ckaid = PK11_MakeIDFromPubKey(&seckey->u.rsa.modulus);
		if (nss_ckaid == NULL) {
			return diag("unable to compute 'CKAID' from modulus");
		}
		pkc->ckaid = ckaid_from_secitem(nss_ckaid);
		SECITEM_FreeItem(nss_ckaid, PR_TRUE);
		size_t size;
		form_keyid(exponent, modulus, &pkc->keyid, &size);
		pkc->type = &pubkey_type_rsa;
		pkc->public_key = seckey;
		ldbg_alloc(&global_logger, "ecdsa->public_key", seckey, HERE);
		break;
	}
	case ecKey:
	{
		SECItem *nss_ckaid = PK11_MakeIDFromPubKey(&seckey->u.ec.publicValue);
		if (nss_ckaid == NULL) {
			return diag("unable to compute 'CKAID' from public value");
		}
		pkc->ckaid = ckaid_from_secitem(nss_ckaid);
		SECITEM_FreeItem(nss_ckaid, PR_TRUE);
		err_t e = keyblob_to_keyid(pkc->ckaid.ptr, pkc->ckaid.len, &pkc->keyid);
		if (e != NULL) {
			return diag("%s", e);
		}
		pkc->type = &pubkey_type_ecdsa;
		pkc->public_key = seckey;
		ldbg_alloc(&global_logger, "ecdsa->public_key", seckey, HERE);
		break;
	}
	default:
		return diag("decoded Public Key has unknown type %d", key_type);
	}

	return NULL;
}

static diag_t spki_to_pubkey_content(CERTSubjectPublicKeyInfo *spki,
				     struct pubkey_content *pkc)
{
	SECKEYPublicKey *seckey = SECKEY_ExtractPublicKey(spki);
	if (seckey == NULL) {
		return diag_nss_error("extracting Public Key from Subject Public Key Info");
	}

	diag_t d = seckey_to_pubkey_content(seckey, pkc);
	if (d != NULL) {
		SECKEY_DestroyPublicKey(seckey);
	}
	return d;
}

diag_t pubkey_der_to_pubkey_content(shunk_t der, struct pubkey_content *pkc)
{
	SECItem der_item = same_shunk_as_secitem(der, siBuffer);/*loose const */
	CERTSubjectPublicKeyInfo *spki = SECKEY_DecodeDERSubjectPublicKeyInfo(&der_item);
	if (spki == NULL) {
		return diag_nss_error("decoding Subject Public Key Info DER");
	}

	diag_t d = spki_to_pubkey_content(spki, pkc);
	SECKEY_DestroySubjectPublicKeyInfo(spki);
	return d;
}
