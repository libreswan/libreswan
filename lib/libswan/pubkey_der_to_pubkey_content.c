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


static diag_t seckey_to_pubkey_content(SECKEYPublicKey *seckey,
				       union pubkey_content *pkc,
				       keyid_t *keyid, ckaid_t *ckaid, size_t *size,
				       const struct pubkey_type **type)
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
		*ckaid = ckaid_from_secitem(nss_ckaid);
		SECITEM_FreeItem(nss_ckaid, PR_TRUE);
		form_keyid(exponent, modulus, keyid, size);
		*type = &pubkey_type_rsa;
		pkc->rsa.seckey_public = seckey;
		dbg_alloc("ecdsa->seckey_pubkey", seckey, HERE);
		break;
	}
	case ecKey:
	{
		SECItem *nss_ckaid = PK11_MakeIDFromPubKey(&seckey->u.ec.publicValue);
		if (nss_ckaid == NULL) {
			return diag("unable to compute 'CKAID' from public value");
		}
		*ckaid = ckaid_from_secitem(nss_ckaid);
		SECITEM_FreeItem(nss_ckaid, PR_TRUE);
		err_t e = keyblob_to_keyid(ckaid->ptr, ckaid->len, keyid);
		if (e != NULL) {
			return diag("%s", e);
		}
		*type = &pubkey_type_ecdsa;
		*size = seckey->u.ec.publicValue.len;
		pkc->ecdsa.seckey_public = seckey;
		dbg_alloc("ecdsa->seckey_pubkey", seckey, HERE);
		break;
	}
	default:
		return diag("decoded Public Key has unknown type %d", key_type);
	}

	if (DBGP(DBG_BASE)) {
		DBG_dump_hunk("computed ecdsa CKAID", *ckaid);
	}

	return NULL;
}

static diag_t spki_to_pubkey_content(CERTSubjectPublicKeyInfo *spki,
				     union pubkey_content *pkc,
				     keyid_t *keyid, ckaid_t *ckaid, size_t *size,
				     const struct pubkey_type **type)
{
	SECKEYPublicKey *seckey = SECKEY_ExtractPublicKey(spki);
	if (seckey == NULL) {
		return diag_nss_error("extracting Public Key from Subject Public Key Info");
	}

	diag_t d = seckey_to_pubkey_content(seckey, pkc, keyid, ckaid, size, type);
	if (d != NULL) {
		SECKEY_DestroyPublicKey(seckey);
	}
	return d;
}

diag_t pubkey_der_to_pubkey_content(shunk_t der, union pubkey_content *pkc,
				    keyid_t *keyid, ckaid_t *ckaid, size_t *size,
				    const struct pubkey_type **type)
{
	SECItem der_item = same_shunk_as_secitem(der, siBuffer);/*loose const */
	CERTSubjectPublicKeyInfo *spki = SECKEY_DecodeDERSubjectPublicKeyInfo(&der_item);
	if (spki == NULL) {
		return diag_nss_error("decoding Subject Public Key Info DER");
	}

	diag_t d = spki_to_pubkey_content(spki, pkc, keyid, ckaid, size, type);
	SECKEY_DestroySubjectPublicKeyInfo(spki);
	return d;
}
