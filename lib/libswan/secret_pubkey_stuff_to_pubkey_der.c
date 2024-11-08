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

static diag_t seckey_pubkey_to_der(SECKEYPublicKey *seckey_pubkey, chunk_t *der)
{
	SECItem *seckey_der = SECKEY_EncodeDERSubjectPublicKeyInfo(seckey_pubkey);
	if (seckey_der == NULL) {
		return diag_nss_error("encoding Subject Public Key Info as DER");
	}

	*der = clone_secitem_as_chunk(*seckey_der, "Subject Public Key Info DER");
	SECITEM_FreeItem(seckey_der, PR_TRUE/*and SECItem*/);
	return NULL;
}

diag_t secret_pubkey_stuff_to_pubkey_der(struct secret_pubkey_stuff *pks, chunk_t *der)
{
	SECKEYPublicKey *seckey_pubkey = SECKEY_ConvertToPublicKey(pks->private_key);
	if (seckey_pubkey == NULL) {
		return diag_nss_error("extracting Public Key from Private Key");
	}

	diag_t d = seckey_pubkey_to_der(seckey_pubkey, der);
	SECKEY_DestroyPublicKey(seckey_pubkey);
	return d;
}
