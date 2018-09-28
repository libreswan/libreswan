/* Output the decoded NSS CK_MECHANISM_TYPE, for libreswan
 *
 * Copyright (C) 2017 Andrew Cagney
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
 *
 */

/*
 * XXX: Is there an NSS version of this?
 */

#include "lswlog.h"
#include "lswnss.h"

size_t lswlog_nss_ckm(struct lswlog *buf, CK_MECHANISM_TYPE mechanism)
{
	switch (mechanism) {
#define CASE(T) case T: return lswlogs(buf, #T + strlen("CKM_"))

		CASE(CKM_CONCATENATE_BASE_AND_DATA);
		CASE(CKM_CONCATENATE_BASE_AND_KEY);
		CASE(CKM_CONCATENATE_DATA_AND_BASE);

		CASE(CKM_XOR_BASE_AND_DATA);

		CASE(CKM_EXTRACT_KEY_FROM_KEY);

		CASE(CKM_AES_CBC);
		CASE(CKM_DES3_CBC);
		CASE(CKM_CAMELLIA_CBC);
		CASE(CKM_AES_CTR);
		CASE(CKM_AES_GCM);
		CASE(CKM_AES_MAC);

		CASE(CKM_AES_KEY_GEN);

		CASE(CKM_MD5);
		CASE(CKM_SHA_1);
		CASE(CKM_SHA256);
		CASE(CKM_SHA384);
		CASE(CKM_SHA512);

		CASE(CKM_MD5_KEY_DERIVATION);
		CASE(CKM_SHA1_KEY_DERIVATION);
		CASE(CKM_SHA256_KEY_DERIVATION);
		CASE(CKM_SHA384_KEY_DERIVATION);
		CASE(CKM_SHA512_KEY_DERIVATION);

		CASE(CKM_MD5_HMAC);
		CASE(CKM_SHA_1_HMAC);
		CASE(CKM_SHA256_HMAC);
		CASE(CKM_SHA384_HMAC);
		CASE(CKM_SHA512_HMAC);

		CASE(CKM_DH_PKCS_DERIVE);
		CASE(CKM_ECDH1_DERIVE);

		CASE(CKM_VENDOR_DEFINED);

#undef CASE

	default:
		return lswlogf(buf, "CKM_%08lx", (long)mechanism);
	}
}
