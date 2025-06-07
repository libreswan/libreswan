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
 *
 * Kind of SECOID_FindOIDByMechanism() works for some, but not all
 * values.
 */

#include "lswlog.h"
#include "lswnss.h"

const char *str_nss_ckm(CK_MECHANISM_TYPE mechanism, name_buf *buf)
{
	switch (mechanism) {
		/* Not using #T + strlen("CKM_") because of clang's -Wstring-plus-int */
#define CASE(T) case T:					\
		buf->buf = &#T[strlen("CKM_")];		\
		break

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
		CASE(CKM_AES_ECB);
#ifdef CKM_AES_XCBC_MAC /* print whenever defined */
		CASE(CKM_AES_XCBC_MAC);
#endif

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

#ifdef CKM_NSS_IKE_PRF_DERIVE /* print whenever defined */
		CASE(CKM_NSS_IKE_PRF_DERIVE);
#endif
#ifdef CKM_NSS_IKE1_PRF_DERIVE /* print whenever defined */
		CASE(CKM_NSS_IKE1_PRF_DERIVE);
#endif
#ifdef CKM_NSS_IKE_PRF_PLUS_DERIVE /* print whenever defined */
		CASE(CKM_NSS_IKE_PRF_PLUS_DERIVE);
#endif
#ifdef CKM_NSS_IKE1_APP_B_PRF_DERIVE /* print whenever defined */
		CASE(CKM_NSS_IKE1_APP_B_PRF_DERIVE);
#endif

		CASE(CKM_VENDOR_DEFINED);

#undef CASE

	default:
		snprintf(buf->tmp, sizeof(buf->tmp),
			 "CKM_%08lx", (long)mechanism);
		buf->buf = buf->tmp;
	}
	return buf->buf;
}

size_t jam_nss_ckm(struct jambuf *buf, CK_MECHANISM_TYPE mechanism)
{
	name_buf b;
	return jam_string(buf, str_nss_ckm(mechanism, &b));
}
