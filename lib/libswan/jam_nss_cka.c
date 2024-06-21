/* Output the decoded NSS CK_ATTRIBUTE, for libreswan
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

size_t jam_nss_cka(struct jambuf *buf, CK_ATTRIBUTE_TYPE attribute)
{
	/* Not using #T + strlen("CKA_") because of clang's -Wstring-plus-int */
#define CASE(T) case T: return jam_string(buf, &#T[strlen("CKA_")])

	CK_ATTRIBUTE_TYPE cka_nss = (attribute & CKA_NSS_MESSAGE_MASK);
	attribute &= ~CKA_NSS_MESSAGE_MASK;
	if (cka_nss != 0) {
		switch (cka_nss) {
			CASE(CKA_NSS_MESSAGE);
			CASE(CKA_DIGEST);
		default:
			return jam(buf, "CKA_%08lx", (long)attribute);
		}
		jam_string(buf, "|");
	}

	switch (attribute) {
		CASE(CKA_DERIVE);
		CASE(CKA_FLAGS_ONLY);
		CASE(CKA_WRAP);
		CASE(CKA_UNWRAP);
		CASE(CKA_ENCRYPT);
		CASE(CKA_DECRYPT);
		CASE(CKA_SIGN);
		CASE(CKA_SIGN_RECOVER);
		CASE(CKA_VERIFY);
		CASE(CKA_VERIFY_RECOVER);
	default:
		return jam(buf, "CKA_%08lx", (long)attribute);
	}
#undef CASE
}
