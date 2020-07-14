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

size_t jam_nss_cka(struct lswlog *buf, CK_ATTRIBUTE_TYPE attribute)
{
	switch (attribute) {
#define CASE(T) case T: return jam_string(buf, #T + strlen("CKA_"))
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
#undef CASE
	default:
		return jam(buf, "CKA_%08lx", (long)attribute);
	}
}
