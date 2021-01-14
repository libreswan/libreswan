/* Output the decoded NSS CK_FLAG, for libreswan
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

size_t jam_nss_ckf(struct jambuf *buf, CK_FLAGS flags)
{
	const char *sep = "";
	size_t size = 0;
	/* nothing smart about this */
#define FLAG(F) \
	if (flags & F) {					\
		size += jam_string(buf, sep);			\
		/* Not using #T + strlen("CKF_") because of clang's -Wstring-plus-int */
		size += jam_string(buf, &#F[strlen("CKF_")]);	\
		sep = "+";					\
		flags ^= F;					\
	}
	FLAG(CKF_SIGN);
	FLAG(CKF_ENCRYPT);
	FLAG(CKF_DECRYPT);
	if (flags != 0) {
		size += jam(buf, "%sCKF_%08lx", sep, (long) flags);
	}
	return size;
}
