/* Output the decoded NSS CK_GENERATE_FUNCTION, for libreswan
 *
 * Copyright (C) 2024 Andrew Cagney
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

size_t jam_nss_ckg(struct jambuf *buf, CK_GENERATOR_FUNCTION generator)
{
	switch (generator) {
	/* Not using #T + strlen("CKG_") because of clang's -Wstring-plus-int */
#define CASE(T) case T: return jam_string(buf, &#T[strlen("CKG_")])
		CASE(CKG_NO_GENERATE);
		CASE(CKG_GENERATE);
		CASE(CKG_GENERATE_COUNTER);
		CASE(CKG_GENERATE_COUNTER_XOR);
		CASE(CKG_GENERATE_RANDOM);
	default:
		return jam(buf, "CKG_%08lx", (long)generator);
	}
#undef CASE
}
