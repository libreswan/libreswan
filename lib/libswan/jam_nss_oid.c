/* Output the decoded NSS SECOidTag, for libreswan
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

/*
 * XXX: Is there an NSS version of this?
 */

#include "lswlog.h"
#include "lswnss.h"

const char *str_nss_oid(SECOidTag oidtag, enum_buf *b)
{
	SECOidData *data = SECOID_FindOIDByTag(oidtag);
	if (data != NULL) {
		b->buf = data->desc;
	} else {
		snprintf(b->tmp, sizeof(b->tmp),
			 "SEC_OID_%d", oidtag);
		b->buf = b->tmp;
	}
	return b->tmp;
}

size_t jam_nss_oid(struct jambuf *buf, SECOidTag oidtag)
{
	SECOidData *data = SECOID_FindOIDByTag(oidtag);
	if (data != NULL) {
		return jam_string(buf, data->desc);
	}
	return jam(buf, "SEC_OID_%d", oidtag);
}
