/* Output a secitem
 *
 * Copyright (C) 2018 Andrew Cagney
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

static size_t lswlog_nss_secitemtype(struct lswlog *buf, SECItemType type)
{
#define C(T) case T: return lswlogs(buf, #T)
	switch (type) {
		C(siBuffer);
		C(siClearDataBuffer);
		C(siCipherDataBuffer);
		C(siDERCertBuffer);
		C(siEncodedCertBuffer);
		C(siDERNameBuffer);
		C(siEncodedNameBuffer);
		C(siAsciiNameString);
		C(siAsciiString);
		C(siDEROID);
		C(siUnsignedInteger);
		C(siUTCTime);
		C(siGeneralizedTime);
		C(siVisibleString);
		C(siUTF8String);
		C(siBMPString);
	default:
		return lswlogf(buf, "(SECItemType)%d", type);
	}
}

size_t lswlog_nss_secitem(struct lswlog *buf, const SECItem *secitem)
{
	size_t size = 0;
	if (secitem == NULL) {
		size = lswlogs(buf, "(SECItem*)NULL");
	} else {
		lswlog_nss_secitemtype(buf, secitem->type);
		lswlogs(buf, ": ");
		lswlog_bytes(buf, secitem->data, secitem->len);
	}
	return size;
}
