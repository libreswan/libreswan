/*
 * NSS certificate loading routines, for libreswan
 *
 * Copyright (C) 2015 Matt Rogers <mrogers@libreswan.org>
 * Copyright (C) 2016, Andrew Cagney <cagney@gnu.org>
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#include <libreswan.h>
#include "ietf_constants.h"
#include "constants.h"
#include "lswlog.h"
#include "lswalloc.h"
#include "lswnss.h"
#include "asn1.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "pem.h"

#include <nss.h>
#include <pk11pub.h>
#include <cert.h>

#include "nss_cert_load.h"

CERTCertificate *get_cert_by_nickname_from_nss(const char *nickname)
{
	return nickname == NULL ? NULL :
		PK11_FindCertFromNickname(nickname,
			lsw_return_nss_password_file_info());
}

struct ckaid_match_arg {
	SECItem ckaid;
	CERTCertificate *cert;
};

static SECStatus ckaid_match(CERTCertificate *cert, SECItem *ignore1 UNUSED, void *arg)
{
	struct ckaid_match_arg *ckaid_match_arg = arg;
	if (ckaid_match_arg->cert != NULL) {
		return SECSuccess;
	}
	SECItem *ckaid = PK11_GetLowLevelKeyIDForCert(NULL, cert,
						      lsw_return_nss_password_file_info());
	if (ckaid == NULL) {
		DBG(DBG_CONTROL,
		    DBG_log("GetLowLevelID for cert %s failed", cert->nickname));
		return SECSuccess;
	}
	if (SECITEM_ItemsAreEqual(ckaid, &ckaid_match_arg->ckaid)) {
		DBG(DBG_CONTROLMORE, DBG_log("CKAID matched cert %s", cert->nickname));
		ckaid_match_arg->cert = CERT_DupCertificate(cert);
		/* bail early, but how?  */
	}
	SECITEM_FreeItem(ckaid, PR_TRUE);
	return SECSuccess;
}

CERTCertificate *get_cert_by_ckaid_t_from_nss(ckaid_t ckaid)
{
	struct ckaid_match_arg ckaid_match_arg = {
		.cert = NULL,
		.ckaid = *ckaid.nss,
	};
	PK11_TraverseSlotCerts(ckaid_match, &ckaid_match_arg,
			       lsw_return_nss_password_file_info());
	return ckaid_match_arg.cert;
}

CERTCertificate *get_cert_by_ckaid_from_nss(const char *ckaid)
{
	if (ckaid == NULL) {
		return NULL;
	}
	/* convert hex string ckaid to binary bin */
	size_t binlen = (strlen(ckaid) + 1) / 2;
	char *bin = alloc_bytes(binlen, "ckaid");
	const char *ugh = ttodata(ckaid, 0, 16, bin, binlen, &binlen);
	if (ugh != NULL) {
		pfree(bin);
		/* should have been rejected by whack? */
		libreswan_log("invalid hex CKAID '%s': %s", ckaid, ugh);
		return NULL;
	}

	SECItem ckaid_nss = {
		.type = siBuffer,
		.data = (void*) bin,
		.len = binlen,
	};
	ckaid_t ckaid_buf = {
		.nss = &ckaid_nss,
	};
	CERTCertificate *cert = get_cert_by_ckaid_t_from_nss(ckaid_buf);
	pfree(bin);
	return cert;
}
