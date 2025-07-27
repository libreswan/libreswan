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

#include "lswnss.h"
#include "lswlog.h"

#include "nss_cert_load.h"

CERTCertificate *get_cert_by_nickname_from_nss(const char *nickname,
					       const struct logger *logger)
{
	return nickname == NULL ? NULL :
		PK11_FindCertFromNickname(nickname,
					  lsw_nss_get_password_context(logger));
}

struct ckaid_match_arg {
	SECItem ckaid;
	CERTCertificate *cert;
	const struct logger *logger;
};

static SECStatus ckaid_match(CERTCertificate *cert, SECItem *ignore1 UNUSED, void *arg)
{
	struct ckaid_match_arg *ckaid_match_arg = arg;
	if (ckaid_match_arg->cert != NULL) {
		return SECSuccess;
	}
	SECItem *ckaid = PK11_GetLowLevelKeyIDForCert(NULL, cert,
						      lsw_nss_get_password_context(ckaid_match_arg->logger));
	if (ckaid == NULL) {
		dbg("GetLowLevelID for cert %s failed", cert->nickname);
		return SECSuccess;
	}
	if (SECITEM_ItemsAreEqual(ckaid, &ckaid_match_arg->ckaid)) {
		dbg("CKAID matched cert %s", cert->nickname);
		ckaid_match_arg->cert = CERT_DupCertificate(cert);
		/* bail early, but how? */
	}
	SECITEM_FreeItem(ckaid, PR_TRUE);
	return SECSuccess;
}

CERTCertificate *get_cert_by_ckaid_from_nss(const ckaid_t *ckaid,
					    const struct logger *logger)
{
	struct ckaid_match_arg ckaid_match_arg = {
		.cert = NULL,
		.ckaid = same_ckaid_as_secitem(ckaid),
		.logger = logger,
	};
	PK11_TraverseSlotCerts(ckaid_match, &ckaid_match_arg,
			       lsw_nss_get_password_context(logger));
	return ckaid_match_arg.cert;
}
