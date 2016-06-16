/*
 * NSS certificate loading routines, for libreswan
 *
 * Copyright (C) 2015 Matt Rogers <mrogers@libreswan.org>
 * Copyright (C) 2016, Andrew Cagney <cagney@gnu.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
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
/*
 * load a coded key or certificate file with autodetection
 * of binary DER or base64 PEM ASN.1 formats.
 * On success, returns TRUE, leaving a dynamically allocated blob in *blob.
 * On failure, returns FALSE.
 */
bool load_coded_file(const char *filename,
		const char *type, chunk_t *blob)
{
	err_t ugh = NULL;
	FILE *fd = fopen(filename, "r");

	if (fd == NULL) {
		libreswan_log("  could not open %s file '%s'", type, filename);
	} else {
		long sz_ftell;
		size_t sz_fread;

		fseek(fd, 0, SEEK_END);
		sz_ftell = ftell(fd);

		/* a cert file larger than 50K seems wrong */
		if (sz_ftell <= 0 || sz_ftell > 50000) {
			libreswan_log("  discarded %s file '%s', bad size %lu bytes",
				type, filename, sz_ftell);
			fclose(fd);
			return FALSE;
		}

		rewind(fd);
		setchunk(*blob, alloc_bytes(sz_ftell, type), sz_ftell);
		sz_fread = fread(blob->ptr, 1, blob->len, fd);
		fclose(fd);
		if (sz_fread != blob->len) {
			libreswan_log("  could not read complete certificate-blob from %s file '%s'",
				type, filename);
			freeanychunk(*blob);
			return FALSE;
		}

		libreswan_log("  loading %s file '%s' (%ld bytes)",
			type, filename, sz_ftell);

		/* try DER format */
		if (is_asn1(*blob)) {
			DBG(DBG_PARSING,
				DBG_log("  file coded in DER format"));
			return TRUE;
		}

		/* try PEM format */
		ugh = pemtobin(blob);

		if (ugh == NULL) {
			if (is_asn1(*blob)) {
				DBG(DBG_PARSING,
					DBG_log("  file coded in PEM format"));
				return TRUE;
			}
			ugh = "file coded in unknown format, discarded";
		}

		/* a conversion error has occured */
		libreswan_log("ERROR: file rejected: %s", ugh);
		freeanychunk(*blob);
	}
	return FALSE;
}

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

CERTCertificate *get_cert_by_ckaid_from_nss(const char *ckaid)
{
	if (ckaid == NULL) {
		return NULL;
	}
	size_t buflen = strlen(ckaid);
	char *buf = alloc_bytes(buflen, "ckaid"); /* good enough */
	const char *ugh = ttodata(ckaid, 0, 16, buf, buflen, &buflen);
	if (ugh != NULL) {
		pfree(buf);
		/* should have been rejected by whack? */
		libreswan_log("invalid hex CKAID '%s': %s", ckaid, ugh);
		return NULL;
	}

	struct ckaid_match_arg ckaid_match_arg = {
		.cert = NULL,
		.ckaid = {
			.type = siBuffer,
			.data = (void*) buf,
			.len = buflen,
		},
	};
	PK11_TraverseSlotCerts(ckaid_match, &ckaid_match_arg,
			       lsw_return_nss_password_file_info());
	pfree(buf);
	return ckaid_match_arg.cert;
}
