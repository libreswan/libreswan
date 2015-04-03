/*
 * NSS certificate loading routines
 * Copyright (C) 2015 Matt Rogers <mrogers@libreswan.org>
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
#include "lswconf.h"
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

bool cert_exists_in_nss(const char *nickname)
{
	CERTCertificate *cert;

	cert = PK11_FindCertFromNickname(nickname,
					lsw_return_nss_password_file_info());
	if (cert == NULL)
		return FALSE;

	CERT_DestroyCertificate(cert);

	return TRUE;
}

static CERTCertificate *get_cert_from_nss(const char *nickname)
{
	CERTCertificate *cert;
	cert = PK11_FindCertFromNickname(nickname,
					lsw_return_nss_password_file_info());
	return cert;
}

bool load_nss_cert_from_db(const char *nickname, cert_t *cert)
{
	if (cert == NULL)
		return FALSE;

	cert->u.nss_cert = NULL;
	cert->ty = CERT_NONE;

	cert->u.nss_cert = get_cert_from_nss(nickname);

	if (cert->u.nss_cert == NULL) {
		libreswan_log(
			"could not find cert with nickname '%s' in NSS",
			nickname);
		return FALSE;
	}
	cert->ty = CERT_X509_SIGNATURE;

	return TRUE;
}
