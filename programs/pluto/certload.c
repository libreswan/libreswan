/*
 * Certificate support for IKE authentication
 * Copyright (C) 2002-2004 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2005-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
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
#include "pkcs.h"
#include "pem.h"

#include <nss.h>
#include <pk11pub.h>
#include <cert.h>


/*
 * extracts the chunk_t of the given cert_t
 */
chunk_t get_cert_chunk(cert_t cert)
{
	switch (cert.ty) {
	case CERT_NONE:
		return empty_chunk; /* quietly forget about it */

	case CERT_X509_SIGNATURE:
		return cert.u.x509->certificate;

	default:
		bad_case(cert.ty);
	}
}

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

/*
 *  Loads a X.509 or certificate
 */
bool load_cert(const char *filename,
	const char *label, cert_t *cert)
{
	chunk_t blob = empty_chunk;

	/* initialize cert struct */
	cert->u.x509 = NULL;

	if (load_coded_file(filename, label, &blob)) {

		x509cert_t *x509cert = alloc_thing(x509cert_t,
						"x509cert");
		*x509cert = empty_x509cert;

		if (!parse_x509cert(blob, 0, x509cert)) {
			libreswan_log(" error in X.509 certificate %s",
				filename);
			free_x509cert(x509cert);
		} else {
			cert->ty = CERT_X509_SIGNATURE;
			cert->u.x509 = x509cert;
			return TRUE;
		}
	}
	return FALSE;
}

/*
 * For each link pointing to the certificate increase the count by one
 * Currently, only one cert type is supported.
 * This function is called even when no certificates are involved
 */
void share_cert(cert_t cert)
{
	switch (cert.ty) {
	case CERT_NONE:
		break; /* quietly forget about it */
	case CERT_X509_SIGNATURE:
		share_x509cert(cert.u.x509);
		break;
	default:
		bad_case(cert.ty);
	}
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

bool load_cert_from_nss(const char *nssHostCertNickName,
			const char *label, cert_t *cert)
{
	chunk_t blob = empty_chunk;
	CERTCertificate *nssCert;

	/* initialize cert struct */
	cert->u.x509 = NULL;

	nssCert = PK11_FindCertFromNickname(nssHostCertNickName,
					lsw_return_nss_password_file_info());

	if (nssCert == NULL) {
		libreswan_log(
			"    could not open %s with nick name '%s' in NSS DB",
			label, nssHostCertNickName);
		return FALSE;
	}

	DBG(DBG_CRYPT,
		DBG_log("Found pointer to cert %s now giving it to further processing",
			nssHostCertNickName));

	/* blob's memory will be owned by cert (if successful) */
	clonetochunk(blob, nssCert->derCert.data, nssCert->derCert.len, label);

	if (!is_asn1(blob)) {
		libreswan_log("  cert read from NSS db is not in DER format");
		pfree(blob.ptr);
		return FALSE;
	} else {
		x509cert_t *x509cert = alloc_thing(x509cert_t, "x509cert");

		DBG(DBG_PARSING,
			DBG_log("file coded in DER format"));

		*x509cert = empty_x509cert;

		if (!parse_x509cert(blob, 0, x509cert /* ownership! */)) {
			libreswan_log("  error in X.509 certificate");
			/* free blob and *x509cert and any dangly bits */
			free_x509cert(x509cert);
			return FALSE;	/* failure */
		} else {
			cert->ty = CERT_X509_SIGNATURE;
			cert->u.x509 = x509cert;
			return TRUE;	/* success! */
		}
	}
}

void load_authcerts_from_nss(const char *type, u_char auth_flags)
{
	CERTCertListNode *node;
	CERTCertList *list = PK11_ListCerts(PK11CertListCA,
					lsw_return_nss_password_file_info());

	if (list != NULL) {
		for (node = CERT_LIST_HEAD(list); !CERT_LIST_END(node, list);
			node = CERT_LIST_NEXT(node)) {

			cert_t cert;

			if (load_cert_from_nss(node->cert->nickname,
						type, &cert))
				add_authcert(&cert.u.x509, auth_flags);
		}
	}
}
