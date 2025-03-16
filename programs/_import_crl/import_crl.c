/* CRL import helper, for libreswan.
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
 *
 */

#include <unistd.h>
#include <prlong.h>
#include <secder.h>
#include <errno.h>
#include <secerr.h>
#include <cert.h>
#include <certdb.h>
#include <nss.h>		/* for NSS_Shutdown() */

#include "lswconf.h"
#include "lswnss.h"
#include "lswtool.h"
#include "lswalloc.h"
#include "lswlog.h"		/* for fatal() */
#include "import_crl.h"
#include "pem.h"
#include "timescale.h"

#ifdef __clang__
/*
 * clang complains about these from nss.h, gcc does not?
 */
extern SECStatus NSS_Shutdown(void);
extern SECStatus NSS_InitReadWrite(const char *configdir);
#endif

static err_t fetch_asn1_blob(const char *url, chunk_t *blob, struct logger *logger)
{
	err_t ugh = "CRL support not built in";

	*blob = EMPTY_CHUNK;
	if (startswith(url, "ldap:")) {
#ifdef USE_LDAP
		ugh = fetch_ldap(url, blob, logger);
#endif
	} else {
#ifdef USE_LIBCURL
		init_curl(logger);
		ugh = fetch_curl(url, blob, logger);
		shutdown_curl();
#endif
	}
	if (ugh != NULL) {
		free_chunk_content(blob);
		return ugh;
	}

	ugh = asn1_ok(ASN1(*blob));
	if (ugh == NULL) {
		dbg("  fetched blob coded in DER format");
	} else {
		ugh = pemtobin(blob);
		if (ugh != NULL) {
		} else if (asn1_ok(ASN1(*blob)) == NULL) {
			dbg("  fetched blob coded in PEM format");
		} else {
			ugh = "Blob coded in unknown format (within PEM)";
		}
	}
	if (ugh == NULL && blob->len == 0)
		ugh = "empty ASN.1 blob";
	if (ugh != NULL)
		free_chunk_content(blob);
	return ugh;
}

/*
 * _import_crl <url> <der size>
 * the der blob is passed through STDIN from pluto's fork
 */
int main(int argc, char *argv[])
{
	struct logger *logger = tool_logger(argc, argv);

	if (argc != 4) {
		fatal(PLUTO_EXIT_FAIL, logger, "expecting: <url> <crl-fetch-timeout> <curl-iface>");
	}

	/* <url */
	char *url = argv[1];

	/* crl_fetch_timeout */
	diag_t d = ttodeltatime(argv[2], &crl_fetch_timeout, TIMESCALE_SECONDS);
	if (d != NULL) {
		fatal(PLUTO_EXIT_FAIL, logger, "invalid crl_fetch_timeout %s: %s",
		      argv[2], str_diag(d));
	}

	curl_iface = (argv[3][0] == '\0' ? NULL : argv[3]);

	chunk_t blob;
	err_t e = fetch_asn1_blob(url, &blob, logger);
	if (e != NULL) {
		fatal(PLUTO_EXIT_FAIL, logger, "fetch failed: %s", e);
	}

	const struct lsw_conf_options *oco = lsw_init_options();
	init_nss(oco->nssdir, (struct nss_flags){0}, logger);

	/* should never fail */
	CERTCertDBHandle *handle = CERT_GetDefaultCertDB();
	if (handle == NULL) {
		return PLUTO_EXIT_FAIL;
	}

	SECItem si = {
		.type = siBuffer,
		.data = blob.ptr,
		.len = blob.len,
	};

	CERTSignedCrl *crl = CERT_ImportCRL(handle, &si, url, SEC_CRL_TYPE, NULL);
	if (crl == NULL) {
		llog_nss_error(RC_LOG, logger, "import of CRL failed, ");
		return PLUTO_EXIT_FAIL;
	}

	llog_pem_bytes(RC_LOG|NO_PREFIX, logger, "NAME", crl->crl.derName.data, crl->crl.derName.len);

	free_chunk_content(&blob);

	SEC_DestroyCrl(crl);
	NSS_Shutdown();

	return 0;
}

/* globals */
deltatime_t crl_fetch_timeout;
char *curl_iface;
