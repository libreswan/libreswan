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

#include "import_crl.h"

#include "config_setup.h"
#include "lswnss.h"
#include "lswtool.h"
#include "lswalloc.h"
#include "lswlog.h"		/* for fatal() */
#include "pem.h"

static err_t fetch_blob(const char *url, time_t timeout, chunk_t *blob,
			struct verbose verbose)
{
	vdbg("fetching %s with timeout %ld", url, (long)timeout);
	verbose.level++;
#ifdef USE_LDAP
	if (startswith(url, "ldap:")) {
		return fetch_ldap(url, timeout, blob, verbose);
	}
#endif
#ifdef USE_LIBCURL
	return fetch_curl(url, timeout, blob, verbose);
#endif
	return "build is not configured with CRL support";
}

static err_t decode_blob(chunk_t *blob, struct verbose verbose)
{
	vdbg("decoding %zu byte blob", blob->len);
	verbose.level++;

	err_t ugh = asn1_ok(ASN1(*blob));
	if (ugh == NULL) {
		vdbg("fetched blob already DER");
		return NULL;
	}

	vdbg("fetched blob is not DER: %s", ugh);
	ugh = pemtobin(blob);
	if (ugh != NULL) {
		vdbg("fetched blob is not PEM: %s", ugh);
		return ugh;
	}

	vdbg("fetched blob is PEM");
	ugh = asn1_ok(ASN1(*blob));
	if (ugh != NULL) {
		vdbg("fetched blob in PEM format does not contain DER: %s", ugh);
		return ugh;
	}

	if (blob->len == 0) {
		ugh = "empty ASN.1 blob";
	}

	return NULL;
}

/*
 * _import_crl <url> <der size>
 * the der blob is passed through STDIN from pluto's fork
 */
int main(int argc, char *argv[])
{
	err_t err;
	struct logger *logger = tool_logger(argc, argv);
	struct verbose verbose = VERBOSE(DEBUG_STREAM, logger, "");
	vdbg("%s:", argv[0]);

	if (argc != 4) {
		fatal(PLUTO_EXIT_FAIL, logger, "expecting: <url> <crl-fetch-timeout> <curl-iface>");
	}

	/* lazy parsing, assume pluto isn't broken */
	char *url = argv[1];
	time_t timeout = atol(argv[2]);
	curl_iface = (argv[3][0] == '\0' ? NULL : argv[3]);

	chunk_t blob = NULL_HUNK;
	err = fetch_blob(url, timeout, &blob, verbose);
	if (err != NULL) {
		fatal(PLUTO_EXIT_FAIL, logger, "fetch failed: %s", err);
	}

	err = decode_blob(&blob, verbose);
	if (err != NULL) {
		free_chunk_content(&blob);
		fatal(PLUTO_EXIT_FAIL, logger, "fetch invalid: %s", err);
	}

	init_nss(config_setup_nssdir(), (struct nss_flags){0}, logger);

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
char *curl_iface;
