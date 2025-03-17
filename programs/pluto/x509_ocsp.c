/* OCSP initialization for NSS
 *
 * Copyright (C) 2015 Matt Rogers <mrogers@libreswan.org>
 * Copyright (C) 2016 Paul Wouters <pwouters@redhat.com>
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

#include "x509_ocsp.h"
#include "x509.h"

/* NSS needs */
#include <secerr.h>
#include <ocsp.h>

#include "lswnss.h"
#include "defs.h"		/* for so_serial_t */
#include "log.h"

/* note: returning a diag is fatal! */
diag_t init_x509_ocsp(struct logger *logger)
{
	SECStatus rv;

	/*
	 * CERT_GetDefaultCertDB() simply returns the contents of a
	 * static variable set by NSS_Initialize().  It doesn't check
	 * the value and doesn't set PR error.  Short of calling
	 * CERT_SetDefaultCertDB(NULL), the value can never be NULL.
	 */
	CERTCertDBHandle *handle = CERT_GetDefaultCertDB();
	passert(handle != NULL);

	rv = CERT_EnableOCSPChecking(handle);
	if (rv != SECSuccess) {
		return diag_nss_error("error enabling OCSP checking");
	}
	dbg("NSS OCSP checking enabled");

	/*
	 * enable a default responder
	 */
	if (x509_ocsp.uri != NULL && x509_ocsp.trust_name != NULL) {
		dbg("OCSP default responder url: %s", x509_ocsp.uri);
		dbg("OCSP responder cert NSS nickname: %s", x509_ocsp.trust_name);

		rv = CERT_SetOCSPDefaultResponder(handle, x509_ocsp.uri,
							  x509_ocsp.trust_name);


		if (rv == SECSuccess) {
			rv = CERT_EnableOCSPDefaultResponder(handle);
			if (rv != SECSuccess) {
				int err = PORT_GetError();
				if (err == SEC_ERROR_OCSP_RESPONDER_CERT_INVALID) {
					llog(RC_LOG, logger,
					     "responder certificate %s is invalid. please verify its keyUsage extensions for OCSP",
					     x509_ocsp.trust_name);
				} else {
					llog_nss_error(RC_LOG, logger,
						       "error enabling OCSP default responder");
				}
			}
		} else {
			int err = PORT_GetError();
			if (err == SEC_ERROR_UNKNOWN_CERT) {
				llog(RC_LOG, logger,
				     "OCSP responder cert \"%s\" not found in NSS",
				     x509_ocsp.trust_name);
			} else {
				/* uses global value */
				llog_nss_error(RC_LOG, logger, "error setting default responder");
			}
		}
	}

	if (deltatime_cmp(x509_ocsp.timeout, >, deltatime_zero)) {
		dbg("OCSP timeout of %ju seconds", deltasecs(x509_ocsp.timeout));
		if (CERT_SetOCSPTimeout(deltasecs(x509_ocsp.timeout)) != SECSuccess) {
			/* don't shoot pluto over this */
			llog_nss_error(RC_LOG, logger, "error setting OCSP timeout to %ju", deltasecs(x509_ocsp.timeout));
		}
	}

	if (x509_ocsp.strict) {
		rv = CERT_SetOCSPFailureMode(ocspMode_FailureIsVerificationFailure);
	} else {
		rv = CERT_SetOCSPFailureMode(ocspMode_FailureIsNotAVerificationFailure);
	}

	if (rv != SECSuccess) {
		return diag_nss_error("error setting OCSP failure mode");
	}

	switch (x509_ocsp.method) {
	case OCSP_METHOD_POST:
		rv = CERT_ForcePostMethodForOCSP(true);
		ldbg(logger, "OCSP will use POST method");
		break;
	case OCSP_METHOD_GET:
		rv = CERT_ForcePostMethodForOCSP(false);
		ldbg(logger, "OCSP will use GET method");
		break;
	}

	if (rv != SECSuccess) {
		/* don't shoot pluto over this */
		llog_nss_error(RC_LOG, logger, "error enabling OCSP POST method");
	}

	/*
	 * NSS uses 0 for unlimited and -1 for disabled. We use 0 for
	 * disabled and just a large number for a large cache.
	 */
	int nss_max = deltasecs(x509_ocsp.cache_max_age);
	if (nss_max == 0) {
		nss_max = -1;
	}

	rv = CERT_OCSPCacheSettings(x509_ocsp.cache_size, deltasecs(x509_ocsp.cache_min_age), nss_max);
	if (rv != SECSuccess) {
		/* don't shoot pluto over this */
		deltatime_buf minb, maxb;
		llog_nss_error(RC_LOG, logger,
			       "error setting OCSP cache parameters (size=%d, min=%s, max=%s)",
			       x509_ocsp.cache_size,
			       str_deltatime(x509_ocsp.cache_min_age, &minb),
			       str_deltatime(x509_ocsp.cache_max_age, &maxb));
	}

	return NULL;
}

struct x509_ocsp_config x509_ocsp = {
	.uri = NULL,
	.trust_name = NULL,
	.timeout = DELTATIME_INIT(OCSP_DEFAULT_TIMEOUT),
	.method = OCSP_METHOD_GET,
	.cache_size = OCSP_DEFAULT_CACHE_SIZE,
	.cache_min_age = DELTATIME_INIT(OCSP_DEFAULT_CACHE_MIN_AGE),
	.cache_max_age = DELTATIME_INIT(OCSP_DEFAULT_CACHE_MAX_AGE),
	.strict = false,
	.enable = false,
};
