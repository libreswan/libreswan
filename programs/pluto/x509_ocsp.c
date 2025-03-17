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
	if (ocsp_uri != NULL && ocsp_trust_name != NULL) {
		dbg("OCSP default responder url: %s", ocsp_uri);
		dbg("OCSP responder cert NSS nickname: %s", ocsp_trust_name);

		rv = CERT_SetOCSPDefaultResponder(handle, ocsp_uri,
							  ocsp_trust_name);


		if (rv == SECSuccess) {
			rv = CERT_EnableOCSPDefaultResponder(handle);
			if (rv != SECSuccess) {
				int err = PORT_GetError();
				if (err == SEC_ERROR_OCSP_RESPONDER_CERT_INVALID) {
					llog(RC_LOG, logger,
					     "responder certificate %s is invalid. please verify its keyUsage extensions for OCSP",
					     ocsp_trust_name);
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
				     ocsp_trust_name);
			} else {
				/* uses global value */
				llog_nss_error(RC_LOG, logger, "error setting default responder");
			}
		}
	}

	if (deltatime_cmp(ocsp_timeout, >, deltatime_zero)) {
		dbg("OCSP timeout of %ju seconds", deltasecs(ocsp_timeout));
		if (CERT_SetOCSPTimeout(deltasecs(ocsp_timeout)) != SECSuccess) {
			/* don't shoot pluto over this */
			llog_nss_error(RC_LOG, logger, "error setting OCSP timeout to %ju", deltasecs(ocsp_timeout));
		}
	}

	if (ocsp_strict) {
		rv = CERT_SetOCSPFailureMode(ocspMode_FailureIsVerificationFailure);
	} else {
		rv = CERT_SetOCSPFailureMode(ocspMode_FailureIsNotAVerificationFailure);
	}

	if (rv != SECSuccess) {
		return diag_nss_error("error setting OCSP failure mode");
	}

	switch (ocsp_method) {
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
	int nss_max = deltasecs(ocsp_cache_max_age);
	if (nss_max == 0) {
		nss_max = -1;
	}

	rv = CERT_OCSPCacheSettings(ocsp_cache_size, deltasecs(ocsp_cache_min_age), nss_max);
	if (rv != SECSuccess) {
		/* don't shoot pluto over this */
		deltatime_buf minb, maxb;
		llog_nss_error(RC_LOG, logger,
			       "error setting OCSP cache parameters (size=%d, min=%s, max=%s)",
			       ocsp_cache_size,
			       str_deltatime(ocsp_cache_min_age, &minb),
			       str_deltatime(ocsp_cache_max_age, &maxb));
	}

	return NULL;
}


char *ocsp_uri = NULL;
char *ocsp_trust_name = NULL;
deltatime_t ocsp_timeout = DELTATIME_INIT(OCSP_DEFAULT_TIMEOUT);
enum ocsp_method ocsp_method = OCSP_METHOD_GET;
int ocsp_cache_size = OCSP_DEFAULT_CACHE_SIZE;
deltatime_t ocsp_cache_min_age = DELTATIME_INIT(OCSP_DEFAULT_CACHE_MIN_AGE);
deltatime_t ocsp_cache_max_age = DELTATIME_INIT(OCSP_DEFAULT_CACHE_MAX_AGE);
bool ocsp_strict = false;
bool ocsp_enable = false;
