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

#include "x509.h"
#include "nss_ocsp.h"
/* NSS needs */
#include <secerr.h>
#include <ocsp.h>

#include "lswnss.h"
#include "defs.h"		/* for so_serial_t */
#include "log.h"

/* note: returning a diag is fatal! */
diag_t init_nss_ocsp(const char *responder_url, const char *trust_cert_name,
		     int timeout, bool strict, int cache_size,
		     deltatime_t cache_min, deltatime_t cache_max,
		     bool ocsp_post, struct logger *logger)
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
	if (responder_url != NULL && trust_cert_name != NULL) {
		dbg("OCSP default responder url: %s", responder_url);
		dbg("OCSP responder cert NSS nickname: %s", trust_cert_name);

		rv = CERT_SetOCSPDefaultResponder(handle, responder_url,
							  trust_cert_name);


		if (rv == SECSuccess) {
			rv = CERT_EnableOCSPDefaultResponder(handle);
			if (rv != SECSuccess) {
				int err = PORT_GetError();
				if (err == SEC_ERROR_OCSP_RESPONDER_CERT_INVALID) {
					llog(RC_LOG_SERIOUS, logger,
						    "responder certificate %s is invalid. please verify its keyUsage extensions for OCSP",
						    trust_cert_name);
				} else {
					llog_nss_error(RC_LOG_SERIOUS, logger,
						       "error enabling OCSP default responder");
				}
			}
		} else {
			int err = PORT_GetError();
			if (err == SEC_ERROR_UNKNOWN_CERT) {
				llog(RC_LOG, logger,
					    "OCSP responder cert \"%s\" not found in NSS",
					    trust_cert_name);
			} else {
				/* uses global value */
				llog_nss_error(RC_LOG, logger, "error setting default responder");
			}
		}
	}

	if (timeout != 0) {
		dbg("OCSP timeout of %d seconds", timeout);
		if (CERT_SetOCSPTimeout(timeout) != SECSuccess) {
			/* don't shoot pluto over this */
			llog_nss_error(RC_LOG_SERIOUS, logger, "error setting OCSP timeout");
		}
	}

	if (strict) {
		rv = CERT_SetOCSPFailureMode(ocspMode_FailureIsVerificationFailure);
	} else {
		rv = CERT_SetOCSPFailureMode(ocspMode_FailureIsNotAVerificationFailure);
	}

	if (rv != SECSuccess) {
		return diag_nss_error("error setting OCSP failure mode");
	}

	if (ocsp_post) {
		rv = CERT_ForcePostMethodForOCSP(true);
		dbg("OCSP will use POST method");
	} else {
		rv = CERT_ForcePostMethodForOCSP(false);
	}

	if (rv != SECSuccess) {
		/* don't shoot pluto over this */
		llog_nss_error(RC_LOG_SERIOUS, logger, "error enabling OCSP POST method");
	}

	/*
	 * NSS uses 0 for unlimited and -1 for disabled. We use 0 for disabled
	 * and just a large number for a large cache
	 */
	unsigned nss_max = deltasecs(cache_max);
	if (nss_max == 0) {
		nss_max = -1;
	}

	rv = CERT_OCSPCacheSettings(cache_size, deltasecs(cache_min), nss_max);
	if (rv != SECSuccess) {
		/* don't shoot pluto over this */
		deltatime_buf minb, maxb;
		llog_nss_error(RC_LOG_SERIOUS, logger,
			       "error setting OCSP cache parameters (size=%d, min=%s, max=%s)",
			       cache_size,
			       str_deltatime(cache_min, &minb),
			       str_deltatime(cache_max, &maxb));
	}

	return NULL;
}
