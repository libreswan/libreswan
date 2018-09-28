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

#include "lswlog.h"
#include "x509.h"
#include "nss_err.h"
#include "nss_ocsp.h"
/* NSS needs */
#include <secerr.h>
#include <ocsp.h>

/* note: returning FALSE here means pluto die! */
bool init_nss_ocsp(const char *responder_url, const char *trust_cert_name,
		      int timeout, bool strict, int cache_size,
			int cache_min, int cache_max, bool ocsp_post)
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
		loglog(RC_LOG_SERIOUS, "NSS error enabling OCSP checking: %s",
				       nss_err_str(PORT_GetError()));
		return FALSE;
	}
	DBG(DBG_X509, DBG_log("NSS OCSP checking enabled"));

	/*
	 * enable a default responder
	 */
	if (responder_url != NULL && trust_cert_name != NULL) {
		DBG(DBG_X509, DBG_log("OCSP default responder url: %s",
					 responder_url));
		DBG(DBG_X509, DBG_log("OCSP responder cert NSS nickname: %s",
					 trust_cert_name));

		rv = CERT_SetOCSPDefaultResponder(handle, responder_url,
							  trust_cert_name);


		if (rv == SECSuccess) {
			rv = CERT_EnableOCSPDefaultResponder(handle);
			if (rv != SECSuccess) {
				int err = PORT_GetError();

				if (err == SEC_ERROR_OCSP_RESPONDER_CERT_INVALID) {
					loglog(RC_LOG_SERIOUS, "responder certificate %s is invalid. please verify its keyUsage extensions for OCSP",
								trust_cert_name);
				} else {
					loglog(RC_LOG_SERIOUS, "NSS error enabling OCSP default responder: %s", nss_err_str(err));
				}
			}
		} else {
			int err = PORT_GetError();

			if (err == SEC_ERROR_UNKNOWN_CERT) {
				libreswan_log("OCSP responder cert \"%s\" not found in NSS",
						 trust_cert_name);
			} else {
				libreswan_log("NSS error setting default responder: %s", nss_err_str(err));
			}
		}
	}

	if (timeout != 0) {
		DBG(DBG_X509, DBG_log("OCSP timeout of %d seconds",
					 timeout));
		if (CERT_SetOCSPTimeout(timeout) != SECSuccess) {
			/* don't shoot pluto over this */
			loglog(RC_LOG_SERIOUS, "NSS error setting OCSP timeout: %s",
						nss_err_str(PORT_GetError()));
		}
	}

	if (strict)
		rv = CERT_SetOCSPFailureMode(ocspMode_FailureIsVerificationFailure);
	else
		rv = CERT_SetOCSPFailureMode(ocspMode_FailureIsNotAVerificationFailure);

	if (rv != SECSuccess) {
		loglog(RC_LOG_SERIOUS, "NSS error setting OCSP failure mode: %s",
					nss_err_str(PORT_GetError()));
		return FALSE;
	}

	if (ocsp_post)
		rv = CERT_ForcePostMethodForOCSP(TRUE);
	else
		rv = CERT_ForcePostMethodForOCSP(FALSE);

	if (rv != SECSuccess) {
		/* don't shoot pluto over this */
		loglog(RC_LOG_SERIOUS, "NSS error enabling OCSP POST method: %s",
				       nss_err_str(PORT_GetError()));
	}

	/*
	 * NSS uses 0 for unlimited and -1 for disabled. We use 0 for disabled
	 * and just a large number for a large cache
	 */
	if (cache_max == 0)
		cache_max = -1;

	rv = CERT_OCSPCacheSettings(cache_size, cache_min, cache_max);
	if (rv != SECSuccess) {
		/* don't shoot pluto over this */
		loglog(RC_LOG_SERIOUS, "NSS error setting OCSP cache parameters (size=%d, min=%d, max=%d): %s",
			 cache_size, cache_min, cache_max,
			 nss_err_str(PORT_GetError()));
	}

	return TRUE;
}
