/* OCSP initialization for NSS
 *
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
 *
 */

#include "lswlog.h"
#include "x509.h"
#include "nss_ocsp.h"
/* NSS needs */
#include <secerr.h>
#include <ocsp.h>

bool init_nss_ocsp(const char *responder_url, const char *trust_cert_name,
					      int timeout,
					      bool strict)
{
	CERTCertDBHandle *handle = CERT_GetDefaultCertDB();
	if (handle == NULL) {
		DBG(DBG_CONTROL, DBG_log("NSS error getting db handle [%d]",
					  PORT_GetError()));
		return FALSE;
	}

	SECStatus rv = CERT_EnableOCSPChecking(handle);
	if (rv != SECSuccess) {
		DBG(DBG_CONTROL, DBG_log("NSS error enabling OCSP checking [%d]",
					 PORT_GetError()));
		return FALSE;
	}

	/*
	 * enable a default responder
	 */
	if (responder_url != NULL && trust_cert_name != NULL) {
		DBG(DBG_CONTROL, DBG_log("OCSP default responder url: %s",
					 responder_url));
		DBG(DBG_CONTROL, DBG_log("OCSP responder cert NSS nickname: %s",
					 trust_cert_name));

		rv = CERT_SetOCSPDefaultResponder(handle, responder_url,
							  trust_cert_name);
		if (rv != SECSuccess) {
			int err = PORT_GetError();

			if (err == SEC_ERROR_UNKNOWN_CERT) {
				DBG(DBG_CONTROL, DBG_log("OCSP responder cert \"%s\" not found in NSS",
							 trust_cert_name));
			} else {
				DBG(DBG_CONTROL, DBG_log("NSS error setting default responder [%d]",err));
			}
			goto responder_done;
		}
		rv = CERT_EnableOCSPDefaultResponder(handle);
		if (rv != SECSuccess) {
			int err = PORT_GetError();
			/*
			 * There are more of these that should be warned about
			 */
			if (err == SEC_ERROR_OCSP_RESPONDER_CERT_INVALID) {
				DBG(DBG_CONTROL, DBG_log("responder certificate %s is invalid. please verify its keyUsage extensions for OCSP",
							 trust_cert_name));
			} else {
				DBG(DBG_CONTROL, DBG_log("NSS error enabling default responder [%d]",err));
			}
		}
	}
responder_done:
	if (timeout != 0) {
		DBG(DBG_CONTROL, DBG_log("OCSP timeout of %d seconds",
					 timeout));
		if (CERT_SetOCSPTimeout(timeout) != SECSuccess) {
			DBG(DBG_CONTROL, DBG_log("NSS error setting timeout [%d]",
					PORT_GetError()));
			return FALSE;
		}
	}

	/*
	 * set failure mode
	 */
	if (strict) {
		if (CERT_SetOCSPFailureMode(
				  ocspMode_FailureIsVerificationFailure) !=
						SECSuccess) {
			DBG(DBG_CONTROL, DBG_log("NSS error setting OCSP failure mode [%d]",
					PORT_GetError()));
			return FALSE;
		}
	} else {
		if (CERT_SetOCSPFailureMode(
				  ocspMode_FailureIsNotAVerificationFailure) !=
						SECSuccess) {
			DBG(DBG_CONTROL, DBG_log("NSS error setting OCSP failure mode [%d]",
					PORT_GetError()));
			return FALSE;
		}
	}
	return TRUE;
}
