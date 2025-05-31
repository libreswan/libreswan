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

#include "sparse_names.h"
#include "lswnss.h"
#include "defs.h"		/* for so_serial_t */
#include "log.h"
#include "show.h"

static bool enable_default_responder(CERTCertDBHandle *handle, struct logger *logger)
{
	SECStatus rv;
	ldbg(logger, "OCSP setting default responder url: %s trustname %s",
	     x509_ocsp.uri, x509_ocsp.trust_name);

	/* try to set the default responder */

	rv = CERT_SetOCSPDefaultResponder(handle, x509_ocsp.uri, x509_ocsp.trust_name);
	if (rv != SECSuccess) {
		int err = PORT_GetError();
		if (err == SEC_ERROR_UNKNOWN_CERT) {
			llog(RC_LOG, logger,
			     "NSS: OCSP: WARNING: could not set default responder ocsp-uri='%s', certificate ocsp-trustname='%s' unknown",
			     x509_ocsp.uri, x509_ocsp.trust_name);
			return false;
		}

		/* why not kill pluto? */
		/* uses global value */
		llog_nss_error(RC_LOG, logger,
			       "OCSP: WARNING: could not set default responder ocsp-uri='%s' ocsp-trustname='%s'",
			       x509_ocsp.uri, x509_ocsp.trust_name);
		return false;
	}

	/* try to enable default responder */

	ldbg(logger, "OCSP enabling default responder");

	rv = CERT_EnableOCSPDefaultResponder(handle);
	if (rv != SECSuccess) {
		int err = PORT_GetError();
		if (err == SEC_ERROR_OCSP_RESPONDER_CERT_INVALID) {
			/* why not kill pluto? */
			llog(RC_LOG, logger,
			     "NSS: OCSP: WARNING: could not enable default responder ocsp-uri='%s', certificate ocsp-trustname='%s' invalid, please verify its keyUsage extensions for OCSP",
			     x509_ocsp.uri, x509_ocsp.trust_name);
			return false;
		}

		/* why not kill pluto? */
		/* uses global value */
		llog_nss_error(RC_LOG, logger,
			       "OCSP: WARNING: could not enable default responder ocsp-uri='%s' ocsp-trustname='%s'",
			       x509_ocsp.uri, x509_ocsp.trust_name);
		return false;
	}

	return true;
}

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
		return diag_nss_error("OCSP: error enabling checking");
	}
	ldbg(logger, "NSS: OCSP started");

	/*
	 * enable a default responder
	 */
	if (x509_ocsp.uri != NULL && x509_ocsp.trust_name != NULL) {
		if (enable_default_responder(handle, logger)) {
			llog(RC_LOG, logger,
			     "NSS: OCSP: default responder ocsp-uri='%s' with ocsp-trustname='%s' enabled",
			     x509_ocsp.uri, x509_ocsp.trust_name);
		}
	} else if (x509_ocsp.uri != NULL) {
		llog(RC_LOG, logger,
		     "NSS: OCSP: WARNING: default responder invalid, ocsp-uri=%s requires ocsp-trustname=",
		     x509_ocsp.uri);
	} else if (x509_ocsp.trust_name != NULL) {
		llog(RC_LOG, logger,
		     "NSS: OCSP: WARNING: default responder invalid, ocsp-trustname=%s requires ocsp-uri=",
		     x509_ocsp.trust_name);
	}

	if (deltatime_cmp(x509_ocsp.timeout, >, deltatime_zero)) {
		ldbg(logger, "OCSP timeout of %ju seconds", deltasecs(x509_ocsp.timeout));
		if (CERT_SetOCSPTimeout(deltasecs(x509_ocsp.timeout)) != SECSuccess) {
			/* don't shoot pluto over this */
			llog_nss_error(RC_LOG, logger, "OCSP: WARNING: could not set ocsp-timeout=%ju",
				       deltasecs(x509_ocsp.timeout));
		}
	}

	if (x509_ocsp.strict) {
		rv = CERT_SetOCSPFailureMode(ocspMode_FailureIsVerificationFailure);
	} else {
		rv = CERT_SetOCSPFailureMode(ocspMode_FailureIsNotAVerificationFailure);
	}
	if (rv != SECSuccess) {
		return diag_nss_error("OCSP: error setting ocsp-strict=%s",
				      bool_str(x509_ocsp.strict));
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
		name_buf b;
		llog_nss_error(RC_LOG, logger, "OCSP: WARNING: could not set ocsp-method=%s",
			       str_sparse(&ocsp_method_names, x509_ocsp.method, &b));
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
			       "OCSP: WARNING: could not set cache parameters (ocsp-cache-size=%d, ocsp-cache-min-age=%s, ocsp-cache-max-age=%s)",
			       x509_ocsp.cache_size,
			       str_deltatime(x509_ocsp.cache_min_age, &minb),
			       str_deltatime(x509_ocsp.cache_max_age, &maxb));
	}

	return NULL;
}

void show_x509_ocsp(struct show *s)
{
	SHOW_JAMBUF(s, buf) {
		jam(buf, "ocsp-enable=%s", bool_str(x509_ocsp.enable));
		jam_string(buf, ", ");
		jam(buf, "ocsp-strict=%s", bool_str(x509_ocsp.strict));
		jam_string(buf, ", ");
		jam(buf, "ocsp-timeout=");
		jam_deltatime(buf, x509_ocsp.timeout);
	}

	SHOW_JAMBUF(s, buf) {
		jam_string(buf, "ocsp-uri=");
		jam_string(buf, (x509_ocsp.uri != NULL ? x509_ocsp.uri : "<unset>"));
		jam_string(buf, ", ");
		jam_string(buf, "ocsp-trust-name=");
		jam_string(buf, (x509_ocsp.trust_name != NULL ? x509_ocsp.trust_name : "<unset>"));
	}

	SHOW_JAMBUF(s, buf) {
		jam(buf, "ocsp-cache-size=%d", x509_ocsp.cache_size);
		jam_string(buf, ", ocsp-cache-min-age=");
		jam_deltatime(buf, x509_ocsp.cache_min_age);
		jam_string(buf, ", ocsp-cache-max-age=");
		jam_deltatime(buf, x509_ocsp.cache_max_age);
		jam_string(buf, ", ocsp-method=");
		jam_sparse(buf, &ocsp_method_names, x509_ocsp.method);
	}
}

struct x509_ocsp_config x509_ocsp = {0};
