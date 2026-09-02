/* NSS certificate verification routines for libreswan
 *
 * Copyright (C) 2015,2018 Matt Rogers <mrogers@libreswan.org>
 * Copyright (C) 2017-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2018-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 D. Hugh Redelmeier <hugh@mimosa.com>
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>
#include <limits.h>
#include <sys/types.h>

#include "sysdep.h"
#include "lswnss.h"
#include "constants.h"
#include "x509.h"
#include "nss_cert_verify.h"
#include "fips_mode.h" /* for is_fips_mode() */
#include "certs.h"
#include <secder.h>
#include <secerr.h>
#include <certdb.h>
#include <keyhi.h>
#include <secpkcs7.h>
#include "demux.h"
#include "state.h"
#include "pluto_timing.h"
#include "root_certs.h"
#include "ip_info.h"
#include "log.h"
#include "log_limiter.h"
#include "x509_ocsp.h"
#include "x509_crl.h"		/* for crl_strict; */

bool groundhogday;

static bool crl_is_current(CERTSignedCrl *crl)
{
	return SEC_CheckCrlTimes(&crl->crl, PR_Now()) != secCertTimeExpired;
}

static bool cert_issuer_has_current_crl(CERTCertDBHandle *handle,
					CERTCertificate *cert,
					struct logger *logger)
{
	if (!PEXPECT(logger, handle != NULL) ||
	    !PEXPECT(logger, cert != NULL)) {
		return false;
	}

	ldbg(logger, "%s: looking for a CRL issued by %s",
	     __func__, cert->issuerName);

	/*
	 * Use SEC_LookupCrls method instead of SEC_FindCrlByName.
	 * For some reason, SEC_FindCrlByName was giving out bad pointers!
	 *
	 * crl = (CERTSignedCrl *)SEC_FindCrlByName(handle, &searchName, SEC_CRL_TYPE);
	 */
	CERTCrlHeadNode *crl_list = NULL;

	if (SEC_LookupCrls(handle, &crl_list, SEC_CRL_TYPE) != SECSuccess) {
		return false;
	}

	bool current = false;

	for (CERTCrlNode *crl_node = crl_list->first; crl_node != NULL;
	     crl_node = crl_node->next) {
		CERTSignedCrl *crl = crl_node->crl;
		if (crl != NULL &&
		    SECITEM_ItemsAreEqual(&cert->derIssuer, &crl->crl.derName)) {
			current = crl_is_current(crl);
			ldbg(logger, "%s: %s CRL found",
			     __func__, current ? "current" : "expired");
			break;
		}
	}

	PORT_FreeArena(crl_list->arena, PR_FALSE);
	return current;
}

static void log_bad_cert(struct logger *logger, const char *prefix,
			 const char *usage, CERTVerifyLogNode *head)
{
	/*
	 * Usually there is only one error in the list, but sometimes
	 * there are several.
	 *
	 * ??? When there are several, they (often? always?) seem to be
	 *     duplicates, so we filter.
	 */
	const char *last_sn = NULL;
	long last_error = 0;

	for (CERTVerifyLogNode *node = head; node != NULL; node = node->next) {
		if (last_sn != NULL && streq(last_sn, node->cert->subjectName) &&
		    last_error == node->error)
			continue;	/* duplicate error */

		last_sn = node->cert->subjectName;
		last_error = node->error;
		/* ??? we ignore node->depth and node->arg */
		llog_nss_error_code(RC_LOG, logger, node->error,
				    "%s: %s certificate %s invalid",
				    prefix, usage, node->cert->subjectName);
	}
}

static void set_rev_per_meth(CERTRevocationFlags *rev, PRUint64 *lflags,
						       PRUint64 *cflags)
{
	rev->leafTests.cert_rev_flags_per_method = lflags;
	rev->chainTests.cert_rev_flags_per_method = cflags;
}

static unsigned int rev_val_flags(void)
{
	unsigned int flags = CERT_REV_M_TEST_USING_THIS_METHOD;

	if (x509_ocsp.strict) {
		flags |= CERT_REV_M_REQUIRE_INFO_ON_MISSING_SOURCE;
		flags |= CERT_REV_M_FAIL_ON_MISSING_FRESH_INFO;
	}

	if (x509_ocsp.method == OCSP_METHOD_POST) {
		flags |= CERT_REV_M_FORCE_POST_METHOD_FOR_OCSP;
	}
	return flags;
}

static void set_rev_params(CERTRevocationFlags *rev, struct logger *logger)
{
	CERTRevocationTests *rt = &rev->leafTests;
	PRUint64 *rf = rt->cert_rev_flags_per_method;
	name_buf omb;
	ldbg(logger, "crl_strict: %s, ocsp: %s, ocsp_strict: %s, ocsp_post: %s",
	     bool_str(x509_crl.strict),
	     bool_str(x509_ocsp.enable),
	     bool_str(x509_ocsp.strict),
	     str_sparse_long(&ocsp_method_names, x509_ocsp.method, &omb));

	rt->number_of_defined_methods = cert_revocation_method_count;
	rt->number_of_preferred_methods = 0;

	rf[cert_revocation_method_crl] |= CERT_REV_M_TEST_USING_THIS_METHOD;
	rf[cert_revocation_method_crl] |= CERT_REV_M_FORBID_NETWORK_FETCHING;

	if (x509_ocsp.enable) {
		rf[cert_revocation_method_ocsp] = rev_val_flags();
	}
}

/* SEC_ERROR_INADEQUATE_CERT_TYPE etc.: /usr/include/nss3/secerr.h */

#define RETRYABLE_TYPE(err) ((err) == SEC_ERROR_INADEQUATE_CERT_TYPE || \
			      (err) == SEC_ERROR_INADEQUATE_KEY_USAGE)

static bool verify_end_cert(struct logger *logger,
			    const CERTCertList *trustcl,
			    PRTime groundhogtime,
			    CERTCertificate *end_cert)
{
	CERTRevocationFlags rev;
	zero(&rev);	/* ??? are there pointer fields?  YES, and different for different union members! */

	PRUint64 revFlagsLeaf[2] = { 0, 0 };
	PRUint64 revFlagsChain[2] = { 0, 0 };

	set_rev_per_meth(&rev, revFlagsLeaf, revFlagsChain);
	set_rev_params(&rev, logger);

	ldbg(logger, "groundhogtime is %ju", (uintmax_t)groundhogtime);

	CERTValInParam cvin[] = {
		{
			.type = cert_pi_revocationFlags,
			.value = { .pointer = { .revocation = &rev } }
		},
		{
			.type = cert_pi_useAIACertFetch,
			.value = { .scalar = { .b = x509_ocsp.enable ? PR_TRUE : PR_FALSE } }
		},
		{
			.type = cert_pi_trustAnchors,
			.value = { .pointer = { .chain = trustcl, } }
		},
		{
			.type = cert_pi_useOnlyTrustAnchors,
			.value = { .scalar = { .b = PR_TRUE } }
		},
		{
			.type = cert_pi_date,
			.value.scalar.time = groundhogtime,
		},
		{
			.type = cert_pi_end
		}
	};

	struct usage_desc {
		SECCertificateUsage usage;
		const char *usageName;
	};

	static const struct usage_desc usages[] = {
		{ certificateUsageIPsec, "IPsec" },
#ifdef USE_NSS_TLS_SECURITY_PROFILE
		{ certificateUsageSSLClient, "TLS Client" },
		{ certificateUsageSSLServer, "TLS Server" }
#endif
	};

	if (LDBGP(DBG_BASE, logger)) {
		LDBG_log(logger, "%s verifying %s using:", __func__, end_cert->subjectName);
		unsigned nr = 0;
		for (CERTCertListNode *node = CERT_LIST_HEAD(trustcl);
		     !CERT_LIST_END(node, trustcl);
		     node = CERT_LIST_NEXT(node)) {
			LDBG_log(logger, "  trusted CA: %s", node->cert->subjectName);
			nr++;
		}
		if (nr == 0) {
			LDBG_log(logger, "  but have no trusted CAs");
		}
	}

	bool keep_trying = true;
	for (unsigned pi = 0; pi < elemsof(usages) && keep_trying; pi++) {
		const struct usage_desc *p = &usages[pi];
		ldbg(logger, "verify_end_cert trying profile %s", p->usageName);

		/*
		 * WARNING: cvout[] points at cvout_error_log.  Both vfy_log's
		 * arena and cvout[1].value.pointer.chan need to be
		 * freed (and the latter is messy).
		 */
		enum cvout_param {
			cvout_errorLog,
			cvout_end,
		};
		CERTVerifyLog cvout_error_log = {
			.count = 0,
			.head = NULL,
			.tail = NULL,
			.arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE), /* must-"free" */
		};
		CERTValOutParam cvout[] = {
			[cvout_errorLog] = {
				.type = cert_po_errorLog,
				.value = { .pointer = { .log = &cvout_error_log } }
			},
			[cvout_end] = {
				.type = cert_po_end,
			}
		};

		SECStatus rv = CERT_PKIXVerifyCert(end_cert, p->usage, cvin, cvout, NULL);

		if (rv == SECSuccess) {
			/* success! */
			PEXPECT(logger, (cvout_error_log.count == 0 &&
					 cvout_error_log.head == NULL));
			PORT_FreeArena(cvout_error_log.arena, PR_FALSE);
			ldbg(logger, "certificate is valid (profile %s)", p->usageName);
			return true;
		}

		/*
		 * Deal with failure; log; cleanup; and maybe try
		 * again!
		 */
		PEXPECT(logger, rv == SECFailure);
		/* XXX: cvout_error_log.head can be NULL */

		/*
		 * The (error) log can have more than one entry
		 * but we only test the first with RETRYABLE_TYPE.
		 */
		if (pi == elemsof(usages) - 1) {
			/* none left */
			log_bad_cert(logger, "ERROR", p->usageName, cvout_error_log.head);
			keep_trying = false; /* technically redundant */
		} else if (cvout_error_log.head != NULL &&
			   !RETRYABLE_TYPE(cvout_error_log.head->error)) {
			/* we are a conclusive failure */
			log_bad_cert(logger, "ERROR", p->usageName, cvout_error_log.head);
			keep_trying = false;
		} else {
			/*
			 * This usage failed: prepare to repeat for
			 * the next one.
			 */
			log_bad_cert(logger, "warning", p->usageName,  cvout_error_log.head);
		}

		PORT_FreeArena(cvout_error_log.arena, PR_FALSE);
	}

	return false;
}

/*
 * check if any of the certificates have an outdated CRL.
 *
 * XXX: Why isn't NSS doing this for us?
 */
static bool crl_update_check(CERTCertDBHandle *handle,
			     struct certs *certs,
			     struct logger *logger)
{
	for (struct certs *entry = certs; entry != NULL;
	     entry = entry->next) {
		if (!cert_issuer_has_current_crl(handle, entry->cert, logger)) {
			return true;
		}
	}
	return false;
}

/*
 * Does a temporary import of the DER certificate an appends it to the
 * CERTS array.
 */

static void add_decoded_cert_1(struct certs **certs,
			       struct logger *logger,
			       CERTCertificate *cert);

static void add_decoded_cert(CERTCertDBHandle *handle,
			     struct certs **certs,
			     SECItem der_cert,
			     struct logger *logger)
{
	/*
	 * Reject root certificates.
	 *
	 * XXX: Since NSS implements this by decoding the certificate
	 * using CERT_DecodeDERCertificate(), examining, and then
	 * deleting the certificate it isn't the most efficient (it
	 * means decoding the certificate twice).  On the other hand
	 * it does keep the certificate well away from the certificate
	 * database (although it isn't clear if this is really a
	 * problem?).  And it is what NSS does internally - first
	 * check the certificate and then call
	 * CERT_NewTempCertificate().  Presumably the decode operation
	 * is considered "cheap".
	 */
	if (CERT_IsRootDERCert(&der_cert)) {
		ldbg(logger, "ignoring root certificate");
		return;
	}

	/*
	 * Import the cert into temporary storage.
	 *
	 * CERT_NewTempCertificate() calls *FindOrImport*() which,
	 * presumably, checks for an existing certificate and returns
	 * that if it is found.
	 *
	 * However, unlike CERT_ImportCerts() it doesn't do extra
	 * hashing.
	 *
	 * NSS's vfrychain.c makes for interesting reading.
	 *
	 * XXX: must-delref
	 */
	CERTCertificate *cert = CERT_NewTempCertificate(handle, &der_cert,
							NULL /*nickname*/,
							PR_FALSE /*isperm*/,
							PR_TRUE /* copyDER */);
	if (cert == NULL) {
		/*
		 * XXX: need to log something here.
		 *
		 * When the certificate payload is rejected pluto
		 * stumbles on, only to eventually reject the peer's
		 * auth for some for some seamingly unrelated reason.
		 */
		llog_nss_error(RC_LOG, logger,
			       "decoding certificate payload using CERT_NewTempCertificate() failed");
		if (PR_GetError() == SEC_ERROR_REUSED_ISSUER_AND_SERIAL) {
			enum stream stream = log_limiter_stream(logger, CERTIFICATE_LOG_LIMITER);
			if (stream != NO_STREAM) {
				llog_pem_bytes(stream, logger, "CERTIFICATE", der_cert.data, der_cert.len);
			}
		}
		return;
	}
	ldbg(logger, "decoded cert: %s", cert->subjectName);

	add_decoded_cert_1(certs, logger, cert); /* adds ref when needed */
	CERT_DestroyCertificate(cert); /* local reference */
}

static void add_decoded_cert_1(struct certs **certs,
			       struct logger *logger,
			       CERTCertificate *cert)
{
	/*
	 * Currently only a check for RSA is needed, as the only ECDSA
	 * key size not allowed in FIPS mode (p192 curve), is not
	 * implemented by NSS.
	 *
	 * XXX: While NSS should be the one making this check, as of
	 * 2026-08 and version 3.125, NSS allows undersized certs in
	 * FIPS mode.
	 *
	 * See also RSA_secret_sane() and ECDSA_secret_sane()
	 */
	if (is_fips_mode()) {
		SECKEYPublicKey *pk = CERT_ExtractPublicKey(cert);
		if (pk == NULL) {
			llog_nss_error(RC_LOG, logger,
				       "extracting certificate public key using CERT_ExtractPublicKey() failed");
			return;
		}

		if (pk->keyType == rsaKey) {
			unsigned key_bit_size = pk->u.rsa.modulus.len * BITS_IN_BYTE;
			if (key_bit_size < FIPS_MIN_RSA_KEY_SIZE) {
				llog(RC_LOG, logger,
				     "FIPS: rejecting peer cert with key size %u under %u: %s",
				     key_bit_size, FIPS_MIN_RSA_KEY_SIZE,
				     cert->subjectName);
				SECKEY_DestroyPublicKey(pk);
				return;
			}
		}
		SECKEY_DestroyPublicKey(pk);
	}

	/*
	 * Add a reference to the certificate to the CERTS array.
	 */
	add_cert(certs, cert);
}

/*
 * Decode the cert payloads creating a list of temp certificates.
 */
static struct certs *decode_cert_payloads(CERTCertDBHandle *handle,
					  enum ike_version ike_version,
					  struct payload_digest *cert_payloads,
					  struct logger *logger)
{
	struct certs *certs = NULL;
	/* accumulate the known certificates */
	ldbg(logger, "checking for known CERT payloads");
	for (struct payload_digest *p = cert_payloads; p != NULL; p = p->next) {
		enum ike_cert_type cert_type;
		const struct enum_names *cert_names;
		switch (ike_version) {
		case IKEv2:
			cert_type = p->payload.v2cert.isac_enc;
			cert_names = &ikev2_cert_type_names;
			break;
		case IKEv1:
			cert_type = p->payload.cert.isacert_type;
			cert_names = &ike_cert_type_names;
			break;
		default:
			bad_case(ike_version);
		}
		name_buf cert_name;
		if (!enum_short(cert_names, cert_type, &cert_name)) {
			llog(RC_LOG, logger,
				    "ignoring certificate with unknown type %d",
				    cert_type);
			continue;
		}

		ldbg(logger, "saving certificate of type '%s'", cert_name.buf);
		/* convert remaining buffer to something nss likes */
		shunk_t payload_hunk = pbs_in_left(&p->pbs);
		/* NSS doesn't do const */
		SECItem payload = {
			.type = siDERCertBuffer,
			.data = (void*)payload_hunk.ptr,
			.len = payload_hunk.len,
		};

		switch (cert_type) {
		case CERT_X509_SIGNATURE:
			add_decoded_cert(handle, &certs, payload, logger);
			break;
		case CERT_PKCS7_WRAPPED_X509:
		{
			SEC_PKCS7ContentInfo *contents = SEC_PKCS7DecodeItem(&payload, NULL, NULL, NULL, NULL,
									     NULL, NULL, NULL);
			if (contents == NULL) {
				llog(RC_LOG, logger,
					    "Wrapped PKCS7 certificate payload could not be decoded");
				continue;
			}
			if (!SEC_PKCS7ContainsCertsOrCrls(contents)) {
				llog(RC_LOG, logger,
					    "Wrapped PKCS7 certificate payload did not contain any certificates");
				SEC_PKCS7DestroyContentInfo(contents);
				continue;
			}
			for (SECItem **cert_list = SEC_PKCS7GetCertificateList(contents);
			     *cert_list; cert_list++) {
				add_decoded_cert(handle, &certs, **cert_list, logger);
			}
			SEC_PKCS7DestroyContentInfo(contents);
			break;
		}
		default:
			llog(RC_LOG, logger,
			     "ignoring %s certificate payload", cert_name.buf);
			break;
		}
	}
	return certs;
}

/*
 * Decode and verify the chain received by pluto.
 * ee_out is the resulting end cert
 */

struct verified_certs find_and_verify_certs(struct logger *logger,
					    enum ike_version ike_version,
					    struct payload_digest *cert_payloads,
					    struct root_certs *root_certs,
					    const struct id *keyid)
{
	struct verified_certs result = {
		.cert_chain = NULL,
		.force_crl_update = false,
		.harmless = true,
		.groundhog = false,
	};

	if (!PEXPECT(logger, cert_payloads != NULL)) {
		return result;
	}

	if (root_certs_empty(root_certs)) {
		llog(RC_LOG, logger,
		     "no Certificate Authority in NSS Certificate DB! certificate payloads discarded");
		return result;
	}

	/*
	 * CERT_GetDefaultCertDB() returns the contents of a static
	 * variable set by NSS_Initialize().  It doesn't check the
	 * value, doesn't set PR error, and doesn't add a reference
	 * count.
	 *
	 * Short of calling CERT_SetDefaultCertDB(NULL), the value can
	 * never be NULL.
	 */
	CERTCertDBHandle *handle = CERT_GetDefaultCertDB();
	PASSERT(logger, handle != NULL);

	/*
	 * In order for NSS to verify an entire chain, down to a
	 * CA loaded permanently into the NSS db, a temporary import
	 * is done which decodes and adds the certs to the in-memory
	 * cache. When CERT_VerifyCert is called against the end
	 * certificate both permanent and in-memory cache are used
	 * together to try to complete the chain.
	 *
	 * This routine populates certs[] with the imported
	 * certificates.  For details read CERT_ImportCerts().
	 */
	logtime_t decode_time = logtime_start(logger);
	result.cert_chain = decode_cert_payloads(handle, ike_version,
						 cert_payloads, logger);
	logtime_stop(&decode_time, "%s() calling decode_cert_payloads()", __func__);
	if (result.cert_chain == NULL) {
		return result;
	}

	CERTCertificate *end_cert = make_end_cert_first(&result.cert_chain);
	if (end_cert == NULL) {
		llog(RC_LOG, logger, "X509: no EE-cert in chain!");
		release_certs(&result.cert_chain);
		return result;
	}
	if (CERT_IsCACert(end_cert, NULL)) {
		/* utter screwup */
		llog_pexpect(logger, HERE, "end cert is a root certificate!");
		release_certs(&result.cert_chain);
		result.harmless = false;
		return result;
	}

	logtime_t crl_time = logtime_start(logger);
	bool crl_update_needed = crl_update_check(handle, result.cert_chain, logger);
	logtime_stop(&crl_time, "%s() calling crl_update_check()", __func__);
	if (crl_update_needed) {
		if (x509_crl.strict) {
			result.force_crl_update =  (deltasecs(x509_crl.check_interval) > 0);
			result.harmless = false;
			release_certs(&result.cert_chain);
			if (result.force_crl_update) {
				llog(RC_LOG, logger,
				     "certificate payload rejected; crl-strict=yes and Certificate Revocation List (CRL) is expired or missing, forcing CRL update");
			} else {
				llog(RC_LOG, logger, "certificate payload rejected; crl-strict=yes and Certificate Revocation List (CRL) is expired or missing");
				llog(WARNING_STREAM, logger, "automatic update of Certificate Revocation List (CRL) is disabled; see \"crlcheckinterval=\"");
			}
			return result;
		}
		ldbg(logger, "missing or expired CRL");
	}

	logtime_t verify_time = logtime_start(logger);
	bool end_ok = verify_end_cert(logger, root_certs->trustcl,
				      0, end_cert);
	if (!end_ok && groundhogday) {
		/*
		 * Go through the CA certs retrying any with an
		 * expired time.
		 */
		PRTime prnow = PR_Now();
		for (CERTCertListNode *node = CERT_LIST_HEAD(root_certs->trustcl);
		     !CERT_LIST_END(node, root_certs->trustcl);
		     node = CERT_LIST_NEXT(node)) {
			PRTime not_before, not_after;
			PRTime groundhogtime = 0;
			if (CERT_GetCertTimes(node->cert, &not_before, &not_after) != SECSuccess) {
				continue;
			}
			if (LL_CMP(not_after, <, prnow)) {
				groundhogtime = not_after;
			} else if (LL_CMP(not_before, >, prnow)) {
				groundhogtime = not_before;
			} else {
				continue;
			}
			ldbg(logger, "  retrying groundhog CA: %s", node->cert->subjectName);
			CERTCertList ground_certs = {
				.list = PR_INIT_STATIC_CLIST(&ground_certs.list),
			};
			CERTCertListNode ground_cert = {
				.cert = node->cert,
			};
			PR_INSERT_LINK(&ground_cert.links, &ground_certs.list);

			if (verify_end_cert(logger, &ground_certs,
					    groundhogtime, end_cert)) {
				result.groundhog = true;
				end_ok = true;
				break;
			}
		}
	}
	logtime_stop(&verify_time, "%s() calling verify_end_cert()", __func__);
	if (!end_ok) {
		/*
		 * XXX: preserve verify_end_cert()'s behaviour? only
		 * send this to the file
		 */
		llog(LOG_STREAM/*not-whack*/, logger, "NSS: end certificate invalid");
		release_certs(&result.cert_chain);
		result.harmless = false;
		return result;
	}

	logtime_t start_add = logtime_start(logger);
	add_pubkey_from_nss_cert(&result.pubkey_db, keyid, end_cert, logger);
	logtime_stop(&start_add, "%s() calling add_pubkey_from_nss_cert()", __func__);

	return result;
}

diag_t cert_verify_subject_alt_name(const char *who,
				    const CERTCertificate *cert,
				    const struct id *id,
				    struct logger *logger)
{
	/*
	 * Get a handle on the certificate's subject alt name.
	 */
	SECItem	subAltName;
	SECStatus rv = CERT_FindCertExtension(cert, SEC_OID_X509_SUBJECT_ALT_NAME,
					      &subAltName);
	if (rv != SECSuccess) {
		id_buf idb;
		name_buf kb;
		return diag("%s certificate contains no subjectAltName extension to match %s '%s'",
			    who, str_enum_short(&ike_id_type_names, id->kind, &kb),
			    str_id(id, &idb));
	}

	/*
	 * Now decode that into a circular buffer (yes not a list) so
	 * the ID can be compared against it.
	 */
	PLArenaPool *arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	PASSERT(logger, arena != NULL);
	CERTGeneralName *nameList = CERT_DecodeAltNameExtension(arena, &subAltName);
	if (nameList == NULL) {
		PORT_FreeArena(arena, PR_FALSE);
		id_buf idb;
		name_buf kb;
		return diag("%s certificate subjectAltName extension failed to decode while looking for %s '%s'",
			    who, str_enum_short(&ike_id_type_names, id->kind, &kb),
			    str_id(id, &idb));
	}

	/*
	 * Convert the ID with no special escaping (other than that
	 * specified for converting an ASN.1 DN to text).
	 *
	 * The result is printable without sanitizing - str_id_bytes()
	 * only emits printable ASCII (the JAM_BYTES parameter is for
	 * converting the printable ASCII to something suitable for
	 * quoted shell).
	 *
	 * XXX: Is there any point in continuing when KIND isn't
	 * ID_FQDN?  For instance, ID_DER_ASN1_DN (in fact, for DN,
	 * code was calling this with the ID's first character - not
	 * an @ - discarded making the value useless).
	 *
	 * XXX: Is this overkill?  For instance, since DNS ID has a
	 * very limited character set, the escaping used is largely
	 * academic - any escape character ('\', '?') is invalid and
	 * can't match.
	 */
	id_buf ascii_id_buf;
	const char *ascii_id = str_id_bytes(id, jam_raw_bytes, &ascii_id_buf);
	if (id->kind == ID_FQDN) {
		if (PEXPECT(logger, ascii_id[0] == '@')) {
			ascii_id++;
		}
	} else {
		PEXPECT(logger, ascii_id[0] != '@');
	}

	/*
	 * Try converting the ID to an address.  If it fails, assume
	 * it is a DNS name?
	 *
	 * XXX: Is this a "smart" way of handling both an ID_*address*
	 * and an ID_FQDN containing a textual IP address?
	 */
	ip_address myip;
	diag_t d = ttoaddress_num(shunk1(ascii_id), NULL/*UNSPEC*/, &myip);
	bool san_ip = (d == NULL);
	pfree_diag(&d);

	/*
	 * nameList is a pointer into a non-empty circular linked
	 * list.  This loop visits each entry.
	 *
	 * We have visited each when we come back to the start.
	 * We test only at the end, after we advance, because we want to visit
	 * the first entry the first time we see it but stop when we get to it
	 * the second time.
	 */
	CERTGeneralName *current = nameList;
	do {
		switch (current->type) {
		case certDNSName:
		case certRFC822Name:
		{
			if (san_ip)
				break;
			/*
			 * Match the parameter name with the name in the certificate.
			 * The name in the cert may start with "*."; that will match
			 * any initial component in name (up to the first '.').
			 */
			/* we need to cast because name.other.data is unsigned char * */
			const char *c_ptr = (const void *) current->name.other.data;
			size_t c_len =  current->name.other.len;

			const char *n_ptr = ascii_id;
			static const char wild[] = "*.";
			const size_t wild_len = sizeof(wild) - 1;

			if (c_len > wild_len && startswith(c_ptr, wild)) {
				/* wildcard in cert: ignore first component of name */
				c_ptr += wild_len;
				c_len -= wild_len;
				n_ptr = strchr(n_ptr, '.');
				if (n_ptr == NULL)
					break;	/* cannot match */

				n_ptr++;	/* skip . */
			}

			if (c_len == strlen(n_ptr) && strncaseeq(n_ptr, c_ptr, c_len)) {
				LDBGP_JAMBUF(DBG_BASE, logger, buf) {
					jam(buf, "peer certificate subjectAltname '%s' matched '", ascii_id),
					jam_sanitized_bytes(buf, current->name.other.data,
							    current->name.other.len);
				}
				PORT_FreeArena(arena, PR_FALSE);
				return NULL;
			}
			break;
		}

		case certIPAddress:
		{
			if (!san_ip)
				break;
			/*
			 * XXX: If one address is IPv4 and the other
			 * is IPv6 then the hunk_memeq() check will
			 * fail because the lengths are wrong.
			 */
			shunk_t as = address_as_shunk(&myip);
			if (hunk_memeq(as, current->name.other.data,
				       current->name.other.len)) {
				address_buf b;
				ldbg(logger, "%s certificate subjectAltname matches address %s",
				     who, str_address(&myip, &b));
				PORT_FreeArena(arena, PR_FALSE);
				return NULL;
			}
			address_buf b;
			ldbg(logger, "peer certificate subjectAltname does not match address %s",
			     str_address(&myip, &b));
			break;
		}

		default:
			break;
		}
		current = CERT_GetNextGeneralName(current);
	} while (current != nameList);

	/*
	 * Don't need to free nameList, it's part of the arena.
	 */
	PORT_FreeArena(arena, PR_FALSE);
	name_buf esb;
	return diag("%s certificate subjectAltName extension does not match %s '%s'",
		    who, str_enum_short(&ike_id_type_names, id->kind, &esb),
		    ascii_id);
}

static SECItem *impaired_pkcs7_certs(const struct cert *cert, bool send_full_chain,
				     struct logger *logger)
{
	/*
	 * CERT_GetDefaultCertDB() simply returns the contents of a
	 * static variable set by NSS_Initialize().  It doesn't check
	 * the value and doesn't set PR error.  Short of calling
	 * CERT_SetDefaultCertDB(NULL), the value can never be NULL.
	 */
	CERTCertDBHandle *handle = CERT_GetDefaultCertDB();
	PASSERT(logger, handle != NULL);
	SEC_PKCS7ContentInfo *content
		= SEC_PKCS7CreateCertsOnly(cert->nss_cert,
					   send_full_chain ? PR_TRUE : PR_FALSE,
					   handle);
	SECItem *pkcs7 = SEC_PKCS7EncodeItem(NULL, NULL, content,
					     NULL, NULL, NULL);
	SEC_PKCS7DestroyContentInfo(content);
	return pkcs7;
}

static SECItem *impaired_pkcs7_crl(void)
{
	static const uint8_t x[] = {
 0x30, 0x82, 0x02, 0xc1, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02, 0xa0,
 0x82, 0x02, 0xb2, 0x30, 0x82, 0x02, 0xae, 0x02, 0x01, 0x01, 0x31, 0x00, 0x30, 0x0b, 0x06, 0x09,
 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0xa1, 0x82, 0x02, 0x96, 0x30, 0x82, 0x02,
 0x92, 0x30, 0x81, 0xfb, 0x02, 0x01, 0x01, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x81, 0xac, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
 0x04, 0x06, 0x13, 0x02, 0x43, 0x41, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13,
 0x07, 0x4f, 0x6e, 0x74, 0x61, 0x72, 0x69, 0x6f, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04,
 0x07, 0x13, 0x07, 0x54, 0x6f, 0x72, 0x6f, 0x6e, 0x74, 0x6f, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03,
 0x55, 0x04, 0x0a, 0x13, 0x09, 0x4c, 0x69, 0x62, 0x72, 0x65, 0x73, 0x77, 0x61, 0x6e, 0x31, 0x18,
 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x0f, 0x54, 0x65, 0x73, 0x74, 0x20, 0x44, 0x65,
 0x70, 0x61, 0x72, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x31, 0x25, 0x30, 0x23, 0x06, 0x03, 0x55, 0x04,
 0x03, 0x13, 0x1c, 0x4c, 0x69, 0x62, 0x72, 0x65, 0x73, 0x77, 0x61, 0x6e, 0x20, 0x74, 0x65, 0x73,
 0x74, 0x20, 0x43, 0x41, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6d, 0x61, 0x69, 0x6e, 0x63, 0x61, 0x31,
 0x24, 0x30, 0x22, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x15,
 0x74, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67, 0x40, 0x6c, 0x69, 0x62, 0x72, 0x65, 0x73, 0x77, 0x61,
 0x6e, 0x2e, 0x6f, 0x72, 0x67, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x38, 0x33, 0x30, 0x31,
 0x38, 0x33, 0x33, 0x31, 0x35, 0x5a, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x37, 0x30, 0x38, 0x32, 0x35,
 0x31, 0x38, 0x33, 0x33, 0x31, 0x35, 0x5a, 0x30, 0x16, 0x30, 0x14, 0x02, 0x01, 0x09, 0x18, 0x0f,
 0x32, 0x30, 0x32, 0x36, 0x30, 0x38, 0x33, 0x30, 0x31, 0x38, 0x33, 0x33, 0x31, 0x35, 0x5a, 0x30,
 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82,
 0x01, 0x81, 0x00, 0x6a, 0xb8, 0x4b, 0x81, 0xd4, 0xac, 0xec, 0x45, 0xee, 0x83, 0x12, 0xe0, 0x50,
 0x75, 0xea, 0xb0, 0x58, 0x11, 0xdc, 0xbb, 0xc2, 0xaf, 0x7c, 0x5a, 0xdc, 0xc8, 0xa5, 0xc5, 0xcf,
 0x53, 0x11, 0x8b, 0x19, 0x9b, 0xde, 0x0a, 0x95, 0xdc, 0x70, 0xef, 0x1f, 0x9b, 0x1e, 0x23, 0xdf,
 0xa0, 0x11, 0x4c, 0x52, 0xbc, 0x23, 0x9d, 0x3c, 0x41, 0x7d, 0xc4, 0x79, 0x95, 0x33, 0xfc, 0xc9,
 0x8e, 0x4d, 0x1f, 0x20, 0xc1, 0x2c, 0x6b, 0x56, 0x0b, 0x15, 0x64, 0x40, 0x5f, 0xe8, 0x2d, 0xee,
 0x07, 0x1c, 0x8d, 0xcd, 0x47, 0xc3, 0x2d, 0xa2, 0x1c, 0xb4, 0x8f, 0xb3, 0x9c, 0x10, 0x99, 0x7f,
 0x01, 0x5e, 0x55, 0x4f, 0x25, 0x3d, 0x05, 0x59, 0xce, 0xf6, 0xee, 0x06, 0x25, 0x42, 0x24, 0x38,
 0x98, 0x37, 0xe7, 0x08, 0x00, 0x7d, 0x62, 0xdb, 0x0b, 0x04, 0x4d, 0x5c, 0xe2, 0x04, 0xd5, 0x67,
 0x55, 0xb2, 0xcd, 0x09, 0x4f, 0x82, 0x9b, 0xb5, 0xbb, 0x1c, 0x26, 0x51, 0x30, 0x09, 0xcd, 0xfb,
 0x23, 0x19, 0x78, 0xee, 0xa1, 0xb1, 0x35, 0x8b, 0xe5, 0xd9, 0xf5, 0x3d, 0xa0, 0x22, 0x71, 0xbe,
 0xa3, 0xe7, 0xad, 0xf2, 0xd5, 0x52, 0x8b, 0xd3, 0xa4, 0x5a, 0xa0, 0xa4, 0x6a, 0x6e, 0xb0, 0x2a,
 0x96, 0xd3, 0x7b, 0xd5, 0x9d, 0x7e, 0xae, 0x06, 0xb2, 0xe8, 0xa9, 0x10, 0x41, 0x2c, 0x26, 0x10,
 0xc6, 0x28, 0x64, 0xcc, 0x77, 0x3b, 0xec, 0x16, 0x44, 0x15, 0x02, 0xf8, 0x0a, 0x87, 0x4e, 0x62,
 0xa1, 0xcb, 0xa1, 0xc9, 0xc4, 0xcc, 0xc6, 0x3e, 0xf8, 0x8b, 0xbe, 0x31, 0xad, 0x67, 0xa2, 0x81,
 0xfd, 0xf4, 0xdd, 0x38, 0xfc, 0xcd, 0xeb, 0x7c, 0x1d, 0x16, 0xfb, 0x53, 0x9c, 0x9a, 0x92, 0x43,
 0x59, 0x97, 0x05, 0x75, 0xb4, 0x91, 0xd7, 0x70, 0x17, 0xff, 0xe6, 0x89, 0x6f, 0x1e, 0x6e, 0x0d,
 0x32, 0x03, 0x4e, 0x48, 0xea, 0x12, 0x43, 0x74, 0x7e, 0xb8, 0x0b, 0x4b, 0x76, 0x8e, 0x98, 0x18,
 0xfa, 0x3e, 0x8c, 0xff, 0x04, 0x2e, 0xb9, 0x57, 0x9b, 0x51, 0x75, 0x2d, 0xcc, 0x1f, 0xa0, 0x93,
 0x5e, 0xc2, 0x86, 0xda, 0x57, 0xe1, 0x50, 0x06, 0x31, 0xe1, 0x7c, 0x1c, 0x10, 0x7c, 0x3f, 0xa5,
 0xe5, 0x15, 0xe6, 0x75, 0x4b, 0x67, 0x2c, 0x76, 0xf0, 0x91, 0x56, 0x26, 0xf2, 0x44, 0xb0, 0x0d,
 0x39, 0x15, 0xac, 0x8e, 0x8d, 0xd0, 0x76, 0x54, 0x0a, 0x0d, 0xc9, 0xe2, 0x1a, 0xe8, 0xd6, 0xeb,
 0xc7, 0x4d, 0xf5, 0x55, 0xdc, 0xbb, 0x25, 0x36, 0xa9, 0x67, 0xcf, 0xbe, 0x34, 0x42, 0x64, 0x6f,
 0x7b, 0x56, 0x17, 0x05, 0x04, 0x39, 0x1f, 0x82, 0x02, 0x19, 0x4a, 0x54, 0x4b, 0x2f, 0x4c, 0xe7,
 0xa7, 0x37, 0x2e, 0xf8, 0x6f, 0xc1, 0x2c, 0x3d, 0x27, 0x3f, 0x65, 0x9b, 0x23, 0x1c, 0x10, 0x4c,
 0x91, 0xc6, 0xb4, 0x31, 0x00,
	};
	SECItem pkcs7 = {
		.type = siBuffer,
		.len = sizeof(x),
		.data = DISCARD_CONST(uint8_t *, x), /*strip const*/
	};
	return SECITEM_DupItem(&pkcs7);
}

SECItem *impaired_pkcs7_blob(const struct cert *mycert,
			     bool send_full_chain,
			     struct logger *logger)
{
	if (impair.send_pkcs7_thingie == 1) {
		llog(IMPAIR_STREAM, logger, "sending certs as PKCS7 blob");
		passert(mycert != NULL);
		return impaired_pkcs7_certs(mycert, send_full_chain, logger);
	}

	llog(IMPAIR_STREAM, logger, "sending crl as PKCS7 blob");
	return impaired_pkcs7_crl();
}
