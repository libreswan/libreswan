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

#include "sparse_names.h"
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
					CERTCertificate *cert)
{
	if (!pexpect(handle != NULL) || !pexpect(cert != NULL))
		return false;

	dbg("%s: looking for a CRL issued by %s",
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
			dbg("%s: %s CRL found",
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

static void set_rev_params(CERTRevocationFlags *rev)
{
	CERTRevocationTests *rt = &rev->leafTests;
	PRUint64 *rf = rt->cert_rev_flags_per_method;
	name_buf omb;
	dbg("crl_strict: %s, ocsp: %s, ocsp_strict: %s, ocsp_post: %s",
	    bool_str(x509_crl.strict),
	    bool_str(x509_ocsp.enable),
	    bool_str(x509_ocsp.strict),
	    str_sparse(&ocsp_method_names, x509_ocsp.method, &omb));

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
	set_rev_params(&rev);

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
#if 0
		{ certificateUsageSSLClient, "TLS Client" },
		{ certificateUsageSSLServer, "TLS Server" }
#endif
	};

	if (DBGP(DBG_BASE)) {
		DBG_log("%s verifying %s using:", __func__, end_cert->subjectName);
		unsigned nr = 0;
		for (CERTCertListNode *node = CERT_LIST_HEAD(trustcl);
		     !CERT_LIST_END(node, trustcl);
		     node = CERT_LIST_NEXT(node)) {
			DBG_log("  trusted CA: %s", node->cert->subjectName);
			nr++;
		}
		if (nr == 0) {
			DBG_log("  but have no trusted CAs");
		}
	}

	bool keep_trying = true;
	for (unsigned pi = 0; pi < elemsof(usages) && keep_trying; pi++) {
		const struct usage_desc *p = &usages[pi];
		dbg("verify_end_cert trying profile %s", p->usageName);

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
			pexpect(cvout_error_log.count == 0 && cvout_error_log.head == NULL);
			PORT_FreeArena(cvout_error_log.arena, PR_FALSE);
			dbg("certificate is valid (profile %s)", p->usageName);
			return true;
		}

		/*
		 * Deal with failure; log; cleanup; and maybe try
		 * again!
		 */
		pexpect(rv == SECFailure);
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
			     struct certs *certs)
{
	for (struct certs *entry = certs; entry != NULL;
	     entry = entry->next) {
		if (!cert_issuer_has_current_crl(handle, entry->cert)) {
			return true;
		}
	}
	return false;
}

/*
 * Does a temporary import of the DER certificate an appends it to the
 * CERTS array.
 */

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
		dbg("ignoring root certificate");
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
			       "NSS: decoding certificate payload using CERT_NewTempCertificate() failed");
		if (PR_GetError() == SEC_ERROR_REUSED_ISSUER_AND_SERIAL) {
			lset_t rc_flags = log_limiter_rc_flags(logger, CERTIFICATE_LOG_LIMITER);
			if (rc_flags != LEMPTY) {
				llog_pem_bytes(rc_flags, logger, "CERTIFICATE", der_cert.data, der_cert.len);
			}
		}
		return;
	}
	dbg("decoded cert: %s", cert->subjectName);

	/*
	 * Currently only a check for RSA is needed, as the only ECDSA
	 * key size not allowed in FIPS mode (p192 curve), is not
	 * implemented by NSS.
	 *
	 * See also RSA_secret_sane() and ECDSA_secret_sane()
	 */
	if (is_fips_mode()) {
		SECKEYPublicKey *pk = CERT_ExtractPublicKey(cert);
		passert(pk != NULL);
		unsigned key_bit_size = pk->u.rsa.modulus.len * BITS_IN_BYTE;
		if (pk->keyType == rsaKey && key_bit_size < FIPS_MIN_RSA_KEY_SIZE) {
			llog(RC_LOG, logger,
			     "FIPS: rejecting peer cert with key size %u under %u: %s",
			     key_bit_size, FIPS_MIN_RSA_KEY_SIZE,
			     cert->subjectName);
			SECKEY_DestroyPublicKey(pk);
			CERT_DestroyCertificate(cert);
			return;
		}
		SECKEY_DestroyPublicKey(pk);
	}

	/*
	 * Append the certificate to the CERTS array.
	 *
	 * XXX: Caller doesn't seem to delete the reference to the
	 * certificate (or at least the imported intermediate
	 * certificates, for the end certificate things are less clear
	 * as it escapes to x509.c only to then be leaked)?  Perhaps
	 * that's the intend?  Over time accumulate a pool of imported
	 * certificates in NSS's certificate database?
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
	dbg("checking for known CERT payloads");
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
		enum_buf cert_name;
		if (!enum_name_short(cert_names, cert_type, &cert_name)) {
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
		.crl_update_needed = false,
		.harmless = true,
		.groundhog = false,
	};

	if (!pexpect(cert_payloads != NULL)) {
		/* logged by pexpect() */
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
	passert(handle != NULL);

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
	bool crl_update_needed = crl_update_check(handle, result.cert_chain);
	logtime_stop(&crl_time, "%s() calling crl_update_check()", __func__);
	if (crl_update_needed) {
		if (x509_crl.strict) {
			llog(RC_LOG, logger,
			     "certificate payload rejected; crl-strict=yes and Certificate Revocation List (CRL) is expired or missing, forcing CRL update");
			release_certs(&result.cert_chain);
			result.crl_update_needed = true;
			result.harmless = false;
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
				    const struct id *id)
{
	/*
	 * Get a handle on the certificate's subject alt name.
	 */
	SECItem	subAltName;
	SECStatus rv = CERT_FindCertExtension(cert, SEC_OID_X509_SUBJECT_ALT_NAME,
					      &subAltName);
	if (rv != SECSuccess) {
		id_buf idb;
		enum_buf kb;
		return diag("%s certificate contains no subjectAltName extension to match %s '%s'",
			    who, str_enum(&ike_id_type_names, id->kind, &kb),
			    str_id(id, &idb));
	}

	/*
	 * Now decode that into a circular buffer (yes not a list) so
	 * the ID can be compared against it.
	 */
	PLArenaPool *arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	passert(arena != NULL);
	CERTGeneralName *nameList = CERT_DecodeAltNameExtension(arena, &subAltName);
	if (nameList == NULL) {
		PORT_FreeArena(arena, PR_FALSE);
		id_buf idb;
		enum_buf kb;
		return diag("%s certificate subjectAltName extension failed to decode while looking for %s '%s'",
			    who, str_enum(&ike_id_type_names, id->kind, &kb),
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
		if (pexpect(ascii_id[0] == '@'))
			ascii_id++;
	} else {
		pexpect(ascii_id[0] != '@');
	}

	/*
	 * Try converting the ID to an address.  If it fails, assume
	 * it is a DNS name?
	 *
	 * XXX: Is this a "smart" way of handling both an ID_*address*
	 * and an ID_FQDN containing a textual IP address?
	 */
	ip_address myip;
	bool san_ip = (ttoaddress_num(shunk1(ascii_id), NULL/*UNSPEC*/, &myip) == NULL);

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
				LDBGP_JAMBUF(DBG_BASE, &global_logger, buf) {
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
				dbg("%s certificate subjectAltname matches address %s",
				    who, str_address(&myip, &b));
				PORT_FreeArena(arena, PR_FALSE);
				return NULL;
			}
			address_buf b;
			dbg("peer certificate subjectAltname does not match address %s",
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
	esb_buf esb;
	return diag("%s certificate subjectAltName extension does not match %s '%s'",
		    who, str_enum(&ike_id_type_names, id->kind, &esb),
		    ascii_id);
}

SECItem *nss_pkcs7_blob(const struct cert *cert, bool send_full_chain)
{
	/*
	 * CERT_GetDefaultCertDB() simply returns the contents of a
	 * static variable set by NSS_Initialize().  It doesn't check
	 * the value and doesn't set PR error.  Short of calling
	 * CERT_SetDefaultCertDB(NULL), the value can never be NULL.
	 */
	CERTCertDBHandle *handle = CERT_GetDefaultCertDB();
	passert(handle != NULL);
	SEC_PKCS7ContentInfo *content
		= SEC_PKCS7CreateCertsOnly(cert->nss_cert,
					   send_full_chain ? PR_TRUE : PR_FALSE,
					   handle);
	SECItem *pkcs7 = SEC_PKCS7EncodeItem(NULL, NULL, content,
					     NULL, NULL, NULL);
	SEC_PKCS7DestroyContentInfo(content);
	return pkcs7;
}
