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
#include "lswfips.h" /* for libreswan_fipsmode() */
#include "nss_err.h"
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

/*
 * set up the slot/handle/trust things that NSS needs
 */
static bool prepare_nss_import(PK11SlotInfo **slot)
{
	/*
	 * possibly need to handle passworded db case here
	 */
	*slot = PK11_GetInternalKeySlot();
	if (*slot == NULL) {
		LSWDBGP(DBG_BASE, buf) {
			jam(buf, "NSS: cert import calling PK11_GetInternalKeySlot() failed: ");
			jam_nss_error(buf);
		}
		return FALSE;
	}
	return TRUE;
}

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
		llog(RC_LOG_SERIOUS, logger,
			    "certificate %s failed %s verification",
			    node->cert->subjectName, usage);
		/* ??? we ignore node->depth and node->arg */
		llog(RC_LOG_SERIOUS, logger, "NSS %s: %s", prefix,
			    nss_err_str(node->error));
		/*
		 * XXX: this redundant log message is to keep tests happy -
		 * the above ERROR: line will have already explained the the
		 * problem.
		 *
		 * Two things should change - drop the below, and prefix the
		 * above with "NSS ERROR: ".
		 */
		if (node->error == SEC_ERROR_REVOKED_CERTIFICATE) {
			llog(RC_LOG_SERIOUS, logger, "certificate revoked!");
		}
	}
}

static void new_vfy_log(CERTVerifyLog *log)
{
	log->count = 0;
	log->head = NULL;
	log->tail = NULL;
	log->arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
}

static void set_rev_per_meth(CERTRevocationFlags *rev, PRUint64 *lflags,
						       PRUint64 *cflags)
{
	rev->leafTests.cert_rev_flags_per_method = lflags;
	rev->chainTests.cert_rev_flags_per_method = cflags;
}

static unsigned int rev_val_flags(PRBool strict, PRBool post)
{
	unsigned int flags = CERT_REV_M_TEST_USING_THIS_METHOD;

	if (strict) {
		flags |= CERT_REV_M_REQUIRE_INFO_ON_MISSING_SOURCE;
		flags |= CERT_REV_M_FAIL_ON_MISSING_FRESH_INFO;
	}

	if (post) {
		flags |= CERT_REV_M_FORCE_POST_METHOD_FOR_OCSP;
	}
	return flags;
}

static void set_rev_params(CERTRevocationFlags *rev,
			   const struct rev_opts *rev_opts)
{
	CERTRevocationTests *rt = &rev->leafTests;
	PRUint64 *rf = rt->cert_rev_flags_per_method;
	dbg("crl_strict: %d, ocsp: %d, ocsp_strict: %d, ocsp_post: %d",
	    rev_opts->crl_strict, rev_opts->ocsp,
	    rev_opts->ocsp_strict, rev_opts->ocsp_post);

	rt->number_of_defined_methods = cert_revocation_method_count;
	rt->number_of_preferred_methods = 0;

	rf[cert_revocation_method_crl] |= CERT_REV_M_TEST_USING_THIS_METHOD;
	rf[cert_revocation_method_crl] |= CERT_REV_M_FORBID_NETWORK_FETCHING;

	if (rev_opts->ocsp) {
		rf[cert_revocation_method_ocsp] = rev_val_flags(rev_opts->ocsp_strict,
								rev_opts->ocsp_post);
	}
}

/* SEC_ERROR_INADEQUATE_CERT_TYPE etc.: /usr/include/nss3/secerr.h */

#define RETRYABLE_TYPE(err) ((err) == SEC_ERROR_INADEQUATE_CERT_TYPE || \
			      (err) == SEC_ERROR_INADEQUATE_KEY_USAGE)

static bool verify_end_cert(struct logger *logger,
			    const struct root_certs *root_certs,
			    const struct rev_opts *rev_opts,
			    CERTCertificate *end_cert)
{
	CERTRevocationFlags rev;
	zero(&rev);	/* ??? are there pointer fields?  YES, and different for different union members! */

	PRUint64 revFlagsLeaf[2] = { 0, 0 };
	PRUint64 revFlagsChain[2] = { 0, 0 };

	set_rev_per_meth(&rev, revFlagsLeaf, revFlagsChain);
	set_rev_params(&rev, rev_opts);

	CERTValInParam cvin[] = {
		{
			.type = cert_pi_revocationFlags,
			.value = { .pointer = { .revocation = &rev } }
		},
		{
			.type = cert_pi_useAIACertFetch,
			.value = { .scalar = { .b = rev_opts->ocsp ? PR_TRUE : PR_FALSE } }
		},
		{
			.type = cert_pi_trustAnchors,
			.value = { .pointer = { .chain = root_certs->trustcl, } }
		},
		{
			.type = cert_pi_useOnlyTrustAnchors,
			.value = { .scalar = { .b = PR_TRUE } }
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
#ifdef NSS_IPSEC_PROFILE
		{ certificateUsageIPsec, "IPsec" },
#endif
		{ certificateUsageSSLClient, "TLS Client" },
		{ certificateUsageSSLServer, "TLS Server" }
	};

	bool verified = false;	/* more ways to fail than succeed */

	CERTVerifyLog vfy_log;

	enum cvout_param {
		cvout_errorLog,
		cvout_end,
	};

	CERTValOutParam cvout[] = {
		[cvout_errorLog] = {
			.type = cert_po_errorLog,
			.value = { .pointer = { .log = &vfy_log } }
		},
		[cvout_end] = {
			.type = cert_po_end
		}
	};

	if (DBGP(DBG_BASE)) {
		DBG_log("%s verifying %s using:", __func__, end_cert->subjectName);
		unsigned nr = 0;
		CERTCertList *trustcl = root_certs->trustcl;
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

	for (const struct usage_desc *p = usages; ; p++) {
		dbg("verify_end_cert trying profile %s", p->usageName);

		new_vfy_log(&vfy_log);
		SECStatus rv = CERT_PKIXVerifyCert(end_cert, p->usage, cvin, cvout, NULL);

		if (rv == SECSuccess) {
			/* success! */
			pexpect(vfy_log.count == 0 && vfy_log.head == NULL);
			dbg("certificate is valid (profile %s)", p->usageName);
			verified = true;
			break;
		}

		pexpect(rv == SECFailure);

		/* Failure.  Can we try again? */

		/*
		 * The (error) log can have more than one entry
		 * but we only test the first with RETRYABLE_TYPE.
		 */
		passert(vfy_log.count > 0 && vfy_log.head != NULL);

		if (p == &usages[elemsof(usages) - 1] ||
		    !RETRYABLE_TYPE(vfy_log.head->error)) {
			/* we are a conclusive failure */
			log_bad_cert(logger, "ERROR", p->usageName, vfy_log.head);
			break;
		}

		/* this usage failed: prepare to repeat for the next one */

		log_bad_cert(logger, "warning", p->usageName,  vfy_log.head);

		PORT_FreeArena(vfy_log.arena, PR_FALSE);
	}

	PORT_FreeArena(vfy_log.arena, PR_FALSE);

	return verified;
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
		dbg_nss_error(logger, "NSS: decoding certs using CERT_ImportCerts() failed");
		return;
	}
	dbg("decoded cert: %s", cert->subjectName);

	/*
	 * Currently only a check for RSA is needed, as the only ECDSA
	 * key size not allowed in FIPS mode (p192 curve), is not implemented
	 * by NSS.
	 * See also RSA_secret_sane() and ECDSA_secret_sane()
	 */
	if (libreswan_fipsmode()) {
		SECKEYPublicKey *pk = CERT_ExtractPublicKey(cert);
		passert(pk != NULL);
		if (pk->keyType == rsaKey &&
			((pk->u.rsa.modulus.len * BITS_PER_BYTE) < FIPS_MIN_RSA_KEY_SIZE)) {
			llog(RC_LOG, logger,
				    "FIPS: Rejecting peer cert with key size %d under %d",
				    pk->u.rsa.modulus.len * BITS_PER_BYTE,
				    FIPS_MIN_RSA_KEY_SIZE);
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
		const char *cert_name;
		switch (ike_version) {
		case IKEv2:
			cert_type = p->payload.v2cert.isac_enc;
			cert_name = enum_short_name(&ikev2_cert_type_names, cert_type);
			break;
		case IKEv1:
			cert_type = p->payload.cert.isacert_type;
			cert_name = enum_short_name(&ike_cert_type_names, cert_type);
			break;
		default:
			bad_case(ike_version);
		}
		if (cert_name == NULL) {
			llog(RC_LOG_SERIOUS, logger,
				    "ignoring certificate with unknown type %d",
				    cert_type);
			continue;
		}

		dbg("saving certificate of type '%s'", cert_name);
		/* convert remaining buffer to something nss likes */
		shunk_t payload_hunk = pbs_in_left_as_shunk(&p->pbs);
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
				llog(RC_LOG_SERIOUS, logger,
					    "Wrapped PKCS7 certificate payload could not be decoded");
				continue;
			}
			if (!SEC_PKCS7ContainsCertsOrCrls(contents)) {
				llog(RC_LOG_SERIOUS, logger,
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
			llog(RC_LOG_SERIOUS, logger,
				    "ignoring %s certificate payload", cert_name);
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
					    const struct rev_opts *rev_opts,
					    struct root_certs *root_certs,
					    const struct id *keyid)
{
	struct verified_certs result = {
		.cert_chain = NULL,
		.crl_update_needed = false,
		.harmless = true,
	};

	if (!pexpect(cert_payloads != NULL)) {
		/* logged by pexpect() */
		return result;
	}

	PK11SlotInfo *slot = NULL;
	if (!prepare_nss_import(&slot)) {
		/* logged by above */
		return result;
	}

	if (root_certs_empty(root_certs)) {
		llog(RC_LOG, logger, "no Certificate Authority in NSS Certificate DB! certificate payloads discarded");
		return result;
	}

	/*
	 * CERT_GetDefaultCertDB() simply returns the contents of a
	 * static variable set by NSS_Initialize().  It doesn't check
	 * the value and doesn't set PR error.  Short of calling
	 * CERT_SetDefaultCertDB(NULL), the value can never be NULL.
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
		pexpect_fail(logger, HERE, "end cert is a root certificate!");
		release_certs(&result.cert_chain);
		result.harmless = false;
		return result;
	}

	logtime_t crl_time = logtime_start(logger);
	bool crl_update_needed = crl_update_check(handle, result.cert_chain);
	logtime_stop(&crl_time, "%s() calling crl_update_check()", __func__);
	if (crl_update_needed) {
		if (rev_opts->crl_strict) {
			llog(RC_LOG, logger,
				    "missing or expired CRL in strict mode, failing pending update and forcing CRL update");
			release_certs(&result.cert_chain);
			result.crl_update_needed = true;
			result.harmless = false;
			return result;
		}
		dbg("missing or expired CRL");
	}

	logtime_t verify_time = logtime_start(logger);
	bool end_ok = verify_end_cert(logger, root_certs, rev_opts, end_cert);
	logtime_stop(&verify_time, "%s() calling verify_end_cert()", __func__);
	if (!end_ok) {
		/*
		 * XXX: preserve verify_end_cert()'s behaviour? only
		 * send this to the file
		 */
		llog(RC_LOG|LOG_STREAM, logger, "NSS: end certificate invalid");
		release_certs(&result.cert_chain);
		result.harmless = false;
		return result;
	}

	logtime_t start_add = logtime_start(logger);
	add_pubkey_from_nss_cert(&result.pubkey_db, keyid, end_cert, logger);
	logtime_stop(&start_add, "%s() calling add_pubkey_from_nss_cert()", __func__);

	return result;
}

bool cert_VerifySubjectAltName(const CERTCertificate *cert,
			       const struct id *id, struct logger *logger)
{
	/*
	 * Get a handle on the certificate's subject alt name.
	 */
	SECItem	subAltName;
	SECStatus rv = CERT_FindCertExtension(cert, SEC_OID_X509_SUBJECT_ALT_NAME,
					      &subAltName);
	if (rv != SECSuccess) {
		id_buf name;
		llog(RC_LOG_SERIOUS, logger,
			    "certificate contains no subjectAltName extension to match %s '%s'",
			    enum_name(&ike_idtype_names, id->kind),
			    str_id(id, &name));
		return false;
	}

	/*
	 * Now decode that into a circular buffer (yes not a list) so
	 * the ID can be compared against it.
	 */
	PLArenaPool *arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	passert(arena != NULL);
	CERTGeneralName *nameList = CERT_DecodeAltNameExtension(arena, &subAltName);
	if (nameList == NULL) {
		id_buf name;
		llog(RC_LOG_SERIOUS, logger,
			    "certificate subjectAltName extension failed to decode while looking for %s '%s'",
			    enum_name(&ike_idtype_names, id->kind),
			    str_id(id, &name));
		/* XXX: is nss error set? */
		PORT_FreeArena(arena, PR_FALSE);
		return false;
	}

	/*
	 * Convert the ID with no special escaping (other than that
	 * specified for converting an ASN.1 DN to text).
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
	char raw_id_buf[IDTOA_BUF];
	struct jambuf raw_id_jambuf = ARRAY_AS_JAMBUF(raw_id_buf);
	jam_id(&raw_id_jambuf, id, jam_raw_bytes);
	const char *raw_id = raw_id_buf;
	if (id->kind == ID_FQDN) {
		if (pexpect(raw_id[0] == '@'))
			raw_id++;
	} else {
		pexpect(raw_id[0] != '@');
	}

	/*
	 * Try converting the ID to an address.  If it fails, assume
	 * it is a DNS name?
	 *
	 * XXX: Is this a "smart" way of handling both an ID_*address*
	 * and an ID_FQDN containing a textual IP address?
	 */
	ip_address myip;
	bool san_ip = (tnatoaddr(raw_id, 0, AF_UNSPEC, &myip) == NULL);

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

			const char *n_ptr = raw_id;
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
				LSWDBGP(DBG_BASE, buf) {
					jam(buf, "subjectAltname '");
					jam_sanitized_bytes(buf, raw_id, strlen(raw_id)),
					jam(buf, "' matched '");
					jam_sanitized_bytes(buf, current->name.other.data,
							    current->name.other.len);
					jam(buf, "' in certificate");
				}
				PORT_FreeArena(arena, PR_FALSE);
				return TRUE;
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
				dbg("subjectAltname matches address %s",
				    str_address(&myip, &b));
				PORT_FreeArena(arena, PR_FALSE);
				return true;
			}
			address_buf b;
			dbg("subjectAltname does not match address %s",
			    str_address(&myip, &b));
			break;
		}

		default:
			break;
		}
		current = CERT_GetNextGeneralName(current);
	} while (current != nameList);

	LLOG_JAMBUF(RC_LOG_SERIOUS, logger, buf) {
		jam(buf, "certificate subjectAltName extension does not match ");
		jam_enum(buf, &ike_idtype_names, id->kind);
		jam(buf, " '");
		jam_sanitized_bytes(buf, raw_id, strlen(raw_id));
		jam(buf, "'");
	}

	/* Don't free nameList, it's part of the arena. */
	PORT_FreeArena(arena, PR_FALSE);
	return false;
}

SECItem *nss_pkcs7_blob(CERTCertificate *cert, bool send_full_chain)
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
		= SEC_PKCS7CreateCertsOnly(cert,
					   send_full_chain ? PR_TRUE : PR_FALSE,
					   handle);
	SECItem *pkcs7 = SEC_PKCS7EncodeItem(NULL, NULL, content,
					     NULL, NULL, NULL);
	SEC_PKCS7DestroyContentInfo(content);
	return pkcs7;
}
