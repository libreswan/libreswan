/* NSS certificate verification routines for libreswan
 *
 * Copyright (C) 2015,2018 Matt Rogers <mrogers@libreswan.org>
 * Copyright (C) 2017-2018 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2018-2019 Andrew Cagney
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
#include <libreswan.h>
#include "sysdep.h"
#include "lswnss.h"
#include "constants.h"
#include "lswlog.h"
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
		LSWDBGP(DBG_X509, buf) {
			lswlogs(buf, "NSS: cert import calling PK11_GetInternalKeySlot() failed: ");
			lswlog_nss_error(buf);
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
	if (handle == NULL || cert == NULL)
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

	CERTSignedCrl *crl = NULL;

	for (CERTCrlNode *crl_node = crl_list->first; crl_node != NULL;
	     crl_node = crl_node->next) {
		if (crl_node->crl != NULL &&
				SECITEM_ItemsAreEqual(&cert->derIssuer,
						 &crl_node->crl->crl.derName)) {
			crl = crl_node->crl;
			dbg("%s : CRL found", __func__);
			break;
		}
	}

	bool res = crl != NULL && crl_is_current(crl);
	dbg("releasing crl list in %s with result %s",
	     __func__, res ? "true" : "false");
	PORT_FreeArena(crl_list->arena, PR_FALSE);
	return res;
}

static void log_bad_cert(CERTVerifyLogNode *node)
{
	loglog(RC_LOG_SERIOUS, "Certificate %s failed verification",
	       node->cert->subjectName);
	loglog(RC_LOG_SERIOUS, "ERROR: %s",
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
		libreswan_log("certificate revoked!");
	}
}

static void new_vfy_log(CERTVerifyLog *log)
{
	log->count = 0;
	log->head = NULL;
	log->tail = NULL;
	log->arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
}

static CERTCertList *get_all_ca_certs(void)
{
	PK11SlotInfo *slot = PK11_GetInternalKeySlot();

	if (slot == NULL)
		return NULL;

	if (PK11_NeedLogin(slot)) {
		SECStatus rv = PK11_Authenticate(slot, PR_TRUE,
				lsw_return_nss_password_file_info());
		if (rv != SECSuccess)
			return NULL;
	}

	CERTCertList *allcerts = PK11_ListCertsInSlot(slot);

	if (allcerts == NULL)
		return NULL;

	CERTCertList *roots = CERT_NewCertList();

	CERTCertListNode *node;

	/*
	 * XXX: would a better call be:
	 * CERT_FilterCertListByUsage(allcerts, certUsageAnyCA, PR_TRUE)
	 */
	for (node = CERT_LIST_HEAD(allcerts); !CERT_LIST_END(node, allcerts);
						node = CERT_LIST_NEXT(node)) {
		if (CERT_IsCACert(node->cert, NULL) && node->cert->isRoot) {
			CERTCertificate *cert = CERT_DupCertificate(node->cert);
			CERT_AddCertToListTail(roots, cert);
		}
	}

	CERT_DestroyCertList(allcerts);

	if (roots == NULL || CERT_LIST_EMPTY(roots))
		return NULL;

	return roots;
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

#define RETRYABLE_TYPE(err) ((err) == SEC_ERROR_INADEQUATE_CERT_TYPE || \
			      (err) == SEC_ERROR_INADEQUATE_KEY_USAGE)

static bool verify_end_cert(CERTCertList *trustcl,
			    const struct rev_opts *rev_opts,
			    CERTCertificate *end_cert,
			    bool *bad)
{
	CERTVerifyLog *cur_log = NULL;
	CERTVerifyLog vfy_log;
	CERTVerifyLog vfy_log2;

	new_vfy_log(&vfy_log);
	new_vfy_log(&vfy_log2);

	CERTRevocationFlags rev;
	zero(&rev);	/* ??? are there pointer fields?  YES, and different for different union members! */

	PRUint64 revFlagsLeaf[2] = { 0, 0 };
	PRUint64 revFlagsChain[2] = { 0, 0 };

	set_rev_per_meth(&rev, revFlagsLeaf, revFlagsChain);
	set_rev_params(&rev, rev_opts);

	int in_idx = 0;
	CERTValInParam cvin[7];
	CERTValOutParam cvout[3];
	zero(&cvin);	/* ??? are there pointer fields?  YES, and different for different union members! */
	zero(&cvout);	/* ??? are there pointer fields?  YES, and different for different union members! */

	cvin[in_idx].type = cert_pi_revocationFlags;
	cvin[in_idx++].value.pointer.revocation = &rev;

	cvin[in_idx].type = cert_pi_useAIACertFetch;
	cvin[in_idx++].value.scalar.b = rev_opts->ocsp ? PR_TRUE : PR_FALSE;

	cvin[in_idx].type = cert_pi_trustAnchors;
	cvin[in_idx++].value.pointer.chain = trustcl;

	cvin[in_idx].type = cert_pi_useOnlyTrustAnchors;
	cvin[in_idx++].value.scalar.b = PR_TRUE;

	cvin[in_idx].type = cert_pi_end;

	cvout[0].type = cert_po_errorLog;
	cvout[0].value.pointer.log = cur_log = &vfy_log;
	cvout[1].type = cert_po_certList;
	cvout[1].value.pointer.chain = NULL;
	cvout[2].type = cert_po_end;

	bool fin;

#ifdef NSS_IPSEC_PROFILE
	SECStatus rv = CERT_PKIXVerifyCert(end_cert, certificateUsageIPsec,
						cvin, cvout, NULL);
	if (rv != SECSuccess || cur_log->count > 0) {
		if (cur_log->count > 0 && cur_log->head != NULL) {
			log_bad_cert(cur_log->head);
			*bad = true;
			fin = false;
		} else {
			/*
			 * An rv != SECSuccess without CERTVerifyLog
			 * results should not * happen, but catch it anyway
			 */
			loglog(RC_LOG_SERIOUS, "X509: unspecified NSS verification failure");
			fin = false;
		}
	} else {
		DBG(DBG_X509, DBG_log("certificate is valid"));
		fin = true;
	}
#else
	/* kludge alert!!
	 * verification may be performed twice: once with the
	 * 'client' usage and once with 'server', which is an NSS
	 * detail and not related to IKE. In the absence of a real
	 * IKE profile being available for NSS, this covers more
	 * KU/EKU combinations
	 *
	 * double kludge alert!!  What was a simple goto was converted
	 * to a for loop that, while appearing to be infinite,
	 * typically executes once and very occasionally twice.  Look
	 * very carefully for "continue" and "break".
	 */

	SECCertificateUsage usage;

	for (usage = certificateUsageSSLClient; ; usage = certificateUsageSSLServer) {
		SECStatus rv = CERT_PKIXVerifyCert(end_cert, usage, cvin, cvout, NULL);
		if (rv != SECSuccess || cur_log->count > 0) {
			if (cur_log->count > 0 && cur_log->head != NULL) {
				if (usage == certificateUsageSSLClient &&
				    RETRYABLE_TYPE(cur_log->head->error)) {
					/* try again, after some adjustments */
					DBG(DBG_X509,
					    DBG_log("retrying verification with the NSS serverAuth profile"));
					cvout[0].value.pointer.log = cur_log = &vfy_log2;
					cvout[1].value.pointer.chain = NULL;
					continue;
				} else {
					log_bad_cert(cur_log->head);
					*bad = true;
					fin = false;
				}
			} else {
				/*
				 * An rv != SECSuccess without CERTVerifyLog results should not
				 * happen, but catch it anyway
				 */
				libreswan_log("X509: unspecified NSS verification failure");
				fin = false;
			}
		} else {
			DBG(DBG_X509, DBG_log("certificate is valid"));
			fin = true;
		}
		break;
	}
#endif
	PORT_FreeArena(vfy_log.arena, PR_FALSE);
	PORT_FreeArena(vfy_log2.arena, PR_FALSE);

	if (cvout[1].value.pointer.chain != NULL) {
		CERT_DestroyCertList(cvout[1].value.pointer.chain);
	}

	return fin;
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
			     SECItem der_cert)
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
		LSWDBGP(DBG_BASE, buf) {
			lswlogs(buf, "NSS: decoding certs using CERT_ImportCerts() failed: ");
			lswlog_nss_error(buf);
		}
		return;
	}
	dbg("decoded cert: %s", cert->subjectName);

	/* extra verification */
#ifdef FIPS_CHECK
	if (libreswan_fipsmode()) {
		SECKEYPublicKey *pk = CERT_ExtractPublicKey(cert);
		passert(pk != NULL);
		if ((pk->u.rsa.modulus.len * BITS_PER_BYTE) < FIPS_MIN_RSA_KEY_SIZE) {
			libreswan_log("FIPS: Rejecting peer cert with key size %d under %d",
					pk->u.rsa.modulus.len * BITS_PER_BYTE,
					FIPS_MIN_RSA_KEY_SIZE);
			SECKEY_DestroyPublicKey(pk);
			CERT_DestroyCertificate(cert);
			return;
		}
		SECKEY_DestroyPublicKey(pk);
	}
#endif /* FIPS_CHECK */

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
					  struct payload_digest *cert_payloads)
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
			loglog(RC_LOG_SERIOUS, "ignoring certificate with unknown type %d",
			       cert_type);
			continue;
		}

		dbg("saving certificate of type '%s'", cert_name);
		/* convert remaining buffer to something nss  likes */
		chunk_t payload_chunk = same_in_pbs_left_as_chunk(&p->pbs);
		SECItem payload = same_chunk_as_secitem(payload_chunk, siDERCertBuffer);

		switch (cert_type) {
		case CERT_X509_SIGNATURE:
			add_decoded_cert(handle, &certs, payload);
			break;
		case CERT_PKCS7_WRAPPED_X509:
		{
			SEC_PKCS7ContentInfo *contents = SEC_PKCS7DecodeItem(&payload, NULL, NULL, NULL, NULL,
									     NULL, NULL, NULL);
			if (contents == NULL) {
				loglog(RC_LOG_SERIOUS, "Wrapped PKCS7 certificate payload could not be decoded");
				continue;
			}
			if (!SEC_PKCS7ContainsCertsOrCrls(contents)) {
				loglog(RC_LOG_SERIOUS, "Wrapped PKCS7 certificate payload did not contain any certificates");
				SEC_PKCS7DestroyContentInfo(contents);
				continue;
			}
			for (SECItem **cert_list = SEC_PKCS7GetCertificateList(contents);
			     *cert_list; cert_list++) {
				add_decoded_cert(handle, &certs, **cert_list);
			}
			SEC_PKCS7DestroyContentInfo(contents);
			break;
		}
		default:
			loglog(RC_LOG_SERIOUS, "ignoring %s certificate payload", cert_name);
			break;
		}
	}
	return certs;
}

/*
 * Decode and verify the chain received by pluto.
 * ee_out is the resulting end cert
 */
struct certs *find_and_verify_certs(struct state *st,
				    struct payload_digest *cert_payloads,
				    const struct rev_opts *rev_opts,
				    bool *crl_needed, bool *bad)
{
	*crl_needed = false;
	*bad = false;

	if (!pexpect(cert_payloads != NULL)) {
		/* logged by pexpect() */
		return NULL;
	}

	PK11SlotInfo *slot = NULL;
	if (!prepare_nss_import(&slot)) {
		/* logged by above */
		return NULL;
	}

	statetime_t trustcl_time = statetime_start(st);
	CERTCertList *trustcl = get_all_ca_certs(); /* must free trustcl */
	statetime_stop(&trustcl_time, "%s() calling get_all_ca_certs()", __func__);
	if (trustcl == NULL) {
		libreswan_log("No Certificate Authority in NSS Certificate DB! Certificate payloads discarded.");
		return NULL;
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
	statetime_t decode_time = statetime_start(st);
	struct certs *certs = decode_cert_payloads(handle, st->st_ike_version,
						   cert_payloads);
	statetime_stop(&decode_time, "%s() calling decode_cert_payloads()", __func__);
	if (certs == NULL) {
		CERT_DestroyCertList(trustcl);
		return NULL;
	}
	CERTCertificate *end_cert = make_end_cert_first(&certs);
	if (end_cert == NULL) {
		libreswan_log("X509: no EE-cert in chain!");
		release_certs(&certs);
		CERT_DestroyCertList(trustcl);
		return NULL;
	}

	statetime_t crl_time = statetime_start(st);
	*crl_needed = crl_update_check(handle, certs);
	statetime_stop(&crl_time, "%s() calling crl_update_check()", __func__);
	if (*crl_needed) {
		if (rev_opts->crl_strict) {
			*bad = true;
			libreswan_log("missing or expired CRL in strict mode, failing pending update");
			CERT_DestroyCertList(trustcl);
			release_certs(&certs);
			return NULL;
		}
		DBG(DBG_X509, DBG_log("missing or expired CRL"));
	}

	statetime_t verify_time = statetime_start(st);
	bool end_ok = verify_end_cert(trustcl, rev_opts, end_cert, bad);
	statetime_stop(&verify_time, "%s() calling verify_end_cert()", __func__);
	if (!end_ok) {
		release_certs(&certs);
		CERT_DestroyCertList(trustcl);
		return NULL;
	}

	CERT_DestroyCertList(trustcl);
	return certs;
}

bool cert_VerifySubjectAltName(const CERTCertificate *cert, const char *name)
{
	SECItem	subAltName;
	SECStatus rv = CERT_FindCertExtension(cert, SEC_OID_X509_SUBJECT_ALT_NAME,
			&subAltName);
	if (rv != SECSuccess) {
		DBG(DBG_X509, DBG_log("certificate contains no subjectAltName extension"));
		return FALSE;
	}

	ip_address myip;
	bool san_ip = (tnatoaddr(name, 0, AF_UNSPEC, &myip) == NULL);

	PLArenaPool *arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	passert(arena != NULL);

	CERTGeneralName *nameList = CERT_DecodeAltNameExtension(arena, &subAltName);

	if (nameList == NULL) {
		loglog(RC_LOG_SERIOUS, "certificate subjectAltName extension failed to decode");
		PORT_FreeArena(arena, PR_FALSE);
		return FALSE;
	}

	/*
	 * nameList is a pointer into a non-empty circular linked list.
	 * This loop visits each entry.
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
			/*
			 * Match the parameter name with the name in the certificate.
			 * The name in the cert may start with "*."; that will match
			 * any initial component in name (up to the first '.').
			 */
			/* we need to cast because name.other.data is unsigned char * */
			const char *c_ptr = (const void *) current->name.other.data;
			size_t c_len =  current->name.other.len;

			const char *n_ptr = name;
			static const char wild[] = "*.";
			const size_t wild_len = sizeof(wild) - 1;

			if (san_ip)
				break;

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
				/*
				 * ??? if current->name.other.data contains bad characters,
				 * what prevents them being logged?
				 */
				DBG(DBG_X509, DBG_log("subjectAltname %s matched %*s in certificate",
					name, current->name.other.len, current->name.other.data));
				PORT_FreeArena(arena, PR_FALSE);
				return TRUE;
			}
			break;
		}

		case certIPAddress:
			if (!san_ip)
				break;

			if ((current->name.other.len == 4) && (addrtypeof(&myip) == AF_INET)) {
				if (memcmp(current->name.other.data, &myip.u.v4.sin_addr.s_addr, 4) == 0) {
					DBG(DBG_X509, DBG_log("subjectAltname IPv4 matches %s", name));
					PORT_FreeArena(arena, PR_FALSE);
					return TRUE;
				} else {
					DBG(DBG_X509, DBG_log("subjectAltname IPv4 does not match %s", name));
					break;
				}
			}
			if ((current->name.other.len == 16) && (addrtypeof(&myip) == AF_INET6)) {
				if (memcmp(current->name.other.data, &myip.u.v6.sin6_addr.s6_addr, 16) == 0) {
					DBG(DBG_X509, DBG_log("subjectAltname IPv6 matches %s", name));
					PORT_FreeArena(arena, PR_FALSE);
					return TRUE;
				} else {
					DBG(DBG_X509, DBG_log("subjectAltname IPv6 does not match %s", name));
					break;
				}
			}
			DBG(DBG_X509, DBG_log("subjectAltname IP address family mismatch for %s", name));
			break;

		default:
			break;
		}
		current = CERT_GetNextGeneralName(current);
	} while (current != nameList);

	loglog(RC_LOG_SERIOUS, "No matching subjectAltName found");
	/* Don't free nameList, it's part of the arena. */
	PORT_FreeArena(arena, PR_FALSE);
	return FALSE;
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

