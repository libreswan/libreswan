/* pluto NSS certificate verification routines
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
#include "lswconf.h"
#include "constants.h"
#include "lswlog.h"
#include "x509.h"
#include "nss_cert_vfy.h"
#include <secder.h>
#include <secerr.h>
#include <certdb.h>
/*
 * copies of NSS functions that are not yet exported by the library
 */
static SECStatus _NSSCPY_GetCrlTimes(CERTCrl *date, PRTime *notBefore,
					     PRTime *notAfter)
{
	int rv;
	/* convert DER not-before time */
	rv = DER_DecodeTimeChoice(notBefore, &date->lastUpdate);
	if (rv) {
		return(SECFailure);
	}

	/* convert DER not-after time */
	if (date->nextUpdate.data) {
		rv = DER_DecodeTimeChoice(notAfter, &date->nextUpdate);
		if (rv) {
			return(SECFailure);
		}
	} else {
		LL_I2L(*notAfter, 0L);
	}

	return(SECSuccess);
}

static SECCertTimeValidity _NSSCPY_CheckCrlTimes(CERTCrl *crl, PRTime t)
{
	PRTime notBefore, notAfter, llPendingSlop, tmp1;
	SECStatus rv;
	PRInt32 pSlop = CERT_GetSlopTime();

	rv = _NSSCPY_GetCrlTimes(crl, &notBefore, &notAfter);
	if (rv) {
		return(secCertTimeExpired); 
	}
	LL_I2L(llPendingSlop, pSlop);
	/* convert to micro seconds */
	LL_I2L(tmp1, PR_USEC_PER_SEC);
	LL_MUL(llPendingSlop, llPendingSlop, tmp1);
	LL_SUB(notBefore, notBefore, llPendingSlop);
	if ( LL_CMP( t, <, notBefore ) ) {
		return(secCertTimeNotValidYet);
	}
	/* If next update is omitted and the test for notBefore passes, then
	 * we assume that the crl is up to date.
	 */
	if ( LL_IS_ZERO(notAfter) ) {
		return(secCertTimeValid);
	}
	if ( LL_CMP( t, >, notAfter) ) {
		return(secCertTimeExpired);
	}
	return(secCertTimeValid);
}
/* end NSS copies */

/*
 * set up the slot/handle/trust things that NSS needs
 */
static bool prepare_nss_import(PK11SlotInfo **slot, CERTCertDBHandle **handle)
{
	/*
	 * possibly need to handle passworded db case here
	 */
	if ((*slot = PK11_GetInternalKeySlot()) == NULL) {
		    DBG(DBG_X509,
			DBG_log("PK11_GetInternalKeySlot error [%d]",
				PORT_GetError()));
		return FALSE;
	}

	if ((*handle = CERT_GetDefaultCertDB()) == NULL) {
		    DBG(DBG_X509,
			DBG_log("error getting db handle [%d]",
				PORT_GetError()));
		return FALSE;
	}

	return TRUE;
}

/*
 * returns true if there's a CRL for the cert (from its issuer) that is needing an update
 * *found is for a strict mode check outside this function
 */
static bool crl_needs_update(CERTCertDBHandle *handle,
			     CERTCertificate *cert, bool *found)
{
	CERTCrlHeadNode *crl_list = NULL;
	CERTCrlNode *crl_node = NULL;
	CERTSignedCrl *crl = NULL;

	if (cert == NULL || handle == NULL || found == NULL)
		return FALSE;

	*found = FALSE;

	/* 
	 * Use SEC_LookupCrls method instead of SEC_FindCrlByName.
	 * For some reason, SEC_FindCrlByName was giving out bad pointers!
	 *
	 * crl = (CERTSignedCrl *)SEC_FindCrlByName(handle, &searchName, SEC_CRL_TYPE);
	 */
	if (SEC_LookupCrls(handle, &crl_list, SEC_CRL_TYPE) != SECSuccess) {
		DBG(DBG_X509, DBG_log("no CRLs found"));
		return FALSE;
	}

	crl_node = crl_list->first;

	while (crl_node != NULL) {
		if (crl_node->crl != NULL &&
				SECITEM_ItemsAreEqual(&cert->derIssuer,
						 &crl_node->crl->crl.derName)) {
			crl = crl_node->crl;
			break;
		}

		crl_node = crl_node->next;
	}

	if (crl != NULL) {
		DBG(DBG_X509, DBG_log("CRL for %s found, checking if CRL is up to date",
				      cert->issuerName));
		*found = TRUE;
		if (_NSSCPY_CheckCrlTimes(&crl->crl,
					  PR_Now()) == secCertTimeExpired) {
			DBG(DBG_X509,
			    DBG_log("CRL has expired!"));
			return TRUE;
		}
		DBG(DBG_X509,
		    DBG_log("CRL is current"));
	}

	return FALSE;
}

/*
 * check if any of the certificates have an outdated CRL.
 */
static bool crl_update_check(CERTCertDBHandle *handle,
				   CERTCertificate **chain,
				   int chain_len,
				   bool *found)
{
	int i;
	bool needupdate = FALSE;

	for (i = 0; i < chain_len && chain[i] != NULL; i++) {
		if (crl_needs_update(handle, chain[i], found)) {
			needupdate = TRUE;
			DBG(DBG_X509,
			    DBG_log("CRL update needed"));
			break;
		}
	}
	return needupdate;
}

static int translate_nss_err(long err, bool ca)
{
	int ret;
	char *hd = ca ? "CA" : "Peer";

	switch (err) {
	case SEC_ERROR_INADEQUATE_KEY_USAGE:
		DBG(DBG_X509,
		    DBG_log("%s certificate has inadequate keyUsage flags", hd));
		ret = VERIFY_RET_FAIL;
		break;
	case SEC_ERROR_INADEQUATE_CERT_TYPE:
		DBG(DBG_X509,
		    DBG_log("%s certificate type is not approved for this application (EKU)", hd));
		ret = VERIFY_RET_FAIL;
		break;
	case SEC_ERROR_UNKNOWN_ISSUER:
		DBG(DBG_X509,
		    DBG_log("%s certificate issuer not recognized", hd));
		ret = VERIFY_RET_FAIL;
		break;
	case SEC_ERROR_OCSP_UNKNOWN_CERT:
		DBG(DBG_X509,
		    DBG_log("The OCSP server has no status for the certificate"));
		ret = VERIFY_RET_FAIL;
		break;
	case SEC_ERROR_UNTRUSTED_ISSUER:
		DBG(DBG_X509,
		    DBG_log("%s certificate issuer has been marked as not trusted by the user", hd));
		ret = VERIFY_RET_FAIL;
		break;
	case SEC_ERROR_REVOKED_CERTIFICATE:
		DBG(DBG_X509,
		    DBG_log("%s certificate has been revoked", hd));
		ret = VERIFY_RET_REVOKED;
		break;
	default:
		DBG(DBG_X509,
		    DBG_log("%s certificate verify failed [%ld]", hd, err));
		ret = VERIFY_RET_FAIL;
		break;
	}
	return ret;

}

static int get_node_error_status(CERTVerifyLogNode *node)
{
	if (node == NULL || node->cert == NULL)
		return VERIFY_RET_FAIL;

	DBG(DBG_X509,
	    DBG_log("Certificate %s failed verification [%ld]",
		    node->cert->subjectName,
		    node->error));

	return translate_nss_err(node->error, CERT_IsCACert(node->cert, NULL));
}

/*
 * Does a temporary import, which decodes the entire chain and allows
 * CERT_VerifyCert to verify the chain when passed the end certificate 
 */
static int crt_tmp_import(CERTCertDBHandle *handle, CERTCertificate ***chain,
						      SECItem *ders,
						      int der_cnt)
{
	SECStatus rv;
	int i, fin_count = 0;
	int nonroot = 0;
	CERTCertificate **cc = NULL;
	SECItem **derlist = NULL;

	if (der_cnt < 1) {
		DBG(DBG_X509, DBG_log("nothing to decode"));
		return 0;
	}

	derlist = (SECItem **) PORT_Alloc(sizeof(SECItem *) * der_cnt);

	for (i = 0; i < der_cnt; i++) {
		if (!CERT_IsRootDERCert(&ders[i]))
			derlist[nonroot++] = &ders[i];
	}

	if (nonroot < 1) {
		DBG(DBG_X509, DBG_log("nothing to decode"));
		fin_count = 0;
		goto done;
	}

	rv = CERT_ImportCerts(handle, 0, nonroot, derlist, chain, PR_FALSE,
							          PR_FALSE,
							          NULL);
	if (rv != SECSuccess || *chain == NULL) {
		DBG(DBG_X509, DBG_log("could not decode any certs"));
		goto done;
	}

	for (cc = *chain; fin_count < nonroot && *cc != NULL; cc++) {
		DBG(DBG_X509, DBG_log("decoded %s", (*cc)->subjectName));
		fin_count++;
	}

done:
	PORT_Free(derlist);
	return fin_count;
}

static void new_vfy_log(CERTVerifyLog *log)
{
	log->count = 0;
	log->head = NULL;
	log->tail = NULL;
	log->arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
}

static CERTCertList *get_all_root_certs(void)
{
	PK11SlotInfo *slot = NULL;
	CERTCertList *allcerts = NULL;
	CERTCertList *roots = NULL;
	CERTCertListNode *node = NULL;

	if ((slot = PK11_GetInternalKeySlot()) == NULL)
		return NULL;

	if (PK11_NeedLogin(slot)) {
		SECStatus rv = PK11_Authenticate(slot, PR_TRUE,
				lsw_return_nss_password_file_info());
		if (rv != SECSuccess)
			return NULL;
	}
	allcerts = PK11_ListCertsInSlot(slot);

	if (allcerts == NULL)
		return NULL;

	roots = CERT_NewCertList();

	for (node = CERT_LIST_HEAD(allcerts); !CERT_LIST_END(node, allcerts);
					        node = CERT_LIST_NEXT(node)) {
		if (CERT_IsCACert(node->cert, NULL) && node->cert->isRoot)
			CERT_AddCertToListTail(roots, node->cert);
	}

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

static unsigned int rev_val_flags(PRBool strict)
{
	unsigned int flags = 0;
	flags |= CERT_REV_M_TEST_USING_THIS_METHOD;
	if (strict) {
		flags |= CERT_REV_M_REQUIRE_INFO_ON_MISSING_SOURCE;
		flags |= CERT_REV_M_FAIL_ON_MISSING_FRESH_INFO;
	}
	return flags;
}

static void set_rev_params(CERTRevocationFlags *rev, bool crl,
						     bool crl_strict,
						     bool ocsp,
						     bool ocsp_strict)
{
	CERTRevocationTests *rt = &rev->leafTests;
	PRUint64 *rf = rt->cert_rev_flags_per_method;
	DBG(DBG_X509, DBG_log("crl: %d, crl_strict: %d, ocsp: %d, ocsp_strict: %d",
				crl, crl_strict, ocsp, ocsp_strict));

	rt->number_of_defined_methods = cert_revocation_method_count;
	rt->number_of_preferred_methods = 0;

	if (crl) {
		rf[cert_revocation_method_crl] = rev_val_flags(crl_strict);
	}
	if (ocsp) {
		rf[cert_revocation_method_ocsp] = rev_val_flags(ocsp_strict);
	}
}

#define CRL_OR_OCSP(r) (r[RO_CRL] || r[RO_OCSP])
#define RETRY_TYPE(err, re) ((err == SEC_ERROR_INADEQUATE_CERT_TYPE || \
			      err == SEC_ERROR_INADEQUATE_KEY_USAGE) && re)

static int vfy_chain_pkix(CERTCertificate **chain, int chain_len,
						   CERTCertificate **end_out,
						   bool *rev_opts)
{
	int in_idx = 0;
	int i;
	int fin = 0;
	bool reverify = TRUE;
	SECStatus rv;
	CERTVerifyLog vfy_log;
	CERTVerifyLog vfy_log2;
	CERTVerifyLog *cur_log = NULL;
	CERTCertificate *end_cert = NULL;
	CERTValInParam cvin[7];
	CERTValOutParam cvout[3];
	CERTCertList *trustcl = NULL;
	CERTRevocationFlags rev;
	SECCertificateUsage usage = certificateUsageSSLClient;
	PRUint64 revFlagsLeaf[2] = { 0, 0 };
	PRUint64 revFlagsChain[2] = { 0, 0 };

	for (i = 0; i < chain_len; i++) {
		if (!CERT_IsCACert(chain[i], NULL)) {
		       end_cert = chain[i];
		       break;
		}
	}

	if (end_cert == NULL) {
		DBG(DBG_X509, DBG_log("no end cert in chain!"));
		return VERIFY_RET_FAIL;
	}

	if ((trustcl = get_all_root_certs()) == NULL) {
		DBG(DBG_X509, DBG_log("no trust anchor available for verification"));
		return VERIFY_RET_FAIL;
	}

	new_vfy_log(&vfy_log);
	new_vfy_log(&vfy_log2);
	zero(&cvin);
	zero(&cvout);
	zero(&rev);

	set_rev_per_meth(&rev, revFlagsLeaf, revFlagsChain);
	set_rev_params(&rev, rev_opts[RO_CRL], rev_opts[RO_CRL_S],
			     rev_opts[RO_OCSP], rev_opts[RO_OCSP_S]);
	cvin[in_idx].type = cert_pi_revocationFlags;
	cvin[in_idx++].value.pointer.revocation = &rev;

	cvin[in_idx].type = cert_pi_useAIACertFetch;
	cvin[in_idx++].value.scalar.b = CRL_OR_OCSP(rev_opts);

	cvin[in_idx].type = cert_pi_trustAnchors;
	cvin[in_idx++].value.pointer.chain = trustcl;

	cvin[in_idx].type = cert_pi_useOnlyTrustAnchors;
	cvin[in_idx++].value.scalar.b = PR_TRUE;

	cvin[in_idx].type = cert_pi_end;

	cvout[0].type = cert_po_errorLog;
	cvout[0].value.pointer.log = &vfy_log;
	cur_log = &vfy_log;
	cvout[1].type = cert_po_certList;
	cvout[1].value.pointer.chain = NULL;
	cvout[2].type = cert_po_end;

	/* kludge alert!!
	 * verification may be performed twice: once with the
	 * 'client' usage and once with 'server', which is an NSS
	 * detail and not related to IKE. In the absense of a real
	 * IKE profile being available for NSS, this covers more
	 * KU/EKU combinations
	 */
retry:
	rv = CERT_PKIXVerifyCert(end_cert, usage, cvin, cvout, NULL);

	if (rv != SECSuccess || cur_log->count > 0) {
		if (cur_log->count > 0 && cur_log->head != NULL) {
			if (RETRY_TYPE(cur_log->head->error, reverify)) {
				DBG(DBG_X509,
				    DBG_log("retrying verification with the NSS serverAuth profile"));
				cur_log = &vfy_log2;
				cvout[0].value.pointer.log = cur_log;
				cvout[1].value.pointer.chain = NULL;
				usage = certificateUsageSSLServer;
				reverify = FALSE;
				goto retry;
			}
			fin = get_node_error_status(cur_log->head);
		} else {
			fin = translate_nss_err(PORT_GetError(), FALSE);
		}
	} else {
		DBG(DBG_X509, DBG_log("certificate is valid"));
		*end_out = end_cert;
		fin = VERIFY_RET_OK;
	}
	CERT_DestroyCertList(trustcl);

	return fin;
}

static void chunks_to_si(chunk_t *chunks, SECItem *items, int chunk_n,
						          int max_i)
{
	int i;

	for (i = 0; i < chunk_n && i < max_i; i++) {
		items[i] = chunk_to_secitem(chunks[i]);
	}
}

#define VFY_INVALID_USE(d, n) (d == NULL || \
			       d[0].ptr == NULL || \
			       d[0].len < 1 || \
			       n < 1 || \
			       n > MAX_CA_PATH_LEN)

/*
 * Decode and verify the chain received by pluto.
 * ee_out is the resulting end cert
 */
int verify_and_cache_chain(chunk_t *ders, int num_ders, CERTCertificate **ee_out,
							bool *rev_opts)
{
	SECItem si_ders[MAX_CA_PATH_LEN] = { {siBuffer, NULL, 0} };
	CERTCertificate **cert_chain = NULL;
	PK11SlotInfo *slot = NULL;
	CERTCertDBHandle *handle = NULL;
	int chain_len = 0;
	int ret = 0;
	bool need_fetch = FALSE;
	bool crlfound = FALSE;

	if (VFY_INVALID_USE(ders, num_ders))
		return -1;

	chunks_to_si(ders, si_ders, num_ders, MAX_CA_PATH_LEN);

	if (!prepare_nss_import(&slot, &handle))
		return -1;
	/*
	 * In order for NSS to verify an entire chain, down to a
	 * CA loaded permanently into the NSS db, a temporary import
	 * is done which decodes and adds the certs to the in-memory
	 * cache. When CERT_VerifyCert is called against the end
	 * certificate both permanent and in-memory cache are used
	 * together to try to complete the chain.
	 */
	if ((chain_len = crt_tmp_import(handle, &cert_chain,
					          si_ders,
					          num_ders)) < 1)
		return -1;

	if ((need_fetch = crl_update_check(handle, cert_chain,
							 chain_len,
							 &crlfound))) {
		if (rev_opts[RO_CRL_S]) {
			DBG(DBG_X509, DBG_log("CRL expired in strict mode, failing pending update"));
			return VERIFY_RET_FAIL | VERIFY_RET_CRL_NEED;
		}
	}

	if (rev_opts[RO_CRL_S] && !crlfound) {
		DBG(DBG_X509, DBG_log("no CRL found in strict mode, failing"));
		return VERIFY_RET_FAIL | VERIFY_RET_CRL_NEED;
	}

	ret |= need_fetch ? VERIFY_RET_CRL_NEED : 0;

	ret |= vfy_chain_pkix(cert_chain, chain_len, ee_out, rev_opts);

	return ret;
}
