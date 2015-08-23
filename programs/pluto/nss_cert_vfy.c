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
#include "nss_copies.h"
#include "nss_cert_vfy.h"
#include "nss_err.h"
#include <secder.h>
#include <secerr.h>
#include <certdb.h>

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

static bool crl_is_current(CERTSignedCrl *crl)
{
	return NSSCERT_CheckCrlTimes(&crl->crl, PR_Now()) != secCertTimeExpired;
}

static CERTSignedCrl *get_issuer_crl(CERTCertDBHandle *handle,
				     CERTCertificate *cert)
{
	CERTCrlHeadNode *crl_list = NULL;
	CERTCrlNode *crl_node = NULL;
	CERTSignedCrl *crl = NULL;

	if (handle == NULL || cert == NULL)
		return NULL;

	DBG(DBG_X509,
	    DBG_log("%s : looking for a CRL issued by %s", __FUNCTION__,
							   cert->issuerName));
	/*
	 * Use SEC_LookupCrls method instead of SEC_FindCrlByName.
	 * For some reason, SEC_FindCrlByName was giving out bad pointers!
	 *
	 * crl = (CERTSignedCrl *)SEC_FindCrlByName(handle, &searchName, SEC_CRL_TYPE);
	 */
	if (SEC_LookupCrls(handle, &crl_list, SEC_CRL_TYPE) != SECSuccess) {
		return NULL;
	}

	crl_node = crl_list->first;

	while (crl_node != NULL) {
		if (crl_node->crl != NULL &&
				SECITEM_ItemsAreEqual(&cert->derIssuer,
						 &crl_node->crl->crl.derName)) {
			crl = crl_node->crl;
			DBG(DBG_X509,
			    DBG_log("%s : CRL found", __FUNCTION__));
			break;
		}
		crl_node = crl_node->next;
	}

	return crl;
}

static bool cert_issuer_has_current_crl(CERTCertDBHandle *handle,
				 CERTCertificate *cert)
{
	CERTSignedCrl *crl = get_issuer_crl(handle, cert);

	if (crl != NULL && crl_is_current(crl))
		return TRUE;

	return FALSE;
}

/*
 * check if any of the certificates have an outdated CRL.
 */
static bool crl_update_check(CERTCertDBHandle *handle,
				   CERTCertificate **chain,
				   int chain_len)
{
	int i;

	for (i = 0; i < chain_len && chain[i] != NULL; i++) {
		if (!cert_issuer_has_current_crl(handle, chain[i])) {
			return TRUE;
		}
	}
	return FALSE;
}

static int nss_err_to_revfail(CERTVerifyLogNode *node)
{
	int ret = VERIFY_RET_FAIL;

	if (node == NULL || node->cert == NULL) {
		return ret;
	}

	DBG(DBG_X509,
	    DBG_log("Certificate %s failed verification : %s",
		    node->cert->subjectName,
		    nss_err_str(node->error)));

	if (node->error == SEC_ERROR_REVOKED_CERTIFICATE) {
		ret = VERIFY_RET_REVOKED;
	}

	return ret;
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

static void set_rev_params(CERTRevocationFlags *rev, bool crl_strict,
						     bool ocsp,
						     bool ocsp_strict)
{
	CERTRevocationTests *rt = &rev->leafTests;
	PRUint64 *rf = rt->cert_rev_flags_per_method;
	DBG(DBG_X509, DBG_log("crl_strict: %d, ocsp: %d, ocsp_strict: %d",
				crl_strict, ocsp, ocsp_strict));

	rt->number_of_defined_methods = cert_revocation_method_count;
	rt->number_of_preferred_methods = 0;

	rf[cert_revocation_method_crl] |= CERT_REV_M_TEST_USING_THIS_METHOD;
	rf[cert_revocation_method_crl] |= CERT_REV_M_FORBID_NETWORK_FETCHING;

	if (ocsp) {
		rf[cert_revocation_method_ocsp] = rev_val_flags(ocsp_strict);
	}
}

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

	zero(&cvin);	/* ??? are there pointer fields? */
	zero(&cvout);	/* ??? are there pointer fields? */
	zero(&rev);	/* ??? are there pointer fields? */

	set_rev_per_meth(&rev, revFlagsLeaf, revFlagsChain);
	set_rev_params(&rev, rev_opts[RO_CRL_S], rev_opts[RO_OCSP],
						 rev_opts[RO_OCSP_S]);
	cvin[in_idx].type = cert_pi_revocationFlags;
	cvin[in_idx++].value.pointer.revocation = &rev;

	cvin[in_idx].type = cert_pi_useAIACertFetch;
	cvin[in_idx++].value.scalar.b = rev_opts[RO_OCSP];

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
			fin = nss_err_to_revfail(cur_log->head);
		} else {
			/* An rv != SECFailure without CERTVerifyLog results should not
			 * happen, but catch it anyways */
			DBG(DBG_X509,
			    DBG_log("unspecified NSS verification failure"));
			fin = VERIFY_RET_FAIL;
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

	if (crl_update_check(handle, cert_chain, chain_len)) {
		if (rev_opts[RO_CRL_S]) {
			DBG(DBG_X509, DBG_log("missing or expired CRL in strict mode, failing pending update"));
			return VERIFY_RET_FAIL | VERIFY_RET_CRL_NEED;
		}
		DBG(DBG_X509, DBG_log("missing or expired CRL"));
		ret |= VERIFY_RET_CRL_NEED;
	}

	ret |= vfy_chain_pkix(cert_chain, chain_len, ee_out, rev_opts);

	return ret;
}
