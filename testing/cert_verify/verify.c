/*
 * test NSS verification of an end certificate for a particular certUsage
 * launched by usage_test - see README
 *
 * Copyright (C) 2015 Matt Rogers <mrogers@libreswan.org>
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
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "constants.h"
#include <nss.h>
#include <secerr.h>
#include <cert.h>
#include <ocsp.h>

/*
 * typedef enum SECCertUsageEnum {
 *  certUsageSSLClient = 0,
 *  certUsageSSLServer = 1,
 *  certUsageSSLServerWithStepUp = 2,
 *  certUsageSSLCA = 3,
 *  certUsageEmailSigner = 4,
 *  certUsageEmailRecipient = 5,
 *  certUsageObjectSigner = 6,
 *  certUsageUserCertImport = 7,
 *  certUsageVerifyCA = 8,
 *  certUsageProtectedObjectSigner = 9,
 *  certUsageStatusResponder = 10,
 *  certUsageAnyCA = 11
 *} SECCertUsage;
 */

SECCertUsage usage = certUsageSSLClient;
SECCertificateUsage pkixusage = certificateUsageCheckAllUsages;
char *db_dir = NULL;
char *end_file = NULL;
char *sub_file = NULL;
char *rightca_nick = NULL;
PRBool retry_verify = PR_FALSE;
PRBool retried = PR_FALSE;

static void get_file(SECItem *cert, const char *path)
{
	unsigned char *buf;
	size_t fsize;
	FILE *fp = fopen(path, "r");
	if (fp == NULL) {
		printf("error opening %s\n", path);
		exit(1);
	}
	fseek(fp, 0, SEEK_END);
	fsize = (size_t)ftell(fp);
	fseek(fp, 0, SEEK_SET);

	buf = (unsigned char *) PORT_Alloc(fsize);
	if (fread(buf, 1, fsize, fp) != fsize) {
		printf("read failed on %s\n", path);
		exit(1);
	}
	cert->type = siBuffer;
	cert->len = fsize;
	cert->data = buf;
}

static int err_stat(CERTVerifyLogNode *node)
{
	return node->error;
}

static void print_usage(void)
{
	printf("./verify [ -d <nss directory> |\n"
		"	   -e <end certificate file> |\n"
		"	   -n <nickname of end issuer> |\n"
		"	   -u <NSS usage profile> ]\n\n"
		" -u argument must be one of:\n"
		" *  certUsageSSLCLient\n"
		" *  certUsageSSLClient,\n"
		" *  certUsageSSLServer,\n"
		" *  certUsageSSLServerWithStepUp,\n"
		" *  certUsageSSLCA,\n"
		" *  certUsageEmailSigner,\n"
		" *  certUsageEmailRecipient,\n"
		" *  certUsageObjectSigner,\n"
		" *  certUsageUserCertImport,\n"
		" *  certUsageVerifyCA,\n"
		" *  certUsageProtectedObjectSigner,\n"
		" *  certUsageStatusResponder,\n"
		" *  certUsageAnyCA\n");
	exit(-1);
}

static void set_usage(const char *ustr)
{
	if (ustr == NULL)
		return;

	if (!strcmp("certUsageSSLClient", optarg)) {
		usage = certUsageSSLClient;
		pkixusage = certificateUsageSSLClient;
	} else if (!strcmp("certUsageSSLServer", optarg)) {
		usage = certUsageSSLServer;
		pkixusage = certificateUsageSSLServer;
	} else if (!strcmp("certUsageSSLServerWithStepUp", optarg)) {
		usage = certUsageSSLServerWithStepUp;
		pkixusage = certificateUsageSSLServerWithStepUp;
	} else if (!strcmp("certUsageSSLCA", optarg)) {
		usage = certUsageSSLCA;
		pkixusage = certificateUsageSSLCA;
	} else if (!strcmp("certUsageEmailSigner", optarg)) {
		usage = certUsageEmailSigner;
		pkixusage = certificateUsageEmailSigner;
	} else if (!strcmp("certUsageEmailRecipient", optarg)) {
		usage = certUsageEmailRecipient;
		pkixusage = certificateUsageEmailRecipient;
	} else if (!strcmp("certUsageObjectSigner", optarg)) {
		usage = certUsageObjectSigner;
		pkixusage = certificateUsageObjectSigner;
	} else if (!strcmp("certUsageUserCertImport", optarg)) {
		usage = certUsageUserCertImport;
		pkixusage = certificateUsageUserCertImport;
	} else if (!strcmp("certUsageVerifyCA", optarg)) {
		usage = certUsageVerifyCA;
		pkixusage = certificateUsageVerifyCA;
	} else if (!strcmp("certUsageProtectedObjectSigner", optarg)) {
		usage = certUsageProtectedObjectSigner;
		pkixusage = certificateUsageProtectedObjectSigner;
	} else if (!strcmp("certUsageStatusResponder", optarg)) {
		usage = certUsageStatusResponder;
		pkixusage = certificateUsageStatusResponder;
	} else if (!strcmp("certUsageAnyCA", optarg)) {
		usage = certUsageAnyCA;
		pkixusage = certificateUsageAnyCA;
	} else {
		print_usage();
	}
}

/* would not do name in pluto, but dn */
static CERTCertList *get_trust_certlist(CERTCertDBHandle *handle,
				     const char *name)
{
	CERTCertList *trustcl = NULL;
	CERTCertList *tmpcl = NULL;
	CERTCertificate *ca = NULL;
	CERTCertListNode *node = NULL;

	if ((ca = CERT_FindCertByNickname(handle, name)) == NULL) {
		printf("CERT_FindCertByNickname failed %d\n",
				PORT_GetError());
		return NULL;
	}

	if (ca->isRoot) {
		printf("trust anchor: %s\n",ca->subjectName);
		trustcl = CERT_NewCertList();
		CERT_AddCertToListTail(trustcl, ca);
	} else {
		tmpcl = CERT_GetCertChainFromCert(ca, PR_Now(), certUsageAnyCA);
		if (tmpcl == NULL) {
			printf("CERT_GetCertChainFromCert failed %d\n",
					PORT_GetError());
			return NULL;
		}
		for (node = CERT_LIST_HEAD(tmpcl); !CERT_LIST_END(node, tmpcl);
				node = CERT_LIST_NEXT(node)) {
			printf("CERT list: %s\n", node->cert->subjectName);
			if (node->cert->isRoot) {
				trustcl = CERT_NewCertList();
				CERT_AddCertToListTail(trustcl, node->cert);
				break;
			}
		}
	}

	if (trustcl == NULL || CERT_LIST_EMPTY(trustcl)) {
		printf("Trust chain empty!\n");
		return NULL;
	}

	return trustcl;
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

static void set_rev_params(CERTRevocationFlags *rev, PRBool crl,
						     PRBool ocsp,
						     PRBool strict)
{
	CERTRevocationTests *rt = &rev->leafTests;
	PRUint64 *rf = rt->cert_rev_flags_per_method;

	rt->number_of_defined_methods = 0;
	rt->number_of_preferred_methods = 0;

	if (crl) {
		rf[cert_revocation_method_crl] = rev_val_flags(strict);
		rt->number_of_defined_methods++;
	}
	if (ocsp) {
		rf[cert_revocation_method_ocsp] = rev_val_flags(strict);
		rt->number_of_defined_methods++;
	}
}

int main(int argc, char *argv[])
{
	int opt;
	long fin = 0;
	int use_pkix = 0;
	SECStatus rv;
	char pbuf[1024];
	PRBool crlcheck = PR_FALSE;
	PRBool ocspcheck = PR_FALSE;
	PRBool strict = PR_FALSE;
	CERTCertDBHandle *handle = NULL;
	CERTCertificate **certout = NULL;
	CERTVerifyLog vfy_log;
	CERTVerifyLog vfy_log2;
	CERTVerifyLog *cur_log;
	CERTValOutParam *pkixout = NULL;

	SECItem c1;
	SECItem c2;
	SECItem *certs[2];
	certs[0] = &c1;
	certs[1] = &c2;

	int numcerts = 0;
	while ((opt = getopt(argc, argv, "u:d:e:pn:s:coSr")) != -1) {
		switch (opt) {
			/* usage type */
		case 'u':
			set_usage(optarg);
			break;
		case 'd':
			db_dir = optarg;
			break;
		case 's':
			sub_file = optarg;
			break;
		case 'c':
			crlcheck = PR_TRUE;
			break;
		case 'o':
			ocspcheck = PR_TRUE;
			break;
		case 'S':
			strict = PR_TRUE;
			break;
		case 'e':
			end_file = optarg;
			break;
		case 'p':
			use_pkix = 1;
			break;
		case 'n':
			rightca_nick = optarg;
			break;
		case 'r':
			retry_verify = PR_TRUE;
			break;
		default:
			print_usage();
			break;
		}
	}

	if (db_dir == NULL)
		db_dir = "testfiles/";
	if (end_file == NULL)
		end_file = "testfiles/end.pem";

	get_file(certs[numcerts++], end_file);

	if (sub_file != NULL) {
		get_file(certs[numcerts++], sub_file);
	}

	snprintf(pbuf, sizeof(pbuf), "sql:%s", db_dir);
	if (NSS_Initialize(pbuf, "", "", "secmod.db", 0x1) != SECSuccess) {
		printf("NSS_Initialize failed %d\n", PORT_GetError());
		exit(-1);
	}

	if ((handle = CERT_GetDefaultCertDB()) == NULL) {
		printf("NULL handle\n");
		exit(-1);
	}
	if (ocspcheck) {
		CERT_EnableOCSPChecking(handle);
		CERT_DisableOCSPDefaultResponder(handle);
		if (strict)
			CERT_SetOCSPFailureMode(ocspMode_FailureIsNotAVerificationFailure);
	}

	rv = CERT_ImportCerts(handle, 0, numcerts, certs, &certout, PR_FALSE,
							 PR_FALSE, NULL);
	if (rv != SECSuccess) {
		printf("CERT_ImportCerts failed %d\n", PORT_GetError());
		exit(-1);
	}
	vfy_log.count = 0;
	vfy_log.head = NULL;
	vfy_log.tail = NULL;
	vfy_log.arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);

	vfy_log2.count = 0;
	vfy_log2.head = NULL;
	vfy_log2.tail = NULL;
	vfy_log2.arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);

	if (use_pkix) {
		int in_idx = 0;
		CERTValInParam cvin[7];
		CERTValOutParam cvout[3];
		CERTCertList *trustcl = NULL;
		CERTRevocationFlags rev;
		PRUint64 revFlagsLeaf[2] = { 0, 0 };
		PRUint64 revFlagsChain[2] = { 0, 0 };

		zero(&cvin);	/* ??? is this reasonable? */
		zero(&cvout);	/* ??? is this reasonable? */
		zero(&rev);	/* ??? is this reasonable? */

		if (rightca_nick == NULL)
			rightca_nick = "root";

		if ((trustcl = get_trust_certlist(handle, rightca_nick)) == NULL) {
			printf("Couldn't find trust anchor\n");
			exit(-1);
		}

		cvin[in_idx].type = cert_pi_useAIACertFetch;
		cvin[in_idx++].value.scalar.b = PR_TRUE;
		cvin[in_idx].type = cert_pi_revocationFlags;
		cvin[in_idx++].value.pointer.revocation = &rev;
		cvin[in_idx].type = cert_pi_trustAnchors;
		cvin[in_idx++].value.pointer.chain = trustcl;
		cvin[in_idx].type = cert_pi_useOnlyTrustAnchors;
		cvin[in_idx++].value.scalar.b = PR_TRUE;

		set_rev_per_meth(&rev, revFlagsLeaf, revFlagsChain);
		set_rev_params(&rev, crlcheck, ocspcheck, strict);
		cvin[in_idx].type = cert_pi_end;

		cvout[0].type = cert_po_errorLog;
		cvout[0].value.pointer.log = &vfy_log;
		cur_log = &vfy_log;
		cvout[1].type = cert_po_certList;
		cvout[1].value.pointer.chain = NULL;
		cvout[2].type = cert_po_end;
		pkixout = &cvout[0];

pkixredo:
		rv = CERT_PKIXVerifyCert(*certout, pkixusage, cvin, cvout,
				NULL);

		//CERT_DestroyCertList(trustcl);
	} else {
		cur_log = &vfy_log;
vfyredo:
		rv = CERT_VerifyCert(handle, *certout, PR_TRUE, usage, PR_Now(),
								       NULL,
								       cur_log);
	}

	if (rv != SECSuccess || cur_log->count > 0) {
		if (cur_log->count > 0 && cur_log->head != NULL) {
			fin = err_stat(cur_log->head);
		} else {
			fin = PORT_GetError();
		}
		if (fin == SEC_ERROR_INADEQUATE_KEY_USAGE) {
			printf("SEC_ERROR_INADEQUATE_KEY_USAGE : Certificate key usage inadequate for attempted operation.\n"
				);
		} else if (fin == SEC_ERROR_INADEQUATE_CERT_TYPE) {
			printf("SEC_ERROR_INADEQUATE_CERT_TYPE : Certificate type not approved for application.\n"
				);
		} else {
			printf("OTHER : %ld", fin);
		}
	}
	if ((fin == SEC_ERROR_INADEQUATE_CERT_TYPE ||
			fin == SEC_ERROR_INADEQUATE_KEY_USAGE) &&
					 retry_verify && !retried) {
		printf("Retrying verification\n");
		fin = 0;
		retried = PR_TRUE;
		if (use_pkix) {
			pkixout[0].value.pointer.log = &vfy_log2;
			cur_log = &vfy_log2;
			pkixout[1].value.pointer.chain = NULL;
			if (pkixusage == certificateUsageSSLClient) {
				pkixusage = certificateUsageSSLServer;
			} else {
				pkixusage = certificateUsageSSLClient;
			}
			goto pkixredo;
		} else {
			if (usage == certUsageSSLClient) {
				usage = certUsageSSLServer;
			} else {
				usage = certUsageSSLClient;
			}
			goto vfyredo;
		}
	}

	PORT_FreeArena(vfy_log.arena, PR_FALSE);
	PORT_FreeArena(vfy_log2.arena, PR_FALSE);
	NSS_Shutdown();
	exit(fin == 0 ? 0 : 1);
}
