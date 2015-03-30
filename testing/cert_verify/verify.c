/*
 * test NSS verification of an end certificate for a particular certUsage
 * launched by usage_test - see README
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
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <nss.h>
#include <secerr.h>
#include <cert.h>

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
char *db_dir = NULL;
char *end_file = NULL;

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
	fread(buf, fsize, 1, fp);
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

int main(int argc, char *argv[])
{
	int opt;
	long fin = 0;
	SECStatus rv;
	char pbuf[1024];
	CERTCertDBHandle *handle = NULL;
	CERTCertificate **certout = NULL;
	CERTVerifyLog vfy_log;

	SECItem *certptr = (SECItem *) PORT_Alloc(sizeof(SECItem));
	while ((opt = getopt(argc, argv, "u:d:e:")) != -1) {
		switch(opt) {
			/* usage type */
		case 'u':
			if (!strcmp("certUsageSSLClient", optarg)) {
				usage = certUsageSSLClient;
			} else if (!strcmp("certUsageSSLServer", optarg)) {
				usage = certUsageSSLServer;
			} else if (!strcmp("certUsageSSLServerWithStepUp", optarg)) {
				usage = certUsageSSLServerWithStepUp;
			} else if (!strcmp("certUsageSSLCA", optarg)) {
				usage = certUsageSSLCA;
			} else if (!strcmp("certUsageEmailSigner", optarg)) {
				usage = certUsageEmailSigner;
			} else if (!strcmp("certUsageEmailRecipient", optarg)) {
				usage = certUsageEmailRecipient;
			} else if (!strcmp("certUsageObjectSigner", optarg)) {
				usage = certUsageObjectSigner;
			} else if (!strcmp("certUsageUserCertImport", optarg)) {
				usage = certUsageUserCertImport;
			} else if (!strcmp("certUsageVerifyCA", optarg)) {
				usage = certUsageVerifyCA;
			} else if (!strcmp("certUsageProtectedObjectSigner", optarg)) {
				usage = certUsageProtectedObjectSigner;
			} else if (!strcmp("certUsageStatusResponder", optarg)) {
				usage = certUsageStatusResponder;
			} else if (!strcmp("certUsageAnyCA", optarg)) {
				usage = certUsageAnyCA;
			} else {
				print_usage();
			}
			break;
		case 'd':
			db_dir = optarg;
			break;
		case 'e':
			end_file = optarg;
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

	get_file(certptr, end_file);

	snprintf(pbuf, sizeof(pbuf), "sql:%s", db_dir);
	if (NSS_Initialize(pbuf, "", "", "secmod.db", 0x1) != SECSuccess) {
		printf("NSS_Initialize failed %d\n", PORT_GetError());
		exit(-1);
	}

	if ((handle = CERT_GetDefaultCertDB()) == NULL) {
		printf("NULL handle\n");
		exit(-1);
	}
	/*
	 * The same CERT_ImportCerts and CERT_VerifyCert routines used
	 * by pluto
	 */
	rv = CERT_ImportCerts(handle, 0, 1, &certptr, &certout, PR_FALSE,
						         PR_FALSE, NULL);
	if (rv != SECSuccess) {
		printf("CERT_ImportCerts failed %d\n", PORT_GetError());
		exit(-1);
	}
	vfy_log.count = 0;
	vfy_log.head = NULL;
	vfy_log.tail = NULL;
	vfy_log.arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);

	rv = CERT_VerifyCert(handle, *certout, PR_TRUE, usage, PR_Now(),
							       NULL,
							       &vfy_log);

	if (rv != SECSuccess || vfy_log.count > 0) {
		if (vfy_log.count > 0 && vfy_log.head != NULL) {
			fin = err_stat(vfy_log.head);
		} else {
			fin = PORT_GetError();
		}
		if (fin == SEC_ERROR_INADEQUATE_KEY_USAGE) {
			printf("SEC_ERROR_INADEQUATE_KEY_USAGE : Certificate key usage inadequate for attempted operation."
				);
		} else if (fin == SEC_ERROR_INADEQUATE_CERT_TYPE) {
			printf("SEC_ERROR_INADEQUATE_CERT_TYPE : Certificate type not approved for application."
				);
		} else {
			printf("OTHER : %ld", fin);
		}
	}
	exit(fin == 0 ? 0 : 1);
}
