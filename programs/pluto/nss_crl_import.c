/* CRL importer
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
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "lswlog.h"
#include <sys/wait.h>
#include <cert.h>
#include "nss_crl_import.h"

#include <certdb.h>
/* 
 * Calls the _import_crl process to add a CRL to the NSS db.
 */
int send_crl_to_import(u_char *der, size_t len, const char *url)
{

	CERTSignedCrl *crl = NULL;
	CERTCertificate *cacert = NULL;
	CERTCertDBHandle *handle = NULL;
	PLArenaPool *arena = NULL;
	SECItem crl_si;
	char *arg[4] = { NULL };
	char lenarg[32];
	int wstatus;
	int ret = -1;
	int pfd[2];

	if (der == NULL || len < 1) {
		DBG_log("CRL buffer error");
		return -1;
	}

	snprintf(lenarg, sizeof(lenarg), "%lu", len);
	arg[0] = PLUTO_CRL_HELPER;
	arg[1] = (char *)url;
	arg[2] = lenarg;

	DBG_log("Calling %s to import CRL - url: %s, der size: %s",
						  arg[0],
						  arg[1],
						  arg[2]);

	crl_si.len = len;
	crl_si.data = der;
	crl_si.type = siBuffer;

	/* do some pre-decoding, and check for the issuer.
	 * The issuer name is needed to flush the cache */
	if ((handle = CERT_GetDefaultCertDB()) == NULL) {
		DBG(DBG_X509,
		    DBG_log("could not get db handle %d", PORT_GetError()));
		return -1;
	}

	arena = PORT_NewArena(SEC_ASN1_DEFAULT_ARENA_SIZE);

	/* arena owned by crl */
	if ((crl = CERT_DecodeDERCrl(arena, &crl_si, SEC_CRL_TYPE)) == NULL) {
		DBG(DBG_X509,
		    DBG_log("could not decode crl %d", PORT_GetError()));
		PORT_FreeArena(arena, FALSE);
		goto end;
	}

	if ((cacert = CERT_FindCertByName(handle, &crl->crl.derName)) == NULL) {
		DBG(DBG_X509,
		    DBG_log("could not find cert by crl.derName %d",
							       PORT_GetError()));
		SEC_DestroyCrl(crl);
		goto end;
	}

	if (pipe(pfd) == -1) {
		DBG_log("pipe() error: %s", strerror(errno));
		goto end;
	}
	switch(fork()) {
	case -1:
		DBG_log("fork() error: %s", strerror(errno));
		break;
	case 0: /*child*/
		if (close(pfd[1]) == -1) {
			DBG_log("close(pfd[1]) error: %s",
				 strerror(errno));
			break;
		}

		if (pfd[0] != STDIN_FILENO) {
			if (dup2(pfd[0], STDIN_FILENO) == -1) {
				DBG_log("dup2() error: %s",
					 strerror(errno));
				break;
			}
			if (close(pfd[0]) == -1) {
				DBG_log("close() error: %s",
					 strerror(errno));
				break;
			}
		}
		execve(arg[0], arg, NULL);
		DBG_log("execve() error: %s", strerror(errno));
		break;
	default: /*parent*/
		if (close(pfd[0]) == -1) {
			DBG_log("close(pfd[0]) error: %s",
				 strerror(errno));
			break;
		}
		if (write(pfd[1], der, len) != (ssize_t)len) {
			DBG_log("partial/failed write");
			break;
		}
		if (close(pfd[1]) == -1) {
			DBG_log("close(pfd[1]) error: %s",
					strerror(errno));
			break;
		}
		wait(&wstatus);

		if (WIFEXITED(wstatus)) {
			DBG_log("CRL helper exited with status: %d",
					 WEXITSTATUS(wstatus));
			ret = WEXITSTATUS(wstatus);
		}
		break;
	}

	/* update CRL cache */
	if (ret == 0) {
		CERT_CRLCacheRefreshIssuer(CERT_GetDefaultCertDB(),
					   &cacert->derSubject);
	}
end:
	if (cacert != NULL)
		CERT_DestroyCertificate(cacert);

	return ret;
}
