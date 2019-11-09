/* CRL importer
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
#include <sys/wait.h>		/* for WIFEXITED() et.al. */
#include <cert.h>

#include "nss_crl_import.h"
#include <certdb.h>
#include "defs.h"
#include "log.h"
#include "lswalloc.h"
#include "nss_err.h"
#include "lswnss.h"	/* for lswlog_nss_error() */

static const char crl_name[] = "_import_crl";

/*
 * Calls the _import_crl process to add a CRL to the NSS db.
 */
int send_crl_to_import(u_char *der, size_t len, const char *url)
{
	CERTSignedCrl *crl = NULL;
	CERTCertificate *cacert = NULL;
	PLArenaPool *arena = NULL;
	SECItem crl_si;
	char *arg[4] = { NULL };
	char lenarg[32];
	char crl_path_space[4096]; /* plenty long? */
	ssize_t n = 0;
	int wstatus;
	int ret = -1;
	int pfd[2];

	if (der == NULL || len < 1) {
		DBG_log("CRL buffer error");
		return -1;
	}

	snprintf(lenarg, sizeof(lenarg), "%zu", len);
	arg[1] = (char *)url;
	arg[2] = lenarg;

	/* find a pathname to the CRL import helper */
#if !(defined(macintosh) || (defined(__MACH__) && defined(__APPLE__)))
	/*
	 * The program will be in the same directory as Pluto,
	 * so we use the sympolic link /proc/self/exe to
	 * tell us of the path prefix.
	 */
	n = readlink("/proc/self/exe", crl_path_space,
		sizeof(crl_path_space));
	if (n < 0) {
# ifdef __uClibc__
		/* on some nommu we have no proc/self/exe, try without path */
		*crl_path_space = '\0';
		n = 0;
# else
		EXIT_LOG_ERRNO(errno,
			       "readlink(\"/proc/self/exe\") failed for crl helper");
# endif
	}
#else
	arg[0] = clone_str("/usr/local/libexec/ipsec/_import_crl", "crl helper");
#endif

	if ((size_t)n > sizeof(crl_path_space) - sizeof(crl_name))
		exit_log("path to %s is too long", crl_name);

	while (n > 0 && crl_path_space[n - 1] != '/')
		n--;

	strcpy(crl_path_space + n, crl_name);

	arg[0] = clone_str(crl_path_space, "crl path");

	DBG_log("Calling %s to import CRL - url: %s, der size: %s",
		arg[0],
		arg[1],
		arg[2]);

	crl_si.len = len;
	crl_si.data = der;
	crl_si.type = siBuffer;

	/*
	 * CERT_GetDefaultCertDB() simply returns the contents of a
	 * static variable set by NSS_Initialize().  It doesn't check
	 * the value and doesn't set PR error.  Short of calling
	 * CERT_SetDefaultCertDB(NULL), the value can never be NULL.
	 */
	CERTCertDBHandle *handle = CERT_GetDefaultCertDB();
	passert(handle != NULL);

	/* do some pre-decoding, and check for the issuer.
	 * The issuer name is needed to flush the cache */

	arena = PORT_NewArena(SEC_ASN1_DEFAULT_ARENA_SIZE);

	/* arena owned by crl */
	if ((crl = CERT_DecodeDERCrl(arena, &crl_si, SEC_CRL_TYPE)) == NULL) {
		LSWDBGP(DBG_X509, buf) {
			lswlogs(buf, "NSS: decoding CRL using CERT_DecodeDERCrl() failed: ");
			lswlog_nss_error(buf);
		}
		PORT_FreeArena(arena, FALSE);
		goto end;
	}

	if ((cacert = CERT_FindCertByName(handle, &crl->crl.derName)) == NULL) {
		LSWDBGP(DBG_X509, buf) {
			lswlogs(buf, "NSS: finding cert by name using CERT_FindCertByName() failed: ");
			lswlog_nss_error(buf);
		}
		SEC_DestroyCrl(crl);
		goto end;
	}

	if (pipe(pfd) == -1) {
		DBG_log("pipe() error: %s", strerror(errno));
		goto end;
	}

	pid_t child = fork();

	switch (child) {
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

		waitpid(child, &wstatus, 0);

		if (WIFEXITED(wstatus)) {
			DBG_log("CRL helper exited with status: %d",
					 WEXITSTATUS(wstatus));
			ret = WEXITSTATUS(wstatus);
		}
		pfree(arg[0]);
		break;
	}

	/* update CRL cache */
	if (ret == 0) {
		CERT_CRLCacheRefreshIssuer(handle, &cacert->derSubject);
	}
end:
	if (cacert != NULL)
		CERT_DestroyCertificate(cacert);

	return ret;
}
