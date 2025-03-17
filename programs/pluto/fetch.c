/* Dynamic fetching of X.509 CRLs, for libreswan
 *
 * Copyright (C) 2015 Matt Rogers <mrogers@libreswan.org>
 * Copyright (C) 2002 Stephane Laroche <stephane.laroche@colubris.com>
 * Copyright (C) 2002-2004 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2003-2008 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
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

#include <pthread.h>    /* Must be the first include file */
#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>		/* for WIFEXITED() et.al. */

#include <cert.h>
#include <certdb.h>

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "id.h"
#include "asn1.h"
#include "pem.h"
#include "x509.h"
#include "fetch.h"
#include "secrets.h"
#include "keys.h"
#include "crl_queue.h"
#include "server.h"
#include "lswnss.h"			/* for llog_nss_error() */
#include "whack_shutdown.h"		/* for exiting_pluto; */

static pthread_t fetch_thread_id;
static fetch_crl_fn fetch_crl; /* type check */

/*
 * Calls the _import_crl process to add a CRL to the NSS db.
 */
static int send_crl_to_import(const char *url, struct logger *logger)
{
	deltatime_buf td;

	char *arg[] = {
		IPSEC_EXECDIR "/_import_crl",
		(char*)url,
		(char*)str_deltatime(crl_fetch_timeout, &td),
		(curl_iface == NULL ? "" : curl_iface),
		NULL,
	};

	dbg("Calling %s to import CRL - url: %s %s %s",
	    arg[0],
	    arg[1],
	    arg[2],
	    arg[3]);

	int pfd[2];
	if (pipe(pfd) == -1) {
		dbg("pipe() error: %s", strerror(errno));
		return -1;
	}

	if (PBAD(logger, pfd[0] == STDIN_FILENO) ||
	    PBAD(logger, pfd[1] == STDERR_FILENO) ||
	    PBAD(logger, pfd[1] == STDERR_FILENO)) {
		return -1;
	}

	pid_t child = fork();

	if (child < 0) {
		llog_error(logger, errno, "fork(_import_crl)");
		return -1;
	}

	if (child == 0) {

		dup2(pfd[1], STDERR_FILENO);
		dup2(pfd[1], STDOUT_FILENO);
		dup2(pfd[0], STDIN_FILENO);

		close(pfd[0]);
		close(pfd[1]);

		execve(arg[0], arg, NULL);
		llog_error(logger, errno, "execve()");
		exit(127);
	}

	/*parent*/

	if (close(pfd[1]) == -1) {
		llog_error(logger, errno, "close(pfd[1])");
		return -1;
	}

	int wstatus;
	waitpid(child, &wstatus, 0);

	if (!WIFEXITED(wstatus)) {
		llog_error(logger, 0, "CRL helper aborted status: %d", wstatus);
		return -1;
	}

	int ret = WEXITSTATUS(wstatus);
	if (ret != 0) {
		llog_error(logger, 0, "CRL helper exited with status: %d", ret);
		return -1;
	}

	ldbg(logger, "CRL helper ran successfully");

	uint8_t namebuf[1023];
	ssize_t l = read(pfd[0], namebuf, sizeof(namebuf));
	if (l < 0) {
		llog_error(logger, errno, "read(pfd[0])");
		return -1;
	}

	chunk_t der_name = chunk2(namebuf, l);
	ldbg(logger, "CRL helper output %zu bytes:", l);
	ldbg_hunk(logger, der_name);
	pemtobin(&der_name);
	ldbg(logger, "CRL helper output pem:");
	ldbg_hunk(logger, der_name);

	if (close(pfd[0]) == -1) {
		llog_error(logger, errno, "close(pfd[0])");
		return -1;
	}

	/*
	 * CERT_GetDefaultCertDB() simply returns the contents of a
	 * static variable set by NSS_Initialize().  It doesn't check
	 * the value and doesn't set PR error.  Short of calling
	 * CERT_SetDefaultCertDB(NULL), the value can never be NULL.
	 */
	CERTCertDBHandle *handle = CERT_GetDefaultCertDB();
	passert(handle != NULL);
	SECItem name = {
		.type = siBuffer,
		.data = der_name.ptr,
		.len = der_name.len,
	};
	CERTCertificate *cacert =  CERT_FindCertByName(handle, &name);
	if (cacert == NULL) {
		ldbg_nss_error(logger, "finding cert by name using CERT_FindCertByName() failed");
		return -1;
	}

	CERT_CRLCacheRefreshIssuer(handle, &cacert->derSubject);
	ldbg(logger, "CRL issuer %s flushed", cacert->nickname);

	CERT_DestroyCertificate(cacert);

	return 0;
}

/*
 * try to fetch the crls defined by the fetch requests
 */

static bool fetch_crl(chunk_t issuer_dn, const char *url, struct logger *logger)
{
	/* err?!?! */
	if (!pexpect(url != NULL && strlen(url) > 0)) {
		return false;
	}

	/* for CRL use the name passed to helper for the uri */
	int r = send_crl_to_import(url, logger);
	bool ret;
	if (r == -1) {
		ret = false;
		llog(RC_LOG, logger, "_import_crl internal error");
	} else if (r != 0) {
		ret = false;
		llog_nss_error_code(RC_LOG, logger, r, "CRL import error");
	} else {
		ret = true;
		LLOG_JAMBUF(RC_LOG, logger, buf) {
			jam(buf, "imported CRL for '");
			jam_dn(buf, ASN1(issuer_dn), jam_sanitized_bytes);
			jam(buf, "' from: %s", url);
		}
	}
	return ret;
}

/*
 * Submit all known CRLS for processing using
 * append_crl_fetch_request().
 *
 * Any duplicates will be eliminated by submit_crl_fetch_request()
 * when it merges these requests with any still unprocessed requests.
 *
 * Similarly, if check_crls() is called more frequently than
 * fetch_crl() can process, redundant fetches will be merged.
 */

static void check_crls(struct logger *logger)
{
	/*
	 * Shallow - contents point into existing structures.
	 */
	struct crl_fetch_request *requests = NULL;

	if (deltasecs(crl_check_interval) <= 0) {
		llog(RC_LOG, logger, "config crlcheckinterval= is unset");
		return;
	}

	/* schedule the next probe */
	schedule_oneshot_timer(EVENT_CHECK_CRLS, crl_check_interval);

	/*
	 * CERT_GetDefaultCertDB() simply returns the contents of a
	 * static variable set by NSS_Initialize().  It doesn't check
	 * the value and doesn't set PR error.  Short of calling
	 * CERT_SetDefaultCertDB(NULL), the value can never be NULL.
	 */
	CERTCertDBHandle *handle = CERT_GetDefaultCertDB();
	passert(handle != NULL);

	/*
	 * Add NSS's CRLs.
	 */

	CERTCrlHeadNode *crl_list = NULL; /* must free; but after submitting requests */
	if (SEC_LookupCrls(handle, &crl_list, SEC_CRL_TYPE) != SECSuccess) {
		return;
	}

	for (CERTCrlNode *n = crl_list->first; n != NULL; n = n->next) {
		if (n->crl != NULL) {
			chunk_t issuer = same_secitem_as_chunk(n->crl->crl.derName);
			/* XXX: URL can be null, gets filled in later */
			add_crl_fetch_request(ASN1(issuer), shunk1(n->crl->url), &requests, logger);
		}
	}

	/*
	 * Add the pubkeys distribution points to fetch list.
	 */

	for (struct pubkey_list *pkl = pluto_pubkeys; pkl != NULL; pkl = pkl->next) {
		struct pubkey *key = pkl->key;
		if (key != NULL) {
			add_crl_fetch_request(key->issuer, null_shunk, &requests, logger);
		}
	}

	/*
	 * Iterate all X.509 certificates in database. This is needed to
	 * process middle and end certificates.
	 *
	 * Free this after the requests have been appended.
	 */
	CERTCertList *certs = get_all_certificates(logger); /* must free; but after submitting requests */
	if (certs != NULL) {
		for (CERTCertListNode *node = CERT_LIST_HEAD(certs);
		     !CERT_LIST_END(node, certs);
		     node = CERT_LIST_NEXT(node)) {
			chunk_t issuer = same_secitem_as_chunk(node->cert->derSubject);
			add_crl_fetch_request(ASN1(issuer), null_shunk, &requests, logger);
		}
	}

	/*
	 * Submit the requests and then release them.
	 *
	 * Only then release all the data structures that the requests
	 * are pointing into.
	 */

	submit_crl_fetch_requests(&requests, logger);

	dbg("CRL: releasing cert list in %s()", __func__);
	if (certs != NULL) {
		CERT_DestroyCertList(certs);
	}

	dbg("CRL: releasing crl list in %s()", __func__);
	PORT_FreeArena(crl_list->arena, PR_FALSE);
}

static void *fetch_thread(void *arg UNUSED)
{
	dbg("CRL: fetch thread started");
	/* XXX: on thread so no whack */
	struct logger *logger = string_logger(HERE, "crl thread: "); /* must free */
	process_crl_fetch_requests(fetch_crl, logger);
	free_logger(&logger, HERE);
	dbg("CRL: fetch thread stopped");
	return NULL;
}

/*
 * initializes curl and starts the fetching thread
 */
void start_crl_fetch_helper(struct logger *logger)
{
	/*
	 * XXX: CRT checking is probably really a periodic timer,
	 * however: the first fetch 5 seconds after startup; and
	 * further fetches are defined by the config(?) file (is that
	 * loaded before this function was called? yes).
	 */
	init_oneshot_timer(EVENT_CHECK_CRLS, check_crls);
	if (deltasecs(crl_check_interval) <= 0) {
		dbg("CRL: checking disabled");
		return;
	}

	int status;
	status = pthread_create(&fetch_thread_id, NULL,
				fetch_thread, NULL);
	if (status != 0) {
		fatal(PLUTO_EXIT_FAIL, logger,
		      "could not start thread for fetching certificate, status = %d", status);
	}

	if (impair.event_check_crls) {
		llog(RC_LOG, logger, "IMPAIR: not scheduling EVENT_CHECK_CRLS");
		return;
	}

	/*
	 * XXX: why the delay?
	 *
	 * To give pluto time to settle, or so that tests can do stuff
	 * before the CRL fetch list has been refreshed (for the
	 * latter, use impair.event_check_crls).
	 */
	schedule_oneshot_timer(EVENT_CHECK_CRLS, deltatime(5));
}

void stop_crl_fetch_helper(struct logger *logger)
{
	if (deltasecs(crl_check_interval) > 0) {
		/*
		 * Log before blocking.  If the CRL fetch helper is
		 * currently fetching a CRL, this could take a bit.
		 */
		llog(RC_LOG, logger, "shutting down the CRL fetch helper thread");
		pexpect(exiting_pluto);
		/* wake the sleeping dragon from its slumber */
		submit_crl_fetch_requests(NULL, logger);
		/* use a timer? */
		int status = pthread_join(fetch_thread_id, NULL);
		if (status != 0) {
			llog_error(logger, status, "problem waiting for crl fetch thread to exit");
		}
	}
}

void free_crl_fetch(void)
{
}

char *curl_iface = NULL;
deltatime_t crl_fetch_timeout = DELTATIME_INIT(5/*seconds*/);
/* 0 is special and default: do not check crls dynamically */
deltatime_t crl_check_interval = DELTATIME_INIT(0);
