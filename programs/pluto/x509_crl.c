/* CRL fetch queue, for libreswan
 *
 * Copyright (C) 2018,2025  Andrew Cagney
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
 */

#include <pthread.h>		/* must be first */

#include <unistd.h>		/* for pipe() */
#include <errno.h>
#include <sys/wait.h>

#include <cert.h>
#include <certdb.h>

#include "x509_crl.h"

#include "lswalloc.h"
#include "secrets.h"		/* for clone_secitem_as_chunk() */
#include "pem.h"
#include "lswnss.h"
#include "realtime.h"
#include "defs.h"		/* for exiting_pluto */
#include "log.h"
#include "whack_shutdown.h"		/* for exiting_pluto; */
#include "show.h"
#include "timer.h"
#include "keys.h"		/* for pluto_pubkeys; */

static pthread_t fetch_thread_id;

static pthread_mutex_t crl_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t crl_queue_cond = PTHREAD_COND_INITIALIZER;
static struct crl_distribution_point *volatile crl_distribution_queue = NULL;

struct crl_distribution_point {
	realtime_t first_request;
	realtime_t last_request;
	unsigned attempts;
	char *url;
	struct crl_issuer *issuers;
	struct crl_distribution_point *next;
};

struct crl_issuer {
	chunk_t dn;
	struct crl_issuer *next;
};

static void free_crl_issuer(struct crl_issuer **tbd)
{
	/* unlink */
	struct crl_issuer *issuer = (*tbd);
	(*tbd) = issuer->next;
	/* delete */
	free_chunk_content(&issuer->dn);
	pfree(issuer);
}

static void free_crl_distribution_point(struct crl_distribution_point *volatile *tbd)
{
	/* unlink */
	struct crl_distribution_point *dp = (*tbd);
	(*tbd) = dp->next;
	/* delete */
	while (dp->issuers != NULL) {
		free_crl_issuer(&dp->issuers);
	}
	pfree(dp->url);
	pfree(dp);
}

/*
 * *ALWAYS* Append additional distribution points.
 */

static void unlocked_append_distribution_point(asn1_t issuer_dn, shunk_t url)
{
	/*
	 * Find the distribution point.
	 */
	struct crl_distribution_point *volatile *dp;
	for (dp = &crl_distribution_queue; *dp != NULL; dp = &(*dp)->next) {
		if (hunk_streq(url, (*dp)->url)) {
			/* newPoint already present */
			break;
		}
	}
	if ((*dp) == NULL) {
		/*
		 * No distribution point found, add one.
		 */
		*dp = alloc_thing(struct crl_distribution_point, "add distribution point");
		(*dp)->url = clone_hunk_as_string(url, "dp url");
		(*dp)->first_request = realnow();
	}
	/*
	 * Find the issuer.
	 */
	struct crl_issuer **issuer;
	for (issuer = &(*dp)->issuers; (*issuer) != NULL; issuer = &(*issuer)->next) {
		if (same_dn(issuer_dn, ASN1((*issuer)->dn))) {
			break;
		}
	}
	if ((*issuer) == NULL) {
		(*issuer) = alloc_thing(struct crl_issuer, "add distribution point issuer");
		(*issuer)->dn = clone_hunk(issuer_dn, "crl issuer dn");
	}
}

static void unlocked_append_distribution_points(asn1_t issuer_dn, CERTCrlDistributionPoints *cert_dps)
{
	/*
	 * Certificate can have multiple distribution points stored in
	 * a NULL terminated ARRAY.
	 */
	for (CRLDistributionPoint **points = cert_dps->distPoints;
	     points != NULL && *points != NULL; points++) {
		CRLDistributionPoint *point = *points;
		/*
		 * Each point has a circular list of
		 * CERTGeneralNames.
		 */
		if (point->distPointType == generalName &&
		    point->distPoint.fullName != NULL) {
			CERTGeneralName *first_name, *name;
			first_name = name = point->distPoint.fullName;
			do {
				if (name->type == certURI) {
					/* Add single point */
					shunk_t u = same_secitem_as_shunk(name->name.other);
					unlocked_append_distribution_point(issuer_dn, u);
				}
				name = CERT_GetNextGeneralName(name);
			} while (name != NULL && name != first_name);
		}
	}
}

static CERTCrlDistributionPoints *get_cert_distribution_points(CERTCertificate *cert, struct logger *logger)
{
	SECItem crls;
	if (CERT_FindCertExtension(cert, SEC_OID_X509_CRL_DIST_POINTS,
				   &crls) != SECSuccess) {
		ldbg_nss_error(logger, "finding CRL distribution points using CERT_FindCertExtension() failed");
		return NULL;
	}

	CERTCrlDistributionPoints *dps = CERT_DecodeCRLDistributionPoints(cert->arena, &crls);
	if (dps == NULL) {
		ldbg_nss_error(logger, "decoding CRL distribution points using CERT_DecodeCRLDistributionPoints() failed");
		return NULL;
	}

	return dps;
}

static
void add_crl_fetch_request(asn1_t issuer_dn, shunk_t request_url,
			   struct logger *logger)
{
	/*
	 * CERT_GetDefaultCertDB() simply returns the contents of a
	 * static variable set by NSS_Initialize().  It doesn't check
	 * the value and doesn't set PR error.  Short of calling
	 * CERT_SetDefaultCertDB(NULL), the value can never be NULL.
	 */
	CERTCertDBHandle *handle = CERT_GetDefaultCertDB();
	passert(handle != NULL);
	SECItem issuer_secitem = same_shunk_as_secitem(issuer_dn, siBuffer);
	CERTCertificate *ca = CERT_FindCertByName(handle, &issuer_secitem); /* must free */
	if (ca == NULL) {
		llog_nss_error(RC_LOG, logger, "error finding CA to add to fetch request");
		return;
	}

	CERTCrlDistributionPoints *request_dps = get_cert_distribution_points(ca, logger);
	if (request_dps == NULL && request_url.len == 0) {
		ldbg(logger, "CRL: no distribution point available for new fetch request");
		CERT_DestroyCertificate(ca);
		return;
	}

	ldbg(logger, "CRL: submitting crl fetch request");
	pthread_mutex_lock(&crl_queue_mutex);
	{
		/* now add the distribution point */
		if (request_dps != NULL) {
			unlocked_append_distribution_points(issuer_dn, request_dps);
		} else {
			unlocked_append_distribution_point(issuer_dn, request_url);
		}
	}
	ldbg(logger, "CRL: poke the sleeping dragon (fetch thread)");
	pthread_cond_signal(&crl_queue_cond);
	pthread_mutex_unlock(&crl_queue_mutex);

	/* clean up */
	CERT_DestroyCertificate(ca);
}

void submit_crl_fetch_request(asn1_t issuer_dn, struct logger *logger)
{
	add_crl_fetch_request(issuer_dn, /*URL*/null_shunk, logger);
}

/*
 * list all fetch requests
 */

void list_crl_fetch_requests(struct show *s, bool utc)
{
	pthread_mutex_lock(&crl_queue_mutex);
	{
		if (crl_distribution_queue != NULL) {
			show_blank(s);
			show(s, "List of CRL fetch requests:");
			show_blank(s);
			const char prefix[] = "       ";
			for (struct crl_distribution_point *dp = crl_distribution_queue;
			     dp != NULL; dp = dp->next) {
				show(s, "%s", dp->url);
				SHOW_JAMBUF(s, buf) {
					jam_string(buf, prefix);
					jam_realtime(buf, dp->first_request, utc);
					if (!is_realtime_epoch(dp->last_request)) {
						jam_string(buf, ", ");
						jam_realtime(buf, dp->last_request, utc);
					}
					jam(buf, ", attempts: %u", dp->attempts);
				}
				for (struct crl_issuer *issuer = dp->issuers;
				     issuer != NULL; issuer = issuer->next) {
					dn_buf buf;
					show(s, "%s%-10s'%s'",
					     prefix, (issuer == dp->issuers ? "issuer:" : ""),
					     str_dn(ASN1(issuer->dn), &buf));
				}
			}
		}
	}
	pthread_mutex_unlock(&crl_queue_mutex);
}

void free_crl_queue(void)
{
	pexpect(exiting_pluto);
	/* technical overkill - thread is dead */
	pthread_mutex_lock(&crl_queue_mutex);
	{
		while (crl_distribution_queue != NULL) {
			free_crl_distribution_point(&crl_distribution_queue);
		}
	}
	pthread_mutex_unlock(&crl_queue_mutex);
}

/*
 * Calls the _import_crl process to add a CRL to the NSS db.
 */
static bool fetch_crl(const char *url, unsigned attempt, uintmax_t run_nr, struct logger *logger)
{
	deltatime_buf td;

	char *arg[] = {
		IPSEC_EXECDIR "/_import_crl",
		(char*)url,
		(char*)str_deltatime(x509_crl.timeout, &td),
		(x509_crl.curl_iface == NULL ? "" : x509_crl.curl_iface),
		NULL,
	};

	ldbg(logger, "CRL %ju: importing %s using: %s %s %s %s",
	     run_nr, url, arg[0], arg[1], arg[2], arg[3]);

	int pfd[2];
	if (pipe(pfd) == -1) {
		llog_error(logger, errno, "CRL %ju: importing %s failed, pipe()",
			   run_nr, url);
		return false;
	}

	if (PBAD(logger, pfd[0] == STDIN_FILENO) ||
	    PBAD(logger, pfd[1] == STDERR_FILENO) ||
	    PBAD(logger, pfd[1] == STDERR_FILENO)) {
		return false;
	}

	pid_t child = fork();

	if (child < 0) {
		llog_error(logger, errno, "CRL %ju: importing %s failed, fork()",
			   run_nr, url);
		return false;
	}

	if (child == 0) {

		dup2(pfd[1], STDERR_FILENO);
		dup2(pfd[1], STDOUT_FILENO);
		dup2(pfd[0], STDIN_FILENO);

		close(pfd[0]);
		close(pfd[1]);

		execve(arg[0], arg, NULL);
		llog_error(logger, errno, "CRL %ju: importing %s failed, execve()",
			   run_nr, url);
		exit(127);
	}

	/*parent*/

	if (close(pfd[1]) == -1) {
		llog_error(logger, errno, "CRL %ju: importing %s failed, close(pfd[1])",
			   run_nr, url);
		return false;
	}

	int wstatus;
	waitpid(child, &wstatus, 0);

	uint8_t namebuf[1023];
	ssize_t l = read(pfd[0], namebuf, sizeof(namebuf));
	int error = errno;
	chunk_t output = chunk2(namebuf, l);

	if (l < 0) {
		llog_error(logger, error, "CRL %ju: importing %s failed, read(pfd[0])", run_nr, url);
		llog_dump_hunk(RC_LOG, logger, output);
		return false;
	}


	if (!WIFEXITED(wstatus)) {
		llog_error(logger, 0, "CRL %ju: importing %s failed, helper aborted with waitpid status %d",
			   run_nr, url, wstatus);
		llog_dump_hunk(RC_LOG, logger, output);
		return false;
	}

	int ret = WEXITSTATUS(wstatus);
	if (ret != 0) {
		llog_error(logger, 0, "CRL %ju: importing %s failed, helper exited with non-zero status %d",
			   run_nr, url, ret);
		llog_dump_hunk(RC_LOG, logger, output);
		return false;
	}

	ldbg(logger, "CRL %ju: import for %s ran successfully",
	     run_nr, url);
	ldbg(logger, "CRL helper for %s output %zu bytes:", url, l);
	ldbg_hunk(logger, output);

	if (close(pfd[0]) == -1) {
		llog_error(logger, errno, "CRL %ju: importing %s failed, close(pfd[0])",
			   run_nr, url);
		return false;
	}

	chunk_t sign_dn = chunk2(namebuf, l);
	pemtobin(&sign_dn);
	ldbg(logger, "CRL helper for %s output pem:", url);
	ldbg_hunk(logger, sign_dn);

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
		.data = sign_dn.ptr,
		.len = sign_dn.len,
	};
	CERTCertificate *cacert =  CERT_FindCertByName(handle, &name);
	if (cacert == NULL) {
		dn_buf sdn;
		ldbg_nss_error(logger, "CRL %ju: importing %s failed, could not find cert by name %s",
			       run_nr, url, str_dn(ASN1(sign_dn), &sdn));
		return false;
	}

	CERT_CRLCacheRefreshIssuer(handle, &cacert->derSubject);

	LLOG_JAMBUF(RC_LOG, logger, buf) {
		jam(buf, "CRL %ju: imported CRL '", run_nr);
		jam_string(buf, url);
		jam_string(buf, "' signed by '");
		jam_dn(buf, ASN1(sign_dn), jam_sanitized_bytes);
		jam(buf, "' after %u attempt(s)", attempt);
	}

	CERT_DestroyCertificate(cacert);

	return true;
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
	if (deltasecs(x509_crl.check_interval) <= 0) {
		llog(RC_LOG, logger, "config crlcheckinterval= is unset");
		return;
	}

	/* schedule the next probe */
	schedule_oneshot_timer(EVENT_CHECK_CRLS, x509_crl.check_interval);

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
	{
		CERTCrlHeadNode *crl_list = NULL; /* must free; but after submitting requests */
		if (SEC_LookupCrls(handle, &crl_list, SEC_CRL_TYPE) != SECSuccess) {
			return;
		}

		for (CERTCrlNode *n = crl_list->first; n != NULL; n = n->next) {
			if (n->crl != NULL) {
				chunk_t issuer = same_secitem_as_chunk(n->crl->crl.derName);
				/* XXX: URL can be null, gets filled in later */
				add_crl_fetch_request(ASN1(issuer), shunk1(n->crl->url), logger);
			}
		}

		dbg("CRL: releasing crl list in %s()", __func__);
		PORT_FreeArena(crl_list->arena, PR_FALSE);
	}

	/*
	 * Add the pubkeys distribution points to fetch list.
	 */

	for (struct pubkey_list *pkl = pluto_pubkeys; pkl != NULL; pkl = pkl->next) {
		struct pubkey *key = pkl->key;
		if (key != NULL) {
			add_crl_fetch_request(key->issuer, null_shunk, logger);
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
			add_crl_fetch_request(ASN1(issuer), null_shunk, logger);
		}
		CERT_DestroyCertList(certs);
	}

}

static void *fetch_thread(void *arg UNUSED)
{
	dbg("CRL: fetch thread started");
	/* XXX: on thread so no whack */
	struct logger *logger = string_logger(HERE, "crl thread"); /* must free */
	pthread_mutex_lock(&crl_queue_mutex);
	uintmax_t run_nr = 0;
	while (!exiting_pluto) {
		/* if there's something process it */
		run_nr++;
		ldbg(logger, "CRL %ju: the sleeping dragon awakes", run_nr);
		unsigned requests_processed = 0;
		for (struct crl_distribution_point *volatile *dp = &crl_distribution_queue;
		     (*dp) != NULL && !exiting_pluto; /*see-below*/) {
			requests_processed++;
			bool fetched = false;
			/*
			 * While fetching unlock the QUEUE.
			 *
			 * While the table is unlocked, the main
			 * thread can append to either the
			 * CRL_DISTRIBUTION_QUEUE or a queue entry's
			 * ISSUERs.
			 */
			ldbg(logger, "CRL %ju:   unlocking crl queue", run_nr);
			(*dp)->attempts++; /* new attempt */
			(*dp)->last_request = realnow();
			pthread_mutex_unlock(&crl_queue_mutex);
			{
				ldbg(logger, "CRL %ju:   fetching: %s", run_nr, (*dp)->url);
				fetched = fetch_crl((*dp)->url, (*dp)->attempts, run_nr, logger);
				ldbg(logger, "CRL %ju:   locked crl queue", run_nr);
			}
			pthread_mutex_lock(&crl_queue_mutex);
			if (fetched) {
				/* advances DP */
				free_crl_distribution_point(dp);
				continue;
			}
			dp = &(*dp)->next;
		}
		if (exiting_pluto) {
			break;
		}
		ldbg(logger, "CRL %ju: %u requests processed, the dragon sleeps",
		     run_nr, requests_processed);
		int status = pthread_cond_wait(&crl_queue_cond, &crl_queue_mutex);
		passert(status == 0);
	}
	pthread_mutex_unlock(&crl_queue_mutex);
	ldbg(logger, "CRL: fetch thread stopped");
	free_logger(&logger, HERE);
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
	if (deltasecs(x509_crl.check_interval) <= 0) {
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
	if (deltasecs(x509_crl.check_interval) > 0) {
		/*
		 * Log before blocking.  If the CRL fetch helper is
		 * currently fetching a CRL, this could take a bit.
		 */
		llog(RC_LOG, logger, "shutting down the CRL fetch helper thread");
		pexpect(exiting_pluto);
		/*
		 * Wake the sleeping dragon from its slumber.
		 */
		pthread_mutex_lock(&crl_queue_mutex);
		{
			ldbg(logger, "CRL: poke the sleeping dragon (fetch thread), as shutting down");
			pthread_cond_signal(&crl_queue_cond);
		}
		pthread_mutex_unlock(&crl_queue_mutex);
		/*
		 * Use a timer?
		 */
		int status = pthread_join(fetch_thread_id, NULL);
		if (status != 0) {
			llog_error(logger, status, "problem waiting for crl fetch thread to exit");
		}
	}
}

struct x509_crl_config x509_crl = {
	.curl_iface = NULL,
	.strict = false,
	.timeout = DELTATIME_INIT(5/*seconds*/),
	/* 0 is special and default: do not check crls dynamically */
	.check_interval = DELTATIME_INIT(0),
};
