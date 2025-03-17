/* CRL fetch queue, for libreswan
 *
 * Copyright (C) 2018 Andrew Cagney
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

/*
 * List of lists.
 *
 * The main thread appends to these lists (with everything locked).
 *
 * The fetch thread traverses these lists.  While traversing these
 * structures the lock is held.  However once it reaches a node it
 * releases the lock (it then re-claims it when traversal is resumed).
 *
 * This means that, while the fetch thread is processing a node
 * (distribution point), the lists can be growing.  Hence the
 * volatile's sprinkled across this code.
 */

struct crl_distribution_point {
	char *url;
	struct crl_distribution_point *volatile next;
};

struct crl_fetch_queue {
	realtime_t request_time;
	chunk_t issuer_dn;
	struct crl_distribution_point *volatile distribution_points;
	int trials;
	struct logger *logger;
	struct crl_fetch_queue *volatile next;
};

struct crl_fetch_request {
	asn1_t issuer_dn;
	shunk_t url;
	CERTCertificate *ca; /* must free */
	CERTCrlDistributionPoints *dps; /* points into CA */
	struct crl_fetch_request *next;
};

static void free_crl_distribution_points(struct crl_distribution_point *volatile *dp)
{
	while (*dp != NULL) {
		struct crl_distribution_point *tbd = *dp;
		*dp = (*dp)->next;
		pfree(tbd->url);
		pfree(tbd);
	}
}

static void free_crl_fetch_request(struct crl_fetch_queue **request)
{
	free_crl_distribution_points(&(*request)->distribution_points);
	free_chunk_content(&(*request)->issuer_dn);
	free_logger(&(*request)->logger, HERE);
	pfree((*request));
	*request = NULL;
}

static pthread_mutex_t crl_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t crl_queue_cond = PTHREAD_COND_INITIALIZER;
static struct crl_fetch_queue *volatile crl_fetch_queue = NULL;

/*
 * *ALWAYS* Append additional distribution points.
 */

static void unlocked_append_distribution_point(struct crl_distribution_point *volatile *dps, shunk_t url)
{
	struct crl_distribution_point *volatile *dp;
	for (dp = dps; *dp != NULL; dp = &(*dp)->next) {
		if (hunk_streq(url, (*dp)->url)) {
			/* newPoint already present */
			break;
		}
	}
	if (*dp == NULL) {
		/*
		 * End of list; not found.  Clone additional
		 * distribution point.
		 */
		struct crl_distribution_point new_point = {
			.url = clone_hunk_as_string(url, "dp url"),
			.next = NULL,
		};
		*dp = clone_thing(new_point, "add distribution point");
	}
}

static void unlocked_append_distribution_points(struct crl_distribution_point *volatile *dps,
						shunk_t url, CERTCrlDistributionPoints *cert_dps)
{
	if (cert_dps != NULL) {
		/*
		 * Certificate can have multiple distribution points
		 * stored in a NULL terminated ARRAY.
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
						unlocked_append_distribution_point(dps, u);
					}
					name = CERT_GetNextGeneralName(name);
				} while (name != NULL && name != first_name);
			}
		}
	} else {
		unlocked_append_distribution_point(dps, url);
	}
}

void submit_crl_fetch_requests(struct crl_fetch_request **requests, struct logger *logger)
{
	dbg("CRL: submitting crl fetch requests");
	pthread_mutex_lock(&crl_queue_mutex);
	for (struct crl_fetch_request *request = requests != NULL ? *requests : NULL;
	     request != NULL; request = request->next) {
		struct crl_fetch_queue *volatile *entry;
		for (entry = &crl_fetch_queue; *entry != NULL; entry = &(*entry)->next) {
			if (same_dn(request->issuer_dn, ASN1((*entry)->issuer_dn))) {
				/* there is already a fetch request */
				dn_buf dnb;
				dbg("CRL:   adding distribution point to existing fetch request: %s",
				    str_dn(request->issuer_dn, &dnb));
				/* there might be new distribution points */
				unlocked_append_distribution_points(&(*entry)->distribution_points,
								    request->url, request->dps);
				break;
			}
		}
		if (*entry == NULL) {
			dn_buf dnb;
			dbg("CRL:   adding new fetch request: %s",
			    str_dn(request->issuer_dn, &dnb));
			/* APPEND new requests */
			struct crl_fetch_queue new_entry = {
				.request_time = realnow(),
				.issuer_dn = clone_hunk(request->issuer_dn, "crl issuer dn"),
				.distribution_points = NULL,
				.logger = clone_logger(logger, HERE),
				.next = NULL,
			};
			/* copy distribution points */
			unlocked_append_distribution_points(&new_entry.distribution_points,
							    request->url, request->dps);
			*entry = clone_thing(new_entry, "crl entry");
		}
	}
	dbg("CRL: poke the sleeping dragon (fetch thread)");
	pthread_cond_signal(&crl_queue_cond);
	pthread_mutex_unlock(&crl_queue_mutex);

	/* clean up */
	if (requests != NULL) {
		while (*requests != NULL) {
			struct crl_fetch_request *tbd = *requests;
			*requests = tbd->next;
			if (tbd->ca != NULL) {
				CERT_DestroyCertificate(tbd->ca);
				tbd->dps = NULL; /* points into CA's arena */
			}
			pfree(tbd);
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

void add_crl_fetch_request(asn1_t issuer_dn, shunk_t url,
			   struct crl_fetch_request **requests,
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
	CERTCertificate *ca = CERT_FindCertByName(handle, &issuer_secitem);
	if (ca == NULL) {
		llog_nss_error(RC_LOG, logger, "error finding CA to add to fetch request");
		return;
	}

	CERTCrlDistributionPoints *cert_dps = get_cert_distribution_points(ca, logger);
	if (cert_dps == NULL && url.len == 0) {
		dbg("CRL: no distribution point available for new fetch request");
		CERT_DestroyCertificate(ca);
		return;
	}

	struct crl_fetch_request new_request = {
		.issuer_dn = issuer_dn,
		.url = url,
		.ca = ca,
		.dps = cert_dps,
		.next = *requests,
	};

	*requests = clone_thing(new_request, "crl request");
}

void submit_crl_fetch_request(asn1_t issuer_dn, struct logger *logger)
{
	struct crl_fetch_request *requests = NULL;
	add_crl_fetch_request(issuer_dn, /*URL*/null_shunk, &requests, logger);
	submit_crl_fetch_requests(&requests, logger);
}

/*
 * list all fetch requests
 */

static void list_distribution_points(struct show *s, const struct crl_distribution_point *first_gn)
{
	for (const struct crl_distribution_point *gn = first_gn; gn != NULL; gn = gn->next) {
		if (gn == first_gn) {
			show(s, "       distPts: '%s'", gn->url);
		} else {
			show(s, "                '%s'", gn->url);
		}
	}
}

void list_crl_fetch_requests(struct show *s, bool utc)
{
	pthread_mutex_lock(&crl_queue_mutex);
	{
		if (crl_fetch_queue != NULL) {
			show_blank(s);
			show(s, "List of CRL fetch requests:");
			show_blank(s);
			for (struct crl_fetch_queue *req = crl_fetch_queue; req != NULL; req = req->next) {
				realtime_buf rtb;
				show(s, "%s, trials: %d",
					     str_realtime(req->request_time, utc, &rtb),
					     req->trials);
				dn_buf buf;
				show(s, "       issuer:  '%s'",
					     str_dn(ASN1(req->issuer_dn), &buf));
				list_distribution_points(s, req->distribution_points);
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
		while (crl_fetch_queue != NULL) {
			struct crl_fetch_queue *tbd = crl_fetch_queue;
			crl_fetch_queue = tbd->next;
			free_crl_fetch_request(&tbd);
		}
	}
	pthread_mutex_unlock(&crl_queue_mutex);
}

/*
 * Calls the _import_crl process to add a CRL to the NSS db.
 */
static bool fetch_crl(chunk_t issuer_dn, const char *url, struct logger *logger)
{
	deltatime_buf td;
	dn_buf idn;

	char *arg[] = {
		IPSEC_EXECDIR "/_import_crl",
		(char*)url,
		(char*)str_deltatime(crl_fetch_timeout, &td),
		(curl_iface == NULL ? "" : curl_iface),
		NULL,
	};

	ldbg(logger, "importing CRL for %s using: %s %s %s %s",
	     str_dn(ASN1(issuer_dn), &idn),
	     arg[0], arg[1], arg[2], arg[3]);

	int pfd[2];
	if (pipe(pfd) == -1) {
		llog_error(logger, errno, "importing CRL for %s failed, pipe()",
			   str_dn(ASN1(issuer_dn), &idn));
		return false;
	}

	if (PBAD(logger, pfd[0] == STDIN_FILENO) ||
	    PBAD(logger, pfd[1] == STDERR_FILENO) ||
	    PBAD(logger, pfd[1] == STDERR_FILENO)) {
		return false;
	}

	pid_t child = fork();

	if (child < 0) {
		llog_error(logger, errno, "importing CRL for %s failed, fork()",
			   str_dn(ASN1(issuer_dn), &idn));
		return false;
	}

	if (child == 0) {

		dup2(pfd[1], STDERR_FILENO);
		dup2(pfd[1], STDOUT_FILENO);
		dup2(pfd[0], STDIN_FILENO);

		close(pfd[0]);
		close(pfd[1]);

		execve(arg[0], arg, NULL);
		llog_error(logger, errno, "importing CRL for %s failed, execve()",
			   str_dn(ASN1(issuer_dn), &idn));
		exit(127);
	}

	/*parent*/

	if (close(pfd[1]) == -1) {
		llog_error(logger, errno, "importing CRL for %s failed, close(pfd[1])",
			   str_dn(ASN1(issuer_dn), &idn));
		return false;
	}

	int wstatus;
	waitpid(child, &wstatus, 0);

	if (!WIFEXITED(wstatus)) {
		llog_error(logger, 0, "importing CRL for %s failed, helper aborted with waitpid status %d",
			   str_dn(ASN1(issuer_dn), &idn), wstatus);
		return false;
	}

	int ret = WEXITSTATUS(wstatus);
	if (ret != 0) {
		llog_error(logger, 0, "importing CRL for %s failed, helper exited with non-zero status %d",
			   str_dn(ASN1(issuer_dn), &idn), ret);
		return false;
	}

	ldbg(logger, "CRL helper for %s ran successfully",
	     str_dn(ASN1(issuer_dn), &idn));

	uint8_t namebuf[1023];
	ssize_t l = read(pfd[0], namebuf, sizeof(namebuf));
	if (l < 0) {
		llog_error(logger, errno, "importing CRL for %s failed, read(pfd[0])",
			   str_dn(ASN1(issuer_dn), &idn));
		return false;
	}

	ldbg(logger, "CRL helper for %s output %zu bytes:",
	     str_dn(ASN1(issuer_dn), &idn), l);

	if (close(pfd[0]) == -1) {
		llog_error(logger, errno, "importing CRL for %s failed, close(pfd[0])",
			   str_dn(ASN1(issuer_dn), &idn));
		return false;
	}

	chunk_t sign_dn = chunk2(namebuf, l);
	ldbg_hunk(logger, sign_dn);
	pemtobin(&sign_dn);
	ldbg(logger, "CRL helper for %s output pem:",
	     str_dn(ASN1(issuer_dn), &idn));
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
		ldbg_nss_error(logger, "importing CRL for %s failed, could not find cert by name %s",
			       str_dn(ASN1(issuer_dn), &idn),
			       str_dn(ASN1(sign_dn), &sdn));
		return false;
	}

	CERT_CRLCacheRefreshIssuer(handle, &cacert->derSubject);
	ldbg(logger, "CRL issuer %s flushed %s",
	     str_dn(ASN1(issuer_dn), &idn), cacert->nickname);

	LLOG_JAMBUF(RC_LOG, logger, buf) {
		jam_string(buf, "imported CRL for '");
		jam_dn(buf, ASN1(issuer_dn), jam_sanitized_bytes);
		jam_string(buf, "' signed by '");
		jam_dn(buf, ASN1(sign_dn), jam_sanitized_bytes);
		jam_string(buf, "' from "); 
		jam_string(buf, url);
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
	pthread_mutex_lock(&crl_queue_mutex);
	while (!exiting_pluto) {
		/* if there's something process it */
		dbg("CRL: the sleeping dragon awakes");
		unsigned requests_processed = 0;
		for (struct crl_fetch_queue *volatile *volatile reqp = &crl_fetch_queue;
		     *reqp != NULL && !exiting_pluto; ) {
			requests_processed++;
			struct crl_fetch_queue *req = *reqp;
			pexpect(req->distribution_points != NULL);
			bool fetched = false;
			for (struct crl_distribution_point *volatile dp = req->distribution_points;
			     dp != NULL && !fetched && !exiting_pluto; dp = dp->next) {
				/*
				 * While fetching unlock the QUEUE.
				 *
				 * While the table is unlocked, the
				 * main thread can append to either
				 * crl_fetch_request list, or its
				 * crl_distribution_point list.
				 */
				dbg("CRL:   unlocking crl queue");
				pthread_mutex_unlock(&crl_queue_mutex);
				dn_buf dnb;
				dbg("CRL:     fetching: %s",
				    str_dn(ASN1(req->issuer_dn), &dnb));
				if (fetch_crl(req->issuer_dn, dp->url, req->logger)) {
					fetched = true;
				}
				dbg("CRL:   locked crl queue");
				pthread_mutex_lock(&crl_queue_mutex);
			}
			if (fetched) {
				*reqp = req->next;
				free_crl_fetch_request(&req);
			} else {
				req->trials++;
				reqp = &req->next;
			}
		}
		if (exiting_pluto) {
			break;
		}
		dbg("CRL: %u requests processed, the dragon sleeps",
		    requests_processed);
		int status = pthread_cond_wait(&crl_queue_cond, &crl_queue_mutex);
		passert(status == 0);
	}
	pthread_mutex_unlock(&crl_queue_mutex);
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

char *curl_iface = NULL;
bool crl_strict = false;
deltatime_t crl_fetch_timeout = DELTATIME_INIT(5/*seconds*/);
/* 0 is special and default: do not check crls dynamically */
deltatime_t crl_check_interval = DELTATIME_INIT(0);
