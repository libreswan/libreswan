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

#include "defs.h"
#include "log.h"
#include "whack_shutdown.h"		/* for exiting_pluto; */
#include "show.h"
#include "timer.h"
#include "keys.h"		/* for pluto_pubkeys; */
#include "server_fork.h"
#include "config_setup.h"

struct crl_distribution_point;

static server_fork_cb fork_cb;
void fetch_crl(struct crl_distribution_point *wip, int wstatus, shunk_t output,
	       struct logger *logger);
static bool fetch_succeeded(struct crl_distribution_point *dp,
			    int wstatus, shunk_t output,
			    struct logger *logger);

static struct crl_distribution_point *crl_distribution_queue = NULL;

struct crl_distribution_point {
	realtime_t first_request;
	realtime_t last_request;
	unsigned nr;
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

static void free_crl_distribution_point(struct crl_distribution_point **tbd)
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
		static unsigned count;
		(*dp)->nr = ++count;
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
	PASSERT(logger, handle != NULL);
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

	ldbg(logger, "CRL: appending Crl fetch request");
	/* now add the distribution point */
	if (request_dps != NULL) {
		unlocked_append_distribution_points(issuer_dn, request_dps);
	} else {
		unlocked_append_distribution_point(issuer_dn, request_url);
	}

	/* clean up */
	CERT_DestroyCertificate(ca);
}

void submit_crl_fetch_request(asn1_t issuer_dn, struct logger *logger)
{
	add_crl_fetch_request(issuer_dn, /*URL*/null_shunk, logger);

	if (impair.event_check_crls) {
		llog(RC_LOG, logger, "IMPAIR: not initiating FETCH_CRL");
		return;
	}

	fetch_crl(NULL, 0, null_shunk, logger);
}

/*
 * list all fetch requests
 */

void list_crl_fetch_requests(struct show *s, bool utc)
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

/*
 * Calls the _import_crl process to add a CRL to the NSS db.
 */

void fetch_crl(struct crl_distribution_point *wip, int wstatus, shunk_t output,
	       struct logger *logger)
{
	static struct crl_distribution_point **current;

	/*
	 * Advance to the next distribution point.
	 */

	if (exiting_pluto) {
		ldbg(logger, "CRL: the sleeping dragon is slain");
		current = NULL;
		return;
	}

	if (wip != NULL) {
		/* callback */
		PASSERT(logger, wip == (*current));
		if (fetch_succeeded(wip, wstatus, output, logger)) {
			/* advances DP */
			ldbg(logger, "CRL: the sleeping dragon finishes %s", (*current)->url);
			free_crl_distribution_point(current);
		} else {
			/* advance */
			ldbg(logger, "CRL: the sleeping dragon abandons %s", (*current)->url);
			current = &(*current)->next;
		}
	} else if (current == NULL) {
		/* was idle, start again at the front of the queue */
		ldbg(logger, "CRL: the sleeping dragon wakes");
		current = &crl_distribution_queue;
	} else {
		ldbg(logger, "CRL: the sleeping dragon plays with %s", (*current)->url);
	}

	/*
	 * Is there a next distribution point?
	 */

	if ((*current) == NULL) {
		ldbg(logger, "CRL: the sleeping dragon snores");
		current = NULL; /* idle */
		/* schedule the next probe */
		schedule_oneshot_timer(EVENT_CHECK_CRLS, x509_crl.check_interval);
		return;
	}

	/*
	 * Start on the next task.
	 */

	ldbg(logger, "CRL: the sleeping dragon is poked with %s", (*current)->url);
	(*current)->attempts++; /* new attempt */
	(*current)->last_request = realnow();

	deltatime_buf td;

	char *argv[] = {
		IPSEC_EXECDIR "/_import_crl",
		(*current)->url,
		(x509_crl.timeout.is_set ? (char*)str_deltatime(x509_crl.timeout, &td) : "0"),
		(x509_crl.curl_iface != NULL ? (char*)x509_crl.curl_iface : ""),
		NULL,
	};

	ldbg(logger, "CRL: the sleeping dragon runs '%s' '%s' '%s' '%s'",
	     argv[0], argv[1], argv[2], argv[3]);

	char *envp[] = { NULL, };
	server_fork_exec(argv[0], argv, envp, null_shunk, DEBUG_STREAM,
			 fork_cb, (*current), logger);
}

static bool fetch_succeeded(struct crl_distribution_point *dp,
			    int wstatus, shunk_t output,
			    struct logger *logger)
{
	if (!WIFEXITED(wstatus)) {
		llog(ERROR_STREAM, logger,
		     "CRL: importing %s failed, helper aborted with waitpid status %d",
		     dp->url, wstatus);
		llog_hunk(RC_LOG, logger, output);
		return false;
	}

	int ret = WEXITSTATUS(wstatus);
	if (ret != 0) {
		llog(ERROR_STREAM, logger,
		     "CRL: importing %s failed, helper exited with non-zero status %d",
		     dp->url, ret);
		llog_hunk(RC_LOG, logger, output);
		return false;
	}

	if (LDBGP(DBG_BASE, logger)) {
		LDBG_log(logger, "CRL: the sleeping dragon returned from %s with %zu gold",
			 dp->url, output.len);
		LDBG_hunk(logger, output);
	}

	chunk_t sign_dn = clone_hunk(output, "signer");		/* must free */
	pemtobin(&sign_dn);
	if (LDBGP(DBG_BASE, logger)) {
		LDBG_log(logger, "CRL: the sleeping dragon returned from %s signs:", dp->url);
		LDBG_hunk(logger, sign_dn);
	}

	/*
	 * CERT_GetDefaultCertDB() simply returns the contents of a
	 * static variable set by NSS_Initialize().  It doesn't check
	 * the value and doesn't set PR error.  Short of calling
	 * CERT_SetDefaultCertDB(NULL), the value can never be NULL.
	 */
	CERTCertDBHandle *handle = CERT_GetDefaultCertDB();
	PASSERT(logger, handle != NULL);
	SECItem name = {
		.type = siBuffer,
		.data = sign_dn.ptr,
		.len = sign_dn.len,
	};
	CERTCertificate *cacert =  CERT_FindCertByName(handle, &name);
	if (cacert == NULL) {
		dn_buf sdn;
		ldbg_nss_error(logger,
			       "CRL: importing %s failed, could not find cert by name %s",
			       dp->url, str_dn(ASN1(sign_dn), &sdn));
		free_chunk_content(&sign_dn);
		return false;
	}

	CERT_CRLCacheRefreshIssuer(handle, &cacert->derSubject);

	LLOG_JAMBUF(RC_LOG, logger, buf) {
		jam(buf, "CRL: imported CRL '");
		jam_string(buf, dp->url);
		jam_string(buf, "' signed by '");
		jam_dn(buf, ASN1(sign_dn), jam_sanitized_bytes);
		jam(buf, "' after %u attempt(s)", dp->attempts);
	}

	free_chunk_content(&sign_dn);
	CERT_DestroyCertificate(cacert);

	return true;
}

stf_status fork_cb(struct state *st UNUSED,
		    struct msg_digest *md UNUSED,
		    int wstatus, shunk_t output,
		    void *context UNUSED,
		    struct logger *logger)
{
	fetch_crl(context, wstatus, output, logger);
	return STF_OK;
}

/*
 * Submit all known CRLS for processing using
 * append_crl_fetch_request().
 *
 * Any duplicates will be eliminated by submit_crl_fetch_request()
 * when it merges these requests with any still unprocessed requests.
 */

static void event_check_crls(struct logger *logger)
{
	/*
	 * CERT_GetDefaultCertDB() simply returns the contents of a
	 * static variable set by NSS_Initialize().  It doesn't check
	 * the value and doesn't set PR error.  Short of calling
	 * CERT_SetDefaultCertDB(NULL), the value can never be NULL.
	 */
	CERTCertDBHandle *handle = CERT_GetDefaultCertDB();
	PASSERT(logger, handle != NULL);

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

		ldbg(logger, "CRL: releasing crl list in %s()", __func__);
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

	fetch_crl(NULL, 0, null_shunk, logger);
}

/*
 * Command-line trigger of fetch crls.
 */

void fetch_x509_crls(struct show *s)
{
	event_check_crls(show_logger(s));
}

/*
 * initializes curl and starts the fetching thread
 */

bool init_x509_crl_queue(struct logger *logger)
{
	/*
	 * XXX: CRT checking is probably really a periodic timer,
	 * however: the first fetch 5 seconds after startup; and
	 * further fetches are defined by the config(?) file (is that
	 * loaded before this function was called? yes).
	 */
	init_oneshot_timer(EVENT_CHECK_CRLS, event_check_crls);
	if (deltasecs(x509_crl.check_interval) <= 0) {
		ldbg(logger, "CRL: checking disabled as check-interval is zero");
		return false;
	}

	if (impair.event_check_crls) {
		llog(RC_LOG, logger, "IMPAIR: not scheduling EVENT_CHECK_CRLS");
		return true; /*technically still enabled*/
	}

	/*
	 * XXX: why the delay?
	 *
	 * To give pluto time to settle, or so that tests can do stuff
	 * before the CRL fetch list has been refreshed (for the
	 * latter, use impair.event_check_crls).
	 */
	schedule_oneshot_timer(EVENT_CHECK_CRLS, deltatime(5));
	return true;
}

void shutdown_x509_crl_queue(struct logger *logger)
{
	PASSERT(logger, exiting_pluto);
	/* this severs any link to CRL_DISTRIBUTION_QUEUE */
	fetch_crl(NULL, 0, null_shunk, logger);
	/* now delete */
	while (crl_distribution_queue != NULL) {
		free_crl_distribution_point(&crl_distribution_queue);
	}
}

struct x509_crl_config x509_crl = {0}; /* see config_setup.[hc] */
