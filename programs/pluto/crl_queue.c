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

#include <pthread.h>

#include "lswalloc.h"
#include "secrets.h"		/* for clone_secitem_as_chunk() */

#include "crl_queue.h"
#include "lswnss.h"
#include "realtime.h"
#include "defs.h"		/* for exiting_pluto */
#include "log.h"
#include "whack_shutdown.h"		/* for exiting_pluto; */
#include "show.h"

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
		*dp = clone_thing(new_point, "add distributin point");
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

void process_crl_fetch_requests(fetch_crl_fn *fetch_crl, struct logger *unused_logger UNUSED)
{
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
