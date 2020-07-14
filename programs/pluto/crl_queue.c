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

static pthread_mutex_t crl_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t crl_queue_cond = PTHREAD_COND_INITIALIZER;

static struct crl_fetch_request *volatile crl_fetch_requests = NULL;

static generalName_t *deep_clone_general_names(generalName_t *orig)
{
	generalName_t *clone = NULL;
	generalName_t **new = &clone;
	while (orig != NULL) {
		*new = alloc_thing(generalName_t, "crl_queue: general name");
		(*new)->kind = orig->kind;
		(*new)->name = clone_hunk(orig->name, "crl_queue: general name name");
		(*new)->next = NULL;
		orig = orig->next;
		new = &(*new)->next;
	}
	return clone;
}

struct crl_fetch_request *crl_fetch_request(SECItem *issuer_dn,
					    generalName_t *end_dps,
					    struct crl_fetch_request *next)
{
	if (!pexpect(issuer_dn != NULL)) {
		return next;
	}
	if (!pexpect(issuer_dn->data != NULL && issuer_dn->len > 0)) {
		return next;
	}
	/*
	 * CERT_GetDefaultCertDB() simply returns the contents of a
	 * static variable set by NSS_Initialize().  It doesn't check
	 * the value and doesn't set PR error.  Short of calling
	 * CERT_SetDefaultCertDB(NULL), the value can never be NULL.
	 */
	CERTCertDBHandle *handle = CERT_GetDefaultCertDB();
	passert(handle != NULL);
	CERTCertificate *ca = CERT_FindCertByName(handle, issuer_dn);
	if (ca == NULL) {
		LSWLOG(buf) {
			jam_string(buf, "NSS error finding CA to add to fetch request: ");
			jam_nss_error(buf);
		}
		return next;
	}
	generalName_t *request_dps = NULL;
	generalName_t *cert_dps = gndp_from_nss_cert(ca);
	if (cert_dps != NULL) {
		request_dps = deep_clone_general_names(cert_dps);
		free_generalNames(cert_dps, false /*shallow*/);
	} else if (end_dps != NULL) {
		dbg("no CA crl DP available; using provided DP");
		request_dps = deep_clone_general_names(end_dps);
	} else {
		dbg("no distribution point available for new fetch request");
		CERT_DestroyCertificate(ca);
		return next;
	}
	CERT_DestroyCertificate(ca);

	/*
	 * Prepend the new request - keeping new requests ordered
	 * newest-to-oldest.
	 *
	 * When the requests are merged into the fetch queue proper,
	 * their order gets re-reversed putting oldest first.
	 */
	struct crl_fetch_request *request = alloc_thing(struct crl_fetch_request, "crl_queue: request");
	*request = (struct crl_fetch_request) {
		.request_time = realnow(),
		.issuer_dn = SECITEM_DupItem(issuer_dn),
		.dps = request_dps,
		.next = next,
	};
	return request;
}

void free_crl_fetch_requests(struct crl_fetch_request **requests)
{
	struct crl_fetch_request *request = *requests;
	while (request != NULL) {
		free_generalNames(request->dps, true /*deep*/);
		SECITEM_FreeItem(request->issuer_dn, PR_TRUE);
		struct crl_fetch_request *tbd = request;
		request = request->next;
		pfree(tbd);
	}
	*requests = NULL;
}

/*
 * Prepend the new request[s], keeping the list ordered
 * newest-to-oldest.
 *
 * When the requests are merged into the fetch queue, their order gets
 * re-reversed putting oldest first.
 *
 * Allow NULL - this is used to wake up the fetch helper.
 */
void add_crl_fetch_requests(struct crl_fetch_request *requests)
{
	struct crl_fetch_request *end = requests;
	if (end != NULL) {
		while (end->next != NULL) {
			end = end->next;
		}
	}
	/* add to front of queue */
	pthread_mutex_lock(&crl_queue_mutex);
	{
		/* if end's NULL; just wake the helper */
		if (end != NULL) {
			end->next = crl_fetch_requests;
			crl_fetch_requests = requests;
		}
		/* wake up threads waiting for work */
		pthread_cond_signal(&crl_queue_cond);
	}
	pthread_mutex_unlock(&crl_queue_mutex);
	dbg("crl fetch request sent");
}

struct crl_fetch_request *get_crl_fetch_requests(void)
{
	struct crl_fetch_request *requests = NULL;
	pthread_mutex_lock(&crl_queue_mutex);
	{
		while (!exiting_pluto) {
			/* if there's something grab it */
			if (crl_fetch_requests != NULL) {
				dbg("grabbing crl_queue contents");
				requests = crl_fetch_requests;
				crl_fetch_requests = NULL;
				break;
			}
			dbg("waiting for crl_queue to fill");
			int status = pthread_cond_wait(&crl_queue_cond,
						       &crl_queue_mutex);
			if (status != 0) {
				break;
			} /* else ? */
		}
		/*
		 * REQUEST == NULL implies EXITING_PLUTO but not the
		 * reverse.  Could grab a request while pluto is
		 * starting to exit.
		 */
		if (requests == NULL) {
			pexpect(exiting_pluto);
		}
	}
	pthread_mutex_unlock(&crl_queue_mutex);
	return requests;
}

void free_crl_queue(void)
{
	pexpect(exiting_pluto);
	/* technical overkill - thread is dead */
	pthread_mutex_lock(&crl_queue_mutex);
	struct crl_fetch_request *requests = crl_fetch_requests;
	crl_fetch_requests = NULL;
	free_crl_fetch_requests(&requests);
	pthread_mutex_unlock(&crl_queue_mutex);
}
