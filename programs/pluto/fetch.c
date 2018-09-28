/* Dynamic fetching of X.509 CRLs, for libreswan
 *
 * Copyright (C) 2002 Stephane Laroche <stephane.laroche@colubris.com>
 * Copyright (C) 2002-2004 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2003-2008 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2018 Andrew Cagney
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

#if defined(LIBCURL) || defined(LIBLDAP)
#include <pthread.h>    /* Must be the first include file */
#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>
#include <string.h>

#include <cert.h>
#include <certdb.h>

#ifdef LIBCURL
#include <curl/curl.h>	/* from libcurl devel */
#endif

#include <libreswan.h>

#ifdef LIBLDAP
#define LDAP_DEPRECATED 1
#include <ldap.h>
#endif

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "id.h"
#include "asn1.h"
#include "pem.h"
#include "x509.h"
#include "whack.h"
#include "fetch.h"
#include "secrets.h"
#include "nss_err.h"
#include "nss_crl_import.h"
#include "nss_err.h"
#include "keys.h"
#include "crl_queue.h"
#include "timer.h"

#ifdef LIBCURL
#define LIBCURL_UNUSED
#else
#define LIBCURL_UNUSED UNUSED
#endif

#define FETCH_CMD_TIMEOUT       5       /* seconds */

typedef struct fetch_req fetch_req_t;

struct fetch_req {
	fetch_req_t *next;
	realtime_t installed;
	int trials;
	chunk_t issuer;
	generalName_t *distributionPoints;
};

static fetch_req_t empty_fetch_req = {
	NULL,           /* next */
	REALTIME_EPOCH,	/* installed */
	0,              /* trials */
	{ NULL, 0 },    /* issuer */
	NULL            /* distributionPoints */
};

/* chained list of crl fetch requests */
static fetch_req_t *crl_fetch_reqs  = NULL;

static pthread_t thread;
static pthread_mutex_t crl_fetch_list_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * lock access to the chained crl fetch request list
 */
static void lock_crl_fetch_list(const char *who)
{
	pthread_mutex_lock(&crl_fetch_list_mutex);
	DBG(DBG_X509, DBG_log("crl fetch request list locked by '%s'", who));
}

/*
 * unlock access to the chained crl fetch request list
 */
static void unlock_crl_fetch_list(const char *who)
{
	pthread_mutex_unlock(&crl_fetch_list_mutex);
	DBG(DBG_X509, DBG_log("crl fetch request list unlocked by '%s'", who));
}

/*
 *  free the dynamic memory used to store fetch requests
 */
static void free_fetch_request(fetch_req_t *req)
{
	pfree(req->issuer.ptr);
	free_generalNames(req->distributionPoints, TRUE);
	pfree(req);
}

#ifdef LIBCURL
/*
 * Appends *ptr into (chunk_t *)data.
 * A call-back used with libcurl.
 */
static size_t write_buffer(void *ptr, size_t size, size_t nmemb, void *data)
{
	size_t realsize = size * nmemb;
	chunk_t *mem = (chunk_t *)data;

	/* note: memory allocated by realloc(3) */
	mem->ptr = realloc(mem->ptr, mem->len + realsize);
	/* ??? what should we do on realloc failure? */
	if (mem->ptr != NULL) {
		memcpy(&(mem->ptr[mem->len]), ptr, realsize);
		mem->len += realsize;
	}
	return realsize;
}
#endif

/*
 * fetches a binary blob from a url with libcurl
 */
static err_t fetch_curl(chunk_t url LIBCURL_UNUSED,
			chunk_t *blob LIBCURL_UNUSED)
{
#ifdef LIBCURL
	char errorbuffer[CURL_ERROR_SIZE] = "";
	char *uri;
	chunk_t response = empty_chunk;	/* managed by realloc/free */
	long timeout = FETCH_CMD_TIMEOUT;
	CURLcode res;

	/* get it with libcurl */
	CURL *curl = curl_easy_init();

	if (curl != NULL) {
		/* we need a NUL-terminated string for curl */
		uri = str_from_chunk(url, "NUL-terminated url");

		if (curl_timeout > 0)
			timeout = curl_timeout;

		DBG(DBG_X509,
		    DBG_log("Trying cURL '%s' with connect timeout of %ld",
			uri, timeout));

		curl_easy_setopt(curl, CURLOPT_URL, uri);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_buffer);
		curl_easy_setopt(curl, CURLOPT_FILE, (void *)&response);
		curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorbuffer);
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, timeout);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2 * timeout);
		/* work around for libcurl signal bug */
		curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
		if (curl_iface != NULL)
			curl_easy_setopt(curl, CURLOPT_INTERFACE, curl_iface);

		res = curl_easy_perform(curl);

		if (res == CURLE_OK) {
			/* clone from realloc(3)ed memory to pluto-allocated memory */
			clonetochunk(*blob, response.ptr, response.len, "curl blob");
		} else {
			libreswan_log("fetching uri (%s) with libcurl failed: %s", uri,
			     errorbuffer);
		}
		curl_easy_cleanup(curl);
		pfreeany(uri);

		if (response.ptr != NULL)
			free(response.ptr);	/* allocated via realloc(3) */
	}
	return strlen(errorbuffer) > 0 ? "libcurl error" : NULL;
#else
	return "not compiled with libcurl support";
#endif
}

#ifdef LIBLDAP
/*
 * parses the result returned by an ldap query
 */
static err_t parse_ldap_result(LDAP * ldap, LDAPMessage *result, chunk_t *blob)
{
	err_t ugh = NULL;

	LDAPMessage * entry = ldap_first_entry(ldap, result);

	if (entry != NULL) {
		BerElement *ber = NULL;
		char *attr;

		attr = ldap_first_attribute(ldap, entry, &ber);

		if (attr != NULL) {
			struct berval **values = ldap_get_values_len(ldap,
								     entry,
								     attr);

			if (values != NULL) {
				if (values[0] != NULL) {
					blob->len = values[0]->bv_len;
					blob->ptr = alloc_bytes(blob->len,
								"ldap blob");
					memcpy(blob->ptr, values[0]->bv_val,
					       blob->len);
					if (values[1] != NULL)
						libreswan_log(
							"warning: more than one value was fetched from LDAP URL");


				} else {
					ugh = "no values in attribute";
				}
				ldap_value_free_len(values);
			} else {
				ugh = ldap_err2string(
					ldap_result2error(ldap, entry, 0));
			}
			ldap_memfree(attr);
		} else {
			ugh = ldap_err2string(
				ldap_result2error(ldap, entry, 0));
		}
		ber_free(ber, 0);
	} else {
		ugh = ldap_err2string(ldap_result2error(ldap, result, 0));
	}
	return ugh;
}

/*
 * fetches a binary blob from an ldap url
 */
static err_t fetch_ldap_url(chunk_t url, chunk_t *blob)
{
	LDAPURLDesc *lurl;
	LDAPMessage *result;
	err_t ugh = NULL;
	int msgid;
	int rc;

	char *ldap_url = str_from_chunk(url, "ldap query");

	DBG(DBG_X509,
	    DBG_log("Trying LDAP URL '%s'", ldap_url));

	rc = ldap_url_parse(ldap_url, &lurl);
	pfreeany(ldap_url);

	if (rc == LDAP_SUCCESS) {
		LDAP *ldap = ldap_init(lurl->lud_host, lurl->lud_port);

		if (ldap != NULL) {
			int ldap_version = LDAP_VERSION3;
			struct timeval timeout;

			timeout.tv_sec  = FETCH_CMD_TIMEOUT;
			timeout.tv_usec = 0;
			ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION,
					&ldap_version);
			ldap_set_option(ldap, LDAP_OPT_NETWORK_TIMEOUT,
					&timeout);

			msgid = ldap_simple_bind(ldap, NULL, NULL);

			rc = ldap_result(ldap, msgid, 1, &timeout, &result);

			switch (rc) {
			case -1:
				ldap_msgfree(result);
				return "ldap_simple_bind error";

			case LDAP_SUCCESS:
				ldap_msgfree(result);
				return "ldap_simple_bind timeout";

			case LDAP_RES_BIND:
				ldap_msgfree(result);
				rc = LDAP_SUCCESS;
				break;
			}
			if (rc == LDAP_SUCCESS) {
				timeout.tv_sec = FETCH_CMD_TIMEOUT;
				timeout.tv_usec = 0;

				rc = ldap_search_st(ldap, lurl->lud_dn,
						    lurl->lud_scope,
						    lurl->lud_filter,
						    lurl->lud_attrs,
						    0, &timeout, &result);

				if (rc == LDAP_SUCCESS) {
					ugh = parse_ldap_result(ldap, result,
								blob);
					ldap_msgfree(result);
				} else {
					ugh = ldap_err2string(rc);
				}
			} else {
				ugh = ldap_err2string(rc);
			}
			ldap_unbind_s(ldap);
		} else {
			ugh = "ldap init";
		}
		ldap_free_urldesc(lurl);
	} else {
		ugh = ldap_err2string(rc);
	}
	return ugh;
}
#else
static err_t fetch_ldap_url(chunk_t url UNUSED,
			    chunk_t *blob UNUSED)
{
	return "LDAP URL fetching not activated in pluto source code";
}
#endif

/*
 * fetch an ASN.1 blob coded in PEM or DER format from a URL
 * Returns error message or NULL.
 * Iff no error, *blob contains fetched ASN.1 blob (to be freed by caller).
 */
static err_t fetch_asn1_blob(chunk_t url, chunk_t *blob)
{
	err_t ugh = NULL;

	*blob = empty_chunk;
	if (url.len >= 5 && strncaseeq((const char *)url.ptr, "ldap:", 5))
		ugh = fetch_ldap_url(url, blob);
	else
		ugh = fetch_curl(url, blob);
	if (ugh != NULL) {
	} else if (is_asn1(*blob)) {
		DBG(DBG_PARSING,
		    DBG_log("  fetched blob coded in DER format"));
	} else {
		ugh = pemtobin(blob);
		if (ugh != NULL) {
		} else if (is_asn1(*blob)) {
			DBG(DBG_PARSING,
			    DBG_log("  fetched blob coded in PEM format"));
		} else {
			ugh = "Blob coded in unknown format (within PEM)";
		}
	}
	if (ugh == NULL && blob->len == 0)
		ugh = "empty ASN.1 blob";
	if (ugh != NULL)
		freeanychunk(*blob);
	return ugh;
}

/* Note: insert_crl_nss frees *blob */
static bool insert_crl_nss(chunk_t *blob, const chunk_t crl_uri)
{
	/* for CRL use the name passed to helper for the uri */
	bool ret = FALSE;
	char *uri_str = str_from_chunk(crl_uri, "URI str");

	if (uri_str == NULL) {
		DBGF(DBG_X509, "no CRL URI available");
	} else {
		int r = send_crl_to_import(blob->ptr, blob->len, uri_str);
		if (r == -1) {
			libreswan_log("_import_crl internal error");
		} else if (r != 0) {
			libreswan_log("NSS CRL import error: %s",
				      nss_err_str((PRInt32)r));
		} else {
			DBGF(DBG_X509, "CRL imported");
			ret = TRUE;
		}
	}

	pfreeany(uri_str);
	freeanychunk(*blob);
	return ret;
}

/*
 * try to fetch the crls defined by the fetch requests
 */
static void fetch_crls(void)
{
	lock_crl_fetch_list("fetch_crls");

	for (fetch_req_t **reqp = &crl_fetch_reqs;
	     *reqp != NULL && !exiting_pluto; ) {
		fetch_req_t *req = *reqp;
		bool valid_crl = FALSE;

		for (generalName_t *gn = req->distributionPoints;
		     gn != NULL; gn = gn->next) {
			chunk_t blob;
			err_t ugh = fetch_asn1_blob(gn->name, &blob);

			if (ugh != NULL) {
				DBG(DBG_X509,
					DBG_log("fetch failed:  %s", ugh));
			} else {
				if (insert_crl_nss(&blob, gn->name)) {
					DBG(DBG_X509,
					    DBG_log("we have a valid crl"));
					valid_crl = TRUE;
					break;
				}
			}
		}

		if (valid_crl) {
			/* delete fetch request */
			*reqp = req->next;	/* remove from list */
			free_fetch_request(req);
			/* reqp unchanged in this iteration */
		} else {
			/* retain fetch request for next time */
			req->trials++;
			reqp = &req->next;
		}
	}
	unlock_crl_fetch_list("fetch_crls");
}

/*
 * Create a possibly duplicate list of all known CRLS and send them
 * off to fetch_crls() for a refresh.
 *
 * Any duplicates will be eliminated by fetch_crls() when it merges
 * these requests with any still unprocessed requests.
 *
 * Similarly, if check_crls() is called more frequently then
 * fetch_crls() can process, redundant fetches will be merged.
 */
void check_crls(void)
{
	event_schedule(EVENT_CHECK_CRLS, crl_check_interval, NULL);
	struct crl_fetch_request *requests = NULL;

	/*
	 * CERT_GetDefaultCertDB() simply returns the contents of a
	 * static variable set by NSS_Initialize().  It doesn't check
	 * the value and doesn't set PR error.  Short of calling
	 * CERT_SetDefaultCertDB(NULL), the value can never be NULL.
	 */
	CERTCertDBHandle *handle = CERT_GetDefaultCertDB();
	passert(handle != NULL);

	CERTCrlHeadNode *crl_list = NULL;

	if (SEC_LookupCrls(handle, &crl_list, SEC_CRL_TYPE) != SECSuccess)
		return;

	CERTCrlNode *crl_node = crl_list->first;

	while (crl_node != NULL) {
		if (crl_node->crl != NULL) {
			SECItem *issuer = &crl_node->crl->crl.derName;

			if (crl_node->crl->url == NULL) {
				requests = crl_fetch_request(issuer, NULL, requests);
			} else {
				generalName_t end_dp = {
					.kind = GN_URI,
					.name = {
						.ptr = (u_char *)crl_node->crl->url,
						.len = strlen(crl_node->crl->url)
					},
					.next = NULL
				};
				requests = crl_fetch_request(issuer, &end_dp,
							     requests);
			}
		}
		crl_node = crl_node->next;
	}
	DBGF(DBG_X509, "releasing crl list in %s", __func__);
	PORT_FreeArena(crl_list->arena, PR_FALSE);

	/* add the pubkeys distribution points to fetch list */

	struct pubkey_list *pubkeys = pluto_pubkeys;
	struct pubkey *key;

	while (pubkeys != NULL) {
		key = pubkeys->key;
		if (key != NULL) {
			SECItem issuer = same_chunk_as_dercert_secitem(key->issuer);
			requests = crl_fetch_request(&issuer, NULL, requests);
		}
		pubkeys = pubkeys->next;
	}

	/*
	 * Iterate all X.509 certificates in database. This is needed to
	 * process middle and end certificates.
	 */
	CERTCertList *certs = get_all_certificates();

	if (certs != NULL) {
		CERTCertListNode *node;

		for (node = CERT_LIST_HEAD(certs);
		     !CERT_LIST_END(node, certs);
		     node = CERT_LIST_NEXT(node)) {
			requests = crl_fetch_request(&node->cert->derSubject,
						     NULL, requests);
		}
		CERT_DestroyCertList(certs);
	}
	add_crl_fetch_requests(requests);
}

static void merge_crl_fetch_request(struct crl_fetch_request *);

static void *fetch_thread(void *arg UNUSED)
{
	DBG(DBG_X509,
	    DBG_log("fetch thread started"));

	while (!exiting_pluto) {
		DBGF(DBG_X509, "fetching crl requests (may block)");
		struct crl_fetch_request *requests = get_crl_fetch_requests();

		/*
		 * Merge in the next batch of newest-to-oldest ordered
		 * requests.
		 *
		 * If a request isn't present, then it will be
		 * prepended, and since the oldest request is
		 * processed last, it is put right at the front.
		 */

		DBGF(DBG_X509, "merging new fetch requests");
		for (struct crl_fetch_request *request = requests;
		     request != NULL; request = request->next) {
			merge_crl_fetch_request(request);
		}
		free_crl_fetch_requests(&requests);

		/*
		 * Process all outstanding requests.
		 *
		 * Any brand new requests, prepended by the above, get
		 * processed first (and due to the double reversal) in
		 * the order they were submitted.
		 *
		 * Old requests then get processed at the end.
		 */
		fetch_crls();
	}
	DBGF(DBG_X509, "shutting down crl fetch thread");
	return NULL;
}

/*
 * initializes curl and starts the fetching thread
 */
void init_fetch(void)
{
	if (deltasecs(crl_check_interval) > 0) {
		int status;

#ifdef LIBCURL
		/* init curl */
		status = curl_global_init(CURL_GLOBAL_DEFAULT);
		if (status != 0)
			libreswan_log("libcurl could not be initialized, status = %d",
			     status);
#endif
		status = pthread_create(&thread, NULL, fetch_thread, NULL);
		if (status != 0)
			libreswan_log(
				"could not start thread for fetching certificate, status = %d",
				status);
		event_schedule(EVENT_CHECK_CRLS, deltatime(5), NULL);
	}
}

void free_crl_fetch(void)
{
	lock_crl_fetch_list("free_crl_fetch");

	while (crl_fetch_reqs != NULL) {
		fetch_req_t *req = crl_fetch_reqs;
		crl_fetch_reqs = req->next;
		free_fetch_request(req);
	}

	unlock_crl_fetch_list("free_crl_fetch");

#ifdef LIBCURL
	if (deltasecs(crl_check_interval) > 0) {
		/* cleanup curl */
		curl_global_cleanup();
	}
#endif
}

/*
 * Add additional distribution points.
 * Note: clones anything it needs to keep.
 */
static void add_distribution_points(const generalName_t *newPoints,
				    generalName_t **distributionPoints)
{
	for (; newPoints != NULL; newPoints = newPoints->next) {
		generalName_t *gn;

		for (gn = *distributionPoints; ; gn = gn->next) {
			if (gn == NULL) {
				/*
				 * End of list; not found.
				 * Clone additional distribution point.
				 */
				generalName_t *ngn = clone_const_thing(*newPoints, "generalName");
				ngn->name = clone_chunk(newPoints->name,
							"add_distribution_points: general name name");
				/* insert additional CRL distribution point */
				ngn->next = *distributionPoints;
				*distributionPoints = ngn;
				break;
			}
			if (gn->kind == newPoints->kind &&
			    gn->name.len == newPoints->name.len &&
			    memeq(gn->name.ptr, newPoints->name.ptr,
				   gn->name.len)) {
				/* newPoint already present */
				break;
			}
		}
	}
}

/*
 * Add a crl fetch request to the chained list.
 * Note: clones anything that needs to persist.
 */
static void merge_crl_fetch_request(struct crl_fetch_request *request)
{
	DBG(DBG_X509, DBG_log("attempting to add a new CRL fetch request"));

	chunk_t idn = same_secitem_as_chunk(*request->issuer_dn);

	/* LOCK: matching unlock is at end of loop -- must be executed */
	lock_crl_fetch_list("add_crl_fetch_request");

	fetch_req_t *req;

	for (req = crl_fetch_reqs; ; req = req->next) {
		if (req == NULL) {
			/* end of list; no match found */

			/* create a new fetch request */
			fetch_req_t *nr = alloc_thing(fetch_req_t, "fetch request");

			*nr = empty_fetch_req;

			/* note current time */
			nr->installed = request->request_time;

			/* clone issuer (again) */
			nr->issuer = clone_chunk(idn, "issuer dn");

			/* copy distribution points */
			add_distribution_points(request->dps, &nr->distributionPoints);

			/* insert new fetch request at the head of the queue */
			nr->next = crl_fetch_reqs;
			crl_fetch_reqs = nr;

			DBG(DBG_X509,
			    DBG_log("crl fetch request added"));
			break;
		}
		if (same_dn(idn, req->issuer)) {
			/* there is already a fetch request */
			DBG(DBG_X509,
			    DBG_log("crl fetch request already exists"));

			/* there might be new distribution points */
			add_distribution_points(request->dps, &req->distributionPoints);

			DBG(DBG_X509,
			    DBG_log("crl fetch request augmented"));
			break;
		}
	}
	/* UNLOCK: matching lock is before loop */
	unlock_crl_fetch_list("add_crl_fetch_request");
}

/*
 * list all distribution points
 */
static void list_distribution_points(const generalName_t *first_gn)
{
	const generalName_t *gn;
	for (gn = first_gn; gn != NULL; gn = gn->next) {
		whack_log(RC_COMMENT, "       %s '%.*s'",
			gn == first_gn ? "distPts:" : "        ",
			(int)gn->name.len,
			gn->name.ptr);
	}
}

/*
 *  list all fetch requests in the chained list
 */
void list_crl_fetch_requests(bool utc)
{
	fetch_req_t *req;

	lock_crl_fetch_list("list_crl_fetch_requests");
	req = crl_fetch_reqs;

	if (req != NULL) {
		whack_log(RC_COMMENT, " ");
		whack_log(RC_COMMENT, "List of CRL fetch requests:");
		whack_log(RC_COMMENT, " ");
	}

	while (req != NULL) {
		char buf[ASN1_BUF_LEN];
		LSWLOG_WHACK(RC_COMMENT, buf) {
			lswlog_realtime(buf, req->installed, utc);
			lswlogf(buf, ", trials: %d", req->trials);
		}
		dntoa(buf, ASN1_BUF_LEN, req->issuer);
		whack_log(RC_COMMENT, "       issuer:  '%s'", buf);
		list_distribution_points(req->distributionPoints);
		req = req->next;
	}
	unlock_crl_fetch_list("list_crl_fetch_requests");
}

#else /* defined(LIBCURL) || defined(LIBLDAP) */
/* we'll just ignore for now - this is all going away anyway */
#endif
