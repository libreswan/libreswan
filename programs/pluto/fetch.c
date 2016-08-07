/* Dynamic fetching of X.509 CRLs
 * Copyright (C) 2002 Stephane Laroche <stephane.laroche@colubris.com>
 * Copyright (C) 2002-2004 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2003-2008 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
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
 *
 */

#if defined(LIBCURL) || defined(LDAP_VER)
#include <pthread.h>    /* Must be the first include file */
#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>
#include <string.h>

#ifdef LIBCURL
#include <curl/curl.h>	/* from libcurl devel */
#endif

#include <libreswan.h>

#ifdef LDAP_VER
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
	{ 0 },		/* installed */
	0,              /* trials */
	{ NULL, 0 },    /* issuer */
	NULL            /* distributionPoints */
};

/* chained list of crl fetch requests */
static fetch_req_t *crl_fetch_reqs  = NULL;

static pthread_t thread;
static pthread_mutex_t crl_fetch_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t fetch_wake_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t fetch_wake_cond = PTHREAD_COND_INITIALIZER;

extern char *curl_iface;
extern long curl_timeout;

/*
 * lock access to the chained crl fetch request list
 */
static void lock_crl_fetch_list(const char *who)
{
	pthread_mutex_lock(&crl_fetch_list_mutex);
	DBG(DBG_CONTROLMORE,
	    DBG_log("crl fetch request list locked by '%s'", who));
}

/*
 * unlock access to the chained crl fetch request list
 */
static void unlock_crl_fetch_list(const char *who)
{
	DBG(DBG_CONTROLMORE,
	    DBG_log("crl fetch request list unlocked by '%s'", who));
	pthread_mutex_unlock(&crl_fetch_list_mutex);
}

/*
 * wakes up the sleeping fetch thread
 */
void wake_fetch_thread(const char *who)
{
	if (deltasecs(crl_check_interval) > 0) {
		DBG(DBG_CONTROLMORE,
		    DBG_log("fetch thread wake call by '%s'", who));
		pthread_mutex_lock(&fetch_wake_mutex);
		pthread_cond_signal(&fetch_wake_cond);
		pthread_mutex_unlock(&fetch_wake_mutex);
	}
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
		/* we need a null terminated string for curl */
		uri = alloc_bytes(url.len + 1, "null terminated url");
		memcpy(uri, url.ptr, url.len);
		*(uri + url.len) = '\0';

		if (curl_timeout > 0)
			timeout = curl_timeout;

		DBG(DBG_CONTROL,
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
		pfree(uri);

		if (response.ptr != NULL)
			free(response.ptr);	/* allocated via realloc(3) */
	}
	return strlen(errorbuffer) > 0 ? "libcurl error" : NULL;
#else
	return "not compiled with libcurl support";
#endif
}

#ifdef LDAP_VER
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

	char *ldap_url = alloc_bytes(url.len + 1, "ldap query");

	snprintf(ldap_url, url.len + 1, "%.*s", (int)url.len, url.ptr);

	DBG(DBG_CONTROL,
	    DBG_log("Trying LDAP URL '%s'", ldap_url));

	rc = ldap_url_parse(ldap_url, &lurl);
	pfree(ldap_url);

	if (rc == LDAP_SUCCESS) {
		LDAP *ldap = ldap_init(lurl->lud_host, lurl->lud_port);

		if (ldap != NULL) {
			int ldap_version =
				LDAP_VER == 2 ? LDAP_VERSION2 : LDAP_VERSION3;
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
 */
static err_t fetch_asn1_blob(chunk_t url, chunk_t *blob)
{
	err_t ugh = NULL;

	if (url.len >= 4 && strncaseeq((const char *)url.ptr, "ldap", 4))
		ugh = fetch_ldap_url(url, blob);
	else
		ugh = fetch_curl(url, blob);
	if (ugh != NULL)
		return ugh;

	if (is_asn1(*blob)) {
		DBG(DBG_PARSING,
		    DBG_log("  fetched blob coded in DER format"));
	} else {
		ugh = pemtobin(blob);
		if (ugh == NULL) {
			if (is_asn1(*blob)) {
				DBG(DBG_PARSING,
				    DBG_log("  fetched blob coded in PEM format"));
			} else {
				ugh = "Blob coded in unknown format";
				pfreeany(blob->ptr);
			}
		} else {
			pfreeany(blob->ptr);
		}
	}
	return ugh;
}

/*
 * try to fetch the crls defined by the fetch requests
 */
static void fetch_crls(void)
{
	fetch_req_t *req;
	fetch_req_t **reqp;

	lock_crl_fetch_list("fetch_crls");
	req  =  crl_fetch_reqs;
	reqp = &crl_fetch_reqs;

	while (req != NULL) {
		bool valid_crl = FALSE;
		chunk_t blob = empty_chunk;
		generalName_t *gn = req->distributionPoints;

		while (gn != NULL) {
			err_t ugh = fetch_asn1_blob(gn->name, &blob);

			if (ugh != NULL) {
				DBG(DBG_CONTROL,
					DBG_log("fetch failed:  %s", ugh));
			} else {
				chunk_t crl_uri;
				clonetochunk(crl_uri, gn->name.ptr,
					     gn->name.len, "crl uri");
				if (insert_crl_nss(&blob, &crl_uri, NULL)) {
					DBG(DBG_CONTROL,
					    DBG_log("we have a valid crl"));
					valid_crl = TRUE;
					break;
				}
			}
			gn = gn->next;
		}

		if (valid_crl) {
			/* delete fetch request */
			fetch_req_t *req_free = req;

			req   = req->next;
			*reqp = req;
			free_fetch_request(req_free);
		} else {
			/* try again next time */
			req->trials++;
			reqp = &req->next;
			req  =  req->next;
		}
	}
	unlock_crl_fetch_list("fetch_crls");
}

static void *fetch_thread(void *arg UNUSED)
{
	DBG(DBG_CONTROL,
	    DBG_log("fetch thread started"));

	pthread_mutex_lock(&fetch_wake_mutex);
	for (;;) {
		struct timespec wakeup_time;
		int status;

		clock_gettime(CLOCK_REALTIME, &wakeup_time);
		wakeup_time.tv_sec += deltasecs(crl_check_interval);

		DBG(DBG_CONTROL,
		    DBG_log("next regular crl check in %ld seconds",
			    (long)deltasecs(crl_check_interval)));
		status = pthread_cond_timedwait(&fetch_wake_cond,
						&fetch_wake_mutex,
						&wakeup_time);

		if (status == ETIMEDOUT) {
			DBG(DBG_CONTROL, {
				    DBG_log(" ");
				    DBG_log("*time to check crls");
			    });
			check_crls();
		} else {
			DBG(DBG_CONTROL,
			    DBG_log("fetch thread was woken up"));
		}
		fetch_crls();
	}
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
void add_distribution_points(const generalName_t *newPoints,
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
				clonetochunk(ngn->name, newPoints->name.ptr,
					     newPoints->name.len,
					     "crl uri");

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
void add_crl_fetch_request_nss(SECItem *issuer_dn, generalName_t *end_dp)
{
	DBG(DBG_CONTROL, DBG_log("attempting to add a new CRL fetch request"));

	if (issuer_dn == NULL || issuer_dn->data == NULL ||
				 issuer_dn->len < 1) {
		DBG(DBG_CONTROL,
		    DBG_log("no issuer dn to gather fetch information from"));
		return;
	}

	CERTCertificate *ca = CERT_FindCertByName(CERT_GetDefaultCertDB(),
						issuer_dn);
	if (ca == NULL) {
		DBG_log("no CA cert found to add fetch request: [%d]",
							       PORT_GetError());
		return;
	}

	chunk_t idn = same_secitem_as_chunk(*issuer_dn);

	/* LOCK: matching unlock is at end of loop -- must be executed */
	lock_crl_fetch_list("add_crl_fetch_request");

	fetch_req_t *req;

	for (req = crl_fetch_reqs; ; req = req->next) {
		if (req == NULL) {
			/* end of list; no match found */

			generalName_t *new_dp = gndp_from_nss_cert(ca);

			if (new_dp == NULL) {
				if (end_dp == NULL) {
					DBG(DBG_CONTROL,
						DBG_log("no distribution point available for new fetch request"));
					break;
				}
				DBG(DBG_CONTROL,
					DBG_log("no CA crl DP available; using provided DP"));
				new_dp = end_dp;
			}

			/* create a new fetch request */
			fetch_req_t *nr = alloc_thing(fetch_req_t, "fetch request");

			*nr = empty_fetch_req;

			/* note current time */
			nr->installed = realnow();

			/* clone issuer */
			clonetochunk(nr->issuer, idn.ptr, idn.len, "issuer dn");

			/* copy distribution points */
			add_distribution_points(new_dp, &nr->distributionPoints);

			/* insert new fetch request at the head of the queue */
			nr->next = crl_fetch_reqs;
			crl_fetch_reqs = nr;

			DBG(DBG_CONTROL,
			    DBG_log("crl fetch request added"));
			break;
		}
		if (same_dn(idn, req->issuer)) {
			/* there is already a fetch request */
			DBG(DBG_CONTROL,
			    DBG_log("crl fetch request already exists"));

			/* there might be new distribution points */
			generalName_t *new_dp = gndp_from_nss_cert(ca);

			if (new_dp == NULL) {
				if (end_dp == NULL) {
					DBG(DBG_CONTROL,
						DBG_log("no CA crl DP available"));
					break;
				}
				DBG(DBG_CONTROL,
				    DBG_log("no CA crl DP available; using provided DP"));
				new_dp = end_dp;
			}

			add_distribution_points(new_dp, &req->distributionPoints);
			DBG(DBG_CONTROL,
			    DBG_log("crl fetch request augmented"));
			break;
		}
	}
	/* UNLOCK: matching lock is before loop */
	unlock_crl_fetch_list("add_crl_fetch_request");

	CERT_DestroyCertificate(ca);
}

/*
 * list all distribution points
 */
void list_distribution_points(const generalName_t *first_gn)
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
		char tbuf[REALTIMETOA_BUF];

		whack_log(RC_COMMENT, "%s, trials: %d",
			  realtimetoa(req->installed, utc, tbuf, sizeof(tbuf)),
			  req->trials);
		dntoa(buf, ASN1_BUF_LEN, req->issuer);
		whack_log(RC_COMMENT, "       issuer:  '%s'", buf);
		list_distribution_points(req->distributionPoints);
		req = req->next;
	}
	unlock_crl_fetch_list("list_crl_fetch_requests");
}

#else /* defined(LIBCURL) || defined(LDAP_VER) */
/* we'll just ignore for now - this is all going away anyway */
#endif
