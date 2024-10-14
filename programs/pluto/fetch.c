/* Dynamic fetching of X.509 CRLs, for libreswan
 *
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
#include "nss_crl_import.h"
#include "keys.h"
#include "crl_queue.h"
#include "server.h"
#include "lswnss.h"			/* for llog_nss_error() */
#include "whack_shutdown.h"		/* for exiting_pluto; */

#define FETCH_CMD_TIMEOUT       5       /* seconds */

char *curl_iface = NULL;
deltatime_t curl_timeout = DELTATIME_INIT(FETCH_CMD_TIMEOUT);

static pthread_t fetch_thread_id;

#ifdef LIBCURL

#include <curl/curl.h>		/* rpm:libcurl-devel dep:libcurl4-nss-dev */

/*
 * Appends *ptr into (chunk_t *)data.
 * A call-back used with libcurl.
 */
static size_t write_buffer(void *ptr, size_t size, size_t nmemb, void *data)
{
	size_t realsize = size * nmemb;
	chunk_t *mem = (chunk_t *)data;

	/* note: memory allocated by realloc(3) */
	unsigned char *m = realloc(mem->ptr, mem->len + realsize);

	if (m == NULL) {
		/* don't overwrite mem->ptr */
		return 0;	/* failure */
	} else {
		memcpy(&(m[mem->len]), ptr, realsize);
		mem->ptr = m;
		mem->len += realsize;
		return realsize;
	}
}

/*
 * fetches a binary blob from a url with libcurl
 */
static err_t fetch_curl(const char *url, chunk_t *blob, struct logger *logger)
{
	char errorbuffer[CURL_ERROR_SIZE] = "?";
	chunk_t response = EMPTY_CHUNK;	/* managed by realloc/free */
	long timeout = deltasecs(curl_timeout);

	/* get it with libcurl */
	CURL *curl = curl_easy_init();

	if (curl == NULL)
		return "cannot initialize curl";

	dbg("Trying cURL '%s' with connect timeout of %ld", url, timeout);

	CURLcode res = CURLE_OK;

#	define CESO(optype, optarg) { \
		if (res == CURLE_OK) { \
			res = curl_easy_setopt(curl, optype, optarg); \
			if (res != CURLE_OK) { \
				dbg("curl_easy_setopt " #optype " failed %d", res); \
			} \
		} \
	}

	CESO(CURLOPT_URL, url);
	CESO(CURLOPT_WRITEFUNCTION, write_buffer);
	/*
	 * coverity scan:
	 * "bad_sizeof: Taking the size of &response, which is the address of an object, is suspicious."
	 * In fact, this code is correct.
	 */
	CESO(CURLOPT_WRITEDATA, (void *)&response);
	CESO(CURLOPT_ERRORBUFFER, errorbuffer);
	CESO(CURLOPT_CONNECTTIMEOUT, timeout);
	CESO(CURLOPT_TIMEOUT, 2 * timeout);
	CESO(CURLOPT_NOSIGNAL, 1);	/* work around for libcurl signal bug */

	if (curl_iface != NULL)
		CESO(CURLOPT_INTERFACE, curl_iface);

#	undef CESO

	if (res == CURLE_OK)
		res = curl_easy_perform(curl);

	if (res == CURLE_OK) {
		/* clone from realloc(3)ed memory to pluto-allocated memory */
		errorbuffer[0] = '\0';
		*blob = clone_hunk(response, "curl blob");
	} else {
		llog(RC_LOG, logger,
		     "fetching uri (%s) with libcurl failed: %s", url, errorbuffer);
	}
	curl_easy_cleanup(curl);

	/* ??? where/how should this be logged? */
	if (errorbuffer[0] != '\0') {
		dbg("libcurl(%s) yielded %s", url, errorbuffer);
	}

	if (response.ptr != NULL)
		free(response.ptr);	/* allocated via realloc(3) */

	/* ??? should this return errorbuffer instead? */
	return strlen(errorbuffer) > 0 ? "libcurl error" : NULL;
}

#else	/* LIBCURL */

static err_t fetch_curl(const char *url,
			chunk_t *blob,
			struct logger *logger)
{
	ldbg(logger, "%s() ignoring %s %p", __func__, url, blob->ptr);
	return "not compiled with libcurl support";
}

#endif	/* LIBCURL */


#ifdef LIBLDAP

#define LDAP_DEPRECATED 1
#include <ldap.h>

/*
 * parses the result returned by an ldap query
 */
static err_t parse_ldap_result(LDAP *ldap, LDAPMessage *result, chunk_t *blob,
			       struct logger *logger)
{
	err_t ugh = NULL;

	LDAPMessage *entry = ldap_first_entry(ldap, result);

	if (entry != NULL) {
		BerElement *ber = NULL;
		char *attr = ldap_first_attribute(ldap, entry, &ber);

		if (attr != NULL) {
			struct berval **values = ldap_get_values_len(ldap,
								     entry,
								     attr);

			if (values != NULL) {
				if (values[0] != NULL) {
					*blob = clone_bytes_as_chunk(
						values[0]->bv_val,
						values[0]->bv_len,
						"ldap blob");
					if (values[1] != NULL)
						llog(RC_LOG, logger,
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
static err_t fetch_ldap_url(const char *url, chunk_t *blob, struct logger *logger)
{
	LDAPURLDesc *lurl;
	err_t ugh = NULL;
	int rc;

	dbg("Trying LDAP URL '%s'", url);

	rc = ldap_url_parse(url, &lurl);

	if (rc == LDAP_SUCCESS) {
		LDAP *ldap = ldap_init(lurl->lud_host, lurl->lud_port);

		if (ldap != NULL) {
			struct timeval timeout;

			timeout.tv_sec  = FETCH_CMD_TIMEOUT;
			timeout.tv_usec = 0;
			const int ldap_version = LDAP_VERSION3;
			ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION,
					&ldap_version);
			ldap_set_option(ldap, LDAP_OPT_NETWORK_TIMEOUT,
					&timeout);

			int msgid = ldap_simple_bind(ldap, NULL, NULL);

			LDAPMessage *result;
			rc = ldap_result(ldap, msgid, 1, &timeout, &result);

			switch (rc) {
			case -1:
				ldap_msgfree(result);
				return "ldap_simple_bind error";

			case 0:
				ldap_msgfree(result);
				return "ldap_simple_bind timeout";

			case LDAP_RES_BIND:
				ldap_msgfree(result);
				timeout.tv_sec = FETCH_CMD_TIMEOUT;
				timeout.tv_usec = 0;

				rc = ldap_search_st(ldap, lurl->lud_dn,
						    lurl->lud_scope,
						    lurl->lud_filter,
						    lurl->lud_attrs,
						    0, &timeout, &result);

				if (rc == LDAP_SUCCESS) {
					ugh = parse_ldap_result(ldap,
								result,
								blob,
								logger);
					ldap_msgfree(result);
				} else {
					ugh = ldap_err2string(rc);
				}
				break;

			default:
				/* ??? should we ldap_msgfree(result);? */
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

static err_t fetch_ldap_url(const char *url UNUSED,
			    chunk_t *blob UNUSED,
			    struct logger *logger UNUSED)
{
	return "LDAP URL fetching not activated in pluto source code";
}

#endif

/*
 * fetch an ASN.1 blob coded in PEM or DER format from a URL
 * Returns error message or NULL.
 * Iff no error, *blob contains fetched ASN.1 blob (to be freed by caller).
 */

static err_t fetch_asn1_blob(const char *url, chunk_t *blob, struct logger *logger)
{
	err_t ugh = NULL;

	*blob = EMPTY_CHUNK;
	if (startswith(url, "ldap:")) {
		ugh = fetch_ldap_url(url, blob, logger);
	} else {
		ugh = fetch_curl(url, blob, logger);
	}
	if (ugh != NULL) {
		free_chunk_content(blob);
		return ugh;
	}

	ugh = asn1_ok(ASN1(*blob));
	if (ugh == NULL) {
		dbg("  fetched blob coded in DER format");
	} else {
		ugh = pemtobin(blob);
		if (ugh != NULL) {
		} else if (asn1_ok(ASN1(*blob)) == NULL) {
			dbg("  fetched blob coded in PEM format");
		} else {
			ugh = "Blob coded in unknown format (within PEM)";
		}
	}
	if (ugh == NULL && blob->len == 0)
		ugh = "empty ASN.1 blob";
	if (ugh != NULL)
		free_chunk_content(blob);
	return ugh;
}

/* Note: insert_crl_nss frees *blob */
static bool insert_crl_nss(chunk_t blob, chunk_t issuer, const char *url, struct logger *logger)
{
	/* for CRL use the name passed to helper for the uri */
	int r = send_crl_to_import(blob.ptr, blob.len, url, logger);
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
			jam_dn(buf, ASN1(issuer), jam_sanitized_bytes);
			jam(buf, "' from: %s", url);
		}
	}
	return ret;
}

/*
 * try to fetch the crls defined by the fetch requests
 */

static fetch_crl_fn fetch_crl; /* type check */

static bool fetch_crl(chunk_t issuer_dn, const char *url, struct logger *logger)
{
	/* err?!?! */
	if (!pexpect(url != NULL && strlen(url) > 0)) {
		return false;
	}

	chunk_t blob = empty_chunk; /* must free */
	err_t ugh = fetch_asn1_blob(url, &blob, logger);
	if (ugh != NULL) {
		dbg("CRL: fetch failed:  %s", ugh);
		return false;
	}

	bool ok = insert_crl_nss(blob, issuer_dn, url, logger);
	free_chunk_content(&blob);
	return ok;
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

#ifdef LIBCURL
	/* init curl */
	status = curl_global_init(CURL_GLOBAL_DEFAULT);
	if (status != 0) {
		fatal(PLUTO_EXIT_FAIL, logger,
		      "libcurl could not be initialized, status = %d", status);
	}
#endif

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
#ifdef LIBCURL
	if (deltasecs(crl_check_interval) > 0) {
		/* cleanup curl */
		curl_global_cleanup();
	}
#endif
}
