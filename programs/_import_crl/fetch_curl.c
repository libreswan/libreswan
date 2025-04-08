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
#include <curl/curl.h>		/* rpm:libcurl-devel dep:libcurl4-nss-dev */
#include <stdlib.h>	/* danger; using malloc() */
#include <string.h>

#include "import_crl.h"

#include "err.h"
#include "lswlog.h"

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

err_t fetch_curl(const char *url, time_t timeout, chunk_t *blob,
		 struct verbose verbose)
{
	char errorbuffer[CURL_ERROR_SIZE] = "?";
	chunk_t response = EMPTY_CHUNK;	/* managed by realloc/free */

	/* init curl */
	int status = curl_global_init(CURL_GLOBAL_DEFAULT);
	if (status != 0) {
		vfatal("libcurl could not be initialized, status = %d", status);
	}

	/* get it with libcurl */
	CURL *curl = curl_easy_init();

	if (curl == NULL)
		return "cannot initialize curl";

	vdbg("Trying cURL '%s' with connect timeout of %ld",
	     url, (long)timeout);

	CURLcode res = CURLE_OK;

#	define CESO(optype, optarg) { \
		if (res == CURLE_OK) { \
			res = curl_easy_setopt(curl, optype, optarg); \
			if (res != CURLE_OK) { \
				vdbg("curl_easy_setopt " #optype " failed %d", res); \
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
		llog(RC_LOG, verbose.logger,
		     "fetching uri (%s) with libcurl failed: %s", url, errorbuffer);
	}
	curl_easy_cleanup(curl);
	curl_global_cleanup();

	/* ??? where/how should this be logged? */
	if (errorbuffer[0] != '\0') {
		vdbg("libcurl(%s) yielded %s", url, errorbuffer);
	}

	if (response.ptr != NULL)
		free(response.ptr);	/* allocated via realloc(3) */

	/* ??? should this return errorbuffer instead? */
	return strlen(errorbuffer) > 0 ? "libcurl error" : NULL;
}
