/* Dynamic fetching of X.509 CRLs, for libreswan
 *
 * Copyright (C) 2025  Andrew Cagney
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

#ifndef IMPORT_CRL_H
#define IMPORT_CRL_H

#include <sys/types.h>		/* for time_t */

#include "verbose.h"
#include "err.h"
#include "chunk.h"
#include "deltatime.h"

struct logger;

extern char *curl_iface;

#ifdef USE_LIBCURL
err_t fetch_curl(const char *url, time_t timeout, chunk_t *blob, struct verbose verbose);
#endif

#ifdef USE_LDAP
err_t fetch_ldap(const char *url, time_t timeout, chunk_t *blob, struct verbose verbose);
#endif

#endif
