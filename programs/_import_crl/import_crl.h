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

#ifndef FETCH_H
#define FETCH_H

#include "err.h"
#include "chunk.h"
#include "deltatime.h"

struct logger;

extern deltatime_t crl_fetch_timeout;
extern char *curl_iface;

#ifdef USE_LIBCURL
err_t fetch_curl(const char *url, chunk_t *blob, struct logger *logger);
void init_curl(struct logger *logger);
void shutdown_curl(void);
#endif

#ifdef USE_LDAP
err_t fetch_ldap(const char *url, chunk_t *blob, struct logger *logger);
#endif

#endif
