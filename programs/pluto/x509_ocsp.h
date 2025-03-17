/* OCSP initialization for NSS
 *
 * Copyright (C) 2015 Matt Rogers <mrogers@libreswan.org>
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
#ifndef X509_OCSP_H
#define X509_OCSP_H

#include <stdbool.h>

#include "diag.h"
#include "deltatime.h"
#include "ocsp_method.h"

struct logger;

extern diag_t init_x509_ocsp(struct logger *logger);

extern bool ocsp_strict;
extern bool ocsp_enable;
extern bool ocsp_post;
extern char *ocsp_uri;
extern char *ocsp_trust_name;
extern deltatime_t ocsp_timeout;
extern enum ocsp_method ocsp_method;
extern int ocsp_cache_size;
extern deltatime_t ocsp_cache_min_age;
extern deltatime_t ocsp_cache_max_age;

#endif

