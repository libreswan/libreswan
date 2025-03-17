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

struct x509_ocsp_config {
	bool enable;
	bool strict;
	char *uri;
	char *trust_name;
	deltatime_t timeout;
	enum ocsp_method method;
	int cache_size;
	deltatime_t cache_min_age;
	deltatime_t cache_max_age;
};

extern struct x509_ocsp_config x509_ocsp;

#endif
