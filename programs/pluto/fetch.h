/* Dynamic fetching of X.509 CRLs
 * Copyright (C) 2002 Stephane Laroche <stephane.laroche@colubris.com>
 * Copyright (C) 2002-2004 Andreas Steffen, Zuercher Hochschule Winterthur
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

#ifndef FETCH_H
#define FETCH_H

#include <stdbool.h>

#include "chunk.h"
#include "err.h"
#include "deltatime.h"

struct logger;

extern void start_crl_fetch_helper(struct logger *logger);
extern void stop_crl_fetch_helper(struct logger *logger);

extern void free_crl_fetch(void);

extern deltatime_t crl_fetch_timeout;
extern char *curl_iface;
extern bool crl_strict;
extern bool ocsp_strict;
extern bool ocsp_enable;
extern bool ocsp_post;
extern deltatime_t crl_check_interval;

#endif
