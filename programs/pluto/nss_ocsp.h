/* OCSP initialization for NSS
 *
 * Copyright (C) 2015 Matt Rogers <mrogers@libreswan.org>
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
#ifndef _NSS_OCSP_H
#define _NSS_OCSP_H

#include <libreswan.h>

#define OCSP_DEFAULT_TIMEOUT 2
extern bool init_nss_ocsp(const char *responder_url,
			  const char *trust_cert_name,
			  int timeout,
			  bool strict);

#endif /* _NSS_OCSP_H */
