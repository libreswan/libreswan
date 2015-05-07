/* pluto NSS certificate verification routines
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
#ifndef _NSS_CERT_VFY_H
#define _NSS_CERT_VFY_H

#include <libreswan.h>
#include "lswalloc.h"
#include <cert.h>

extern int verify_and_cache_chain(chunk_t *ders, int num_ders,
						 CERTCertificate **ee_out,
						 bool *rev_opts);

/* rev_opts index */
#define RO_OCSP 0
#define RO_OCSP_S 1
#define RO_CRL_S 2
#define RO_SZ 3

#define VERIFY_RET_OK       0x0001
#define VERIFY_RET_REVOKED  0x0002
#define VERIFY_RET_FAIL     0x0004

#define VERIFY_RET_CRL_NEED 0x1000

#endif /* _NSS_CERT_VFY_H */
