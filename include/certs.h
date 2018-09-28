/* Certificate support for IKE authentication
 * Copyright (C) 2002-2004 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2003-2006 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
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

#ifndef _CERTS_H
#define _CERTS_H

/* workaround for NSS/NSPR bug on MIPS with cert.h */
#ifndef _ABIO32
# define _ABIO32        1
#endif

#ifndef _ABIN32
# define _ABIN32        2
#endif

#ifndef _ABI64
# define _ABI64         3
#endif

#include <cert.h> /* NSS */
#include "x509.h"

/* advance warning of imminent expiry of
 * cacerts, public keys, and crls
 * unused: OCSP_CERT_WARNING_INTERVAL	(30 * secs_per_day)
 * unused: ACERT_WARNING_INTERVAL	(1 * secs_per_day)
 * unused: CA_CERT_WARNING_INTERVAL	(30 * secs_per_day)
 * unused: CRL_WARNING_INTERVAL		(7 * secs_per_day)
 */
#define PUBKEY_WARNING_INTERVAL		(14 * secs_per_day)

/* certificate access structure
 * currently X.509 certificates are supported
 */
typedef struct {
	enum ike_cert_type ty;
	union {
		/* some day we may support more */
		CERTCertificate *nss_cert;	/* CERT_X509_SIGNATURE */
	} u;
} cert_t;

const char *cert_nickname(const cert_t *cert);

extern void list_certs(void);
#endif /* _CERTS_H */
