/* Certificate support for IKE authentication
 * Copyright (C) 2002-2004 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2003-2006 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
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

#ifndef _CERTS_H
#define _CERTS_H

#include "secrets.h"
#include "x509.h"

/* advance warning of imminent expiry of
 * cacerts, public keys, and crls
 * unused: OCSP_CERT_WARNING_INTERVAL	(30 * secs_per_day)
 * unused: ACERT_WARNING_INTERVAL	(1 * secs_per_day)
 */
#define CA_CERT_WARNING_INTERVAL	(30 * secs_per_day)
#define PUBKEY_WARNING_INTERVAL		(14 * secs_per_day)
#define CRL_WARNING_INTERVAL		(7 * secs_per_day)

/* access structure for RSA private keys */

typedef struct rsa_privkey rsa_privkey_t;

struct rsa_privkey {
	chunk_t keyobject;
	chunk_t field[8];
};

/* certificate access structure
 * currently X.509 certificates are supported
 */
typedef struct {
	enum ike_cert_type ty;
	union {
		/* some day we may support more */
		x509cert_t *x509;	/* CERT_X509_SIGNATURE */
	} u;
} cert_t;


extern chunk_t get_mycert(cert_t cert);
extern bool load_cert(const char *filename,
		      const char *label, cert_t *cert);

extern void share_cert(cert_t cert);
extern void release_cert(cert_t cert);
extern void list_certs(bool utc);

extern struct pubkey* allocate_RSA_public_key(const cert_t cert);
extern bool load_coded_file(const char *filename,
			    const char *type, chunk_t *blob);
extern bool cert_exists_in_nss(const char *nickname);
extern bool load_cert_from_nss(const char *nssHostCertNickName,
			       const char *label, cert_t *cert);
extern void load_authcerts_from_nss(const char *type, u_char auth_flags);

#endif /* _CERTS_H */
