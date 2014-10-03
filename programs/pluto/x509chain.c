/*
 * Support of X.509 certificates and CRLs
 *
 * Copyright (C) 2000 Andreas Hess, Patric Lichtsteiner, Roger Wegmann
 * Copyright (C) 2001 Marco Bertossa, Andreas Schleiss
 * Copyright (C) 2002 Mario Strasser
 * Copyright (C) 2000-2004 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2010 Paul Wouters <paul@xelerance.com>
 *
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
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <limits.h>
#include <sys/types.h>
#include <libreswan.h>
#include "sysdep.h"
#include "lswalloc.h"
#include "lswconf.h"
#include "constants.h"
#include "lswlog.h"
#include "defs.h"
#include "id.h"
#include "asn1.h"
#include "oid.h"
#include "x509.h"
#include "certs.h"
#include "packet.h"
#include "md5.h"
#include "sha1.h"
#include "pkcs.h"
#include "paths.h"


/*
 * AUTH CERTIFICATE chains
 */
static x509cert_t *x509authcerts = NULL;

x509cert_t *x509_get_authcerts_chain(void)
{
	return x509authcerts;
}

/*
 *  get a X.509 authority certificate with a given subject or keyid
 */
x509cert_t *get_authcert(chunk_t subject, chunk_t serial, chunk_t keyid,
			u_char auth_flags)
{
	x509cert_t *cert = x509authcerts;
	x509cert_t *prev_cert = NULL;

	while (cert != NULL) {
		if (cert->authority_flags & auth_flags &&
			((keyid.ptr != NULL) ?
				same_keyid(keyid, cert->subjectKeyID) :
				(same_dn(subject, cert->subject) &&
					same_serial(serial,
						cert->serialNumber)))) {
			if (cert != x509authcerts) {
				/* bring the certificate up front */
				prev_cert->next = cert->next;
				cert->next = x509authcerts;
				x509authcerts = cert;
			}
			return cert;
		}
		prev_cert = cert;
		cert = cert->next;
	}
	return NULL;
}

/*
 * free the first authority certificate in the chain
 */
static void free_first_authcert(void)
{
	x509cert_t *first = x509authcerts;

	x509authcerts = first->next;
	free_x509cert(first);
}

/* frees a chain of CA certificates from the x509authcert list.
 * get_authcert() moves the found cert to the front of the list,
 * so we can just do free_first_authcert().
 */
void free_authcert_chain(x509cert_t *chain)
{

	while (chain != NULL) {
		x509cert_t *ac = NULL;

		lock_authcert_list("free_authcert_chain");
		ac = get_authcert(chain->subject, chain->serialNumber,
					      chain->subjectKeyID, AUTH_CA);

		chain = chain->next;

		if (ac != NULL)
			free_first_authcert();

		unlock_authcert_list("free_authcert_chain");
	}
}

/*
 * free  all CA certificates
 */
void free_authcerts(void)
{
	lock_authcert_list("free_authcerts");

	while (x509authcerts != NULL)
		free_first_authcert();

	unlock_authcert_list("free_authcerts");
}

/*
 * add an authority certificate to the chained list
 */
void add_authcert(x509cert_t *cert, u_char auth_flags)
{
	x509cert_t *old_cert;

	/* set authority flags */
	cert->authority_flags |= auth_flags;

	lock_authcert_list("add_authcert");

	old_cert = get_authcert(cert->subject, cert->serialNumber,
				cert->subjectKeyID, auth_flags);

	if (old_cert != NULL) {
		if (same_x509cert(cert, old_cert)) {
			/*
			 * cert is already present, just add additional
			 * authority flags
			 */
			old_cert->authority_flags |= cert->authority_flags;
			DBG(DBG_X509 | DBG_PARSING,
				DBG_log("  authcert is already present and identical");
				);
			unlock_authcert_list("add_authcert");

			free_x509cert(cert);
			return;
		} else {
			/*
			 * cert is already present but will be replaced by
			 * new cert
			 */
			free_first_authcert();
			DBG(DBG_X509 | DBG_PARSING,
				DBG_log("  existing authcert deleted");
				);
		}
	}

	/* add new authcert to chained list */
	cert->next = x509authcerts;
	x509authcerts = cert;
	share_x509cert(cert);	/* set count to one */
	DBG(DBG_X509 | DBG_PARSING,
		DBG_log("  authcert inserted");
		);
	unlock_authcert_list("add_authcert");
}

/********************** auth cert lists **********/

/*
 * Checks if the current certificate is revoked. It goes through the
 * list of revoked certificates of the corresponding crl. If the
 * certificate is found in the list, TRUE is returned
 */
bool x509_check_revocation(const x509crl_t *crl, chunk_t serial)
{
	revokedCert_t *revokedCert = crl->revokedCertificates;
	char tbuf[REALTIMETOA_BUF];

	DBG(DBG_X509,
		DBG_dump_chunk("serial number:", serial);
		);

	while (revokedCert != NULL) {
		/* compare serial numbers */
		if (revokedCert->userCertificate.len == serial.len &&
			memeq(revokedCert->userCertificate.ptr, serial.ptr,
				serial.len)) {
			libreswan_log("certificate was revoked on %s",
				realtimetoa(revokedCert->revocationDate,
					TRUE, tbuf, sizeof(tbuf)));
			return TRUE;
		}
		revokedCert = revokedCert->next;
	}
	DBG(DBG_X509,
		DBG_log("certificate not revoked");
		);
	return FALSE;
}

/*
 * get a cacert with a given subject or keyid from an alternative list
 */
x509cert_t *get_alt_cacert(chunk_t subject, chunk_t serial,
					chunk_t keyid,
					x509cert_t *cert)
{
	while (cert != NULL) {
		if ((keyid.ptr != NULL) ? same_keyid(keyid,
							cert->subjectKeyID) :
			(same_dn(subject, cert->subject) &&
				same_serial(serial, cert->serialNumber)))
			return cert;

		cert = cert->next;
	}
	return NULL;
}

/*
 * establish trust into a candidate authcert by going up the trust chain.
 * validity and revocation status are not checked.
 */
bool trust_authcert_candidate(const x509cert_t *cert,
			x509cert_t *alt_chain)
{
	int pathlen;

	lock_authcert_list("trust_authcert_candidate");

	for (pathlen = 0; pathlen < MAX_CA_PATH_LEN; pathlen++) {
		const x509cert_t *authcert = NULL;

		DBG(DBG_CONTROL,
			char buf[ASN1_BUF_LEN];
			dntoa(buf, ASN1_BUF_LEN, cert->subject);
			DBG_log("subject: '%s'", buf);
			dntoa(buf, ASN1_BUF_LEN, cert->issuer);
			DBG_log("issuer:  '%s'", buf);
			if (cert->authKeyID.ptr != NULL) {
				datatot(cert->authKeyID.ptr,
					cert->authKeyID.len, ':',
					buf, ASN1_BUF_LEN);
				DBG_log("authkey:  %s", buf);
			}
			);

		/* search in alternative chain first */
		authcert = get_alt_cacert(cert->issuer,
					cert->authKeySerialNumber,
					cert->authKeyID, alt_chain);

		if (authcert != NULL) {
			DBG(DBG_CONTROL,
				DBG_log("issuer cacert found in alternative chain");
				);
		} else {
			/* search in trusted chain */
			authcert = get_authcert(cert->issuer,
						cert->authKeySerialNumber,
						cert->authKeyID, AUTH_CA);

			if (authcert != NULL) {
				DBG(DBG_CONTROL,
					DBG_log("issuer cacert found");
					);
			} else {
				plog("issuer cacert not found");
				unlock_authcert_list(
					"trust_authcert_candidate");
				return FALSE;
			}
		}

		if (!check_signature(cert->tbsCertificate, cert->signature,
					cert->algorithm, authcert)) {
			plog("invalid certificate signature");
			unlock_authcert_list("trust_authcert_candidate");
			return FALSE;
		}
		DBG(DBG_CONTROL,
			DBG_log("valid certificate signature");
			);

		/* check if cert is a self-signed root ca */
		if (pathlen > 0 && same_dn(cert->issuer, cert->subject)) {
			DBG(DBG_CONTROL,
				DBG_log("reached self-signed root ca");
				);
			unlock_authcert_list("trust_authcert_candidate");
			return TRUE;
		}

		/* go up one step in the trust chain */
		cert = authcert;
	}
	plog("maximum ca path length of %d levels exceeded", MAX_CA_PATH_LEN);
	unlock_authcert_list("trust_authcert_candidate");
	return FALSE;
}

/*
 * verify the validity of a certificate by
 * checking the notBefore and notAfter dates
 * Note: *until = min(*until, cert->notAfter)
 */
err_t check_validity(const x509cert_t *cert, realtime_t *until /* IN/OUT */)
{
	char curtime[REALTIMETOA_BUF];
	realtime_t current_time = realnow();

	realtimetoa(current_time, TRUE, curtime, sizeof(curtime));

	DBG(DBG_X509,
		char tbuf[REALTIMETOA_BUF];

		DBG_log("  not before  : %s",
			realtimetoa(cert->notBefore, TRUE, tbuf, sizeof(tbuf)));
		DBG_log("  current time: %s", curtime);
		DBG_log("  not after   : %s",
			realtimetoa(cert->notAfter, TRUE, tbuf, sizeof(tbuf)));
		);

	if (realbefore(cert->notAfter, *until))
		*until = cert->notAfter;

	if (realbefore(current_time, cert->notBefore)) {
		char tbuf[REALTIMETOA_BUF];

		return builddiag(
			"X.509 certificate is not valid until %s (it is now=%s)",
			realtimetoa(cert->notBefore, TRUE, tbuf,
				sizeof(tbuf)), curtime);
	}

	if (realbefore(cert->notAfter, current_time)) {
		char tbuf[REALTIMETOA_BUF];

		DBG(DBG_X509 | DBG_PARSING,
			DBG_log("  aftercheck : %ld > %ld",
				(unsigned long)current_time.real_secs,
				(unsigned long)cert->notAfter.real_secs));
		return builddiag(
			"X.509 certificate expired at %s (it is now %s)",
			realtimetoa(cert->notAfter, TRUE, tbuf,
				sizeof(tbuf)),
			curtime);
	} else {
		return NULL;
	}
}

