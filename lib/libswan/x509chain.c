/* Support of X.509 certificates and CRLs
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
#include <libreswan/ipsec_policy.h>

#include "sysdep.h"
#include "lswalloc.h"
#include "lswconf.h"
#include "constants.h"
#include "lswlog.h"
#include "lswtime.h"

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
 * Filter eliminating the directory entries starting with .,
 * and also "CVS" (thus eliminating '.' and '..')
 */
int file_select(
#ifdef SCANDIR_HAS_CONST
	const
#endif
	struct dirent *entry)
{
	return entry->d_name[0] != '.' &&
	       strcmp(entry->d_name, "CVS") != 0 &&
	       strcmp(entry->d_name, "RCS") != 0;

}

/*
 * AUTH CERTIFICATE chains
 */
static x509cert_t *x509authcerts = NULL;

/*const*/ x509cert_t *x509_get_authcerts_chain(void)
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
		    ((keyid.ptr != NULL) ? same_keyid(keyid,
						      cert->subjectKeyID) :
		     (same_dn(subject, cert->subject) &&
		      same_serial(serial, cert->serialNumber)))) {
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
 *  free the first authority certificate in the chain
 */
static void free_first_authcert(void)
{
	x509cert_t *first = x509authcerts;

	x509authcerts = first->next;
	free_x509cert(first);
}

/*
 *  free  all CA certificates
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
			/* cert is already present, just add additional authority flags */
			old_cert->authority_flags |= cert->authority_flags;
			DBG(DBG_X509 | DBG_PARSING,
			    DBG_log("  authcert is already present and identical")
			    );
			unlock_authcert_list("add_authcert");

			free_x509cert(cert);
			return;
		} else {
			/* cert is already present but will be replaced by new cert */
			free_first_authcert();
			DBG(DBG_X509 | DBG_PARSING,
			    DBG_log("  existing authcert deleted")
			    );
		}
	}

	/* add new authcert to chained list */
	cert->next = x509authcerts;
	x509authcerts = cert;
	share_x509cert(cert); /* set count to one */
	DBG(DBG_X509 | DBG_PARSING,
	    DBG_log("  authcert inserted")
	    );
	unlock_authcert_list("add_authcert");
}

/*
 *  Loads authority certificates
 */
void load_authcerts(const char *type, const char *path, u_char auth_flags)
{
	struct dirent **filelist;
	char buf[ASN1_BUF_LEN];
	char *save_dir;
	int n;

	/* change directory to specified path */
	save_dir = getcwd(buf, ASN1_BUF_LEN);

	if (chdir(path)) {
		libreswan_log("Could not change to directory '%s': %s",
			path, strerror(errno));
	} else {
		DBG(DBG_CONTROL, DBG_log("Changed path to directory '%s'",
					 path));
		n = scandir(".", &filelist, (void *) file_select, alphasort);

		if (n < 0) {
			char buff[256];
			strerror_r(errno, buff, 256 );
			libreswan_log("  scandir() ./ error: %s", buff);
		} else {
			while (n--) {
				cert_t cert;

				if (load_cert(filelist[n]->d_name,
#ifdef SINGLE_CONF_DIR
					      FALSE, /* too verbose in single conf dir */
#else
					      TRUE,
#endif
					      type, &cert))
					add_authcert(cert.u.x509, auth_flags);

				free(filelist[n]);
			}
			free(filelist);
		}

		/* restore directory path */
		if (chdir(save_dir) != 0) {
			char buff[256];
			strerror_r(errno, buff, 256 );
			libreswan_log("  chdir() ./ error: %s", buff);
		}
	}

}

/********************** auth cert lists **********/

/*
 * Checks if CA a is trusted by CA b
 */
bool trusted_ca(chunk_t a, chunk_t b, int *pathlen)
{
	bool match = FALSE;
	char abuf[ASN1_BUF_LEN], bbuf[ASN1_BUF_LEN];

	dntoa(abuf, ASN1_BUF_LEN, a);
	dntoa(bbuf, ASN1_BUF_LEN, b);

	DBG(DBG_X509 | DBG_CONTROLMORE,
	    DBG_log("  trusted_ca called with a=%s b=%s",
		    abuf, bbuf));

	/* no CA b specified -> any CA a is accepted */
	if (b.ptr == NULL) {
		*pathlen = (a.ptr == NULL) ? 0 : MAX_CA_PATH_LEN;
		return TRUE;
	}

	/* no CA a specified -> trust cannot be established */
	if (a.ptr == NULL) {
		*pathlen = MAX_CA_PATH_LEN;
		return FALSE;
	}

	*pathlen = 0;

	/* CA a equals CA b -> we have a match */
	if (same_dn(a, b))
		return TRUE;

	/* CA a might be a subordinate CA of b */
	lock_authcert_list("trusted_ca");

	while ((*pathlen)++ < MAX_CA_PATH_LEN) {
		x509cert_t *cacert = get_authcert(a, empty_chunk, empty_chunk,
						  AUTH_CA);

		/* cacert not found or self-signed root cacert-> exit */
		if (cacert == NULL || same_dn(cacert->issuer, a))
			break;

		/* does the issuer of CA a match CA b? */
		match = same_dn(cacert->issuer, b);

		/* we have a match and exit the loop */
		if (match)
			break;

		/* go one level up in the CA chain */
		a = cacert->issuer;
	}

	unlock_authcert_list("trusted_ca");

	DBG(DBG_X509 | DBG_CONTROLMORE,
	    DBG_log("  trusted_ca returning with %s",
		    match ? "match" : "failed"));

	return match;
}

/*  Checks if the current certificate is revoked. It goes through the
 *  list of revoked certificates of the corresponding crl. If the
 *  certificate is found in the list, TRUE is returned
 */
bool x509_check_revocation(const x509crl_t *crl, chunk_t serial)
{
	revokedCert_t *revokedCert = crl->revokedCertificates;
	char tbuf[TIMETOA_BUF];

	DBG(DBG_X509,
	    DBG_dump_chunk("serial number:", serial)
	    );

	while (revokedCert != NULL) {
		/* compare serial numbers */
		if (revokedCert->userCertificate.len == serial.len &&
		    memcmp(revokedCert->userCertificate.ptr, serial.ptr,
			   serial.len) == 0) {
			libreswan_log("certificate was revoked on %s",
				      timetoa(&revokedCert->revocationDate,
					      TRUE, tbuf, sizeof(tbuf)));
			return TRUE;
		}
		revokedCert = revokedCert->next;
	}
	DBG(DBG_X509,
	    DBG_log("certificate not revoked")
	    );
	return FALSE;
}

/*
 * get a cacert with a given subject or keyid from an alternative list
 */
static const x509cert_t *get_alt_cacert(chunk_t subject, chunk_t serial,
				        chunk_t keyid,
				        const x509cert_t *cert)
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

/* establish trust into a candidate authcert by going up the trust chain.
 * validity and revocation status are not checked.
 */
bool trust_authcert_candidate(const x509cert_t *cert,
			      const x509cert_t *alt_chain)
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
			    datatot(cert->authKeyID.ptr, cert->authKeyID.len,
				    ':',
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
			    DBG_log("issuer cacert found in alternative chain")
			    );
		} else {
			/* search in trusted chain */
			authcert = get_authcert(cert->issuer,
						cert->authKeySerialNumber,
						cert->authKeyID, AUTH_CA);

			if (authcert != NULL) {
				DBG(DBG_CONTROL,
				    DBG_log("issuer cacert found")
				    );
			} else {
				plog("issuer cacert not found");
				unlock_authcert_list("trust_authcert_candidate");
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
		    DBG_log("valid certificate signature")
		    );

		/* check if cert is a self-signed root ca */
		if (pathlen > 0 && same_dn(cert->issuer, cert->subject)) {
			DBG(DBG_CONTROL,
			    DBG_log("reached self-signed root ca")
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

/* verify the validity of a certificate by
 * checking the notBefore and notAfter dates
 */
err_t check_validity(const x509cert_t *cert, time_t *until)
{
	time_t current_time;
	char curtime[TIMETOA_BUF];

	time(&current_time);
	timetoa(&current_time, TRUE, curtime, sizeof(curtime));

	DBG(DBG_X509,
	    char tbuf[TIMETOA_BUF];

	    DBG_log("  not before  : %s",
		    timetoa(&cert->notBefore, TRUE, tbuf, sizeof(tbuf)));
	    DBG_log("  current time: %s", curtime);
	    DBG_log("  not after   : %s",
		    timetoa(&cert->notAfter, TRUE, tbuf, sizeof(tbuf)));
	    );

	if (cert->notAfter < *until)
		*until = cert->notAfter;

	if (current_time < cert->notBefore) {
		char tbuf[TIMETOA_BUF];

		return builddiag(
			"X.509 certificate is not valid until %s (it is now=%s)",
			timetoa(&cert->notBefore, TRUE, tbuf,
				sizeof(tbuf)),
			curtime);
	}

	if (current_time > cert->notAfter) {
		char tbuf[TIMETOA_BUF];

		DBG_log("  aftercheck : %ld > %ld",
			(unsigned long)current_time,
			(unsigned long)cert->notAfter);
		return builddiag(
			"X.509 certificate expired at %s (it is now %s)",
			timetoa(&cert->notAfter, TRUE, tbuf,
				sizeof(tbuf)),
			curtime);
	} else {
		return NULL;
	}
}

/*
 * does our CA match one of the requested CAs?
 */
bool match_requested_ca(generalName_t *requested_ca, chunk_t our_ca,
			int *our_pathlen)
{
	/* if no ca is requested than any ca will match */
	if (requested_ca == NULL) {
		*our_pathlen = 0;
		return TRUE;
	}

	*our_pathlen = MAX_CA_PATH_LEN + 1;

	while (requested_ca != NULL) {
		int pathlen;

		if (trusted_ca(our_ca, requested_ca->name, &pathlen) &&
		    pathlen < *our_pathlen)
			*our_pathlen = pathlen;
		requested_ca = requested_ca->next;
	}

	return *our_pathlen <= MAX_CA_PATH_LEN;
}
