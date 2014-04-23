/* Support of X.509 certificates and CRLs
 * Copyright (C) 2000 Andreas Hess, Patric Lichtsteiner, Roger Wegmann
 * Copyright (C) 2001 Marco Bertossa, Andreas Schleiss
 * Copyright (C) 2002 Mario Strasser
 * Copyright (C) 2000-2004 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2006-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Gilles Espinasse <g.esp@free.fr>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 Kim B. Heino <b@bbbs.net>
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>
#include <limits.h>
#include <sys/types.h>

#include <libreswan.h>

#include "sysdep.h"
#include "lswconf.h"
#include "constants.h"
#include "lswlog.h"
#include "lswtime.h"

#include "defs.h"
#include "log.h"
#include "id.h"
#include "asn1.h"
#include "mpzfuncs.h"
#include "oid.h"
#include "x509.h"
#include "certs.h"
#include "keys.h"
#include "packet.h"
#include "demux.h"      /* needs packet.h */
#include "connections.h"
#include "state.h"
#include "md5.h"
#include "sha1.h"
#include "whack.h"
#include "fetch.h"
#include "pkcs.h"
#include "x509more.h"

/* chained lists of X.509 host/user and ca certificates and crls */

static x509cert_t *x509certs   = NULL;
static x509crl_t  *x509crls    = NULL;

/*
 *  add a X.509 user/host certificate to the chained list
 */
x509cert_t *add_x509cert(x509cert_t *cert)
{
	x509cert_t *c = x509certs;

	while (c != NULL) {
		if (same_x509cert(c, cert)) { /* already in chain, free cert */
			free_x509cert(cert);
			return c;
		}
		c = c->next;
	}

	/* insert new cert at the root of the chain */
	lock_certs_and_keys("add_x509cert");
	cert->next = x509certs;
	x509certs = cert;
	unlock_certs_and_keys("add_x509cert");
	return cert;
}

/*
 *  get a X.509 certificate with a given issuer found at a certain position
 */
x509cert_t *get_x509cert(chunk_t issuer, chunk_t serial, chunk_t keyid,
			 x509cert_t *chain)
{
	x509cert_t *cert = (chain != NULL) ? chain->next : x509certs;

	while (cert != NULL) {
		if ((keyid.ptr != NULL) ? same_keyid(keyid, cert->authKeyID) :
		    (same_dn(issuer, cert->issuer) &&
		     same_serial(serial, cert->authKeySerialNumber)))
			return cert;

		cert = cert->next;
	}
	return NULL;
}

/*
 *  get the X.509 CRL with a given issuer
 */
static x509crl_t *get_x509crl(chunk_t issuer, chunk_t serial, chunk_t keyid)
{
	x509crl_t *crl = x509crls;
	x509crl_t *prev_crl = NULL;

	while (crl != NULL) {
		if ((keyid.ptr != NULL && crl->authKeyID.ptr != NULL) ?
		    same_keyid(keyid, crl->authKeyID) :
		    (same_dn(crl->issuer,
			     issuer) &&
		     same_serial(serial, crl->authKeySerialNumber))) {
			if (crl != x509crls) {
				/* bring the CRL up front */
				prev_crl->next = crl->next;
				crl->next = x509crls;
				x509crls = crl;
			}
			return crl;
		}
		prev_crl = crl;
		crl = crl->next;
	}
	return NULL;
}

/* release a certificate: decrease the count by one
 * and free the certificate when the counter reaches zero
 */
static void release_x509cert(x509cert_t *cert)
{
	if (cert != NULL && --cert->count == 0) {
		x509cert_t **pp = &x509certs;
		while (*pp != cert)
			pp = &(*pp)->next;
		lock_certs_and_keys("release_x509cert");
		*pp = cert->next;
		unlock_certs_and_keys("release_x509cert");
		free_x509cert(cert);
	}
}

/*  release of a certificate decreases the count by one
 *  the certificate is freed when the counter reaches zero
 */
void release_cert(cert_t cert)
{
	switch (cert.ty) {
	case CERT_NONE:
		/* quietly forget about it */
		break;
	case CERT_X509_SIGNATURE:
		release_x509cert(cert.u.x509);
		break;
	default:
		bad_case(cert.ty);
	}
}

static void free_first_crl(void)
{
	x509crl_t *crl = x509crls;

	x509crls = crl->next;
	free_crl(crl);
}

void free_crls(void)
{
	lock_crl_list("free_crls");

	while (x509crls != NULL)
		free_first_crl();

	unlock_crl_list("free_crls");
}

/*
 * stores a chained list of end certs and CA certs
 */
void store_x509certs(x509cert_t **firstcert, bool strict)
{
	x509cert_t *cacerts = NULL;
	x509cert_t **pp = firstcert;

	/* first extract CA certs, discarding root CA certs */

	while (*pp != NULL) {
		x509cert_t *cert = *pp;

		if (cert->isCA) {
			*pp = cert->next;

			/* we don't accept self-signed CA certs */
			if (same_dn(cert->issuer, cert->subject)) {
				libreswan_log("self-signed cacert rejected");
				free_x509cert(cert);
			} else {
				/* insertion into temporary chain of candidate CA certs */
				cert->next = cacerts;
				cacerts = cert;
			}
		} else {
			pp = &cert->next;
		}
	}

	/* now verify the candidate CA certs */

	while (cacerts != NULL) {
		x509cert_t *cert = cacerts;

		cacerts = cacerts->next;

		if (trust_authcert_candidate(cert, cacerts)) {
			add_authcert(cert, AUTH_CA);
		} else {
			libreswan_log("intermediate cacert rejected");
			free_x509cert(cert);
		}
	}

	/* now verify the end certificates */

	pp = firstcert;

	while (*pp != NULL) {
		time_t valid_until;
		x509cert_t *cert = *pp;

		if (verify_x509cert(cert, strict, &valid_until)) {
			DBG(DBG_X509 | DBG_PARSING,
			    DBG_log("public key validated"));
			add_x509_public_key(NULL, cert, valid_until,
					    DAL_SIGNED);
		} else {
			libreswan_log("X.509 certificate rejected");
		}
		*pp = cert->next;
		free_x509cert(cert);
	}
}

/*
 * Insert X.509 CRL into chained list
 */
bool insert_crl(chunk_t blob, chunk_t crl_uri)
{
	x509crl_t *crl = alloc_thing(x509crl_t, "x509crl");

	*crl = empty_x509crl;

	if (parse_x509crl(blob, 0, crl)) {
		x509cert_t *issuer_cert;
		x509crl_t *oldcrl;
		bool valid_sig;
		generalName_t *gn;

		/* add distribution point */
		gn = alloc_thing(generalName_t, "generalName");
		gn->kind = GN_URI;
		gn->name = crl_uri;
		gn->next = crl->distributionPoints;
		crl->distributionPoints = gn;

		lock_authcert_list("insert_crl");
		/* get the issuer cacert */
		issuer_cert = get_authcert(crl->issuer,
					   crl->authKeySerialNumber,
					   crl->authKeyID, AUTH_CA);

		if (issuer_cert == NULL) {
			char distpoint[PATH_MAX];

			distpoint[0] = '\0';
			strncat(distpoint,
				(char *)crl->distributionPoints->name.ptr,
				(crl->distributionPoints->name.len < PATH_MAX ?
				 crl->distributionPoints->name.len : PATH_MAX));

			loglog(RC_LOG_SERIOUS,
			       "CRL rejected: crl issuer cacert not found for (%s)",
			       distpoint);

			free_crl(crl);
			unlock_authcert_list("insert_crl");
			return FALSE;
		}
		DBG(DBG_X509,
		    DBG_log("crl issuer cacert found"));

		/* check the issuer's signature of the crl */
		valid_sig = check_signature(crl->tbsCertList, crl->signature,
					    crl->algorithm, issuer_cert);
		unlock_authcert_list("insert_crl");

		if (!valid_sig) {
			free_crl(crl);
			return FALSE;
		}
		DBG(DBG_X509,
		    DBG_log("valid crl signature"));

		lock_crl_list("insert_crl");
		oldcrl = get_x509crl(crl->issuer, crl->authKeySerialNumber,
				     crl->authKeyID);

		if (oldcrl != NULL) {
			if (crl->thisUpdate > oldcrl->thisUpdate) {
#if defined(LIBCURL) || defined(LDAP_VER)
				/* keep any known CRL distribution points */
				add_distribution_points(
					oldcrl->distributionPoints,
					&crl->distributionPoints);
#endif

				/* now delete the old CRL */
				free_first_crl();
				DBG(DBG_X509,
				    DBG_log("thisUpdate is newer - existing crl deleted"));
			} else {
				unlock_crl_list("insert_crls");
				DBG(DBG_X509,
				    DBG_log("thisUpdate is not newer - existing crl not replaced"));
				free_crl(crl);
				return oldcrl->nextUpdate - time(NULL) > 2 *
				       crl_check_interval;
			}
		}

		/* insert new CRL */
		crl->next = x509crls;
		x509crls = crl;

		unlock_crl_list("insert_crl");

		/* is the fetched crl valid? */
		return crl->nextUpdate - time(NULL) > 2 * crl_check_interval;
	} else {
		loglog(RC_LOG_SERIOUS, "  error in X.509 crl %s",
		       (char *)crl_uri.ptr);
		free_crl(crl);
		return FALSE;
	}
}

/*
 *  Loads CRLs
 */
void load_crls(void)
{
	struct dirent **filelist;
	char buf[PATH_MAX];
	char *save_dir;
	int n;
	const struct lsw_conf_options *oco = lsw_init_options();

	/* change directory to specified path */
	save_dir = getcwd(buf, PATH_MAX);
	if (chdir(oco->crls_dir) == -1) {
		libreswan_log("Could not change to directory '%s': %d %s",
			      oco->crls_dir, errno, strerror(errno));
	} else {
		DBG(DBG_CONTROL,
		    DBG_log("Changing to directory '%s'", oco->crls_dir));
		n = scandir(oco->crls_dir, &filelist, (void *) filter_dotfiles,
			    alphasort);

		if (n > 0) {
			while (n--) {
				chunk_t blob = empty_chunk;
				char *filename = filelist[n]->d_name;

				if (load_coded_file(filename,
#ifdef SINGLE_CONF_DIR
						    FALSE, /* too verbose in a shared dir */
#else
						    TRUE,
#endif
						    "crl", &blob)) {
					chunk_t crl_uri;
					crl_uri.len = 8 +
						      strlen(oco->crls_dir) +
						      strlen(filename);
					crl_uri.ptr = alloc_bytes(
						crl_uri.len + 1, "crl uri");
					/* build CRL file URI */
					snprintf((char *)crl_uri.ptr,
						 crl_uri.len + 1,
						 "file://%s/%s", oco->crls_dir,
						 filename);
					insert_crl(blob, crl_uri);
				}
				free(filelist[n]);
			}
		}
		free(filelist);
	}
	/* restore directory path */
	if (chdir(save_dir) == -1) {
		int e = errno;
		libreswan_log(
			"Changing back to directory '%s' failed - (%d %s)",
			save_dir, e, strerror(e));
	}
}

/*
 * verify if a cert hasn't been revoked by a crl
 */
static bool verify_by_crl(/*const*/ x509cert_t *cert, bool strict,
				    time_t *until)
{
	x509crl_t *crl;
	char ibuf[ASN1_BUF_LEN], cbuf[ASN1_BUF_LEN];

	lock_crl_list("verify_by_crl");
	crl = get_x509crl(cert->issuer, cert->authKeySerialNumber,
			  cert->authKeyID);

	dntoa(ibuf, ASN1_BUF_LEN, cert->issuer);

	if (crl == NULL) {
		unlock_crl_list("verify_by_crl");
		libreswan_log("no crl from issuer \"%s\" found (strict=%s)",
			      ibuf,
			      strict ? "yes" : "no");

#if defined(LIBCURL) || defined(LDAP_VER)
		if (cert->crlDistributionPoints != NULL) {
			add_crl_fetch_request(cert->issuer,
					      cert->crlDistributionPoints);
			wake_fetch_thread("verify_by_crl");
		}
#endif
		if (strict)
			return FALSE;
	} else {
		x509cert_t *issuer_cert;
		bool valid;

		DBG(DBG_X509,
		    DBG_log("issuer crl \"%s\" found", ibuf));

#if defined(LIBCURL) || defined(LDAP_VER)
		add_distribution_points(cert->crlDistributionPoints,
					&crl->distributionPoints);
#endif

		lock_authcert_list("verify_by_crl");

		issuer_cert = get_authcert(crl->issuer,
					   crl->authKeySerialNumber,
					   crl->authKeyID, AUTH_CA);
		dntoa(cbuf, ASN1_BUF_LEN, crl->issuer);
		valid = check_signature(crl->tbsCertList, crl->signature,
					crl->algorithm, issuer_cert);

		unlock_authcert_list("verify_by_crl");

		if (valid) {
			bool revoked_crl, expired_crl;

			DBG(DBG_X509,
			    DBG_log("valid crl signature on \"%s\"", cbuf));

			/* with strict crl policy the public key must have the same
			 * lifetime as the crl
			 */
			if (strict && crl->nextUpdate < *until)
				*until = crl->nextUpdate;

			/* has the certificate been revoked? */
			revoked_crl = x509_check_revocation(crl,
							    cert->serialNumber);

			/* is the crl still valid? */
			expired_crl = time(NULL) > crl->nextUpdate;

			unlock_crl_list("verify_by_crl");

			if (expired_crl) {
				char tbuf[TIMETOA_BUF];
				libreswan_log(
					"crl update for \"%s\" is overdue since %s",
					cbuf,
					timetoa(&crl->nextUpdate, TRUE,
						tbuf, sizeof(tbuf)));

#if defined(LIBCURL) || defined(LDAP_VER)
				/* try to fetch a crl update */
				if (cert->crlDistributionPoints != NULL) {
					add_crl_fetch_request(cert->issuer,
							      cert->crlDistributionPoints);
					wake_fetch_thread("verify_by_crl");
				}
#endif
			} else {
				DBG(DBG_X509,
				    DBG_log("crl is \"%s\" valid", cbuf));
			}

			if (revoked_crl || (strict && expired_crl)) {
				/* remove any cached public keys */
				remove_x509_public_key(cert);
				return FALSE;
			}
		} else {
			unlock_crl_list("verify_by_crl");
			libreswan_log("invalid crl signature on \"%s\"", cbuf);
			if (strict)
				return FALSE;
		}
	}
	return TRUE;
}

#if defined(LIBCURL) || defined(LDAP_VER)
/*
 * check if any crls are about to expire
 */
void check_crls(void)
{
	x509crl_t *crl;
	time_t current_time = time(NULL);

	lock_crl_list("check_crls");
	crl = x509crls;

	while (crl != NULL) {
		time_t time_left = crl->nextUpdate - current_time;
		char buf[ASN1_BUF_LEN];

		DBG(DBG_X509, {
			    dntoa(buf, ASN1_BUF_LEN, crl->issuer);
			    DBG_log("issuer: '%s'", buf);
			    if (crl->authKeyID.ptr != NULL) {
				    datatot(crl->authKeyID.ptr,
					    crl->authKeyID.len, ':',
					    buf, ASN1_BUF_LEN);
				    DBG_log("authkey: %s", buf);
			    }
			    DBG_log("%ld seconds left", time_left);
		    });
		if (time_left < 2 * crl_check_interval)
			add_crl_fetch_request(crl->issuer,
					      crl->distributionPoints);
		crl = crl->next;
	}
	unlock_crl_list("check_crls");
}
#endif

/*
 *  verifies a X.509 certificate
 */
bool verify_x509cert(/*const*/ x509cert_t *cert, bool strict, time_t *until)
{
	int pathlen;

	*until = cert->notAfter;

	if (same_dn(cert->issuer, cert->subject)) {
		libreswan_log(
			"end certificate with identical subject and issuer not accepted");
		return FALSE;
	}

	for (pathlen = 0; pathlen < MAX_CA_PATH_LEN; pathlen++) {
		x509cert_t *issuer_cert;
		char sbuf[ASN1_BUF_LEN];
		char ibuf[ASN1_BUF_LEN];

		err_t ugh = NULL;

		dntoa(sbuf, ASN1_BUF_LEN, cert->subject);
		dntoa(ibuf, ASN1_BUF_LEN, cert->issuer);

		DBG(DBG_X509, {
			    DBG_log("subject: '%s'", sbuf);
			    DBG_log("issuer:  '%s'", ibuf);
			    if (cert->authKeyID.ptr != NULL) {
				    char abuf[ASN1_BUF_LEN];
				    datatot(cert->authKeyID.ptr,
					    cert->authKeyID.len, ':',
					    abuf, ASN1_BUF_LEN);
				    DBG_log("authkey:  %s", abuf);
			    }
		    });

		ugh = check_validity(cert, until);

		if (ugh != NULL) {
			libreswan_log("checking validity of \"%s\": %s", sbuf,
				      ugh);
			return FALSE;
		}

		DBG(DBG_X509,
		    DBG_log("valid certificate for \"%s\"", sbuf));

		lock_authcert_list("verify_x509cert");
		issuer_cert = get_authcert(cert->issuer,
					   cert->authKeySerialNumber,
					   cert->authKeyID, AUTH_CA);

		if (issuer_cert == NULL) {
			libreswan_log("issuer cacert not found");
			unlock_authcert_list("verify_x509cert");
			return FALSE;
		}
		DBG(DBG_X509,
		    DBG_log("issuer cacert \"%s\" found", ibuf));

		if (!check_signature(cert->tbsCertificate, cert->signature,
				     cert->algorithm, issuer_cert)) {
			libreswan_log(
				"invalid certificate signature from \"%s\" on \"%s\"",
				ibuf, sbuf);
			unlock_authcert_list("verify_x509cert");
			return FALSE;
		}
		DBG(DBG_X509,
		    DBG_log("valid certificate signature (%s -> %s)",
			    ibuf, sbuf));
		unlock_authcert_list("verify_x509cert");

		/* check if cert is a self-signed root ca */
		if (pathlen > 0 && same_dn(cert->issuer, cert->subject)) {
			DBG(DBG_CONTROL,
			    DBG_log("reached self-signed root ca"));
			return TRUE;
		} else {
			/* check certificate revocation crls */
#if defined(LIBCURL) || defined(LDAP_VER)
			if (!verify_by_crl(cert, strict, until))
				return FALSE;

#endif
		}

		/* go up one step in the trust chain */
		cert = issuer_cert;
	}

	libreswan_log("maximum ca path length of %d levels exceeded",
		      MAX_CA_PATH_LEN);
	return FALSE;
}

/*
 *  list all X.509 certs in a chained list
 */
static void list_x509cert_chain(const char *caption, x509cert_t* cert,
				u_char auth_flags,
				bool utc)
{
	time_t tnow;

	/* determine the current time */
	time(&tnow);

	whack_log(RC_COMMENT, " ");
	whack_log(RC_COMMENT, "List of X.509 %s Certificates:", caption);

	while (cert != NULL) {
		if (auth_flags == AUTH_NONE ||
		    (auth_flags & cert->authority_flags)) {
			unsigned keysize;
			char keyid[KEYID_BUF];
			char buf[ASN1_BUF_LEN];
			char tbuf[TIMETOA_BUF];

			cert_t c;

			c.ty = CERT_X509_SIGNATURE;
			c.u.x509 = cert;

			whack_log(RC_COMMENT, "%s, count: %d",
				  timetoa(&cert->installed, utc, tbuf,
					  sizeof(tbuf)),
				  cert->count);
			dntoa(buf, ASN1_BUF_LEN, cert->subject);
			whack_log(RC_COMMENT, "       subject: '%s'", buf);
			dntoa(buf, ASN1_BUF_LEN, cert->issuer);
			whack_log(RC_COMMENT, "       issuer:  '%s'", buf);
			datatot(cert->serialNumber.ptr, cert->serialNumber.len,
				':',
				buf, ASN1_BUF_LEN);
			whack_log(RC_COMMENT, "       serial:   %s", buf);
			form_keyid(cert->publicExponent, cert->modulus, keyid,
				   &keysize);
			whack_log(RC_COMMENT,
				  "       pubkey:   %4d RSA Key %s%s",
				  8 * keysize, keyid,
				  has_private_key(c) ? ", has private key" : "");
			whack_log(RC_COMMENT,
				  "       validity: not before %s %s",
				  timetoa(&cert->notBefore, utc, tbuf,
					  sizeof(tbuf)),
				  (cert->notBefore <
				   tnow) ? "ok" : "fatal (not valid yet)");
			whack_log(RC_COMMENT,
				  "                 not after  %s %s",
				  timetoa(&cert->notAfter, utc, tbuf,
					  sizeof(tbuf)),
				  check_expiry(cert->notAfter,
					       CA_CERT_WARNING_INTERVAL,
					       TRUE));
			if (cert->subjectKeyID.ptr != NULL) {
				datatot(cert->subjectKeyID.ptr,
					cert->subjectKeyID.len, ':',
					buf, ASN1_BUF_LEN);
				whack_log(RC_COMMENT, "       subjkey:  %s",
					  buf);
			}
			if (cert->authKeyID.ptr != NULL) {
				datatot(cert->authKeyID.ptr,
					cert->authKeyID.len, ':',
					buf, ASN1_BUF_LEN);
				whack_log(RC_COMMENT, "       authkey:  %s",
					  buf);
			}
			if (cert->authKeySerialNumber.ptr != NULL) {
				datatot(cert->authKeySerialNumber.ptr,
					cert->authKeySerialNumber.len,
					':', buf, ASN1_BUF_LEN);
				whack_log(RC_COMMENT, "       aserial:  %s",
					  buf);
			}
		}
		cert = cert->next;
	}
}

/*
 *  list all X.509 end certificates in a chained list
 */
static void list_x509_end_certs(bool utc)
{
	list_x509cert_chain("End", x509certs, AUTH_NONE, utc);
}

/*
 *  list all X.509 authcerts with given auth flags in a chained list
 */
void list_authcerts(const char *caption, u_char auth_flags, bool utc)
{
	lock_authcert_list("list_authcerts");
	list_x509cert_chain(caption,
			    x509_get_authcerts_chain(), auth_flags, utc);
	unlock_authcert_list("list_authcerts");
}

/*
 *  list all X.509 crls in the chained list
 */
void list_crls(bool utc, bool strict)
{
	x509crl_t *crl;

	lock_crl_list("list_crls");
	crl = x509crls;

	whack_log(RC_COMMENT, " ");
	whack_log(RC_COMMENT, "List of X.509 CRLs:");

	while (crl != NULL) {
		char buf[ASN1_BUF_LEN];
		u_int revoked = 0;
		revokedCert_t *revokedCert = crl->revokedCertificates;
		char tbuf[TIMETOA_BUF];

		/* count number of revoked certificates in CRL */
		while (revokedCert != NULL) {
			revoked++;
			revokedCert = revokedCert->next;
		}

		whack_log(RC_COMMENT, "%s, revoked certs: %d",
			  timetoa(&crl->installed, utc, tbuf,
				  sizeof(tbuf)), revoked);
		dntoa(buf, ASN1_BUF_LEN, crl->issuer);
		whack_log(RC_COMMENT, "       issuer:  '%s'", buf);

#if defined(LIBCURL) || defined(LDAP_VER)
		/* list all distribution points */
		list_distribution_points(crl->distributionPoints);
#endif

		whack_log(RC_COMMENT, "       updates:  this %s",
			  timetoa(&crl->thisUpdate, utc, tbuf, sizeof(tbuf)));
		whack_log(RC_COMMENT, "                 next %s %s",
			  timetoa(&crl->nextUpdate, utc, tbuf, sizeof(tbuf)),
			  check_expiry(crl->nextUpdate, CRL_WARNING_INTERVAL,
				       strict));
		if (crl->authKeyID.ptr != NULL) {
			datatot(crl->authKeyID.ptr, crl->authKeyID.len, ':',
				buf, ASN1_BUF_LEN);
			whack_log(RC_COMMENT, "       authkey:  %s", buf);
		}
		if (crl->authKeySerialNumber.ptr != NULL) {
			datatot(crl->authKeySerialNumber.ptr,
				crl->authKeySerialNumber.len, ':',
				buf, ASN1_BUF_LEN);
			whack_log(RC_COMMENT, "       aserial:  %s", buf);
		}

		crl = crl->next;
	}
	unlock_crl_list("list_crls");
}

/*
 *  list all X.509 end certificates
 */
void list_certs(bool utc)
{
	list_x509_end_certs(utc);
}
