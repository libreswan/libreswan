/* Support of X.509 certificates and CRLs
 * Copyright (C) 2000 Andreas Hess, Patric Lichtsteiner, Roger Wegmann
 * Copyright (C) 2001 Marco Bertossa, Andreas Schleiss
 * Copyright (C) 2002 Mario Strasser
 * Copyright (C) 2000-2004 Andreas Steffen, Zuercher Hochschule Winterthur
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
 * Modifications to use OCF interface written by
 * Daniel Djamaludin <danield@cyberguard.com>
 * Copyright (C) 2004-2005 Intel Corporation.  All Rights Reserved.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <limits.h>
#include <sys/types.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "sysdep.h"
#include "oswconf.h"
#include "constants.h"
#include "oswlog.h"
#include "oswtime.h"

#include "defs.h"
#include "log.h"
#include "id.h"
#include "asn1.h"
#include "mpzfuncs.h"
#include "oid.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "keys.h"
#include "packet.h"
#include "demux.h"	/* needs packet.h */
#include "connections.h"
#include "state.h"
#include "md2.h"
#include "md5.h"
#include "sha1.h"
#include "whack.h"
#include "fetch.h"
#include "ocsp.h"
#include "pkcs.h"
#include "plutocerts.h"
#include "x509more.h"

#ifdef HAVE_OCF_AND_OPENSSL
#include "ocf_cryptodev.h"
#endif

/* chained lists of X.509 host/user and ca certificates and crls */

static x509cert_t *x509certs   = NULL;
static x509cert_t *x509authcerts = NULL;
static x509crl_t  *x509crls    = NULL;

/*
 * chained list of OpenPGP end certificates
 */
static pgpcert_t *pgpcerts   = NULL;


/* Maximum length of ASN.1 distinquished name */
#define ASN1_BUF_LEN	      512

/*
 *  add a X.509 user/host certificate to the chained list
 */
x509cert_t*
add_x509cert(x509cert_t *cert)
{
    x509cert_t *c = x509certs;

    while (c != NULL)
    {
	if (same_x509cert(c, cert)) /* already in chain, free cert */
	{
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
x509cert_t*
get_x509cert(chunk_t issuer, chunk_t serial, chunk_t keyid, x509cert_t *chain)
{
    x509cert_t *cert = (chain != NULL)? chain->next : x509certs;

    while (cert != NULL)
    {
	if ((keyid.ptr != NULL) ? same_keyid(keyid, cert->authKeyID)
	    : (same_dn(issuer, cert->issuer)
	       && same_serial(serial, cert->authKeySerialNumber)))
	{
	    return cert;
	}
	cert = cert->next;
    }
    return NULL;
}

/*
 *  get a X.509 authority certificate with a given subject or keyid
 */
x509cert_t*
get_authcert(chunk_t subject, chunk_t serial, chunk_t keyid, u_char auth_flags)
{
    x509cert_t *cert = x509authcerts;
    x509cert_t *prev_cert = NULL;

    while (cert != NULL)
    {
	if (cert->authority_flags & auth_flags
	&& ((keyid.ptr != NULL) ? same_keyid(keyid, cert->subjectKeyID)
	    : (same_dn(subject, cert->subject)
	       && same_serial(serial, cert->serialNumber))))
	{
	    if (cert != x509authcerts)
	    {
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
 * Checks if CA a is trusted by CA b
 */
bool
trusted_ca(chunk_t a, chunk_t b, int *pathlen)
{
    bool match = FALSE;
    char abuf[ASN1_BUF_LEN], bbuf[ASN1_BUF_LEN];

    dntoa(abuf, ASN1_BUF_LEN, a);
    dntoa(bbuf, ASN1_BUF_LEN, b);

    DBG(DBG_X509 | DBG_CONTROLMORE
	, DBG_log("  trusted_ca called with a=%s b=%s"
		  , abuf, bbuf));

    /* no CA b specified -> any CA a is accepted */
    if (b.ptr == NULL)
    {
	*pathlen = (a.ptr == NULL)? 0 : MAX_CA_PATH_LEN;
	return TRUE;
    }

    /* no CA a specified -> trust cannot be established */
    if (a.ptr == NULL)
    {
	*pathlen = MAX_CA_PATH_LEN;
	return FALSE;
    }

    *pathlen = 0;

    /* CA a equals CA b -> we have a match */
    if (same_dn(a, b))
	return TRUE;

    /* CA a might be a subordinate CA of b */
    lock_authcert_list("trusted_ca");

    while ((*pathlen)++ < MAX_CA_PATH_LEN)
    {
	x509cert_t *cacert = get_authcert(a, empty_chunk, empty_chunk, AUTH_CA);

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

    DBG(DBG_X509 | DBG_CONTROLMORE
	, DBG_log("  trusted_ca returning with %s", match ? "match" : "failed"));

    return match;
}

/* 
 * does our CA match one of the requested CAs?
 */
bool
match_requested_ca(generalName_t *requested_ca, chunk_t our_ca, int *our_pathlen)
{
    /* if no ca is requested than any ca will match */
    if (requested_ca == NULL)
    {
	*our_pathlen = 0;
	return TRUE;
    }

    *our_pathlen = MAX_CA_PATH_LEN + 1;

    while (requested_ca != NULL)
    {
	int pathlen;

	if (trusted_ca(our_ca, requested_ca->name, &pathlen)
	&& pathlen < *our_pathlen)
	    *our_pathlen = pathlen;
	requested_ca = requested_ca->next;
    }

    return *our_pathlen <= MAX_CA_PATH_LEN;
}


/*
 *  get the X.509 CRL with a given issuer
 */
static x509crl_t*
get_x509crl(chunk_t issuer, chunk_t serial, chunk_t keyid)
{
    x509crl_t *crl = x509crls;
    x509crl_t *prev_crl = NULL;

    while(crl != NULL)
    {
	if ((keyid.ptr != NULL && crl->authKeyID.ptr != NULL)
	? same_keyid(keyid, crl->authKeyID)
	: (same_dn(crl->issuer, issuer) && same_serial(serial, crl->authKeySerialNumber)))
	{
	    if (crl != x509crls)
	    {
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

/*  release of a certificate decreases the count by one
 "  the certificate is freed when the counter reaches zero
 */
void
release_x509cert(x509cert_t *cert)
{
    if (cert != NULL && --cert->count == 0)
    {
	x509cert_t **pp = &x509certs;
	while (*pp != cert)
	    pp = &(*pp)->next;
	lock_certs_and_keys("release_x509cert");
        *pp = cert->next;
	unlock_certs_and_keys("release_x509cert");
	free_x509cert(cert);
    }
}

pgpcert_t*
pluto_add_pgpcert(pgpcert_t *cert)
{
    return add_pgpcert(&pgpcerts, cert);
}

/*  release of a certificate decreases the count by one
 "  the certificate is freed when the counter reaches zero
 */
void
release_cert(cert_t cert)
{
   switch (cert.type)
    {
    case CERT_PGP:
	release_pgpcert(&pgpcerts, cert.u.pgp);
	break;
    case CERT_X509_SIGNATURE:
	release_x509cert(cert.u.x509);
	break;
    default:
	break;
    }
}

/*
 *  free the first authority certificate in the chain
 */
static void
free_first_authcert(void)
{
    x509cert_t *first = x509authcerts;
    x509authcerts = first->next;
    free_x509cert(first);
}

/*
 *  free  all CA certificates
 */
void
free_authcerts(void)
{
    lock_authcert_list("free_authcerts");

    while (x509authcerts != NULL)
        free_first_authcert();

    unlock_authcert_list("free_authcerts");
}

static void
free_first_crl(void)
{
    x509crl_t *crl = x509crls;

    x509crls = crl->next;
    free_crl(crl);
}

void
free_crls(void)
{
    lock_crl_list("free_crls");

    while (x509crls != NULL)
	free_first_crl();

    unlock_crl_list("free_crls");
}

/*
 * add an authority certificate to the chained list
 */
void
add_authcert(x509cert_t *cert, u_char auth_flags)
{
    x509cert_t *old_cert;

    /* set authority flags */
    cert->authority_flags |= auth_flags;

    lock_authcert_list("add_authcert");

    old_cert = get_authcert(cert->subject, cert->serialNumber
	, cert->subjectKeyID, auth_flags);

    if (old_cert != NULL)
    {
	if (same_x509cert(cert, old_cert))
	{
	    /* cert is already present, just add additional authority flags */
	    old_cert->authority_flags |= cert->authority_flags;
	    DBG(DBG_X509 | DBG_PARSING ,
		DBG_log("  authcert is already present and identical")
	    )
	    unlock_authcert_list("add_authcert");
	    
	    free_x509cert(cert);
	    return;
	}
	else
	{
	    /* cert is already present but will be replaced by new cert */
	    free_first_authcert();
	    DBG(DBG_X509 | DBG_PARSING ,
		DBG_log("  existing authcert deleted")
	    )
	}
    }
    
    /* add new authcert to chained list */
    cert->next = x509authcerts;
    x509authcerts = cert;
    share_x509cert(cert);  /* set count to one */
    DBG(DBG_X509 | DBG_PARSING,
	DBG_log("  authcert inserted")
    )
    unlock_authcert_list("add_authcert");
}

/*
 *  Loads authority certificates
 */
void
load_authcerts(const char *type, const char *path, u_char auth_flags)
{
    struct dirent **filelist;
    char buf[ASN1_BUF_LEN];
    char *save_dir;
    int n;

    /* change directory to specified path */
    save_dir = getcwd(buf, ASN1_BUF_LEN);

    if (chdir(path))
    {
	openswan_log("Could not change to directory '%s'", path);
    }
    else
    {
	openswan_log("Changing to directory '%s'", path);
	n = scandir(path, &filelist, file_select, alphasort);

	if (n < 0)
	    openswan_log("  scandir() error");
	else
	{
	    while (n--)
	    {
		cert_t cert;

		if (load_cert(CERT_NONE, filelist[n]->d_name, TRUE,
			      type, &cert))
		    add_authcert(cert.u.x509, auth_flags);

		free(filelist[n]);
	    }
	    free(filelist);
	}
    }
    /* restore directory path */
    chdir(save_dir);
}

/*
 * stores a chained list of end certs and CA certs
 */
void
store_x509certs(x509cert_t **firstcert, bool strict)
{
    x509cert_t *cacerts = NULL;
    x509cert_t **pp = firstcert;

    /* first extract CA certs, discarding root CA certs */

    while (*pp != NULL)
    {
	x509cert_t *cert = *pp;

	if (cert->isCA)
	{
	    *pp = cert->next;
	    
	    /* we don't accept self-signed CA certs */
	    if (same_dn(cert->issuer, cert->subject))
	    {
		openswan_log("self-signed cacert rejected");
		free_x509cert(cert);
	    }
	    else
	    {
                /* insertion into temporary chain of candidate CA certs */
                cert->next = cacerts;
                cacerts = cert;
	    }
	}
	else
	    pp = &cert->next;
    }


    /* now verify the candidate CA certs */
    
    while (cacerts != NULL)
    {
        x509cert_t *cert = cacerts;
       
        cacerts = cacerts->next;

        if (trust_authcert_candidate(cert, cacerts))
        {
           add_authcert(cert, AUTH_CA);
        }
        else
        {
           plog("intermediate cacert rejected");
           free_x509cert(cert);
        }
    }
    
    /* now verify the end certificates */


    pp = firstcert;

    while (*pp != NULL)
    {
	time_t valid_until;
	x509cert_t *cert = *pp;

	if (verify_x509cert(cert, strict, &valid_until))
	{
	    DBG(DBG_X509 | DBG_PARSING,
		DBG_log("public key validated")
	    )
	    add_x509_public_key(cert, valid_until, DAL_SIGNED);
	}
	else
	{
	    openswan_log("X.509 certificate rejected");
	}
	*pp = cert->next;
	free_x509cert(cert);
    }
}

/*
 * Insert X.509 CRL into chained list
 */
bool
insert_crl(chunk_t blob, chunk_t crl_uri)
{
    x509crl_t *crl = alloc_thing(x509crl_t, "x509crl");

    *crl = empty_x509crl;

    if (parse_x509crl(blob, 0, crl))
    {
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
	issuer_cert = get_authcert(crl->issuer, crl->authKeySerialNumber,
	    crl->authKeyID, AUTH_CA);

	if (issuer_cert == NULL)
	{
	    char distpoint[PATH_MAX];

	    distpoint[0] = '\0';
	    strncat(distpoint, (char *)crl->distributionPoints->name.ptr,
		    (crl->distributionPoints->name.len < PATH_MAX ?
		     crl->distributionPoints->name.len : PATH_MAX));
	    
	    openswan_log("crl issuer cacert not found for (%s)",
			 distpoint);;

	    free_crl(crl);
	    unlock_authcert_list("insert_crl");
	    return FALSE;
	}
	DBG(DBG_X509,
	    DBG_log("crl issuer cacert found")
	)

	/* check the issuer's signature of the crl */
	valid_sig = check_signature(crl->tbsCertList, crl->signature
			, crl->algorithm, issuer_cert);
	unlock_authcert_list("insert_crl");

	if (!valid_sig)
	{
	    free_crl(crl);
	    return FALSE;
	}
	DBG(DBG_X509,
	    DBG_log("valid crl signature")
	)

	lock_crl_list("insert_crl");
	oldcrl = get_x509crl(crl->issuer, crl->authKeySerialNumber
	    , crl->authKeyID);

	if (oldcrl != NULL)
	{
	    if (crl->thisUpdate > oldcrl->thisUpdate)
	    {
#ifdef HAVE_THREADS
		/* keep any known CRL distribution points */
		add_distribution_points(oldcrl->distributionPoints
		    , &crl->distributionPoints);
#endif

		/* now delete the old CRL */
		free_first_crl();
		DBG(DBG_X509,
		    DBG_log("thisUpdate is newer - existing crl deleted")
		)
	    }
	    else
	    {
		unlock_crl_list("insert_crls");
		DBG(DBG_X509,
		    DBG_log("thisUpdate is not newer - existing crl not replaced");
		)
		free_crl(crl);
		return oldcrl->nextUpdate - time(NULL) > 2*crl_check_interval;
	    }
	}

	/* insert new CRL */
	crl->next = x509crls;
	x509crls = crl;

	unlock_crl_list("insert_crl");

	/* is the fetched crl valid? */
	return crl->nextUpdate - time(NULL) > 2*crl_check_interval;
    }
    else
    {
	openswan_log("  error in X.509 crl");
	free_crl(crl);
	return FALSE;
    }
}

 /*
 *  Loads CRLs
 */
void
load_crls(void)
{
    struct dirent **filelist;
    char buf[PATH_MAX];
    char *save_dir;
    int n;
    const struct osw_conf_options *oco = osw_init_options(); 

    /* change directory to specified path */
    save_dir = getcwd(buf, PATH_MAX);
    if (chdir(oco->crls_dir))
    {
	openswan_log("Could not change to directory '%s'", oco->crls_dir);
    }
    else
    {
	openswan_log("Changing to directory '%s'", oco->crls_dir);
	n = scandir(oco->crls_dir, &filelist, file_select, alphasort);

	if (n <= 0)
	    openswan_log("  Warning: empty directory");
	else
	{
	    while (n--)
	    {
		bool pgp = FALSE;
		chunk_t blob = empty_chunk;
		char *filename = filelist[n]->d_name;

		if (load_coded_file(filename, NULL, TRUE, "crl", &blob, &pgp))
		{
		    chunk_t crl_uri;
                    crl_uri.len = 8 + strlen(oco->crls_dir) + strlen(filename);
		    crl_uri.ptr = alloc_bytes(crl_uri.len + 1, "crl uri");
		    /* build CRL file URI */
		    snprintf((char *)crl_uri.ptr, crl_uri.len +1, "file://%s/%s", oco->crls_dir, filename);
		    insert_crl(blob, crl_uri);
		}
		free(filelist[n]);
	    }
	    free(filelist);
	}
    }
    /* restore directory path */
    chdir(save_dir);
}

/* verify the validity of a certificate by
 * checking the notBefore and notAfter dates
 */
err_t
check_validity(const x509cert_t *cert, time_t *until)
{
    time_t current_time;
    char curtime[TIMETOA_BUF];

    time(&current_time);
    timetoa(&current_time, TRUE, curtime, sizeof(curtime));

    DBG(DBG_X509,
	char tbuf[TIMETOA_BUF];
	
	DBG_log("  not before  : %s"
		, timetoa(&cert->notBefore, TRUE, tbuf, sizeof(tbuf)));
	DBG_log("  current time: %s", curtime);
	DBG_log("  not after   : %s"
		, timetoa(&cert->notAfter, TRUE, tbuf, sizeof(tbuf)));
	);

    if (cert->notAfter < *until) *until = cert->notAfter;

    if (current_time < cert->notBefore) {
	char tbuf[TIMETOA_BUF];

	return builddiag("X.509 certificate is not valid until %s (it is now=%s)"
			 , timetoa(&cert->notBefore, TRUE, tbuf, sizeof(tbuf))
			 , curtime);
    }
    
    if (current_time > cert->notAfter) {
	char tbuf[TIMETOA_BUF];

	DBG_log("  aftercheck : %ld > %ld", (unsigned long)current_time
		, (unsigned long)cert->notAfter);
	return builddiag("X.509 certificate expired at %s (it is now %s)"
			 , timetoa(&cert->notAfter, TRUE, tbuf, sizeof(tbuf))
			 , curtime);
    }

    else
	return NULL;
}

/*  Checks if the current certificate is revoked. It goes through the
 *  list of revoked certificates of the corresponding crl. If the
 *  certificate is found in the list, TRUE is returned
 */
static bool
check_revocation(const x509crl_t *crl, chunk_t serial)
{
    revokedCert_t *revokedCert = crl->revokedCertificates;
    char tbuf[TIMETOA_BUF];

    DBG(DBG_X509,
	DBG_dump_chunk("serial number:", serial)
    )

    while(revokedCert != NULL)
    {
	/* compare serial numbers */
	if (revokedCert->userCertificate.len == serial.len &&
	    memcmp(revokedCert->userCertificate.ptr, serial.ptr, serial.len) == 0)
	{
	    openswan_log("certificate was revoked on %s",
			 timetoa(&revokedCert->revocationDate, TRUE, tbuf, sizeof(tbuf)));
	    return TRUE;
	}
	revokedCert = revokedCert->next;
    }
    DBG(DBG_X509,
	DBG_log("certificate not revoked")
    )
    return FALSE;
}


/*
 * check if any crls are about to expire
 */
void
check_crls(void)
{
#ifdef HAVE_THREADS
    x509crl_t *crl;
    time_t current_time = time(NULL);

    lock_crl_list("check_crls");
    crl = x509crls;

    while (crl != NULL)
    {
	time_t time_left = crl->nextUpdate - current_time;
	u_char buf[ASN1_BUF_LEN];

	DBG(DBG_X509,
	    dntoa(buf, ASN1_BUF_LEN, crl->issuer);
	    DBG_log("issuer: '%s'",buf);
	    if (crl->authKeyID.ptr != NULL)
	    {
		datatot(crl->authKeyID.ptr, crl->authKeyID.len, ':'
		    , buf, ASN1_BUF_LEN);
		DBG_log("authkey: %s", buf);
	    }
	    DBG_log("%ld seconds left", time_left)
	)
	if (time_left < 2*crl_check_interval)
	    add_crl_fetch_request(crl->issuer, crl->distributionPoints);
	crl = crl->next;
    }
    unlock_crl_list("check_crls");
#endif
}

/*
 * verify if a cert hasn't been revoked by a crl
 */
static bool
verify_by_crl(/*const*/ x509cert_t *cert, bool strict, time_t *until)
{
    x509crl_t *crl;
    char ibuf[ASN1_BUF_LEN], cbuf[ASN1_BUF_LEN];

    lock_crl_list("verify_by_crl");
    crl = get_x509crl(cert->issuer, cert->authKeySerialNumber, cert->authKeyID);

    dntoa(ibuf, ASN1_BUF_LEN, cert->issuer);

    if (crl == NULL)
    {
	unlock_crl_list("verify_by_crl");
	openswan_log("no crl from issuer \"%s\" found (strict=%s)", ibuf
		     , strict ? "yes" : "no");

#ifdef HAVE_THREADS
	if (cert->crlDistributionPoints != NULL)
	{
	    add_crl_fetch_request(cert->issuer, cert->crlDistributionPoints);
	    wake_fetch_thread("verify_by_crl");
	}
#endif
	if (strict)
	    return FALSE;
    }
    else
    {
	x509cert_t *issuer_cert;
	bool valid;

	DBG(DBG_X509,
	    DBG_log("issuer crl \"%s\" found", ibuf)
	)
     
#ifdef HAVE_THREADS
	add_distribution_points(cert->crlDistributionPoints
		, &crl->distributionPoints);
#endif

	lock_authcert_list("verify_by_crl");

	issuer_cert = get_authcert(crl->issuer, crl->authKeySerialNumber
				   , crl->authKeyID, AUTH_CA);
	dntoa(cbuf, ASN1_BUF_LEN, crl->issuer);
	valid = check_signature(crl->tbsCertList, crl->signature
				, crl->algorithm, issuer_cert);
	
	unlock_authcert_list("verify_by_crl");

	if (valid)
	{
	    bool revoked_crl, expired_crl;
     
	    DBG(DBG_X509,
		DBG_log("valid crl signature on \"%s\"", cbuf)
	    )

	    /* with strict crl policy the public key must have the same
	     * lifetime as the crl
	     */
	    if (strict && crl->nextUpdate < *until)
	    	*until = crl->nextUpdate;

	    /* has the certificate been revoked? */
	    revoked_crl = check_revocation(crl, cert->serialNumber);
     
	    /* is the crl still valid? */
	    expired_crl = time(NULL) > crl->nextUpdate;

	    unlock_crl_list("verify_by_crl");

	    if (expired_crl)
	    {
	        char tbuf[TIMETOA_BUF];
		openswan_log("crl update for \"%s\" is overdue since %s"
			     , cbuf
			     , timetoa(&crl->nextUpdate, TRUE, tbuf, sizeof(tbuf)));

#ifdef HAVE_THREADS
		/* try to fetch a crl update */
		if (cert->crlDistributionPoints != NULL)
		{
		    add_crl_fetch_request(cert->issuer
			, cert->crlDistributionPoints);
		    wake_fetch_thread("verify_by_crl");
		}
#endif
	    }
	    else
	    {
		DBG(DBG_X509,
		    DBG_log("crl is \"%s\" valid", cbuf)
		)
	    }

	    if (revoked_crl || (strict && expired_crl))
	    {
		/* remove any cached public keys */
		remove_x509_public_key(cert);
		return FALSE;
	    }
	}
	else
	{
	    unlock_crl_list("verify_by_crl");
	    openswan_log("invalid crl signature on \"%s\"", cbuf);
	    if (strict)
		return FALSE;
	}
    }
    return TRUE;
}

/*
 *  verifies a X.509 certificate
 */
bool
verify_x509cert(/*const*/ x509cert_t *cert, bool strict, time_t *until)
{
    int pathlen;

    *until = cert->notAfter;

    if (same_dn(cert->issuer, cert->subject))
    {
	openswan_log("end certificate with identical subject and issuer not accepted");
	return FALSE;
    }


    for (pathlen = 0; pathlen < MAX_CA_PATH_LEN; pathlen++)
    {
	x509cert_t *issuer_cert;
	char sbuf[ASN1_BUF_LEN];
	char ibuf[ASN1_BUF_LEN];
	char abuf[ASN1_BUF_LEN];

	err_t ugh = NULL;

	dntoa(sbuf, ASN1_BUF_LEN, cert->subject);
	dntoa(ibuf, ASN1_BUF_LEN, cert->issuer);

	DBG(DBG_X509,
	    DBG_log("subject: '%s'", sbuf);
	    DBG_log("issuer:  '%s'", ibuf);
	    if (cert->authKeyID.ptr != NULL)
	    {
		datatot(cert->authKeyID.ptr, cert->authKeyID.len, ':'
			, abuf, ASN1_BUF_LEN);
		DBG_log("authkey:  %s", abuf);
	    }
	)

	ugh = check_validity(cert, until);

	if (ugh != NULL)
	{
	    openswan_log("checking validity of \"%s\": %s", sbuf, ugh);
	    return FALSE;
	}

	DBG(DBG_X509,
	    DBG_log("valid certificate for \"%s\"", sbuf)
	)

	lock_authcert_list("verify_x509cert");
	issuer_cert = get_authcert(cert->issuer, cert->authKeySerialNumber
	    , cert->authKeyID, AUTH_CA);

	if (issuer_cert == NULL)
	{
	    openswan_log("issuer cacert not found");
	    unlock_authcert_list("verify_x509cert");
	    return FALSE;
	}
	DBG(DBG_X509,
	    DBG_log("issuer cacert \"%s\" found", ibuf)
	)

	if (!check_signature(cert->tbsCertificate, cert->signature,
			     cert->algorithm, issuer_cert))
	{
	    openswan_log("invalid certificate signature from \"%s\" on \"%s\""
			 , ibuf, sbuf);
	    unlock_authcert_list("verify_x509cert");
	    return FALSE;
	}
	DBG(DBG_X509,
	    DBG_log("valid certificate signature (%s -> %s)"
		    , ibuf, sbuf);
	)
	unlock_authcert_list("verify_x509cert");


	/* check if cert is a self-signed root ca */
	if (pathlen > 0 && same_dn(cert->issuer, cert->subject))
	{
	    DBG(DBG_CONTROL,
		DBG_log("reached self-signed root ca")
	    )
	    return TRUE;
	}
	else
	{
	    /* check certificate revocation using ocsp or crls */
	    if (!verify_by_ocsp(cert, strict, until)
	    &&  !verify_by_crl (cert, strict, until))
		return FALSE;
	}
        
	/* go up one step in the trust chain */
	cert = issuer_cert;
    }

    openswan_log("maximum ca path length of %d levels exceeded", MAX_CA_PATH_LEN);
    return FALSE;
}

/*
 *  list all X.509 certs in a chained list
 */
static void
list_x509cert_chain(const char *caption, x509cert_t* cert, u_char auth_flags
 , bool utc)
{
    bool first = TRUE;
    time_t now;

    /* determine the current time */
    time(&now);

    while (cert != NULL)
    {
	if (auth_flags == AUTH_NONE || (auth_flags & cert->authority_flags))
	{
	    unsigned keysize;
	    char keyid[KEYID_BUF];
	    char buf[ASN1_BUF_LEN];
	    char tbuf[TIMETOA_BUF];
	    
	    cert_t c;

	    c.type = CERT_X509_SIGNATURE;
	    c.u.x509 = cert;

	    if (first)
	    {
		whack_log(RC_COMMENT, " ");
		whack_log(RC_COMMENT, "List of X.509 %s Certificates:", caption);
		whack_log(RC_COMMENT, " ");
		first = FALSE;
	    }

	    whack_log(RC_COMMENT, "%s, count: %d", timetoa(&cert->installed, utc, tbuf, sizeof(tbuf)),
		      cert->count);
	    dntoa(buf, ASN1_BUF_LEN, cert->subject);
	    whack_log(RC_COMMENT, "       subject: '%s'", buf);
	    dntoa(buf, ASN1_BUF_LEN, cert->issuer);
	    whack_log(RC_COMMENT, "       issuer:  '%s'", buf);
	    datatot(cert->serialNumber.ptr, cert->serialNumber.len, ':'
		, buf, ASN1_BUF_LEN);
	    whack_log(RC_COMMENT, "       serial:   %s", buf);
	    form_keyid(cert->publicExponent, cert->modulus, keyid, &keysize);
	    whack_log(RC_COMMENT, "       pubkey:   %4d RSA Key %s%s"
		, 8*keysize, keyid
		, cert->smartcard ? ", on smartcard" :
		(has_private_key(c)? ", has private key" : ""));
	    whack_log(RC_COMMENT, "       validity: not before %s %s",
		timetoa(&cert->notBefore, utc, tbuf, sizeof(tbuf)),
		(cert->notBefore < now)?"ok":"fatal (not valid yet)");
	    whack_log(RC_COMMENT, "                 not after  %s %s",
		timetoa(&cert->notAfter, utc, tbuf, sizeof(tbuf)),
		check_expiry(cert->notAfter, CA_CERT_WARNING_INTERVAL, TRUE));
	    if (cert->subjectKeyID.ptr != NULL)
	    {
		datatot(cert->subjectKeyID.ptr, cert->subjectKeyID.len, ':'
		    , buf, ASN1_BUF_LEN);
		whack_log(RC_COMMENT, "       subjkey:  %s", buf);
	    }
	    if (cert->authKeyID.ptr != NULL)
	    {
		datatot(cert->authKeyID.ptr, cert->authKeyID.len, ':'
		    , buf, ASN1_BUF_LEN);
		whack_log(RC_COMMENT, "       authkey:  %s", buf);
	    }
	    if (cert->authKeySerialNumber.ptr != NULL)
	    {
		datatot(cert->authKeySerialNumber.ptr, cert->authKeySerialNumber.len
		    , ':', buf, ASN1_BUF_LEN);
		whack_log(RC_COMMENT, "       aserial:  %s", buf);
	    }
	}
	cert = cert->next;
    }
}

/*
 *  list all X.509 end certificates in a chained list
 */
void
list_x509_end_certs(bool utc)
{
    list_x509cert_chain("End", x509certs, AUTH_NONE, utc);
}

/*
 *  list all X.509 authcerts with given auth flags in a chained list
 */
void
list_authcerts(const char *caption, u_char auth_flags, bool utc)
{
    lock_authcert_list("list_authcerts");
    list_x509cert_chain(caption, x509authcerts, auth_flags, utc);
    unlock_authcert_list("list_authcerts");
}

/*
 *  list all X.509 crls in the chained list
 */
void
list_crls(bool utc, bool strict)
{
    x509crl_t *crl;

    lock_crl_list("list_crls");
    crl = x509crls;

    if (crl != NULL)
    {
	whack_log(RC_COMMENT, " ");
	whack_log(RC_COMMENT, "List of X.509 CRLs:");
	whack_log(RC_COMMENT, " ");
    }

    while (crl != NULL)
    {
	char buf[ASN1_BUF_LEN];
	u_int revoked = 0;
	revokedCert_t *revokedCert = crl->revokedCertificates;
	char tbuf[TIMETOA_BUF];

	/* count number of revoked certificates in CRL */
	while (revokedCert != NULL)
	{
	    revoked++;
	    revokedCert = revokedCert->next;
        }

	whack_log(RC_COMMENT, "%s, revoked certs: %d",
		  timetoa(&crl->installed, utc, tbuf, sizeof(tbuf)), revoked);
	dntoa(buf, ASN1_BUF_LEN, crl->issuer);
	whack_log(RC_COMMENT, "       issuer:  '%s'", buf);

#ifdef HAVE_THREADS
	/* list all distribution points */
	list_distribution_points(crl->distributionPoints);
#endif

	whack_log(RC_COMMENT, "       updates:  this %s",
		  timetoa(&crl->thisUpdate, utc, tbuf, sizeof(tbuf)));
	whack_log(RC_COMMENT, "                 next %s %s"
		  , timetoa(&crl->nextUpdate, utc, tbuf, sizeof(tbuf))
		  , check_expiry(crl->nextUpdate, CRL_WARNING_INTERVAL, strict));
	if (crl->authKeyID.ptr != NULL)
	{
	    datatot(crl->authKeyID.ptr, crl->authKeyID.len, ':'
		, buf, ASN1_BUF_LEN);
	    whack_log(RC_COMMENT, "       authkey:  %s", buf);
	}
	if (crl->authKeySerialNumber.ptr != NULL)
	{
	    datatot(crl->authKeySerialNumber.ptr, crl->authKeySerialNumber.len, ':'
		, buf, ASN1_BUF_LEN);
	    whack_log(RC_COMMENT, "       aserial:  %s", buf);
	}

	crl = crl->next;
    }
    unlock_crl_list("list_crls");
}

/*
 * get a cacert with a given subject or keyid from an alternative list
 */
static const x509cert_t*
get_alt_cacert(chunk_t subject, chunk_t serial, chunk_t keyid
    , const x509cert_t *cert)
{
    while (cert != NULL)
    {
       if ((keyid.ptr != NULL) ? same_keyid(keyid, cert->subjectKeyID)
           : (same_dn(subject, cert->subject)
              && same_serial(serial, cert->serialNumber)))
       {
           return cert;
       }
       cert = cert->next;
    }
    return NULL;
}

/* extract id and public key from OpenPGP certificate and
 * insert it into a pubkeyrec
 */
void
add_pgp_public_key(pgpcert_t *cert , time_t until
		   , enum dns_auth_level dns_auth_level)
{
    struct pubkey *pk;
    cert_t c;

    c.type = CERT_PGP;
    c.u.pgp = cert;

    /* we support RSA only */
    if (cert->pubkeyAlg != PUBKEY_ALG_RSA)
    {
	openswan_log("  RSA public keys supported only");
	return;
    }

    pk = allocate_RSA_public_key(c);
    pk->id.kind = ID_KEY_ID;
    pk->id.name.ptr = (unsigned char *)cert->fingerprint;
    pk->id.name.len = PGP_FINGERPRINT_SIZE;
    pk->dns_auth_level = dns_auth_level;
    pk->until_time = until;
    delete_public_keys(&pluto_pubkeys, &pk->id, pk->alg);
    install_public_key(pk, &pluto_pubkeys);
}

/* establish trust into a candidate authcert by going up the trust chain.
 * validity and revocation status are not checked.
 */
bool
trust_authcert_candidate(const x509cert_t *cert, const x509cert_t *alt_chain)
{
    int pathlen;

    lock_authcert_list("trust_authcert_candidate");

    for (pathlen = 0; pathlen < MAX_CA_PATH_LEN; pathlen++)
    {
       const x509cert_t *authcert = NULL;
       char buf[ASN1_BUF_LEN];

       DBG(DBG_CONTROL,
           dntoa(buf, ASN1_BUF_LEN, cert->subject);
           DBG_log("subject: '%s'",buf);
           dntoa(buf, ASN1_BUF_LEN, cert->issuer);
           DBG_log("issuer:  '%s'",buf);
           if (cert->authKeyID.ptr != NULL)
           {
               datatot(cert->authKeyID.ptr, cert->authKeyID.len, ':'
                   , buf, ASN1_BUF_LEN);
               DBG_log("authkey:  %s", buf);
           }
	   );

       /* search in alternative chain first */
       authcert = get_alt_cacert(cert->issuer, cert->authKeySerialNumber
           , cert->authKeyID, alt_chain);

       if (authcert != NULL)
       {
           DBG(DBG_CONTROL,
               DBG_log("issuer cacert found in alternative chain")
           )
       }
       else
       {
           /* search in trusted chain */
           authcert = get_authcert(cert->issuer, cert->authKeySerialNumber
               , cert->authKeyID, AUTH_CA);

           if (authcert != NULL)
           {
               DBG(DBG_CONTROL,
                   DBG_log("issuer cacert found")
               )
           }
           else
           {
               plog("issuer cacert not found");
               unlock_authcert_list("trust_authcert_candidate");
               return FALSE;
           }
       }

       if (!check_signature(cert->tbsCertificate, cert->signature,
                            cert->algorithm, authcert))
       {
           plog("invalid certificate signature");
           unlock_authcert_list("trust_authcert_candidate");
           return FALSE;
       }
       DBG(DBG_CONTROL,
           DBG_log("valid certificate signature")
       )

       /* check if cert is a self-signed root ca */
       if (pathlen > 0 && same_dn(cert->issuer, cert->subject))
       {
           DBG(DBG_CONTROL,
               DBG_log("reached self-signed root ca")
           )
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
 *  list all PGP end certificates in a chained list
 */
void
list_pgp_end_certs(bool utc)
{
   pgpcert_t *cert = pgpcerts;
   time_t now;

    /* determine the current time */
    time(&now);

    if (cert != NULL)
    {
	whack_log(RC_COMMENT, " ");
	whack_log(RC_COMMENT, "List of PGP End certificates:");
	whack_log(RC_COMMENT, " ");
    }

    while (cert != NULL)
    {
	unsigned keysize;
	char buf[ASN1_BUF_LEN];
	char tbuf[TIMETOA_BUF];
	cert_t c;

	c.type = CERT_PGP;
	c.u.pgp = cert;

	whack_log(RC_COMMENT, "%s, count: %d"
		  , timetoa(&cert->installed, utc, tbuf, sizeof(tbuf))
		  , cert->count);
	datatot((unsigned char *)cert->fingerprint, PGP_FINGERPRINT_SIZE, 'x', buf, ASN1_BUF_LEN);
	whack_log(RC_COMMENT, "       fingerprint:  %s", buf);
	form_keyid(cert->publicExponent, cert->modulus, buf, &keysize);
	whack_log(RC_COMMENT, "       pubkey:   %4d RSA Key %s%s", 8*keysize, buf,
		(has_private_key(c))? ", has private key" : "");
	whack_log(RC_COMMENT, "       created:  %s"
		  , timetoa(&cert->created, utc, tbuf, sizeof(tbuf)));
	whack_log(RC_COMMENT, "       until:    %s %s"
		  , timetoa(&cert->until, utc, tbuf, sizeof(tbuf)),
		check_expiry(cert->until, CA_CERT_WARNING_INTERVAL, TRUE));
	cert = cert->next;
    }
}

/*
 *  list all X.509 and OpenPGP end certificates
 */
void
list_certs(bool utc)
{
    list_x509_end_certs(utc);
    list_pgp_end_certs(utc);
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
