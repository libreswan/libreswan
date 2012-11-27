/* Certificate support for IKE authentication
 * Copyright (C) 2002-2004 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2005-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
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
#include <errno.h>
#include <limits.h>

#include <libreswan.h>
#include <libreswan/ipsec_policy.h>

#include "constants.h"
#include "lswlog.h"
#include "lswalloc.h"
#include "lswconf.h"
#include "lswtime.h"
#include "asn1.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "pkcs.h"
#include "pem.h"

#include <nss.h>
#include <pk11pub.h>
#include <cert.h>

#define ASN1_BUF_LEN		256

/*
 * used for initialization of private keys
 */
const rsa_privkey_t empty_rsa_privkey = {
    { NULL, 0 }, /* keyobject */
    {
	{ NULL, 0 },{ NULL, 0 },{ NULL, 0 },{ NULL, 0 },
	{ NULL, 0 },{ NULL, 0 },{ NULL, 0 },{ NULL, 0 }
    } 		 /* field[0..7] */
};

/*
 * used for initializatin of certs
 */
const cert_t empty_cert = {FALSE, CERT_NONE, {NULL}};

/*
 * extracts the certificate to be sent to the peer
 */
chunk_t
get_mycert(cert_t cert)
{
    switch (cert.type)
    {
    case CERT_PGP:
	return cert.u.pgp->certificate;
    case CERT_X509_SIGNATURE:
	return cert.u.x509->certificate;
    default:
	return empty_chunk;
    }
}

/* load a coded key or certificate file with autodetection
 * of binary DER or base64 PEM ASN.1 formats and armored PGP format
 */
bool
load_coded_file(const char *filename, prompt_pass_t *pass,
		int verbose,
		const char *type, chunk_t *blob, bool *pgp)
{
    err_t ugh = NULL;
    FILE *fd;

    fd = fopen(filename, "r");
    if (fd)
    {
	size_t bytes;
	fseek(fd, 0, SEEK_END );
	blob->len = ftell(fd);

	if (blob->len <= 0) {
	   if (verbose)
		libreswan_log("  discarded %s file '%s', bad size %zu bytes",
			type, filename, blob->len);
	   fclose(fd);
	   return FALSE;
	}

	rewind(fd);
	blob->ptr = alloc_bytes(blob->len, type);
	bytes = fread(blob->ptr, 1, blob->len, fd);
	if(bytes != blob->len) {
	        libreswan_log("  WARNING: could not fully read certificate-blob filename '%s'\n", filename);
	}
	fclose(fd);

	if(verbose) {
	    libreswan_log("  loaded %s file '%s' (%zu bytes)", type, filename, bytes);
	}

	*pgp = FALSE;

	/* try DER format */
	if (is_asn1(*blob))
	{
	    DBG(DBG_PARSING,
		DBG_log("  file coded in DER format");
	    )
	    return TRUE;
	}

	/* try PEM format */
	ugh = pemtobin(blob, pass, filename, pgp);

	if (ugh == NULL)
	{
	    if (*pgp)
	    {
                DBG(DBG_PARSING,
                    DBG_log("  file coded in armored PGP format");
                )
                return TRUE;
	    }
	    if (is_asn1(*blob))
	    {
		DBG(DBG_PARSING,
		    DBG_log("  file coded in PEM format");
		)
		return TRUE;
	    }
	    ugh = "file coded in unknown format, discarded";
	}

	/* a conversion error has occured */
	if (verbose)
		libreswan_log("  %s", ugh);
	pfree(blob->ptr);
	*blob = empty_chunk;
    }
    else
    {
	libreswan_log("  could not open %s file '%s'", type, filename);
    }
    return FALSE;
}

/*
 *  Loads a PKCS#1 or PGP private RSA key file
 */
rsa_privkey_t*
load_rsa_private_key(const char* filename, int verbose, prompt_pass_t *pass)
{
    bool pgp = FALSE;
    chunk_t blob = empty_chunk;
    char path[PATH_MAX];
    const struct lsw_conf_options *oco;

    oco = lsw_init_options();

    if (*filename == '/') {
	/* absolute pathname --- might be hacked by local rootdir */
	snprintf(path, sizeof(path), "%s%s", oco->rootdir, filename);
    }
    else			/* relative pathname */
	snprintf(path, sizeof(path), "%s/%s", oco->private_dir, filename);

    if (load_coded_file(path, pass, verbose, "private key", &blob, &pgp))
    {
	rsa_privkey_t *key = alloc_thing(rsa_privkey_t, "rsa_privkey");
	*key = empty_rsa_privkey;
	if (pgp)
	{
	    if (parse_pgp(blob, NULL, key))
		return key;
	    else
		libreswan_log("  error in PGP private key");
	}
	else
	{
	    if (parse_pkcs1_private_key(blob, key))
		return key;
	    else
		libreswan_log("  error in PKCS#1 private key");
	}
	pfree(blob.ptr);
	pfree(key);
    }
    return NULL;
}

/*
 *  Loads a X.509 or OpenPGP certificate
 */
bool
load_cert(bool forcedtype, const char *filename,
	  int verbose,
	  const char *label, cert_t *cert)
{
    bool pgp = FALSE;
    chunk_t blob = empty_chunk;

    /* initialize cert struct */
    cert->forced = forcedtype;
    cert->u.x509 = NULL;

    if(!forcedtype) {
	if (load_coded_file(filename, NULL, verbose, label, &blob, &pgp)) {
	    if (pgp) {
		pgpcert_t *pgpcert = alloc_thing(pgpcert_t, "pgpcert");
		*pgpcert = empty_pgpcert;
		if (parse_pgp(blob, pgpcert, NULL)) {
		    cert->forced = FALSE;
		    cert->type = CERT_PGP;
		    cert->u.pgp = pgpcert;
		    return TRUE;
		} else {
		    libreswan_log("  error in OpenPGP certificate");
		    free_pgpcert(pgpcert);
		    return FALSE;
		}
		
	    } else {

		x509cert_t *x509cert = alloc_thing(x509cert_t, "x509cert");
		*x509cert = empty_x509cert;
		
		if (parse_x509cert(blob, 0, x509cert)) {
		    cert->forced = FALSE;
		    cert->type = CERT_X509_SIGNATURE;
		    cert->u.x509 = x509cert;
		    return TRUE;
		    
		} else {
		    libreswan_log("  error in X.509 certificate %s", filename);
		    free_x509cert(x509cert);
		    return FALSE;
		}
	    }
	}
    } else {
	/*
	 * if the certificate type was forced, then load the certificate
	 * as a blob, don't interpret or validate it at all
	 *
	 */
	size_t bytes;
	FILE *fd = fopen(filename, "r");
	    
	if(fd == NULL) {
	    libreswan_log("  can not open certificate-blob filename '%s': %s\n",
			 filename, strerror(errno));
	    return FALSE;
	}
	fseek(fd, 0, SEEK_END );
	cert->forced = TRUE;
	cert->u.blob.len = ftell(fd);
	rewind(fd);
	cert->u.blob.ptr = alloc_bytes(cert->u.blob.len, " cert blob");
	bytes = fread(cert->u.blob.ptr, 1, cert->u.blob.len, fd);
	if(bytes != cert->u.blob.len)	{
		libreswan_log("  WARNING: could not fully read certificate-blob filename '%s'\n", filename);
	}
	fclose(fd);
    }
    return FALSE;
}

/*
 *  Loads a host certificate
 */
bool
load_host_cert(enum ipsec_cert_type certtype, const char *filename,
	       cert_t *cert, int verbose)
{
    const struct lsw_conf_options *oco;
    char path[PATH_MAX];

    oco = lsw_init_options();

    if (*filename == '/')	/* absolute pathname */
    	strncpy(path, filename, ASN1_BUF_LEN);
    else if(oco->certs_dir == NULL) /* pathname relative to cwd */
	snprintf(path, ASN1_BUF_LEN, "./%s", filename);
    else 			/* pathname relative to rootdir */
	snprintf(path, ASN1_BUF_LEN, "%s%s/%s", oco->rootdir
		 , oco->certs_dir, filename);

    return load_cert(certtype, path, verbose, "host cert", cert);
}

/*
 * establish equality of two certificates
 */
bool
same_cert(const cert_t *a, const cert_t *b)
{
    return a->type == b->type && a->u.x509 == b->u.x509;
}

/*  for each link pointing to the certificate
 "  increase the count by one
 */
void
share_cert(cert_t cert)
{
    switch (cert.type)
    {
    case CERT_PGP:
	share_pgpcert(cert.u.pgp);
	break;
    case CERT_X509_SIGNATURE:
	share_x509cert(cert.u.x509);
	break;
    default:
	break;
    }
}

bool
load_cert_from_nss(bool forcedtype, const char *nssHostCertNickName, int verbose,
                  const char *label, cert_t *cert)
{
    chunk_t blob = empty_chunk;
    CERTCertificate *nssCert;

    /* initialize cert struct */
    cert->forced = forcedtype;
    cert->u.x509 = NULL;

    nssCert=CERT_FindCertByNicknameOrEmailAddr(CERT_GetDefaultCertDB(), nssHostCertNickName);

    if(nssCert==NULL) {
	nssCert=PK11_FindCertFromNickname(nssHostCertNickName, lsw_return_nss_password_file_info());
    }

    if(nssCert == NULL) {
	libreswan_log("    could not open %s with nick name '%s' in NSS DB", label, nssHostCertNickName);
	return FALSE;
    }
    else {
	DBG(DBG_CRYPT, DBG_log("Found pointer to cert %s now giving it to further processing",nssHostCertNickName));
    }

    if(forcedtype) {
	cert->u.blob.len=nssCert->derCert.len;
	cert->u.blob.ptr = alloc_bytes(cert->u.blob.len, label);
	memcpy(cert->u.blob.ptr,nssCert->derCert.data,cert->u.blob.len);
	/*I think it should return TRUE, however as in load_cert, FALSE is returned when forcedtype is TRUE so returning FALSE*/
	return FALSE;
    }

    blob.len=nssCert->derCert.len;
    blob.ptr = alloc_bytes(blob.len, label);
    memcpy(blob.ptr,nssCert->derCert.data,blob.len);

    if (is_asn1(blob)) {
	DBG(DBG_PARSING, DBG_log("file coded in DER format"));

	x509cert_t *x509cert = alloc_thing(x509cert_t, "x509cert");
	*x509cert = empty_x509cert;

	if (parse_x509cert(blob, 0, x509cert)) {
		cert->forced = FALSE;
		cert->type = CERT_X509_SIGNATURE;
		cert->u.x509 = x509cert;
		return TRUE;
	} else {
		libreswan_log("  error in X.509 certificate");
		pfree(blob.ptr);
		free_x509cert(x509cert);
		return FALSE;
	}
    }

    if(verbose)
	libreswan_log("  cert read from NSS db is not in DER format");
    pfree(blob.ptr);
    return FALSE;
}

void
load_authcerts_from_nss(const char *type, u_char auth_flags) 
{
    CERTCertList *list = NULL;
    CERTCertListNode *node;

    list = PK11_ListCerts(PK11CertListCA,  lsw_return_nss_password_file_info());

    if(list) {
		for (node = CERT_LIST_HEAD(list); !CERT_LIST_END(node, list);
			node = CERT_LIST_NEXT(node)) {

			cert_t cert;
			if(load_cert_from_nss(CERT_NONE, node->cert->nickname,
#ifdef SINGLE_CONF_DIR
				FALSE, /* too verbose in single conf dir */
#else
				TRUE,
#endif
				type, &cert)) {
			     add_authcert(cert.u.x509, auth_flags);
				}
			}
	     }
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
