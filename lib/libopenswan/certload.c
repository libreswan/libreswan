/* Certificate support for IKE authentication
 * Copyright (C) 2002-2004 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
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
 * RCSID $Id: certs.c,v 1.8 2004/06/27 20:43:41 mcr Exp $
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "constants.h"
#include "oswlog.h"
#include "oswalloc.h"
#include "oswconf.h"
#include "oswtime.h"
#include "asn1.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "pkcs.h"
#include "pem.h"

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
	int bytes;
	fseek(fd, 0, SEEK_END );
	blob->len = ftell(fd);
	rewind(fd);
	blob->ptr = alloc_bytes(blob->len, type);
	bytes = fread(blob->ptr, 1, blob->len, fd);
	fclose(fd);

	if(verbose) {
	    openswan_log("  loaded %s file '%s' (%d bytes)", type, filename, bytes);
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
	openswan_log("  %s", ugh);
	pfree(blob->ptr);
	*blob = empty_chunk;
    }
    else
    {
	openswan_log("  could not open %s file '%s'", type, filename);
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
    const struct osw_conf_options *oco;

    oco = osw_init_options();

    if (*filename == '/')	/* absolute pathname */
    	strncpy(path, filename, sizeof(path));
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
		openswan_log("  error in PGP private key");
	}
	else
	{
	    if (parse_pkcs1_private_key(blob, key))
		return key;
	    else
		openswan_log("  error in PKCS#1 private key");
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
		    openswan_log("  error in OpenPGP certificate");
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
		    openswan_log("  error in X.509 certificate %s", filename);
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
	FILE *fd;
	int bytes;
	    
	fd = fopen(filename, "r");
	if(fd == NULL) {
	    openswan_log("  can not open certificate-blob filename '%s': %s\n",
			 filename, strerror(errno));
	    return FALSE;
	}
	fseek(fd, 0, SEEK_END );
	cert->forced = TRUE;
	cert->u.blob.len = ftell(fd);
	rewind(fd);
	cert->u.blob.ptr = alloc_bytes(cert->u.blob.len, " cert blob");
	bytes = fread(cert->u.blob.ptr, 1, cert->u.blob.len, fd);
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
    const struct osw_conf_options *oco;
    char path[PATH_MAX];

    oco = osw_init_options();

    if (*filename == '/')	/* absolute pathname */
    	strncpy(path, filename, ASN1_BUF_LEN);
    else			/* relative pathname */
	snprintf(path, ASN1_BUF_LEN, "%s/%s", oco->certs_dir, filename);

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

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
