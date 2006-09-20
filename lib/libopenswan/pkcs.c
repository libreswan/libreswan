/* Support of PKCS#1 and PKCS#7 data structures
 * Copyright (C) 2002-2004 Andreas Steffen, Zuercher Hochschule Winterthur
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
 * RCSID $Id: pkcs.c,v 1.5 2004/06/14 01:46:03 mcr Exp $
 */

#include <stdlib.h>
#include <string.h>

#include <openswan.h>

#include "constants.h"
#include "oswlog.h"

#include "oswalloc.h"
#include "oswconf.h"
#include "asn1.h"
#include "oid.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "pkcs.h"

/* ASN.1 definition of a PKCS#1 RSA private key */

static const asn1Object_t privkeyObjects[] = {
  { 0, "RSAPrivateKey",			ASN1_SEQUENCE,     ASN1_OBJ  }, /*  0 */
  { 1,   "version",			ASN1_INTEGER,      ASN1_BODY }, /*  1 */
  { 1,   "modulus",			ASN1_INTEGER,      ASN1_BODY }, /*  2 */
  { 1,   "publicExponent",		ASN1_INTEGER,      ASN1_BODY }, /*  3 */
  { 1,   "privateExponent",		ASN1_INTEGER,      ASN1_BODY }, /*  4 */
  { 1,   "prime1",			ASN1_INTEGER,      ASN1_BODY }, /*  5 */
  { 1,   "prime2",			ASN1_INTEGER,      ASN1_BODY }, /*  6 */
  { 1,   "exponent1",			ASN1_INTEGER,      ASN1_BODY }, /*  7 */
  { 1,   "exponent2",			ASN1_INTEGER,      ASN1_BODY }, /*  8 */
  { 1,   "coefficient",			ASN1_INTEGER,      ASN1_BODY }, /*  9 */
  { 1,   "otherPrimeInfos",		ASN1_SEQUENCE,     ASN1_OPT |
							   ASN1_LOOP }, /* 10 */
  { 2,     "otherPrimeInfo",		ASN1_SEQUENCE,     ASN1_NONE }, /* 11 */
  { 3,       "prime",			ASN1_INTEGER,      ASN1_BODY }, /* 12 */
  { 3,       "exponent",		ASN1_INTEGER,      ASN1_BODY }, /* 13 */
  { 3,       "coefficient",		ASN1_INTEGER,      ASN1_BODY }, /* 14 */
  { 1,   "end opt or loop",		ASN1_EOC,          ASN1_END  }  /* 15 */
};

#define PKCS1_PRIV_KEY_OBJECT		 0
#define PKCS1_PRIV_KEY_VERSION		 1
#define PKCS1_PRIV_KEY_MODULUS		 2
#define PKCS1_PRIV_KEY_COEFF		 9
#define PKCS1_PRIV_KEY_ROOF		16

/* ASN.1 definition of the PKCS#7 ContentInfo type */

static const asn1Object_t contentInfoObjects[] = {
  { 0, "contentInfo",			ASN1_SEQUENCE,     ASN1_NONE  }, /*  0 */
  { 1,   "contentType",			ASN1_OID,          ASN1_BODY }, /*  1 */
  { 1,   "content",			ASN1_CONTEXT_C_0,  ASN1_OPT |
							   ASN1_BODY }, /*  2 */
  { 1,   "end opt",			ASN1_EOC,	   ASN1_END  }  /*  3 */
};

#define PKCS7_INFO_TYPE		1
#define PKCS7_INFO_CONTENT	2
#define PKCS7_INFO_ROOF		4

/* ASN.1 definition of the PKCS#7 SignedData type */

static const asn1Object_t signedDataObjects[] = {
  { 0, "signedData",			ASN1_SEQUENCE,     ASN1_NONE }, /*  0 */
  { 1,   "version",			ASN1_INTEGER,      ASN1_BODY }, /*  1 */
  { 1,   "digestAlgorithms",		ASN1_SET,          ASN1_BODY }, /*  2 */
  { 1,   "contentInfo",			ASN1_SEQUENCE,     ASN1_OBJ  }, /*  3 */
  { 1,   "certificates",		ASN1_CONTEXT_C_0,  ASN1_OPT |
							   ASN1_LOOP }, /*  4 */
  { 2,      "certificate",		ASN1_SEQUENCE,	   ASN1_OBJ  }, /*  5 */
  { 1,   "end opt or loop",		ASN1_EOC,	   ASN1_END  }, /*  6 */
  { 1,   "crls",			ASN1_CONTEXT_C_1,  ASN1_OPT |
							   ASN1_LOOP }, /*  7 */
  { 2,	    "crl",			ASN1_SEQUENCE,     ASN1_OBJ  }, /*  8 */
  { 1,   "end opt or loop",		ASN1_EOC,	   ASN1_END  }, /*  9 */
  { 1,   "signerInfos",			ASN1_SET,	   ASN1_BODY }  /* 10 */
};

#define PKCS7_SIGNED_CERT	 5
#define PKCS7_SIGNED_ROOF	11

/*
 *  Parses a PKCS#1 private key
 */
bool
parse_pkcs1_private_key(chunk_t blob, rsa_privkey_t *key)
{
    asn1_ctx_t ctx;
    chunk_t object;
    u_int level;
    u_int objectID = 0;

    asn1_init(&ctx, blob, 0, FALSE, DBG_PRIVATE);

    while (objectID < PKCS1_PRIV_KEY_ROOF) {

	if (!extract_object(privkeyObjects, &objectID, &object, &level, &ctx))
	     return FALSE;

	if (objectID == PKCS1_PRIV_KEY_OBJECT)
	{
	    key->keyobject = object;
	}
	else if (objectID == PKCS1_PRIV_KEY_VERSION)
	{
	    if (*object.ptr != 0)
	    {
		openswan_log("  wrong PKCS#1 private key version");
		return FALSE;
	    }
	}
	else if (objectID >= PKCS1_PRIV_KEY_MODULUS &&
		 objectID <= PKCS1_PRIV_KEY_COEFF)
	{
	    key->field[objectID - PKCS1_PRIV_KEY_MODULUS] = object;
	}
	objectID++;
    }
    return TRUE;
}

/*
 * Parse PKCS#7 wrapped X.509 certificates
 */
static bool
parse_pkcs7_signedData(chunk_t blob, int level0, x509cert_t **cert)
{
    asn1_ctx_t ctx;
    chunk_t object;
    u_int level;
    u_int objectID = 0;

    asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

    while (objectID < PKCS7_SIGNED_ROOF) {

	if (!extract_object(signedDataObjects, &objectID, &object, &level, &ctx))
	     return FALSE;

	if (objectID == PKCS7_SIGNED_CERT)
	{
	    chunk_t cert_blob;
	    x509cert_t *newcert = alloc_thing(x509cert_t,
					"pkcs7 wrapped x509cert");

	    clonetochunk(cert_blob, object.ptr, object.len, "pkcs7 cert blob");
	    *newcert = empty_x509cert;

	    if (parse_x509cert(cert_blob, level+1, newcert))
	    {
		newcert->next = *cert;
		*cert = newcert;
	    }
	    else
	    {
		free_x509cert(newcert);
	    }
	}
	objectID++;
    }
    return TRUE;
}

/*
 * Parse PKCS#7 wrapped X.509 certificates
 */
bool
parse_pkcs7_cert(chunk_t blob, x509cert_t **cert)
{
    asn1_ctx_t ctx;
    chunk_t object;
    u_int level;
    u_int objectID = 0;

    asn1_init(&ctx, blob, 0, FALSE, DBG_RAW);

    while (objectID < PKCS7_INFO_ROOF) {

	if (!extract_object(contentInfoObjects, &objectID, &object, &level, &ctx))
	     return FALSE;

	if (objectID == PKCS7_INFO_TYPE)
	{
	    if (known_oid(object) != OID_PKCS7_SIGNED_DATA)
	    {
		openswan_log("PKCS#7 content type is not signedData");
		return FALSE;
	    }
	}
	else if (objectID == PKCS7_INFO_CONTENT)
	{
	    parse_pkcs7_signedData(object, level+1, cert);
	}
	objectID++;
    }
    return TRUE;
}

