/* Support of the Online Certificate Status Protocol (OCSP)
 *
 * Copyright (C) 2003 Christoph Gysin, Simon Zwahlen
 *                    Zuercher Hochschule Winterthur
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

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "sysdep.h"
#include "constants.h"
#include "oswtime.h"

#include "defs.h"
#include "id.h"
#include "log.h"
#include "x509.h"
#include "rnd.h"
#include "asn1.h"
#include "pgp.h"
#include "certs.h"
#include "smartcard.h"
#include "oid.h"
#include "whack.h"
#include "keys.h"
#include "fetch.h"
#include "ocsp.h"

#define NONCE_LENGTH		16
#define BUF_LEN			512

#define constcpy(dst, str) \
    { memcpy(dst, str, sizeof(str)); dst += sizeof(str);}

static const char *const cert_status_names[] = {
    "good",
    "revoked",
    "unknown",
    "undefined"
};


static const char *const response_status_names[] = {
    "successful",
    "malformed request",
    "internal error",
    "try later",
    "signature required",
    "unauthorized"
};

/* response container */
typedef struct response response_t;

struct response {
    chunk_t  tbs;
    chunk_t  responder_id_name;
    chunk_t  responder_id_key;
    time_t   produced_at;
    chunk_t  responses;
    chunk_t  nonce;
    int      algorithm;
    chunk_t  signature;
};

const response_t empty_response = {
    { NULL, 0 }   ,	/* tbs */
    { NULL, 0 }   ,	/* responder_id_name */
    { NULL, 0 }   ,	/* responder_id_key */
    UNDEFINED_TIME,	/* produced_at */
    { NULL, 0 }   ,	/* single_response */
    { NULL, 0 }   ,	/* nonce */
    OID_UNKNOWN   ,	/* signature_algorithm */
    { NULL, 0 }		/* signature */
};

/* crl reasons */
typedef enum {
    REASON_UNSPECIFIED =		0,
    REASON_KEYCOMPROMISE = 		1,
    REASON_CACOMPROMISE = 		2,
    REASON_AFFILIATIONCHANGED =		3,
    REASON_SUPERSEEDED =		4,
    REASON_CESSATIONOFOPERATION =	5,
    REASON_CERTIFICATEHOLD =		6,
    REASON_REMOVEFROMCRL =		8
} crl_reason_t;

/* single response container */
typedef struct single_response single_response_t;

struct single_response {
    single_response_t *next;
    int               hash_algorithm;
    chunk_t           issuer_name_hash;
    chunk_t           issuer_key_hash;
    chunk_t           serialNumber;
    cert_status_t     status;
    time_t            revocation_time;
    crl_reason_t      reason;
    time_t            thisUpdate;
    time_t            nextUpdate;
};

const single_response_t empty_single_response = {
      NULL            ,	/* *next */
    OID_UNKNOWN       ,	/* hash_algorithm */
    { NULL, 0 }       ,	/* issuer_name_hash */
    { NULL, 0 }       ,	/* issuer_key_hash */
    { NULL, 0 }       ,	/* serial_number */
    CERT_UNDEFINED    ,	/* status */
    UNDEFINED_TIME    ,	/* revocation_time */
    REASON_UNSPECIFIED,	/* reason */
    UNDEFINED_TIME    ,	/* this_update */
    UNDEFINED_TIME	/* next_update */
};


/* list of single requests */
typedef struct request_list request_list_t;
struct request_list {
    chunk_t request;
    request_list_t *next;
};

/* some prefabricated ASN.1 constants */

const char ASN1_sha1_id[] = {
    0x30, 0x09,
	  0x06, 0x05, 0x2B, 0x0E,0x03, 0x02, 0x1A,
	  0x05, 0x00
};

const char ASN1_sha1WithRSA_id[] = {
    0x30, 0x0D,
	  0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05,
	  0x05, 0x00
};

const char ASN1_nonce_oid[] = {
    0x06, 0x09, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02
};

const char ASN1_response_oid[] = {
    0x06, 0x09, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x04
};


const char ASN1_response_content[] = {
    0x04, 0x0D,
	  0x30, 0x0B,
		0x06, 0x09, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01
};

/* default OCSP uri */
static chunk_t ocsp_default_uri;

/* ocsp cache: pointer to first element */
static ocsp_location_t *ocsp_cache = NULL;

/* static temporary storage for ocsp requestor information */
static x509cert_t *ocsp_requestor_cert = NULL;

static smartcard_t *ocsp_requestor_sc = NULL;

static const struct RSA_private_key *ocsp_requestor_pri = NULL;

/* asn.1 definitions for parsing */

static const asn1Object_t ocspResponseObjects[] = {
  { 0, "OCSPResponse",                  ASN1_SEQUENCE,     ASN1_NONE }, /*  0 */
  { 1,   "responseStatus",              ASN1_ENUMERATED,   ASN1_BODY }, /*  1 */
  { 1,   "responseBytesContext",        ASN1_CONTEXT_C_0,  ASN1_OPT  }, /*  2 */
  { 2,     "responseBytes",             ASN1_SEQUENCE,     ASN1_NONE }, /*  3 */
  { 3,       "responseType",            ASN1_OID,          ASN1_BODY }, /*  4 */
  { 3,       "response",                ASN1_OCTET_STRING, ASN1_BODY }, /*  5 */
  { 1,   "end opt",                     ASN1_EOC,          ASN1_END  }  /*  6 */
};

#define OCSP_RESPONSE_STATUS	1
#define OCSP_RESPONSE_TYPE	4
#define OCSP_RESPONSE		5
#define OCSP_RESPONSE_ROOF	7

static const asn1Object_t basicResponseObjects[] = {
  { 0, "BasicOCSPResponse",             ASN1_SEQUENCE,        ASN1_NONE }, /*  0 */
  { 1,   "tbsResponseData",             ASN1_SEQUENCE,        ASN1_OBJ  }, /*  1 */
  { 2,     "versionContext",            ASN1_CONTEXT_C_0,     ASN1_NONE |
							      ASN1_DEF  }, /*  2 */
  { 3,       "version",                 ASN1_INTEGER,         ASN1_BODY }, /*  3 */
  { 2,     "responderIdContext",        ASN1_CONTEXT_C_1,     ASN1_OPT  }, /*  4 */
  { 3,       "responderIdByName",       ASN1_SEQUENCE,        ASN1_OBJ  }, /*  5 */
  { 2,     "end choice",                ASN1_EOC,             ASN1_END  }, /*  6 */
  { 2,     "responderIdContext",        ASN1_CONTEXT_C_2,     ASN1_OPT  }, /*  7 */
  { 3,       "responderIdByKey",        ASN1_OCTET_STRING,    ASN1_BODY }, /*  8 */
  { 2,     "end choice",                ASN1_EOC,             ASN1_END  }, /*  9 */
  { 2,     "producedAt",                ASN1_GENERALIZEDTIME, ASN1_BODY }, /* 10 */
  { 2,     "responses",                 ASN1_SEQUENCE,        ASN1_OBJ  }, /* 11 */
  { 2,     "responseExtensionsContext", ASN1_CONTEXT_C_1,     ASN1_OPT  }, /* 12 */
  { 3,       "responseExtensions",      ASN1_SEQUENCE,        ASN1_LOOP }, /* 13 */
  { 4,         "extension",             ASN1_SEQUENCE,        ASN1_NONE }, /* 14 */
  { 5,           "extnID",              ASN1_OID,             ASN1_BODY }, /* 15 */
  { 5,           "critical",            ASN1_BOOLEAN,         ASN1_BODY |
							      ASN1_DEF  }, /* 16 */
  { 5,           "extnValue",           ASN1_OCTET_STRING,    ASN1_BODY }, /* 17 */
  { 4,         "end loop",              ASN1_EOC,             ASN1_END  }, /* 18 */
  { 2,     "end opt",                   ASN1_EOC,             ASN1_END  }, /* 19 */
  { 1,   "signatureAlgorithm",          ASN1_EOC,             ASN1_RAW  }, /* 20 */
  { 1,   "signature",                   ASN1_BIT_STRING,      ASN1_BODY }, /* 21 */
  { 1,   "certsContext",                ASN1_CONTEXT_C_0,     ASN1_OPT  }, /* 22 */
  { 2,     "certs",                     ASN1_SEQUENCE,        ASN1_LOOP }, /* 23 */
  { 3,       "certificate",             ASN1_SEQUENCE,        ASN1_OBJ  }, /* 24 */
  { 2,     "end loop",                  ASN1_EOC,	      ASN1_END  }, /* 25 */
  { 1,   "end opt",                     ASN1_EOC,             ASN1_END  }  /* 26 */
};

#define BASIC_RESPONSE_TBS_DATA		 1
#define BASIC_RESPONSE_VERSION		 3
#define BASIC_RESPONSE_ID_BY_NAME	 5
#define BASIC_RESPONSE_ID_BY_KEY	 8
#define BASIC_RESPONSE_PRODUCED_AT	10
#define BASIC_RESPONSE_RESPONSES	11
#define BASIC_RESPONSE_EXT_ID		15
#define BASIC_RESPONSE_CRITICAL		16
#define BASIC_RESPONSE_EXT_VALUE	17
#define BASIC_RESPONSE_ALGORITHM	20
#define BASIC_RESPONSE_SIGNATURE	21
#define BASIC_RESPONSE_CERTIFICATE	24
#define BASIC_RESPONSE_ROOF		27

static const asn1Object_t responsesObjects[] = {
  { 0, "responses",                   ASN1_SEQUENCE,          ASN1_LOOP }, /*  0 */
  { 1,   "singleResponse",            ASN1_EOC,               ASN1_RAW  }, /*  1 */
  { 0, "end loop",                    ASN1_EOC,               ASN1_END  }  /*  2 */
};

#define RESPONSES_SINGLE_RESPONSE	 1
#define RESPONSES_ROOF			 3

static const asn1Object_t singleResponseObjects[] = {
  { 0, "singleResponse",            ASN1_SEQUENCE,          ASN1_BODY }, /*  0 */
  { 1,   "certID",                  ASN1_SEQUENCE,          ASN1_NONE }, /*  1 */
  { 2,     "algorithm",             ASN1_EOC,               ASN1_RAW  }, /*  2 */
  { 2,     "issuerNameHash",        ASN1_OCTET_STRING,      ASN1_BODY }, /*  3 */
  { 2,     "issuerKeyHash",         ASN1_OCTET_STRING,      ASN1_BODY }, /*  4 */
  { 2,     "serialNumber",          ASN1_INTEGER,           ASN1_BODY }, /*  5 */
  { 1,   "certStatusGood",          ASN1_CONTEXT_S_0,       ASN1_OPT  }, /*  6 */
  { 1,   "end opt",                 ASN1_EOC,               ASN1_END  }, /*  7 */
  { 1,   "certStatusRevoked",       ASN1_CONTEXT_C_1,       ASN1_OPT  }, /*  8 */
  { 2,     "revocationTime",        ASN1_GENERALIZEDTIME,   ASN1_BODY }, /*  9 */
  { 2,     "revocationReason",      ASN1_CONTEXT_C_0,       ASN1_OPT  }, /* 10 */
  { 3,       "crlReason",           ASN1_ENUMERATED,        ASN1_BODY }, /* 11 */
  { 2,     "end opt",               ASN1_EOC,               ASN1_END  }, /* 12 */
  { 1,   "end opt",                 ASN1_EOC,               ASN1_END  }, /* 13 */
  { 1,   "certStatusUnknown",       ASN1_CONTEXT_S_2,       ASN1_OPT  }, /* 14 */
  { 1,   "end opt",                 ASN1_EOC,               ASN1_END  }, /* 15 */
  { 1,   "thisUpdate",              ASN1_GENERALIZEDTIME,   ASN1_BODY }, /* 16 */
  { 1,   "nextUpdateContext",       ASN1_CONTEXT_C_0,       ASN1_OPT  }, /* 17 */
  { 2,     "nextUpdate",            ASN1_GENERALIZEDTIME,   ASN1_BODY }, /* 18 */
  { 1,   "end opt",                 ASN1_EOC,               ASN1_END  }, /* 19 */
  { 1,   "singleExtensionsContext", ASN1_CONTEXT_C_1,       ASN1_OPT  }, /* 20 */
  { 2,     "singleExtensions",      ASN1_SEQUENCE,          ASN1_LOOP }, /* 21 */
  { 3,       "extension",           ASN1_SEQUENCE,          ASN1_NONE }, /* 22 */
  { 4,         "extnID",            ASN1_OID,               ASN1_BODY }, /* 23 */
  { 4,         "critical",          ASN1_BOOLEAN,           ASN1_BODY |
							    ASN1_DEF  }, /* 24 */
  { 4,         "extnValue",         ASN1_OCTET_STRING,      ASN1_BODY }, /* 25 */
  { 2,     "end loop",              ASN1_EOC,               ASN1_END  }, /* 26 */
  { 1,   "end opt",                 ASN1_EOC,               ASN1_END  }  /* 27 */
};

#define SINGLE_RESPONSE_ALGORITHM			 2
#define SINGLE_RESPONSE_ISSUER_NAME_HASH		 3
#define SINGLE_RESPONSE_ISSUER_KEY_HASH			 4
#define SINGLE_RESPONSE_SERIAL_NUMBER			 5
#define SINGLE_RESPONSE_CERT_STATUS_GOOD		 6
#define SINGLE_RESPONSE_CERT_STATUS_REVOKED		 8
#define SINGLE_RESPONSE_CERT_STATUS_REVOCATION_TIME	 9
#define SINGLE_RESPONSE_CERT_STATUS_CRL_REASON		11
#define SINGLE_RESPONSE_CERT_STATUS_UNKNOWN		14
#define SINGLE_RESPONSE_THIS_UPDATE			16
#define SINGLE_RESPONSE_NEXT_UPDATE			18
#define SINGLE_RESPONSE_EXT_ID				23
#define SINGLE_RESPONSE_CRITICAL			24
#define SINGLE_RESPONSE_EXT_VALUE			25
#define SINGLE_RESPONSE_ROOF				28

/* build an ocsp location from certificate information
 * without unsharing its contents
 */
static bool
build_ocsp_location(const x509cert_t *cert, ocsp_location_t *location)
{
    static u_char digest[SHA1_DIGEST_SIZE];  /* temporary storage */

    location->uri = (cert->accessLocation.ptr != NULL)
	? cert->accessLocation : ocsp_default_uri;

    /* abort if no ocsp location uri is defined */
    if (location->uri.ptr == NULL)
 	return FALSE;

    setchunk(location->authNameID, digest, SHA1_DIGEST_SIZE);
    compute_digest(cert->issuer, OID_SHA1, &location->authNameID);

    location->next = NULL;
    location->issuer = cert->issuer;
    location->authKeyID = cert->authKeyID;
    location->authKeySerialNumber = cert->authKeySerialNumber;
    
    if (cert->authKeyID.ptr == NULL) 
    {
	x509cert_t *authcert = get_authcert(cert->issuer
		, cert->authKeySerialNumber, cert->authKeyID, AUTH_CA);

	if (authcert != NULL)
	{
	    location->authKeyID = authcert->subjectKeyID;
	    location->authKeySerialNumber = authcert->serialNumber;
	}
    }

    location->nonce = empty_chunk;
    location->certinfo = NULL;

    return TRUE;
}

/*
 * compare two ocsp locations for equality
 */
static bool
same_ocsp_location(const ocsp_location_t *a, const ocsp_location_t *b)
{
    return ((a->authKeyID.ptr != NULL)
		? same_keyid(a->authKeyID, b->authKeyID)
		: (same_dn(a->issuer, b->issuer)
		    && same_serial(a->authKeySerialNumber, b->authKeySerialNumber)))
	    && same_chunk(a->uri, b->uri);
}

/*
 * find an existing ocsp location in a chained list
 */
ocsp_location_t*
get_ocsp_location(const ocsp_location_t * loc, ocsp_location_t *chain)
{

    while (chain != NULL)
    {
	if (same_ocsp_location(loc, chain))
	    return chain;
	chain = chain->next;
    }
    return NULL;
}
 
/* retrieves the status of a cert from the ocsp cache
 * returns CERT_UNDEFINED if no status is found
 */
static cert_status_t
get_ocsp_status(const ocsp_location_t *loc, chunk_t serialNumber
    ,time_t *nextUpdate)
{
    ocsp_certinfo_t *certinfo, **certinfop;
    int cmp = 0;

    /* find location */
    ocsp_location_t *location = get_ocsp_location(loc, ocsp_cache);

    if (location == NULL)
	return CERT_UNDEFINED;

    /* traverse list of certinfos in increasing order */
    certinfop = &location->certinfo;
    certinfo = *certinfop;

    while (certinfo != NULL)
    {
	cmp = cmp_chunk(serialNumber, certinfo->serialNumber);
	if (cmp <= 0)
	    break;
	certinfop = &certinfo->next;
	certinfo = *certinfop;
    }

    if (cmp == 0)
    {
	*nextUpdate = certinfo->nextUpdate;
	return certinfo->status;
    }

    return CERT_UNDEFINED;
}

/*
 * verify the ocsp status of a certificate
 */
bool
verify_by_ocsp(/*const*/ x509cert_t *cert, bool strict, time_t *until)
{
    u_char status;
    ocsp_location_t location;
    time_t nextUpdate = 0;

    /* is an ocsp location defined? */
    if (!build_ocsp_location(cert, &location))
	return FALSE;

    lock_ocsp_cache("verify_by_ocsp");
    status = get_ocsp_status(&location, cert->serialNumber, &nextUpdate);
    unlock_ocsp_cache("verify_by_ocsp");

#ifdef HAVE_THREADS
    if (status == CERT_UNDEFINED || nextUpdate < time(NULL))
    {
	openswan_log("ocsp status is stale or not in cache");
	add_ocsp_fetch_request(&location, cert->serialNumber);

	/* inititate fetching of ocsp status */
	wake_fetch_thread("verify_by_ocsp");
	return !strict;
    }
#endif
    
    switch (status)
    {
    case CERT_GOOD:
    	DBG(DBG_CONTROL,
	    DBG_log("certificate is good")
	)
	/* with strict crl policy the public key must have the
	 * same lifetime as the validity of the ocsp status
	 */
	if (strict && nextUpdate < *until)
	    *until = nextUpdate;
	break;
    case CERT_REVOKED:
	plog("certificate is revoked");
	remove_x509_public_key(cert);
	return FALSE;
    case CERT_UNKNOWN:
	plog("certificate status unkown");
	if (strict)
	{
	    remove_x509_public_key(cert);
	    return FALSE;
	}
	break;
    }
    return TRUE;
}

/*
 * check if an ocsp status is about to expire
 */
void
check_ocsp(void)
{
    ocsp_location_t *location;

    lock_ocsp_cache("check_ocsp");
    location = ocsp_cache;
    
    while (location != NULL)
    {
	char buf[BUF_LEN];
	bool first = TRUE;
	ocsp_certinfo_t *certinfo = location->certinfo;

	while (certinfo != NULL)
	{
	    if (!certinfo->once)
	    {
		time_t time_left = certinfo->nextUpdate - time(NULL);

		DBG(DBG_CONTROL,
		    if (first)
		    {
			dntoa(buf, BUF_LEN, location->issuer);
			DBG_log("issuer: '%s'", buf);
			if (location->authKeyID.ptr != NULL)
			{
			    datatot(location->authKeyID.ptr, location->authKeyID.len
				, ':', buf, BUF_LEN);
			    DBG_log("authkey: %s", buf);
			}
			first = FALSE;
		    }
		    datatot(certinfo->serialNumber.ptr, certinfo->serialNumber.len
			, ':', buf, BUF_LEN);
		    DBG_log("serial: %s, %ld seconds left", buf
			    , (unsigned long)time_left)
		)

#ifdef HAVE_THREADS
		if (time_left < 2*crl_check_interval)
		    add_ocsp_fetch_request(location, certinfo->serialNumber);
#endif
	    }
	    certinfo = certinfo->next;
	}
	location = location->next;
    }
    unlock_ocsp_cache("check_ocsp");
}

/*
 * sets the default uri
 */
void
ocsp_set_default_uri(char *uri)
{
    ocsp_default_uri = empty_chunk;
    
    if (uri == NULL)
	return;
    
    if (strncasecmp(uri, "http", 4) != 0)
    {
	plog("warning: ignoring default ocsp uri with unkown protocol");
	return;
    }
    
    clonetochunk(ocsp_default_uri, uri, strlen(uri), "ocsp default uri");
}

/*
 *  frees the allocated memory of a certinfo struct
 */
static void
free_certinfo(ocsp_certinfo_t *certinfo)
{
    freeanychunk(certinfo->serialNumber);
    pfree(certinfo);
}

/*
 * frees all certinfos in a chained list
 */
static void
free_certinfos(ocsp_certinfo_t *chain)
{
    ocsp_certinfo_t *certinfo;

    while (chain != NULL)
    {
	certinfo = chain;
	chain = chain->next;
	free_certinfo(certinfo);
    }
}

/*
 * frees the memory allocated to an ocsp location including all certinfos
 */
static void
free_ocsp_location(ocsp_location_t* location)
{
    freeanychunk(location->issuer);
    freeanychunk(location->authNameID);
    freeanychunk(location->authKeyID);
    freeanychunk(location->authKeySerialNumber);
    freeanychunk(location->uri);
    free_certinfos(location->certinfo);
    pfree(location);
}

/*
 * free a chained list of ocsp locations
 */
void
free_ocsp_locations(ocsp_location_t **chain)
{
    while (*chain != NULL)
    {
	ocsp_location_t *location = *chain;
	*chain = location->next;
	free_ocsp_location(location);
    }
}

/*
 * free the ocsp cache
 */
void
free_ocsp_cache(void)
{
    lock_ocsp_cache("free_ocsp_cache");
    free_ocsp_locations(&ocsp_cache);
    unlock_ocsp_cache("free_ocsp_cache");
}

/*
 * frees the ocsp cache and global variables
 */
void
free_ocsp(void)
{
    pfreeany(ocsp_default_uri.ptr);
    free_ocsp_cache();
}

/*
 * list a chained list of ocsp_locations
 */
void
list_ocsp_locations(ocsp_location_t *location, bool requests, bool utc
, bool strict)
{
    bool first = TRUE;

    while (location != NULL)
    {
	ocsp_certinfo_t *certinfo = location->certinfo;

	if (certinfo != NULL)
	{
	    char buf[BUF_LEN];

	    if (first)
	    {
		whack_log(RC_COMMENT, " ");
		whack_log(RC_COMMENT, "List of OCSP %s:", requests?
		    "fetch requests":"responses");
		first = FALSE;
            }
	    whack_log(RC_COMMENT, " ");
	    if (location->issuer.ptr != NULL)
	    {
		dntoa(buf, BUF_LEN, location->issuer);
		whack_log(RC_COMMENT, "       issuer:  '%s'", buf);
	    }
	    whack_log(RC_COMMENT, "       uri:     '%.*s", (int)location->uri.len
		, location->uri.ptr);
	    if (location->authNameID.ptr != NULL)
	    {
		datatot(location->authNameID.ptr, location->authNameID.len, ':'
		    , buf, BUF_LEN);
		whack_log(RC_COMMENT, "       authname: %s", buf);
	    }
	    if (location->authKeyID.ptr != NULL)
	    {
		datatot(location->authKeyID.ptr, location->authKeyID.len, ':'
		    , buf, BUF_LEN);
		whack_log(RC_COMMENT, "       authkey:  %s", buf);
	    }
	    if (location->authKeySerialNumber.ptr != NULL)
	    {
		datatot(location->authKeySerialNumber.ptr
		    , location->authKeySerialNumber.len, ':', buf, BUF_LEN);
		whack_log(RC_COMMENT, "       aserial:  %s", buf);
	    }
	    while (certinfo != NULL)
	    {
		char thisUpdate[TIMETOA_BUF];
		
		timetoa(&certinfo->thisUpdate, utc, thisUpdate, sizeof(thisUpdate));

		if (requests)
		{
		    whack_log(RC_COMMENT, "%s, trials: %d", thisUpdate
			, certinfo->trials);
		}
		else if (certinfo->once)
		{
		    whack_log(RC_COMMENT, "%s, onetime use%s", thisUpdate
			, (certinfo->nextUpdate < time(NULL))? " (expired)": "");
		}
		else
		{
		    char tbuf2[TIMETOA_BUF];

		    whack_log(RC_COMMENT, "%s, until %s %s", thisUpdate
			      , timetoa(&certinfo->nextUpdate, utc, tbuf2, sizeof(tbuf2))
			      , check_expiry(certinfo->nextUpdate, OCSP_WARNING_INTERVAL, strict));
		}
		datatot(certinfo->serialNumber.ptr, certinfo->serialNumber.len, ':'
		    , buf, BUF_LEN);
		whack_log(RC_COMMENT, "       serial:   %s, %s", buf
		    , cert_status_names[certinfo->status]);
		certinfo = certinfo->next;
	    }
	}
	location = location->next;
    }
}

/*
 * list the ocsp cache
 */
void
list_ocsp_cache(bool utc, bool strict)
{
    lock_ocsp_cache("list_ocsp_cache");
    list_ocsp_locations(ocsp_cache, FALSE, utc, strict);
    unlock_ocsp_cache("list_ocsp_cache");
}

/* moves a chunk to a memory position, chunk is freed afterwards
 * position pointer is advanced after the insertion point
 */
static void
mv_chunk(u_char **pos, chunk_t content)
{
    if (content.len > 0)
    {
	chunkcpy(*pos, content);
	freeanychunk(content);
    }
}

static bool
get_ocsp_requestor_cert(ocsp_location_t *location)
{
    x509cert_t *cert = NULL;

    /* initialize temporary static storage */
    ocsp_requestor_cert = NULL;
    ocsp_requestor_sc   = NULL;
    ocsp_requestor_pri  = NULL;

    for (;;)
    {
	char buf[BUF_LEN];

	/* looking for a certificate from the same issuer */
	cert = get_x509cert(location->issuer, location->authKeySerialNumber
		    ,location->authKeyID, cert);
   	if (cert == NULL)
	    break;

	DBG(DBG_CONTROL,
	    dntoa(buf, BUF_LEN, cert->subject);
	    DBG_log("candidate: '%s'", buf);
	)

	if (cert->smartcard)
	{
#ifdef SMARTCARD
	    /* look for a matching private key on a smartcard */
	    smartcard_t *sc = scx_get(cert);
	    if (sc != NULL)
	    {
		DBG(DBG_CONTROL,
		    DBG_log("matching smartcard found")
		)
		if (sc->valid)
		{
		    ocsp_requestor_cert = cert;
		    ocsp_requestor_sc = sc;
		    return TRUE;
		}
		plog("unable to sign ocsp request without PIN");
	    }
#endif
	}
	else
	{
	    /* look for a matching private key in the chained list */
	    const struct RSA_private_key *pri = get_x509_private_key(cert);

	    if (pri != NULL)
	    {
		DBG(DBG_CONTROL,
		    DBG_log("matching private key found")
		)
		ocsp_requestor_cert = cert;
		ocsp_requestor_pri = pri;
		return TRUE;
	    }
	}
    }
    return FALSE;
}

static chunk_t
generate_signature(chunk_t digest, smartcard_t *sc
    , const struct RSA_private_key *pri)
{
    chunk_t sigdata;
    u_char *pos;
    size_t siglen = 0;

    if (sc != NULL)
    {
	/* RSA signature is done on smartcard */

#ifdef SMARTCARD
	if (!scx_establish_context(sc->reader))
	{
	    scx_release_context();
	    return empty_chunk;
	}

	siglen = scx_get_keylength(sc) / BITS_PER_BYTE;

	if (siglen == 0)
	{
	    plog("failed to get keylength from smartcard");
	    scx_release_context();
	    return empty_chunk;
	}

	DBG(DBG_CONTROL | DBG_CRYPT,
	    DBG_log("signing hash with RSA key from smartcard (reader: %d, id: %s)"
		, sc->reader, sc->id)
	)

	pos = build_asn1_object(&sigdata, ASN1_BIT_STRING, 1 + siglen);
	*pos++ = 0x00;
	scx_sign_hash(sc, digest.ptr, digest.len, pos, siglen);
	scx_release_context();
#endif
    }
    else
    {
	/* RSA signature is done in software */
	siglen = pri->pub.k;
	pos = build_asn1_object(&sigdata, ASN1_BIT_STRING, 1 + siglen);
	*pos++ = 0x00;
	sign_hash(pri, digest.ptr, digest.len, pos, siglen);
    }
    return sigdata;
}

/*
 * build signature into ocsp request
 * gets built only if a request cert with
 * a corresponding private key is found
 */
static chunk_t
build_signature(chunk_t tbsRequest)
{
    chunk_t signature, sigdata, certs;
    chunk_t digest, digest_info;
    u_char *pos;

    u_char digest_buf[MAX_DIGEST_LEN];
    chunk_t digest_raw = { digest_buf, MAX_DIGEST_LEN };

    if (!compute_digest(tbsRequest, OID_SHA1_WITH_RSA, &digest_raw))
	return empty_chunk;

    /* according to PKCS#1 v2.1 digest must be packaged into
     * an ASN.1 structure for encryption
     */
    pos = build_asn1_object(&digest, ASN1_OCTET_STRING
	    , digest_raw.len);
    chunkcpy(pos, digest_raw);

    pos = build_asn1_object(&digest_info, ASN1_SEQUENCE
	    , sizeof(ASN1_sha1_id) + digest.len);
    constcpy( pos, ASN1_sha1_id);
    mv_chunk(&pos, digest);

    /* generate the RSA signature */
    sigdata = generate_signature(digest_info
	, ocsp_requestor_sc
	, ocsp_requestor_pri);
    freeanychunk(digest_info);
    
    /* has the RSA signature generation been successful? */
    if (sigdata.ptr == NULL)
	return empty_chunk;

    /* include our certificate */
    pos = build_asn1_explicit_object(&certs, ASN1_CONTEXT_C_0
	    , ASN1_SEQUENCE, ocsp_requestor_cert->certificate.len);
    chunkcpy(pos, ocsp_requestor_cert->certificate);

    /* build signature comprising algorithm, signature and cert */
    pos = build_asn1_explicit_object(&signature, ASN1_CONTEXT_C_0
	    , ASN1_SEQUENCE
	    , sizeof(ASN1_sha1WithRSA_id) + sigdata.len + certs.len);
    constcpy( pos, ASN1_sha1WithRSA_id);
    mv_chunk(&pos, sigdata);
    mv_chunk(&pos, certs);

    return signature;
}

/*
 * build requestCert (into Request)
 */
static chunk_t
build_req_cert(ocsp_location_t *location, ocsp_certinfo_t *certinfo)
{
    chunk_t reqCert;
    chunk_t issuerNameHash, issuerKeyHash, serialNumber;
    u_char *pos;

    /* build content */

    /* issuer_name_hash */
    pos = build_asn1_object(&issuerNameHash, ASN1_OCTET_STRING
	    , location->authNameID.len);
    chunkcpy(pos, location->authNameID);

    /* issuer_key_hash */
    pos = build_asn1_object(&issuerKeyHash, ASN1_OCTET_STRING
	    , location->authKeyID.len);
    chunkcpy(pos, location->authKeyID);

    /* serial number */
    pos = build_asn1_object(&serialNumber, ASN1_INTEGER
	    , certinfo->serialNumber.len);
    chunkcpy(pos, certinfo->serialNumber);

    /* assembly */
    pos = build_asn1_object(&reqCert, ASN1_SEQUENCE
	    , sizeof(ASN1_sha1_id) + issuerNameHash.len + issuerKeyHash.len
	    + serialNumber.len);
    constcpy( pos,  ASN1_sha1_id);
    mv_chunk(&pos, issuerNameHash);
    mv_chunk(&pos, issuerKeyHash);
    mv_chunk(&pos, serialNumber);

    return reqCert;
}

/*
 * build request (into requestList)
 */
static chunk_t
build_request(ocsp_location_t *location, ocsp_certinfo_t *certinfo)
{
    /* build request - no singleRequestExtensions used */

    chunk_t request, reqCert;
    u_char *pos;

    /* build content */
    reqCert = build_req_cert(location, certinfo);

    pos = build_asn1_object(&request, ASN1_SEQUENCE
	    , reqCert.len);
    mv_chunk(&pos, reqCert);

    return request;
}

/*
 * build requestList (into TBSRequest)
 */
static chunk_t
build_request_list(ocsp_location_t *location)
{
    chunk_t requestList;
    request_list_t *reqs = NULL;
    ocsp_certinfo_t *certinfo = location->certinfo;
    u_char *pos;

    size_t datalen = 0;

    /* build content */
    while (certinfo != NULL)
    {
	/* build request for every certificate in list
	 * and store them in a chained list
	 */
	request_list_t *req = alloc_thing(request_list_t, "ocsp request");

	req->request = build_request(location, certinfo);
	req->next = reqs;
	reqs = req;

	datalen += req->request.len;
	certinfo = certinfo->next;
    }

    pos = build_asn1_object(&requestList, ASN1_SEQUENCE
	    , datalen);

    /* copy all in chained list, free list afterwards */
    while (reqs != NULL)
    {
 	request_list_t *req = reqs;

	mv_chunk(&pos, req->request);
	reqs = reqs->next;
	pfree(req);
    }

    return requestList;
}

/*
 * build requestorName (into TBSRequest)
 */
static chunk_t
build_requestor_name(void)
{
    chunk_t reqName;
    u_char *pos;

    pos = build_asn1_explicit_object(&reqName, ASN1_CONTEXT_C_1
	    , ASN1_CONTEXT_C_4, ocsp_requestor_cert->subject.len);
    chunkcpy(pos, ocsp_requestor_cert->subject);

    return reqName;
}

/*
 * build nonce extension (into requestExtensions)
 */
static chunk_t
build_nonce_extension(ocsp_location_t *location)
{
    chunk_t nonce, content;
    u_char *pos;

    /* generate a random nonce */
    pos = build_asn1_object(&content, ASN1_OCTET_STRING
	    , NONCE_LENGTH);
    get_rnd_bytes(pos, NONCE_LENGTH);
    clonetochunk(location->nonce, pos, NONCE_LENGTH, "ocsp nonce");

    pos = build_asn1_object(&nonce, ASN1_SEQUENCE
	    , sizeof(ASN1_nonce_oid) + content.len);
    constcpy( pos, ASN1_nonce_oid);
    mv_chunk(&pos, content);

    return nonce;
}

/*
 * build acceptable response types extension (into requestExtensions)
 */
static chunk_t
build_accept_extension(void)
{
    chunk_t acceptExt, content;
    u_char *pos;

    /* content is a sequence of OIDs in an octet string
     * in our case only BasicOCSPResponse
     */
    clonetochunk(content, ASN1_response_content, sizeof(ASN1_response_content)
	, "clone");

    pos = build_asn1_object(&acceptExt, ASN1_SEQUENCE
	    , sizeof(ASN1_response_oid) + content.len);
    constcpy( pos, ASN1_response_oid);
    mv_chunk(&pos, content);

    return acceptExt;
}

/*
 * build requestExtensions (into TBSRequest)
 */
static chunk_t
build_request_ext(ocsp_location_t *location)
{
    chunk_t requestExt;
    chunk_t nonceExt, acceptTypes;
    u_char *pos;

    /* build content */
    nonceExt = build_nonce_extension(location);
    acceptTypes = build_accept_extension();

    pos = build_asn1_explicit_object(&requestExt, ASN1_CONTEXT_C_2
	    , ASN1_SEQUENCE, nonceExt.len + acceptTypes.len);
    mv_chunk(&pos, nonceExt);
    mv_chunk(&pos, acceptTypes);

    return requestExt;
}

/*
 * build TBSRequest (into OCSPRequest)
 */
static chunk_t
build_tbs_request(ocsp_location_t *location, bool has_requestor_cert)
{
    chunk_t tbsRequest;
    chunk_t requestList, requestorName, requestExt;
    u_char *pos;

    /* build content */
    /* version is skipped since the default is ok */
    requestorName = (has_requestor_cert)? build_requestor_name()
					: empty_chunk;
    requestList = build_request_list(location);
    requestExt = build_request_ext(location);

    pos = build_asn1_object(&tbsRequest, ASN1_SEQUENCE
	    , requestList.len + requestorName.len + requestExt.len);
    mv_chunk(&pos, requestorName);
    mv_chunk(&pos, requestList);
    mv_chunk(&pos, requestExt);

    return tbsRequest;
}

/* assembles an ocsp request to given location
 * and sets nonce field in location to the sent nonce
 */
chunk_t
build_ocsp_request(ocsp_location_t *location)
{
    bool has_requestor_cert;
    chunk_t request, tbsRequest, signature;
    char buf[BUF_LEN];
    u_char *pos;

    DBG(DBG_CONTROL,
	DBG_log("assembling ocsp request");
	dntoa(buf, BUF_LEN, location->issuer);
	DBG_log("issuer: '%s'", buf);
	if (location->authKeyID.ptr != NULL)
	{
	    datatot(location->authKeyID.ptr, location->authKeyID.len, ':'
		, buf, BUF_LEN);
	    DBG_log("authkey: %s", buf);
	}
    )
    lock_certs_and_keys("build_ocsp_request");

    /* looks for requestor cert and matching private key */
    has_requestor_cert = get_ocsp_requestor_cert(location);

    /* build content */
    tbsRequest = build_tbs_request(location, has_requestor_cert);

    /* sign tbsReuqest */
    signature = (has_requestor_cert)? build_signature(tbsRequest)
				    : empty_chunk;

    unlock_certs_and_keys("build_ocsp_request");

    /* build ocsp request */
    pos = build_asn1_object(&request, ASN1_SEQUENCE
	    , tbsRequest.len + signature.len);
    mv_chunk(&pos, tbsRequest);
    mv_chunk(&pos, signature);

    return request;
}

/*
 * check if the OCSP response has a valid signature
 */
static bool
valid_ocsp_response(response_t *res)
{
    int pathlen;
    x509cert_t *authcert;

    lock_authcert_list("valid_ocsp_response");
    
    authcert = get_authcert(res->responder_id_name, empty_chunk
		    , res->responder_id_key, AUTH_OCSP | AUTH_CA);

    if (authcert == NULL)
    {
	plog("no matching ocsp signer cert found");
	unlock_authcert_list("valid_ocsp_response");
	return FALSE;
    }
    DBG(DBG_CONTROL,
	DBG_log("ocsp signer cert found")
    )

    if (!check_signature(res->tbs, res->signature,
			 res->algorithm, authcert))
    {
	plog("signature of ocsp response is invalid");
	unlock_authcert_list("valid_ocsp_response");
	return FALSE;
    }
    DBG(DBG_CONTROL,
	DBG_log("signature of ocsp response is valid")
    )


    for (pathlen = 0; pathlen < MAX_CA_PATH_LEN; pathlen++)
    {
	char buf[BUF_LEN];
	err_t ugh = NULL;
	time_t until;

	x509cert_t *cert = authcert;

	DBG(DBG_CONTROL,
	    dntoa(buf, BUF_LEN, cert->subject);
	    DBG_log("subject: '%s'",buf);
	    dntoa(buf, BUF_LEN, cert->issuer);
	    DBG_log("issuer:  '%s'",buf);
	    if (cert->authKeyID.ptr != NULL)
	    {
		datatot(cert->authKeyID.ptr, cert->authKeyID.len, ':'
		    , buf, BUF_LEN);
		DBG_log("authkey:  %s", buf);
	    }
	)

	ugh = check_validity(authcert, &until);

	if (ugh != NULL)
	{
	    plog("%s", ugh);
	    unlock_authcert_list("valid_ocsp_response");
	    return FALSE;
        }
	
	DBG(DBG_CONTROL,
	    DBG_log("certificate is valid")
	)
	
	authcert = get_authcert(cert->issuer, cert->authKeySerialNumber
	    , cert->authKeyID, AUTH_CA);

	if (authcert == NULL)
	{
	    plog("issuer cacert not found");
	    unlock_authcert_list("valid_ocsp_response");
	    return FALSE;
	}
	DBG(DBG_CONTROL,
	    DBG_log("issuer cacert found")
	)

	if (!check_signature(cert->tbsCertificate, cert->signature,
			     cert->algorithm, authcert))
	{
	    plog("certificate signature is invalid");
	    unlock_authcert_list("valid_ocsp_response");
	    return FALSE;
	}
	DBG(DBG_CONTROL,
	    DBG_log("certificate signature is valid")
	)

	/* check if cert is self-signed */
	if (same_dn(cert->issuer, cert->subject))
	{
	    DBG(DBG_CONTROL,
		DBG_log("reached self-signed root ca")
	    )
	    unlock_authcert_list("valid_ocsp_response");
            return TRUE;
	}
    }
    plog("maximum ca path length of %d levels exceeded", MAX_CA_PATH_LEN);
    unlock_authcert_list("valid_ocsp_response");
    return FALSE;

}

/*
 * parse a basic OCSP response
 */
static bool
parse_basic_ocsp_response(chunk_t blob, int level0, response_t *res)
{
    u_int level, version, extn_oid = 0;
    char buf[BUF_LEN];
    asn1_ctx_t ctx;
    bool critical;
    chunk_t object;
    u_int objectID = 0;

    asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

    while (objectID < BASIC_RESPONSE_ROOF)
    {
	if (!extract_object(basicResponseObjects, &objectID, &object, &level, &ctx))
	    return FALSE;
	
	switch (objectID)
	{
	case BASIC_RESPONSE_TBS_DATA:
	    res->tbs = object;
	    break;
	case BASIC_RESPONSE_VERSION:
	    version = (object.len)? (1 + (u_int)*object.ptr) : 1;
	    if (version != OCSP_BASIC_RESPONSE_VERSION)
	    {
		plog("wrong ocsp basic response version (version= %i)",  version);
		return FALSE;
	    }
	    break;
	case BASIC_RESPONSE_ID_BY_NAME:
	    res->responder_id_name = object;
	    DBG(DBG_PARSING,
		dntoa(buf, BUF_LEN, object);
		DBG_log("  '%s'",buf)
	    )
	    break;
	case BASIC_RESPONSE_ID_BY_KEY:
	    res->responder_id_key = object;
	    break;
	case BASIC_RESPONSE_PRODUCED_AT:
	    res->produced_at = asn1totime(&object, ASN1_GENERALIZEDTIME);
	    break;
	case BASIC_RESPONSE_RESPONSES:
	    res->responses = object;
	    break;
	case BASIC_RESPONSE_EXT_ID:
	    extn_oid = known_oid(object);
	    break;
	case BASIC_RESPONSE_CRITICAL:
	    critical = object.len && *object.ptr;
	    DBG(DBG_PARSING,
		DBG_log("  %s",(critical)?"TRUE":"FALSE");
	    )
	    break;
	case BASIC_RESPONSE_EXT_VALUE:
	    if (extn_oid == OID_NONCE)
		res->nonce = object;
	    break;
	case BASIC_RESPONSE_ALGORITHM:
	    res->algorithm = parse_algorithmIdentifier(object, level+1);
	    break;
	case BASIC_RESPONSE_SIGNATURE:
	    res->signature = object;
	    break;
	case BASIC_RESPONSE_CERTIFICATE:
	    {
		chunk_t blob;
		x509cert_t *cert = alloc_thing(x509cert_t, "ocspcert");

		clonetochunk(blob, object.ptr, object.len, "ocspcert blob");
		*cert = empty_x509cert;

                if (parse_x509cert(blob, level+1, cert)
                    && cert->isOcspSigner
                    && trust_authcert_candidate(cert, NULL))
		{
		    add_authcert(cert, AUTH_OCSP);
		}
		else
		{
		    DBG(DBG_CONTROL | DBG_PARSING,
			DBG_log("embedded ocsp certificate rejected")
		    )
		    free_x509cert(cert);
		}
	    }
	    break;
	}
	objectID++;
    }
    return TRUE;
}


/*
 * parse an ocsp response and return the result as a response_t struct
 */
static response_status
parse_ocsp_response(chunk_t blob, response_t * res)
{
    asn1_ctx_t ctx;
    chunk_t object;
    u_int level;
    u_int objectID = 0;

    response_status rStatus = STATUS_INTERNALERROR;
    u_int ocspResponseType = 0;

    asn1_init(&ctx, blob, 0, FALSE, DBG_RAW);

    while (objectID < OCSP_RESPONSE_ROOF)
    {
	if (!extract_object(ocspResponseObjects, &objectID, &object, &level, &ctx))
	    return STATUS_INTERNALERROR;

	switch (objectID) {
	case OCSP_RESPONSE_STATUS:
	    rStatus = (response_status) *object.ptr;

	    switch (rStatus)
	    {
	    case STATUS_SUCCESSFUL:
		break;
	    case STATUS_MALFORMEDREQUEST:
	    case STATUS_INTERNALERROR:
	    case STATUS_TRYLATER:
	    case STATUS_SIGREQUIRED:
	    case STATUS_UNAUTHORIZED:
		plog("ocsp response: server said '%s'"
		    , response_status_names[rStatus]);
		return rStatus;
	    default:
		return STATUS_INTERNALERROR;
	    }
	    break;
	case OCSP_RESPONSE_TYPE:
	    ocspResponseType = known_oid(object);
	    break;
	case OCSP_RESPONSE:
	    {
		switch (ocspResponseType) {
		case OID_BASIC:
		    if (!parse_basic_ocsp_response(object, level+1, res))
			return STATUS_INTERNALERROR;
		    break;
		default:
		    DBG(DBG_CONTROL,
			DBG_log("ocsp response is not of type BASIC");
			DBG_dump_chunk("ocsp response OID: ", object);
		    )
		    return STATUS_INTERNALERROR;
		}
	    }
	    break;
	}
	objectID++;
    }
    return rStatus;
}

/*
 * parse a basic OCSP response
 */
static bool
parse_ocsp_single_response(chunk_t blob, int level0, single_response_t *sres)
{
    u_int level, extn_oid;
    asn1_ctx_t ctx;
    bool critical;
    chunk_t object;
    u_int objectID = 0;

    asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

    while (objectID < SINGLE_RESPONSE_ROOF)
    {
	if (!extract_object(singleResponseObjects, &objectID, &object, &level, &ctx))
	    return FALSE;

	switch (objectID)
	{
	case SINGLE_RESPONSE_ALGORITHM:
	    sres->hash_algorithm = parse_algorithmIdentifier(object, level+1);
	    break;
	case SINGLE_RESPONSE_ISSUER_NAME_HASH:
	    sres->issuer_name_hash = object;
	    break;
	case SINGLE_RESPONSE_ISSUER_KEY_HASH:
	    sres->issuer_key_hash = object;
	    break;
	case SINGLE_RESPONSE_SERIAL_NUMBER:
	    sres->serialNumber = object;
	    break;
	case SINGLE_RESPONSE_CERT_STATUS_GOOD:
	    sres->status = CERT_GOOD;
	    break;
	case SINGLE_RESPONSE_CERT_STATUS_REVOKED:
	    sres->status = CERT_REVOKED;
	    break;
	case SINGLE_RESPONSE_CERT_STATUS_REVOCATION_TIME:
	    sres->revocation_time = asn1totime(&object, ASN1_GENERALIZEDTIME);
	    break;
	case SINGLE_RESPONSE_CERT_STATUS_CRL_REASON:
	    sres->reason = *object.ptr;
	    break;
	case SINGLE_RESPONSE_CERT_STATUS_UNKNOWN:
	    sres->status = CERT_UNKNOWN;
	    break;
	case SINGLE_RESPONSE_THIS_UPDATE:
	    sres->thisUpdate = asn1totime(&object, ASN1_GENERALIZEDTIME);
	    break;
	case SINGLE_RESPONSE_NEXT_UPDATE:
	    sres->nextUpdate = asn1totime(&object, ASN1_GENERALIZEDTIME);
	    break;
	case SINGLE_RESPONSE_EXT_ID:
	    extn_oid = known_oid(object);
	    break;
	case SINGLE_RESPONSE_CRITICAL:
	    critical = object.len && *object.ptr;
	    DBG(DBG_PARSING,
		DBG_log("  %s",(critical)?"TRUE":"FALSE");
	    )
	case SINGLE_RESPONSE_EXT_VALUE:
	    break;
	}
	objectID++;
    }
    return TRUE;
}

/*
 * add an ocsp location to a chained list
 */
ocsp_location_t*
add_ocsp_location(const ocsp_location_t *loc, ocsp_location_t **chain)
{
    ocsp_location_t *location = alloc_thing(ocsp_location_t, "ocsp location");

    /* unshare location fields */
    clonetochunk(location->issuer
		, loc->issuer.ptr, loc->issuer.len
		, "ocsp issuer");

    clonetochunk(location->authNameID
		, loc->authNameID.ptr, loc->authNameID.len
		, "ocsp authNameID");

    if (loc->authKeyID.ptr == NULL)
	location->authKeyID = empty_chunk;
    else
	clonetochunk(location->authKeyID
		, loc->authKeyID.ptr, loc->authKeyID.len
		, "ocsp authKeyID");

    if (loc->authKeySerialNumber.ptr == NULL)
	location->authKeySerialNumber = empty_chunk;
    else
	clonetochunk(location->authKeySerialNumber
    		, loc->authKeySerialNumber.ptr, loc->authKeySerialNumber.len
		, "ocsp authKeySerialNumber");

    clonetochunk(location->uri
		, loc->uri.ptr, loc->uri.len
		, "ocsp uri");

    location->certinfo = NULL;

    /* insert new ocsp location in front of chain */
    location->next = *chain;
    *chain = location;

    DBG(DBG_CONTROL,
	DBG_log("new ocsp location added")
    )

    return location;
}

/*
 * add a certinfo struct to a chained list
 */
void
add_certinfo(ocsp_location_t *loc, ocsp_certinfo_t *info, ocsp_location_t **chain
    , bool request)
{
    ocsp_location_t *location;
    ocsp_certinfo_t *certinfo, **certinfop;
    char buf[BUF_LEN];
    time_t now;
    int cmp = -1;

    location = get_ocsp_location(loc, *chain);
    if (location == NULL)
	location = add_ocsp_location(loc, chain);

    /* traverse list of certinfos in increasing order */
    certinfop = &location->certinfo;
    certinfo = *certinfop;

    while (certinfo != NULL)
    {
	cmp = cmp_chunk(info->serialNumber, certinfo->serialNumber);
	if (cmp <= 0)
	    break;
	certinfop = &certinfo->next;
	certinfo = *certinfop;
    }

    if (cmp != 0)
    {
	/* add a new certinfo entry */
	ocsp_certinfo_t *cnew = alloc_thing(ocsp_certinfo_t, "ocsp certinfo");
	clonetochunk(cnew->serialNumber, info->serialNumber.ptr
	    , info->serialNumber.len, "serialNumber");
	cnew->next = certinfo;
	*certinfop = cnew;
	certinfo = cnew;
    }
	
    DBG(DBG_CONTROL,
	datatot(info->serialNumber.ptr, info->serialNumber.len, ':'
	    , buf, BUF_LEN);
	DBG_log("ocsp %s for serial %s %s"
	    , request?"fetch request":"certinfo"
	    , buf
	    , (cmp == 0)? (request?"already exists":"updated"):"added")
    )

    time(&now);
   
    if (request)
    {
	certinfo->status = CERT_UNDEFINED;
	
	if (cmp != 0)
	    certinfo->thisUpdate = now;

	certinfo->nextUpdate = UNDEFINED_TIME;
    }
    else
    {
	certinfo->status = info->status;

	certinfo->thisUpdate = (info->thisUpdate != UNDEFINED_TIME)?
	    info->thisUpdate : now;

	certinfo->once = (info->nextUpdate == UNDEFINED_TIME);

	certinfo->nextUpdate = (certinfo->once)?
	    (now + OCSP_DEFAULT_VALID_TIME) : info->nextUpdate;
    }
}

/*
 * process received ocsp single response and add it to ocsp cache
 */
static void
process_single_response(ocsp_location_t *location, single_response_t *sres)
{
    ocsp_certinfo_t *certinfo, **certinfop;
    int cmp = 0;

    if (sres->hash_algorithm != OID_SHA1)
    {
	plog("only SHA-1 hash supported in OCSP single response");
	return;
    }
    if (!(same_chunk(sres->issuer_name_hash, location->authNameID)
    &&   same_chunk(sres->issuer_key_hash, location->authKeyID)))
    {
	plog("ocsp single response has wrong issuer");
	return;
    }
    
    /* traverse list of certinfos in increasing order */
    certinfop = &location->certinfo;
    certinfo = *certinfop;

    while (certinfo != NULL)
    {
	cmp = cmp_chunk(sres->serialNumber, certinfo->serialNumber);
	if (cmp <= 0)
	    break;
	certinfop = &certinfo->next;
	certinfo = *certinfop;
    }

    if (cmp != 0)
    {
	plog("received unrequested cert status from ocsp server");
	return;
    }

    /* unlink cert from ocsp fetch request list */
    *certinfop = certinfo->next;
    
    /* update certinfo using the single response information */
    certinfo->thisUpdate = sres->thisUpdate;
    certinfo->nextUpdate = sres->nextUpdate;
    certinfo->status = sres->status;
    
    /* add or update certinfo in ocsp cache */
    lock_ocsp_cache("process_single_response");
    add_certinfo(location, certinfo, &ocsp_cache, FALSE);
    unlock_ocsp_cache("process_single_response");

    /* free certinfo unlinked from ocsp fetch request list */
    free_certinfo(certinfo);

}

/*
 *  parse and verify ocsp response and update the ocsp cache
 */
void
parse_ocsp(ocsp_location_t *location, chunk_t blob)
{
    response_t res = empty_response;

    /* parse the ocsp response without looking at the single responses yet */
    response_status status = parse_ocsp_response(blob, &res);

    if (status != STATUS_SUCCESSFUL)
    {
	plog("error in ocsp response");
	return;
    }
    /* check if there was a nonce in the request */
    if (location->nonce.ptr != NULL && res.nonce.ptr == NULL)
    {
	plog("ocsp response contains no nonce, replay attack possible");
    }
    /* check if the nonce is identical */
    if (res.nonce.ptr != NULL && !same_chunk(res.nonce, location->nonce))
    {
	plog("invalid nonce in ocsp response");
	return;
    }
    /* check if the response is signed by a trusted key */
    if (!valid_ocsp_response(&res))
    {
	plog("invalid ocsp response");
	return;
    }
    DBG(DBG_CONTROL,
	DBG_log("valid ocsp response")
    )

    /* now parse the single responses one at a time */
    {
	u_int level;
	asn1_ctx_t ctx;
	chunk_t object;
	u_int objectID = 0;

	asn1_init(&ctx, res.responses, 0, FALSE, DBG_RAW);

	while (objectID < RESPONSES_ROOF)
	{
	    if (!extract_object(responsesObjects, &objectID, &object, &level, &ctx))
		return;
	    
	    if (objectID == RESPONSES_SINGLE_RESPONSE)
	    {
		single_response_t sres = empty_single_response;

		if (parse_ocsp_single_response(object, level+1, &sres))
		{
		    process_single_response(location, &sres);
		}
	    }
	    objectID++;
	}
    }
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
