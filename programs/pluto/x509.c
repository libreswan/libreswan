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
 * RCSID $Id: x509.c,v 1.23.18.3 2005/07/26 02:11:23 ken Exp $
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <sys/types.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include <sys/queue.h>

#include "constants.h"
#include "oswlog.h"

#include "defs.h"
#include "log.h"
#include "id.h"
#include "asn1.h"
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
#include "x509more.h"
#include "paths.h"

/* chained lists of X.509 host/user and ca certificates and crls */

static x509cert_t *x509certs   = NULL;
static x509cert_t *x509authcerts = NULL;
static x509crl_t  *x509crls    = NULL;

/* ASN.1 definition of a basicConstraints extension */

static const asn1Object_t basicConstraintsObjects[] = {
  { 0, "basicConstraints",		ASN1_SEQUENCE,     ASN1_NONE }, /*  0 */
  { 1,   "CA",				ASN1_BOOLEAN,      ASN1_DEF |
							   ASN1_BODY }, /*  1 */
  { 1,   "pathLenConstraint",		ASN1_INTEGER,      ASN1_OPT |
							   ASN1_BODY }, /*  2 */
  { 1,   "end opt",			ASN1_EOC,          ASN1_END  }  /*  3 */
};

#define BASIC_CONSTRAINTS_CA	1
#define BASIC_CONSTRAINTS_ROOF	4

/* ASN.1 definition of time */

static const asn1Object_t timeObjects[] = {
  { 0,   "utcTime",			ASN1_UTCTIME,         ASN1_OPT |
							      ASN1_BODY }, /*  0 */
  { 0,   "end opt",			ASN1_EOC,             ASN1_END  }, /*  1 */
  { 0,   "generalizeTime",		ASN1_GENERALIZEDTIME, ASN1_OPT |
							      ASN1_BODY }, /*  2 */
  { 0,   "end opt",			ASN1_EOC,             ASN1_END  }  /*  3 */
};

#define TIME_UTC		0
#define TIME_GENERALIZED	2
#define TIME_ROOF		4

/* ASN.1 definiton of an algorithmIdentifier */

static const asn1Object_t algorithmIdentifierObjects[] = {
  { 0, "algorithmIdentifier",		ASN1_SEQUENCE,	   ASN1_NONE }, /*  0 */
  { 1,   "algorithm",			ASN1_OID,	   ASN1_BODY }  /*  1 */
};

#define ALGORITHM_IDENTIFIER_ALG	1
#define ALGORITHM_IDENTIFIER_ROOF	2

/* ASN.1 definition of a keyIdentifier */

static const asn1Object_t keyIdentifierObjects[] = {
  { 0,   "keyIdentifier",		ASN1_OCTET_STRING, ASN1_BODY }  /*  0 */
};

/* ASN.1 definition of a authorityKeyIdentifier extension */

static const asn1Object_t authorityKeyIdentifierObjects[] = {
  { 0,   "authorityKeyIdentifier",	ASN1_SEQUENCE,     ASN1_NONE }, /*  0 */
  { 1,     "keyIdentifier",		ASN1_CONTEXT_S_0,  ASN1_OPT |
							   ASN1_OBJ  }, /*  1 */
  { 1,     "end opt",			ASN1_EOC,          ASN1_END  }, /*  2 */
  { 1,     "authorityCertIssuer",	ASN1_CONTEXT_C_1,  ASN1_OPT |
							   ASN1_OBJ  }, /*  3 */
  { 1,     "end opt",			ASN1_EOC,          ASN1_END  }, /*  4 */
  { 1,     "authorityCertSerialNumber",	ASN1_CONTEXT_S_2,  ASN1_OPT |
							   ASN1_BODY }, /*  5 */
  { 1,     "end opt",			ASN1_EOC,          ASN1_END  }  /*  6 */
};

#define AUTH_KEY_ID_KEY_ID		1
#define AUTH_KEY_ID_CERT_ISSUER		3
#define AUTH_KEY_ID_CERT_SERIAL		5
#define AUTH_KEY_ID_ROOF		7

/* ASN.1 definition of a authorityInfoAccess extension */

static const asn1Object_t authorityInfoAccessObjects[] = {
  { 0,   "authorityInfoAccess",         ASN1_SEQUENCE,     ASN1_LOOP }, /*  0 */
  { 1,     "accessDescription",         ASN1_SEQUENCE,     ASN1_NONE }, /*  1 */
  { 2,       "accessMethod",            ASN1_OID,          ASN1_BODY }, /*  2 */
  { 2,       "accessLocation",          ASN1_EOC,          ASN1_RAW  }, /*  3 */
  { 0,   "end loop",                    ASN1_EOC,          ASN1_END  }  /*  4 */
};

#define AUTH_INFO_ACCESS_METHOD		2
#define AUTH_INFO_ACCESS_LOCATION	3
#define AUTH_INFO_ACCESS_ROOF		5

/* ASN.1 definition of a extendedKeyUsage extension */

static const asn1Object_t extendedKeyUsageObjects[] = {
  { 0, "extendedKeyUsage",		ASN1_SEQUENCE,     ASN1_LOOP }, /*  0 */
  { 1,   "keyPurposeID",		ASN1_OID,     	   ASN1_BODY }, /*  1 */
  { 0, "end loop",			ASN1_EOC,	   ASN1_END  }, /*  2 */
};

#define EXT_KEY_USAGE_PURPOSE_ID	1
#define EXT_KEY_USAGE_ROOF		3

/* ASN.1 definition of generalNames */

static const asn1Object_t generalNamesObjects[] = {
  { 0, "generalNames",			ASN1_SEQUENCE,     ASN1_LOOP }, /*  0 */
  { 1,   "generalName",			ASN1_EOC,          ASN1_RAW  }, /*  1 */
  { 0, "end loop",			ASN1_EOC,          ASN1_END  }  /*  2 */
};

#define GENERAL_NAMES_GN	1
#define GENERAL_NAMES_ROOF	3

/* ASN.1 definition of generalName */

static const asn1Object_t generalNameObjects[] = {
  { 0,   "otherName",			ASN1_CONTEXT_C_0,  ASN1_OPT |
							   ASN1_BODY }, /*  0 */
  { 0,   "end choice",			ASN1_EOC,          ASN1_END  }, /*  1 */
  { 0,   "rfc822Name",			ASN1_CONTEXT_S_1,  ASN1_OPT |
							   ASN1_BODY }, /*  2 */
  { 0,   "end choice",			ASN1_EOC,          ASN1_END  }, /*  3 */
  { 0,   "dnsName",			ASN1_CONTEXT_S_2,  ASN1_OPT |
							   ASN1_BODY }, /*  4 */
  { 0,   "end choice",			ASN1_EOC,          ASN1_END  }, /*  5 */
  { 0,   "x400Address",			ASN1_CONTEXT_S_3,  ASN1_OPT |
							   ASN1_BODY }, /*  6 */
  { 0,   "end choice",			ASN1_EOC,          ASN1_END  }, /*  7 */
  { 0,   "directoryName",		ASN1_CONTEXT_C_4,  ASN1_OPT |
							   ASN1_BODY }, /*  8 */
  { 0,   "end choice",			ASN1_EOC,          ASN1_END  }, /*  9 */
  { 0,   "ediPartyName",		ASN1_CONTEXT_C_5,  ASN1_OPT |
							   ASN1_BODY }, /* 10 */
  { 0,   "end choice",			ASN1_EOC,          ASN1_END  }, /* 11 */
  { 0,   "uniformResourceIdentifier",	ASN1_CONTEXT_S_6,  ASN1_OPT |
							   ASN1_BODY }, /* 12 */
  { 0,   "end choice",			ASN1_EOC,          ASN1_END  }, /* 13 */
  { 0,   "ipAddress",			ASN1_CONTEXT_S_7,  ASN1_OPT |
							   ASN1_BODY }, /* 14 */
  { 0,   "end choice",			ASN1_EOC,          ASN1_END  }, /* 15 */
  { 0,   "registeredID",		ASN1_CONTEXT_S_8,  ASN1_OPT |
							   ASN1_BODY }, /* 16 */
  { 0,   "end choice",			ASN1_EOC,          ASN1_END  }  /* 17 */
};

#define GN_OBJ_OTHER_NAME	 0
#define GN_OBJ_RFC822_NAME	 2
#define GN_OBJ_DNS_NAME		 4
#define GN_OBJ_X400_ADDRESS	 6
#define GN_OBJ_DIRECTORY_NAME	 8
#define GN_OBJ_EDI_PARTY_NAME	10
#define GN_OBJ_URI		12
#define GN_OBJ_IP_ADDRESS	14
#define GN_OBJ_REGISTERED_ID	16
#define GN_OBJ_ROOF		18

/* ASN.1 definition of crlDistributionPoints */

static const asn1Object_t crlDistributionPointsObjects[] = {
  { 0, "crlDistributionPoints",		ASN1_SEQUENCE,     ASN1_LOOP }, /*  0 */
  { 1,   "DistributionPoint",		ASN1_SEQUENCE,     ASN1_NONE }, /*  1 */
  { 2,     "distributionPoint",		ASN1_CONTEXT_C_0,  ASN1_OPT |
							   ASN1_LOOP }, /*  2 */
  { 3,       "fullName",		ASN1_CONTEXT_C_0,  ASN1_OPT |
							   ASN1_OBJ  }, /*  3 */
  { 3,       "end choice",		ASN1_EOC,          ASN1_END  }, /*  4 */
  { 3,       "nameRelativeToCRLIssuer",	ASN1_CONTEXT_C_1,  ASN1_OPT |
							   ASN1_BODY }, /*  5 */
  { 3,       "end choice",		ASN1_EOC,          ASN1_END  }, /*  6 */
  { 2,     "end opt",			ASN1_EOC,          ASN1_END  }, /*  7 */
  { 2,     "reasons",			ASN1_CONTEXT_C_1,  ASN1_OPT |
							   ASN1_BODY }, /*  8 */
  { 2,     "end opt",			ASN1_EOC,          ASN1_END  }, /*  9 */
  { 2,     "crlIssuer",			ASN1_CONTEXT_C_2,  ASN1_OPT |
							   ASN1_BODY }, /* 10 */
  { 2,     "end opt",			ASN1_EOC,          ASN1_END  }, /* 11 */
  { 0, "end loop",			ASN1_EOC,          ASN1_END  }, /* 12 */
};

#define CRL_DIST_POINTS_FULLNAME	 3
#define CRL_DIST_POINTS_ROOF		13

/* ASN.1 definition of an X.509v3 certificate */

static const asn1Object_t certObjects[] = {
  { 0, "certificate",			ASN1_SEQUENCE,     ASN1_OBJ  }, /*  0 */
  { 1,   "tbsCertificate",		ASN1_SEQUENCE,     ASN1_OBJ  }, /*  1 */
  { 2,     "DEFAULT v1",		ASN1_CONTEXT_C_0,  ASN1_DEF  }, /*  2 */
  { 3,       "version",			ASN1_INTEGER,      ASN1_BODY }, /*  3 */
  { 2,     "serialNumber",		ASN1_INTEGER,      ASN1_BODY }, /*  4 */
  { 2,     "signature",			ASN1_EOC,          ASN1_RAW  }, /*  5 */
  { 2,     "issuer",			ASN1_SEQUENCE,     ASN1_OBJ  }, /*  6 */
  { 2,     "validity",			ASN1_SEQUENCE,     ASN1_NONE }, /*  7 */
  { 3,       "notBefore",		ASN1_EOC,          ASN1_RAW  }, /*  8 */
  { 3,       "notAfter",		ASN1_EOC,          ASN1_RAW  }, /*  9 */
  { 2,     "subject",			ASN1_SEQUENCE,     ASN1_OBJ  }, /* 10 */
  { 2,     "subjectPublicKeyInfo",	ASN1_SEQUENCE,     ASN1_NONE }, /* 11 */
  { 3,       "algorithm",		ASN1_EOC,          ASN1_RAW  }, /* 12 */
  { 3,       "subjectPublicKey",	ASN1_BIT_STRING,   ASN1_NONE }, /* 13 */
  { 4,         "RSAPublicKey",		ASN1_SEQUENCE,     ASN1_NONE }, /* 14 */
  { 5,           "modulus",		ASN1_INTEGER,      ASN1_BODY }, /* 15 */
  { 5,           "publicExponent",	ASN1_INTEGER,      ASN1_BODY }, /* 16 */
  { 2,     "issuerUniqueID",		ASN1_CONTEXT_C_1,  ASN1_OPT  }, /* 17 */
  { 2,     "end opt",			ASN1_EOC,          ASN1_END  }, /* 18 */
  { 2,     "subjectUniqueID",		ASN1_CONTEXT_C_2,  ASN1_OPT  }, /* 19 */
  { 2,     "end opt",			ASN1_EOC,          ASN1_END  }, /* 20 */
  { 2,     "optional extensions",	ASN1_CONTEXT_C_3,  ASN1_OPT  }, /* 21 */
  { 3,       "extensions",		ASN1_SEQUENCE,     ASN1_LOOP }, /* 22 */
  { 4,         "extension",		ASN1_SEQUENCE,     ASN1_NONE }, /* 23 */
  { 5,           "extnID",		ASN1_OID,          ASN1_BODY }, /* 24 */
  { 5,           "critical",		ASN1_BOOLEAN,      ASN1_DEF |
							   ASN1_BODY }, /* 25 */
  { 5,           "extnValue",		ASN1_OCTET_STRING, ASN1_BODY }, /* 26 */
  { 3,       "end loop",		ASN1_EOC,          ASN1_END  }, /* 27 */
  { 2,     "end opt",			ASN1_EOC,          ASN1_END  }, /* 28 */
  { 1,   "signatureAlgorithm",		ASN1_EOC,          ASN1_RAW  }, /* 29 */
  { 1,   "signatureValue",		ASN1_BIT_STRING,   ASN1_BODY }  /* 30 */
};

#define X509_OBJ_CERTIFICATE			 0
#define X509_OBJ_TBS_CERTIFICATE		 1
#define X509_OBJ_VERSION			 3
#define X509_OBJ_SERIAL_NUMBER			 4
#define X509_OBJ_SIG_ALG			 5
#define X509_OBJ_ISSUER 			 6
#define X509_OBJ_NOT_BEFORE			 8
#define X509_OBJ_NOT_AFTER			 9
#define X509_OBJ_SUBJECT			10
#define X509_OBJ_SUBJECT_PUBLIC_KEY_ALGORITHM	12
#define X509_OBJ_SUBJECT_PUBLIC_KEY		13
#define X509_OBJ_MODULUS			15
#define X509_OBJ_PUBLIC_EXPONENT		16
#define X509_OBJ_EXTN_ID			24
#define X509_OBJ_CRITICAL			25
#define X509_OBJ_EXTN_VALUE			26
#define X509_OBJ_ALGORITHM			29
#define X509_OBJ_SIGNATURE			30
#define X509_OBJ_ROOF				31


/* ASN.1 definition of an X.509 certificate list */

static const asn1Object_t crlObjects[] = {
  { 0, "certificateList",		ASN1_SEQUENCE,     ASN1_OBJ  }, /*  0 */
  { 1,   "tbsCertList",			ASN1_SEQUENCE,     ASN1_OBJ  }, /*  1 */
  { 2,     "version",			ASN1_INTEGER,      ASN1_OPT |
							   ASN1_BODY }, /*  2 */
  { 2,     "end opt",			ASN1_EOC,          ASN1_END  }, /*  3 */
  { 2,     "signature",			ASN1_EOC,          ASN1_RAW  }, /*  4 */
  { 2,     "issuer",			ASN1_SEQUENCE,     ASN1_OBJ  }, /*  5 */
  { 2,     "thisUpdate",		ASN1_EOC,          ASN1_RAW  }, /*  6 */
  { 2,     "nextUpdate",		ASN1_EOC,          ASN1_RAW  }, /*  7 */
  { 2,     "revokedCertificates",	ASN1_SEQUENCE,     ASN1_OPT |
							   ASN1_LOOP }, /*  8 */
  { 3,       "certList",		ASN1_SEQUENCE,     ASN1_NONE }, /*  9 */
  { 4,         "userCertificate",	ASN1_INTEGER,      ASN1_BODY }, /* 10 */
  { 4,         "revocationDate",	ASN1_EOC,          ASN1_RAW  }, /* 11 */
  { 4,         "crlEntryExtensions",	ASN1_SEQUENCE,     ASN1_OPT |
							   ASN1_LOOP }, /* 12 */
  { 5,           "extension",		ASN1_SEQUENCE,     ASN1_NONE }, /* 13 */
  { 6,             "extnID",		ASN1_OID,          ASN1_BODY }, /* 14 */
  { 6,             "critical",		ASN1_BOOLEAN,      ASN1_DEF |
							   ASN1_BODY }, /* 15 */
  { 6,             "extnValue",		ASN1_OCTET_STRING, ASN1_BODY }, /* 16 */
  { 4,         "end opt or loop",	ASN1_EOC,          ASN1_END  }, /* 17 */
  { 2,     "end opt or loop",		ASN1_EOC,          ASN1_END  }, /* 18 */
  { 2,     "optional extensions",	ASN1_CONTEXT_C_0,  ASN1_OPT  }, /* 19 */
  { 3,       "crlExtensions",		ASN1_SEQUENCE,     ASN1_LOOP }, /* 20 */
  { 4,         "extension",		ASN1_SEQUENCE,     ASN1_NONE }, /* 21 */
  { 5,           "extnID",		ASN1_OID,          ASN1_BODY }, /* 22 */
  { 5,           "critical",		ASN1_BOOLEAN,      ASN1_DEF |
							   ASN1_BODY }, /* 23 */
  { 5,           "extnValue",		ASN1_OCTET_STRING, ASN1_BODY }, /* 24 */
  { 3,       "end loop",		ASN1_EOC,          ASN1_END  }, /* 25 */
  { 2,     "end opt",			ASN1_EOC,          ASN1_END  }, /* 26 */
  { 1,   "signatureAlgorithm",		ASN1_EOC,          ASN1_RAW  }, /* 27 */
  { 1,   "signatureValue",		ASN1_BIT_STRING,   ASN1_BODY }  /* 28 */
 };

#define CRL_OBJ_CERTIFICATE_LIST		 0
#define CRL_OBJ_TBS_CERT_LIST			 1
#define CRL_OBJ_VERSION				 2
#define CRL_OBJ_SIG_ALG				 4
#define CRL_OBJ_ISSUER				 5
#define CRL_OBJ_THIS_UPDATE			 6
#define CRL_OBJ_NEXT_UPDATE			 7
#define CRL_OBJ_USER_CERTIFICATE		10
#define CRL_OBJ_REVOCATION_DATE			11
#define CRL_OBJ_CRL_ENTRY_CRITICAL		15
#define CRL_OBJ_EXTN_ID				22
#define CRL_OBJ_CRITICAL			23
#define CRL_OBJ_EXTN_VALUE			24
#define CRL_OBJ_ALGORITHM			27
#define CRL_OBJ_SIGNATURE			28
#define CRL_OBJ_ROOF				29


const x509cert_t empty_x509cert = {
      NULL        , /* *next */
    UNDEFINED_TIME, /* installed */
            0     , /* count */
      FALSE       , /* smartcard */
     AUTH_NONE    , /* authority_flags */
    { NULL, 0 }   , /* certificate */
    { NULL, 0 }   , /*   tbsCertificate */
            1	  , /*     version */
    { NULL, 0 }   , /*     serialNumber */
    OID_UNKNOWN   , /*     sigAlg */
    { NULL, 0 }   , /*     issuer */
                    /*     validity */
            0     , /*       notBefore */
            0     , /*       notAfter */
    { NULL, 0 }   , /*     subject */
                    /*     subjectPublicKeyInfo */
    OID_UNKNOWN   , /*       subjectPublicKeyAlgorithm */
                    /*       subjectPublicKey */
    { NULL, 0 }   , /*         modulus */
    { NULL, 0 }   , /*         publicExponent */
                    /*     issuerUniqueID */
                    /*     subjectUniqueID */
                    /*     extensions */
                    /*       extension */
                    /*         extnID */
                    /*         critical */
                    /*         extnValue */
      FALSE       , /*           isCA */
      FALSE       , /*           isOcspSigner */
    { NULL, 0 }   , /*           subjectKeyID */
    { NULL, 0 }   , /*           authKeyID */
    { NULL, 0 }   , /*           authKeySerialNumber */
    { NULL, 0 }   , /*           accessLocation */
      NULL        , /*           subjectAltName */
      NULL        , /*           crlDistributionPoints */
    OID_UNKNOWN   , /*   algorithm */
    { NULL, 0 }     /*   signature */
};

const x509crl_t empty_x509crl = {
      NULL        , /* *next */
    UNDEFINED_TIME, /* installed */
      NULL        , /* distributionPoints */
    { NULL, 0 }   , /* certificateList */
    { NULL, 0 }   , /*   tbsCertList */
            1     , /*     version */
    OID_UNKNOWN   , /*     sigAlg */
    { NULL, 0 }   , /*     issuer */
    UNDEFINED_TIME, /*     thisUpdate */
    UNDEFINED_TIME, /*     nextUpdate */
      NULL        , /*     revokedCertificates */
                    /*     crlExtensions */
                    /*       extension */
                    /*         extnID */
                    /*         critical */
                    /*         extnValue */
    { NULL, 0 }   , /*           authKeyID */
    { NULL, 0 }   , /*           authKeySerialNumber */
    OID_UNKNOWN   , /*   algorithm */
    { NULL, 0 }     /*   signature */
};


/* coding of X.501 distinguished name */

typedef struct {
    const u_char *name;
    chunk_t oid;
    u_char type;
} x501rdn_t;


/* X.501 acronyms for well known object identifiers (OIDs) */

static u_char oid_ND[]  = {0x02, 0x82, 0x06, 0x01,
			   0x0A, 0x07, 0x14};
static u_char oid_UID[] = {0x09, 0x92, 0x26, 0x89, 0x93,
			   0xF2, 0x2C, 0x64, 0x01, 0x01};
static u_char oid_DC[]  = {0x09, 0x92, 0x26, 0x89, 0x93,
			   0xF2, 0x2C, 0x64, 0x01, 0x19};
static u_char oid_CN[]  = {0x55, 0x04, 0x03};
static u_char oid_S[]   = {0x55, 0x04, 0x04};
static u_char oid_SN[]  = {0x55, 0x04, 0x05};
static u_char oid_C[]   = {0x55, 0x04, 0x06};
static u_char oid_L[]   = {0x55, 0x04, 0x07};
static u_char oid_ST[]  = {0x55, 0x04, 0x08};
static u_char oid_O[]   = {0x55, 0x04, 0x0A};
static u_char oid_OU[]  = {0x55, 0x04, 0x0B};
static u_char oid_T[]   = {0x55, 0x04, 0x0C};
static u_char oid_D[]   = {0x55, 0x04, 0x0D};
static u_char oid_N[]   = {0x55, 0x04, 0x29};
static u_char oid_G[]   = {0x55, 0x04, 0x2A};
static u_char oid_I[]   = {0x55, 0x04, 0x2B};
static u_char oid_ID[]  = {0x55, 0x04, 0x2D};
static u_char oid_E[]   = {0x2A, 0x86, 0x48, 0x86, 0xF7,
			   0x0D, 0x01, 0x09, 0x01};
static u_char oid_TCGID[] = {0x2B, 0x06, 0x01, 0x04, 0x01, 0x89,
			     0x31, 0x01, 0x01, 0x02, 0x02, 0x4B};

static const x501rdn_t x501rdns[] = {
  {"ND"           , {oid_ND,     7}, ASN1_PRINTABLESTRING},
  {"UID"          , {oid_UID,   10}, ASN1_PRINTABLESTRING},
  {"DC"           , {oid_DC,    10}, ASN1_PRINTABLESTRING},
  {"CN"           , {oid_CN,     3}, ASN1_PRINTABLESTRING},
  {"S"            , {oid_S,      3}, ASN1_PRINTABLESTRING},
  {"SN"           , {oid_SN,     3}, ASN1_PRINTABLESTRING},
  {"serialNumber" , {oid_SN,     3}, ASN1_PRINTABLESTRING},
  {"C"            , {oid_C,      3}, ASN1_PRINTABLESTRING},
  {"L"            , {oid_L,      3}, ASN1_PRINTABLESTRING},
  {"ST"           , {oid_ST,     3}, ASN1_PRINTABLESTRING},
  {"O"            , {oid_O,      3}, ASN1_PRINTABLESTRING},
  {"OU"           , {oid_OU,     3}, ASN1_PRINTABLESTRING},
  {"T"            , {oid_T,      3}, ASN1_PRINTABLESTRING},
  {"D"            , {oid_D,      3}, ASN1_PRINTABLESTRING},
  {"N"            , {oid_N,      3}, ASN1_PRINTABLESTRING},
  {"G"            , {oid_G,      3}, ASN1_PRINTABLESTRING},
  {"I"            , {oid_I,      3}, ASN1_PRINTABLESTRING},
  {"ID"           , {oid_ID,     3}, ASN1_PRINTABLESTRING},
  {"E"            , {oid_E,      9}, ASN1_IA5STRING},
  {"Email"        , {oid_E,      9}, ASN1_IA5STRING},
  {"emailAddress" , {oid_E,      9}, ASN1_IA5STRING},
  {"TCGID"        , {oid_TCGID, 12}, ASN1_PRINTABLESTRING}
};

#define X501_RDN_ROOF   22

/* Maximum length of ASN.1 distinquished name */

#define BUF_LEN	      512

static void
update_chunk(chunk_t *ch, int n)
{
    n = (n > -1 && n < (int)ch->len)? n : (int)ch->len-1;
    ch->ptr += n; ch->len -= n;
}


/*
 *  Pointer is set to the first RDN in a DN
 */
static err_t
init_rdn(chunk_t dn, chunk_t *rdn, chunk_t *attribute, bool *next)
{
    *rdn = empty_chunk;
    *attribute = empty_chunk;

    /* a DN is a SEQUENCE OF RDNs */

    if (*dn.ptr != ASN1_SEQUENCE)
    {
	return "DN is not a SEQUENCE";
    }

    rdn->len = asn1_length(&dn);

    if (rdn->len == ASN1_INVALID_LENGTH)
       return "Invalid RDN length";

    rdn->ptr = dn.ptr;

    /* are there any RDNs ? */
    *next = rdn->len > 0;

    return NULL;
}

/*
 *  Fetches the next RDN in a DN
 */
static err_t
get_next_rdn(chunk_t *rdn, chunk_t * attribute, chunk_t *oid, chunk_t *value
, asn1_t *type, bool *next)
{
    chunk_t body;

    /* initialize return values */
    *oid   = empty_chunk;
    *value = empty_chunk;

    /* if all attributes have been parsed, get next rdn */
    if (attribute->len <= 0)
    {
	/* an RDN is a SET OF attributeTypeAndValue */
	if (*rdn->ptr != ASN1_SET)
	    return "RDN is not a SET";

	attribute->len = asn1_length(rdn);

        if (attribute->len == ASN1_INVALID_LENGTH)
            return "Invalid attribute length";

	attribute->ptr = rdn->ptr;

	/* advance to start of next RDN */
	rdn->ptr += attribute->len;
	rdn->len -= attribute->len;
    }

    /* an attributeTypeAndValue is a SEQUENCE */
    if (*attribute->ptr != ASN1_SEQUENCE)
 	return "attributeTypeAndValue is not a SEQUENCE";

    /* extract the attribute body */
    body.len = asn1_length(attribute);


    if (body.len == ASN1_INVALID_LENGTH)
        return "Invalid attribute body length";


    body.ptr = attribute->ptr;
    
    /* advance to start of next attribute */
    attribute->ptr += body.len;
    attribute->len -= body.len;

    /* attribute type is an OID */
    if (*body.ptr != ASN1_OID)
	return "attributeType is not an OID";

    /* extract OID */
    oid->len = asn1_length(&body);
 
    if (oid->len == ASN1_INVALID_LENGTH)
        return "Invalid attribute OID length";


   oid->ptr = body.ptr;

    /* advance to the attribute value */
    body.ptr += oid->len;
    body.len -= oid->len;

    /* extract string type */
    *type = *body.ptr;

    /* extract string value */
    value->len = asn1_length(&body);

    if (value->len == ASN1_INVALID_LENGTH)
        return "Invalid attribute string length";

    value->ptr = body.ptr;

    /* are there any RDNs left? */
    *next = rdn->len > 0 || attribute->len > 0;

    return NULL;
}

/*
 *  Parses an ASN.1 distinguished name int its OID/value pairs
 */
static err_t
dn_parse(chunk_t dn, chunk_t *str)
{
    chunk_t rdn, oid, attribute, value;
    asn1_t type;
    int oid_code;
    bool next;
    bool first = TRUE;
    err_t ugh;

    if(dn.ptr == NULL) {
	const char *e = "(empty)";
	strncpy(str->ptr, e, str->len);
	update_chunk(str, strlen(e));
	return NULL;
    }
    ugh = init_rdn(dn, &rdn, &attribute, &next);

    if (ugh != NULL) /* a parsing error has occured */
        return ugh;

    while (next)
    {
	ugh = get_next_rdn(&rdn, &attribute, &oid, &value, &type, &next);

	if (ugh != NULL) /* a parsing error has occured */
	    return ugh;

	if (first)		/* first OID/value pair */
	    first = FALSE;
	else			/* separate OID/value pair by a comma */
	    update_chunk(str, snprintf(str->ptr,str->len,", "));

	/* print OID */
	oid_code = known_oid(oid);
	if (oid_code == OID_UNKNOWN)	/* OID not found in list */
	    hex_str(oid, str);
	else
	    update_chunk(str, snprintf(str->ptr,str->len,"%s",
			      oid_names[oid_code].name));

	/* print value */
	update_chunk(str, snprintf(str->ptr,str->len,"=%.*s",
			      (int)value.len,value.ptr));
    }
    return NULL;
}

/*
 *  Count the number of wildcard RDNs in a distinguished name
 */
int
dn_count_wildcards(chunk_t dn)
{
    chunk_t rdn, attribute, oid, value;
    asn1_t type;
    bool next;
    int wildcards = 0;

    err_t ugh = init_rdn(dn, &rdn, &attribute, &next);

    if (ugh != NULL) /* a parsing error has occured */
        return -1;

    while (next)
    {
	ugh = get_next_rdn(&rdn, &attribute, &oid, &value, &type, &next);
	
	if (ugh != NULL) /* a parsing error has occured */
	    return -1;
	if (value.len == 1 && *value.ptr == '*')
	    wildcards++; /* we have found a wildcard RDN */
    }
    return wildcards;
}

/*
 * Prints a binary string in hexadecimal form
 */
void
hex_str(chunk_t bin, chunk_t *str)
{
    u_int i;
    update_chunk(str, snprintf(str->ptr,str->len,"0x"));
    for (i=0; i < bin.len; i++)
	update_chunk(str, snprintf(str->ptr,str->len,"%02X",*bin.ptr++));
}


/*  Converts a binary DER-encoded ASN.1 distinguished name
 *  into LDAP-style human-readable ASCII format
 */
int
dntoa(char *dst, size_t dstlen, chunk_t dn)
{
    err_t ugh = NULL;
    chunk_t str;

    str.ptr = dst;
    str.len = dstlen;
    ugh = dn_parse(dn, &str);

    if (ugh != NULL) /* error, print DN as hex string */
    {
	DBG(DBG_PARSING,
	    DBG_log("error in DN parsing: %s", ugh)
	)
	str.ptr = dst;
	str.len = dstlen;
	hex_str(dn, &str);
    }
    return (int)(dstlen - str.len);
}

/*
 * Same as dntoa but prints a special string for a null dn
 */
int
dntoa_or_null(char *dst, size_t dstlen, chunk_t dn, const char* null_dn)
{
    if (dn.ptr == NULL)
	return snprintf(dst, dstlen, "%s", null_dn);
    else
	return dntoa(dst, dstlen, dn);
}

/*  Converts an LDAP-style human-readable ASCII-encoded
 *  ASN.1 distinguished name into binary DER-encoded format
 */
err_t
atodn(char *src, chunk_t *dn)
{
  /* finite state machine for atodn */

    typedef enum {
	SEARCH_OID =	0,
	READ_OID =	1,
	SEARCH_NAME =	2,
	READ_NAME =	3,
        UNKNOWN_OID =	4
    } state_t;

    u_char oid_len_buf[3];
    u_char name_len_buf[3];
    u_char rdn_seq_len_buf[3];
    u_char rdn_set_len_buf[3];
    u_char dn_seq_len_buf[3];

    chunk_t asn1_oid_len     = { oid_len_buf,     0 };
    chunk_t asn1_name_len    = { name_len_buf,    0 };
    chunk_t asn1_rdn_seq_len = { rdn_seq_len_buf, 0 };
    chunk_t asn1_rdn_set_len = { rdn_set_len_buf, 0 };
    chunk_t asn1_dn_seq_len  = { dn_seq_len_buf,  0 };
    chunk_t oid  = empty_chunk;
    chunk_t name = empty_chunk;

    int whitespace  = 0;
    int rdn_seq_len = 0;
    int rdn_set_len = 0;
    int dn_seq_len  = 0;
    int pos         = 0;

    err_t ugh = NULL;

    u_char *dn_ptr = dn->ptr + 4;

    state_t state = SEARCH_OID;

    do
    {
        switch (state)
	{
	case SEARCH_OID:
	    if (*src != ' ' && *src != '/' && *src !=  ',')
	    {
		oid.ptr = src;
		oid.len = 1;
		state = READ_OID;
	    }
	    break;
	case READ_OID:
	    if (*src != ' ' && *src != '=')
		oid.len++;
	    else
	    {
		for (pos = 0; pos < X501_RDN_ROOF; pos++)
		{
		    if (strlen(x501rdns[pos].name) == oid.len &&
			strncasecmp(x501rdns[pos].name, oid.ptr, oid.len) == 0)
			break; /* found a valid OID */
		}
		if (pos == X501_RDN_ROOF)
		{
		    ugh = "unknown OID in ID_DER_ASN1_DN";
		    state = UNKNOWN_OID;
		    break;
		}
		code_asn1_length(x501rdns[pos].oid.len, &asn1_oid_len);

		/* reset oid and change state */
		oid = empty_chunk;
		state = SEARCH_NAME;
	    }
	    break;
	case SEARCH_NAME:
	    if (*src != ' ' && *src != '=')
	    {
		name.ptr = src;
		name.len = 1;
		whitespace = 0;
		state = READ_NAME;
	    }
	    break;
	case READ_NAME:
	    if (*src != ',' && *src != '/' && *src != '\0')
	    {
		name.len++;
		if (*src == ' ')
		    whitespace++;
		else
		    whitespace = 0;
	    }
	    else
	    {
		name.len -= whitespace;
		code_asn1_length(name.len, &asn1_name_len);

		/* compute the length of the relative distinguished name sequence */
		rdn_seq_len = 1 + asn1_oid_len.len + x501rdns[pos].oid.len +
			      1 + asn1_name_len.len + name.len;
		code_asn1_length(rdn_seq_len, &asn1_rdn_seq_len);

		/* compute the length of the relative distinguished name set */
		rdn_set_len = 1 + asn1_rdn_seq_len.len + rdn_seq_len;
		code_asn1_length(rdn_set_len, &asn1_rdn_set_len);

		/* encode the relative distinguished name */
		*dn_ptr++ = ASN1_SET;
		chunkcpy(dn_ptr, asn1_rdn_set_len);
		*dn_ptr++ = ASN1_SEQUENCE;
		chunkcpy(dn_ptr, asn1_rdn_seq_len);
		*dn_ptr++ = ASN1_OID;
		chunkcpy(dn_ptr, asn1_oid_len);
		chunkcpy(dn_ptr, x501rdns[pos].oid);
		/* encode the ASN.1 character string type of the name */
		*dn_ptr++ = (x501rdns[pos].type == ASN1_PRINTABLESTRING
		    && !is_printablestring(name))? ASN1_T61STRING : x501rdns[pos].type;
		chunkcpy(dn_ptr, asn1_name_len);
		chunkcpy(dn_ptr, name);

		/* accumulate the length of the distinguished name sequence */
		dn_seq_len += 1 + asn1_rdn_set_len.len + rdn_set_len;

		/* reset name and change state */
		name = empty_chunk;
		state = SEARCH_OID;
	    }
	    break;
	case UNKNOWN_OID:
	    break;
	}
    } while (*src++ != '\0');

    /* complete the distinguished name sequence*/
    code_asn1_length(dn_seq_len, &asn1_dn_seq_len);
    dn->ptr += 3 - asn1_dn_seq_len.len;
    dn->len =  1 + asn1_dn_seq_len.len + dn_seq_len;
    dn_ptr = dn->ptr;
    *dn_ptr++ = ASN1_SEQUENCE;
    chunkcpy(dn_ptr, asn1_dn_seq_len);
    return ugh;
}

/*  compare two distinguished names by
 *  comparing the individual RDNs
 */
bool
same_dn(chunk_t a, chunk_t b)
{
    chunk_t rdn_a, rdn_b, attribute_a, attribute_b;
    chunk_t oid_a, oid_b, value_a, value_b;
    asn1_t type_a, type_b;
    bool next_a, next_b;

    /* same lengths for the DNs */
    if (a.len != b.len)
	return FALSE;

    /* try a binary comparison first */
    if (memcmp(a.ptr, b.ptr, b.len) == 0)
       return TRUE;
 



    /* initialize DN parsing */
    if (init_rdn(a, &rdn_a, &attribute_a, &next_a) != NULL
    ||  init_rdn(b, &rdn_b, &attribute_b, &next_b) != NULL)
	return FALSE;

    /* fetch next RDN pair */
    while (next_a && next_b)
    {
	/* parse next RDNs and check for errors */
	if (get_next_rdn(&rdn_a, &attribute_a, &oid_a, &value_a, &type_a, &next_a) != NULL
	||  get_next_rdn(&rdn_b, &attribute_b, &oid_b, &value_b, &type_b, &next_b) != NULL)
	{
	    return FALSE;
	}

	/* OIDs must agree */
	if (oid_a.len != oid_b.len || memcmp(oid_a.ptr, oid_b.ptr, oid_b.len) != 0)
	    return FALSE;

	/* same lengths for values */
	if (value_a.len != value_b.len)
	    return FALSE;

	/* printableStrings and email RDNs require uppercase comparison */
	if (type_a == type_b && (type_a == ASN1_PRINTABLESTRING ||
	   (type_a == ASN1_IA5STRING && known_oid(oid_a) == OID_PKCS9_EMAIL)))
	{
	    if (strncasecmp(value_a.ptr, value_b.ptr, value_b.len) != 0)
		return FALSE;
	}
	else
	{
	    if (strncmp(value_a.ptr, value_b.ptr, value_b.len) != 0)
		return FALSE;
	}
    }
    /* both DNs must have same number of RDNs */
    if (next_a || next_b)
	return FALSE;

    /* the two DNs are equal! */
    return TRUE;
}


/*  compare two distinguished names by comparing the individual RDNs.
 *  A single'*' character designates a wildcard RDN in DN b.
 */
bool
match_dn(chunk_t a, chunk_t b, int *wildcards)
{
    chunk_t rdn_a, rdn_b, attribute_a, attribute_b;
    chunk_t oid_a, oid_b, value_a, value_b;
    asn1_t type_a,  type_b;
    bool next_a, next_b;

    /* initialize wildcard counter */
    *wildcards = 0;

    /* initialize DN parsing */
    if (init_rdn(a, &rdn_a, &attribute_a, &next_a) != NULL
    ||  init_rdn(b, &rdn_b, &attribute_b, &next_b) != NULL)
    	return FALSE;

    /* fetch next RDN pair */
    while (next_a && next_b)
    {
	/* parse next RDNs and check for errors */
	if (get_next_rdn(&rdn_a, &attribute_a, &oid_a, &value_a, &type_a, &next_a) != NULL
	||  get_next_rdn(&rdn_b, &attribute_b, &oid_b, &value_b, &type_b, &next_b) != NULL)
	{
	    return FALSE;
	}

	/* OIDs must agree */
	if (oid_a.len != oid_b.len || memcmp(oid_a.ptr, oid_b.ptr, oid_b.len) != 0)
	    return FALSE;

	/* does rdn_b contain a wildcard? */
	if (value_b.len == 1 && *value_b.ptr == '*')
	{
	    (*wildcards)++;
	    continue;
	}

	/* same lengths for values */
	if (value_a.len != value_b.len)
	    return FALSE;

	/* printableStrings and email RDNs require uppercase comparison */
	if (type_a == type_b && (type_a == ASN1_PRINTABLESTRING ||
	   (type_a == ASN1_IA5STRING && known_oid(oid_a) == OID_PKCS9_EMAIL)))
	{
	    if (strncasecmp(value_a.ptr, value_b.ptr, value_b.len) != 0)
		return FALSE;
	}
	else
	{
	    if (strncmp(value_a.ptr, value_b.ptr, value_b.len) != 0)
		return FALSE;
	}
    }
    /* both DNs must have same number of RDNs */
    if (next_a || next_b) {
	if(*wildcards) {
	    char abuf[BUF_LEN];
	    char bbuf[BUF_LEN];
	    
	    dntoa(abuf, BUF_LEN, a);
	    dntoa(bbuf, BUF_LEN, b);
	    
	    openswan_log("while comparing A='%s'<=>'%s'=B with a wildcard count of %d, %s had too few RDNs",
			 abuf, bbuf, *wildcards, (next_a ? "B" : "A"));
	}
	return FALSE;
    }

    /* the two DNs match! */
    return TRUE;
}

/*
 *  compare two X.509 certificates by comparing their signatures
 */
static bool
same_x509cert(const x509cert_t *a, const x509cert_t *b)
{
    return same_chunk(a->signature, b->signature);
}

/*  for each link pointing to the certificate
 "  increase the count by one
 */
void
share_x509cert(x509cert_t *cert)
{
    if (cert != NULL)
 	cert->count++;
}

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
 * choose either subject DN or a subjectAltName as connection end ID
 */
void
select_x509cert_id(x509cert_t *cert, struct id *end_id)
{
    bool copy_subject_dn = TRUE;	 /* ID is subject DN */

    if (end_id->kind != ID_NONE) /* check for matching subjectAltName */
    {
	generalName_t *gn = cert->subjectAltName;

	while (gn != NULL)
	{
	    struct id id = empty_id;

	    gntoid(&id, gn);
	    if (same_id(&id, end_id))
	    {
		copy_subject_dn = FALSE; /* take subjectAltName instead */
		break;
	    }
	    gn = gn->next;
	}
    }

    if (copy_subject_dn)
    {
	if (end_id->kind != ID_NONE && end_id->kind != ID_DER_ASN1_DN)
	{
	     char buf[IDTOA_BUF];

	     idtoa(end_id, buf, IDTOA_BUF);
	     openswan_log("  no subjectAltName matches ID '%s', replaced by subject DN", buf);
	}
	end_id->kind = ID_DER_ASN1_DN;
	end_id->name.len = cert->subject.len;
	end_id->name.ptr = temporary_cyclic_buffer();
	memcpy(end_id->name.ptr, cert->subject.ptr, cert->subject.len);
    }
}

/*
 * check for equality between two key identifiers
 */
bool
same_keyid(chunk_t a, chunk_t b)
{
    if (a.ptr == NULL || b.ptr == NULL)
	return FALSE;

    return same_chunk(a, b);
}

/*
 * check for equality between two serial numbers
 */
bool
same_serial(chunk_t a, chunk_t b)
{
    /* do not compare serial numbers if one of them is not defined */
    if (a.ptr == NULL || b.ptr == NULL)
	return TRUE;

    return same_chunk(a, b);
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
    char abuf[BUF_LEN], bbuf[BUF_LEN];

    dntoa(abuf, BUF_LEN, a);
    dntoa(bbuf, BUF_LEN, b);

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

/*
 *  free the dynamic memory used to store generalNames
 */
void
free_generalNames(generalName_t* gn, bool free_name)
{
    while (gn != NULL)
    {
	generalName_t *gn_top = gn;
	if (free_name)
	{
	    pfree(gn->name.ptr);
	}
	gn = gn->next;
	pfree(gn_top);
    }
}

/*
 *  free a X.509 certificate
 */
void
free_x509cert(x509cert_t *cert)
{
    if (cert != NULL)
    {
	free_generalNames(cert->subjectAltName, FALSE);
	free_generalNames(cert->crlDistributionPoints, FALSE);
	pfreeany(cert->certificate.ptr);
	pfree(cert);
	cert = NULL;
    }
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

/*
 *  free the dynamic memory used to store revoked certificates
 */
static void
free_revoked_certs(revokedCert_t* revokedCerts)
{
    while (revokedCerts != NULL)
    {
	revokedCert_t * revokedCert = revokedCerts;
	revokedCerts = revokedCert->next;
	pfree(revokedCert);
    }
}

/*
 *  free the dynamic memory used to store CRLs
 */
void
free_crl(x509crl_t *crl)
{
    free_revoked_certs(crl->revokedCertificates);
    free_generalNames(crl->distributionPoints, TRUE);
    pfree(crl->certificateList.ptr);
    pfree(crl);
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
    u_char buf[BUF_LEN];
    u_char *save_dir;
    int n;

    /* change directory to specified path */
    save_dir = getcwd(buf, BUF_LEN);

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

		if (load_cert(CERT_NONE, filelist[n]->d_name, type, &cert))
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
 *  compute a digest over a binary blob
 */
bool
compute_digest(chunk_t tbs, int alg, chunk_t *digest)
{
    switch (alg)
    {
	case OID_MD2:
	case OID_MD2_WITH_RSA:
	{
	    MD2_CTX context;
	    MD2Init(&context);
	    MD2Update(&context, tbs.ptr, tbs.len);
	    MD2Final(digest->ptr, &context);
	    digest->len = MD2_DIGEST_SIZE;
	    return TRUE;
	}
	case OID_MD5:
	case OID_MD5_WITH_RSA:
	{
	    MD5_CTX context;
	    osMD5Init(&context);
	    osMD5Update(&context, tbs.ptr, tbs.len);
	    osMD5Final(digest->ptr, &context);
	    digest->len = MD5_DIGEST_SIZE;
	    return TRUE;
	}
	case OID_SHA1:
	case OID_SHA1_WITH_RSA:
	case OID_SHA1_WITH_RSA_OIW:
	{
	    SHA1_CTX context;
	    SHA1Init(&context);
	    SHA1Update(&context, tbs.ptr, tbs.len);
	    SHA1Final(digest->ptr, &context);
	    digest->len = SHA1_DIGEST_SIZE;
	    return TRUE;
	}
	default:
	    digest->len = 0;
	    return FALSE;
    }
}

/*
 *  decrypts an RSA signature using the issuer's certificate
 */
static bool
decrypt_sig(chunk_t sig, int alg, const x509cert_t *issuer_cert,
	    chunk_t *digest)
{
    switch (alg)
    {
	chunk_t decrypted;
	case OID_RSA_ENCRYPTION:
	case OID_MD2_WITH_RSA:
	case OID_MD5_WITH_RSA:
	case OID_SHA1_WITH_RSA:
	case OID_SHA1_WITH_RSA_OIW:
	case OID_SHA256_WITH_RSA:
	case OID_SHA384_WITH_RSA:
	case OID_SHA512_WITH_RSA:
	{
	    mpz_t s;
	    mpz_t e;
	    mpz_t n;

	    n_to_mpz(s, sig.ptr, sig.len);
	    n_to_mpz(e, issuer_cert->publicExponent.ptr,
			issuer_cert->publicExponent.len);
	    n_to_mpz(n, issuer_cert->modulus.ptr,
			issuer_cert->modulus.len);

	    /* decrypt the signature s = s^e mod n */
	    mpz_powm(s, s, e, n);
	    /* convert back to bytes */
	    decrypted = mpz_to_n(s, issuer_cert->modulus.len);
	    DBG(DBG_PARSING,
		DBG_dump_chunk("  decrypted signature: ", decrypted)
	    )

	    /*  copy the least significant bits of decrypted signature
	     *  into the digest string
	    */
	    memcpy(digest->ptr, decrypted.ptr + decrypted.len - digest->len,
		   digest->len);

	    /* free memory */
	    pfree(decrypted.ptr);
	    mpz_clear(s);
	    mpz_clear(e);
	    mpz_clear(n);
	    return TRUE;
	}
	default:
	    digest->len = 0;
	    return FALSE;
    }
}

/*
 *   Check if a signature over binary blob is genuine
 */
bool
check_signature(chunk_t tbs, chunk_t sig, int algorithm,
		const x509cert_t *issuer_cert)
{
    u_char digest_buf[MAX_DIGEST_LEN];
    u_char decrypted_buf[MAX_DIGEST_LEN];
    chunk_t digest = {digest_buf, MAX_DIGEST_LEN};
    chunk_t decrypted = {decrypted_buf, MAX_DIGEST_LEN};


    if (algorithm != OID_UNKNOWN)
    {
	DBG(DBG_X509 | DBG_PARSING,
	    DBG_log("signature algorithm: '%s'",oid_names[algorithm].name);
	)
    }
    else
    {
	DBG(DBG_X509 | DBG_PARSING,
	    DBG_log("unknown signature algorithm");
	)
    }

    if (!compute_digest(tbs, algorithm, &digest))
    {
	openswan_log("  digest algorithm not supported");
	return FALSE;
    }

    DBG(DBG_PARSING,
	DBG_dump_chunk("  digest:", digest)
    )

    decrypted.len = digest.len; /* we want the same digest length */

    if (!decrypt_sig(sig, algorithm, issuer_cert, &decrypted))
    {
    	openswan_log("  decryption algorithm not supported");
	return FALSE;
    }

    /* check if digests are equal */
    return !memcmp(decrypted.ptr, digest.ptr, digest.len);
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

	    strncpy(distpoint, crl->distributionPoints->name.ptr,
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
	    DBG_log("crl signature is valid")
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
    u_char buf[BUF_LEN];
    u_char *save_dir;
    int n;

    /* change directory to specified path */
    save_dir = getcwd(buf, BUF_LEN);
    if (chdir(CRL_PATH))
    {
	openswan_log("Could not change to directory '%s'", CRL_PATH);
    }
    else
    {
	openswan_log("Changing to directory '%s'", CRL_PATH);
	n = scandir(CRL_PATH, &filelist, file_select, alphasort);

	if (n <= 0)
	    openswan_log("  Warning: empty directory");
	else
	{
	    while (n--)
	    {
		bool pgp = FALSE;
		chunk_t blob = empty_chunk;
		char *filename = filelist[n]->d_name;

		if (load_coded_file(filename, NULL, "crl", &blob, &pgp))
		{
		    chunk_t crl_uri;
                    crl_uri.len = 8 + strlen(CRL_PATH) + strlen(filename);
		    crl_uri.ptr = alloc_bytes(crl_uri.len + 1, "crl uri");
		    /* build CRL file URI */
		    snprintf(crl_uri.ptr, crl_uri.len +1, "file://%s/%s", CRL_PATH, filename);
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

/*
 * extracts the basicConstraints extension
 */
static bool
parse_basicConstraints(chunk_t blob, int level0)
{
    asn1_ctx_t ctx;
    chunk_t object;
    u_int level;
    int objectID = 0;
    bool isCA = FALSE;

    asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

    while (objectID < BASIC_CONSTRAINTS_ROOF) {

	if (!extract_object(basicConstraintsObjects, &objectID,
			    &object,&level, &ctx))
	     break;

	if (objectID == BASIC_CONSTRAINTS_CA)
	{
	    isCA = object.len && *object.ptr;
	    DBG(DBG_PARSING,
		DBG_log("  %s",(isCA)?"TRUE":"FALSE");
	    )
	}
	objectID++;
    }
    return isCA;
}

/*
 *  Converts a X.500 generalName into an ID
 */
void
gntoid(struct id *id, const generalName_t *gn)
{
    switch(gn->kind)
    {
    case GN_DNS_NAME:		/* ID type: ID_FQDN */
	id->kind = ID_FQDN;
	id->name = gn->name;
	break;
    case GN_IP_ADDRESS:		/* ID type: ID_IPV4_ADDR */
	{
	    const struct af_info *afi = &af_inet4_info;
	    err_t ugh = NULL;

	    id->kind = afi->id_addr;
	    ugh = initaddr(gn->name.ptr, gn->name.len, afi->af, &id->ip_addr);
	}
	break;
    case GN_RFC822_NAME:	/* ID type: ID_USER_FQDN */
	id->kind = ID_USER_FQDN;
	id->name = gn->name;
	break;
    default:
	id->kind = ID_NONE;
	id->name = empty_chunk;
    }
}

/*
 * extracts a generalName
 */
static generalName_t*
parse_generalName(chunk_t blob, int level0)
{
    u_char buf[BUF_LEN];
    asn1_ctx_t ctx;
    chunk_t object;
    int objectID = 0;
    u_int level;

    asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

    while (objectID < GN_OBJ_ROOF)
    {
	bool valid_gn = FALSE;
	
	if (!extract_object(generalNameObjects, &objectID, &object, &level, &ctx))
	     return NULL;

	switch (objectID) {
	case GN_OBJ_RFC822_NAME:
	case GN_OBJ_DNS_NAME:
	case GN_OBJ_URI:
	    DBG(DBG_PARSING,
		DBG_log("  '%.*s'", (int)object.len, object.ptr);
	    )
	    valid_gn = TRUE;
	    break;
	case GN_OBJ_DIRECTORY_NAME:
	    DBG(DBG_PARSING,
		dntoa(buf, BUF_LEN, object);
		DBG_log("  '%s'", buf)
	    )
	    valid_gn = TRUE;
	    break;
	case GN_OBJ_IP_ADDRESS:
	    DBG(DBG_PARSING,
		DBG_log("  '%d.%d.%d.%d'", *object.ptr, *(object.ptr+1),
				      *(object.ptr+2), *(object.ptr+3));
	    )
	    valid_gn = TRUE;
	    break;
	case GN_OBJ_OTHER_NAME:
	case GN_OBJ_X400_ADDRESS:
	case GN_OBJ_EDI_PARTY_NAME:
	case GN_OBJ_REGISTERED_ID:
	    break;
	default:
	    break;
	}

	if (valid_gn)
	{
	    generalName_t *gn = alloc_thing(generalName_t, "generalName");
	    gn->kind = (objectID - GN_OBJ_OTHER_NAME) / 2;
	    gn->name = object;
	    gn->next = FALSE;
	    return gn;
        }
	objectID++;
    }
    return NULL;
}


/*
 * extracts one or several GNs and puts them into a chained list
 */
static generalName_t*
parse_generalNames(chunk_t blob, int level0, bool implicit)
{
    asn1_ctx_t ctx;
    chunk_t object;
    u_int level;
    int objectID = 0;
        
    generalName_t *top_gn = NULL;

    asn1_init(&ctx, blob, level0, implicit, DBG_RAW);

    while (objectID < GENERAL_NAMES_ROOF)
    {
	if (!extract_object(generalNamesObjects, &objectID, &object, &level, &ctx))
	     return NULL;
	     
	if (objectID == GENERAL_NAMES_GN)
	{
	    generalName_t *gn = parse_generalName(object, level+1);
	    if (gn != NULL)
	    {
		gn->next = top_gn;
		top_gn = gn;
	    }
	}
	objectID++;
    }
    return top_gn;
}

/*
 * returns a directoryName
 */
chunk_t get_directoryName(chunk_t blob, int level, bool implicit)
{
    chunk_t name = empty_chunk;
    generalName_t * gn = parse_generalNames(blob, level, implicit);

    if (gn != NULL && gn->kind == GN_DIRECTORY_NAME)
	name= gn->name;

    free_generalNames(gn, FALSE);

    return name;
}

/*
 * extracts and converts a UTCTIME or GENERALIZEDTIME object
 */
static time_t
parse_time(chunk_t blob, int level0)
{
    asn1_ctx_t ctx;
    chunk_t object;
    u_int level;
    int objectID = 0;

    asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

    while (objectID < TIME_ROOF)
    {
	if (!extract_object(timeObjects, &objectID, &object, &level, &ctx))
	     return UNDEFINED_TIME;

	if (objectID == TIME_UTC || objectID == TIME_GENERALIZED)
	{
	    return asn1totime(&object, (objectID == TIME_UTC)
			? ASN1_UTCTIME : ASN1_GENERALIZEDTIME);
	}
	objectID++;
    }
    return UNDEFINED_TIME;
 }

/*
 * extracts an algorithmIdentifier
 */
int
parse_algorithmIdentifier(chunk_t blob, int level0)
{
    asn1_ctx_t ctx;
    chunk_t object;
    u_int level;
    int objectID = 0;

    asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

    while (objectID < ALGORITHM_IDENTIFIER_ROOF)
    {
	if (!extract_object(algorithmIdentifierObjects, &objectID, &object, &level, &ctx))
	     return OID_UNKNOWN;

	if (objectID == ALGORITHM_IDENTIFIER_ALG)
	    return known_oid(object);

	objectID++;
    }
    return OID_UNKNOWN;
 }


/*
 * extracts a keyIdentifier
 */
static chunk_t
parse_keyIdentifier(chunk_t blob, int level0, bool implicit)
{
    asn1_ctx_t ctx;
    chunk_t object;
    u_int level;
    int objectID = 0;

    asn1_init(&ctx, blob, level0, implicit, DBG_RAW);

    extract_object(keyIdentifierObjects, &objectID, &object, &level, &ctx);
    return object;
}

/*
 * extracts an authoritykeyIdentifier
 */
void
parse_authorityKeyIdentifier(chunk_t blob, int level0
    , chunk_t *authKeyID, chunk_t *authKeySerialNumber)
{
    asn1_ctx_t ctx;
    chunk_t object;
    u_int level;
    int objectID = 0;

    asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

    while (objectID < AUTH_KEY_ID_ROOF)
    {
	if (!extract_object(authorityKeyIdentifierObjects, &objectID, &object, &level, &ctx))
	     return;

	switch (objectID) {
	case AUTH_KEY_ID_KEY_ID:
	    *authKeyID = parse_keyIdentifier(object, level+1, TRUE);
	    break;
	case AUTH_KEY_ID_CERT_ISSUER:
	    {
		generalName_t * gn = parse_generalNames(object, level+1, TRUE);

		free_generalNames(gn, FALSE);
	    }
	    break;
	case AUTH_KEY_ID_CERT_SERIAL:
	    *authKeySerialNumber = object;
	    break;
	default:
	    break;
	}
	objectID++;
    }
}

/*
 * extracts an authorityInfoAcess location
 */
static void
parse_authorityInfoAccess(chunk_t blob, int level0, chunk_t *accessLocation)
{
    asn1_ctx_t ctx;
    chunk_t object;
    u_int level;
    int objectID = 0;

    u_int accessMethod = OID_UNKNOWN;

    asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

    while (objectID < AUTH_INFO_ACCESS_ROOF)
    {
	if (!extract_object(authorityInfoAccessObjects, &objectID, &object, &level, &ctx))
	     return;

	switch (objectID) {
	case AUTH_INFO_ACCESS_METHOD:
	    accessMethod = known_oid(object);
	    break;
	case AUTH_INFO_ACCESS_LOCATION:
	    {
		switch (accessMethod)
		{
		case OID_OCSP:
		    if (*object.ptr == ASN1_CONTEXT_S_6)
		    {
                        if (asn1_length(&object) == ASN1_INVALID_LENGTH)
                           return;

			DBG(DBG_PARSING,
			    DBG_log("  '%.*s'",(int)object.len, object.ptr)
			)

			/* only HTTP(S) URIs accepted */
			if (strncasecmp(object.ptr, "http", 4) == 0)
			{
			    *accessLocation = object;
			    return;
			}
		    }
		    openswan_log("warning: ignoring OCSP InfoAccessLocation with unkown protocol");
		    break;
		default:
		    /* unkown accessMethod, ignoring */
		    break;
		}
	    }
	    break;
	default:
	    break;
	}
	objectID++;
    }

}

/*
 * extracts extendedKeyUsage OIDs
 */
static bool
parse_extendedKeyUsage(chunk_t blob, int level0)
{
    asn1_ctx_t ctx;
    chunk_t object;
    u_int level;
    int objectID = 0;

    asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

    while (objectID < EXT_KEY_USAGE_ROOF)
    {
	if (!extract_object(extendedKeyUsageObjects, &objectID
			    , &object, &level, &ctx))
	     return FALSE;

	if (objectID == EXT_KEY_USAGE_PURPOSE_ID
	&& known_oid(object) == OID_OCSP_SIGNING)
	    return TRUE;
	objectID++;
    }
    return FALSE;
}

/*  extracts one or several crlDistributionPoints and puts them into
 *  a chained list
 */
static generalName_t*
parse_crlDistributionPoints(chunk_t blob, int level0)
{
    asn1_ctx_t ctx;
    chunk_t object;
    u_int level;
    int objectID = 0;

    generalName_t *top_gn = NULL;      /* top of the chained list */
    generalName_t **tail_gn = &top_gn; /* tail of the chained list */

    asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

    while (objectID < CRL_DIST_POINTS_ROOF)
    {
	if (!extract_object(crlDistributionPointsObjects, &objectID,
			    &object, &level, &ctx))
	     return NULL;

	if (objectID == CRL_DIST_POINTS_FULLNAME)
	{
	    generalName_t *gn = parse_generalNames(object, level+1, TRUE);
	    /* append extracted generalNames to existing chained list */
	    *tail_gn = gn;
	    /* find new tail of the chained list */
            while (gn != NULL)
	    {
		tail_gn = &gn->next;  gn = gn->next;
	    }
	}
	objectID++;
    }
    return top_gn;
}


/*
 *  Parses an X.509v3 certificate
 */
bool
parse_x509cert(chunk_t blob, u_int level0, x509cert_t *cert)
{
    u_char  buf[BUF_LEN];
    asn1_ctx_t ctx;
    bool critical;
    chunk_t object;
    u_int level;
    u_int extn_oid = 0;
    int objectID = 0;

    asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

    while (objectID < X509_OBJ_ROOF)
    {
	if (!extract_object(certObjects, &objectID, &object, &level, &ctx))
	     return FALSE;

	/* those objects which will parsed further need the next higher level */
	level++;

	switch (objectID) {
	case X509_OBJ_CERTIFICATE:
	    cert->certificate = object;
	    break;
	case X509_OBJ_TBS_CERTIFICATE:
	    cert->tbsCertificate = object;
	    break;
	case X509_OBJ_VERSION:
	    cert->version = (object.len) ? (1+(u_int)*object.ptr) : 1;
	    DBG(DBG_PARSING,
		DBG_log("  v%d", cert->version);
	    )
	    break;
	case X509_OBJ_SERIAL_NUMBER:
	    cert->serialNumber = object;
	    break;
	case X509_OBJ_SIG_ALG:
	    cert->sigAlg = parse_algorithmIdentifier(object, level);
	    break;
	case X509_OBJ_ISSUER:
	    cert->issuer = object;
	    DBG(DBG_PARSING,
		dntoa(buf, BUF_LEN, object);
		DBG_log("  '%s'",buf)
	    )
	    break;
	case X509_OBJ_NOT_BEFORE:
	    cert->notBefore = parse_time(object, level);
	    break;
	case X509_OBJ_NOT_AFTER:
	    cert->notAfter = parse_time(object, level);
	    break;
	case X509_OBJ_SUBJECT:
	    cert->subject = object;
	    DBG(DBG_PARSING,
		dntoa(buf, BUF_LEN, object);
		DBG_log("  '%s'",buf)
	    )
	    break;
	case X509_OBJ_SUBJECT_PUBLIC_KEY_ALGORITHM:
	    if (parse_algorithmIdentifier(object, level) == OID_RSA_ENCRYPTION)
		cert->subjectPublicKeyAlgorithm = PUBKEY_ALG_RSA;
            else
            {
                plog("  unsupported public key algorithm");
                return FALSE;
            }
	    break;
	case X509_OBJ_SUBJECT_PUBLIC_KEY:
            if (ctx.blobs[4].len > 0 && *ctx.blobs[4].ptr == 0x00)
	    {
                /* skip initial bit string octet defining 0 unused bits */

		ctx.blobs[4].ptr++; ctx.blobs[4].len--;
	    }
	    else
            {
                plog("  invalid RSA public key format");
                return FALSE;
            }
	    break;
	case X509_OBJ_MODULUS:
            if (object.len < RSA_MIN_OCTETS + 1)
            {
                plog("  " RSA_MIN_OCTETS_UGH);
                return FALSE;
            }
            if (object.len > RSA_MAX_OCTETS + (size_t)(*object.ptr == 0x00))
            {
                plog("  " RSA_MAX_OCTETS_UGH);
                return FALSE;
            }
	    cert->modulus = object;
	    break;
	case X509_OBJ_PUBLIC_EXPONENT:
	    cert->publicExponent = object;
	    break;
	case X509_OBJ_EXTN_ID:
	    extn_oid = known_oid(object);
	    break;
	case X509_OBJ_CRITICAL:
	    critical = object.len && *object.ptr;
	    DBG(DBG_PARSING,
		DBG_log("  %s",(critical)?"TRUE":"FALSE");
	    )
	    break;
	case X509_OBJ_EXTN_VALUE:
	    {
		switch (extn_oid) {
		case OID_SUBJECT_KEY_ID:
		    cert->subjectKeyID =
			parse_keyIdentifier(object, level, FALSE);
		    break;
		case OID_SUBJECT_ALT_NAME:
		    cert->subjectAltName =
			parse_generalNames(object, level, FALSE);
		    break;
		case OID_BASIC_CONSTRAINTS:
		    cert->isCA =
			parse_basicConstraints(object, level);
		    break;
		case OID_CRL_DISTRIBUTION_POINTS:
		    cert->crlDistributionPoints =
			parse_crlDistributionPoints(object, level);
		    break;
		 case OID_AUTHORITY_KEY_ID:
		    parse_authorityKeyIdentifier(object, level
			, &cert->authKeyID, &cert->authKeySerialNumber);
		    break;
		case OID_AUTHORITY_INFO_ACCESS:
		    parse_authorityInfoAccess(object, level, &cert->accessLocation);
		    break;
		case OID_EXTENDED_KEY_USAGE:
		    cert->isOcspSigner = parse_extendedKeyUsage(object, level);
		    break;
		default:
		    break;
		}
	    }
	    break;
	case X509_OBJ_ALGORITHM:
	    cert->algorithm = parse_algorithmIdentifier(object, level);
	    break;
	case X509_OBJ_SIGNATURE:
	    cert->signature = object;
	    break;
	default:
	    break;
	}
	objectID++;
    }
    time(&cert->installed);
    return TRUE;
}

/*
 *  Parses an X.509 CRL
 */
bool
parse_x509crl(chunk_t blob, u_int level0, x509crl_t *crl)
{
    u_char buf[BUF_LEN];
    asn1_ctx_t ctx;
    bool critical;
    chunk_t extnID;
    chunk_t userCertificate;
    chunk_t object;
    u_int level;
    int objectID = 0;

    asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

    while (objectID < CRL_OBJ_ROOF)
    {
	if (!extract_object(crlObjects, &objectID, &object, &level, &ctx))
	     return FALSE;

	/* those objects which will parsed further need the next higher level */
	level++;

	switch (objectID) {
	case CRL_OBJ_CERTIFICATE_LIST:
	    crl->certificateList = object;
	    break;
	case CRL_OBJ_TBS_CERT_LIST:
	    crl->tbsCertList = object;
	    break;
	case CRL_OBJ_VERSION:
	    crl->version = (object.len) ? (1+(u_int)*object.ptr) : 1;
	    DBG(DBG_PARSING,
		DBG_log("  v%d", crl->version);
	    )
	    break;
	case CRL_OBJ_SIG_ALG:
	    crl->sigAlg = parse_algorithmIdentifier(object, level);
	    break;
	case CRL_OBJ_ISSUER:
	    crl->issuer = object;
	    DBG(DBG_PARSING,
		dntoa(buf, BUF_LEN, object);
		DBG_log("  '%s'",buf)
	    )
	    break;
	case CRL_OBJ_THIS_UPDATE:
	    crl->thisUpdate = parse_time(object, level);
	    break;
	case CRL_OBJ_NEXT_UPDATE:
	    crl->nextUpdate = parse_time(object, level);
	    break;
	case CRL_OBJ_USER_CERTIFICATE:
	    userCertificate = object;
	    break;
	case CRL_OBJ_REVOCATION_DATE:
	    {
		/* put all the serial numbers and the revocation date in a chained list
		   with revocedCertificates pointing to the first revoked certificate */

		revokedCert_t *revokedCert = alloc_thing(revokedCert_t, "revokedCert");
		revokedCert->userCertificate = userCertificate;
		revokedCert->revocationDate = parse_time(object, level);
		revokedCert->next = crl->revokedCertificates;
		crl->revokedCertificates = revokedCert;
	    }
	    break;
	case CRL_OBJ_EXTN_ID:
	    extnID = object;
	    break;
	case CRL_OBJ_CRL_ENTRY_CRITICAL:
	case CRL_OBJ_CRITICAL:
	    critical = object.len && *object.ptr;
	    DBG(DBG_PARSING,
		DBG_log("  %s",(critical)?"TRUE":"FALSE");
	    )
	    break;
	case CRL_OBJ_EXTN_VALUE:
	    {
		u_int extn_oid = known_oid(extnID);

		if (extn_oid == OID_AUTHORITY_KEY_ID)
		{
		    parse_authorityKeyIdentifier(object, level
			, &crl->authKeyID, &crl->authKeySerialNumber);
		}
	    }
	    break;
	case CRL_OBJ_ALGORITHM:
	    crl->algorithm = parse_algorithmIdentifier(object, level);
	    break;
	case CRL_OBJ_SIGNATURE:
	    crl->signature = object;
	    break;
	default:
	    break;
	}
	objectID++;
    }
    time(&crl->installed);
    return TRUE;
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

	DBG_log("  aftercheck : %ld > %ld", current_time, cert->notAfter);
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
	u_char buf[BUF_LEN];

	DBG(DBG_X509,
	    dntoa(buf, BUF_LEN, crl->issuer);
	    DBG_log("issuer: '%s'",buf);
	    if (crl->authKeyID.ptr != NULL)
	    {
		datatot(crl->authKeyID.ptr, crl->authKeyID.len, ':'
		    , buf, BUF_LEN);
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
    u_char ibuf[BUF_LEN], cbuf[BUF_LEN];

    lock_crl_list("verify_by_crl");
    crl = get_x509crl(cert->issuer, cert->authKeySerialNumber, cert->authKeyID);

    dntoa(ibuf, BUF_LEN, cert->issuer);

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
	dntoa(cbuf, BUF_LEN, crl->issuer);
	valid = check_signature(crl->tbsCertList, crl->signature
				, crl->algorithm, issuer_cert);
	
	unlock_authcert_list("verify_by_crl");

	if (valid)
	{
	    bool revoked_crl, expired_crl;
     
	    DBG(DBG_X509,
		DBG_log("crl signature on \"%s\" is valid", cbuf)
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
	    openswan_log("crl signature on \"%s\" is invalid", cbuf);
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
	u_char sbuf[BUF_LEN];
	u_char ibuf[BUF_LEN];
	u_char abuf[BUF_LEN];

	err_t ugh = NULL;

	dntoa(sbuf, BUF_LEN, cert->subject);
	dntoa(ibuf, BUF_LEN, cert->issuer);

	DBG(DBG_X509,
	    DBG_log("subject: '%s'", sbuf);
	    DBG_log("issuer:  '%s'", ibuf);
	    if (cert->authKeyID.ptr != NULL)
	    {
		datatot(cert->authKeyID.ptr, cert->authKeyID.len, ':'
			, abuf, BUF_LEN);
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
	    DBG_log("certificate for \"%s\" is valid", sbuf)
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
	    openswan_log("certificate signature from \"%s\" on \"%s\" is invalid"
			 , ibuf, sbuf);
	    unlock_authcert_list("verify_x509cert");
	    return FALSE;
	}
	DBG(DBG_X509,
	    DBG_log("certificate signature (%s -> %s) is valid"
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
	    u_char buf[BUF_LEN];
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
	    dntoa(buf, BUF_LEN, cert->subject);
	    whack_log(RC_COMMENT, "       subject: '%s'", buf);
	    dntoa(buf, BUF_LEN, cert->issuer);
	    whack_log(RC_COMMENT, "       issuer:  '%s'", buf);
	    datatot(cert->serialNumber.ptr, cert->serialNumber.len, ':'
		, buf, BUF_LEN);
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
		    , buf, BUF_LEN);
		whack_log(RC_COMMENT, "       subjkey:  %s", buf);
	    }
	    if (cert->authKeyID.ptr != NULL)
	    {
		datatot(cert->authKeyID.ptr, cert->authKeyID.len, ':'
		    , buf, BUF_LEN);
		whack_log(RC_COMMENT, "       authkey:  %s", buf);
	    }
	    if (cert->authKeySerialNumber.ptr != NULL)
	    {
		datatot(cert->authKeySerialNumber.ptr, cert->authKeySerialNumber.len
		    , ':', buf, BUF_LEN);
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
	u_char buf[BUF_LEN];
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
	dntoa(buf, BUF_LEN, crl->issuer);
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
		, buf, BUF_LEN);
	    whack_log(RC_COMMENT, "       authkey:  %s", buf);
	}
	if (crl->authKeySerialNumber.ptr != NULL)
	{
	    datatot(crl->authKeySerialNumber.ptr, crl->authKeySerialNumber.len, ':'
		, buf, BUF_LEN);
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
       u_char buf[BUF_LEN];

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
           plog("certificate signature is invalid");
           unlock_authcert_list("trust_authcert_candidate");
           return FALSE;
       }
       DBG(DBG_CONTROL,
           DBG_log("certificate signature is valid")
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
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */

