/*
 * Support of X.509 certificates and CRLs
 *
 * Copyright (C) 2000 Andreas Hess, Patric Lichtsteiner, Roger Wegmann
 * Copyright (C) 2001 Marco Bertossa, Andreas Schleiss
 * Copyright (C) 2002 Mario Strasser
 * Copyright (C) 2000-2004 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
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
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <limits.h>
#include <sys/types.h>
#include <libreswan.h>
#include <libreswan/ipsec_policy.h>
#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"
#include "lswalloc.h"
#include "lswtime.h"
#include "mpzfuncs.h"
#include "id.h"
#include "asn1.h"
#include "oid.h"
#include "x509.h"
#include "certs.h"
#include "secrets.h"
#ifdef USE_MD5
#include "md5.h"
#endif
#ifdef USE_SHA1
#include "sha1.h"
#endif
#ifdef USE_SHA2
#include "sha2.h"
#endif
#include <prerror.h>
#include <nss.h>
#include <pk11pub.h>
#include <keyhi.h>
#include <secerr.h>
#include "lswconf.h"

static void hex_str(chunk_t bin, chunk_t *str);	/* forward */

/* ASN.1 definition of a basicConstraints extension */

static const asn1Object_t basicConstraintsObjects[] = {
	{ 0, "basicConstraints", ASN1_SEQUENCE, ASN1_NONE },	/* 0 */
	{ 1, "CA", ASN1_BOOLEAN, ASN1_DEF | ASN1_BODY },	/* 1 */
	{ 1, "pathLenConstraint", ASN1_INTEGER, ASN1_OPT | ASN1_BODY },	/* 2 */
	{ 1, "end opt", ASN1_EOC, ASN1_END }	/* 3 */
};

#define BASIC_CONSTRAINTS_CA 1
#define BASIC_CONSTRAINTS_ROOF 4

/* ASN.1 definition of time */

static const asn1Object_t timeObjects[] = {
	{ 0, "utcTime", ASN1_UTCTIME, ASN1_OPT | ASN1_BODY },	/* 0 */
	{ 0, "end opt", ASN1_EOC, ASN1_END },	/* 1 */
	{ 0, "generalizeTime", ASN1_GENERALIZEDTIME, ASN1_OPT |
		ASN1_BODY },	/* 2 */
	{ 0, "end opt", ASN1_EOC, ASN1_END }	/* 3 */
};

#define TIME_UTC 0
#define TIME_GENERALIZED 2
#define TIME_ROOF 4

/* ASN.1 definiton of an algorithmIdentifier */
static const asn1Object_t algorithmIdentifierObjects[] = {
	{ 0, "algorithmIdentifier", ASN1_SEQUENCE, ASN1_NONE },	/* 0 */
	{ 1, "algorithm", ASN1_OID, ASN1_BODY }	/* 1 */
};

#define ALGORITHM_IDENTIFIER_ALG 1
#define ALGORITHM_IDENTIFIER_ROOF 2

/* ASN.1 definition of a keyIdentifier */
static const asn1Object_t keyIdentifierObjects[] = {
	{ 0, "keyIdentifier", ASN1_OCTET_STRING, ASN1_BODY }	/* 0 */
};

/* ASN.1 definition of a authorityKeyIdentifier extension */
static const asn1Object_t authorityKeyIdentifierObjects[] = {
	{ 0, "authorityKeyIdentifier", ASN1_SEQUENCE, ASN1_NONE },	/* 0 */
	{ 1, "keyIdentifier", ASN1_CONTEXT_S_0, ASN1_OPT | ASN1_OBJ },	/* 1 */
	{ 1, "end opt", ASN1_EOC, ASN1_END },	/* 2 */
	{ 1, "authorityCertIssuer", ASN1_CONTEXT_C_1, ASN1_OPT |
		ASN1_OBJ },	/* 3 */
	{ 1, "end opt", ASN1_EOC, ASN1_END },	/* 4 */
	{ 1, "authorityCertSerialNumber", ASN1_CONTEXT_S_2, ASN1_OPT |
		ASN1_BODY },	/* 5 */
	{ 1, "end opt", ASN1_EOC, ASN1_END }	/* 6 */
};

#define AUTH_KEY_ID_KEY_ID 1
#define AUTH_KEY_ID_CERT_ISSUER 3
#define AUTH_KEY_ID_CERT_SERIAL 5
#define AUTH_KEY_ID_ROOF 7

/* ASN.1 definition of a authorityInfoAccess extension */

static const asn1Object_t authorityInfoAccessObjects[] = {
	{ 0, "authorityInfoAccess", ASN1_SEQUENCE, ASN1_LOOP },	/* 0 */
	{ 1, "accessDescription", ASN1_SEQUENCE, ASN1_NONE },	/* 1 */
	{ 2, "accessMethod", ASN1_OID, ASN1_BODY },	/* 2 */
	{ 2, "accessLocation", ASN1_EOC, ASN1_RAW },	/* 3 */
	{ 0, "end loop", ASN1_EOC, ASN1_END }	/* 4 */
};

#define AUTH_INFO_ACCESS_METHOD 2
#define AUTH_INFO_ACCESS_LOCATION 3
#define AUTH_INFO_ACCESS_ROOF 5

/* ASN.1 definition of a extendedKeyUsage extension */
static const asn1Object_t extendedKeyUsageObjects[] = {
	{ 0, "extendedKeyUsage", ASN1_SEQUENCE, ASN1_LOOP },	/* 0 */
	{ 1, "keyPurposeID", ASN1_OID, ASN1_BODY },	/* 1 */
	{ 0, "end loop", ASN1_EOC, ASN1_END },	/* 2 */
};

#define EXT_KEY_USAGE_PURPOSE_ID 1
#define EXT_KEY_USAGE_ROOF 3

/* ASN.1 definition of generalNames */

static const asn1Object_t generalNamesObjects[] = {
	{ 0, "generalNames", ASN1_SEQUENCE, ASN1_LOOP },	/* 0 */
	{ 1, "generalName", ASN1_EOC, ASN1_RAW },	/* 1 */
	{ 0, "end loop", ASN1_EOC, ASN1_END }	/* 2 */
};

#define GENERAL_NAMES_GN 1
#define GENERAL_NAMES_ROOF 3

/* ASN.1 definition of generalName */
static const asn1Object_t generalNameObjects[] = {
	{ 0, "otherName", ASN1_CONTEXT_C_0, ASN1_OPT | ASN1_BODY },	/* 0 */
	{ 0, "end choice", ASN1_EOC, ASN1_END },	/* 1 */
	{ 0, "rfc822Name", ASN1_CONTEXT_S_1, ASN1_OPT | ASN1_BODY },	/* 2 */
	{ 0, "end choice", ASN1_EOC, ASN1_END },	/* 3 */
	{ 0, "dnsName", ASN1_CONTEXT_S_2, ASN1_OPT | ASN1_BODY },	/* 4 */
	{ 0, "end choice", ASN1_EOC, ASN1_END },	/* 5 */
	{ 0, "x400Address", ASN1_CONTEXT_S_3, ASN1_OPT | ASN1_BODY },	/* 6 */
	{ 0, "end choice", ASN1_EOC, ASN1_END },	/* 7 */
	{ 0, "directoryName", ASN1_CONTEXT_C_4, ASN1_OPT | ASN1_BODY },	/* 8 */
	{ 0, "end choice", ASN1_EOC, ASN1_END },	/* 9 */
	{ 0, "ediPartyName", ASN1_CONTEXT_C_5, ASN1_OPT | ASN1_BODY },	/* 10 */
	{ 0, "end choice", ASN1_EOC, ASN1_END },	/* 11 */
	{ 0, "uniformResourceIdentifier", ASN1_CONTEXT_S_6, ASN1_OPT |
		ASN1_BODY },	/* 12 */
	{ 0, "end choice", ASN1_EOC, ASN1_END },	/* 13 */
	{ 0, "ipAddress", ASN1_CONTEXT_S_7, ASN1_OPT | ASN1_BODY },	/* 14 */
	{ 0, "end choice", ASN1_EOC, ASN1_END },	/* 15 */
	{ 0, "registeredID", ASN1_CONTEXT_S_8, ASN1_OPT | ASN1_BODY },	/* 16 */
	{ 0, "end choice", ASN1_EOC, ASN1_END }	/* 17 */
};

#define GN_OBJ_OTHER_NAME 0
#define GN_OBJ_RFC822_NAME 2
#define GN_OBJ_DNS_NAME 4
#define GN_OBJ_X400_ADDRESS 6
#define GN_OBJ_DIRECTORY_NAME 8
#define GN_OBJ_EDI_PARTY_NAME 10
#define GN_OBJ_URI 12
#define GN_OBJ_IP_ADDRESS 14
#define GN_OBJ_REGISTERED_ID 16
#define GN_OBJ_ROOF 18

/* ASN.1 definition of crlDistributionPoints */
static const asn1Object_t crlDistributionPointsObjects[] = {
	{ 0, "crlDistributionPoints", ASN1_SEQUENCE, ASN1_LOOP },	/* 0 */
	{ 1, "DistributionPoint", ASN1_SEQUENCE, ASN1_NONE },	/* 1 */
	{ 2, "distributionPoint", ASN1_CONTEXT_C_0, ASN1_OPT |
		ASN1_LOOP },	/* 2 */
	{ 3, "fullName", ASN1_CONTEXT_C_0, ASN1_OPT | ASN1_OBJ },	/* 3 */
	{ 3, "end choice", ASN1_EOC, ASN1_END },	/* 4 */
	{ 3, "nameRelativeToCRLIssuer", ASN1_CONTEXT_C_1, ASN1_OPT |
		ASN1_BODY },	/* 5 */
	{ 3, "end choice", ASN1_EOC, ASN1_END },	/* 6 */
	{ 2, "end opt", ASN1_EOC, ASN1_END },	/* 7 */
	{ 2, "reasons", ASN1_CONTEXT_C_1, ASN1_OPT | ASN1_BODY },	/* 8 */
	{ 2, "end opt", ASN1_EOC, ASN1_END },	/* 9 */
	{ 2, "crlIssuer", ASN1_CONTEXT_C_2, ASN1_OPT | ASN1_BODY },	/* 10 */
	{ 2, "end opt", ASN1_EOC, ASN1_END },	/* 11 */
	{ 0, "end loop", ASN1_EOC, ASN1_END },	/* 12 */
};

#define CRL_DIST_POINTS_FULLNAME 3
#define CRL_DIST_POINTS_ROOF 13

/* ASN.1 definition of an X.509v3 certificate */
static const asn1Object_t certObjects[] = {
	{ 0, "certificate", ASN1_SEQUENCE, ASN1_OBJ },	/* 0 */
	{ 1, "tbsCertificate", ASN1_SEQUENCE, ASN1_OBJ },	/* 1 */
	{ 2, "DEFAULT v1", ASN1_CONTEXT_C_0, ASN1_DEF },	/* 2 */
	{ 3, "version", ASN1_INTEGER, ASN1_BODY },	/* 3 */
	{ 2, "serialNumber", ASN1_INTEGER, ASN1_BODY },	/* 4 */
	{ 2, "signature", ASN1_EOC, ASN1_RAW },	/* 5 */
	{ 2, "issuer", ASN1_SEQUENCE, ASN1_OBJ },	/* 6 */
	{ 2, "validity", ASN1_SEQUENCE, ASN1_NONE },	/* 7 */
	{ 3, "notBefore", ASN1_EOC, ASN1_RAW },	/* 8 */
	{ 3, "notAfter", ASN1_EOC, ASN1_RAW },	/* 9 */
	{ 2, "subject", ASN1_SEQUENCE, ASN1_OBJ },	/* 10 */
	{ 2, "subjectPublicKeyInfo", ASN1_SEQUENCE, ASN1_NONE },	/* 11 */
	{ 3, "algorithm", ASN1_EOC, ASN1_RAW },	/* 12 */
	{ 3, "subjectPublicKey", ASN1_BIT_STRING, ASN1_NONE },	/* 13 */
	{ 4, "RSAPublicKey", ASN1_SEQUENCE, ASN1_NONE },	/* 14 */
	{ 5, "modulus", ASN1_INTEGER, ASN1_BODY },	/* 15 */
	{ 5, "publicExponent", ASN1_INTEGER, ASN1_BODY },	/* 16 */
	{ 2, "issuerUniqueID", ASN1_CONTEXT_C_1, ASN1_OPT },	/* 17 */
	{ 2, "end opt", ASN1_EOC, ASN1_END },	/* 18 */
	{ 2, "subjectUniqueID", ASN1_CONTEXT_C_2, ASN1_OPT },	/* 19 */
	{ 2, "end opt", ASN1_EOC, ASN1_END },	/* 20 */
	{ 2, "optional extensions", ASN1_CONTEXT_C_3, ASN1_OPT },	/* 21 */
	{ 3, "extensions", ASN1_SEQUENCE, ASN1_LOOP },	/* 22 */
	{ 4, "extension", ASN1_SEQUENCE, ASN1_NONE },	/* 23 */
	{ 5, "extnID", ASN1_OID, ASN1_BODY },	/* 24 */
	{ 5, "critical", ASN1_BOOLEAN, ASN1_DEF | ASN1_BODY },	/* 25 */
	{ 5, "extnValue", ASN1_OCTET_STRING, ASN1_BODY },	/* 26 */
	{ 3, "end loop", ASN1_EOC, ASN1_END },	/* 27 */
	{ 2, "end opt", ASN1_EOC, ASN1_END },	/* 28 */
	{ 1, "signatureAlgorithm", ASN1_EOC, ASN1_RAW },	/* 29 */
	{ 1, "signatureValue", ASN1_BIT_STRING, ASN1_BODY }	/* 30 */
};

#define X509_OBJ_CERTIFICATE 0
#define X509_OBJ_TBS_CERTIFICATE 1
#define X509_OBJ_VERSION 3
#define X509_OBJ_SERIAL_NUMBER 4
#define X509_OBJ_SIG_ALG 5
#define X509_OBJ_ISSUER 6
#define X509_OBJ_NOT_BEFORE 8
#define X509_OBJ_NOT_AFTER 9
#define X509_OBJ_SUBJECT 10
#define X509_OBJ_SUBJECT_PUBLIC_KEY_ALGORITHM 12
#define X509_OBJ_SUBJECT_PUBLIC_KEY 13
#define X509_OBJ_MODULUS 15
#define X509_OBJ_PUBLIC_EXPONENT 16
#define X509_OBJ_EXTN_ID 24
#define X509_OBJ_CRITICAL 25
#define X509_OBJ_EXTN_VALUE 26
#define X509_OBJ_ALGORITHM 29
#define X509_OBJ_SIGNATURE 30
#define X509_OBJ_ROOF 31

/* ASN.1 definition of an X.509 certificate list */

static const asn1Object_t crlObjects[] = {
	{ 0, "certificateList", ASN1_SEQUENCE, ASN1_OBJ },	/* 0 */
	{ 1, "tbsCertList", ASN1_SEQUENCE, ASN1_OBJ },	/* 1 */
	{ 2, "version", ASN1_INTEGER, ASN1_OPT | ASN1_BODY },	/* 2 */
	{ 2, "end opt", ASN1_EOC, ASN1_END },	/* 3 */
	{ 2, "signature", ASN1_EOC, ASN1_RAW },	/* 4 */
	{ 2, "issuer", ASN1_SEQUENCE, ASN1_OBJ },	/* 5 */
	{ 2, "thisUpdate", ASN1_EOC, ASN1_RAW },	/* 6 */
	{ 2, "nextUpdate", ASN1_EOC, ASN1_RAW },	/* 7 */
	{ 2, "revokedCertificates", ASN1_SEQUENCE, ASN1_OPT |
		ASN1_LOOP },	/* 8 */
	{ 3, "certList", ASN1_SEQUENCE, ASN1_NONE },	/* 9 */
	{ 4, "userCertificate", ASN1_INTEGER, ASN1_BODY },	/* 10 */
	{ 4, "revocationDate", ASN1_EOC, ASN1_RAW },	/* 11 */
	{ 4, "crlEntryExtensions", ASN1_SEQUENCE, ASN1_OPT |
		ASN1_LOOP },	/* 12 */
	{ 5, "extension", ASN1_SEQUENCE, ASN1_NONE },	/* 13 */
	{ 6, "extnID", ASN1_OID, ASN1_BODY },	/* 14 */
	{ 6, "critical", ASN1_BOOLEAN, ASN1_DEF | ASN1_BODY },	/* 15 */
	{ 6, "extnValue", ASN1_OCTET_STRING, ASN1_BODY },	/* 16 */
	{ 4, "end opt or loop", ASN1_EOC, ASN1_END },	/* 17 */
	{ 2, "end opt or loop", ASN1_EOC, ASN1_END },	/* 18 */
	{ 2, "optional extensions", ASN1_CONTEXT_C_0, ASN1_OPT },	/* 19 */
	{ 3, "crlExtensions", ASN1_SEQUENCE, ASN1_LOOP },	/* 20 */
	{ 4, "extension", ASN1_SEQUENCE, ASN1_NONE },	/* 21 */
	{ 5, "extnID", ASN1_OID, ASN1_BODY },	/* 22 */
	{ 5, "critical", ASN1_BOOLEAN, ASN1_DEF | ASN1_BODY },	/* 23 */
	{ 5, "extnValue", ASN1_OCTET_STRING, ASN1_BODY },	/* 24 */
	{ 3, "end loop", ASN1_EOC, ASN1_END },	/* 25 */
	{ 2, "end opt", ASN1_EOC, ASN1_END },	/* 26 */
	{ 1, "signatureAlgorithm", ASN1_EOC, ASN1_RAW },	/* 27 */
	{ 1, "signatureValue", ASN1_BIT_STRING, ASN1_BODY }	/* 28 */
};

#define CRL_OBJ_CERTIFICATE_LIST 0
#define CRL_OBJ_TBS_CERT_LIST 1
#define CRL_OBJ_VERSION 2
#define CRL_OBJ_SIG_ALG 4
#define CRL_OBJ_ISSUER 5
#define CRL_OBJ_THIS_UPDATE 6
#define CRL_OBJ_NEXT_UPDATE 7
#define CRL_OBJ_USER_CERTIFICATE 10
#define CRL_OBJ_REVOCATION_DATE 11
#define CRL_OBJ_CRL_ENTRY_CRITICAL 15
#define CRL_OBJ_EXTN_ID 22
#define CRL_OBJ_CRITICAL 23
#define CRL_OBJ_EXTN_VALUE 24
#define CRL_OBJ_ALGORITHM 27
#define CRL_OBJ_SIGNATURE 28
#define CRL_OBJ_ROOF 29

const x509cert_t empty_x509cert = {
	NULL,	/* *next */
	UNDEFINED_TIME,	/* installed */
	0,	/* count */
	AUTH_NONE,	/* authority_flags */
	{ NULL, 0 },	/* certificate */
	{ NULL, 0 },	/* tbsCertificate */
	1,	/* version */
	{ NULL, 0 },	/* serialNumber */
	OID_UNKNOWN,	/* sigAlg */
	{ NULL, 0 },	/* issuer */
		/* validity */
	0,	/* notBefore */
	0,	/* notAfter */
	{ NULL, 0 },	/* subject */
		/* subjectPublicKeyInfo */
	OID_UNKNOWN,	/* subjectPublicKeyAlgorithm */
		/* subjectPublicKey */
	{ NULL, 0 },	/* modulus */
	{ NULL, 0 },	/* publicExponent */
		/* issuerUniqueID */
		/* subjectUniqueID */
		/* extensions */
		/* extension */
		/* extnID */
		/* critical */
		/* extnValue */
	FALSE,	/* isCA */
	FALSE,	/* isOcspSigner */
	{ NULL, 0 },	/* subjectKeyID */
	{ NULL, 0 },	/* authKeyID */
	{ NULL, 0 },	/* authKeySerialNumber */
	{ NULL, 0 },	/* accessLocation */
	NULL,	/* subjectAltName */
	NULL,	/* crlDistributionPoints */
	OID_UNKNOWN,	/* algorithm */
	{ NULL, 0 }	/* signature */
};

const x509crl_t empty_x509crl = {
	NULL,	/* *next */
	UNDEFINED_TIME,	/* installed */
	NULL,	/* distributionPoints */
	{ NULL, 0 },	/* certificateList */
	{ NULL, 0 },	/* tbsCertList */
	1,	/* version */
	OID_UNKNOWN,	/* sigAlg */
	{ NULL, 0 },	/* issuer */
	UNDEFINED_TIME,	/* thisUpdate */
	UNDEFINED_TIME,	/* nextUpdate */
	NULL,	/* revokedCertificates */
		/* crlExtensions */
		/* extension */
		/* extnID */
		/* critical */
		/* extnValue */
	{ NULL, 0 },	/* authKeyID */
	{ NULL, 0 },	/* authKeySerialNumber */
	OID_UNKNOWN,	/* algorithm */
	{ NULL, 0 }	/* signature */
};

/* coding of X.501 distinguished name */
typedef struct {
	const char *name;
	chunk_t oid;
	u_char type;
} x501rdn_t;

/* X.501 acronyms for well known object identifiers (OIDs) */
static u_char oid_ND[] = { 0x02, 0x82, 0x06, 0x01, 0x0A, 0x07, 0x14 };
static u_char oid_UID[] = { 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64,
				0x01, 0x01 };
static u_char oid_DC[] = { 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64,
				0x01, 0x19 };
static u_char oid_CN[] = { 0x55, 0x04, 0x03 };
static u_char oid_S[] = { 0x55, 0x04, 0x04 };
static u_char oid_SN[] = { 0x55, 0x04, 0x05 };
static u_char oid_C[] = { 0x55, 0x04, 0x06 };
static u_char oid_L[] = { 0x55, 0x04, 0x07 };
static u_char oid_ST[] = { 0x55, 0x04, 0x08 };
static u_char oid_O[] = { 0x55, 0x04, 0x0A };
static u_char oid_OU[] = { 0x55, 0x04, 0x0B };
static u_char oid_T[] = { 0x55, 0x04, 0x0C };
static u_char oid_D[] = { 0x55, 0x04, 0x0D };
static u_char oid_N[] = { 0x55, 0x04, 0x29 };
static u_char oid_G[] = { 0x55, 0x04, 0x2A };
static u_char oid_I[] = { 0x55, 0x04, 0x2B };
static u_char oid_ID[] = { 0x55, 0x04, 0x2D };
static u_char oid_E[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09,
				0x01 };
static u_char oid_UN[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09,
				0x02 };
static u_char oid_TCGID[] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x89, 0x31, 0x01,
				0x01, 0x02, 0x02, 0x4B };

static const x501rdn_t x501rdns[] = {
	{ "ND", { oid_ND, 7 }, ASN1_PRINTABLESTRING },
	{ "UID", { oid_UID, 10 }, ASN1_PRINTABLESTRING },
	{ "DC", { oid_DC, 10 }, ASN1_PRINTABLESTRING },
	{ "CN", { oid_CN, 3 }, ASN1_PRINTABLESTRING },
	{ "S", { oid_S, 3 }, ASN1_PRINTABLESTRING },
	{ "SN", { oid_SN, 3 }, ASN1_PRINTABLESTRING },
	{ "serialNumber", { oid_SN, 3 }, ASN1_PRINTABLESTRING },
	{ "C", { oid_C, 3 }, ASN1_PRINTABLESTRING },
	{ "L", { oid_L, 3 }, ASN1_PRINTABLESTRING },
	{ "ST", { oid_ST, 3 }, ASN1_PRINTABLESTRING },
	{ "O", { oid_O, 3 }, ASN1_PRINTABLESTRING },
	{ "OU", { oid_OU, 3 }, ASN1_PRINTABLESTRING },
	{ "T", { oid_T, 3 }, ASN1_PRINTABLESTRING },
	{ "D", { oid_D, 3 }, ASN1_PRINTABLESTRING },
	{ "N", { oid_N, 3 }, ASN1_PRINTABLESTRING },
	{ "G", { oid_G, 3 }, ASN1_PRINTABLESTRING },
	{ "I", { oid_I, 3 }, ASN1_PRINTABLESTRING },
	{ "ID", { oid_ID, 3 }, ASN1_PRINTABLESTRING },
	{ "E", { oid_E, 9 }, ASN1_IA5STRING },
	{ "Email", { oid_E, 9 }, ASN1_IA5STRING },
	{ "emailAddress", { oid_E, 9 }, ASN1_IA5STRING },
	{ "UN", { oid_UN, 9 }, ASN1_IA5STRING },
	{ "unstructuredName", { oid_UN, 9 }, ASN1_IA5STRING },
	{ "TCGID", { oid_TCGID, 12 }, ASN1_PRINTABLESTRING }
};

#define X501_RDN_ROOF elemsof(x501rdns)

static void format_chunk(chunk_t *ch, const char *format, ...) PRINTF_LIKE(2);

/*
 * format into a chunk.
 * The chunk is used as a cursor for free space at the end of the buffer.
 * We leave it advanced to the remainder of the free space.
 * BUG: if there is no free space to start with, we don't do anything.
 */
static void format_chunk(chunk_t *ch, const char *format, ...)
{
	if (ch->len > 0) {
		size_t len = ch->len;
		va_list args;
		va_start(args, format);
		int ret = vsnprintf((char *)ch->ptr, len, format, args);
		va_end(args);
		if (ret < 0) {
			/*
			 * BUG: if ret < 0, vsnprintf encountered some error,
			 * we ought to raise a stink
			 * For now: pretend nothing happened!
			 */
		} else if ((size_t)ret > len) {
			/*
			 * BUG: if ret >= len, then the vsnprintf output was
			 * truncate, we ought to raise a stink!
			 * For now: accept truncated output.
			 */
			ch->ptr += len;
			ch->len = 0;
		} else {
			ch->ptr += ret;
			ch->len -= ret;
		}
	}
}

/*
 * Pointer is set to the first RDN in a DN
 */
static err_t init_rdn(chunk_t dn, chunk_t *rdn, chunk_t *attribute, bool *next)
{
	*rdn = empty_chunk;
	*attribute = empty_chunk;

	/* a DN is a SEQUENCE OF RDNs */
	if (*dn.ptr != ASN1_SEQUENCE)
		return "DN is not a SEQUENCE";

	rdn->len = asn1_length(&dn);

	if (rdn->len == ASN1_INVALID_LENGTH)
		return "Invalid RDN length";

	rdn->ptr = dn.ptr;

	/* are there any RDNs ? */
	*next = rdn->len > 0;

	return NULL;
}

/*
 * Fetches the next RDN in a DN
 */
static err_t get_next_rdn(chunk_t *rdn, chunk_t * attribute, chunk_t *oid,
			chunk_t *value,
			asn1_t *type, bool *next)
{
	chunk_t body;

	/* initialize return values */
	*oid = empty_chunk;
	*value = empty_chunk;

	/* if all attributes have been parsed, get next rdn */
	if (attribute->len <= 0) {
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
 * Parses an ASN.1 distinguished name int its OID/value pairs
 */
static err_t dn_parse(chunk_t dn, chunk_t *str)
{
	chunk_t rdn, oid, attribute, value;
	asn1_t type;
	int oid_code;
	bool next;
	bool first = TRUE;
	err_t ugh;

	if (dn.ptr == NULL) {
		format_chunk(str, "(empty)");
		return NULL;
	}
	ugh = init_rdn(dn, &rdn, &attribute, &next);

	if (ugh != NULL)	/* a parsing error has occured */
		return ugh;

	while (next) {
		ugh =
			get_next_rdn(&rdn, &attribute, &oid, &value, &type,
				&next);

		if (ugh != NULL)	/* a parsing error has occured */
			return ugh;

		if (first)	/* first OID/value pair */
			first = FALSE;
		else	/* separate OID/value pair by a comma */
			format_chunk(str, ", ");

		/* print OID */
		oid_code = known_oid(oid);
		if (oid_code == OID_UNKNOWN)	/* OID not found in list */
			hex_str(oid, str);
		else
			format_chunk(str, "%s", oid_names[oid_code].name);

		/* print value */
		format_chunk(str, "=%.*s", (int)value.len, value.ptr);
	}
	return NULL;
}

/*
 * Count the number of wildcard RDNs in a distinguished name
 */
int dn_count_wildcards(chunk_t dn)
{
	chunk_t rdn, attribute, oid, value;
	asn1_t type;
	bool next;
	int wildcards = 0;

	err_t ugh = init_rdn(dn, &rdn, &attribute, &next);

	if (ugh != NULL)	/* a parsing error has occured */
		return -1;

	while (next) {
		ugh =
			get_next_rdn(&rdn, &attribute, &oid, &value, &type,
				&next);

		if (ugh != NULL)	/* a parsing error has occured */
			return -1;

		if (value.len == 1 && *value.ptr == '*')
			wildcards++;	/* we have found a wildcard RDN */
	}
	return wildcards;
}

/*
 * Prints a binary string in hexadecimal form
 */
static void hex_str(chunk_t bin, chunk_t *str)
{
	u_int i;

	format_chunk(str, "0x");
	for (i = 0; i < bin.len; i++)
		format_chunk(str, "%02X", *bin.ptr++);
}

/*
 * Converts a binary DER-encoded ASN.1 distinguished name
 * into LDAP-style human-readable ASCII format
 */
int dntoa(char *dst, size_t dstlen, chunk_t dn)
{
	err_t ugh = NULL;
	chunk_t str;

	str.ptr = (unsigned char*)dst;
	str.len = dstlen;
	ugh = dn_parse(dn, &str);

	if (ugh != NULL) {	/* error, print DN as hex string */
		libreswan_log("error in DN parsing: %s", ugh);
		str.ptr = (unsigned char *)dst;
		str.len = dstlen;
		hex_str(dn, &str);
	}
	return (int)(dstlen - str.len);
}

/*
 * Same as dntoa but prints a special string for a null dn
 */
int dntoa_or_null(char *dst, size_t dstlen, chunk_t dn, const char* null_dn)
{
	if (dn.ptr == NULL)
		return snprintf(dst, dstlen, "%s", null_dn);
	else
		return dntoa(dst, dstlen, dn);
}

/*
 * function for use in atodn() that escapes a character in
 * in the leftid/rightid string. Needed for '//' and ',,'
 * escapes for OID fields
 */
static void escape_char(char *str, char esc)
{
	char *src, *dst;
	int once = 0;

	src = dst = str;
	while (*src != '\0' && once == 0) {
		*dst = *src;
		src++;
		if (*dst++ == esc && *src == esc) {
			src++;
			once = 1;
		}
	}
	while (*src != '\0') {
		*dst = *src;
		src++;
		dst++;
	}
	*dst = '\0';
}

/*
 * Converts an LDAP-style human-readable ASCII-encoded
 * ASN.1 distinguished name into binary DER-encoded format
 */
err_t atodn(char *src, chunk_t *dn)
{
	/* finite state machine for atodn */

	typedef enum {
		SEARCH_OID = 0,
		READ_OID = 1,
		SEARCH_NAME = 2,
		READ_NAME = 3,
		UNKNOWN_OID = 4
	} state_t;

	u_char oid_len_buf[ASN1_MAX_LEN_LEN];
	u_char name_len_buf[ASN1_MAX_LEN_LEN];
	u_char rdn_seq_len_buf[ASN1_MAX_LEN_LEN];
	u_char rdn_set_len_buf[ASN1_MAX_LEN_LEN];
	u_char dn_seq_len_buf[ASN1_MAX_LEN_LEN];

	chunk_t asn1_oid_len = { oid_len_buf, 0 };
	chunk_t asn1_name_len = { name_len_buf, 0 };
	chunk_t asn1_rdn_seq_len = { rdn_seq_len_buf, 0 };
	chunk_t asn1_rdn_set_len = { rdn_set_len_buf, 0 };
	chunk_t asn1_dn_seq_len = { dn_seq_len_buf, 0 };
	chunk_t oid = empty_chunk;
	chunk_t name = empty_chunk;

	int whitespace = 0;
	int rdn_seq_len = 0;
	int rdn_set_len = 0;
	int dn_seq_len = 0;
	int pos = 0;

	err_t ugh = NULL;

	/* leave room for prefix */
	u_char *dn_ptr = dn->ptr + 1 + ASN1_MAX_LEN_LEN;

	state_t state = SEARCH_OID;

	do {
		switch (state) {
		case SEARCH_OID:
			if (*src != ' ' && *src != '/' && *src != ',') {
				oid.ptr = (unsigned char *)src;
				oid.len = 1;
				state = READ_OID;
			}
			break;
		case READ_OID:
			if (*src != ' ' && *src != '=') {
				oid.len++;
			} else {
				for (pos = 0; pos < (int)X501_RDN_ROOF;
					pos++) {
					if (strlen(x501rdns[pos].name) ==
						oid.len &&
						strncasecmp(x501rdns[pos].name,
							(char *)oid.ptr,
							oid.len) == 0)
						break;	/* found a valid OID */
				}
				if (pos == X501_RDN_ROOF) {
					ugh = "unknown OID in ID_DER_ASN1_DN";
					state = UNKNOWN_OID;
					break;
				}
				code_asn1_length(x501rdns[pos].oid.len,
						&asn1_oid_len);

				/* reset oid and change state */
				oid = empty_chunk;
				state = SEARCH_NAME;
			}
			break;
		case SEARCH_NAME:
			if (*src != ' ' && *src != '=') {
				name.ptr = (unsigned char *)src;
				name.len = 1;
				whitespace = 0;
				state = READ_NAME;
			}
			break;
		case READ_NAME:
			if (*src != ',' && *src != '/' && *src != '\0') {
				name.len++;
				if (*src == ' ')
					whitespace++;
				else
					whitespace = 0;
			} else {
				if (*src == ',') {
					if (*++src == ',') {
						src--;
						name.len++;
						escape_char(src, ',');
						break;
					} else {
						src--;
					}
				}
				if (*src == '/') {
					if (*++src == '/') {
						src--;
						name.len++;
						escape_char(src, '/');
						break;
					} else {
						src--;
					}
				}

				name.len -= whitespace;
				code_asn1_length(name.len, &asn1_name_len);

				/*
				 * compute the length of the relative
				 * distinguished name sequence
				 */
				rdn_seq_len = 1 + asn1_oid_len.len +
					x501rdns[pos].oid.len +
					1 + asn1_name_len.len + name.len;
				code_asn1_length(rdn_seq_len,
						&asn1_rdn_seq_len);

				/*
				 * compute the length of the relative
				 * distinguished name set
				 */
				rdn_set_len = 1 + asn1_rdn_seq_len.len +
					rdn_seq_len;
				code_asn1_length(rdn_set_len,
						&asn1_rdn_set_len);

				/* encode the relative distinguished name */
				if (IDTOA_BUF < dn_ptr - dn->ptr +
					1 + asn1_rdn_set_len.len +
					/* set */
					1 + asn1_rdn_seq_len.len +
					/* sequence */
					1 + asn1_oid_len.len +
					x501rdns[pos].oid.len +	/*
								 * oid len,
								 * oid
								 */
					1 + asn1_name_len.len + name.len
					/* type name */
					) {
					/* no room! */
					ugh = "DN is too big";
					state = UNKNOWN_OID;
					/*
					 * I think that it is safe to continue
					 * (but perhaps pointless)
					 */
				} else {
					*dn_ptr++ = ASN1_SET;
					chunkcpy(dn_ptr, asn1_rdn_set_len);
					*dn_ptr++ = ASN1_SEQUENCE;
					chunkcpy(dn_ptr, asn1_rdn_seq_len);
					*dn_ptr++ = ASN1_OID;
					chunkcpy(dn_ptr, asn1_oid_len);
					chunkcpy(dn_ptr, x501rdns[pos].oid);
					/*
					 * encode the ASN.1 character string
					 * type of the name
					 */
					*dn_ptr++ =
						(x501rdns[pos].type ==
							ASN1_PRINTABLESTRING &&
							!is_printablestring(
								name)) ?
						ASN1_T61STRING :
						x501rdns[pos].type;
					chunkcpy(dn_ptr, asn1_name_len);
					chunkcpy(dn_ptr, name);

					/*
					 * accumulate the length of the
					 * distinguished name sequence
					 */
					dn_seq_len += 1 +
						asn1_rdn_set_len.len +
						rdn_set_len;

					/* reset name and change state */
					name = empty_chunk;
					state = SEARCH_OID;
				}
			}
			break;
		case UNKNOWN_OID:
			break;
		}
	} while (*src++ != '\0');

	/*
	 * complete the distinguished name sequence: prefix it with
	 * ASN1_SEQUENCE and length
	 */
	code_asn1_length((size_t)dn_seq_len, &asn1_dn_seq_len);
	dn->ptr += ASN1_MAX_LEN_LEN + 1 - 1 - asn1_dn_seq_len.len;
	dn->len = 1 + asn1_dn_seq_len.len + dn_seq_len;
	dn_ptr = dn->ptr;
	*dn_ptr++ = ASN1_SEQUENCE;
	chunkcpy(dn_ptr, asn1_dn_seq_len);
	return ugh;
}

/*
 * compare two distinguished names by
 * comparing the individual RDNs
 */
bool same_dn(chunk_t a, chunk_t b)
{
	chunk_t rdn_a, rdn_b, attribute_a, attribute_b;
	chunk_t oid_a, oid_b, value_a, value_b;
	asn1_t type_a, type_b;
	bool next_a, next_b;

	/* same lengths for the DNs */
	if (a.len != b.len)
		return FALSE;

	/* try a binary comparison first */
	if (memeq(a.ptr, b.ptr, b.len))
		return TRUE;

	/* initialize DN parsing */
	if (init_rdn(a, &rdn_a, &attribute_a, &next_a) != NULL ||
		init_rdn(b, &rdn_b, &attribute_b, &next_b) != NULL)
		return FALSE;

	/* fetch next RDN pair */
	while (next_a && next_b) {
		/* parse next RDNs and check for errors */
		if (get_next_rdn(&rdn_a, &attribute_a, &oid_a, &value_a,
					&type_a, &next_a) != NULL ||
			get_next_rdn(&rdn_b, &attribute_b, &oid_b, &value_b,
				&type_b, &next_b) != NULL)
			return FALSE;

		/* OIDs must agree */
		if (oid_a.len != oid_b.len ||
			!memeq(oid_a.ptr, oid_b.ptr, oid_b.len))
			return FALSE;

		/* same lengths for values */
		if (value_a.len != value_b.len)
			return FALSE;

		/*
		 * printableStrings and email RDNs require uppercase
		 * comparison
		 */
		if (type_a == type_b && (type_a == ASN1_PRINTABLESTRING ||
						(type_a == ASN1_IA5STRING &&
							known_oid(oid_a) ==
							OID_PKCS9_EMAIL))) {
			if (strncasecmp((char *)value_a.ptr,
						(char *)value_b.ptr,
						value_b.len) != 0)
				return FALSE;
		} else {
			if (strncmp((char *)value_a.ptr, (char *)value_b.ptr,
					value_b.len) != 0)
				return FALSE;
		}
	}
	/* both DNs must have same number of RDNs */
	if (next_a || next_b)
		return FALSE;

	/* the two DNs are equal! */
	return TRUE;
}

/*
 * compare two distinguished names by comparing the individual RDNs.
 * A single'*' character designates a wildcard RDN in DN b.
 */
bool match_dn(chunk_t a, chunk_t b, int *wildcards)
{
	chunk_t rdn_a, rdn_b, attribute_a, attribute_b;
	chunk_t oid_a, oid_b, value_a, value_b;
	asn1_t type_a, type_b;
	bool next_a, next_b;

	/* initialize wildcard counter */
	*wildcards = 0;

	/* initialize DN parsing */
	if (init_rdn(a, &rdn_a, &attribute_a, &next_a) != NULL ||
		init_rdn(b, &rdn_b, &attribute_b, &next_b) != NULL)
		return FALSE;

	/* fetch next RDN pair */
	while (next_a && next_b) {
		/* parse next RDNs and check for errors */
		if (get_next_rdn(&rdn_a, &attribute_a, &oid_a, &value_a,
					&type_a, &next_a) != NULL ||
			get_next_rdn(&rdn_b, &attribute_b, &oid_b, &value_b,
				&type_b, &next_b) != NULL)
			return FALSE;

		/* OIDs must agree */
		if (oid_a.len != oid_b.len ||
			!memeq(oid_a.ptr, oid_b.ptr, oid_b.len))
			return FALSE;

		/* does rdn_b contain a wildcard? */
		if (value_b.len == 1 && *value_b.ptr == '*') {
			(*wildcards)++;
			continue;
		}

		/* same lengths for values */
		if (value_a.len != value_b.len)
			return FALSE;

		/*
		 * printableStrings and email RDNs require uppercase
		 * comparison
		 */
		if (type_a == type_b && (type_a == ASN1_PRINTABLESTRING ||
						(type_a == ASN1_IA5STRING &&
							known_oid(oid_a) ==
							OID_PKCS9_EMAIL))) {
			if (strncasecmp((char *)value_a.ptr,
						(char *)value_b.ptr,
						value_b.len) != 0)
				return FALSE;
		} else {
			if (strncmp((char *)value_a.ptr, (char *)value_b.ptr,
					value_b.len) != 0)
				return FALSE;
		}
	}
	/* both DNs must have same number of RDNs */
	if (next_a || next_b) {
		if (*wildcards) {
			char abuf[ASN1_BUF_LEN];
			char bbuf[ASN1_BUF_LEN];

			dntoa(abuf, ASN1_BUF_LEN, a);
			dntoa(bbuf, ASN1_BUF_LEN, b);

			libreswan_log(
				"while comparing A='%s'<=>'%s'=B with a wildcard count of %d, %s had too few RDNs",
				abuf, bbuf, *wildcards,
				(next_a ? "B" : "A"));
		}
		return FALSE;
	}

	/* the two DNs match! */
	return TRUE;
}

/*
 * compare two X.509 certificates by comparing their signatures
 */
bool same_x509cert(const x509cert_t *a, const x509cert_t *b)
{
	return same_chunk(a->signature, b->signature);
}

/*
 * for each link pointing to the certificate
 * increase the count by one
 */
void share_x509cert(x509cert_t *cert)
{
	if (cert != NULL)
		cert->count++;
}

/*
 * choose either subject DN or a subjectAltName as connection end ID
 */
void select_x509cert_id(x509cert_t *cert, struct id *end_id)
{
	bool copy_subject_dn = TRUE;	/* ID is subject DN */

	if (end_id->kind != ID_NONE) {	/* check for matching subjectAltName */
		generalName_t *gn = cert->subjectAltName;

		while (gn != NULL) {
			struct id id = empty_id;

			gntoid(&id, gn);
			if (same_id(&id, end_id)) {
				/* take subjectAltName instead */
				copy_subject_dn = FALSE;
				break;
			}
			gn = gn->next;
		}
	}

	if (copy_subject_dn) {
		if (end_id->kind != ID_NONE &&
			end_id->kind != ID_DER_ASN1_DN &&
			end_id->kind != ID_FROMCERT) {
			char buf[IDTOA_BUF];

			idtoa(end_id, buf, IDTOA_BUF);
			libreswan_log(
				"  no subjectAltName matches ID '%s', replaced by subject DN",
				buf);
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
bool same_keyid(chunk_t a, chunk_t b)
{
	if (a.ptr == NULL || b.ptr == NULL)
		return FALSE;

	return same_chunk(a, b);
}

/*
 * check for equality between two serial numbers
 */
bool same_serial(chunk_t a, chunk_t b)
{
	/* do not compare serial numbers if one of them is not defined */
	if (a.ptr == NULL || b.ptr == NULL)
		return TRUE;

	return same_chunk(a, b);
}

/*
 * free the dynamic memory used to store generalNames
 */
void free_generalNames(generalName_t* gn, bool free_name)
{
	while (gn != NULL) {
		generalName_t *gn_top = gn;
		if (free_name)
			pfree(gn->name.ptr);
		gn = gn->next;
		pfree(gn_top);
	}
}

/*
 * free a X.509 certificate
 */
void free_x509cert(x509cert_t *cert)
{
	if (cert != NULL) {
		free_generalNames(cert->subjectAltName, FALSE);
		free_generalNames(cert->crlDistributionPoints, FALSE);
		pfreeany(cert->certificate.ptr);
		pfree(cert);
		cert = NULL;
	}
}

/*
 * free the dynamic memory used to store revoked certificates
 */
static void free_revoked_certs(revokedCert_t* revokedCerts)
{
	while (revokedCerts != NULL) {
		revokedCert_t * revokedCert = revokedCerts;
		revokedCerts = revokedCert->next;
		pfree(revokedCert);
	}
}

/*
 * free the dynamic memory used to store CRLs
 */
void free_crl(x509crl_t *crl)
{
	free_revoked_certs(crl->revokedCertificates);
	free_generalNames(crl->distributionPoints, TRUE);
	pfree(crl->certificateList.ptr);
	pfree(crl);
}

/*
 * compute a digest over a binary blob
 */
static bool compute_digest(chunk_t tbs, int alg, chunk_t *digest)
{
	switch (alg) {
#ifdef USE_MD5
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
#endif
#ifdef USE_SHA1
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
#endif
#ifdef USE_SHA2
	case OID_SHA256:
	case OID_SHA256_WITH_RSA:
	{
		unsigned int len;
		SECStatus s;
		sha256_context context;

		sha256_init(&context);
		sha256_write(&context, tbs.ptr, tbs.len);
		s = PK11_DigestFinal(context.ctx_nss, digest->ptr, &len,
				SHA2_256_DIGEST_SIZE);
		passert(s == SECSuccess);
		passert(len == SHA2_256_DIGEST_SIZE);
		PK11_DestroyContext(context.ctx_nss, PR_TRUE);
		digest->len = SHA2_256_DIGEST_SIZE;
		return TRUE;
	}
	case OID_SHA384:
	case OID_SHA384_WITH_RSA:
	{
		sha512_context context;
		unsigned int len;
		SECStatus s;

		sha384_init(&context);
		s = PK11_DigestOp(context.ctx_nss, tbs.ptr, tbs.len);
		passert(s == SECSuccess);
		s = PK11_DigestFinal(context.ctx_nss, digest->ptr, &len,
				SHA2_384_DIGEST_SIZE);
		passert(s == SECSuccess);
		passert(len == SHA2_384_DIGEST_SIZE);
		PK11_DestroyContext(context.ctx_nss, PR_TRUE);
		digest->len = SHA2_384_DIGEST_SIZE;
		return TRUE;
	}
	case OID_SHA512:
	case OID_SHA512_WITH_RSA:
	{
		sha512_context context;
		unsigned int len;
		SECStatus s;

		sha512_init(&context);
		sha512_write(&context, tbs.ptr, tbs.len);

		s = PK11_DigestFinal(context.ctx_nss, digest->ptr, &len,
				SHA2_512_DIGEST_SIZE);
		passert(s == SECSuccess);
		passert(len == SHA2_512_DIGEST_SIZE);
		PK11_DestroyContext(context.ctx_nss, PR_TRUE);
		digest->len = SHA2_512_DIGEST_SIZE;
		return TRUE;
	}
#endif
	default:
		digest->len = 0;
		return FALSE;
	}
}

/*
 * decrypts an RSA signature using the issuer's certificate
 */
static bool decrypt_sig(chunk_t sig, int alg, const x509cert_t *issuer_cert,
			chunk_t *digest)
{
	switch (alg) {
	case OID_RSA_ENCRYPTION:
	case OID_MD5_WITH_RSA:
	case OID_SHA1_WITH_RSA:
	case OID_SHA1_WITH_RSA_OIW:
	case OID_SHA256_WITH_RSA:
	case OID_SHA384_WITH_RSA:
	case OID_SHA512_WITH_RSA:
	case OID_SHA224_WITH_RSA:
	{

		SECKEYPublicKey *publicKey;
		PRArenaPool *arena;
		SECStatus retVal;
		SECItem nss_n, nss_e;
		SECItem dsig, signature;
		int skip;

		arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
		if (arena == NULL) {
			PORT_SetError(SEC_ERROR_NO_MEMORY);
			return FALSE;
		}

		publicKey =
			(SECKEYPublicKey *) PORT_ArenaZAlloc(arena,
				sizeof(SECKEYPublicKey));
		if (publicKey == NULL) {
			PORT_FreeArena(arena, PR_FALSE);
			PORT_SetError(SEC_ERROR_NO_MEMORY);
			DBG(DBG_X509 | DBG_CONTROL,
				DBG_log("NSS: error in allocating memory to public key");
				);
			return FALSE;
		}

		publicKey->arena = arena;
		publicKey->keyType = rsaKey;
		publicKey->pkcs11Slot = NULL;
		publicKey->pkcs11ID = CK_INVALID_HANDLE;

		DBG(DBG_X509 | DBG_CONTROL,	/* n */
			DBG_dump("NSS cert: modulus : ",
				issuer_cert->modulus.ptr,
				issuer_cert->modulus.len);
			);

		DBG(DBG_X509 | DBG_CONTROL,	/* e */
			DBG_dump("NSS cert: exponent : ",
				issuer_cert->publicExponent.ptr,
				issuer_cert->publicExponent.len);
			);

		DBG(DBG_X509 | DBG_CONTROL,	/* s */
			DBG_dump("NSS: input signature : ", sig.ptr, sig.len);
			);

		/* Converting n and e to nss_n and nss_e */

		skip = (issuer_cert->modulus.len > 0 &&
			issuer_cert->modulus.ptr[0] == 0x00) ? 1 : 0;
		if (skip != 1) {
			DBG(DBG_X509 | DBG_CONTROL,
				DBG_log("NSS: RSA Modulus has no leading 0x00 byte, modules < 2^511 ?");
				);
		}
		nss_n.data = issuer_cert->modulus.ptr + skip;
		nss_n.len = issuer_cert->modulus.len - skip;
		nss_n.type = siBuffer;

		/*
		 * exponents are always < 2^255, so they never have
		 * a leading zero
		 */
		nss_e.data = issuer_cert->publicExponent.ptr;
		nss_e.len = issuer_cert->publicExponent.len;
		nss_e.type = siBuffer;

		retVal = SECITEM_CopyItem(arena, &publicKey->u.rsa.modulus,
					&nss_n);
		if (retVal == SECSuccess) {
			retVal = SECITEM_CopyItem(arena,
						&publicKey->
						u.rsa.publicExponent,
						&nss_e);
		}

		if (retVal != SECSuccess) {
			SECKEY_DestroyPublicKey(publicKey);
			loglog(RC_LOG_SERIOUS,
				"NSS x509dn.c: error in creating public key");
			return FALSE;
		}

		skip = sig.len > nss_n.len && sig.ptr[0] == 0x00 ? 1 : 0;

		if (skip != 1) {
			DBG(DBG_X509 | DBG_CONTROL,
				DBG_log("NSS: RSA Signature has no leading 0x00 byte?");
				);
		}

		signature.data = sig.ptr + skip;
		signature.len  = sig.len - skip;
		signature.type = siBuffer;
		DBG(DBG_X509 | DBG_CONTROL,
			DBG_log("RSA Signature length is %d", signature.len);
			);

		dsig.len = signature.len;	/*
						 * this is a hack! yes,
						 * a digest will always be
						 * shorter then the full sig
						 */
		dsig.data = alloc_bytes(dsig.len, "NSS decrypted signature");
		dsig.type = siBuffer;

		/* Verifying RSA signature */
		if (PK11_VerifyRecover(publicKey, &signature, &dsig,
					lsw_return_nss_password_file_info()) ==
			SECSuccess) {
			DBG(DBG_X509 | DBG_CONTROL,
				DBG_dump("NSS digest sig: ",
					dsig.data, dsig.len);
				DBG_log("NSS: length of digest sig = %d",
					dsig.len);
				);
		} else {
			loglog(RC_LOG_SERIOUS,
				"NSS: PK11_VerifyRecover() failed (%d)",
				PR_GetError());
		}

		SECKEY_DestroyPublicKey(publicKey);

		DBG(DBG_X509 | DBG_CONTROL,
			DBG_dump("NSS scratchpad plus computed digest sig: ",
				dsig.data, dsig.len);
			DBG_dump("NSS adjusted digest sig: ",
				dsig.data + dsig.len - digest->len,
				digest->len);
			DBG_dump_chunk("NSS expected digest sig: ", *digest);
			);

		if (memeq(dsig.data + dsig.len - digest->len, digest->ptr,
				digest->len)) {
			pfree(dsig.data);
			DBG(DBG_CONTROL,
				DBG_log("NSS: RSA Signature verified, hash values matched");
				);
			return TRUE;
		}
		pfree(dsig.data);

		loglog(RC_LOG_SERIOUS,
			"NSS: RSA Signature FAILED verification");
		digest->len = 0;
		return FALSE;
	}

	case OID_MD2_WITH_RSA:
	{
		loglog(RC_LOG_SERIOUS,
			"NSS: RSA Signature FAILED verification - RSA with MD2 not supported - too weak");
		digest->len = 0;
		return FALSE;
	}

	default:
		loglog(RC_LOG_SERIOUS,
			"decrypt_sig: RSA Signature FAILED verification - OID RSA algorithm '%d' not supported", alg);
		digest->len = 0;
		return FALSE;
	}
}

/*
 *   Check if a signature over binary blob is genuine
 */
bool check_signature(chunk_t tbs, chunk_t sig, int algorithm,
		const x509cert_t *issuer_cert)
{
	u_char digest_buf[MAX_DIGEST_LEN];
	chunk_t digest = { digest_buf, MAX_DIGEST_LEN };

	if (algorithm != OID_UNKNOWN) {
		DBG(DBG_X509 | DBG_CONTROL,
			DBG_log("signature algorithm: '%s'",
				oid_names[algorithm].name);
			);
	} else {
		DBG(DBG_X509 | DBG_CONTROL,
			DBG_log("unknown signature algorithm");
			);
	}

	if (!compute_digest(tbs, algorithm, &digest)) {
		libreswan_log("  digest algorithm not supported");
		return FALSE;
	}

	DBG(DBG_CONTROL,
		DBG_dump_chunk("  digest:", digest);
		);

	if (!decrypt_sig(sig, algorithm, issuer_cert, &digest)) {
		libreswan_log(" NSS: failure in verifying signature");
		return FALSE;
	}
	return TRUE;
}

/*
 * extracts the basicConstraints extension
 */
static bool parse_basicConstraints(chunk_t blob, int level0)
{
	asn1_ctx_t ctx;
	chunk_t object;
	u_int level;
	unsigned int objectID = 0;
	bool isCA = FALSE;

	asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

	while (objectID < BASIC_CONSTRAINTS_ROOF) {

		if (!extract_object(basicConstraintsObjects, &objectID,
					&object, &level, &ctx))
			break;

		if (objectID == BASIC_CONSTRAINTS_CA) {
			isCA = object.len && *object.ptr;
			DBG(DBG_CONTROL,
				DBG_log("  %s", isCA ? "TRUE" : "FALSE");
				);
		}
		objectID++;
	}
	return isCA;
}

/*
 *  Converts a X.500 generalName into an ID
 */
void gntoid(struct id *id, const generalName_t *gn)
{
	switch (gn->kind) {
	case GN_DNS_NAME:	/* ID type: ID_FQDN */
		id->kind = ID_FQDN;
		id->name = gn->name;
		break;
	case GN_IP_ADDRESS:	/* ID type: ID_IPV4_ADDR */
	{
		const struct af_info *afi = &af_inet4_info;
		err_t ugh = NULL;

		id->kind = afi->id_addr;
		ugh = initaddr(gn->name.ptr, gn->name.len, afi->af,
			&id->ip_addr);
		if (!ugh) {
			libreswan_log(
				"Warning: gntoid() failed to initaddr(): %s",
				ugh);
		}

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
static generalName_t*parse_generalName(chunk_t blob, int level0)
{
	asn1_ctx_t ctx;
	chunk_t object;
	unsigned int objectID = 0;
	u_int level;

	asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

	while (objectID < GN_OBJ_ROOF) {
		bool valid_gn = FALSE;

		if (!extract_object(generalNameObjects, &objectID, &object,
					&level, &ctx))
			return NULL;

		switch (objectID) {
		case GN_OBJ_RFC822_NAME:
		case GN_OBJ_DNS_NAME:
		case GN_OBJ_URI:
			DBG(DBG_PARSING,
				DBG_log("  '%.*s'",
					(int)object.len, object.ptr);
				);
			valid_gn = TRUE;
			break;
		case GN_OBJ_DIRECTORY_NAME:
			DBG(DBG_PARSING,
				u_char buf[ASN1_BUF_LEN];
				dntoa((char *)buf, ASN1_BUF_LEN, object);
				DBG_log("  '%s'", buf);
				);
			valid_gn = TRUE;
			break;
		case GN_OBJ_IP_ADDRESS:
			DBG(DBG_PARSING,
				DBG_log("  '%d.%d.%d.%d'", *object.ptr,
					*(object.ptr + 1),
					*(object.ptr + 2), *(object.ptr + 3));
				);
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

		if (valid_gn) {
			generalName_t *gn = alloc_thing(generalName_t,
							"generalName");
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
static generalName_t*parse_generalNames(chunk_t blob, int level0,
					bool implicit)
{
	asn1_ctx_t ctx;
	chunk_t object;
	u_int level;
	unsigned int objectID = 0;

	generalName_t *top_gn = NULL;

	asn1_init(&ctx, blob, level0, implicit, DBG_RAW);

	while (objectID < GENERAL_NAMES_ROOF) {
		if (!extract_object(generalNamesObjects, &objectID, &object,
					&level, &ctx))
			return NULL;

		if (objectID == GENERAL_NAMES_GN) {
			generalName_t *gn =
				parse_generalName(object, level + 1);
			if (gn != NULL) {
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
		name = gn->name;

	free_generalNames(gn, FALSE);

	return name;
}

/*
 * extracts and converts a UTCTIME or GENERALIZEDTIME object
 */
static time_t parse_time(chunk_t blob, int level0)
{
	asn1_ctx_t ctx;
	chunk_t object;
	u_int level;
	u_int objectID = 0;

	asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

	while (objectID < TIME_ROOF) {
		if (!extract_object(timeObjects, &objectID, &object, &level,
					&ctx))
			return UNDEFINED_TIME;

		if (objectID == TIME_UTC || objectID == TIME_GENERALIZED) {
			return asn1totime(&object, (objectID == TIME_UTC) ?
					ASN1_UTCTIME : ASN1_GENERALIZEDTIME);
		}
		objectID++;
	}
	return UNDEFINED_TIME;
}

/*
 * extracts an algorithmIdentifier
 */
int parse_algorithmIdentifier(chunk_t blob, int level0)
{
	asn1_ctx_t ctx;
	chunk_t object;
	u_int level;
	u_int objectID = 0;

	asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

	while (objectID < ALGORITHM_IDENTIFIER_ROOF) {
		if (!extract_object(algorithmIdentifierObjects, &objectID,
					&object, &level, &ctx))
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
static chunk_t parse_keyIdentifier(chunk_t blob, int level0, bool implicit)
{
	asn1_ctx_t ctx;
	chunk_t object;
	u_int level;
	u_int objectID = 0;

	asn1_init(&ctx, blob, level0, implicit, DBG_RAW);

	extract_object(keyIdentifierObjects, &objectID, &object, &level, &ctx);
	return object;
}

/*
 * extracts an authoritykeyIdentifier
 */
void parse_authorityKeyIdentifier(chunk_t blob, int level0,
				chunk_t *authKeyID,
				chunk_t *authKeySerialNumber)
{
	asn1_ctx_t ctx;
	chunk_t object;
	u_int level;
	u_int objectID = 0;

	asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

	while (objectID < AUTH_KEY_ID_ROOF) {
		if (!extract_object(authorityKeyIdentifierObjects, &objectID,
					&object, &level, &ctx))
			return;

		switch (objectID) {
		case AUTH_KEY_ID_KEY_ID:
			*authKeyID = parse_keyIdentifier(object, level + 1,
							TRUE);
			break;
		case AUTH_KEY_ID_CERT_ISSUER:
		{
			generalName_t * gn = parse_generalNames(object,
								level + 1,
								TRUE);

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
static void parse_authorityInfoAccess(chunk_t blob, int level0,
				chunk_t *accessLocation)
{
	asn1_ctx_t ctx;
	chunk_t object;
	u_int level;
	u_int objectID = 0;

	u_int accessMethod = OID_UNKNOWN;

	asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

	while (objectID < AUTH_INFO_ACCESS_ROOF) {
		if (!extract_object(authorityInfoAccessObjects, &objectID,
					&object, &level, &ctx))
			return;

		switch (objectID) {
		case AUTH_INFO_ACCESS_METHOD:
			accessMethod = known_oid(object);
			break;
		case AUTH_INFO_ACCESS_LOCATION:
		{
			switch (accessMethod) {
			case OID_OCSP:
				if (*object.ptr == ASN1_CONTEXT_S_6) {
					if (asn1_length(&object) ==
						ASN1_INVALID_LENGTH)
						return;

					DBG(DBG_PARSING,
						DBG_log("  '%.*s'",
							(int)object.len,
							object.ptr);
						);

					/* only HTTP(S) URIs accepted */
					if (strncasecmp((char *)object.ptr,
							"http", 4) == 0) {
						*accessLocation = object;
						return;
					}
				}
				libreswan_log(
					"warning: ignoring OCSP InfoAccessLocation with unknown protocol");
				break;
			default:
				/* unknown accessMethod, ignoring */
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
static bool parse_extendedKeyUsage(chunk_t blob, int level0)
{
	asn1_ctx_t ctx;
	chunk_t object;
	u_int level;
	u_int objectID = 0;

	asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

	while (objectID < EXT_KEY_USAGE_ROOF) {
		if (!extract_object(extendedKeyUsageObjects, &objectID,
					&object, &level, &ctx))
			return FALSE;

		if (objectID == EXT_KEY_USAGE_PURPOSE_ID &&
			known_oid(object) == OID_OCSP_SIGNING)
			return TRUE;

		objectID++;
	}
	return FALSE;
}

/*
 *  extracts one or several crlDistributionPoints and puts them into
 *  a chained list
 */
static generalName_t*parse_crlDistributionPoints(chunk_t blob, int level0)
{
	asn1_ctx_t ctx;
	chunk_t object;
	u_int level;
	u_int objectID = 0;

	generalName_t *top_gn = NULL;	/* top of the chained list */
	generalName_t **tail_gn = &top_gn;	/* tail of the chained list */

	asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

	while (objectID < CRL_DIST_POINTS_ROOF) {
		if (!extract_object(crlDistributionPointsObjects, &objectID,
					&object, &level, &ctx))
			return NULL;

		if (objectID == CRL_DIST_POINTS_FULLNAME) {
			generalName_t *gn = parse_generalNames(object,
							level + 1,
							TRUE);
			/*
			 * append extracted generalNames to
			 * existing chained list
			 */
			*tail_gn = gn;
			/* find new tail of the chained list */
			while (gn != NULL) {
				tail_gn = &gn->next;
				gn = gn->next;
			}
		}
		objectID++;
	}
	return top_gn;
}

/*
 *  Parses an X.509v3 certificate
 */
bool parse_x509cert(chunk_t blob, u_int level0, x509cert_t *cert)
{
	asn1_ctx_t ctx;
	bool critical;
	chunk_t object;
	u_int level;
	u_int extn_oid = 0;
	u_int objectID = 0;

	asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

	while (objectID < X509_OBJ_ROOF) {
		if (!extract_object(certObjects, &objectID, &object, &level,
					&ctx))
			return FALSE;

		/*
		 * those objects which will parsed further need
		 * the next higher level
		 */
		level++;

		switch (objectID) {
		case X509_OBJ_CERTIFICATE:
			cert->certificate = object;
			break;
		case X509_OBJ_TBS_CERTIFICATE:
			cert->tbsCertificate = object;
			break;
		case X509_OBJ_VERSION:
			cert->version =
				(object.len) ? (1 + (u_int) * object.ptr) : 1;
			DBG(DBG_PARSING,
				DBG_log("  v%d", cert->version);
				);
			break;
		case X509_OBJ_SERIAL_NUMBER:
			cert->serialNumber = object;
			break;
		case X509_OBJ_SIG_ALG:
			cert->sigAlg =
				parse_algorithmIdentifier(object, level);
			break;
		case X509_OBJ_ISSUER:
			cert->issuer = object;
			DBG(DBG_PARSING,
				u_char buf[ASN1_BUF_LEN];
				dntoa((char *)buf, ASN1_BUF_LEN, object);
				DBG_log("  '%s'", buf);
				);
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
				u_char buf[ASN1_BUF_LEN];
				dntoa((char *)buf, ASN1_BUF_LEN, object);
				DBG_log("  '%s'", buf);
				);
			break;
		case X509_OBJ_SUBJECT_PUBLIC_KEY_ALGORITHM:
			if (parse_algorithmIdentifier(object,
							level) ==
				OID_RSA_ENCRYPTION) {
				cert->subjectPublicKeyAlgorithm =
					PUBKEY_ALG_RSA;
			} else {
				plog("  unsupported public key algorithm");
				return FALSE;
			}
			break;
		case X509_OBJ_SUBJECT_PUBLIC_KEY:
			if (ctx.blobs[4].len > 0 && *ctx.blobs[4].ptr ==
				0x00) {
				/*
				 * skip initial bit string octet defining
				 * 0 unused bits
				 */

				ctx.blobs[4].ptr++;
				ctx.blobs[4].len--;
			} else {
				plog("  invalid RSA public key format");
				return FALSE;
			}
			break;
		case X509_OBJ_MODULUS:
			if (object.len < RSA_MIN_OCTETS + 1) {
				plog("  " RSA_MIN_OCTETS_UGH);
				return FALSE;
			}
			if (object.len > RSA_MAX_OCTETS +
				(size_t)(*object.ptr == 0x00)) {
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
				DBG_log("  %s", critical ? "TRUE" : "FALSE");
				);
			break;
		case X509_OBJ_EXTN_VALUE:
		{
			switch (extn_oid) {
			case OID_SUBJECT_KEY_ID:
				cert->subjectKeyID =
					parse_keyIdentifier(object, level,
							FALSE);
				break;
			case OID_SUBJECT_ALT_NAME:
				cert->subjectAltName =
					parse_generalNames(object, level,
							FALSE);
				break;
			case OID_BASIC_CONSTRAINTS:
				cert->isCA =
					parse_basicConstraints(object, level);
				break;
			case OID_CRL_DISTRIBUTION_POINTS:
				cert->crlDistributionPoints =
					parse_crlDistributionPoints(object,
								level);
				break;
			case OID_AUTHORITY_KEY_ID:
				parse_authorityKeyIdentifier(object, level,
							&cert->authKeyID,
							&cert->
							authKeySerialNumber);
				break;
			case OID_AUTHORITY_INFO_ACCESS:
				parse_authorityInfoAccess(object, level,
							&cert->accessLocation);
				break;
			case OID_EXTENDED_KEY_USAGE:
				cert->isOcspSigner = parse_extendedKeyUsage(
					object, level);
				break;
			default:
				break;
			}
		}
		break;
		case X509_OBJ_ALGORITHM:
			cert->algorithm = parse_algorithmIdentifier(object,
								level);
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
bool parse_x509crl(chunk_t blob, u_int level0, x509crl_t *crl)
{
	asn1_ctx_t ctx;
	bool critical;
	chunk_t extnID;
	chunk_t userCertificate;
	chunk_t object;
	u_int level;
	u_int objectID = 0;

	userCertificate.len = 0;
	userCertificate.ptr = NULL;

	asn1_init(&ctx, blob, level0, FALSE, DBG_RAW);

	while (objectID < CRL_OBJ_ROOF) {
		if (!extract_object(crlObjects, &objectID, &object, &level,
					&ctx))
			return FALSE;

		/*
		 * those objects which will parsed further need
		 * the next higher level
		 */
		level++;

		switch (objectID) {
		case CRL_OBJ_CERTIFICATE_LIST:
			crl->certificateList = object;
			break;
		case CRL_OBJ_TBS_CERT_LIST:
			crl->tbsCertList = object;
			break;
		case CRL_OBJ_VERSION:
			crl->version =
				(object.len) ? (1 + (u_int) * object.ptr) : 1;
			DBG(DBG_PARSING,
				DBG_log("  v%d", crl->version);
				);
			break;
		case CRL_OBJ_SIG_ALG:
			crl->sigAlg = parse_algorithmIdentifier(object, level);
			break;
		case CRL_OBJ_ISSUER:
			crl->issuer = object;
			DBG(DBG_PARSING,
				u_char buf[ASN1_BUF_LEN];
				dntoa((char *)buf, ASN1_BUF_LEN, object);
				DBG_log("  '%s'", buf);
				);
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
			/*
			 * put all the serial numbers and the revocation
			 * date in a chained list with revocedCertificates
			 * pointing to the first revoked certificate
			 */
			revokedCert_t *revokedCert = alloc_thing(revokedCert_t,
								"revokedCert");
			/*
			 * since it is assumed here that
			 * CRL_OBJ_USER_CERTIFICATE is reached
			 * before CRL_OBJ_REVOCATION_DATE
			 */
			revokedCert->userCertificate = userCertificate;
			revokedCert->revocationDate =
				parse_time(object, level);
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
				DBG_log("  %s", critical ? "TRUE" : "FALSE");
				);
			break;
		case CRL_OBJ_EXTN_VALUE:
		{
			u_int extn_oid = known_oid(extnID);

			if (extn_oid == OID_AUTHORITY_KEY_ID) {
				parse_authorityKeyIdentifier(object, level,
							&crl->authKeyID,
							&crl->
							authKeySerialNumber);
			}
		}
		break;
		case CRL_OBJ_ALGORITHM:
			crl->algorithm = parse_algorithmIdentifier(object,
								level);
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
