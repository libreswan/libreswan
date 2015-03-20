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
 */

#ifndef _X509_H
#define _X509_H

/* Maximum length of ASN.1 distinquished name */
#define ASN1_BUF_LEN	      512

/* Definition of generalNames kinds */

typedef enum {
    GN_OTHER_NAME =		0,
    GN_RFC822_NAME =		1,
    GN_DNS_NAME =		2,
    GN_X400_ADDRESS =		3,
    GN_DIRECTORY_NAME =		4,
    GN_EDI_PARTY_NAME = 	5,
    GN_URI =			6,
    GN_IP_ADDRESS =		7,
    GN_REGISTERED_ID =		8
} generalNames_t;

/* access structure for a GeneralName */

typedef struct generalName generalName_t;

struct generalName {
    generalName_t   *next;
    generalNames_t  kind;
    chunk_t         name;
};

/* authority flags */

#define AUTH_NONE	0x00	/* no authorities */
#define AUTH_CA		0x01	/* certification authority */
#define AUTH_AA		0x02	/* authorization authority */
#define AUTH_OCSP	0x04	/* ocsp signing authority */

/* forward declaration */
struct id;

/* access structure for an X.509v3 certificate */

typedef struct x509cert x509cert_t;

struct x509cert {
  x509cert_t     *next;
  time_t	 installed;
  int		 count;
  u_char	 authority_flags;
  chunk_t	 certificate;
  chunk_t          tbsCertificate;
  u_int              version;
  chunk_t            serialNumber;
                /*   signature */
  int                  sigAlg;
  chunk_t            issuer;
                /*   validity */
  time_t               notBefore;
  time_t               notAfter;
  chunk_t            subject;
                /*   subjectPublicKeyInfo */
  enum pubkey_alg      subjectPublicKeyAlgorithm;
                /*     subjectPublicKey */
  chunk_t                modulus;
  chunk_t                publicExponent;
                /*   issuerUniqueID */
                /*   subjectUniqueID */
                /*   v3 extensions */
                /*   extension */
                /*     extension */
                /*       extnID */
                /*       critical */
                /*       extnValue */
  bool			   isCA;
  bool			   isOcspSigner; /* ocsp */
  chunk_t		   subjectKeyID;
  chunk_t		   authKeyID;
  chunk_t		   authKeySerialNumber;
  chunk_t		   accessLocation; /* ocsp */
  generalName_t		   *subjectAltName;
  generalName_t		   *crlDistributionPoints;
		/* signatureAlgorithm */
  int                algorithm;
  chunk_t          signature;
};

/* access structure for a revoked serial number */

typedef struct revokedCert revokedCert_t;

struct revokedCert{
  revokedCert_t *next;
  chunk_t       userCertificate;
  time_t        revocationDate;
};

/* storage structure for an X.509 CRL */

typedef struct x509crl x509crl_t;

struct x509crl {
  x509crl_t     *next;
  time_t	 installed;
  generalName_t *distributionPoints;
  chunk_t        certificateList;
  chunk_t          tbsCertList;
  u_int              version;
  	         /*  signature */
  int                  sigAlg;
  chunk_t            issuer;
  time_t             thisUpdate;
  time_t             nextUpdate;
  revokedCert_t      *revokedCertificates;
                /*   v2 extensions */
                /*   crlExtensions */
                /*     extension */
                /*       extnID */
                /*       critical */
                /*       extnValue */
  chunk_t		 authKeyID;
  chunk_t		 authKeySerialNumber;

                /* signatureAlgorithm */
  int                algorithm;
  chunk_t          signature;
};

/*  apply a strict CRL policy
 *  flag set in plutomain.c and used in ipsec_doi.c and rcv_whack.c
 */
extern bool strict_crl_policy;

/*
 * check periodically for expired crls
 */ 
extern long crl_check_interval;

/* used for initialization */
extern const x509crl_t  empty_x509crl;
extern const x509cert_t empty_x509cert;

extern bool same_serial(chunk_t a, chunk_t b);
extern bool same_keyid(chunk_t a, chunk_t b);
extern bool same_dn(chunk_t a, chunk_t b);
#define MAX_CA_PATH_LEN		7
extern bool trusted_ca(chunk_t a, chunk_t b, int *pathlen);
extern bool match_requested_ca(generalName_t *requested_ca
    , chunk_t our_ca, int *our_pathlen);
extern bool match_dn(chunk_t a, chunk_t b, int *wildcards);
extern void hex_str(chunk_t bin, chunk_t *str);
extern int dn_count_wildcards(chunk_t dn);
extern int dntoa(char *dst, size_t dstlen, chunk_t dn);
extern int dntoa_or_null(char *dst, size_t dstlen, chunk_t dn
    , const char* null_dn);
extern err_t atodn(char *src, chunk_t *dn);
extern void gntoid(struct id *id, const generalName_t *gn);
extern void select_x509cert_id(x509cert_t *cert, struct id *end_id);
extern bool parse_x509cert(chunk_t blob, u_int level0, x509cert_t *cert);
extern bool parse_x509crl(chunk_t blob, u_int level0, x509crl_t *crl);
extern int parse_algorithmIdentifier(chunk_t blob, int level0);
extern void parse_authorityKeyIdentifier(chunk_t blob, int level0
    , chunk_t *authKeyID, chunk_t *authKeySerialNumber);
extern chunk_t get_directoryName(chunk_t blob, int level, bool implicit);
extern err_t check_validity(const x509cert_t *cert, time_t *until);
extern bool compute_digest(chunk_t tbs, int alg, chunk_t *digest);
extern bool check_signature(chunk_t tbs, chunk_t sig, int algorithm
    , const x509cert_t *issuer_cert);
extern bool verify_x509cert(/*const*/ x509cert_t *cert, bool strict, time_t *until);
extern x509cert_t* add_x509cert(x509cert_t *cert);
extern x509cert_t* get_x509cert(chunk_t issuer, chunk_t serial, chunk_t keyid
    , x509cert_t* chain);
extern x509cert_t* get_authcert(chunk_t subject, chunk_t serial, chunk_t keyid
    , u_char auth_flags);
extern void share_x509cert(x509cert_t *cert);
extern void release_x509cert(x509cert_t *cert);
extern void free_x509cert(x509cert_t *cert);
extern void store_x509certs(x509cert_t **firstcert, bool strict);
extern void add_authcert(x509cert_t *cert, u_char auth_flags);
extern bool trust_authcert_candidate(const x509cert_t *cert
    , const x509cert_t *alt_chain);
extern void load_authcerts(const char *type, const char *path
    , u_char auth_flags);
extern void load_crls(void);
extern bool insert_crl(chunk_t blob, chunk_t crl_uri);
extern void list_x509_end_certs(bool utc);
extern void list_authcerts(const char *caption, u_char auth_flags, bool utc);
extern void list_crls(bool utc, bool strict);
extern void free_authcerts(void);
extern void free_crls(void);
extern void free_crl(x509crl_t *crl);
extern void free_generalNames(generalName_t* gn, bool free_name);

/* in x509dn.c */
extern bool same_x509cert(const x509cert_t *a, const x509cert_t *b);

/* in x509chain.c */
extern bool x509_check_revocation(const x509crl_t *crl, chunk_t serial);
extern x509cert_t *x509_get_authcerts_chain(void);

#if defined(LIBCURL) || defined(LDAP_VER)
extern void check_crls(void);
extern void lock_crl_list(const char *who);
extern void unlock_crl_list(const char *who);
extern void lock_cacert_list(const char *who);
extern void unlock_cacert_list(const char *who);
extern void lock_authcert_list(const char *who);
extern void unlock_authcert_list(const char *who);
#else
/* WARNING empty x509 locking functions defined bypassing real locking */
/* not fixing this hack, see issues #1390, #1391, #1392 */
#define lock_crl_list(who) /* nothing */
#define unlock_crl_list(who) /* nothing */
#define lock_cacert_list(who) /* nothing */
#define unlock_cacert_list(who) /* nothing */
#define lock_authcert_list(who) /* nothing */
#define unlock_authcert_list(who) /* nothing */
#endif

/* filter eliminating the directory entries '.' and '..' */
typedef struct dirent dirent_t;

extern int file_select(
#ifdef SCANDIR_HAS_CONST
		       const
#endif
		       dirent_t *entry);


#endif /* _X509_H */
