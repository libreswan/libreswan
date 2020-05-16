/* Support of X.509 certificates and CRLs
 * Copyright (C) 2000 Andreas Hess, Patric Lichtsteiner, Roger Wegmann
 * Copyright (C) 2001 Marco Bertossa, Andreas Schleiss
 * Copyright (C) 2002 Mario Strasser
 * Copyright (C) 2000-2004 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2015 Matt Rogers <mrogers@libreswan.org>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#ifndef _X509_H
#define _X509_H

#include <nss.h>
#include <cert.h>

#include "deltatime.h"
#include "chunk.h"
#include "err.h"
#include "constants.h"
#include "jambuf.h"

struct logger;
struct pubkey_list;
struct fd;

/*
 * NSS can actually support a much larger path length
 */
#define MAX_CA_PATH_LEN 7

/* Definition of generalNames kinds */

typedef enum {
	GN_OTHER_NAME =		0,
	GN_RFC822_NAME =	1,
	GN_DNS_NAME =		2,
	GN_X400_ADDRESS =	3,
	GN_DIRECTORY_NAME =	4,
	GN_EDI_PARTY_NAME =	5,
	GN_URI =		6,
	GN_IP_ADDRESS =		7,
	GN_REGISTERED_ID =	8
} generalNames_t;

/* access structure for a GeneralName */

typedef struct generalName generalName_t;

struct generalName {
	generalName_t *next;
	generalNames_t kind;
	chunk_t name;
};

/* forward declaration */
struct id;
/*
 * check periodically for expired crls
 */
extern deltatime_t crl_check_interval;

extern bool same_dn(chunk_t a, chunk_t b);
extern bool match_dn(chunk_t a, chunk_t b, int *wildcards);
extern int dn_count_wildcards(chunk_t dn);
extern err_t atodn(const char *src, chunk_t *dn);
extern void free_generalNames(generalName_t *gn, bool free_name);
extern void load_crls(void);
extern void list_authcerts(const struct fd *whackfd);
extern void list_crls(const struct fd *whackfd);
extern void clear_ocsp_cache(void);

/*
 * New NSS x509 converted functions
 */
extern SECItem same_chunk_as_dercert_secitem(chunk_t chunk);
extern chunk_t get_dercert_from_nss_cert(CERTCertificate *cert);
extern generalName_t *gndp_from_nss_cert(CERTCertificate *cert);
extern void select_nss_cert_id(CERTCertificate *cert, struct id *end_id);
extern bool add_pubkey_from_nss_cert(struct pubkey_list **pubkey_db,
				     const struct id *keyid,
				     CERTCertificate *cert,
				     struct logger *logger);
extern bool trusted_ca_nss(chunk_t a, chunk_t b, int *pathlen);
extern CERTCertList *get_all_certificates(void);

/*
 * Formatting.
 *
 * jam_dn() converts the ASN.1 DN into a "standards compliant"
 * distinguised name (aka DN).
 *
 * XXX: Where "standards compliant" presumably means RFC-1485 et.al. -
 * the raw output is passed to CERT_AsciiToName() and that expects
 * RFC-1485.  However, it looks like a different excaping schema is
 * used.
 *
 * The JAM_BYTES_FN parameter controls additional escaping (after
 * RFC-1485) that should be applied to UTF-8 strings.  For instance:
 * jam_sanitized_bytes() makes the string suitable for logging; and
 * jam_meta_escaped_bytes() makes the string suitable for shell
 * scripts.
 *
 * The str_*() wrappers are hardwired to jam_sanitized_bytes() and,
 * hence, are only suitable for logging.
 */

typedef struct {
	/* Maximum length of ASN.1 distinquished name */
	/* XXX: where did 512 come from? */
	char buf[512/*includes NUL and SENTINEL*/];
} dn_buf;

#define ASN1_BUF_LEN	sizeof(dn_buf)

const char *str_dn(chunk_t dn, dn_buf *buf);
const char *str_dn_or_null(chunk_t dn, const char *null_dn, dn_buf *buf);

void jam_dn_or_null(struct lswlog *buf, chunk_t dn, const char *null_dn,
		    jam_bytes_fn *jam_bytes);
void jam_dn(struct lswlog *buf, chunk_t dn, jam_bytes_fn *jam_bytes);
void jam_raw_dn(struct lswlog *buf, chunk_t dn, jam_bytes_fn *jam_bytes,
		bool nss_compatible);

#endif /* _X509_H */
