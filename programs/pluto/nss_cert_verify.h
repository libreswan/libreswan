/* NSS certificate verification routines for libreswan
 *
 * Copyright (C) 2015 Matt Rogers <mrogers@libreswan.org>
 * Copyright (C) 2018-2019 Andrew Cagney <cagney@gnu.org>
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
 *
 */
#ifndef NSS_CERT_VFY_H
#define NSS_CERT_VFY_H

#include <cert.h>

#include "defs.h"
#include "chunk.h"

struct certs;
struct payload_digest;
struct root_certs;
struct logger;

/*
 * Try to find and verify the end cert.  Sets CRL_NEEDED and BAD (for
 * instance, revoked) when required.  Logs then returns NULL if the
 * certs were discarded.
 */

struct verified_certs {
	struct certs *cert_chain;
	struct pubkey_list *pubkey_db;
	bool crl_update_needed;
	bool harmless;
	bool groundhog;
};

struct verified_certs find_and_verify_certs(struct logger *log,
					    enum ike_version ike_version,
					    struct payload_digest *cert_payloads,
					    struct root_certs *root_cert,
					    const struct id *keyid);

extern diag_t cert_verify_subject_alt_name(const char *who,
					   const CERTCertificate *cert,
					   const struct id *id,
					   struct logger *logger);

extern SECItem *nss_pkcs7_blob(const struct cert *cert,
			       bool send_full_chain,
			       struct logger *logger);

extern bool groundhogday;

#endif /* NSS_CERT_VFY_H */
