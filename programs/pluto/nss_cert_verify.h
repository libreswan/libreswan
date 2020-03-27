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

/* rev_opts index */
struct rev_opts {
	bool ocsp;
	bool ocsp_strict;
	bool ocsp_post;
	bool crl_strict;
};

struct verified_certs {
	struct certs *cert_chain;
	struct pubkey_list *pubkey_db;
	bool crl_update_needed;
	bool harmless;
};

struct verified_certs find_and_verify_certs(struct logger *log,
					    enum ike_version ike_version,
					    struct payload_digest *cert_payloads,
					    const struct rev_opts *rev_opts,
					    struct root_certs *root_cert,
					    const struct id *keyid);

extern bool cert_VerifySubjectAltName(const CERTCertificate *cert,
				      const struct id *id);

extern SECItem *nss_pkcs7_blob(CERTCertificate *cert, bool send_full_chain);

/**
 * Check if a certificate's public key adheres to FIPS.
 *
 * @return             `true` if the public key's properties are FIPS-approved.
 * @param cert         The certificate whose public key needs to be checked.
 * @param cert_desc    Human-friendly description of `cert`. Used only for log
 *                     messages.
 */
extern bool cert_fips_verify_public_key(CERTCertificate * const cert,
					char const * const cert_desc);

#endif /* NSS_CERT_VFY_H */
