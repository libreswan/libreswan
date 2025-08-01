/* IKE x509 routines for pluto - formerly x509more.h
 * defined in x509.c
 *
 * Copyright (C) 2000 Andreas Hess, Patric Lichtsteiner, Roger Wegmann
 * Copyright (C) 2001 Marco Bertossa, Andreas Schleiss
 * Copyright (C) 2002 Mario Strasser
 * Copyright (C) 2000-2003 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2015 Matt Rogers, <mrogers@libreswan.org>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 D. Hugh Redelmeier <hugh@mimosa.com>
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

#ifndef _PLUTO_X509_H
#define _PLUTO_X509_H

#include "defs.h"
#include "demux.h"
#include "server.h"

#include <cert.h>

/* forward reference */
struct connection;
struct msg_digest;
struct certs;
struct ike_sa;
struct cert;
enum send_ca_policy;

diag_t match_peer_id_cert(const struct certs *peer_certs,
			  const struct id *peer_id,
			  struct id *cert_id);

extern generalName_t *collect_rw_ca_candidates(ip_address local_address,
					       enum ike_version ike_version);

extern void load_authcerts(const char *type, const char *path,
			   uint8_t auth_flags);

extern bool match_v1_requested_ca(const struct ike_sa *ike,
				  chunk_t our_ca, int *our_pathlen,
				  struct verbose verbose);

extern int get_auth_chain(chunk_t *out_chain, int chain_max,
			  const struct cert *end_cert,
			  enum send_ca_policy send_policy,
			  struct logger *logger);

extern void free_auth_chain(chunk_t *chain, int chain_len);

#if defined(USE_LIBCURL) || defined(USE_LDAP)
bool find_crl_fetch_dn(chunk_t *issuer_dn, struct connection *c);
#endif

bool remote_has_preloaded_pubkey(const struct ike_sa *ike);

#endif /* _PLUTO_X509_H */
