/*
 * mechanisms for managing keys (public, private, and preshared secrets)
 * inside of pluto. Common code is in ../../include/secrets.h and libswan.
 *
 * Copyright (C) 1998-2005,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2007  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2011 Mika Ilmaranta <ilmis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
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
#ifndef _KEYS_H
#define _KEYS_H

#include "x509.h"
#include "certs.h"

struct connection;
struct RSA_private_key;
struct RSA_public_key;
struct pubkey;

extern int sign_hash(const struct RSA_private_key *k, const u_char *hash_val,
		      size_t hash_len, u_char *sig_val, size_t sig_len);

extern err_t RSA_signature_verify_nss(const struct RSA_public_key *k,
				      const u_char *hash_val, size_t hash_len,
				      const u_char *sig_val, size_t sig_len);

extern const struct RSA_private_key *get_RSA_private_key(
	const struct connection *c);

extern bool has_private_key(cert_t cert);
extern void list_public_keys(bool utc, bool check_pub_keys);
extern void list_psks(void);

struct gw_info; /* forward declaration of tag (defined in dnskey.h) */
extern void transfer_to_public_keys(struct gw_info *gateways_from_dns
#ifdef USE_KEYRR
				    , struct pubkey_list **keys
#endif /* USE_KEYRR */
				    );

extern const chunk_t *get_preshared_secret(const struct connection *c);

extern void load_preshared_secrets(void);
extern void free_preshared_secrets(void);
extern err_t load_nss_cert_secret(CERTCertificate *cert);

extern struct secret *lsw_get_xauthsecret(const struct connection *c UNUSED,
					  char *xauthname);

/* keys from ipsec.conf */
extern struct pubkey_list *pluto_pubkeys;

struct pubkey *get_pubkey_with_matching_ckaid(const char *ckaid);

struct packet_byte_stream;
extern stf_status RSA_check_signature_gen(struct state *st,
					  const u_char hash_val[MAX_DIGEST_LEN],
					  size_t hash_len,
					  const struct packet_byte_stream *sig_pbs
#ifdef USE_KEYRR
					  , const struct pubkey_list *keys_from_dns
#endif /* USE_KEYRR */
					  , const struct gw_info *gateways_from_dns,
					  err_t (*try_RSA_signature)(
						  const u_char hash_val[MAX_DIGEST_LEN],
						  size_t hash_len,
						  const struct packet_byte_stream *sig_pbs,
						  struct pubkey *kr,
						  struct state *st));

#endif /* _KEYS_H */
