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
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2017 Sahana Prasad <sahana.prasad07@gmail.com>
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
#ifndef _KEYS_H
#define _KEYS_H

#include "lswcdefs.h"
#include "x509.h"
#include "certs.h"
#include "err.h"
#include "ckaid.h"

struct connection;
struct RSA_private_key;
struct RSA_public_key;
struct pubkey;
struct pubkey_type;
struct crypt_mac;
struct packet_byte_stream;
struct private_key_stuff;
struct hash_desc;
struct show;

extern err_t RSA_signature_verify_nss(const struct RSA_public_key *k,
				      const struct crypt_mac *hash,
				      const uint8_t *sig_val, size_t sig_len,
				      const struct hash_desc *hash_algo,
				      struct logger *logger);


const struct private_key_stuff *get_connection_private_key(const struct connection *c,
							   const struct pubkey_type *type,
							   struct logger *logger);

extern bool has_private_key(cert_t cert);
extern void list_public_keys(struct show *s, bool utc, bool check_pub_keys);
extern void list_psks(struct show *s);

extern const chunk_t *get_connection_psk(const struct connection *c,
					 struct logger *logger);
extern chunk_t *get_connection_ppk(const struct connection *c,
				   chunk_t **ppk_id, struct logger *logger);
extern const chunk_t *get_ppk_by_id(const chunk_t *ppk_id);

extern void load_preshared_secrets(struct logger *logger);
extern void free_preshared_secrets(struct logger *logger);
extern void free_remembered_public_keys(void);
err_t preload_private_key_by_cert(const struct cert *cert, bool *load_needed, struct logger *logger);
err_t preload_private_key_by_ckaid(const ckaid_t *ckaid, bool *load_needed, struct logger *logger);

extern struct secret *lsw_get_xauthsecret(char *xauthname);

/* keys from ipsec.conf */
extern struct pubkey_list *pluto_pubkeys;

const struct pubkey *find_pubkey_by_ckaid(const char *ckaid);

typedef err_t (try_signature_fn) (const struct crypt_mac *hash,
				  const struct packet_byte_stream *sig_pbs,
				  struct pubkey *kr,
				  struct state *st,
				  const struct hash_desc *hash_algo);
extern stf_status check_signature_gen(struct state *st,
				      const struct crypt_mac *hash,
				      const struct packet_byte_stream *sig_pbs,
				      const struct hash_desc *hash_algo,
				      const struct pubkey_type *type,
				      try_signature_fn *try_signature);

#endif /* _KEYS_H */
