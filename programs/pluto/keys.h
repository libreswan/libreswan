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
struct pubkey_content;
struct pubkey;
struct pubkey_type;
struct crypt_mac;
struct hash_desc;
struct show;
struct ike_sa;
struct pubkey_signer;

struct secret_pubkey_stuff *get_local_private_key(const struct connection *c,
						  const struct pubkey_type *type,
						  struct logger *logger);

extern bool has_private_key(cert_t cert);
extern void list_psks(struct show *s);

enum keys_to_show { SHOW_ALL_KEYS = 1, SHOW_EXPIRED_KEYS, };
extern void show_pubkeys(struct show *s, bool utc, enum keys_to_show keys_to_show);

const struct secret_preshared_stuff *get_connection_psk(const struct connection *c);
const struct secret_ppk_stuff *get_connection_ppk_and_ppk_id(const struct connection *c);
const struct secret_ppk_stuff *get_connection_ppk(const struct connection *c,
						  shunk_t ppk_id, unsigned int index);

extern void load_preshared_secrets(struct logger *logger);
extern void free_preshared_secrets(struct logger *logger);
extern void free_remembered_public_keys(void);
err_t preload_private_key_by_cert(const struct cert *cert, bool *load_needed, struct logger *logger);
err_t preload_private_key_by_ckaid(const ckaid_t *ckaid, bool *load_needed, struct logger *logger);

extern const struct secret_preshared_stuff  *xauth_secret_by_xauthname(char *xauthname);

/* keys from ipsec.conf */
extern struct pubkey_list *pluto_pubkeys;

const struct pubkey *find_pubkey_by_ckaid(const char *ckaid);

extern diag_t authsig_and_log_using_pubkey(struct ike_sa *ike,
					   const struct crypt_mac *hash,
					   shunk_t signature,
					   const struct hash_desc *hash_algo,
					   const struct pubkey_signer *signer,
					   const char *signature_payload_name);

#endif /* _KEYS_H */
