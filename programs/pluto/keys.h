/*
 * mechanisms for managing keys (public, private, and preshared secrets)
 * inside of pluto. Common code is in ../../include/secrets.h and libopenswan.
 *
 * Copyright (C) 1998-2005  D. Hugh Redelmeier.
 * Copyright (C0 2005 Michael Richardson <mcr@xelerance.com>
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
 * RCSID $Id: keys.h,v 1.35 2005/02/15 01:52:30 mcr Exp $
 */
#ifndef _KEYS_H
#define _KEYS_H

#include "secrets.h"
#include "x509.h"
#include "certs.h"

struct connection;

extern void sign_hash(const struct RSA_private_key *k, const u_char *hash_val
		      , size_t hash_len, u_char *sig_val, size_t sig_len);

extern const struct RSA_private_key *get_RSA_private_key(const struct connection *c);

extern const struct RSA_private_key *get_x509_private_key(/*const*/ x509cert_t *cert);

extern bool has_private_key(cert_t cert);
extern bool has_private_rawkey(struct pubkey *pk);
extern void add_x509_public_key(x509cert_t *cert, time_t until
    , enum dns_auth_level dns_auth_level);
extern void add_pgp_public_key(pgpcert_t *cert, time_t until
    , enum dns_auth_level dns_auth_level);
extern void remove_x509_public_key(/*const*/ x509cert_t *cert);
extern void list_public_keys(bool utc);
extern void list_psks(void);

struct gw_info;	/* forward declaration of tag (defined in dnskey.h) */
extern void transfer_to_public_keys(struct gw_info *gateways_from_dns
#ifdef USE_KEYRR
    , struct pubkey_list **keys
#endif /* USE_KEYRR */
    );

extern const chunk_t *get_preshared_secret(const struct connection *c);

extern const char *pluto_shared_secrets_file;
extern void load_preshared_secrets(int whackfd);
extern void free_preshared_secrets(void);

extern struct secret *osw_find_secret_by_public_key(struct secret *secrets
						    , struct pubkey *my_public_key
						    , int kind);

/* keys from ipsec.conf */
extern struct pubkey_list *pluto_pubkeys;


#endif /* _KEYS_H */
