/* mechanisms for preshared keys (public, private, and preshared secrets)
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
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
 * RCSID $Id: keys.h,v 1.35.4.1 2007/10/22 15:53:56 paul Exp $
 */
#ifndef _KEYS_H
#define _KEYS_H

#include <gmp.h>    /* GNU MP library */

#ifndef SHARED_SECRETS_FILE
# define SHARED_SECRETS_FILE  "/etc/ipsec.secrets"
#endif

extern void load_preshared_secrets(int whackfd);
extern void free_preshared_secrets(void);

struct state;	/* forward declaration */

extern const char *shared_secrets_file;

struct RSA_public_key
{
    char keyid[KEYID_BUF];	/* see ipsec_keyblobtoid(3) */

    /* length of modulus n in octets: [RSA_MIN_OCTETS, RSA_MAX_OCTETS] */
    unsigned k;

    /* public: */
    MP_INT
	n,	/* modulus: p * q */
	e;	/* exponent: relatively prime to (p-1) * (q-1) [probably small] */
};

struct RSA_private_key {
    struct RSA_public_key pub;	/* must be at start for RSA_show_public_key */

    MP_INT
	d,	/* private exponent: (e^-1) mod ((p-1) * (q-1)) */
	/* help for Chinese Remainder Theorem speedup: */
	p,	/* first secret prime */
	q,	/* second secret prime */
	dP,	/* first factor's exponent: (e^-1) mod (p-1) == d mod (p-1) */
	dQ,	/* second factor's exponent: (e^-1) mod (q-1) == d mod (q-1) */
	qInv;	/* (q^-1) mod p */
};

extern void free_RSA_public_content(struct RSA_public_key *rsa);

extern err_t unpack_RSA_public_key(struct RSA_public_key *rsa, const chunk_t *pubkey);

extern const struct RSA_private_key *get_RSA_private_key(const struct connection *c);

extern const struct RSA_private_key *get_x509_private_key(/*const*/ x509cert_t *cert);

extern void sign_hash(const struct RSA_private_key *k, const u_char *hash_val
    , size_t hash_len, u_char *sig_val, size_t sig_len);


/* public key machinery  */

struct pubkey {
    struct id id;
    unsigned refcnt;	/* reference counted! */
    enum dns_auth_level dns_auth_level;
    char *dns_sig;
    time_t installed_time
	, last_tried_time
	, last_worked_time
	, until_time;
    chunk_t issuer;
    enum pubkey_alg alg;
    union {
	struct RSA_public_key rsa;
    } u;
};

struct pubkey_list {
    struct pubkey *key;
    struct pubkey_list *next;
};


extern struct pubkey_list *pubkeys;	/* keys from ipsec.conf */

extern struct pubkey *public_key_from_rsa(const struct RSA_public_key *k);
extern struct pubkey_list *free_public_keyentry(struct pubkey_list *p);
extern void free_public_keys(struct pubkey_list **keys);
extern void free_remembered_public_keys(void);
extern void delete_public_keys(const struct id *id, enum pubkey_alg alg);
extern void form_keyid(chunk_t e, chunk_t n, char* keyid, unsigned *keysize);

extern struct pubkey *reference_key(struct pubkey *pk);
extern void unreference_key(struct pubkey **pkp);


extern err_t add_public_key(const struct id *id
    , enum dns_auth_level dns_auth_level
    , enum pubkey_alg alg
    , const chunk_t *key
    , struct pubkey_list **head);

extern bool has_private_key(cert_t cert);
extern void add_x509_public_key(x509cert_t *cert, time_t until
    , enum dns_auth_level dns_auth_level);
extern void add_pgp_public_key(pgpcert_t *cert, time_t until
    , enum dns_auth_level dns_auth_level);
extern void remove_x509_public_key(/*const*/ x509cert_t *cert);
extern void list_public_keys(bool utc);

struct gw_info;	/* forward declaration of tag (defined in dnskey.h) */
extern void transfer_to_public_keys(struct gw_info *gateways_from_dns
#ifdef USE_KEYRR
    , struct pubkey_list **keys
#endif /* USE_KEYRR */
    );

extern bool same_RSA_public_key(const struct RSA_public_key *a
    , const struct RSA_public_key *b);

extern struct pubkey* allocate_RSA_public_key(const cert_t cert);
extern void install_public_key(struct pubkey *pk, struct pubkey_list **head);
extern void free_public_key(struct pubkey *pk);

#endif /* _KEYS_H */
