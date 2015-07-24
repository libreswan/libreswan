/* mechanisms for preshared keys (public, private, and preshared secrets)
 * definitions: lib/libswan/secrets.c
 *
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
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
#ifndef _SECRETS_H
#define _SECRETS_H

#include <gmp.h>	/* GNU MP library */
#include "id.h"

#include <nss.h>
#include <pk11pub.h>
#include "x509.h"

#ifndef SHARED_SECRETS_FILE
# define SHARED_SECRETS_FILE  "/etc/ipsec.secrets"
#endif

struct state;	/* forward declaration */
struct secret;	/* opaque definition, private to secrets.c */

struct RSA_public_key {
	char keyid[KEYID_BUF];	/* see ipsec_keyblobtoid(3) */

	/* length of modulus n in octets: [RSA_MIN_OCTETS, RSA_MAX_OCTETS] */
	unsigned k;

	/* public: */
	MP_INT
		n,	/* modulus: p * q */
		e;	/* exponent: relatively prime to (p-1) * (q-1) [probably small] */
	CERTCertificate *nssCert;
};

struct RSA_private_key {
	struct RSA_public_key pub;	/* must be at start for RSA_show_public_key */

	MP_INT
		d,				/* private exponent: (e^-1) mod ((p-1) * (q-1)) */
	/* help for Chinese Remainder Theorem speedup: */
		p,				/* first secret prime */
		q,				/* second secret prime */
		dP,				/* first factor's exponent: (e^-1) mod (p-1) == d mod (p-1) */
		dQ,				/* second factor's exponent: (e^-1) mod (q-1) == d mod (q-1) */
		qInv;				/* (q^-1) mod p */
	/*
	 * ckaid for use in NSS
	 *
	 * Value returned by PK11_GetLowLevelKeyIDForCert().
	 * ??? Bound on size doesn't seem to be documented in NSS.
	 * Empirically, 64 bytes is sufficient.
	 */
	unsigned char ckaid[64];
	unsigned int ckaid_len;
};

extern void free_RSA_public_content(struct RSA_public_key *rsa);

extern err_t unpack_RSA_public_key(struct RSA_public_key *rsa,
				   const chunk_t *pubkey);

struct private_key_stuff {
	enum PrivateKeyKind kind;
	union {
		chunk_t preshared_secret;
		struct RSA_private_key RSA_private_key;
		/* struct smartcard *smartcard; */
	} u;
};

extern struct private_key_stuff *lsw_get_pks(struct secret *s);
extern int lsw_get_secretlineno(const struct secret *s);
extern struct id_list *lsw_get_idlist(const struct secret *s);

/*
 * return 1 to continue to next,
 * return 0 to return current secret
 * return -1 to return NULL
 */
typedef int (*secret_eval)(struct secret *secret,
			   struct private_key_stuff *pks,
			   void *uservoid);

extern struct secret *lsw_foreach_secret(struct secret *secrets,
					 secret_eval func, void *uservoid);
extern struct secret *lsw_get_defaultsecret(struct secret *secrets);

/* public key machinery */
struct pubkey {
	struct id id;
	unsigned refcnt; /* reference counted! */
	enum dns_auth_level dns_auth_level;
	char *dns_sig;
	realtime_t installed_time;
	realtime_t until_time;
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

/* struct used to prompt for a secret passphrase
 * from a console with file descriptor fd
 */
#define MAX_PROMPT_PASS_TRIALS	5
#define PROMPT_PASS_LEN		64

typedef void (*pass_prompt_func)(int mess_no, const char *message,
				 ...) PRINTF_LIKE (2);

typedef struct {
	char secret[PROMPT_PASS_LEN];
	pass_prompt_func prompt;
	int fd;
} prompt_pass_t;

extern struct pubkey_list *pubkeys;	/* keys from ipsec.conf */

extern struct pubkey *public_key_from_rsa(const struct RSA_public_key *k);
extern struct pubkey_list *free_public_keyentry(struct pubkey_list *p);
extern void free_public_keys(struct pubkey_list **keys);
extern void free_remembered_public_keys(void);
extern void delete_public_keys(struct pubkey_list **head,
			       const struct id *id,
			       enum pubkey_alg alg);
extern void form_keyid(chunk_t e, chunk_t n, char *keyid, unsigned *keysize);

extern struct pubkey *reference_key(struct pubkey *pk);
extern void unreference_key(struct pubkey **pkp);

extern err_t add_public_key(const struct id *id,
			    enum dns_auth_level dns_auth_level,
			    enum pubkey_alg alg,
			    const chunk_t *key,
			    struct pubkey_list **head);

extern bool same_RSA_public_key(const struct RSA_public_key *a,
				const struct RSA_public_key *b);
extern void install_public_key(struct pubkey *pk, struct pubkey_list **head);

extern void free_public_key(struct pubkey *pk);

extern void lsw_load_preshared_secrets(struct secret **psecrets,
				       const char *secrets_file);
extern void lsw_free_preshared_secrets(struct secret **psecrets);

extern bool lsw_has_private_rawkey(struct secret *secrets, struct pubkey *pk);

extern struct secret *lsw_find_secret_by_public_key(struct secret *secrets,
						    struct pubkey *my_public_key,
						    enum PrivateKeyKind kind);

extern struct secret *lsw_find_secret_by_id(struct secret *secrets,
					    enum PrivateKeyKind kind,
					    const struct id *my_id,
					    const struct id *his_id,
					    bool asym);

extern void lock_certs_and_keys(const char *who);
extern void unlock_certs_and_keys(const char *who);

#endif /* _SECRETS_H */
