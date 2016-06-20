/* mechanisms for preshared keys (public, private, and preshared secrets)
 * definitions: lib/libswan/secrets.c
 *
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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

#include "id.h"

#include <nss.h>
#include <pk11pub.h>
#include "x509.h"

struct state;	/* forward declaration */
struct secret;	/* opaque definition, private to secrets.c */

/*
 * For rationale behind *_t? Blame chunk_t.
 */
typedef struct {
	SECItem *nss;
} ckaid_t;

struct RSA_public_key {
	char keyid[KEYID_BUF];	/* see ipsec_keyblobtoid(3) */

	/*
	 * The "adjusted" length of modulus n in octets:
	 * [RSA_MIN_OCTETS, RSA_MAX_OCTETS].
	 *
	 * According to form_keyid() this is the modulus length less
	 * any leading byte added by DER encoding.
	 *
	 * The adjusted length is used in sign_hash() as the signature
	 * length - wouldn't PK11_SignatureLen be better?
	 *
	 * The adjusted length is used in same_RSA_public_key() as
	 * part of comparing two keys - but wouldn't that be
	 * redundant?  The direct n==n test would pick up the
	 * difference.
	 */
	unsigned k;

	/*
	 * NSS's(?) idea of a unique ID for a public private key pair.
	 * For RSA it is something like the SHA1 of the modulus.  It
	 * replaces KEYID.
	 *
	 * This is the value returned by
	 * PK11_GetLowLevelKeyIDForCert() or
	 * PK11_GetLowLevelKeyIDForPrivateKey() (see
	 * form_ckaid_nss()), or computed by brute force from the
	 * modulus (see form_ckaid_rsa()).
	 *
	 * XXX: When support for ECC is added this may need to be
	 * moved to "pubkey"; or ECC will need its own value.  Think
	 * of moving it here from RSA_private_key as a first step.
	 */
	ckaid_t ckaid;

	/* public: */
	chunk_t n;	/* modulus: p * q */
	chunk_t e;	/* exponent: relatively prime to (p-1) * (q-1) [probably small] */
};

struct RSA_private_key {
	struct RSA_public_key pub;
};

extern void free_RSA_public_content(struct RSA_public_key *rsa);

err_t rsa_pubkey_to_rfc_resource_record(chunk_t exponent, chunk_t modulus, chunk_t *rr);
err_t rfc_resource_record_to_rsa_pubkey(chunk_t rr, chunk_t *exponent, chunk_t *modulus);

err_t rsa_pubkey_to_base64(chunk_t exponent, chunk_t modulus, char **rr);
err_t base64_to_rsa_pubkey(const char *rr, chunk_t *exponent, chunk_t *modulus);

err_t pack_RSA_public_key(const struct RSA_public_key *rsa, chunk_t *pubkey);
err_t unpack_RSA_public_key(struct RSA_public_key *rsa, const chunk_t *pubkey);

void DBG_log_RSA_public_key(const struct RSA_public_key *rsa);

struct private_key_stuff {
	enum PrivateKeyKind kind;
	/*
	 * Was this allocated on the heap and hence, should it be
	 * freeed (along with all members)?
	 *
	 * The old secrets file stuff passes around a pointer to a
	 * cached structure so it shouldn't be freed.
	 */
	bool on_heap;
	/*
	 * This replaced "int lsw_secretlineno()", which assumes only
	 * one file (no includes) and isn't applicable to NSS.  For
	 * NSS it's the entry number.
	 */
	int line;
	union {
		chunk_t preshared_secret;
		struct RSA_private_key RSA_private_key;
		/* struct smartcard *smartcard; */
	} u;
};

extern struct private_key_stuff *lsw_get_pks(struct secret *s);
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

bool ckaid_starts_with(ckaid_t ckaid, const char *start);
char *ckaid_as_string(ckaid_t ckaid);
err_t form_ckaid_rsa(chunk_t modulus, ckaid_t *ckaid);
err_t form_ckaid_nss(const SECItem *const nss_ckaid, ckaid_t *ckaid);
void freeanyckaid(ckaid_t *ckaid);
void DBG_log_ckaid(const char *prefix, ckaid_t ckaid);

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
extern err_t lsw_add_rsa_secret(struct secret **secrets, CERTCertificate *cert);
extern struct pubkey *allocate_RSA_public_key_nss(CERTCertificate *cert);

/* these do not clone */
chunk_t same_secitem_as_chunk(SECItem si);
SECItem same_chunk_as_secitem(chunk_t chunk, SECItemType type);

chunk_t clone_secitem_as_chunk(SECItem si, const char *name);
SECItem clone_chunk_as_secitem(chunk_t chunk, SECItemType type, const char *name);

#endif /* _SECRETS_H */
