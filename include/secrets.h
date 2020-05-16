/* mechanisms for preshared keys (public, private, and preshared secrets)
 * definitions: lib/libswan/secrets.c
 *
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
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
#ifndef _SECRETS_H
#define _SECRETS_H

#include <nss.h>
#include <pk11pub.h>

#include "lswcdefs.h"
#include "x509.h"
#include "id.h"
#include "err.h"
#include "realtime.h"
#include "ckaid.h"

struct logger;
struct state;	/* forward declaration */
struct secret;	/* opaque definition, private to secrets.c */
struct pubkey;		/* forward */
union pubkey_content;	/* forward */
struct pubkey_type;	/* forward */
struct hash_desc;

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

struct ECDSA_public_key {
	char keyid[KEYID_BUF];
	unsigned int k;
	chunk_t ecParams;
	chunk_t pub; /* publicValue */
	ckaid_t ckaid;
};

struct ECDSA_private_key {
	struct ECDSA_public_key pub;
	chunk_t ecParams;
	chunk_t pub_val; /* publicValue */
	chunk_t privateValue;
	chunk_t version;
};

err_t rsa_pubkey_to_base64(chunk_t exponent, chunk_t modulus, char **rr);

err_t unpack_RSA_public_key(struct RSA_public_key *rsa, const chunk_t *pubkey);
err_t unpack_ECDSA_public_key(struct ECDSA_public_key *ecdsa, const chunk_t *pubkey); /* ASKK */

struct private_key_stuff {
	enum PrivateKeyKind kind;
	/*
	 * Was this allocated on the heap and hence, should it be
	 * freed (along with all members)?
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
		struct ECDSA_private_key ECDSA_private_key;
		/* struct smartcard *smartcard; */
	} u;

	chunk_t ppk;
	chunk_t ppk_id;
	/* for PKI */
	const struct pubkey_type *pubkey_type;
	SECKEYPrivateKey *private_key;
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

struct hash_signature {
	size_t len;
	/*
	 * XXX: See https://tools.ietf.org/html/rfc4754#section-7 for
	 * where 1056 is coming from.
	 * It is the largest of the signature lengths amongst
	 * ECDSA 256, 384, and 521.
	 */
	uint8_t ptr[PMAX(RSA_MAX_OCTETS, BYTES_FOR_BITS(1056))];
};

union pubkey_content {
	struct RSA_public_key rsa;
	struct ECDSA_public_key ecdsa;
};

struct pubkey_type {
	const char *name;
	enum pubkey_alg alg;
	enum PrivateKeyKind private_key_kind;
	void (*free_pubkey_content)(union pubkey_content *pkc);
	err_t (*unpack_pubkey_content)(union pubkey_content *pkc, chunk_t key);
	void (*extract_pubkey_content)(union pubkey_content *pkc,
				       SECKEYPublicKey *pubkey_nss,
				       SECItem *ckaid_nss);
	void (*extract_private_key_stuff)(struct private_key_stuff *pks,
					  SECKEYPublicKey *pubk,
					  SECItem *cert_ckaid);
	void (*free_secret_content)(struct private_key_stuff *pks);
	err_t (*secret_sane)(struct private_key_stuff *pks);
	struct hash_signature (*sign_hash)(const struct private_key_stuff *pks,
					   const uint8_t *hash_octets, size_t hash_len,
					   const struct hash_desc *hash_algo,
					   struct logger *logger);
};

extern const struct pubkey_type pubkey_type_rsa;
extern const struct pubkey_type pubkey_type_ecdsa;

const struct pubkey_type *pubkey_alg_type(enum pubkey_alg alg);

/* public key machinery */
struct pubkey {
	struct id id;
	unsigned refcnt; /* reference counted! */
	enum dns_auth_level dns_auth_level;
	realtime_t installed_time;
	realtime_t until_time;
	uint32_t dns_ttl; /* from wire. until_time is derived using this */
	chunk_t issuer;
	const struct pubkey_type *type;
	union pubkey_content u;
};

/*
 * XXX: While these fields seem to really belong in 'struct pubkey',
 * moving them isn't so easy - code assumes the fields are also found
 * in {RSA,ECDSA}_private_key's .pub.  Perhaps that structure have its
 * own copy.
 *
 * All pointers are references into the underlying PK structure.
 */

const char *pubkey_keyid(const struct pubkey *pk);
const ckaid_t *pubkey_ckaid(const struct pubkey *pk);
unsigned pubkey_size(const struct pubkey *pk);

const ckaid_t *secret_ckaid(const struct secret *);
const char *secret_keyid(const struct secret *);

struct pubkey_list {
	struct pubkey *key;
	struct pubkey_list *next;
};

extern struct pubkey_list *pubkeys;	/* keys from ipsec.conf */

extern struct pubkey_list *free_public_keyentry(struct pubkey_list *p);
extern void free_public_keys(struct pubkey_list **keys);
extern void free_remembered_public_keys(void);
extern void delete_public_keys(struct pubkey_list **head,
			       const struct id *id,
			       const struct pubkey_type *type);
extern void form_keyid(chunk_t e, chunk_t n, char *keyid, unsigned *keysize);

extern struct pubkey *reference_key(struct pubkey *pk);
extern void unreference_key(struct pubkey **pkp);

extern err_t add_public_key(const struct id *id,
			    enum dns_auth_level dns_auth_level,
			    const struct pubkey_type *type,
			    const chunk_t *key,
			    struct pubkey_list **head);
extern err_t add_ipseckey(const struct id *id,
			  enum dns_auth_level dns_auth_level,
			  const struct pubkey_type *type, uint32_t ttl,
			  uint32_t ttl_used, const chunk_t *key,
			  struct pubkey_list **head);

extern bool same_RSA_public_key(const struct RSA_public_key *a,
				const struct RSA_public_key *b);
extern void install_public_key(struct pubkey *pk, struct pubkey_list **head);

extern void free_public_key(struct pubkey *pk);

extern void lsw_load_preshared_secrets(struct secret **psecrets,
				       const char *secrets_file);
extern void lsw_free_preshared_secrets(struct secret **psecrets);

extern bool lsw_has_private_rawkey(const struct secret *secrets, const struct pubkey *pk);

extern struct secret *lsw_find_secret_by_public_key(struct secret *secrets,
						    const struct pubkey *my_public_key);

extern struct secret *lsw_find_secret_by_id(struct secret *secrets,
					    enum PrivateKeyKind kind,
					    const struct id *my_id,
					    const struct id *his_id,
					    bool asym);

extern struct secret *lsw_get_ppk_by_id(struct secret *secrets, chunk_t ppk_id);

extern err_t lsw_add_secret(struct secret **secrets, CERTCertificate *cert);

/* these do not clone */
chunk_t same_secitem_as_chunk(SECItem si);
SECItem same_chunk_as_secitem(chunk_t chunk, SECItemType type);

chunk_t clone_secitem_as_chunk(SECItem si, const char *name);

struct pubkey *allocate_pubkey_nss(CERTCertificate *cert, struct logger *logger);

#endif /* _SECRETS_H */
