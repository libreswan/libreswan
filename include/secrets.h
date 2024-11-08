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

#include <pk11pub.h>

#include "lswcdefs.h"
#include "x509.h"
#include "id.h"
#include "err.h"
#include "realtime.h"
#include "ckaid.h"
#include "diag.h"
#include "keyid.h"
#include "refcnt.h"
#include "crypt_mac.h"
#include "ike_alg.h"		/* for HASH_ALGORITHM_IDENTIFIER */

struct logger;
struct state;	/* forward declaration */
struct secret;	/* opaque definition, private to secrets.c */
struct pubkey;		/* forward */
struct pubkey_content;	/* forward */
struct pubkey_type;	/* forward */
struct hash_desc;
struct cert;

/*
 * The raw public key.
 *
 * While this is abstracted as a SECKEYPublicKey, it can be thought of
 * as the Subject Public Key Info.
 */

struct pubkey_content {
	const struct pubkey_type *type;
	keyid_t keyid;	/* see ipsec_keyblobtoid(3) */
	ckaid_t ckaid;
	SECKEYPublicKey *public_key;
};

/*
 * private key types
 */
enum secret_kind {
	/* start at one so accidental 0 will not match */
	SECRET_PSK = 1,
	SECRET_RSA,
	SECRET_XAUTH,
	SECRET_PPK,
	SECRET_ECDSA, /* should not be needed */
	SECRET_NULL,
	SECRET_INVALID,
};

struct secret_pubkey_stuff {
	SECKEYPrivateKey *private_key;
	struct pubkey_content content;
};

struct secret_stuff {
	enum secret_kind kind;
	/*
	 * This replaced "int lsw_secretlineno()", which assumes only
	 * one file (no includes) and isn't applicable to NSS.  For
	 * NSS it's the entry number.
	 */
	int line;
	union {
		chunk_t preshared_secret;
		struct secret_pubkey_stuff pubkey;
	} u;

	chunk_t ppk;
	chunk_t ppk_id;
};

diag_t secret_pubkey_stuff_to_pubkey_der(struct secret_pubkey_stuff *pks, chunk_t *der);
diag_t pubkey_der_to_pubkey_content(shunk_t pubkey_der, struct pubkey_content *pkc);

extern struct secret_stuff *get_secret_stuff(struct secret *s);
extern struct secret_pubkey_stuff *get_secret_pubkey_stuff(struct secret *s);
extern struct id_list *lsw_get_idlist(const struct secret *s);

/*
 * return 1 to continue to next,
 * return 0 to return current secret
 * return -1 to return NULL
 */
typedef int (*secret_eval)(struct secret *secret,
			   struct secret_stuff *pks,
			   void *uservoid);

struct secret *foreach_secret(struct secret *secrets,
			      secret_eval func, void *uservoid);

struct hash_signature {
	size_t len;
	/*
	 * For ECDSA, see https://tools.ietf.org/html/rfc4754#section-7
	 * for where 1056 is coming from (it is the largest of the
	 * signature lengths amongst ECDSA 256, 384, and 521).
	 *
	 * For RSA this needs to be big enough to fit the modulus.
	 * Because the modulus in the SECItem is signed (but the raw
	 * value is unsigned), the modulus may have been prepended
	 * with an additional zero byte.  Hence the +1 to accommodate
	 * fuzzy checks against modulus.len.
	 *
	 * New code should just ask NSS for the signature length.
	 */
	uint8_t ptr[PMAX(BYTES_FOR_BITS(8192)+1/*RSA*/, BYTES_FOR_BITS(1056)/*ECDSA*/)];
};

struct pubkey_type {
	const char *name;
	enum secret_kind private_key_kind;
	void (*free_pubkey_content)(struct pubkey_content *pkc);
	/* to/from the blob in DNS's IPSECKEY's Public Key field */
	diag_t (*ipseckey_rdata_to_pubkey_content)(shunk_t ipseckey_pubkey,
						   struct pubkey_content *pkc);
	err_t (*pubkey_content_to_ipseckey_rdata)(const struct pubkey_content *pkc,
						  chunk_t *ipseckey_pubkey,
						  enum ipseckey_algorithm_type *ipseckey_algorithm);
	/* nss */
	err_t (*extract_pubkey_content)(struct pubkey_content *pkc,
					SECKEYPublicKey *pubkey_nss, SECItem *ckaid_nss);
	bool (*pubkey_same)(const struct pubkey_content *lhs, const struct pubkey_content *rhs);
#define pubkey_strength_in_bits(PUBKEY) ((PUBKEY)->content.type->strength_in_bits(PUBKEY))
	size_t (*strength_in_bits)(const struct pubkey *pubkey);
};

struct pubkey_signer {
	const char *name;
	enum digital_signature_blob digital_signature_blob;
	const struct pubkey_type *type;
	struct hash_signature (*sign_hash)(const struct secret_pubkey_stuff *pks,
					   const uint8_t *hash_octets, size_t hash_len,
					   const struct hash_desc *hash_algo,
					   struct logger *logger);
	/*
	 * Danger! This function returns three results
	 *
	 * true;FATAL_DIAG=NULL: pubkey verified
	 * false;FATAL_DIAG=NULL: pubkey did not verify
	 * false;FATAL_DIAG!=NULL: operation should be aborted
	 */
	bool (*authenticate_signature)(const struct crypt_mac *hash,
				       shunk_t signature,
				       struct pubkey *kr,
				       const struct hash_desc *hash_algo,
				       diag_t *fatal_diag,
				       struct logger *logger);
	size_t (*jam_auth_method)(struct jambuf *,
				  const struct pubkey_signer *,
				  const struct pubkey *,
				  const struct hash_desc *);
};

extern const struct pubkey_type pubkey_type_rsa;
extern const struct pubkey_type pubkey_type_ecdsa;

extern const struct pubkey_signer pubkey_signer_raw_rsa;		/* IKEv1 */
extern const struct pubkey_signer pubkey_signer_raw_pkcs1_1_5_rsa;	/* rfc7296 */
extern const struct pubkey_signer pubkey_signer_raw_ecdsa;		/* rfc4754 */

extern const struct pubkey_signer pubkey_signer_digsig_pkcs1_1_5_rsa;	/* rfc7427 */
extern const struct pubkey_signer pubkey_signer_digsig_rsassa_pss;	/* rfc7427 */
extern const struct pubkey_signer pubkey_signer_digsig_ecdsa;		/* rfc7427 */

const struct pubkey_type *pubkey_alg_type(enum ipseckey_algorithm_type alg);

/*
 * Public Key Machinery.
 *
 * This is a mashup of fields taken both from the certificate and the
 * subject public key info.
 */
struct pubkey {
	refcnt_t refcnt;	/* reference counted! */
	struct id id;
	enum dns_auth_level dns_auth_level;
	realtime_t installed_time;
	realtime_t until_time;
	uint32_t dns_ttl; /* from wire. until_time is derived using this */
	asn1_t issuer;
	struct pubkey_content content;
	/* for overalloc of issuer */
	uint8_t end[];
};

/*
 * XXX: While these fields seem to really belong in 'struct pubkey',
 * moving them isn't so easy - code assumes the fields are also found
 * in {RSA,ECDSA}_private_key's .pub.  Perhaps that structure have its
 * own copy.
 *
 * All pointers are references into the underlying PK structure.
 */

const ckaid_t *pubkey_ckaid(const struct pubkey *pk);
const keyid_t *pubkey_keyid(const struct pubkey *pk);

const ckaid_t *secret_ckaid(const struct secret *);
const keyid_t *secret_keyid(const struct secret *);

struct pubkey_list {
	struct pubkey *key;
	struct pubkey_list *next;
};

extern struct pubkey_list *pubkeys;	/* keys from ipsec.conf */

extern struct pubkey_list *free_public_keyentry(struct pubkey_list *p);
extern void free_public_keys(struct pubkey_list **keys);

diag_t unpack_dns_ipseckey(const struct id *id, /* ASKK */
			   enum dns_auth_level dns_auth_level,
			   enum ipseckey_algorithm_type algorithm_type,
			   realtime_t install_time, realtime_t until_time,
			   uint32_t ttl,
			   shunk_t dnssec_pubkey,
			   struct pubkey **pubkey,
			   struct pubkey_list **head);

void replace_public_key(struct pubkey_list **pubkey_db,
			struct pubkey **pk);
void delete_public_keys(struct pubkey_list **head,
			const struct id *id,
			const struct pubkey_type *type);
extern void form_keyid(chunk_t e, chunk_t n, keyid_t *keyid, size_t *keysize); /*XXX: make static? */

struct pubkey *pubkey_addref_where(struct pubkey *pk, where_t where);
#define pubkey_addref(PK) pubkey_addref_where(PK, HERE)
extern void pubkey_delref_where(struct pubkey **pkp, where_t where);
#define pubkey_delref(PKP) pubkey_delref_where(PKP, HERE)

bool secret_pubkey_same(struct secret *lhs, struct secret *rhs);

extern void lsw_load_preshared_secrets(struct secret **psecrets, const char *secrets_file,
				       struct logger *logger);
extern void lsw_free_preshared_secrets(struct secret **psecrets, struct logger *logger);

extern struct secret *lsw_find_secret_by_id(struct secret *secrets,
					    enum secret_kind kind,
					    const struct id *my_id,
					    const struct id *his_id,
					    bool asym);

extern struct secret *lsw_get_ppk_by_id(struct secret *secrets, chunk_t ppk_id);

/* err_t!=NULL -> neither found nor loaded; loaded->just pulled in */
err_t find_or_load_private_key_by_cert(struct secret **secrets, const struct cert *cert,
				       const struct secret_pubkey_stuff **pks, bool *load_needed,
				       struct logger *logger);
err_t find_or_load_private_key_by_ckaid(struct secret **secrets, const ckaid_t *ckaid,
					const struct secret_pubkey_stuff **pks, bool *load_needed,
					struct logger *logger);

diag_t create_pubkey_from_cert(const struct id *id,
			       CERTCertificate *cert, struct pubkey **pk,
			       struct logger *logger) MUST_USE_RESULT;

#endif /* _SECRETS_H */
