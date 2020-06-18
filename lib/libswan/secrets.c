/*
 * mechanisms for preshared keys (public, private, and preshared secrets)
 *
 * this is the library for reading (and later, writing!) the ipsec.secrets
 * files.
 *
 * Copyright (C) 1998-2004  D. Hugh Redelmeier.
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2015 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2016-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2019 Paul Wouters <pwouters@redhat.com>
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

#include <pthread.h>	/* pthread.h must be first include file */
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>	/* missing from <resolv.h> on old systems */
#include <glob.h>
#ifndef GLOB_ABORTED
#define GLOB_ABORTED GLOB_ABEND        /* fix for old versions */
#endif

#include <nss.h>
#include <pk11pub.h>
#include <prerror.h>
#include <cert.h>
#include <cryptohi.h>
#include <keyhi.h>

#include "sysdep.h"
#include "lswlog.h"
#include "constants.h"
#include "lswalloc.h"
#include "id.h"
#include "x509.h"
#include "secrets.h"
#include "certs.h"
#include "lex.h"

#include "lswconf.h"
#include "lswnss.h"
#include "ip_info.h"
#include "nss_cert_load.h"
#include "ike_alg.h"
#include "ike_alg_hash.h"

/* this does not belong here, but leave it here for now */
const struct id empty_id;	/* ID_NONE */

struct fld {
	const char *name;
	ssize_t offset;
};

static const struct fld RSA_private_field[] = {
	{
		.name = "Modulus",
		.offset = offsetof(struct RSA_private_key, pub.n),
	},
	{
		.name = "PublicExponent",
		.offset = offsetof(struct RSA_private_key, pub.e),
	},

	{
		.name = "PrivateExponent",
		.offset = -1,
	},
	{
		.name = "Prime1",
		.offset = -1,
	},
	{
		.name = "Prime2",
		.offset = -1,
	},
	{
		.name = "Exponent1",
		.offset = -1,
	},
	{
		.name = "Exponent2",
		.offset = -1,
	},
	{
		.name = "Coefficient",
		.offset = -1,
	},
	{
		.name = "CKAIDNSS",
		.offset = -1,
	},
};

static void lsw_process_secrets_file(struct secret **psecrets,
				const char *file_pat);

struct secret {
	struct secret  *next;
	struct id_list *ids;
	struct private_key_stuff pks;
};

struct private_key_stuff *lsw_get_pks(struct secret *s)
{
	return &s->pks;
}

struct id_list *lsw_get_idlist(const struct secret *s)
{
	return s->ids;
}

/*
 * forms the keyid from the public exponent e and modulus n
 */
void form_keyid(chunk_t e, chunk_t n, char *keyid, unsigned *keysize)
{
	/* eliminate leading zero byte in modulus from ASN.1 coding */
	if (*n.ptr == 0x00) {
		/*
		 * The "adjusted" length of modulus n in octets:
		 * [RSA_MIN_OCTETS, RSA_MAX_OCTETS].
		 *
		 * According to form_keyid() this is the modulus length
		 * less any leading byte added by DER encoding.
		 *
		 * The adjusted length is used in sign_hash() as the
		 * signature length - wouldn't PK11_SignatureLen be
		 * better?
		 *
		 * The adjusted length is used in
		 * same_RSA_public_key() as part of comparing two keys
		 * - but wouldn't that be redundant?  The direct n==n
		 * test would pick up the difference.
		 */
		DBG(DBG_CRYPT, DBG_log("XXX: adjusted modulus length %zu->%zu",
				       n.len, n.len - 1));
		n.ptr++;
		n.len--;
	}

	/* form the Libreswan keyid */
	keyid[0] = '\0';	/* in case of splitkeytoid failure */
	splitkeytoid(e.ptr, e.len, n.ptr, n.len, keyid, KEYID_BUF);

	/* return the RSA modulus size in octets */
	*keysize = n.len;
}

static err_t RSA_unpack_pubkey_content(union pubkey_content *u, chunk_t pubkey)
{
	return unpack_RSA_public_key(&u->rsa, &pubkey);
}

static void RSA_free_public_content(struct RSA_public_key *rsa)
{
	free_chunk_content(&rsa->n);
	free_chunk_content(&rsa->e);
}

static void RSA_free_pubkey_content(union pubkey_content *u)
{
	RSA_free_public_content(&u->rsa);
}

static void extract_RSA_public_key(struct RSA_public_key *pub,
				   SECKEYPublicKey *pubk,
				   SECItem *cert_ckaid)
{
	pub->e = clone_bytes_as_chunk(pubk->u.rsa.publicExponent.data,
					   pubk->u.rsa.publicExponent.len, "e");
	pub->n = clone_bytes_as_chunk(pubk->u.rsa.modulus.data,
					   pubk->u.rsa.modulus.len, "n");
	pub->ckaid = ckaid_from_secitem(cert_ckaid);
	form_keyid(pub->e, pub->n, pub->keyid, &pub->k);
}

static void RSA_extract_pubkey_content(union pubkey_content *pkc,
				       SECKEYPublicKey *pubkey_nss,
				       SECItem *ckaid_nss)
{
	extract_RSA_public_key(&pkc->rsa, pubkey_nss, ckaid_nss);
}

static void RSA_extract_private_key_stuff(struct private_key_stuff *pks,
					  SECKEYPublicKey *pubkey_nss,
					  SECItem *ckaid_nss)
{
	struct RSA_private_key *rsak = &pks->u.RSA_private_key;
	extract_RSA_public_key(&rsak->pub, pubkey_nss, ckaid_nss);
}

static void RSA_free_secret_content(struct private_key_stuff *pks)
{
	SECKEY_DestroyPrivateKey(pks->private_key);
	struct RSA_private_key *rsak = &pks->u.RSA_private_key;
	RSA_free_public_content(&rsak->pub);
}

static err_t RSA_secret_sane(struct private_key_stuff *pks)
{
	const struct RSA_private_key *k = &pks->u.RSA_private_key;
	/*
	 * PKCS#1 1.5 section 6 requires modulus to have at least 12 octets.
	 *
	 * We actually require more (for security).
	 */
	if (k->pub.k < RSA_MIN_OCTETS)
		return RSA_MIN_OCTETS_UGH;

	/* we picked a max modulus size to simplify buffer allocation */
	if (k->pub.k > RSA_MAX_OCTETS)
		return RSA_MAX_OCTETS_UGH;

	return NULL;
}

/* returns the length of the result on success; 0 on failure */
static struct hash_signature RSA_sign_hash(const struct private_key_stuff *pks,
					   const uint8_t *hash_val, size_t hash_len,
					   const struct hash_desc *hash_algo,
					   struct logger *logger)
{
	dbg("RSA_sign_hash: Started using NSS");
	if (!pexpect(pks->private_key != NULL)) {
		dbg("no private key!");
		return (struct hash_signature) { .len = 0, };
	}

	SECItem data = {
		.type = siBuffer,
		.len = hash_len,
		.data = DISCARD_CONST(u_char *, hash_val),
	};

	struct hash_signature sig = { .len = PK11_SignatureLen(pks->private_key), };
	passert(sig.len <= sizeof(sig.ptr/*array*/));
	SECItem signature = {
		.type = siBuffer,
		.len = sig.len,
		.data = sig.ptr,
	};

	if (hash_algo == NULL /* ikev1*/ ||
	    hash_algo == &ike_alg_hash_sha1 /* old style rsa with SHA1*/) {
		SECStatus s = PK11_Sign(pks->private_key, &signature, &data);
		if (s != SECSuccess) {
			/* PR_GetError() returns the thread-local error */
			log_nss_error(RC_LOG_SERIOUS, logger, PR_GetError(),
				      "RSA sign function failed");
			return (struct hash_signature) { .len = 0, };
		}
	} else { /* Digital signature scheme with rsa-pss*/
		const CK_RSA_PKCS_PSS_PARAMS *mech = hash_algo->nss.rsa_pkcs_pss_params;
		if (mech == NULL) {
			log_message(RC_LOG_SERIOUS, logger,
				    "digital signature scheme not supported for hash algorithm %s",
				    hash_algo->common.fqn);
			return (struct hash_signature) { .len = 0, };
		}

		SECItem mech_item = {
			.type = siBuffer,
			.data = (void*)mech, /* strip const */
			.len = sizeof(*mech),
		};
		SECStatus s = PK11_SignWithMechanism(pks->private_key, CKM_RSA_PKCS_PSS,
						     &mech_item, &signature, &data);
		if (s != SECSuccess) {
			/* PR_GetError() returns the thread-local error */
			log_nss_error(RC_LOG_SERIOUS, logger, PR_GetError(),
				      "RSA DSS sign function failed");
			return (struct hash_signature) { .len = 0, };
		}
	}

	dbg("RSA_sign_hash: Ended using NSS");
	return sig;
}

const struct pubkey_type pubkey_type_rsa = {
	.alg = PUBKEY_ALG_RSA,
	.name = "RSA",
	.private_key_kind = PKK_RSA,
	.free_pubkey_content = RSA_free_pubkey_content,
	.unpack_pubkey_content = RSA_unpack_pubkey_content,
	.extract_pubkey_content = RSA_extract_pubkey_content,
	.extract_private_key_stuff = RSA_extract_private_key_stuff,
	.free_secret_content = RSA_free_secret_content,
	.secret_sane = RSA_secret_sane,
	.sign_hash = RSA_sign_hash,
};

static err_t ECDSA_unpack_pubkey_content(union pubkey_content *u, chunk_t pubkey)
{
	return unpack_ECDSA_public_key(&u->ecdsa, &pubkey);
}

static void ECDSA_free_public_content(struct ECDSA_public_key *ecdsa)
{
	free_chunk_content(&ecdsa->pub);
	free_chunk_content(&ecdsa->ecParams);
	/* ckaid is an embedded struct (no pointer) */
	/*
	 * ??? what about ecdsa->pub.{version,ckaid}?
	 *
	 * CKAID's been changed to an embedded struct (so no pointer).
	 * VERSION was dropped?
	 */
}

static void ECDSA_free_pubkey_content(union pubkey_content *u)
{
	ECDSA_free_public_content(&u->ecdsa);
}

static void extract_ECDSA_public_key(struct ECDSA_public_key *pub,
				     SECKEYPublicKey *pubkey_nss,
				     SECItem *ckaid_nss)
{
	pub->pub = clone_secitem_as_chunk(pubkey_nss->u.ec.publicValue, "ECDSA pub");
	pub->ecParams = clone_secitem_as_chunk(pubkey_nss->u.ec.DEREncodedParams, "ECDSA ecParams");
	pub->k = pubkey_nss->u.ec.publicValue.len;
	pub->ckaid = ckaid_from_secitem(ckaid_nss);
	/* keyid */
	char keyid[KEYID_BUF] = "";
	memcpy(keyid, pubkey_nss->u.ec.publicValue.data, KEYID_BUF-1);
	if (DBGP(DBG_BASE)) {
		DBG_dump("keyid", keyid, KEYID_BUF-1);
	}
	keyblobtoid((const unsigned char *)keyid, KEYID_BUF,
		    pub->keyid, KEYID_BUF);
	if (DBGP(DBG_CRYPT)) {
		DBG_log("k %u", pub->k);
		DBG_dump_hunk("pub", pub->pub);
		DBG_dump_hunk("ecParams", pub->ecParams);
	}
}

static void ECDSA_extract_pubkey_content(union pubkey_content *pkc,
					 SECKEYPublicKey *pubkey_nss,
					 SECItem *ckaid_nss)
{
	extract_ECDSA_public_key(&pkc->ecdsa, pubkey_nss, ckaid_nss);
}

static void ECDSA_extract_private_key_stuff(struct private_key_stuff *pks,
					    SECKEYPublicKey *pubkey_nss,
					    SECItem *ckaid_nss)
{
	struct ECDSA_private_key *ecdsak = &pks->u.ECDSA_private_key;
	extract_ECDSA_public_key(&ecdsak->pub, pubkey_nss, ckaid_nss);
}

static void ECDSA_free_secret_content(struct private_key_stuff *pks)
{
	SECKEY_DestroyPrivateKey(pks->private_key);
	struct ECDSA_private_key *ecdsak = &pks->u.ECDSA_private_key;
	ECDSA_free_public_content(&ecdsak->pub);
}

/*
 * The only unsafe (according to FIPS) curve is p192, and NSS does not
 * implement this, so there is no ECDSA curve that libreswan needs to
 * disallow for security reasons
 */
static err_t ECDSA_secret_sane(struct private_key_stuff *pks_unused UNUSED)
{
	dbg("ECDSA is assumed to be sane");
	return NULL;
}

static struct hash_signature ECDSA_sign_hash(const struct private_key_stuff *pks,
					     const uint8_t *hash_val, size_t hash_len,
					     const struct hash_desc *hash_algo_unused UNUSED,
					     struct logger *logger)
{

	if (!pexpect(pks->private_key != NULL)) {
		dbg("no private key!");
		return (struct hash_signature) { .len = 0, };
	}

	DBG(DBG_CRYPT, DBG_log("ECDSA_sign_hash: Started using NSS"));

	/* point HASH to sign at HASH_VAL */
	SECItem hash_to_sign = {
		.type = siBuffer,
		.len = hash_len,
		.data = DISCARD_CONST(uint8_t *, hash_val),
	};

	/* point signature at the SIG_VAL buffer */
	uint8_t raw_signature_data[sizeof(struct hash_signature)];
	SECItem raw_signature = {
		.type = siBuffer,
		.len = PK11_SignatureLen(pks->private_key),
		.data = raw_signature_data,
	};
	passert(raw_signature.len <= sizeof(raw_signature_data));
	dbg("ECDSA signature.len %d", raw_signature.len);

	/* create the raw signature */
	SECStatus s = PK11_Sign(pks->private_key, &raw_signature, &hash_to_sign);
	DBG(DBG_CRYPT, DBG_dump("sig_from_nss", raw_signature.data, raw_signature.len));
	if (s != SECSuccess) {
		/* PR_GetError() returns the thread-local error */
		log_nss_error(RC_LOG_SERIOUS, logger, PR_GetError(),
			      "ECDSA sign function failed");
		return (struct hash_signature) { .len = 0, };
	}

	SECItem encoded_signature;
	if (DSAU_EncodeDerSigWithLen(&encoded_signature, &raw_signature,
				     raw_signature.len) != SECSuccess) {
		/* PR_GetError() returns the thread-local error */
		log_nss_error(RC_LOG, logger, PR_GetError(),
			      "NSS: constructing DER encoded ECDSA signature using DSAU_EncodeDerSigWithLen() failed:");
		return (struct hash_signature) { .len = 0, };
	}
	struct hash_signature signature = {
		.len = encoded_signature.len,
	};
	passert(encoded_signature.len <= sizeof(signature.ptr/*an-array*/));
	memcpy(signature.ptr, encoded_signature.data, encoded_signature.len);
	SECITEM_FreeItem(&encoded_signature, PR_FALSE);

	DBG(DBG_CRYPT, DBG_log("ECDSA_sign_hash: Ended using NSS"));
	return signature;
}

const struct pubkey_type pubkey_type_ecdsa = {
	.alg = PUBKEY_ALG_ECDSA,
	.name = "ECDSA",
	.private_key_kind = PKK_ECDSA,
	.unpack_pubkey_content = ECDSA_unpack_pubkey_content,
	.free_pubkey_content = ECDSA_free_pubkey_content,
	.extract_private_key_stuff = ECDSA_extract_private_key_stuff,
	.free_secret_content = ECDSA_free_secret_content,
	.secret_sane = ECDSA_secret_sane,
	.sign_hash = ECDSA_sign_hash,
	.extract_pubkey_content = ECDSA_extract_pubkey_content,
};

const struct pubkey_type *pubkey_alg_type(enum pubkey_alg alg)
{
	static const struct pubkey_type *pubkey_types[] = {
		[PUBKEY_ALG_RSA] = &pubkey_type_rsa,
		[PUBKEY_ALG_ECDSA] = &pubkey_type_ecdsa,
	};
	passert(alg < elemsof(pubkey_types));
	const struct pubkey_type *type = pubkey_types[alg];
	pexpect(type != NULL);
	return type;
}

/*
 * XXX: Go for a simplicity - a switch is easier than adding to
 * pubkey_type - especially when the fields could end up moving to
 * struct pubkey proper (we can but dream).
 */

const char *pubkey_keyid(const struct pubkey *pk)
{
	switch (pk->type->alg) {
	case PUBKEY_ALG_RSA:
		return pk->u.rsa.keyid;
	case PUBKEY_ALG_ECDSA:
		return pk->u.ecdsa.keyid;
	default:
		bad_case(pk->type->alg);
	}
}

const ckaid_t *pubkey_ckaid(const struct pubkey *pk)
{
	switch (pk->type->alg) {
	case PUBKEY_ALG_RSA:
		return &pk->u.rsa.ckaid;
	case PUBKEY_ALG_ECDSA:
		return &pk->u.ecdsa.ckaid;
	default:
		bad_case(pk->type->alg);
	}
}

const ckaid_t *secret_ckaid(const struct secret *secret)
{
	if (secret->pks.pubkey_type != NULL) {
		switch (secret->pks.pubkey_type->alg) {
		case PUBKEY_ALG_RSA:
			return &secret->pks.u.RSA_private_key.pub.ckaid;
		case PUBKEY_ALG_ECDSA:
			return &secret->pks.u.ECDSA_private_key.pub.ckaid;
		default:
			bad_case(secret->pks.pubkey_type->alg);
		}
	} else {
		return NULL;
	}
}

const char *secret_keyid(const struct secret *secret)
{

	if (secret->pks.pubkey_type != NULL) {
		switch (secret->pks.pubkey_type->alg) {
		case PUBKEY_ALG_RSA:
			return secret->pks.u.RSA_private_key.pub.keyid;
		case PUBKEY_ALG_ECDSA:
			return secret->pks.u.ECDSA_private_key.pub.keyid;
		default:
			bad_case(secret->pks.pubkey_type->alg);
		}
	} else {
		return NULL;
	}
}

unsigned pubkey_size(const struct pubkey *pk)
{
	switch (pk->type->alg) {
	case PUBKEY_ALG_RSA:
		return pk->u.rsa.k;
	case PUBKEY_ALG_ECDSA:
		return pk->u.ecdsa.k;
	default:
		bad_case(pk->type->alg);
	}
}

/*
 * free a public key struct
 */
void free_public_key(struct pubkey *pk)
{
	free_id_content(&pk->id);
	free_chunk_content(&pk->issuer);
	/* algorithm-specific freeing */
	pk->type->free_pubkey_content(&pk->u);
	pfree(pk);
}

struct secret *lsw_foreach_secret(struct secret *secrets,
				secret_eval func, void *uservoid)
{
	for (struct secret *s = secrets; s != NULL; s = s->next) {
		struct private_key_stuff *pks = &s->pks;
		int result = (*func)(s, pks, uservoid);

		if (result == 0)
			return s;

		if (result == -1)
			break;
	}
	return NULL;
}

static struct secret *find_pubkey_secret_by_ckaid(struct secret *secrets,
						  const struct pubkey_type *type,
						  const SECItem *pubkey_ckaid)
{
	for (struct secret *s = secrets; s != NULL; s = s->next) {
		const struct private_key_stuff *pks = &s->pks;
		dbg("trying secret %s:%s",
		    enum_name(&pkk_names, pks->kind),
		    (pks->kind == PKK_RSA ? pks->u.RSA_private_key.pub.keyid :
		     pks->kind == PKK_ECDSA ? pks->u.ECDSA_private_key.pub.keyid :
		     "N/A"));
		if (s->pks.pubkey_type == type) {
			const ckaid_t *s_ckaid = secret_ckaid(s);
			if (ckaid_eq_nss(s_ckaid, pubkey_ckaid)) {
				dbg("matched");
				return s;
			}
		}
	}
	return NULL;
}

struct secret *lsw_find_secret_by_public_key(struct secret *secrets,
					     const struct pubkey *public_key)
{
	dbg("searching for secret matching public key %s:%s",
	    public_key->type->name, pubkey_keyid(public_key));
	SECItem nss_ckaid = same_ckaid_as_secitem(pubkey_ckaid(public_key));
	return find_pubkey_secret_by_ckaid(secrets, public_key->type,
					   &nss_ckaid);
}

struct secret *lsw_find_secret_by_id(struct secret *secrets,
				     enum PrivateKeyKind kind,
				     const struct id *local_id,
				     const struct id *remote_id,
				     bool asym)
{
	enum {
		match_none = 000,

		/* bits */
		match_default = 001,
		match_any = 002,
		match_remote = 004,
		match_local = 010
	};
	unsigned int best_match = match_none;
	struct secret *best = NULL;

	for (struct secret *s = secrets; s != NULL; s = s->next) {
		if (DBGP(DBG_BASE)) {
			id_buf idl;
			DBG_log("line %d: key type %s(%s) to type %s",
				s->pks.line,
				enum_name(&pkk_names, kind),
				str_id(local_id, &idl),
				enum_name(&pkk_names, s->pks.kind));
		}

		if (s->pks.kind == kind) {
			unsigned int match = match_none;

			if (s->ids == NULL) {
				/*
				 * a default (signified by lack of ids):
				 * accept if no more specific match found
				 */
				match = match_default;
			} else {
				/* check if both ends match ids */
				struct id_list *i;
				int idnum = 0;

				for (i = s->ids; i != NULL; i = i->next) {
					idnum++;
					if (any_id(&i->id)) {
						/*
						 * match any will
						 * automatically match
						 * local and remote so
						 * treat it as its own
						 * match type so that
						 * specific matches
						 * get a higher
						 * "match" value and
						 * are used in
						 * preference to "any"
						 * matches.
						 */
						match |= match_any;
					} else {
						if (same_id(&i->id, local_id)) {
							match |= match_local;
						}

						if (remote_id != NULL &&
						    same_id(&i->id, remote_id)) {
							match |= match_remote;
						}
					}

					if (DBGP(DBG_BASE)) {
						id_buf idi;
						id_buf idl;
						id_buf idr;
						DBG_log("%d: compared key %s to %s / %s -> 0%02o",
							idnum,
							str_id(&i->id, &idi),
							str_id(local_id, &idl),
							(remote_id == NULL ? "" : str_id(remote_id, &idr)),
							match);
					}
				}

				/*
				 * If our end matched the only id in the list,
				 * default to matching any peer.
				 * A more specific match will trump this.
				 */
				if (match == match_local &&
				    s->ids->next == NULL)
					match |= match_default;
			}

			dbg("line %d: match=0%02o", s->pks.line, match);

			switch (match) {
			case match_local:
				/*
				 * if this is an asymmetric
				 * (eg. public key) system, allow
				 * this-side-only match to count, even
				 * if there are other ids in the list.
				 */
				if (!asym)
					break;
				/* FALLTHROUGH */
			case match_default:	/* default all */
			case match_any:	/* a wildcard */
			case match_local | match_default:	/* default peer */
			case match_local | match_any: /* %any/0.0.0.0 and local */
			case match_remote | match_any: /* %any/0.0.0.0 and remote */
			case match_local | match_remote:	/* explicit */
				if (match == best_match) {
					/*
					 * two good matches are equally good:
					 * do they agree?
					 */
					bool same = FALSE;

					switch (kind) {
					case PKK_NULL:
						same = TRUE;
						break;
					case PKK_PSK:
						same = hunk_eq(s->pks.u.preshared_secret,
							       best->pks.u.preshared_secret);
						break;
					case PKK_RSA:
						/*
						 * Dirty trick: since we have
						 * code to compare RSA public
						 * keys, but not private keys,
						 * we make the assumption that
						 * equal public keys mean equal
						 * private keys. This ought to
						 * work.
						 */
						same = same_RSA_public_key(
							&s->pks.u.RSA_private_key.pub,
							&best->pks.u.RSA_private_key.pub);
						break;
					case PKK_ECDSA:
						/* there are no ECDSA kind of secrets */
						/* ??? this seems not to be the case */
						break;
					case PKK_XAUTH:
						/*
						 * We don't support this yet,
						 * but no need to die
						 */
						break;
					case PKK_PPK:
						same = hunk_eq(s->pks.ppk,
							       best->pks.ppk);
						break;
					default:
						bad_case(kind);
					}
					if (!same) {
						dbg("multiple ipsec.secrets entries with distinct secrets match endpoints: first secret used");
						/*
						 * list is backwards:
						 * take latest in list
						 */
						best = s;
					}
				} else if (match > best_match) {
					dbg("match 0%02o beats previous best_match 0%02o match=%p (line=%d)",
					    match,
					    best_match,
					    s, s->pks.line);

					/* this is the best match so far */
					best_match = match;
					best = s;
				} else {
					dbg("match 0%02o loses to best_match 0%02o",
					    match, best_match);
				}
			}
		}
	}

	dbg("concluding with best_match=0%02o best=%p (lineno=%d)",
	    best_match, best,
	    best == NULL ? -1 : best->pks.line);

	return best;
}

/*
 * check the existence of an RSA private key matching an RSA public
 */
bool lsw_has_private_rawkey(const struct secret *secrets, const struct pubkey *pk)
{
	for (const struct secret *s = secrets; s != NULL; s = s->next) {
		if (s->pks.kind == PKK_RSA &&
		    same_RSA_public_key(&s->pks.u.RSA_private_key.pub,
					&pk->u.rsa))
		{
			return TRUE;
		}
	}
	return FALSE;
}

/*
 * digest a secrets file
 *
 * The file is a sequence of records.  A record is a maximal sequence of
 * tokens such that the first, and only the first, is in the first column
 * of a line.
 *
 * Tokens are generally separated by whitespace and are key words, ids,
 * strings, or data suitable for ttodata(3).  As a nod to convention,
 * a trailing ":" on what would otherwise be a token is taken as a
 * separate token.  If preceded by whitespace, a "#" is taken as starting
 * a comment: it and the rest of the line are ignored.
 *
 * One kind of record is an include directive.  It starts with "include".
 * The filename is the only other token in the record.
 * If the filename does not start with /, it is taken to
 * be relative to the directory containing the current file.
 *
 * The other kind of record describes a key.  It starts with a
 * sequence of ids and ends with key information.  Each id
 * is an IP address, a Fully Qualified Domain Name (which will immediately
 * be resolved), or @FQDN which will be left as a name.
 *
 * The form starts the key part with a ":".
 *
 * For Preshared Key, use the "PSK" keyword, and follow it by a string
 * or a data token suitable for ttodata(3).
 *
 * For raw RSA Keys in NSS, use the "RSA" keyword, followed by a
 * brace-enclosed list of key field keywords and data values.
 * The data values are large integers to be decoded by ttodata(3).
 * The fields are a subset of those used by BIND 8.2 and have the
 * same names.
 *
 * For XAUTH passwords, use @username followed by ":XAUTH" followed by the password
 *
 * For Post-Quantum Preshared Keys, use the "PPKS" keyword if the PPK is static.
 *
 * PIN for smartcard is no longer supported - use NSS with smartcards
 */

/* parse PSK from file */
static err_t lsw_process_psk_secret(chunk_t *psk)
{
	err_t ugh = NULL;

	if (*flp->tok == '"' || *flp->tok == '\'') {
		size_t len = flp->cur - flp->tok  - 2;

		if (len < 8) {
			loglog(RC_LOG_SERIOUS, "WARNING: using a weak secret (PSK)");
		}
		*psk = clone_bytes_as_chunk(flp->tok + 1, len, "PSK");
		(void) shift();
	} else {
		char buf[RSA_MAX_ENCODING_BYTES];	/*
							 * limit on size of
							 * binary
							 * representation
							 * of key
							 */
		size_t sz;
		char diag_space[TTODATAV_BUF];

		ugh = ttodatav(flp->tok, flp->cur - flp->tok, 0, buf,
			       sizeof(buf), &sz,
			       diag_space, sizeof(diag_space),
			       TTODATAV_SPACECOUNTS);
		if (ugh != NULL) {
			/* ttodata didn't like PSK data */
			ugh = builddiag("PSK data malformed (%s): %s", ugh,
					flp->tok);
		} else {
			*psk = clone_bytes_as_chunk(buf, sz, "PSK");
			(void) shift();
		}
	}

	dbg("processing PSK at line %d: %s",
	    flp->lino, ugh == NULL ? "passed" : ugh);

	return ugh;
}

/* parse XAUTH secret from file */
static err_t lsw_process_xauth_secret(chunk_t *xauth)
{
	err_t ugh = NULL;

	if (*flp->tok == '"' || *flp->tok == '\'') {
		*xauth = clone_bytes_as_chunk(flp->tok + 1, flp->cur - flp->tok  - 2,
					      "XAUTH");
		(void) shift();
	} else {
		char buf[RSA_MAX_ENCODING_BYTES];	/*
							 * limit on size of
							 * binary
							 * representation
							 * of key
							 */
		size_t sz;
		char diag_space[TTODATAV_BUF];

		ugh = ttodatav(flp->tok, flp->cur - flp->tok, 0, buf,
			       sizeof(buf), &sz,
			       diag_space, sizeof(diag_space),
			       TTODATAV_SPACECOUNTS);
		if (ugh != NULL) {
			/* ttodata didn't like PSK data */
			ugh = builddiag("PSK data malformed (%s): %s", ugh,
					flp->tok);
		} else {
			*xauth = clone_bytes_as_chunk(buf, sz, "XAUTH");
			(void) shift();
		}
	}

	dbg("processing XAUTH at line %d: %s",
	    flp->lino, ugh == NULL ? "passed" : ugh);

	return ugh;
}

/* parse static PPK  */
static err_t lsw_process_ppk_static_secret(chunk_t *ppk, chunk_t *ppk_id)
{
	err_t ugh = NULL;

	if (*flp->tok == '"' || *flp->tok == '\'') {
		size_t len = flp->cur - flp->tok - 2;

		*ppk_id = clone_bytes_as_chunk(flp->tok + 1, len, "PPK ID");
	} else {
		ugh = "No quotation marks found. PPK ID should be in quotation marks";
		return ugh;
	}

	if (!shift()) {
		ugh = "No PPK found. PPK should be specified after PPK ID";
		free_chunk_content(ppk_id);
		return ugh;
	}

	if (*flp->tok == '"' || *flp->tok == '\'') {
		size_t len = flp->cur - flp->tok - 2;

		*ppk = clone_bytes_as_chunk(flp->tok + 1, len, "PPK");
		(void) shift();
	} else {
		char buf[RSA_MAX_ENCODING_BYTES];	/*
							 * limit on size of
							 * binary
							 * representation
							 * of key
							 */
		size_t sz;
		char diag_space[TTODATAV_BUF];

		ugh = ttodatav(flp->tok, flp->cur - flp->tok, 0, buf,
			       sizeof(buf), &sz,
			       diag_space, sizeof(diag_space),
			       TTODATAV_SPACECOUNTS);
		if (ugh != NULL) {
			/* ttodata didn't like PPK data */
			ugh = builddiag("PPK data malformed (%s): %s", ugh,
					flp->tok);
			free_chunk_content(ppk_id);
		} else {
			*ppk = clone_bytes_as_chunk(buf, sz, "PPK");
			(void) shift();
		}
	}

	dbg("processing PPK at line %d: %s",
	    flp->lino, ugh == NULL ? "passed" : ugh);

	return ugh;
}

struct secret *lsw_get_ppk_by_id(struct secret *s, chunk_t ppk_id)
{
	while (s != NULL) {
		struct private_key_stuff pks = s->pks;
		if (pks.kind == PKK_PPK && hunk_eq(pks.ppk_id, ppk_id))
			return s;
		s = s->next;
	}
	return NULL;
}

static SECKEYPrivateKey *copy_private_key(SECKEYPrivateKey *private_key)
{
	SECKEYPrivateKey *unpacked_key = NULL;
	if (private_key->pkcs11Slot != NULL) {
		PK11SlotInfo *slot = PK11_ReferenceSlot(private_key->pkcs11Slot);
		if (slot != NULL) {
			dbg("copying key using reference slot");
			unpacked_key = PK11_CopyTokenPrivKeyToSessionPrivKey(slot, private_key);
			PK11_FreeSlot(slot);
		}
	}
	if (unpacked_key == NULL) {
		CK_MECHANISM_TYPE mech = PK11_MapSignKeyType(private_key->keyType);
		PK11SlotInfo *slot = PK11_GetBestSlot(mech, NULL);
		if (slot != NULL) {
			dbg("copying key using mech/slot");
			unpacked_key = PK11_CopyTokenPrivKeyToSessionPrivKey(slot, private_key);
			PK11_FreeSlot(slot);
		}
	}
	if (unpacked_key == NULL) {
		dbg("copying key using SECKEY_CopyPrivateKey()");
		unpacked_key = SECKEY_CopyPrivateKey(private_key);
	}
	return unpacked_key;
}

/*
 * Parse fields of RSA private key.
 *
 * A braced list of keyword and value pairs.
 * At the moment, each field is required, in order.
 * The fields come from BIND 8.2's representation
 *
 * Danger! When an error is returned, the contents of *PKS are a mess
 * - the caller gets to free this up (which is still easier than try
 * to do it here).
 */
static err_t lsw_process_rsa_secret(struct private_key_stuff *pks)
{
	struct RSA_private_key *rsak = &pks->u.RSA_private_key;
	passert(tokeq("{"));
	while (1) {
		if (!shift()) {
			return "premature end of RSA key";
		}
		if (tokeq("}")) {
			break;
		}

		const struct fld *p = NULL;
		const struct fld *f;
		for (f = RSA_private_field;
		     f < RSA_private_field + elemsof(RSA_private_field);
		     f++) {
			if (tokeqword(f->name)) {
				p = f;
				break;
			}
		}
		if (p == NULL) {
			return builddiag("RSA keyword '%s' not recognised", flp->tok);
		}
		if (!shift()) {
			return "premature end of RSA key";
		}

		/* skip optional ':' */
		if (tokeq(":") && !shift()) {
			return "premature end of RSA key";
		}

		/* Binary Value of key field */
		unsigned char bv[RSA_MAX_ENCODING_BYTES];
		size_t bvlen;
		char diag_space[TTODATAV_BUF];
		err_t ugh = ttodatav(flp->tok, flp->cur - flp->tok, 0,
				     (char *)bv, sizeof(bv),
				     &bvlen,
				     diag_space, sizeof(diag_space),
				     TTODATAV_SPACECOUNTS);
		if (ugh != NULL) {
			/* in RSA key, ttodata didn't like */
			return builddiag("RSA data malformed (%s): %s",
					 ugh, flp->tok);
		}
		passert(sizeof(bv) >= bvlen);

		/* dispose of the data */
		if (p->offset >= 0) {
			dbg("saving %s", p->name);
			DBG(DBG_PRIVATE, DBG_dump(p->name, bv, bvlen));
			chunk_t *n = (chunk_t*) ((char *)rsak + p->offset);
			*n = clone_bytes_as_chunk(bv, bvlen, p->name);
			DBG(DBG_PRIVATE, DBG_dump_hunk(p->name, *n));
		} else {
			dbg("ignoring %s", p->name);
		}
	}
	passert(tokeq("}"));
	if (shift()) {
		return "malformed end of RSA private key -- unexpected token after '}'";
	}

	/*
	 * Check that all required fields are present.
	 */
	const struct fld *p;
	for (p = RSA_private_field;
	     p < &RSA_private_field[elemsof(RSA_private_field)]; p++) {
		if (p->offset >= 0) {
			chunk_t *n = (chunk_t*) ((char *)rsak + p->offset);
			if (n->len == 0) {
				return builddiag("field '%s' either missing or empty", p->name);
			}
		}
	}

	rsak->pub.k = rsak->pub.n.len;
	rsak->pub.keyid[0] = '\0';	/* in case of failure */
	if (rsak->pub.e.len > 0 || rsak->pub.n.len >0) {
		splitkeytoid(rsak->pub.e.ptr, rsak->pub.e.len,
			     rsak->pub.n.ptr, rsak->pub.n.len,
			     rsak->pub.keyid, sizeof(rsak->pub.keyid));
	}

	/* Finally, the CKAID */
	err_t err = form_ckaid_rsa(rsak->pub.n, &rsak->pub.ckaid);
	if (err) {
		/* let caller recover from mess */
		return err;
	}

	/* now try to find the private key in NSS */

	PK11SlotInfo *slot = PK11_GetInternalKeySlot();
	if (!pexpect(slot != NULL)) {
		return "NSS: has no internal slot ....";
	}

	SECItem nss_ckaid = same_ckaid_as_secitem(&rsak->pub.ckaid);
	SECKEYPrivateKey *private_key = PK11_FindKeyByKeyID(slot, &nss_ckaid,
							    lsw_return_nss_password_file_info());
	if (private_key == NULL) {
		dbg("NSS: can't find the private key using the NSS CKAID");
		CERTCertificate *cert = get_cert_by_ckaid_from_nss(&rsak->pub.ckaid);
		if (cert == NULL) {
			return "can't find the private key matching the NSS CKAID";
		}
		private_key = PK11_FindKeyByAnyCert(cert, lsw_return_nss_password_file_info());
		CERT_DestroyCertificate(cert);
		if (private_key == NULL) {
			return "can't find the private key (the certificate found using NSS CKAID has no matching private key)";
		}
	}
	pks->private_key = copy_private_key(private_key);
	SECKEY_DestroyPrivateKey(private_key);

	return pks->pubkey_type->secret_sane(pks);
}

static pthread_mutex_t certs_and_keys_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * lock access to my certs and keys
 */
static void lock_certs_and_keys(const char *who)
{
	pthread_mutex_lock(&certs_and_keys_mutex);
	dbg("certs and keys locked by '%s'", who);
}

/*
 * unlock access to my certs and keys
 */
static void unlock_certs_and_keys(const char *who)
{
	dbg("certs and keys unlocked by '%s'", who);
	pthread_mutex_unlock(&certs_and_keys_mutex);
}

static void add_secret(struct secret **slist,
		       struct secret *s,
		       const char *story)
{
	/* if the id list is empty, add two empty ids */
	if (s->ids == NULL) {
		struct id_list *idl = alloc_bytes(sizeof(struct id_list), "id list");
		idl->next = NULL;
		idl->id = empty_id;
		idl->id.kind = ID_NONE;
		idl->id.ip_addr = address_any(&ipv4_info);

		struct id_list *idl2 = alloc_bytes(sizeof(struct id_list), "id list");
		idl2->next = idl;
		idl2->id = empty_id;
		idl2->id.kind = ID_NONE;
		idl2->id.ip_addr = address_any(&ipv4_info);

		s->ids = idl2;
	}

	lock_certs_and_keys(story);
	s->next = *slist;
	*slist = s;
	unlock_certs_and_keys(story);
}

static void process_secret(struct secret **psecrets,
			struct secret *s)
{
	err_t ugh = NULL;

	if (tokeqword("psk")) {
		s->pks.kind = PKK_PSK;
		/* preshared key: quoted string or ttodata format */
		ugh = !shift() ? "ERROR: unexpected end of record in PSK" :
			lsw_process_psk_secret(&s->pks.u.preshared_secret);
	} else if (tokeqword("xauth")) {
		/* xauth key: quoted string or ttodata format */
		s->pks.kind = PKK_XAUTH;
		ugh = !shift() ? "ERROR: unexpected end of record in PSK" :
			lsw_process_xauth_secret(&s->pks.u.preshared_secret);
	} else if (tokeqword("rsa")) {
		/*
		 * RSA key: the fun begins.
		 * A braced list of keyword and value pairs.
		 */
		s->pks.kind = PKK_RSA;
		s->pks.pubkey_type = &pubkey_type_rsa;
		if (!shift()) {
			ugh = "ERROR: bad RSA key syntax";
		} else if (tokeq("{")) {
			/* raw RSA key in NSS */
			ugh = lsw_process_rsa_secret(&s->pks);
		} else {
			/* RSA key in certificate in NSS */
			ugh = "WARNING: The :RSA secrets entries for X.509 certificates are no longer needed";
		}
		if (ugh == NULL) {
			libreswan_log("loaded private key for keyid: %s:%s",
				enum_name(&pkk_names, s->pks.kind),
				s->pks.u.RSA_private_key.pub.keyid);
		} else {
			dbg("cleaning up mess left in raw rsa key");
			s->pks.pubkey_type->free_secret_content(&s->pks);
		}
	} else if (tokeqword("ppks")) {
		s->pks.kind = PKK_PPK;
		ugh = !shift() ? "ERROR: unexpected end of record in static PPK" :
			lsw_process_ppk_static_secret(&s->pks.ppk, &s->pks.ppk_id);
	} else if (tokeqword("pin")) {
		ugh = "ERROR: keyword 'pin' obsoleted, please use NSS for smartcard support";
	} else {
		ugh = builddiag("ERROR: unrecognized key format: %s", flp->tok);
	}

	if (ugh != NULL) {
		loglog(RC_LOG_SERIOUS, "\"%s\" line %d: %s",
			flp->filename, flp->lino, ugh);
		/* free id's that should have been allocated */
		if (s->ids != NULL) {
			struct id_list *i, *ni;
			for (i = s->ids; i != NULL; i = ni) {
				ni = i->next;	/* grab before freeing i */
				free_id_content(&i->id);
				pfree(i);
			}
		}
		/* finally free s */
		pfree(s);
	} else if (flushline("expected record boundary in key")) {
		/* gauntlet has been run: install new secret */
		add_secret(psecrets, s, "process_secret");
	}
}

static void lsw_process_secret_records(struct secret **psecrets)
{
	/* const struct secret *secret = *psecrets; */

	/* read records from ipsec.secrets and load them into our table */
	for (;; ) {
		(void)flushline(NULL);	/* silently ditch leftovers, if any */
		if (flp->bdry == B_file)
			break;

		flp->bdry = B_none;	/* eat the Record Boundary */
		(void)shift();	/* get real first token */

		if (tokeqword("include")) {
			/* an include directive */
			char fn[MAX_TOK_LEN];	/*
						 * space for filename
						 * (I hope)
						 */
			char *p = fn;
			char *end_prefix = strrchr(flp->filename, '/');

			if (!shift()) {
				loglog(RC_LOG_SERIOUS,
					"\"%s\" line %d: unexpected end of include directive",
					flp->filename, flp->lino);
				continue;	/* abandon this record */
			}

			/*
			 * if path is relative and including file's pathname has
			 * a non-empty dirname, prefix this path with that
			 * dirname.
			 */
			if (flp->tok[0] != '/' && end_prefix != NULL) {
				size_t pl = end_prefix - flp->filename + 1;

				/*
				 * "clamp" length to prevent problems now;
				 * will be rediscovered and reported later.
				 */
				if (pl > sizeof(fn))
					pl = sizeof(fn);
				memcpy(fn, flp->filename, pl);
				p += pl;
			}
			if (flp->cur - flp->tok >= &fn[sizeof(fn)] - p) {
				loglog(RC_LOG_SERIOUS,
					"\"%s\" line %d: include pathname too long",
					flp->filename, flp->lino);
				continue;	/* abandon this record */
			}
			/*
			 * The above test checks that there is enough space for strcpy
			 * but clang 3.4 thinks the destination will overflow.
			 *	strcpy(p, flp->tok);
			 * Rewrite as a memcpy in the hope of calming it.
			 */
			memcpy(p, flp->tok, flp->cur - flp->tok + 1);
			(void) shift();	/* move to Record Boundary, we hope */
			if (flushline("ignoring malformed INCLUDE -- expected Record Boundary after filename"))
			{
				lsw_process_secrets_file(psecrets, fn);
				flp->tok = NULL;	/* redundant? */
			}
		} else {
			/* expecting a list of indices and then the key info */
			struct secret *s = alloc_thing(struct secret, "secret");

			s->ids = NULL;
			s->pks.kind = PKK_PSK;	/* default */
			s->pks.u.preshared_secret = EMPTY_CHUNK;
			s->pks.line = flp->lino;
			s->next = NULL;

			for (;;) {
				struct id id;
				err_t ugh;

				if (tokeq(":")) {
					/* found key part */
					(void) shift();	/* eat ":" */
					process_secret(psecrets, s);
					break;
				}

				/*
				 * an id
				 * See RFC2407 IPsec Domain of
				 * Interpretation 4.6.2
				 */
				if (tokeq("%any")) {
					id = empty_id;
					id.kind = ID_IPV4_ADDR;
					id.ip_addr = address_any(&ipv4_info);
					ugh = NULL;
				} else if (tokeq("%any6")) {
					id = empty_id;
					id.kind = ID_IPV6_ADDR;
					id.ip_addr = address_any(&ipv6_info);
					ugh = NULL;
				} else {
					ugh = atoid(flp->tok, &id);
				}

				if (ugh != NULL) {
					loglog(RC_LOG_SERIOUS,
						"ERROR \"%s\" line %d: index \"%s\" %s",
						flp->filename,
						flp->lino, flp->tok,
						ugh);
				} else {
					struct id_list *i = alloc_thing(
						struct id_list,
						"id_list");

					i->id = id;
					i->next = s->ids;
					s->ids = i;
					id_buf b;
					dbg("id type added to secret(%p) %s: %s",
					    s, enum_name(&pkk_names, s->pks.kind),
					    str_id(&id, &b));
				}
				if (!shift()) {
					/* unexpected Record Boundary or EOF */
					loglog(RC_LOG_SERIOUS,
						"\"%s\" line %d: unexpected end of id list",
						flp->filename, flp->lino);
					pfree(s);
					break;
				}
			}
		}
	}
}

static int globugh_secrets(const char *epath, int eerrno)
{
	LOG_ERRNO(eerrno, "problem with secrets file \"%s\"", epath);
	return 1;	/* stop glob */
}

static void lsw_process_secrets_file(struct secret **psecrets,
				const char *file_pat)
{
	struct file_lex_position pos;
	char **fnp;
	glob_t globbuf;

	pos.depth = flp == NULL ? 0 : flp->depth + 1;

	if (pos.depth > 10) {
		loglog(RC_LOG_SERIOUS,
			"preshared secrets file \"%s\" nested too deeply",
			file_pat);
		return;
	}

	/* do globbing */
	int r = glob(file_pat, GLOB_ERR, globugh_secrets, &globbuf);

	switch (r) {
	case 0:
		/* success */
		/* for each file... */
		for (fnp = globbuf.gl_pathv; fnp != NULL && *fnp != NULL; fnp++) {
			if (lexopen(&pos, *fnp, FALSE)) {
				libreswan_log("loading secrets from \"%s\"", *fnp);
				(void) flushline(
					"file starts with indentation (continuation notation)");
				lsw_process_secret_records(psecrets);
				lexclose();
			}
		}
		break;

	case GLOB_NOSPACE:
		loglog(RC_LOG_SERIOUS,
			"out of space processing secrets filename \"%s\"",
			file_pat);
		break;

	case GLOB_ABORTED:
		/* already logged by globugh_secrets() */
		break;

	case GLOB_NOMATCH:
		libreswan_log("no secrets filename matched \"%s\"", file_pat);
		break;

	default:
		loglog(RC_LOG_SERIOUS, "unknown glob error %d", r);
		break;
	}

	globfree(&globbuf);
}

void lsw_free_preshared_secrets(struct secret **psecrets)
{
	lock_certs_and_keys("free_preshared_secrets");

	if (*psecrets != NULL) {
		struct secret *s, *ns;

		libreswan_log("forgetting secrets");

		for (s = *psecrets; s != NULL; s = ns) {
			struct id_list *i, *ni;

			ns = s->next;	/* grab before freeing s */
			for (i = s->ids; i != NULL; i = ni) {
				ni = i->next;	/* grab before freeing i */
				free_id_content(&i->id);
				pfree(i);
			}
			switch (s->pks.kind) {
			case PKK_PSK:
				pfree(s->pks.u.preshared_secret.ptr);
				break;
			case PKK_PPK:
				pfree(s->pks.ppk.ptr);
				pfree(s->pks.ppk_id.ptr);
				break;
			case PKK_XAUTH:
				pfree(s->pks.u.preshared_secret.ptr);
				break;
			case PKK_RSA:
			case PKK_ECDSA:
				/* Note: pub is all there is */
				s->pks.pubkey_type->free_secret_content(&s->pks);
				break;
			default:
				bad_case(s->pks.kind);
			}
			pfree(s);
		}
		*psecrets = NULL;
	}

	unlock_certs_and_keys("free_preshared_secrets");
}

void lsw_load_preshared_secrets(struct secret **psecrets,
				const char *secrets_file)
{
	lsw_free_preshared_secrets(psecrets);
	(void) lsw_process_secrets_file(psecrets, secrets_file);
}

struct pubkey *reference_key(struct pubkey *pk)
{
	pk->refcnt++;
	return pk;
}

void unreference_key(struct pubkey **pkp)
{
	struct pubkey *pk = *pkp;

	if (pk == NULL)
		return;

	/* print stuff */
	id_buf b;
	dbg("unreference key: %p %s cnt %d--",
	    pk, str_id(&pk->id, &b), pk->refcnt);

	/* cancel out the pointer */
	*pkp = NULL;

	passert(pk->refcnt != 0);
	pk->refcnt--;

	/* we are going to free the key as the refcount will hit zero */
	if (pk->refcnt == 0)
		free_public_key(pk);
}

/*
 * Free a public key record.
 * As a convenience, this returns a pointer to next.
 */
struct pubkey_list *free_public_keyentry(struct pubkey_list *p)
{
	struct pubkey_list *nxt = p->next;

	if (p->key != NULL)
		unreference_key(&p->key);
	pfree(p);
	return nxt;
}

void free_public_keys(struct pubkey_list **keys)
{
	while (*keys != NULL)
		*keys = free_public_keyentry(*keys);
}

bool same_RSA_public_key(const struct RSA_public_key *a,
			 const struct RSA_public_key *b)
{
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
	DBG(DBG_CRYPT,
	    if (a->k != b->k && hunk_eq(a->e, b->e)) {
		    DBG_log("XXX: different modulus k (%u vs %u) modulus (%zu vs %zu) caused a mismatch",
			    a->k, b->k, a->n.len, b->n.len);
	    });

	DBG(DBG_CRYPT,
		DBG_log("k did %smatch", (a->k == b->k) ? "" : "NOT ");
		);
	DBG(DBG_CRYPT,
	    DBG_log("n did %smatch",
		    hunk_eq(a->n, b->n) ? "" : "NOT ");
		);
	DBG(DBG_CRYPT,
		DBG_log("e did %smatch",
			hunk_eq(a->e, b->e) ? "" : "NOT ");
		);

	return a == b ||
		(a->k == b->k &&
		 hunk_eq(a->n, b->n) &&
		 hunk_eq(a->e, b->e));
}

void install_public_key(struct pubkey *pk, struct pubkey_list **head)
{
	struct pubkey_list *p =
		alloc_thing(struct pubkey_list, "pubkey entry");

	/* XXX: how screwed up is this? */
	pk->id = clone_id(&pk->id, "install public key id");

	/* copy issuer dn; XXX: how screwed up is this? */
	pk->issuer = clone_hunk(pk->issuer, "install public key issuer");

	/* store the time the public key was installed */
	pk->installed_time = realnow();

	/* install new key at front */
	p->key = reference_key(pk);
	p->next = *head;
	*head = p;
}

void delete_public_keys(struct pubkey_list **head,
			const struct id *id,
			const struct pubkey_type *type)
{
	struct pubkey_list **pp, *p;

	for (pp = head; (p = *pp) != NULL; ) {
		struct pubkey *pk = p->key;

		if (same_id(id, &pk->id) && pk->type == type)
			*pp = free_public_keyentry(p);
		else
			pp = &p->next;
	}
}

static err_t add_pubkey_secret_5(struct secret **secrets, const struct pubkey_type *type,
				 SECKEYPublicKey *pubk, SECItem *ckaid_nss,
				 CERTCertificate *cert)
{
	struct secret *s = alloc_thing(struct secret, "pubkey secret");
	s->pks.pubkey_type = type;
	s->pks.kind = type->private_key_kind;
	s->pks.line = 0;

	/* make an unpacked copy of the private key */

	SECKEYPrivateKey *private_key =
		PK11_FindKeyByAnyCert(cert,
				      lsw_return_nss_password_file_info());
	if (private_key == NULL)
		return "NSS: cert private key not found";

	s->pks.private_key = copy_private_key(private_key);
	SECKEY_DestroyPrivateKey(private_key);
	private_key = NULL;

	type->extract_private_key_stuff(&s->pks, pubk, ckaid_nss);

	err_t err = type->secret_sane(&s->pks);
	if (err != NULL) {
		type->free_secret_content(&s->pks);
		pfree(s);
		return err;
	}

	add_secret(secrets, s, "lsw_add_rsa_secret");
	return NULL;
}

static const struct pubkey_type *pubkey_type_nss(SECKEYPublicKey *pubk)
{
	KeyType key_type = SECKEY_GetPublicKeyType(pubk);
	switch (key_type) {
	case rsaKey:
		return &pubkey_type_rsa;
	case ecKey:
		return &pubkey_type_ecdsa;
	default:
		return NULL;
	}
}

static err_t add_pubkey_secret(struct secret **secrets, CERTCertificate *cert,
			       SECKEYPublicKey *pubk)
{
	/* XXX: see also nss_cert_key_kind(cert) */
	const struct pubkey_type *type = pubkey_type_nss(pubk);
	if (type == NULL) {
		return "NSS cert not supported";
	}

	/*
	 * Getting a SECItem ptr from PK11_GetLowLevelKeyID doesn't
	 * mean that the private key exists. The data may be empty if
	 * there's no private key.
	 */
	SECItem *ckaid_nss =
		PK11_GetLowLevelKeyIDForCert(NULL, cert,
					     lsw_return_nss_password_file_info()); /* MUST FREE */

	if (ckaid_nss == NULL) {
		return "NSS: key ID not found";
	}

	if (ckaid_nss->data == NULL || ckaid_nss->len < 1) {
		SECITEM_FreeItem(ckaid_nss, PR_TRUE);
		return "NSS: no CKAID data";
	}

	if (find_pubkey_secret_by_ckaid(*secrets, type, ckaid_nss) != NULL) {
		SECITEM_FreeItem(ckaid_nss, PR_TRUE);
		dbg("secrets entry for certificate already exists: %s", cert->nickname);
		return NULL;
	}

	dbg("adding %s secret for certificate: %s", type->name, cert->nickname);

	err_t err = add_pubkey_secret_5(secrets, type, pubk, ckaid_nss, cert);
	SECITEM_FreeItem(ckaid_nss, PR_TRUE);
	return err;
}

err_t lsw_add_secret(struct secret **secrets, CERTCertificate *cert)
{
	if (cert == NULL) {
		return "NSS cert not found";
	}

	SECKEYPublicKey *pubk = SECKEY_ExtractPublicKey(&cert->subjectPublicKeyInfo);
	if (pubk == NULL) {
		/* dbg(... nss error) */
		return "NSS: could not determine certificate kind; SECKEY_ExtractPublicKey() failed";
	}

	err_t err = add_pubkey_secret(secrets, cert, pubk);
	SECKEY_DestroyPublicKey(pubk);
	return err;
}

static struct pubkey *allocate_pubkey_nss_3(CERTCertificate *cert,
					    SECKEYPublicKey *pubkey_nss,
					    struct logger *logger)
{
	const struct pubkey_type *type = pubkey_type_nss(pubkey_nss);
	if (type == NULL) {
		log_message(RC_LOG, logger,
			    "NSS: certificate key kind is unknown; not creating pubkey");
		return NULL;
	}

	SECItem *ckaid_nss = PK11_GetLowLevelKeyIDForCert(NULL, cert,
							  lsw_return_nss_password_file_info()); /* must free */
	if (ckaid_nss == NULL) {
		/* someone deleted CERT from the NSS DB */
		log_message(RC_LOG, logger,
			    "NSS: could not extract CKAID from RSA certificate '%s'",
			    cert->nickname);
		return NULL;
	}

	struct pubkey *pk = alloc_thing(struct pubkey, "RSA pubkey");
	pk->type = type;
	pk->id = empty_id;
	pk->issuer = empty_chunk;
	type->extract_pubkey_content(&pk->u, pubkey_nss, ckaid_nss);
	SECITEM_FreeItem(ckaid_nss, PR_TRUE);
	return pk;
}

struct pubkey *allocate_pubkey_nss(CERTCertificate *cert, struct logger *logger)
{
	if (!pexpect(cert != NULL)) {
		return NULL;
	}

	SECKEYPublicKey *pubkey_nss = SECKEY_ExtractPublicKey(&cert->subjectPublicKeyInfo); /* must free */
	if (pubkey_nss == NULL) {
		log_message(RC_LOG, logger,
			    "NSS: could not extract public key from certificate '%s'",
			    cert->nickname);
		return NULL;
	}

	struct pubkey *pubkey = allocate_pubkey_nss_3(cert, pubkey_nss, logger);
	SECKEY_DestroyPublicKey(pubkey_nss);
	return pubkey;
}
