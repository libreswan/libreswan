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
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>	/* missing from <resolv.h> on old systems */

#include <pk11pub.h>
#include <prerror.h>
#include <cert.h>
#include <cryptohi.h>
#include <keyhi.h>

#include "lswglob.h"
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
#include "certs.h"

/*
 * Build up a diagnostic in a static buffer -- NOT RE-ENTRANT.
 *
 * Although this would be a generally useful function, it is very
 * hard to come up with a discipline that prevents different uses
 * from interfering.  It is intended that by limiting it to building
 * diagnostics, we will avoid this problem.
 * Juggling is performed to allow an argument to be a previous
 * result: the new string may safely depend on the old one.  This
 * restriction is not checked in any way: violators will produce
 * confusing results (without crashing!).
 *
 * @param fmt String format
 * @param ... strings
 * @return err_t
 */

static err_t builddiag(const char *fmt, ...) PRINTF_LIKE(1);	/* NOT RE-ENTRANT */
static err_t builddiag(const char *fmt, ...)
{
	/* longer messages will be truncated */
	static char mydiag_space[LOG_WIDTH];
	char t[sizeof(mydiag_space)];	/* build result here first */
	va_list args;
	va_start(args, fmt);
	t[0] = '\0';	/* in case nothing terminates string */
	vsnprintf(t, sizeof(t), fmt, args);
	va_end(args);
	strcpy(mydiag_space, t);
	return mydiag_space;
}

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

static void process_secrets_file(struct file_lex_position *flp,
				 struct secret **psecrets, const char *file_pat);

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
void form_keyid(chunk_t e, chunk_t n, keyid_t *keyid, size_t *keysize)
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
		DBGF(DBG_CRYPT, "XXX: adjusted modulus length %zu->%zu",
		     n.len, n.len - 1);
		n.ptr++;
		n.len--;
	}

	/* form the Libreswan keyid */
	err_t err = splitkey_to_keyid(e.ptr, e.len, n.ptr, n.len, keyid);
	passert(err == NULL);

	/* return the RSA modulus size in octets */
	*keysize = n.len;
}

static err_t RSA_unpack_pubkey_content(union pubkey_content *u,
				       keyid_t *keyid, ckaid_t *ckaid, size_t *size,
				       chunk_t pubkey)
{
	return unpack_RSA_public_key(&u->rsa, keyid, ckaid, size, &pubkey);
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

static void RSA_extract_public_key(struct RSA_public_key *pub,
				   keyid_t *keyid, ckaid_t *ckaid, size_t *size,
				   SECKEYPublicKey *pubk,
				   SECItem *cert_ckaid)
{
	pub->e = clone_bytes_as_chunk(pubk->u.rsa.publicExponent.data,
					   pubk->u.rsa.publicExponent.len, "e");
	pub->n = clone_bytes_as_chunk(pubk->u.rsa.modulus.data,
					   pubk->u.rsa.modulus.len, "n");
	*ckaid = ckaid_from_secitem(cert_ckaid);
	form_keyid(pub->e, pub->n, keyid, size);
}

static void RSA_extract_pubkey_content(union pubkey_content *pkc,
				       keyid_t *keyid, ckaid_t *ckaid, size_t *size,
				       SECKEYPublicKey *pubkey_nss,
				       SECItem *ckaid_nss)
{
	RSA_extract_public_key(&pkc->rsa, keyid, ckaid, size, pubkey_nss, ckaid_nss);
}

static void RSA_extract_private_key_pubkey_content(struct private_key_stuff *pks,
						   keyid_t *keyid, ckaid_t *ckaid, size_t *size,
						   SECKEYPublicKey *pubkey_nss,
						   SECItem *ckaid_nss)
{
	struct RSA_private_key *rsak = &pks->u.RSA_private_key;
	RSA_extract_public_key(&rsak->pub, keyid, ckaid, size,
			       pubkey_nss, ckaid_nss);
}

static void RSA_free_secret_content(struct private_key_stuff *pks)
{
	SECKEY_DestroyPrivateKey(pks->private_key);
	struct RSA_private_key *rsak = &pks->u.RSA_private_key;
	RSA_free_public_content(&rsak->pub);
}

static err_t RSA_secret_sane(struct private_key_stuff *pks)
{
	/*
	 * PKCS#1 1.5 section 6 requires modulus to have at least 12 octets.
	 *
	 * We actually require more (for security).
	 */
	if (pks->size < RSA_MIN_OCTETS)
		return RSA_MIN_OCTETS_UGH;

	/* we picked a max modulus size to simplify buffer allocation */
	if (pks->size > RSA_MAX_OCTETS)
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
		.data = DISCARD_CONST(uint8_t *, hash_val),
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
			log_nss_error(RC_LOG_SERIOUS, logger,
				      "RSA sign function failed");
			return (struct hash_signature) { .len = 0, };
		}
	} else { /* Digital signature scheme with rsa-pss*/
		const CK_RSA_PKCS_PSS_PARAMS *mech = hash_algo->nss.rsa_pkcs_pss_params;
		if (mech == NULL) {
			llog(RC_LOG_SERIOUS, logger,
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
			log_nss_error(RC_LOG_SERIOUS, logger,
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
	.extract_private_key_pubkey_content = RSA_extract_private_key_pubkey_content,
	.free_secret_content = RSA_free_secret_content,
	.secret_sane = RSA_secret_sane,
	.sign_hash = RSA_sign_hash,
};

static err_t ECDSA_unpack_pubkey_content(union pubkey_content *u,
					 keyid_t *keyid, ckaid_t *ckaid, size_t *size,
					 chunk_t pubkey)
{
	return unpack_ECDSA_public_key(&u->ecdsa, keyid, ckaid, size, &pubkey);
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

static void ECDSA_extract_public_key(struct ECDSA_public_key *pub,
				     keyid_t *keyid, ckaid_t *ckaid, size_t *size,
				     SECKEYPublicKey *pubkey_nss,
				     SECItem *ckaid_nss)
{
	pub->pub = clone_secitem_as_chunk(pubkey_nss->u.ec.publicValue, "ECDSA pub");
	pub->ecParams = clone_secitem_as_chunk(pubkey_nss->u.ec.DEREncodedParams, "ECDSA ecParams");
	*size = pubkey_nss->u.ec.publicValue.len;
	*ckaid = ckaid_from_secitem(ckaid_nss);
	/* keyid */
	err_t e = keyblob_to_keyid(pubkey_nss->u.ec.publicValue.data,
				   pubkey_nss->u.ec.publicValue.len, keyid);
	passert(e == NULL);

	if (DBGP(DBG_CRYPT)) {
		DBG_log("keyid *%s", str_keyid(*keyid));
		DBG_log("  size: %zu", *size);
		DBG_dump_hunk("pub", pub->pub);
		DBG_dump_hunk("ecParams", pub->ecParams);
	}
}

static void ECDSA_extract_pubkey_content(union pubkey_content *pkc,
					 keyid_t *keyid, ckaid_t *ckaid, size_t *size,
					 SECKEYPublicKey *pubkey_nss,
					 SECItem *ckaid_nss)
{
	ECDSA_extract_public_key(&pkc->ecdsa, keyid, ckaid, size, pubkey_nss, ckaid_nss);
}

static void ECDSA_extract_private_key_pubkey_content(struct private_key_stuff *pks,
						     keyid_t *keyid, ckaid_t *ckaid, size_t *size,
						     SECKEYPublicKey *pubkey_nss,
						     SECItem *ckaid_nss)
{
	struct ECDSA_private_key *ecdsak = &pks->u.ECDSA_private_key;
	ECDSA_extract_public_key(&ecdsak->pub, keyid, ckaid, size,
				 pubkey_nss, ckaid_nss);
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

	DBGF(DBG_CRYPT, "ECDSA_sign_hash: Started using NSS");

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
	if (DBGP(DBG_CRYPT)) {
		DBG_dump("sig_from_nss", raw_signature.data, raw_signature.len);
	}
	if (s != SECSuccess) {
		/* PR_GetError() returns the thread-local error */
		log_nss_error(RC_LOG_SERIOUS, logger,
			      "ECDSA sign function failed");
		return (struct hash_signature) { .len = 0, };
	}

	SECItem encoded_signature;
	if (DSAU_EncodeDerSigWithLen(&encoded_signature, &raw_signature,
				     raw_signature.len) != SECSuccess) {
		/* PR_GetError() returns the thread-local error */
		log_nss_error(RC_LOG, logger,
			      "NSS: constructing DER encoded ECDSA signature using DSAU_EncodeDerSigWithLen() failed:");
		return (struct hash_signature) { .len = 0, };
	}
	struct hash_signature signature = {
		.len = encoded_signature.len,
	};
	passert(encoded_signature.len <= sizeof(signature.ptr/*an-array*/));
	memcpy(signature.ptr, encoded_signature.data, encoded_signature.len);
	SECITEM_FreeItem(&encoded_signature, PR_FALSE);

	DBGF(DBG_CRYPT, "ECDSA_sign_hash: Ended using NSS");
	return signature;
}

const struct pubkey_type pubkey_type_ecdsa = {
	.alg = PUBKEY_ALG_ECDSA,
	.name = "ECDSA",
	.private_key_kind = PKK_ECDSA,
	.unpack_pubkey_content = ECDSA_unpack_pubkey_content,
	.free_pubkey_content = ECDSA_free_pubkey_content,
	.extract_private_key_pubkey_content = ECDSA_extract_private_key_pubkey_content,
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

const keyid_t *pubkey_keyid(const struct pubkey *pk)
{
	switch (pk->type->alg) {
	case PUBKEY_ALG_RSA:
	case PUBKEY_ALG_ECDSA:
		return &pk->keyid;
	default:
		bad_case(pk->type->alg);
	}
}

const ckaid_t *pubkey_ckaid(const struct pubkey *pk)
{
	return &pk->ckaid;
}

const ckaid_t *secret_ckaid(const struct secret *secret)
{
	if (secret->pks.pubkey_type != NULL) {
		return &secret->pks.ckaid;
	} else {
		return NULL;
	}
}

const keyid_t *secret_keyid(const struct secret *secret)
{

	if (secret->pks.pubkey_type != NULL) {
		switch (secret->pks.pubkey_type->alg) {
		case PUBKEY_ALG_RSA:
		case PUBKEY_ALG_ECDSA:
			return &secret->pks.keyid;
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
	case PUBKEY_ALG_ECDSA:
		return pk->size;
	default:
		bad_case(pk->type->alg);
	}
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

static struct secret *find_secret_by_pubkey_ckaid_1(struct secret *secrets,
						    const struct pubkey_type *type,
						    const SECItem *pubkey_ckaid)
{
	for (struct secret *s = secrets; s != NULL; s = s->next) {
		const struct private_key_stuff *pks = &s->pks;
		dbg("trying secret %s:%s",
		    enum_name(&pkk_names, pks->kind),
		    str_keyid(pks->keyid));
		if (type == NULL/*wildcard*/ ||
		    s->pks.pubkey_type == type) {
			/* only public/private key pairs have a CKAID */
			const ckaid_t *sckaid = secret_ckaid(s);
			if (sckaid != NULL &&
			    ckaid_eq_nss(sckaid, pubkey_ckaid)) {
				dbg("matched");
				return s;
			}
		}
	}
	return NULL;
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
static err_t process_psk_secret(struct file_lex_position *flp, chunk_t *psk)
{
	err_t ugh = NULL;

	if (flp->tok[0] == '"' || flp->tok[0] == '\'') {
		size_t len = flp->cur - flp->tok  - 2;

		if (len < 8) {
			llog(RC_LOG_SERIOUS, flp->logger,
				    "WARNING: using a weak secret (PSK)");
		}
		*psk = clone_bytes_as_chunk(flp->tok + 1, len, "PSK");
		shift(flp);
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
			shift(flp);
		}
	}

	dbg("processing PSK at line %d: %s",
	    flp->lino, ugh == NULL ? "passed" : ugh);

	return ugh;
}

/* parse XAUTH secret from file */
static err_t process_xauth_secret(struct file_lex_position *flp, chunk_t *xauth)
{
	err_t ugh = NULL;

	if (flp->tok[0] == '"' || flp->tok[0] == '\'') {
		*xauth = clone_bytes_as_chunk(flp->tok + 1, flp->cur - flp->tok - 2,
					      "XAUTH");
		shift(flp);
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
			shift(flp);
		}
	}

	dbg("processing XAUTH at line %d: %s",
	    flp->lino, ugh == NULL ? "passed" : ugh);

	return ugh;
}

/* parse static PPK  */
static err_t process_ppk_static_secret(struct file_lex_position *flp,
				       chunk_t *ppk, chunk_t *ppk_id)
{
	err_t ugh = NULL;

	if (flp->tok[0] == '"' || flp->tok[0] == '\'') {
		size_t len = flp->cur - flp->tok - 2;

		*ppk_id = clone_bytes_as_chunk(flp->tok + 1, len, "PPK ID");
	} else {
		ugh = "No quotation marks found. PPK ID should be in quotation marks";
		return ugh;
	}

	if (!shift(flp)) {
		ugh = "No PPK found. PPK should be specified after PPK ID";
		free_chunk_content(ppk_id);
		return ugh;
	}

	if (*flp->tok == '"' || *flp->tok == '\'') {
		size_t len = flp->cur - flp->tok - 2;

		*ppk = clone_bytes_as_chunk(flp->tok + 1, len, "PPK");
		shift(flp);
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
			shift(flp);
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
static err_t process_rsa_secret(struct file_lex_position *flp,
				struct private_key_stuff *pks)
{
	struct RSA_private_key *rsak = &pks->u.RSA_private_key;
	passert(tokeq("{"));
	while (1) {
		if (!shift(flp)) {
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
		if (!shift(flp)) {
			return "premature end of RSA key";
		}

		/* skip optional ':' */
		if (tokeq(":") && !shift(flp)) {
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
			if (DBGP(DBG_CRYPT)) {
				DBG_dump(p->name, bv, bvlen);
			}
			chunk_t *n = (chunk_t*) ((char *)rsak + p->offset);
			*n = clone_bytes_as_chunk(bv, bvlen, p->name);
			if (DBGP(DBG_CRYPT)) {
				DBG_dump_hunk(p->name, *n);
			}
		} else {
			dbg("ignoring %s", p->name);
		}
	}
	passert(tokeq("}"));
	if (shift(flp)) {
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

	pks->size = rsak->pub.n.len;
	pks->keyid = empty_keyid;	/* in case of failure */
	if (rsak->pub.e.len > 0 || rsak->pub.n.len >0) {
		err_t e = splitkey_to_keyid(rsak->pub.e.ptr, rsak->pub.e.len,
					    rsak->pub.n.ptr, rsak->pub.n.len,
					    &pks->keyid);
		if (e != NULL) {
			return e;
		}
	}

	/* Finally, the CKAID */
	err_t err = form_ckaid_rsa(rsak->pub.n, &pks->ckaid);
	if (err) {
		/* let caller recover from mess */
		return err;
	}

	/* now try to find the private key in NSS */

	PK11SlotInfo *slot = PK11_GetInternalKeySlot();
	if (!pexpect(slot != NULL)) {
		return "NSS: has no internal slot ....";
	}

	SECItem nss_ckaid = same_ckaid_as_secitem(&pks->ckaid);
	SECKEYPrivateKey *private_key = PK11_FindKeyByKeyID(slot, &nss_ckaid,
							    lsw_nss_get_password_context(flp->logger));
	if (private_key == NULL) {
		dbg("NSS: can't find the private key using the NSS CKAID");
		CERTCertificate *cert = get_cert_by_ckaid_from_nss(&pks->ckaid,
								   flp->logger);
		if (cert == NULL) {
			return "can't find the private key matching the NSS CKAID";
		}
		private_key = PK11_FindKeyByAnyCert(cert, lsw_nss_get_password_context(flp->logger));
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
		idl->id.ip_addr = ipv4_info.address.any;

		struct id_list *idl2 = alloc_bytes(sizeof(struct id_list), "id list");
		idl2->next = idl;
		idl2->id = empty_id;
		idl2->id.kind = ID_NONE;
		idl2->id.ip_addr = ipv4_info.address.any;

		s->ids = idl2;
	}

	lock_certs_and_keys(story);
	s->next = *slist;
	*slist = s;
	unlock_certs_and_keys(story);
}

static void process_secret(struct file_lex_position *flp,
			   struct secret **psecrets, struct secret *s)
{
	err_t ugh = NULL;

	if (tokeqword("psk")) {
		s->pks.kind = PKK_PSK;
		/* preshared key: quoted string or ttodata format */
		ugh = !shift(flp) ? "ERROR: unexpected end of record in PSK" :
			process_psk_secret(flp, &s->pks.u.preshared_secret);
	} else if (tokeqword("xauth")) {
		/* xauth key: quoted string or ttodata format */
		s->pks.kind = PKK_XAUTH;
		ugh = !shift(flp) ? "ERROR: unexpected end of record in PSK" :
			process_xauth_secret(flp, &s->pks.u.preshared_secret);
	} else if (tokeqword("rsa")) {
		/*
		 * RSA key: the fun begins.
		 * A braced list of keyword and value pairs.
		 */
		s->pks.kind = PKK_RSA;
		s->pks.pubkey_type = &pubkey_type_rsa;
		if (!shift(flp)) {
			ugh = "ERROR: bad RSA key syntax";
		} else if (tokeq("{")) {
			/* raw RSA key in NSS */
			ugh = process_rsa_secret(flp, &s->pks);
		} else {
			/* RSA key in certificate in NSS */
			ugh = "WARNING: The :RSA secrets entries for X.509 certificates are no longer needed";
		}
		if (ugh == NULL) {
			llog(RC_LOG, flp->logger,
				    "loaded private key for keyid: %s:%s",
				    enum_name(&pkk_names, s->pks.kind),
				    str_keyid(s->pks.keyid));
		} else {
			dbg("cleaning up mess left in raw rsa key");
			s->pks.pubkey_type->free_secret_content(&s->pks);
		}
	} else if (tokeqword("ppks")) {
		s->pks.kind = PKK_PPK;
		ugh = !shift(flp) ? "ERROR: unexpected end of record in static PPK" :
			process_ppk_static_secret(flp, &s->pks.ppk, &s->pks.ppk_id);
	} else if (tokeqword("pin")) {
		ugh = "ERROR: keyword 'pin' obsoleted, please use NSS for smartcard support";
	} else {
		ugh = builddiag("ERROR: unrecognized key format: %s", flp->tok);
	}

	if (ugh != NULL) {
		llog(RC_LOG_SERIOUS, flp->logger,
			    "\"%s\" line %d: %s",
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
	} else if (flushline(flp, "expected record boundary in key")) {
		/* gauntlet has been run: install new secret */
		add_secret(psecrets, s, "process_secret");
	}
}

static void process_secret_records(struct file_lex_position *flp,
				   struct secret **psecrets)
{
	/* const struct secret *secret = *psecrets; */

	/* read records from ipsec.secrets and load them into our table */
	for (;; ) {
		flushline(flp, NULL);	/* silently ditch leftovers, if any */
		if (flp->bdry == B_file)
			break;

		flp->bdry = B_none;	/* eat the Record Boundary */
		shift(flp);	/* get real first token */

		if (tokeqword("include")) {
			/* an include directive */
			char fn[MAX_TOK_LEN];	/*
						 * space for filename
						 * (I hope)
						 */
			char *p = fn;
			char *end_prefix = strrchr(flp->filename, '/');

			if (!shift(flp)) {
				llog(RC_LOG_SERIOUS, flp->logger,
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
				llog(RC_LOG_SERIOUS, flp->logger,
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
			shift(flp);	/* move to Record Boundary, we hope */
			if (flushline(flp, "ignoring malformed INCLUDE -- expected Record Boundary after filename")) {
				process_secrets_file(flp, psecrets, fn);
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
					shift(flp);	/* eat ":" */
					process_secret(flp, psecrets, s);
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
					id.ip_addr = ipv4_info.address.any;
					ugh = NULL;
				} else if (tokeq("%any6")) {
					id = empty_id;
					id.kind = ID_IPV6_ADDR;
					id.ip_addr = ipv6_info.address.any;
					ugh = NULL;
				} else {
					ugh = atoid(flp->tok, &id);
				}

				if (ugh != NULL) {
					llog(RC_LOG_SERIOUS, flp->logger,
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
				if (!shift(flp)) {
					/* unexpected Record Boundary or EOF */
					llog(RC_LOG_SERIOUS, flp->logger,
						    "\"%s\" line %d: unexpected end of id list",
						    flp->filename, flp->lino);
					pfree(s);
					break;
				}
			}
		}
	}
}

static void process_secrets_file(struct file_lex_position *oflp,
				 struct secret **psecrets, const char *file_pat)
{
	if (oflp->depth > 10) {
		llog(RC_LOG_SERIOUS, oflp->logger,
			    "preshared secrets file \"%s\" nested too deeply",
			    file_pat);
		return;
	}

	/* do globbing */
	glob_t globbuf;
	int r = lswglob(file_pat, &globbuf, "secrets", oflp->logger);

	switch (r) {
	case 0:
		/* success */
		/* for each file... */
		for (char **fnp = globbuf.gl_pathv; fnp != NULL && *fnp != NULL; fnp++) {
			struct file_lex_position *flp = NULL;
			if (lexopen(&flp, *fnp, false, oflp)) {
				llog(RC_LOG, flp->logger,
					    "loading secrets from \"%s\"", *fnp);
				flushline(flp, "file starts with indentation (continuation notation)");
				process_secret_records(flp, psecrets);
				lexclose(&flp);
			}
		}
		break;

	case GLOB_NOSPACE:
		llog(RC_LOG_SERIOUS, oflp->logger,
			    "out of space processing secrets filename \"%s\"",
			    file_pat);
		break;

	case GLOB_ABORTED:
		/* already logged by globugh_secrets() */
		break;

	case GLOB_NOMATCH:
		llog(RC_LOG, oflp->logger,
			    "no secrets filename matched \"%s\"", file_pat);
		break;

	default:
		llog(RC_LOG_SERIOUS, oflp->logger,
			    "unknown glob error %d", r);
		break;
	}

	globfree(&globbuf);
}

void lsw_free_preshared_secrets(struct secret **psecrets, struct logger *logger)
{
	lock_certs_and_keys("free_preshared_secrets");

	if (*psecrets != NULL) {
		struct secret *s, *ns;

		llog(RC_LOG, logger, "forgetting secrets");

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

void lsw_load_preshared_secrets(struct secret **psecrets, const char *secrets_file,
				struct logger *logger)
{
	lsw_free_preshared_secrets(psecrets, logger);
	struct file_lex_position flp = {
		.logger = logger,
		.depth = 0,
	};
	process_secrets_file(&flp, psecrets, secrets_file);
}

struct pubkey *pubkey_addref(struct pubkey *pk, where_t where)
{
	return refcnt_addref(pk, where);
}

/*
 * free a public key struct
 */
static void free_public_key(struct pubkey **pk, where_t where UNUSED)
{
	free_id_content(&(*pk)->id);
	free_chunk_content(&(*pk)->issuer);
	/* algorithm-specific freeing */
	(*pk)->type->free_pubkey_content(&(*pk)->u);
	pfree(*pk);
	*pk = NULL;
}

void pubkey_delref(struct pubkey **pkp, where_t where)
{
	refcnt_delref(pkp, free_public_key, where);
}

/*
 * Free a public key record.
 * As a convenience, this returns a pointer to next.
 */
struct pubkey_list *free_public_keyentry(struct pubkey_list *p)
{
	struct pubkey_list *nxt = p->next;

	if (p->key != NULL)
		pubkey_delref(&p->key, HERE);
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
	if (DBGP(DBG_CRYPT)) {
	    DBG_log("n did %smatch", hunk_eq(a->n, b->n) ? "" : "NOT ");
	    DBG_log("e did %smatch", hunk_eq(a->e, b->e) ? "" : "NOT ");
	}

	return a == b ||
		(hunk_eq(a->n, b->n) &&
		 hunk_eq(a->e, b->e));
}

/*
 * XXX: this gets called, via replace_public_key() with a PK that is
 * still pointing into a cert.  Hence the "how screwed up is this?"
 * :-(
 */
static void install_public_key(struct pubkey **pk, struct pubkey_list **head)
{
	struct pubkey_list *p = alloc_thing(struct pubkey_list, "pubkey entry");
	/* install new key at front */
	p->key = *pk;
	p->next = *head;
	*head = p;
	*pk = NULL; /* stolen */
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

void replace_public_key(struct pubkey_list **pubkey_db,
			struct pubkey **pk)
{
	/* ??? clang 3.5 thinks pk might be NULL */
	delete_public_keys(pubkey_db, &(*pk)->id, (*pk)->type);
	install_public_key(pk, pubkey_db);
	passert(*pk == NULL); /* stolen */
}

static struct pubkey *alloc_public_key(const struct id *id, /* ASKK */
				       enum dns_auth_level dns_auth_level,
				       const struct pubkey_type *type,
				       realtime_t install_time, realtime_t until_time,
				       uint32_t ttl,
				       const union pubkey_content *pkc,
				       const keyid_t *keyid, const ckaid_t *ckaid, size_t size,
				       where_t where)
{
	struct pubkey *pk = refcnt_alloc(struct pubkey, where);
	pk->u = *pkc;
	pk->id = clone_id(id, "public key id");
	pk->dns_auth_level = dns_auth_level;
	pk->type = type;
	pk->installed_time = install_time;
	pk->until_time = until_time;
	pk->dns_ttl = ttl;
	pk->issuer = EMPTY_CHUNK;	/* raw keys have no issuer */
	pk->keyid = *keyid;
	pk->ckaid = *ckaid;
	pk->size = size;
	return pk;
}

err_t add_public_key(const struct id *id, /* ASKK */
		     enum dns_auth_level dns_auth_level,
		     const struct pubkey_type *type,
		     realtime_t install_time, realtime_t until_time,
		     uint32_t ttl,
		     const chunk_t *key,
		     struct pubkey **pkp,
		     struct pubkey_list **head)
{
	/* first: algorithm-specific decoding of key chunk */
	union pubkey_content scratch_pkc;
	keyid_t keyid;
	ckaid_t ckaid;
	size_t size;
	err_t err = type->unpack_pubkey_content(&scratch_pkc, &keyid, &ckaid, &size, *key);
	if (err != NULL) {
		return err;
	}

	struct pubkey *pubkey = alloc_public_key(id, dns_auth_level, type,
						 install_time, until_time, ttl,
						 &scratch_pkc, &keyid, &ckaid, size,
						 HERE);
	if (pkp != NULL) {
		*pkp = pubkey_addref(pubkey, HERE);
	}
	install_public_key(&pubkey, head);
	passert(pubkey == NULL); /* stolen */
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

static const struct pubkey_type *private_key_type_nss(SECKEYPrivateKey *private_key)
{
	KeyType key_type = SECKEY_GetPrivateKeyType(private_key);
	switch (key_type) {
	case rsaKey:
		return &pubkey_type_rsa;
	case ecKey:
		return &pubkey_type_ecdsa;
	default:
		return NULL;
	}
}

static err_t add_private_key(struct secret **secrets, const struct private_key_stuff **pks,
			     SECKEYPublicKey *pubk, SECItem *ckaid_nss,
			     const struct pubkey_type *type, SECKEYPrivateKey *private_key)
{
	struct secret *s = alloc_thing(struct secret, "pubkey secret");
	s->pks.pubkey_type = type;
	s->pks.kind = type->private_key_kind;
	s->pks.line = 0;
	/* make an unpacked copy of the private key */
	s->pks.private_key = copy_private_key(private_key);
	type->extract_private_key_pubkey_content(&s->pks, &s->pks.keyid, &s->pks.ckaid, &s->pks.size,
						 pubk, ckaid_nss);

	err_t err = type->secret_sane(&s->pks);
	if (err != NULL) {
		type->free_secret_content(&s->pks);
		pfree(s);
		return err;
	}

	add_secret(secrets, s, "lsw_add_rsa_secret");
	*pks = &s->pks;
	return NULL;
}

static err_t find_or_load_private_key_by_cert_3(struct secret **secrets, CERTCertificate *cert,
						const struct private_key_stuff **pks, struct logger *logger,
						SECKEYPublicKey *pubk, SECItem *ckaid_nss,
						const struct pubkey_type *type)
{

	SECKEYPrivateKey *private_key = PK11_FindKeyByAnyCert(cert, lsw_nss_get_password_context(logger));
	if (private_key == NULL)
		return "NSS: cert private key not found";
	err_t err = add_private_key(secrets, pks,
				    /* extracted fields */
				    pubk, ckaid_nss, type, private_key);
	SECKEY_DestroyPrivateKey(private_key);
	return err;
}

static err_t find_or_load_private_key_by_cert_2(struct secret **secrets, CERTCertificate *cert,
						const struct private_key_stuff **pks, bool *load_needed,
						struct logger *logger,
						SECKEYPublicKey *pubk, SECItem *ckaid_nss)
{

	/* XXX: see also nss_cert_key_kind(cert) */
	const struct pubkey_type *type = pubkey_type_nss(pubk);
	if (type == NULL) {
		return "NSS cert not supported";
	}

	struct secret *s = find_secret_by_pubkey_ckaid_1(*secrets, type, ckaid_nss);
	if (s != NULL) {
		dbg("secrets entry for certificate already exists: %s", cert->nickname);
		*pks = &s->pks;
		*load_needed = false;
		return NULL;
	}

	dbg("adding %s secret for certificate: %s", type->name, cert->nickname);
	*load_needed = true;
	err_t err = find_or_load_private_key_by_cert_3(secrets, cert, pks, logger,
						       /* extracted fields */
						       pubk, ckaid_nss, type);
	return err;
}

static err_t find_or_load_private_key_by_cert_1(struct secret **secrets, CERTCertificate *cert,
						const struct private_key_stuff **pks, bool *load_needed,
						struct logger *logger,
						SECKEYPublicKey *pubk)
{
	/*
	 * Getting a SECItem ptr from PK11_GetLowLevelKeyID doesn't
	 * mean that the private key exists - it is just a hash formed
	 * from the cert's public key.
	 */
	SECItem *ckaid_nss =
		PK11_GetLowLevelKeyIDForCert(NULL, cert, lsw_nss_get_password_context(logger)); /* MUST FREE */
	if (ckaid_nss == NULL) {
		return "NSS: key ID not found";
	}

	err_t err = find_or_load_private_key_by_cert_2(secrets, cert, pks, load_needed, logger,
						       /* extracted fields */
						       pubk, ckaid_nss);
	SECITEM_FreeItem(ckaid_nss, PR_TRUE);
	return err;
}

err_t find_or_load_private_key_by_cert(struct secret **secrets, const struct cert *cert,
				       const struct private_key_stuff **pks, bool *load_needed,
				       struct logger *logger)
{
	*load_needed = false;

	if (cert == NULL || cert->u.nss_cert == NULL) {
		return "NSS cert not found";
	}

	SECKEYPublicKey *pubk = SECKEY_ExtractPublicKey(&cert->u.nss_cert->subjectPublicKeyInfo);
	if (pubk == NULL) {
		/* dbg(... nss error) */
		return "NSS: could not determine certificate kind; SECKEY_ExtractPublicKey() failed";
	}

	err_t err = find_or_load_private_key_by_cert_1(secrets, cert->u.nss_cert, pks, load_needed, logger,
						       /* extracted fields */
						       pubk);
	SECKEY_DestroyPublicKey(pubk);
	return err;
}

static err_t find_or_load_private_key_by_ckaid_1(struct secret **secrets,
						 const struct private_key_stuff **pks,
						 SECItem *ckaid_nss, SECKEYPrivateKey *private_key)
{
	const struct pubkey_type *type = private_key_type_nss(private_key);
	if (type == NULL) {
		return "NSS private key not supported (unknown type)";
	}

	SECKEYPublicKey *pubk = SECKEY_ConvertToPublicKey(private_key); /* must free */
	if (pubk == NULL) {
		return "NSS private key has no public key";
	}

	err_t err = add_private_key(secrets, pks, pubk, ckaid_nss, type, private_key);
	SECKEY_DestroyPublicKey(pubk);
	return err;
}

err_t find_or_load_private_key_by_ckaid(struct secret **secrets, const ckaid_t *ckaid,
					const struct private_key_stuff **pks, bool *load_needed,
					struct logger *logger)
{
	*load_needed = false;
	passert(ckaid != NULL);

	SECItem ckaid_nss = same_ckaid_as_secitem(ckaid);
	struct secret *s = find_secret_by_pubkey_ckaid_1(*secrets, NULL, &ckaid_nss);
	if (s != NULL) {
		dbg("secrets entry for ckaid already exists");
		*pks = &s->pks;
		*load_needed = false;
		return NULL;
	}

	*load_needed = true;
	PK11SlotInfo *slot = PK11_GetInternalKeySlot();
	if (!pexpect(slot != NULL)) {
		return "NSS: has no internal slot ....";
	}

	/* must free */
	SECKEYPrivateKey *private_key = PK11_FindKeyByKeyID(slot, &ckaid_nss,
							    lsw_nss_get_password_context(logger));
	if (private_key == NULL) {
		/*
		 * XXX: The code loading ipsec.secrets also tries to
		 * use the CKAID to find the certificate, and then
		 * uses that to find the private key?  Why?
		 */
		return "can't find the private key matching the NSS CKAID";
	}

	ckaid_buf ckb;
	dbg("loaded private key matching CKAID %s", str_ckaid(ckaid, &ckb));
	err_t err = find_or_load_private_key_by_ckaid_1(secrets, pks, &ckaid_nss, private_key);
	SECKEY_DestroyPrivateKey(private_key);
	return err;
}

static diag_t create_pubkey_from_cert_1(const struct id *id,
					CERTCertificate *cert,
					SECKEYPublicKey *pubkey_nss,
					struct pubkey **pk,
					struct logger *logger)
{
	const struct pubkey_type *type = pubkey_type_nss(pubkey_nss);
	if (type == NULL) {
		return diag("NSS: certificate key kind is unknown; not creating pubkey");
	}

	SECItem *ckaid_nss = PK11_GetLowLevelKeyIDForCert(NULL, cert,
							  lsw_nss_get_password_context(logger)); /* must free */
	if (ckaid_nss == NULL) {
		/* someone deleted CERT from the NSS DB */
		return diag("NSS: could not extract CKAID from RSA certificate '%s'",
			    cert->nickname);
	}

	union pubkey_content pkc;
	keyid_t keyid;
	ckaid_t ckaid;
	size_t size;
	type->extract_pubkey_content(&pkc, &keyid, &ckaid, &size, pubkey_nss, ckaid_nss);

	realtime_t install_time = realnow();
	realtime_t until_time;
	PRTime not_before, not_after;
	if (CERT_GetCertTimes(cert, &not_before, &not_after) != SECSuccess) {
		until_time = realtime(-1);
	} else {
		until_time = realtime(not_after / PR_USEC_PER_SEC);
	}
	*pk = alloc_public_key(id, /*dns_auth_level*/0/*default*/,
			       type, install_time, until_time,
			       /*ttl*/0, &pkc, &keyid, &ckaid, size,
			       HERE);
	(*pk)->issuer = clone_secitem_as_chunk(cert->derIssuer, "der");
	SECITEM_FreeItem(ckaid_nss, PR_TRUE);
	return NULL;
}

diag_t create_pubkey_from_cert(const struct id *id,
			       CERTCertificate *cert, struct pubkey **pk, struct logger *logger)
{
	if (!pexpect(cert != NULL)) {
		return NULL;
	}

	/*
	 * Try to convert CERT to an internal PUBKEY object.  If
	 * someone, in parallel, deletes the underlying cert from the
	 * NSS DB, then this will fail.
	 */
	SECKEYPublicKey *pubkey_nss = SECKEY_ExtractPublicKey(&cert->subjectPublicKeyInfo); /* must free */
	if (pubkey_nss == NULL) {
		return diag("NSS: could not extract public key from certificate '%s'",
			    cert->nickname);
	}

	diag_t d = create_pubkey_from_cert_1(id, cert, pubkey_nss, pk, logger);
	SECKEY_DestroyPublicKey(pubkey_nss);
	return d;
}
