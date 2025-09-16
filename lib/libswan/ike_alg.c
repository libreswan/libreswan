/*
 * IKE modular algorithm handling interface, for libreswan
 *
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * Copyright (C) 2003 Mathieu Lafon <mlafon@arkoon.net>
 * Copyright (C) 2005-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2011-2012 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013-2014 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2016-2018 Andrew Cagney
 * Copyright (C) 2020 Nupur Agrawal <nupur202000@gmail.com>
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>


#include "sysdep.h"
#include "constants.h"
#include "fips_mode.h"
#include "lswlog.h"
#include "lswalloc.h"
#include "proposals.h"
#include "ike_alg.h"
#include "ike_alg_integ.h"
#include "ike_alg_encrypt.h"
#include "ike_alg_encrypt_ops.h"
#include "ike_alg_prf.h"
#include "ike_alg_prf_mac_ops.h"
#include "ike_alg_prf_ikev1_ops.h"
#include "ike_alg_prf_ikev2_ops.h"
#include "ike_alg_hash.h"
#include "ike_alg_hash_ops.h"
#include "ike_alg_kem.h"
#include "ike_alg_kem_ops.h"
#include "ike_alg_ipcomp.h"
#include "ike_alg_ipcomp_ops.h"

#define FOR_EACH_IKE_ALGP(TYPE,A)					\
	for (const struct ike_alg **(A) = (TYPE)->algorithms->start;	\
	     (A) < (TYPE)->algorithms->end;				\
	     (A)++)

#define FOR_EACH_IKE_ALG_NAME(ALG, NAME)				\
	for (shunk_t NAME##input = shunk1((ALG)->names),		\
		     NAME = shunk_token(&NAME##input, NULL, ",");	\
	     NAME.len > 0; NAME = shunk_token(&NAME##input, NULL, ","))

struct algorithm_table {
	const struct ike_alg **start;
	const struct ike_alg **end;
};

#define ALGORITHM_TABLE(TABLE) {						\
		.start = (const struct ike_alg **)(TABLE),			\
		.end = (const struct ike_alg **)(TABLE) + elemsof(TABLE),	\
	}

#define FOR_EACH_IKE_ALG_TYPEP(TYPEP)					\
	for (const struct ike_alg_type *const *TYPEP = ike_alg_types;	\
	     TYPEP < ike_alg_types + elemsof(ike_alg_types);		\
	     TYPEP++)

static const struct ike_alg_type *const ike_alg_types[] = {
	&ike_alg_encrypt,
	&ike_alg_hash,
	&ike_alg_prf,
	&ike_alg_integ,
	&ike_alg_kem,
	&ike_alg_ipcomp,
};

const char *ike_alg_key_name(enum ike_alg_key key)
{
	static const char *names[IKE_ALG_KEY_ROOF] = {
		[IKEv1_OAKLEY_ID] = "IKEv1 OAKLEY ID",
		[IKEv1_IPSEC_ID] = "IKEv1 ESP ID",
		[IKEv2_ALG_ID] = "IKEv2 ID",
		[SADB_ALG_ID] = "SADB ID",
	};
	passert(key < elemsof(names));
	return names[key];
}

static const struct ike_alg **next_alg(const struct ike_alg_type *type,
				       const struct ike_alg **last)
{
	struct algorithm_table *table = type->algorithms;
	if (last == NULL) {
		return table->start;
	}
	passert(last >= table->start);
	passert(last < table->end);
	last++;
	if (last >= table->end) {
		return NULL;
	}
	return last;
}

const struct encrypt_desc **next_encrypt_desc(const struct encrypt_desc **last)
{
	return (const struct encrypt_desc**)next_alg(&ike_alg_encrypt,
						     (const struct ike_alg**)last);
}

const struct prf_desc **next_prf_desc(const struct prf_desc **last)
{
	return (const struct prf_desc**)next_alg(&ike_alg_prf,
						 (const struct ike_alg**)last);
}

const struct integ_desc **next_integ_desc(const struct integ_desc **last)
{
	return (const struct integ_desc**)next_alg(&ike_alg_integ,
						   (const struct ike_alg**)last);
}

const struct kem_desc **next_kem_desc(const struct kem_desc **last)
{
	return (const struct kem_desc**)next_alg(&ike_alg_kem,
						(const struct ike_alg**)last);
}

const struct ipcomp_desc **next_ipcomp_desc(const struct ipcomp_desc **last)
{
	return (const struct ipcomp_desc**)next_alg(&ike_alg_ipcomp,
						    (const struct ike_alg**)last);
}

const struct ike_alg *ike_alg_byname(const struct ike_alg_type *type,
				     shunk_t name)
{
	passert(type != NULL);
	for (const struct ike_alg **alg = next_alg(type, NULL);
	     alg != NULL; alg = next_alg(type, alg)) {
		FOR_EACH_IKE_ALG_NAME(*alg, alg_name) {
			if (hunk_caseeq(alg_name, name)) {
				return *alg;
			}
		}
	}
	return NULL;
}

bool ike_alg_enum_matched(const struct ike_alg_type *type, shunk_t name)
{
	passert(type != NULL);
	for (enum ike_alg_key key = IKE_ALG_KEY_FLOOR; key < IKE_ALG_KEY_ROOF; key++) {
		if (type->enum_names[key] != NULL &&
		    enum_byname(type->enum_names[key], name) >= 0) {
			return true;
		}
	}
	return false;
}

bool ike_alg_is_valid(const struct ike_alg *alg)
{
	FOR_EACH_IKE_ALGP(alg->type, algp) {
		if (*algp == alg) {
			return true;
		}
	}
	return false;
}

bool ike_alg_is_ike(const struct ike_alg *alg,
		    const struct logger *logger UNUSED)
{
	return alg->type->desc_is_ike(alg);
}

bool encrypt_desc_is_aead(const struct encrypt_desc *enc_desc)
{
	return enc_desc != NULL && enc_desc->aead_tag_size > 0;
}

/*
 * return ike_alg object by {type, key, id}
 */

static const struct ike_alg *lookup_by_id(const struct ike_alg_type *type,
					  enum ike_alg_key key,
					  int id, name_buf *b,
					  lset_t debug)
{
	struct logger *logger = &global_logger;

	FOR_EACH_IKE_ALGP(type, algp) {
		const struct ike_alg *alg = *algp;
		if (alg->id[key] == id) {
			/* Note: .enum_name[key] can be NULL so don't
			 * bother with .enum_name[] lookup.  */
			ldbgf(debug, logger,
			      "%s %s algorithm %s id: %u found by %s()",
			      ike_alg_key_name(key),
			      type->name, alg->fqn, id, __func__);
			/* must save name */
			b->buf = alg->fqn;
			return alg;
		}
 	}

	/*
	 * Even though the lookup failed, b->buf must still be set.
	 *
	 * When .enum_names[] is NULL the enum_long() call will set it
	 * to the numeric value.
	 */
	bool known = enum_long(type->enum_names[key], id, b);
	ldbgf(debug, logger,
	      "%s %s id: %u, not found by %s(); %s %s",
	      ike_alg_key_name(key), type->name, id, __func__,
	      b->buf,
	      (type->enum_names[key] == NULL ? "no .enum_names[]" :
	       known ? "known by .enum_names[]" :
	       "unknown by .enum_names[]"));
	return NULL;
}

const struct ike_alg *ike_alg_by_sadb_alg_id(const struct ike_alg_type *algorithms,
					     unsigned id)
{
	name_buf b;
	return lookup_by_id(algorithms, SADB_ALG_ID, id, &b, DBG_CRYPT);
}

static const struct ike_alg *ikev1_oakley_lookup(const struct ike_alg_type *algorithms,
						 unsigned id, name_buf *b)
{
	const struct ike_alg *alg = lookup_by_id(algorithms, IKEv1_OAKLEY_ID,
						 id, b, DBG_CRYPT);
	if (alg == NULL || !ike_alg_is_ike(alg, &global_logger)) {
		return NULL;
	}

	return alg;
}

const struct encrypt_desc *ikev1_ike_encrypt_desc(enum ikev1_encr_attribute id, name_buf *b)
{
	return encrypt_desc(ikev1_oakley_lookup(&ike_alg_encrypt, id, b));
}

const struct prf_desc *ikev1_ike_prf_desc(enum ikev1_auth_attribute id, name_buf *b)
{
	return prf_desc(ikev1_oakley_lookup(&ike_alg_prf, id, b));
}

const struct kem_desc *ikev1_ike_kem_desc(enum oakley_group id, name_buf *b)
{
	return kem_desc(ikev1_oakley_lookup(&ike_alg_kem, id, b));
}

const struct ipcomp_desc *ikev1_ike_ipcomp_desc(enum ipsec_ipcomp_algo id, name_buf *b)
{
	return ipcomp_desc(ikev1_oakley_lookup(&ike_alg_ipcomp, id, b));
}

const struct encrypt_desc *ikev1_kernel_encrypt_desc(enum ikev1_esp_transform id, name_buf *b)
{
	return encrypt_desc(lookup_by_id(&ike_alg_encrypt, IKEv1_IPSEC_ID, id, b, DBG_CRYPT));
}

const struct integ_desc *ikev1_kernel_integ_desc(enum ikev1_auth_attribute id, name_buf *b)
{
	return integ_desc(lookup_by_id(&ike_alg_integ, IKEv1_IPSEC_ID, id, b, DBG_CRYPT));
}

const struct ipcomp_desc *ikev1_kernel_ipcomp_desc(enum ipsec_ipcomp_algo id, name_buf *b)
{
	return ipcomp_desc(lookup_by_id(&ike_alg_ipcomp, IKEv1_IPSEC_ID, id, b, DBG_CRYPT));
}

static const struct ike_alg *ikev2_lookup(const struct ike_alg_type *algorithms, int id,
					  struct name_buf *b)
{
	return lookup_by_id(algorithms, IKEv2_ALG_ID, id, b, DBG_CRYPT);
}

const struct encrypt_desc *ikev2_encrypt_desc(enum ikev2_trans_type_encr id, struct name_buf *b)
{
	return encrypt_desc(ikev2_lookup(&ike_alg_encrypt, id, b));
}

const struct hash_desc *ikev2_hash_desc(enum ikev2_hash_algorithm id, struct name_buf *b)
{
	return hash_desc(ikev2_lookup(&ike_alg_hash, id, b));
}

const struct prf_desc *ikev2_prf_desc(enum ikev2_trans_type_prf id, struct name_buf *b)
{
	return prf_desc(ikev2_lookup(&ike_alg_prf, id, b));
}

const struct integ_desc *ikev2_integ_desc(enum ikev2_trans_type_integ id, struct name_buf *b)
{
	return integ_desc(ikev2_lookup(&ike_alg_integ, id, b));
}

const struct kem_desc *ikev2_kem_desc(enum ikev2_trans_type_kem id, struct name_buf *b)
{
	return kem_desc(ikev2_lookup(&ike_alg_kem, id, b));
}

const struct ipcomp_desc *ikev2_ipcomp_desc(enum ipsec_ipcomp_algo id, struct name_buf *b)
{
	return ipcomp_desc(ikev2_lookup(&ike_alg_ipcomp, id, b));
}

const struct encrypt_desc *encrypt_desc_by_sadb_ealg_id(unsigned id)
{
	name_buf b;
	return encrypt_desc(lookup_by_id(&ike_alg_encrypt, SADB_ALG_ID, id, &b, DBG_CRYPT));
}

const struct integ_desc *integ_desc_by_sadb_aalg_id(unsigned id)
{
	name_buf b;
	return integ_desc(lookup_by_id(&ike_alg_integ, SADB_ALG_ID, id, &b, DBG_CRYPT));
}

const struct ipcomp_desc *ipcomp_desc_by_sadb_calg_id(unsigned id)
{
	name_buf b;
	return ipcomp_desc(lookup_by_id(&ike_alg_ipcomp, SADB_ALG_ID, id, &b, DBG_CRYPT));
}

/*
 * Validate and register IKE algorithm objects
 *
 * Order the array so that, when listed, the algorithms are in the
 * order expected by test scripts.
 */

static bool ike_alg_in_table(const struct ike_alg *alg)
{
	const struct ike_alg_type *alg_type = alg->type;
	FOR_EACH_IKE_ALGP(alg_type, algp) {
		if (alg == *algp) {
			return true;
		}
	}
	return false;
}

static void pexpect_ike_alg_base_in_table(struct logger *logger, where_t where,
					  const struct ike_alg *alg,
					  const struct ike_alg *base_alg)
{
	if (!ike_alg_in_table(base_alg)) {
		llog_pexpect(logger, where,
			     PRI_IKE_ALG" base "PRI_IKE_ALG" missing from algorithm table",
			     pri_ike_alg(alg), pri_ike_alg(base_alg));
	}
}

/*
 * Check that name appears in alg->names
 */

static bool ike_alg_has_name(const struct ike_alg *alg, shunk_t name)
{
	FOR_EACH_IKE_ALG_NAME(alg, alg_name) {
		if (hunk_caseeq(alg_name, name)) {
			return true;
		}
	}
	return false;
}

static bool pexpect_ike_alg_has_name(struct logger *logger, where_t where,
				     const struct ike_alg *alg,
				     const char *name,
				     const char *description)
{
	if (name == NULL) {
		llog_pexpect(logger, where, PRI_IKE_ALG" %s name is NULL",
			     pri_ike_alg(alg), description);
		return false;
	} else if (!ike_alg_has_name(alg, shunk1(name))) {
		llog_pexpect(logger, where, PRI_IKE_ALG" missing %s name %s",
			     pri_ike_alg(alg), description, name);
		return false;
	}
	return true;
}

/*
 * Check that BASE_ALG's names also appear in ALG's names.
 *
 * For instance, a PRF implemented using a HASH must have all the
 * shorter HASH names in the PRF name table.
 */
static void pexpect_ike_alg_has_base_names(struct logger *logger, where_t where,
					   const struct ike_alg *alg,
					   const struct ike_alg *base_alg)
{
	FOR_EACH_IKE_ALG_NAME(base_alg, alg_name) {
		if (!ike_alg_has_name(alg, alg_name)) {
			llog_pexpect(logger, where,
				     PRI_IKE_ALG" missing name "PRI_SHUNK" in base "PRI_IKE_ALG,
				     pri_ike_alg(alg), pri_shunk(alg_name),
				     pri_ike_alg(base_alg));
		}
	}
}

/*
 * Simple hash functions.
 */

static const struct hash_desc *hash_descriptors[] = {
#ifdef USE_MD5
	&ike_alg_hash_md5,
#endif
#ifdef USE_SHA1
	&ike_alg_hash_sha1,
#endif
#ifdef USE_SHA2
	&ike_alg_hash_sha2_256,
	&ike_alg_hash_sha2_384,
	&ike_alg_hash_sha2_512,
#endif
	&ike_alg_hash_identity,
};

static void hash_desc_check(const struct ike_alg *alg, struct logger *logger)
{
	const struct hash_desc *hash = hash_desc(alg);
	/* sizes */
	struct crypt_mac mac;
	size_t min_size = (hash == &ike_alg_hash_identity ? 0 : 1);
	pexpect_ike_alg(logger, alg, hash->hash_digest_size >= min_size);
	pexpect_ike_alg(logger, alg, hash->hash_block_size >= min_size);
	pexpect_ike_alg(logger, alg, hash->hash_digest_size <= sizeof(mac.ptr/*an array*/));
	pexpect_ike_alg(logger, alg, hash->hash_block_size <= sizeof(mac.ptr/*an array*/));
	/* ops */
	if (hash->hash_ops != NULL) {
		pexpect_ike_alg(logger, alg, hash->hash_ops->backend != NULL);
		pexpect_ike_alg(logger, alg, hash->hash_ops->check != NULL);
		pexpect_ike_alg(logger, alg, hash->hash_ops->digest_symkey != NULL);
		pexpect_ike_alg(logger, alg, hash->hash_ops->digest_bytes != NULL);
		pexpect_ike_alg(logger, alg, hash->hash_ops->final_bytes != NULL);
		hash->hash_ops->check(hash, logger);
	}
}

static bool hash_desc_is_ike(const struct ike_alg *alg)
{
	const struct hash_desc *hash = hash_desc(alg);
	return hash->hash_ops != NULL;
}

static struct algorithm_table hash_algorithms = ALGORITHM_TABLE(hash_descriptors);

const struct ike_alg_type ike_alg_hash = {
	.name = "hash",
	.story = "Hashing Algorithm",
	.algorithms = &hash_algorithms,
	.enum_names = {
		[IKEv1_OAKLEY_ID] = &oakley_hash_names,
		[IKEv2_ALG_ID] = &ikev2_hash_algorithm_names,
	},
	.desc_check = hash_desc_check,
	.desc_is_ike = hash_desc_is_ike,
};

/*
 * PRF function.
 *
 * Sometimes, but not always, built on a HASH function using the HMAC
 * construct.
 */

static const struct prf_desc *prf_descriptors[] = {
#ifdef USE_MD5
	&ike_alg_prf_hmac_md5,
#endif
#ifdef USE_SHA1
	&ike_alg_prf_sha1,
#endif
#ifdef USE_SHA2
	&ike_alg_prf_sha2_256,
	&ike_alg_prf_sha2_384,
	&ike_alg_prf_sha2_512,
#endif
#ifdef USE_PRF_AES_XCBC
	&ike_alg_prf_aes_xcbc,
#endif
};

static void prf_desc_check(const struct ike_alg *alg, struct logger *logger)
{
	const struct prf_desc *prf = prf_desc(alg);
	/* sizes */
	struct crypt_mac mac;
	pexpect_ike_alg(logger, alg, prf->prf_key_size > 0);
	pexpect_ike_alg(logger, alg, prf->prf_output_size > 0);
	pexpect_ike_alg(logger, alg, prf->prf_key_size <= sizeof(mac.ptr/*array*/));
	pexpect_ike_alg(logger, alg, prf->prf_output_size <= sizeof(mac.ptr/*array*/));
	pexpect_ike_alg(logger, alg, DEFAULT_NONCE_SIZE >= prf->prf_key_size / 2); /* see 2.10 Nonces */
	/* names */
	pexpect_ike_alg_has_name(logger, HERE, alg, prf->prf_ike_audit_name, ".prf_ike_audit_name");
	/* all or none */
	pexpect_ike_alg(logger, alg, (prf->prf_mac_ops != NULL) == (prf->prf_ikev1_ops != NULL));
	pexpect_ike_alg(logger, alg, (prf->prf_mac_ops != NULL) == (prf->prf_ikev2_ops != NULL));
	/* Using NSS implies mechanism */
	pexpect_ike_alg(logger, alg,
			(prf->prf_mac_ops == &ike_alg_prf_mac_nss_ops) /*implies*/<= (prf->nss.mechanism > 0));
	/* ops */
	if (prf->prf_mac_ops != NULL) {
		pexpect_ike_alg(logger, alg, prf->prf_mac_ops->backend != NULL);
		pexpect_ike_alg(logger, alg, prf->prf_mac_ops->check != NULL);
		pexpect_ike_alg(logger, alg, prf->prf_mac_ops->init_symkey != NULL);
		pexpect_ike_alg(logger, alg, prf->prf_mac_ops->init_bytes != NULL);
		pexpect_ike_alg(logger, alg, prf->prf_mac_ops->digest_symkey != NULL);
		pexpect_ike_alg(logger, alg, prf->prf_mac_ops->digest_bytes != NULL);
		pexpect_ike_alg(logger, alg, prf->prf_mac_ops->final_symkey != NULL);
		pexpect_ike_alg(logger, alg, prf->prf_mac_ops->final_bytes != NULL);
		/*
		 * IKEv1 IKE algorithms must have a hasher - used for
		 * things like computing IV.
		 */
		pexpect_ike_alg(logger, alg, prf->ikev1_oakley_id < 0 ||
				     prf->hasher != NULL);
		prf->prf_mac_ops->check(prf, logger);
	}

	if (prf->prf_ikev1_ops != NULL) {
		pexpect_ike_alg(logger, alg, prf->prf_ikev1_ops->backend != NULL);
		pexpect_ike_alg(logger, alg, prf->prf_ikev1_ops->signature_skeyid != NULL);
		pexpect_ike_alg(logger, alg, prf->prf_ikev1_ops->pre_shared_key_skeyid != NULL);
		pexpect_ike_alg(logger, alg, prf->prf_ikev1_ops->skeyid_d != NULL);
		pexpect_ike_alg(logger, alg, prf->prf_ikev1_ops->skeyid_a != NULL);
		pexpect_ike_alg(logger, alg, prf->prf_ikev1_ops->skeyid_e != NULL);
		pexpect_ike_alg(logger, alg, prf->prf_ikev1_ops->appendix_b_keymat_e != NULL);
	}

	if (prf->prf_ikev2_ops != NULL) {
		pexpect_ike_alg(logger, alg, prf->prf_ikev2_ops->backend != NULL);
		pexpect_ike_alg(logger, alg, prf->prf_ikev2_ops->prfplus != NULL);
		pexpect_ike_alg(logger, alg, prf->prf_ikev2_ops->ike_sa_skeyseed != NULL);
		pexpect_ike_alg(logger, alg, prf->prf_ikev2_ops->ike_sa_rekey_skeyseed != NULL);
		pexpect_ike_alg(logger, alg, prf->prf_ikev2_ops->ike_sa_resume_skeyseed != NULL);
		pexpect_ike_alg(logger, alg, prf->prf_ikev2_ops->ike_sa_keymat != NULL);
		pexpect_ike_alg(logger, alg, prf->prf_ikev2_ops->child_sa_keymat != NULL);
		pexpect_ike_alg(logger, alg, prf->prf_ikev2_ops->psk_auth != NULL);
		pexpect_ike_alg(logger, alg, prf->prf_ikev2_ops->psk_resume != NULL);
	}

	if (prf->hasher != NULL) {
		/*
		 * Check for dangling pointer.
		 */
		pexpect_ike_alg_base_in_table(logger, HERE, &prf->common, &prf->hasher->common);
		pexpect_ike_alg(logger, alg, prf->prf_output_size == prf->hasher->hash_digest_size);
		pexpect_ike_alg_has_base_names(logger, HERE, &prf->common, &prf->hasher->common);
	}
}

static bool prf_desc_is_ike(const struct ike_alg *alg)
{
	const struct prf_desc *prf = prf_desc(alg);
	return prf->prf_mac_ops != NULL;
}

static struct algorithm_table prf_algorithms = ALGORITHM_TABLE(prf_descriptors);

const struct ike_alg_type ike_alg_prf = {
	.name = "PRF",
	.story = "Pseudorandom Function (KDF)",
	.algorithms = &prf_algorithms,
	.enum_names = {
		[IKEv1_OAKLEY_ID] = &oakley_hash_names,
		[IKEv1_IPSEC_ID] = NULL, /* ESP/AH uses IKE PRF */
		[IKEv2_ALG_ID] = &ikev2_trans_type_prf_names,
	},
	.desc_check = prf_desc_check,
	.desc_is_ike = prf_desc_is_ike,
};

/*
 * Integrity.
 */

static const struct integ_desc *integ_descriptors[] = {
#ifdef USE_MD5
	&ike_alg_integ_hmac_md5_96,
#endif
#ifdef USE_SHA1
	&ike_alg_integ_sha1,
#endif
#ifdef USE_SHA2
	&ike_alg_integ_sha2_512,
	&ike_alg_integ_sha2_384,
	&ike_alg_integ_sha2_256,
	&ike_alg_integ_hmac_sha2_256_truncbug,
#endif
#ifdef USE_AES
	&ike_alg_integ_aes_xcbc,
	&ike_alg_integ_aes_cmac,
#endif
	&ike_alg_integ_none,
};

static void integ_desc_check(const struct ike_alg *alg, struct logger *logger)
{
	const struct integ_desc *integ = integ_desc(alg);
	/* sizes */
	struct crypt_mac mac;
	pexpect_ike_alg(logger, alg, integ->integ_keymat_size > 0);
	pexpect_ike_alg(logger, alg, integ->integ_output_size > 0);
	pexpect_ike_alg(logger, alg, integ->integ_keymat_size <= sizeof(mac.ptr/*an array*/));
	pexpect_ike_alg(logger, alg, integ->integ_output_size <= sizeof(mac.ptr/*an array*/));
	/*names*/
	pexpect_ike_alg_has_name(logger, HERE, alg, integ->integ_tcpdump_name, ".integ_tcpdump_name");
	pexpect_ike_alg_has_name(logger, HERE, alg, integ->integ_ike_audit_name, ".integ_ike_audit_name");
	pexpect_ike_alg_has_name(logger, HERE, alg, integ->integ_kernel_audit_name, ".integ_kernel_audit_name");
	if (integ->ikev1_ipsec_id >= 0) {
		name_buf esb;
		pexpect_ike_alg_streq(logger, alg, integ->integ_kernel_audit_name,
				      str_enum_short(&auth_alg_names,
						     integ->ikev1_ipsec_id,
						     &esb));
	}
	if (integ->prf != NULL) {
		pexpect_ike_alg(logger, alg, integ->integ_keymat_size == integ->prf->prf_key_size);
		pexpect_ike_alg(logger, alg, integ->integ_output_size <= integ->prf->prf_output_size);
		pexpect_ike_alg(logger, alg, prf_desc_is_ike(&integ->prf->common));
		pexpect_ike_alg_has_base_names(logger, HERE, &integ->common, &integ->prf->common);
	}
}

static bool integ_desc_is_ike(const struct ike_alg *alg)
{
	const struct integ_desc *integ = integ_desc(alg);
	return integ->prf != NULL || integ == &ike_alg_integ_none;
}

static struct algorithm_table integ_algorithms = ALGORITHM_TABLE(integ_descriptors);

const struct ike_alg_type ike_alg_integ = {
	.name = "integrity",
	.story = "Integrity Algorithm",
	.algorithms = &integ_algorithms,
	.enum_names = {
		[IKEv1_OAKLEY_ID] = &oakley_hash_names,
		[IKEv1_IPSEC_ID] = &auth_alg_names,
		[IKEv2_ALG_ID] = &ikev2_trans_type_integ_names,
	},
	.desc_check = integ_desc_check,
	.desc_is_ike = integ_desc_is_ike,
};

/*
 * Encryption
 */

static const struct encrypt_desc *encrypt_descriptors[] = {
#ifdef USE_AES
	&ike_alg_encrypt_aes_ccm_16,
	&ike_alg_encrypt_aes_ccm_12,
	&ike_alg_encrypt_aes_ccm_8,
	/* see note above */
#endif
#ifdef USE_3DES
	&ike_alg_encrypt_3des_cbc,
#endif
#ifdef USE_CAMELLIA
	&ike_alg_encrypt_camellia_ctr,
	&ike_alg_encrypt_camellia_cbc,
#endif
#ifdef USE_AES
	&ike_alg_encrypt_aes_gcm_16,
	&ike_alg_encrypt_aes_gcm_12,
	&ike_alg_encrypt_aes_gcm_8,
	&ike_alg_encrypt_aes_ctr,
	&ike_alg_encrypt_aes_cbc,
#endif
	&ike_alg_encrypt_null_integ_aes_gmac,
	&ike_alg_encrypt_null,
#ifdef USE_CHACHA
	&ike_alg_encrypt_chacha20_poly1305,
#endif
};

bool encrypt_has_key_bit_length(const struct encrypt_desc *encrypt,
				unsigned keylen)
{
	/*
	 * This loop is written so that KEYLEN is always compared
	 * against the first entry in .key_bit_lengths - even when
	 * that entry is zero.  This happens when encryption is 'none'
	 * and the KEYLEN really is zero.
	 */
	const unsigned *p = encrypt->key_bit_lengths;
	do {
		if (*p == keylen) {
			return true;
		}
		p++;
	} while (*p != 0);
	return false;
}

unsigned encrypt_max_key_bit_length(const struct encrypt_desc *encrypt)
{
	/* by definition: largest is first */
	return encrypt->key_bit_lengths[0];
}

unsigned encrypt_min_key_bit_length(const struct encrypt_desc *encrypt)
{
	/* by definition: smallest is last */
	unsigned smallest = 0;
	for (const unsigned *keyp = encrypt->key_bit_lengths; *keyp; keyp++) {
		smallest = *keyp;
	}
	return smallest;
}

static void encrypt_desc_check(const struct ike_alg *alg, struct logger *logger)
{
	const struct encrypt_desc *encrypt = encrypt_desc(alg);
	/*
	 * AES_GCM is a screwup.  AES_GCM_16 has the name "aes_gcm"
	 * but when logging tcp or audit, that is assigned to
	 * AES_GCM_8.
	 */
	if (encrypt == &ike_alg_encrypt_aes_gcm_8) {
		pexpect_ike_alg_streq(logger, alg, encrypt->encrypt_tcpdump_name, "aes_gcm");
		pexpect_ike_alg_streq(logger, alg, encrypt->encrypt_ike_audit_name, "aes_gcm");
	} else {
		pexpect_ike_alg_has_name(logger, HERE, alg, encrypt->encrypt_tcpdump_name, ".encrypt_tcpdump_name");
		pexpect_ike_alg_has_name(logger, HERE, alg, encrypt->encrypt_ike_audit_name, ".encrypt_ike_audit_name");
	}
	pexpect_ike_alg_has_name(logger, HERE, alg, encrypt->encrypt_kernel_audit_name, ".encrypt_kernel_audit_name");

	/*
	 * Only implemented one way, if at all.
	 */
	if (encrypt->encrypt_ops != NULL) {
		pexpect_ike_alg(logger, alg, encrypt->encrypt_ops->backend != NULL);
		pexpect_ike_alg(logger, alg, encrypt->encrypt_ops->cipher_check != NULL);
		pexpect_ike_alg(logger, alg, ((encrypt->encrypt_ops->cipher_op_context_create != NULL) ==
					      (encrypt->encrypt_ops->cipher_op_context_destroy != NULL)));
		pexpect_ike_alg(logger, alg, ((encrypt->encrypt_ops->cipher_op_normal == NULL) !=
					      (encrypt->encrypt_ops->cipher_op_aead == NULL)));
	}

	/*
	 * AEAD implementation implies a valid AEAD tag size.
	 * Converse for non-AEAD implementation.
	 */
	if (encrypt->encrypt_ops != NULL) {
		pexpect_ike_alg(logger, alg, (encrypt->encrypt_ops->cipher_op_aead == NULL ||
					      encrypt->aead_tag_size > 0));
		pexpect_ike_alg(logger, alg, (encrypt->encrypt_ops->cipher_op_normal == NULL ||
					      encrypt->aead_tag_size == 0));
	}

	/*
	 * Key length checks.
	 *
	 * Either the algorithm is 'null', or there is a non-zero
	 * KEYDEFLEN.
	 */
	if (encrypt == &ike_alg_encrypt_null) {
		pexpect_ike_alg(logger, alg, encrypt->keydeflen == 0);
		pexpect_ike_alg(logger, alg, encrypt->ikev1_ipsec_id == IKEv1_ESP_NULL);
		pexpect_ike_alg(logger, alg, encrypt->ikev2_alg_id == IKEv2_ENCR_NULL);
		pexpect_ike_alg(logger, alg, encrypt->enc_blocksize == 1);
		pexpect_ike_alg(logger, alg, encrypt->wire_iv_size == 0);
		pexpect_ike_alg(logger, alg, encrypt->key_bit_lengths[0] == 0);
	} else {
		pexpect_ike_alg(logger, alg, encrypt->keydeflen > 0);
		pexpect_ike_alg(logger, alg, encrypt->key_bit_lengths[0] > 0);
	}
	/* Key lengths are in descending order and 0 terminated. */
	{
		const unsigned *keylenp = encrypt->key_bit_lengths;
		unsigned last_key_len = *keylenp;
		keylenp++;
		pexpect_ike_alg(logger, alg, encrypt->key_bit_lengths[elemsof(encrypt->key_bit_lengths) - 1] == 0);
		for (; *keylenp != 0; keylenp++) {
			pexpect_ike_alg(logger, alg, last_key_len > *keylenp);
		}
	}
	/* * The default (even when 0) is always valid. */
	pexpect_ike_alg(logger, alg, encrypt_has_key_bit_length(encrypt, encrypt->keydeflen));
}

static bool encrypt_desc_is_ike(const struct ike_alg *alg)
{
	const struct encrypt_desc *encrypt = encrypt_desc(alg);
	if (encrypt->encrypt_ops == NULL) {
		return false;
	}
	if (encrypt->encrypt_ops == &ike_alg_encrypt_null_ops) {
		return impair.allow_null_none;
	}
	return true;
}

static struct algorithm_table encrypt_algorithms = ALGORITHM_TABLE(encrypt_descriptors);

const struct ike_alg_type ike_alg_encrypt = {
	.name = "encryption",
	.story = "Encryption Algorithm (cipher)",
	.algorithms = &encrypt_algorithms,
	.enum_names = {
		[IKEv1_OAKLEY_ID] = &oakley_enc_names,
		[IKEv1_IPSEC_ID] = &esp_transformid_names,
		[IKEv2_ALG_ID] = &ikev2_trans_type_encr_names,
	},
	.desc_check = encrypt_desc_check,
	.desc_is_ike = encrypt_desc_is_ike,
};

/*
 * DH group
 */

static const struct kem_desc *kem_descriptors[] = {
	&ike_alg_kem_none,
#ifdef USE_DH2
	&ike_alg_kem_modp1024,
#endif
	&ike_alg_kem_modp1536,
	&ike_alg_kem_modp2048,
	&ike_alg_kem_modp3072,
	&ike_alg_kem_modp4096,
	&ike_alg_kem_modp6144,
	&ike_alg_kem_modp8192,
	&ike_alg_kem_secp256r1,
	&ike_alg_kem_secp384r1,
	&ike_alg_kem_secp521r1,
#ifdef USE_DH22
	&ike_alg_kem_dh22,
#endif
#ifdef USE_DH23
	&ike_alg_kem_dh23,
#endif
#ifdef USE_DH24
	&ike_alg_kem_dh24,
#endif
#ifdef USE_DH31
	&ike_alg_kem_curve25519,
#endif

#ifdef USE_ML_KEM_512
	&ike_alg_kem_ml_kem_512,
#endif
#ifdef USE_ML_KEM_768
	&ike_alg_kem_ml_kem_768,
#endif
#ifdef USE_ML_KEM_1024
	&ike_alg_kem_ml_kem_1024,
#endif
};

static void kem_desc_check(const struct ike_alg *alg, struct logger *logger)
{
	const struct kem_desc *kem = kem_desc(alg);
	/* IKEv1 always supports this */
	pexpect_ike_alg(logger, alg, kem->ikev1_oakley_id == kem->ikev1_ipsec_id);
	/* always implemented */
	pexpect_ike_alg(logger, alg, kem->kem_ops != NULL);
	if (kem->kem_ops != NULL) {
		pexpect_ike_alg(logger, alg, kem->kem_ops->backend != NULL);
		pexpect_ike_alg(logger, alg, kem->kem_ops->check != NULL);
		pexpect_ike_alg(logger, alg, kem->kem_ops->calc_local_secret != NULL);
		/* all-in or none-in! */
		pexpect_ike_alg(logger, alg, ((kem->kem_ops->calc_shared_secret == NULL) ==
					      ((kem->kem_ops->kem_encapsulate != NULL) &&
					       (kem->kem_ops->kem_decapsulate != NULL))));
		pexpect_ike_alg(logger, alg, ((kem->kem_ops->kem_encapsulate != NULL) ==
					      (kem->kem_ops->kem_decapsulate != NULL)));
		/* more? */
		kem->kem_ops->check(kem, logger);
	}
}

static bool kem_desc_is_ike(const struct ike_alg *alg)
{
	const struct kem_desc *kem = kem_desc(alg);
	return kem->kem_ops != NULL;
}

static struct algorithm_table kem_algorithms = ALGORITHM_TABLE(kem_descriptors);

const struct ike_alg_type ike_alg_kem = {
	.name = "KEM",
	.story = "Key Exchange Method (DH)",
	.algorithms = &kem_algorithms,
	.enum_names = {
		[IKEv1_OAKLEY_ID] = &oakley_group_names,
		[IKEv1_IPSEC_ID] = &oakley_group_names,
		[IKEv2_ALG_ID] = &oakley_group_names,
	},
	.desc_check = kem_desc_check,
	.desc_is_ike = kem_desc_is_ike,
};

/*
 * IPCOMP
 */

static const struct ipcomp_desc *ipcomp_descriptors[] = {
	&ike_alg_ipcomp_deflate,
	&ike_alg_ipcomp_lzs,
	&ike_alg_ipcomp_lzjh,
};

static void ipcomp_desc_check(const struct ike_alg *alg, struct logger *logger)
{
	const struct ipcomp_desc *ipcomp = ipcomp_desc(alg);
	pexpect_ike_alg(logger, alg, ipcomp != NULL);
}

static bool ipcomp_desc_is_ike(const struct ike_alg *alg)
{
	const struct ipcomp_desc *ipcomp = ipcomp_desc(alg);
	return ipcomp->ipcomp_ops != NULL;
}

static struct algorithm_table ipcomp_algorithms = ALGORITHM_TABLE(ipcomp_descriptors);

const struct ike_alg_type ike_alg_ipcomp = {
	.name = "IPCOMP",
	.story = "IP Compression",
	.algorithms = &ipcomp_algorithms,
	.enum_names = {
		[IKEv1_OAKLEY_ID] = &ipsec_ipcomp_algo_names,
		[IKEv1_IPSEC_ID] = &ipsec_ipcomp_algo_names,
		[IKEv2_ALG_ID] = &ipsec_ipcomp_algo_names,
	},
	.desc_check = ipcomp_desc_check,
	.desc_is_ike = ipcomp_desc_is_ike,
};

/*
 * Check mapping between enums and names.
 */
static void check_enum_name(const char *what,
			    const struct ike_alg *alg,
			    int id, enum_names *enum_names,
			    struct logger *logger)
{
	if (id >= 0) {
		if (enum_names == NULL) {
			llog_passert(logger, HERE, "%s %s %s has no enum names",
				     alg->type->name,
				     alg->fqn, what);
		}
		name_buf enum_name;
		bool ok = enum_short(enum_names, id, &enum_name);
		ldbgf(DBG_CRYPT, logger, "%s id: %d enum name: %s",
		      what, id, enum_name.buf);
		pexpect_ike_alg_has_name(logger, HERE, alg,
					 (ok ? enum_name.buf : NULL),
					 "enum table name");
	} else {
		ldbgf(DBG_CRYPT, logger, "%s id: %d enum name: N/A", what, id);
	}
}

/*
 * Verify an algorithm table, pruning anything that isn't supported.
 */

static void check_algorithm_table(const struct ike_alg_type *type,
				  struct logger *logger)
{
	/*
	 * Sanity check the raw algorithm table.
	 *
	 * Anything going wrong here results in an abort.
	 */
	passert(type->name != NULL);
	passert(type->story != NULL);

	ldbgf(DBG_CRYPT, logger, "%s algorithm assertion checks", type->name);
	FOR_EACH_IKE_ALGP(type, algp) {
		const struct ike_alg *alg = *algp;

		ldbgf(DBG_CRYPT, logger,
		      "%s algorithm %s, IKEv1 OAKLEY: %d, IKEv1 ESP_INFO: %d, IKEv2: %d SADB: %d",
		      type->name, alg->fqn,
		      alg->id[IKEv1_OAKLEY_ID],
		      alg->id[IKEv1_IPSEC_ID],
		      alg->id[IKEv2_ALG_ID],
		      alg->id[SADB_ALG_ID]);

		/*
		 * Check the FQN first; and require upper case.  If
		 * this one fails abort as everything else relies on a
		 * usable .fqn.
		 */
		if (!pexpect_ike_alg_has_name(logger, HERE, alg, alg->fqn, ".fqn")) {
			continue;
		}
		pexpect_ike_alg(logger, alg, (strlen(alg->fqn) ==
				      strspn(alg->fqn, "ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789")));

		/*
		 * Validate the other .common names.
		 *
		 * Requiring this is easier than trying to ensure that
		 * changes to NAME don't break NAMES.
		 */
		pexpect_ike_alg_has_name(logger, HERE, alg, alg->fqn, ".name");

		/*
		 * Check the IDs have all been set (i.e, non-zero).
		 *
		 * Don't even try to check 'none' algorithms.
		 */
		if (alg != &ike_alg_integ_none.common &&
		    alg != &ike_alg_kem_none.common) {
			for (enum ike_alg_key key = IKE_ALG_KEY_FLOOR;
			     key < IKE_ALG_KEY_ROOF; key++) {
				int id = alg->id[key];
				switch (key) {
				case SADB_ALG_ID:
					pexpect_ike_alg_key(logger, alg, key, id >= 0);
					break;
				default:
					pexpect_ike_alg_key(logger, alg, key, id == -1 || id > 0);
					break;
				}
			}
		}

		/*
		 * Validate an IKE_ALG's IKEv1 and IKEv2 enum_name
		 * entries.
		 *
		 * struct ike_alg_encrypt_aes_ccm_8 et.al. do not
		 * define the IKEv1 field "common.id[IKEv1_OAKLEY_ID]"
		 * so need to handle that.
		 */
		bool at_least_one_valid_id = false;
		for (enum ike_alg_key key = IKE_ALG_KEY_FLOOR;
		     key < IKE_ALG_KEY_ROOF; key++) {
			int id = alg->id[key];
			switch (key) {
			case SADB_ALG_ID:
				/* SADB needs sparse names */
				continue;
			default:
				if (id < 0) continue;
				break;
			}
			at_least_one_valid_id = true;
			check_enum_name(ike_alg_key_name(key),
					alg, id,
					type->enum_names[key],
					logger);
		}
		pexpect_ike_alg(logger, alg, at_least_one_valid_id);

		/*
		 * Algorithm can't appear twice.
		 *
		 * Search the previously validated algorithms using a
		 * fudged up ALL array that only contain the
		 * previously verified algorithms.
		 */
		struct algorithm_table table = *type->algorithms;
		table.end = algp;
		struct ike_alg_type scratch = *type;
		scratch.algorithms = &table;
		for (enum ike_alg_key key = IKE_ALG_KEY_FLOOR;
		     key < IKE_ALG_KEY_ROOF; key++) {
			int id = alg->id[key];
			switch (key) {
			case SADB_ALG_ID:
				if (id <= 0) continue;
				break;
			default:
				if (id < 0) continue;
				break;
			}
			name_buf b;
			pexpect_ike_alg_key(logger, alg, key,
					    lookup_by_id(&scratch, key, id, &b, LEMPTY) == NULL);
		}

		/*
		 * Extra algorithm specific checks.
		 *
		 * Don't even try to check 'none' algorithms.
		 */
		if (alg != &ike_alg_integ_none.common &&
		    alg != &ike_alg_kem_none.common) {
			pexpect_ike_alg(logger, alg, type->desc_check != NULL);
			type->desc_check(alg, logger);
		}
	}
}

static const char *backend_name(const struct ike_alg *alg)
{
	if (alg->type == &ike_alg_hash) {
		const struct hash_desc *hash = hash_desc(alg);
		if (hash->hash_ops != NULL) {
			return hash->hash_ops->backend;
		}
	} else if (alg->type == &ike_alg_prf) {
		const struct prf_desc *prf = prf_desc(alg);
		if (prf->prf_mac_ops != NULL) {
			return prf->prf_mac_ops->backend;
		}
	} else if (alg->type == &ike_alg_integ) {
		const struct integ_desc *integ = integ_desc(alg);
		if (integ->prf != NULL &&
		    integ->prf->prf_mac_ops != NULL) {
			return integ->prf->prf_mac_ops->backend;
		}
	} else if (alg->type == &ike_alg_encrypt) {
		const struct encrypt_desc *encrypt = encrypt_desc(alg);
		if (encrypt->encrypt_ops != NULL) {
			return encrypt->encrypt_ops->backend;
		}
	} else if (alg->type == &ike_alg_kem) {
		const struct kem_desc *kem = kem_desc(alg);
		if (kem->kem_ops != NULL) {
			return kem->kem_ops->backend;
		}
	} else if (alg->type == &ike_alg_ipcomp) {
		const struct ipcomp_desc *ipcomp = ipcomp_desc(alg);
		if (ipcomp->ipcomp_ops != NULL) {
			return ipcomp->ipcomp_ops->backend;
		}
	} else {
		bad_case(0);
	}
	return NULL;
}

static void jam_ike_alg_details(struct jambuf *buf, size_t name_width,
				size_t backend_width, const struct ike_alg *alg)
{
	/*
	 * NAME [{256,192,*128}]:
	 */
	name_width -= jam_string(buf, alg->fqn);
	/*
	 * Concatenate [key,...] or {key,...} with default
	 * marked with '*'.
	 */
	if (alg->type == &ike_alg_encrypt) {
#define MAX_KEYSIZES (int)strlen("{256,192,*128}")
		name_width -= MAX_KEYSIZES;
		jam(buf, "%*s", (int) name_width, "");
		const struct encrypt_desc *encr = encrypt_desc(alg);
		int s = 0;
		s += jam_string(buf, encr->keylen_omitted ? "[" : "{");
		const char *sep = "";
		for (const unsigned *keyp = encr->key_bit_lengths; *keyp; keyp++) {
			s += jam_string(buf, sep);
			if (*keyp == encr->keydeflen) {
				s += jam(buf, "*");
			}
			s += jam(buf, "%d", *keyp);
			sep = ",";
		}
		s += jam(buf, encr->keylen_omitted ? "]" : "}");
		jam(buf, "%*s", MAX_KEYSIZES - s, "");
	} else {
		jam(buf, "%*s", (int) name_width, "");
	}
	jam_string(buf, " ");

	/*
	 * IKEv1: IKE ESP AH  IKEv2: IKE ESP AH
	 */
	bool v1_ike;
	bool v2_ike;
	if (ike_alg_is_ike(alg, &global_logger)) {
		v1_ike = alg->id[IKEv1_OAKLEY_ID] >= 0;
		v2_ike = alg->id[IKEv2_ALG_ID] >= 0;
	} else {
		v1_ike = false;
		v2_ike = false;
	}
	bool v1_esp;
	bool v2_esp;
	bool v1_ah;
	bool v2_ah;
	if (alg->type == &ike_alg_hash ||
	    alg->type == &ike_alg_prf) {
		v1_esp = v2_esp = v1_ah = v2_ah = false;
	} else if (alg->type == &ike_alg_encrypt) {
		v1_esp = alg->id[IKEv1_IPSEC_ID] >= 0;
		v2_esp = alg->id[IKEv2_ALG_ID] >= 0;
		v1_ah = false;
		v2_ah = false;
	} else if (alg->type == &ike_alg_integ) {
		v1_esp = alg->id[IKEv1_IPSEC_ID] >= 0;
		v2_esp = alg->id[IKEv2_ALG_ID] >= 0;
		/* NULL not allowed for AH */
		v1_ah = v2_ah = integ_desc(alg)->integ_ikev1_ah_transform > 0;
	} else if (alg->type == &ike_alg_kem) {
		v1_esp = v1_ah = alg->id[IKEv1_IPSEC_ID] >= 0;
		v2_esp = v2_ah = alg->id[IKEv2_ALG_ID] >= 0;
	} else if (alg->type == &ike_alg_ipcomp) {
		v1_esp = v1_ah = alg->id[IKEv1_IPSEC_ID] >= 0;
		v2_esp = v2_ah = alg->id[IKEv2_ALG_ID] >= 0;
	} else {
		bad_case(0);
	}
	jam_string(buf, "IKEv1:");
	jam_string(buf, (v1_ike
			 ? " IKE"
			 : "    "));
	jam_string(buf, (v1_esp
			 ? " ESP"
			 : "    "));
	jam_string(buf, (v1_ah
			 ? " AH"
			 : "   "));
	jam_string(buf, "  IKEv2:");
	jam_string(buf, (v2_ike
			 ? " IKE"
			 : "    "));
	jam_string(buf, (v2_esp
			 ? " ESP"
			 : "    "));
	jam_string(buf, (v2_ah
			 ? " AH"
			 : "   "));
	jam_string(buf, (alg->fips.approved
			 ? "  FIPS"
			 : "      "));

	/*
	 * Concatenate:   XXX backend
	 */
	if (backend_width > 0) {
		const char *b = backend_name(alg);
		jam(buf, " %-*s", (int) backend_width, b != NULL ? b : "");
	}

	/*
	 * Concatenate:   alias ...
	 */
	{
		const char *sep = " ";
		FOR_EACH_IKE_ALG_NAME(alg, alg_name) {
			/* filter out NAME */
			if (!hunk_strcaseeq(alg_name, alg->fqn)) {
				jam(buf, "%s"PRI_SHUNK, sep, pri_shunk(alg_name));
				sep = ", ";
			}
		}
	}
}

static void log_ike_algs(struct logger *logger)
{
	/*
	 * Find a suitable column width by looking for the longest
	 * name.
	 */
	size_t name_width = 0;
	size_t backend_width = 0;
	FOR_EACH_IKE_ALG_TYPEP(typep) {
		const struct ike_alg_type *type = *typep;
		FOR_EACH_IKE_ALGP(type, algp) {
			size_t s = strlen((*algp)->fqn);
			if ((*algp)->type == &ike_alg_encrypt) {
				s += MAX_KEYSIZES + 1;
			}
			name_width = max(s, name_width);
			const char *b = backend_name(*algp);
			if (b != NULL) {
				size_t s = strlen(b);
				backend_width = max(s, backend_width);
			}
		}
	}

	/*
	 * When in FIPS mode sprinkle "FIPS" through out the output.
	 * This way grepping for FIPS shows up more information.
	 */
	FOR_EACH_IKE_ALG_TYPEP(typep) {
		const struct ike_alg_type *type = *typep;
		llog(RC_LOG, logger, "%s%s:",
		     (is_fips_mode() ? "FIPS " : ""),
		     type->story);
		FOR_EACH_IKE_ALGP(type, algp) {
			LLOG_JAMBUF(RC_LOG, logger, buf) {
				jam_string(buf, "  ");
				jam_ike_alg_details(buf, name_width, backend_width, *algp);
			}
		}
	}
}

/*
 * Strip out any non-FIPS algorithms.
 *
 * This prevents checks being performed on algorithms that are.
 */
static void strip_nonfips(const struct ike_alg_type *type, struct logger *logger)
{
	const struct ike_alg **end = type->algorithms->start;
	FOR_EACH_IKE_ALGP(type, algp) {
		const struct ike_alg *alg = *algp;
		/*
		 * Check FIPS before trying to run any tests.
		 */
		if (!alg->fips.approved) {
			llog(RC_LOG, logger,
			     "%s %s disabled; not FIPS compliant",
			     type->story, alg->fqn);
			continue;
		}
		*end++ = alg;
	}
	type->algorithms->end = end;
}

void init_ike_alg(struct logger *logger)
{
	bool fips = is_fips_mode();

	/*
	 * If needed, completely strip out non-FIPS algorithms.
	 * Prevents inconsistency where a non-FIPS algorithm is
	 * referring to something that's been disabled.
	 */
	if (fips) {
		FOR_EACH_IKE_ALG_TYPEP(typep) {
			strip_nonfips(*typep, logger);
		}
	}

	/*
	 * Now verify what is left.
	 */
	FOR_EACH_IKE_ALG_TYPEP(typep) {
		check_algorithm_table(*typep, logger);
	}

	/*
	 * Log the final lists as a pretty table.
	 */
	log_ike_algs(logger);
}
