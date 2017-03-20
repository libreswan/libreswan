/*
 * IKE modular algorithm handling interface, for libreswan
 *
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * Copyright (C) 2003 Mathieu Lafon <mlafon@arkoon.net>
 * Copyright (C) 2005-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2011-2012 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013-2014 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013-2014 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2016-2017 Andrew Cagney <cagney@gnu.org>
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "lswfips.h"
#include "lswlog.h"
#include "lswalloc.h"
#include "ike_alg.h"
#include "alg_info.h"
#include "ike_alg_hmac_prf_ops.h"
#include "ike_alg_nss_prf_ops.h"
#include "ike_alg_nss_hash_ops.h"
#include "ike_alg_dh.h"

#include "ike_alg_null.h"
#ifdef USE_TWOFISH
#include "ike_alg_twofish.h"
#endif
#ifdef USE_SERPENT
#include "ike_alg_serpent.h"
#endif
#ifdef USE_AES
#include "ike_alg_aes.h"
#endif
#ifdef USE_CAMELLIA
#include "ike_alg_camellia.h"
#endif
#ifdef USE_3DES
#include "ike_alg_3des.h"
#endif
#ifdef USE_SHA2
#include "ike_alg_sha2.h"
#endif
#ifdef USE_SHA1
#include "ike_alg_sha1.h"
#endif
#ifdef USE_MD5
#include "ike_alg_md5.h"
#endif
#ifdef USE_CAST
#include "ike_alg_cast.h"
#endif
#ifdef USE_RIPEMD
#include "ike_alg_ripemd.h"
#endif

/*==========================================================
*
*       IKE algo list handling
*
*       - registration
*       - lookup
*=========================================================*/

#define FOR_EACH_IKE_ALGP(TABLE,A)				\
	for (const struct ike_alg **(A) = (TABLE)->start;	\
	     (A) < (TABLE)->end;				\
	     (A)++)

#define FOR_EACH_IKE_ALG_NAMEP(ALG, NAMEP)				\
	for (const char *const *(NAMEP) = (ALG)->names;			\
	     (NAMEP) < (ALG)->names + elemsof((ALG)->names) && *(NAMEP); \
	     (NAMEP)++)

struct algorithm_table {
	const struct ike_alg **start;
	const struct ike_alg **end;
	const char *name;
};

#define ALGORITHM_TABLE(NAME, TABLE) {						\
		.start = (const struct ike_alg **)(TABLE),			\
		.end = (const struct ike_alg **)(TABLE) + elemsof(TABLE),	\
		.name = (NAME),							\
	}

struct type_algorithms {
	struct algorithm_table all;
	enum ike_alg_type type;
	enum_names *const enum_names[IKE_ALG_KEY_ROOF];
	void (*desc_check)(const struct ike_alg*);
	bool (*desc_is_ike)(const struct ike_alg*);
};

static struct type_algorithms encrypt_algorithms;
static struct type_algorithms hash_algorithms;
static struct type_algorithms prf_algorithms;
static struct type_algorithms integ_algorithms;
static struct type_algorithms dhmke_algorithms;

static struct type_algorithms *const type_algorithms[] = {
	/*INVALID*/ NULL,
	&encrypt_algorithms,
	&hash_algorithms,
	&prf_algorithms,
	&integ_algorithms,
	&dhmke_algorithms,
};

const char *ike_alg_key_name(enum ike_alg_key key)
{
	static const char *names[IKE_ALG_KEY_ROOF] = {
		[IKEv1_OAKLEY_ID] = "IKEv1 OAKLEY ID",
		[IKEv1_ESP_ID] = "IKEv1 ESP ID",
		[IKEv2_ALG_ID] = "IKEv2 ID",
	};
	passert(key < elemsof(names));
	return names[key];
}

static const struct ike_alg **next_alg(const struct algorithm_table *table,
				       const struct ike_alg **last)
{
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
	return (const struct encrypt_desc**)next_alg(&encrypt_algorithms.all,
						     (const struct ike_alg**)last);
}

const struct prf_desc **next_prf_desc(const struct prf_desc **last)
{
	return (const struct prf_desc**)next_alg(&prf_algorithms.all,
						 (const struct ike_alg**)last);
}

const struct integ_desc **next_integ_desc(const struct integ_desc **last)
{
	return (const struct integ_desc**)next_alg(&integ_algorithms.all,
						   (const struct ike_alg**)last);
}

const struct oakley_group_desc **next_oakley_group(const struct oakley_group_desc **last)
{
	return (const struct oakley_group_desc**)next_alg(&dhmke_algorithms.all,
							  (const struct ike_alg**)last);
}

static const struct ike_alg *alg_byname(const struct algorithm_table *algorithms,
					const char *name)
{
	for (const struct ike_alg **alg = next_alg(algorithms, NULL);
	     alg != NULL; alg = next_alg(algorithms, alg)) {
		FOR_EACH_IKE_ALG_NAMEP(*alg, namep) {
			if (strcaseeq(name, *namep)) {
				return *alg;
			}
		}
	}
	return NULL;
}

const struct oakley_group_desc *group_desc_byname(const char *name)
{
	return oakley_group_desc(alg_byname(&dhmke_algorithms.all, name));
}

bool ike_alg_is_valid(const struct ike_alg *alg)
{
	FOR_EACH_IKE_ALGP(&type_algorithms[alg->algo_type]->all, algp) {
		if (*algp == alg) {
			return TRUE;
		}
	}
	return FALSE;
}

bool ike_alg_is_ike(const struct ike_alg *alg)
{
	return type_algorithms[alg->algo_type]->desc_is_ike(alg);
}

const char *ike_alg_type_name(enum ike_alg_type type)
{
	passert(type < elemsof(type_algorithms));
	return type_algorithms[type]->all.name;
}

bool ike_alg_is_aead(const struct encrypt_desc *enc_desc)
{
	pexpect(enc_desc != NULL);
	return enc_desc != NULL && enc_desc->aead_tag_size > 0;
}

/*
 * Casts
 */

const struct hash_desc *hash_desc(const struct ike_alg *alg)
{
	passert(alg == NULL || alg->algo_type == IKE_ALG_HASH);
	return (const struct hash_desc *)alg;
}

const struct prf_desc *prf_desc(const struct ike_alg *alg)
{
	passert(alg == NULL || alg->algo_type == IKE_ALG_PRF);
	return (const struct prf_desc *)alg;
}

const struct integ_desc *integ_desc(const struct ike_alg *alg)
{
	passert(alg == NULL || alg->algo_type == IKE_ALG_INTEG);
	return (const struct integ_desc *)alg;
}

const struct encrypt_desc *encrypt_desc(const struct ike_alg *alg)
{
	passert(alg == NULL || alg->algo_type == IKE_ALG_ENCRYPT);
	return (const struct encrypt_desc *)alg;
}

const struct oakley_group_desc *oakley_group_desc(const struct ike_alg *alg)
{
	passert(alg == NULL || alg->algo_type == IKE_ALG_DH);
	return (const struct oakley_group_desc *)alg;
}

/*
 * return ike_alg object by {type, key, id}
 */

static const struct ike_alg *lookup_by_id(struct type_algorithms *algorithms,
					  enum ike_alg_key key,
					  int id, lset_t debug)
{
	FOR_EACH_IKE_ALGP(&algorithms->all, algp) {
		const struct ike_alg *alg = *algp;
		if (alg->id[key] == id) {
			DBG(debug,
			    const char *name = enum_short_name(algorithms->enum_names[key], id);
			    DBG_log("%s ike_alg_lookup_by_id id: %s=%u, found %s\n",
				    algorithms->all.name,
				    name ? name : "???",
				    id, alg->name));
			return alg;
		}
 	}
	DBG(debug,
	    const char *name = enum_short_name(algorithms->enum_names[key], id);
	    DBG_log("%s ike_alg_lookup_by_id id: %s=%u, not found\n",
		    algorithms->all.name, name ? name : "???", id));
	return NULL;
}

static const struct ike_alg *ikev1_oakley_lookup(struct type_algorithms *algorithms,
						 unsigned id)
{
	const struct ike_alg *alg = lookup_by_id(algorithms,
						 IKEv1_OAKLEY_ID,
						 id, DBG_CRYPT);
	if (alg == NULL || !ike_alg_is_ike(alg)) {
		return NULL;
	}
	return alg;
}

const struct encrypt_desc *ikev1_get_ike_encrypt_desc(enum ikev1_encr_attribute id)
{
	return encrypt_desc(ikev1_oakley_lookup(&encrypt_algorithms, id));
}

const struct prf_desc *ikev1_get_ike_prf_desc(enum ikev1_auth_attribute id)
{
	return prf_desc(ikev1_oakley_lookup(&prf_algorithms, id));
}

const struct integ_desc *ikev1_get_ike_integ_desc(enum ikev1_auth_attribute id)
{
	return integ_desc(ikev1_oakley_lookup(&integ_algorithms, id));
}

static const struct ike_alg *ikev2_lookup(struct type_algorithms *algorithms, int id)
{

	return lookup_by_id(algorithms, IKEv2_ALG_ID, id, DBG_CRYPT);
}

const struct encrypt_desc *ikev2_get_encrypt_desc(enum ikev2_trans_type_encr id)
{
	return encrypt_desc(ikev2_lookup(&encrypt_algorithms, id));
}

const struct prf_desc *ikev2_get_prf_desc(enum ikev2_trans_type_prf id)
{
	return prf_desc(ikev2_lookup(&prf_algorithms, id));
}

const struct integ_desc *ikev2_get_integ_desc(enum ikev2_trans_type_integ id)
{
	return integ_desc(ikev2_lookup(&integ_algorithms, id));
}

const struct oakley_group_desc *lookup_group(u_int16_t group)
{
	for (const struct oakley_group_desc **groupp = next_oakley_group(NULL);
	     groupp != NULL; groupp = next_oakley_group(groupp)) {
		if (group == (*groupp)->group) {
			return *groupp;
		}
	}
	return NULL;
}

/*
 * Validate and register IKE algorithm objects
 *
 * Order the array so that, when listed, the algorithms are in the
 * order expected by test scripts.
 */

static void check_alg_in_table(const struct ike_alg *alg,
			     struct algorithm_table *table)
{
	FOR_EACH_IKE_ALGP(table, algp) {
		if (alg == *algp) {
			return;
		}
	}
	PASSERT_FAIL("%s missing from %s table",
		     alg->name, table->name);
}

/*
 * Check for name in names
 */
static void check_name_in_names(const char *adjective,
				  const char *name,
				  const struct ike_alg *alg)
{
	FOR_EACH_IKE_ALG_NAMEP(alg, namep) {
		if (strcaseeq(name, *namep)) {
			return;
		}
	}
	PEXPECT_LOG("%s name %s missing from %s %s names",
		    adjective, name, type_algorithms[alg->algo_type]->all.name, alg->name);
}

static void check_names_in_names(const char *adjective,
				   const struct ike_alg *child,
				   const struct ike_alg *parent)
{
	FOR_EACH_IKE_ALG_NAMEP(child, namep) {
		check_name_in_names(adjective, *namep, parent);
	}
}

/*
 * Simple hash functions.
 */

static struct hash_desc *hash_descriptors[] = {
	&ike_alg_hash_md5,
	&ike_alg_hash_sha1,
	&ike_alg_hash_sha2_256,
	&ike_alg_hash_sha2_384,
	&ike_alg_hash_sha2_512,
};

static void hash_desc_check(const struct ike_alg *alg)
{
	const struct hash_desc *hash = hash_desc(alg);
	passert_ike_alg(alg, hash->hash_digest_len > 0);
	passert_ike_alg(alg, hash->hash_block_size > 0);
	check_name_in_names("hash", hash->common.name, &hash->common);
	if (hash->hash_ops) {
		passert_ike_alg(alg, hash->hash_ops->check != NULL);
		passert_ike_alg(alg, hash->hash_ops->digest_symkey != NULL);
		passert_ike_alg(alg, hash->hash_ops->digest_bytes != NULL);
		passert_ike_alg(alg, hash->hash_ops->final_bytes != NULL);
		passert_ike_alg(alg, hash->hash_ops->symkey_to_symkey != NULL);
		hash->hash_ops->check(hash);
	}
}

static bool hash_desc_is_ike(const struct ike_alg *alg)
{
	const struct hash_desc *hash = hash_desc(alg);
	return hash->hash_ops != NULL;
}

static struct type_algorithms hash_algorithms = {
	.all = ALGORITHM_TABLE("HASH", hash_descriptors),
	.type = IKE_ALG_HASH,
	.enum_names = {
		[IKEv1_OAKLEY_ID] = &oakley_hash_names,
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

static struct prf_desc *prf_descriptors[] = {
#ifdef USE_MD5
	&ike_alg_prf_md5,
#endif
#ifdef USE_SHA1
	&ike_alg_prf_sha1,
#endif
#ifdef USE_SHA2
	&ike_alg_prf_sha2_256,
	&ike_alg_prf_sha2_384,
	&ike_alg_prf_sha2_512,
#endif
};

static void prf_desc_check(const struct ike_alg *alg)
{
	const struct prf_desc *prf = prf_desc(alg);
	passert_ike_alg(alg, prf->prf_key_size > 0);
	passert_ike_alg(alg, prf->prf_output_size > 0);
	if (prf->prf_ops != NULL) {
		passert_ike_alg(alg, prf->prf_ops->check != NULL);
		passert_ike_alg(alg, prf->prf_ops->init_symkey != NULL);
		passert_ike_alg(alg, prf->prf_ops->init_bytes != NULL);
		passert_ike_alg(alg, prf->prf_ops->digest_symkey != NULL);
		passert_ike_alg(alg, prf->prf_ops->digest_bytes != NULL);
		passert_ike_alg(alg, prf->prf_ops->final_symkey != NULL);
		passert_ike_alg(alg, prf->prf_ops->final_bytes != NULL);
		/*
		 * IKEv1 IKE algorithms must have a hasher - used for
		 * things like computing IV.
		 */
		passert_ike_alg(alg, prf->common.id[IKEv1_OAKLEY_ID] == 0
				     || prf->hasher != NULL);
		prf->prf_ops->check(prf);
	}
	if (prf->hasher) {
		/*
		 * Check for dangling pointer.
		 */
		check_alg_in_table(&prf->hasher->common, &hash_algorithms.all);
		passert_ike_alg(alg, prf->prf_output_size == prf->hasher->hash_digest_len);
		check_names_in_names("prf hasher", &prf->hasher->common, alg);
	}
}

static bool prf_desc_is_ike(const struct ike_alg *alg)
{
	const struct prf_desc *prf = prf_desc(alg);
	return prf->prf_ops != NULL;
}

static struct type_algorithms prf_algorithms = {
	.all = ALGORITHM_TABLE("PRF", prf_descriptors),
	.type = IKE_ALG_PRF,
	.enum_names = {
		[IKEv1_OAKLEY_ID] = &oakley_hash_names,
		[IKEv1_ESP_ID] = NULL, /* ESP/AH uses IKE PRF */
		[IKEv2_ALG_ID] = &ikev2_trans_type_prf_names,
	},
	.desc_check = prf_desc_check,
	.desc_is_ike = prf_desc_is_ike,
};

/*
 * Integrity.
 */

static struct integ_desc *integ_descriptors[] = {
#ifdef USE_MD5
	&ike_alg_integ_md5,
#endif
#ifdef USE_SHA1
	&ike_alg_integ_sha1,
#endif
#ifdef USE_SHA2
	&ike_alg_integ_sha2_512,
	&ike_alg_integ_sha2_384,
	&ike_alg_integ_sha2_256,
#endif
#ifdef USE_AES
	&ike_alg_integ_aes_xcbc,
	&ike_alg_integ_aes_cmac,
#endif
#ifdef USE_RIPEMD
	&ike_alg_integ_hmac_ripemd_160_96,
#endif
};

static void integ_desc_check(const struct ike_alg *alg)
{
	const struct integ_desc *integ = integ_desc(alg);
	passert_ike_alg(alg, integ->integ_key_size > 0);
	passert_ike_alg(alg, integ->integ_output_size > 0);
	if (integ->prf) {
		passert_ike_alg(alg, integ->integ_key_size == integ->prf->prf_key_size);
		passert_ike_alg(alg, integ->integ_output_size <= integ->prf->prf_output_size);
		passert_ike_alg(alg, prf_desc_is_ike(&integ->prf->common));
		check_names_in_names("integ prf", &integ->prf->common, alg);
	}
}

static bool integ_desc_is_ike(const struct ike_alg *alg)
{
	const struct integ_desc *integ = integ_desc(alg);
	return integ->prf != NULL;
}

static struct type_algorithms integ_algorithms = {
	.all = ALGORITHM_TABLE("INTEG", integ_descriptors),
	.type = IKE_ALG_INTEG,
	.enum_names = {
		[IKEv1_OAKLEY_ID] = &oakley_hash_names,
		[IKEv1_ESP_ID] = &auth_alg_names,
		[IKEv2_ALG_ID] = &ikev2_trans_type_integ_names,
	},
	.desc_check = integ_desc_check,
	.desc_is_ike = integ_desc_is_ike,
};

/*
 * Encryption
 */

static struct encrypt_desc *encrypt_descriptors[] = {
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
#ifdef USE_SERPENT
	&ike_alg_encrypt_serpent_cbc,
#endif
#ifdef USE_TWOFISH
	&ike_alg_encrypt_twofish_cbc,
	&ike_alg_encrypt_twofish_ssh,
#endif
#ifdef USE_CAST
	&ike_alg_encrypt_cast_cbc,
#endif
	&ike_alg_encrypt_null,
};

bool encrypt_has_key_bit_length(const struct encrypt_desc *encrypt,
				unsigned keylen)
{
	for (const unsigned *keyp = encrypt->key_bit_lengths; *keyp; keyp++) {
		if (*keyp == keylen) {
			return TRUE;
		}
	}
	return FALSE;
}

unsigned encrypt_max_key_bit_length(const struct encrypt_desc *encrypt)
{
	/* by definition */
	return encrypt->key_bit_lengths[0];
}

static void encrypt_desc_check(const struct ike_alg *alg)
{
	const struct encrypt_desc *encrypt = encrypt_desc(alg);
	/*
	 * Only implemented one way, if at all.
	 */
	if (encrypt->encrypt_ops != NULL) {
		passert_ike_alg(alg, encrypt->encrypt_ops->check != NULL);
		passert_ike_alg(alg, ((encrypt->encrypt_ops->do_crypt == NULL)
				      != (encrypt->encrypt_ops->do_aead == NULL)));
	}

	/*
	 * AEAD implementation implies a valid AEAD tag size.
	 * Converse for non-AEAD implementation.
	 */
	if (encrypt->encrypt_ops != NULL) {
		passert_ike_alg(alg, encrypt->encrypt_ops->do_aead == NULL || encrypt->aead_tag_size > 0);
		passert_ike_alg(alg, encrypt->encrypt_ops->do_crypt == NULL || encrypt->aead_tag_size == 0);
	}

	if (encrypt->keydeflen) {
		/*
		 * Acceptable key bit-length checks (assuming the
		 * algorithm isn't NULL):
		 *
		 * - 0 terminated
		 *
		 * - in descending order
		 *
		 * - provided there is a KEYDEFLEN (i.e., not the NULL
		 *   algorithm), there is at least one key length.
		 */
		passert_ike_alg(alg, encrypt->key_bit_lengths[0] > 0);
		passert_ike_alg(alg, encrypt->key_bit_lengths[elemsof(encrypt->key_bit_lengths) - 1] == 0);
		for (const unsigned *keyp = encrypt->key_bit_lengths; *keyp; keyp++) {
			/* at end, keyp[1] will be 0 */
			passert_ike_alg(alg, keyp[0] > keyp[1]);
		}
		/*
		 * the default appears in the list
		 */
		passert_ike_alg(alg, encrypt_has_key_bit_length(encrypt, encrypt->keydeflen));
	} else {
		/*
		 * Interpret a zero default key as implying NULL encryption.
		 */
		passert_ike_alg(alg, encrypt->common.id[IKEv1_ESP_ID] == ESP_NULL
			|| encrypt->common.id[IKEv2_ALG_ID] == IKEv2_ENCR_NULL);
		passert_ike_alg(alg, encrypt->enc_blocksize == 1);
		passert_ike_alg(alg, encrypt->wire_iv_size == 0);
		passert_ike_alg(alg, encrypt->key_bit_lengths[0] == 0);
	}
}

static bool encrypt_desc_is_ike(const struct ike_alg *alg)
{
	const struct encrypt_desc *encrypt = encrypt_desc(alg);
	return encrypt->encrypt_ops != NULL;
}

static struct type_algorithms encrypt_algorithms = {
	.all = ALGORITHM_TABLE("ENCRYPT", encrypt_descriptors),
	.type = IKE_ALG_ENCRYPT,
	.enum_names = {
		[IKEv1_OAKLEY_ID] = &oakley_enc_names,
		[IKEv1_ESP_ID] = &esp_transformid_names,
		[IKEv2_ALG_ID] = &ikev2_trans_type_encr_names,
	},
	.desc_check = encrypt_desc_check,
	.desc_is_ike = encrypt_desc_is_ike,
};

/*
 * DH group
 */

static struct oakley_group_desc *dhmke_descriptors[] = {
	&oakley_group_modp1024,
	&oakley_group_modp1536,
	&oakley_group_modp2048,
	&oakley_group_modp3072,
	&oakley_group_modp4096,
	&oakley_group_modp6144,
	&oakley_group_modp8192,
	&oakley_group_dh19,
	&oakley_group_dh20,
	&oakley_group_dh21,
#ifdef USE_DH22
	&oakley_group_dh22,
#endif
	&oakley_group_dh23,
	&oakley_group_dh24,
};

static void dhmke_desc_check(const struct ike_alg *alg)
{
	const struct oakley_group_desc *dhmke = oakley_group_desc(alg);
	passert_ike_alg(alg, dhmke->group > 0);
	passert_ike_alg(alg, dhmke->bytes > 0);
	passert_ike_alg(alg, dhmke->common.id[IKEv2_ALG_ID] == dhmke->group);
	passert_ike_alg(alg, dhmke->common.id[IKEv1_OAKLEY_ID] == dhmke->group);
	/* always implemented */
	passert_ike_alg(alg, dhmke->dhmke_ops != NULL);
	passert_ike_alg(alg, dhmke->dhmke_ops->check != NULL);
	passert_ike_alg(alg, dhmke->dhmke_ops->calc_ke != NULL);
	passert_ike_alg(alg, dhmke->dhmke_ops->calc_g_ir != NULL);
	/* more? */
	dhmke->dhmke_ops->check(dhmke);
}

static bool dhmke_desc_is_ike(const struct ike_alg *alg)
{
	const struct oakley_group_desc *dhmke = oakley_group_desc(alg);
	return dhmke->dhmke_ops != NULL;
}

static struct type_algorithms dhmke_algorithms = {
	.all = ALGORITHM_TABLE("DH", dhmke_descriptors),
	.type = IKE_ALG_DH,
	.enum_names = {
		[IKEv1_OAKLEY_ID] = &oakley_group_names,
		[IKEv1_ESP_ID] = NULL,
		[IKEv2_ALG_ID] = &oakley_group_names,
	},
	.desc_check = dhmke_desc_check,
	.desc_is_ike = dhmke_desc_is_ike,
};

/*
 * Check mapping between enums and names.
 */
static void check_enum_name(const char *what,
			    const struct ike_alg *alg,
			    int id, enum_names *enum_names)
{
	if (id > 0) {
		if (enum_names == NULL) {
			PASSERT_FAIL("%s %s %s has no enum names",
				     type_algorithms[alg->algo_type]->all.name,
				     alg->name, what);
		}
		const char *enum_name = enum_short_name(enum_names, id);
		DBG(DBG_CRYPT,
		    DBG_log("%s id: %d enum name: %s",
			    what, id, enum_name));
		passert_ike_alg(alg, enum_name != NULL);
		check_name_in_names("enum", enum_name, alg);
	} else {
		DBG(DBG_CRYPT, DBG_log("%s id: %d enum name: N/A", what, id));
	}
}

/*
 * Verify an algorithm table, pruning anything that isn't supported.
 */

static void check_algorithm_table(struct type_algorithms *algorithms)
{
	/*
	 * Sanity check the raw algorithm table.
	 *
	 * Anything going wrong here results in an abort.
	 */

	DBG(DBG_CRYPT, DBG_log("%s algorithm assertion checks", algorithms->all.name));
	FOR_EACH_IKE_ALGP(&algorithms->all, algp) {
		const struct ike_alg *alg = *algp;

		DBG(DBG_CRYPT, DBG_log("%s algorithm %s; official name: %s, IKEv1 OAKLEY id: %d, IKEv1 ESP_INFO id: %d, IKEv2 id: %d",
				       algorithms->all.name, alg->name, alg->officname,
				       alg->id[IKEv1_OAKLEY_ID],
				       alg->id[IKEv1_ESP_ID],
				       alg->id[IKEv2_ALG_ID]));
		passert_ike_alg(alg, alg->name != NULL);
		passert_ike_alg(alg, alg->officname != NULL);
		passert_ike_alg(alg, alg->algo_type == algorithms->type);

		/*
		 * Validate an IKE_ALG's IKEv1 and IKEv2 enum_name
		 * entries.
		 *
		 * struct ike_alg_encrypt_aes_ccm_8 et.al. do not
		 * define the IKEv1 field "common.id[IKEv1_OAKLEY_ID]" so need to
		 * handle that.
		 */
		bool at_least_one_valid_id = FALSE;
		for (enum ike_alg_key key = IKE_ALG_KEY_FLOOR;
		     key < IKE_ALG_KEY_ROOF; key++) {
			int id = alg->id[key];
			if (id > 0) {
				at_least_one_valid_id = TRUE;
				check_enum_name(ike_alg_key_name(key),
						alg, id,
						algorithms->enum_names[key]);
			}
		}
		passert_ike_alg(alg, at_least_one_valid_id);

		/*
		 * Check that name appears in the names list.
		 *
		 * Requiring this is easier than trying to ensure that
		 * changes to NAME don't break NAMES.
		 */
		check_name_in_names(algorithms->all.name, alg->name, alg);

		/*
		 * Algorithm can't appear twice.
		 *
		 * Search the previously validated algorithms using a
		 * fudged up ALL array that only contain the
		 * previously verified algorithms.
		 */
		struct type_algorithms scratch = *algorithms;
		scratch.all.end = algp;
		for (enum ike_alg_key key = IKE_ALG_KEY_FLOOR;
		     key < IKE_ALG_KEY_ROOF; key++) {
			int id = alg->id[key];
			passert_ike_alg(alg, id == 0
				|| (lookup_by_id(&scratch, key, id, LEMPTY)
				    == NULL));
		}

		/*
		 * Extra algorithm specific checks.
		 */
		passert_ike_alg(alg, algorithms->desc_check != NULL);
		algorithms->desc_check(alg);
	}

        /*
	 * Log the final list as a pretty table.
	 */
	FOR_EACH_IKE_ALGP(&algorithms->all, algp) {
		const struct ike_alg *alg = *algp;
		char buf[IKE_ALG_SNPRINT_BUFSIZ] = "";
		ike_alg_snprint(buf, sizeof(buf), alg);
		libreswan_log("%s", buf);
	}
}

/*
 * Yet more code dealing with appending a string to a string buffer.
 */
static void append(char **bufp, const char *end, const char *str)
{
	passert(*bufp + strlen(str) < end);
	strcpy(*bufp, str);
	*bufp += strlen(str);
	passert(*bufp < end);
}

void ike_alg_snprint(char *buf, size_t sizeof_buf,
		     const struct ike_alg *alg)
{
	pexpect(sizeof_buf >= IKE_ALG_SNPRINT_BUFSIZ);
	char *const end = buf + sizeof_buf;
	/*
	 * TYPE NAME:
	 */
	{
		char *start = buf;
		append(&buf, end, ike_alg_type_name(alg->algo_type));
		append(&buf, end, " ");
		append(&buf, end, alg->name);
		append(&buf, end, ":");
		/* magic number from eyeballing the output */
		ssize_t pad = 21 - (buf - start);
		passert_ike_alg(alg, pad >= 0);
		for (ssize_t i = 0; i < pad; i++) {
			append(&buf, end, " ");
		}
	}
	/*
	 * IKEv1: IKE ESP AH  IKEv2: IKE ESP AH
	 */
	bool v1_ike;
	bool v2_ike;
	if (ike_alg_is_ike(alg)) {
		v1_ike = alg->id[IKEv1_OAKLEY_ID] > 0;
		v2_ike = (alg->id[IKEv2_ALG_ID] > 0);
	} else {
		v1_ike = FALSE;
		v2_ike = FALSE;
	}
	bool v1_esp;
	bool v2_esp;
	bool v1_ah;
	bool v2_ah;
	switch (alg->algo_type) {
	case IKE_ALG_PRF:
	case IKE_ALG_DH:
	case IKE_ALG_HASH:
		v1_esp = v2_esp = v1_ah = v2_ah = FALSE;
		break;
	case IKE_ALG_ENCRYPT:
		v1_esp = alg->id[IKEv1_ESP_ID] > 0;
		v2_esp = alg->id[IKEv2_ALG_ID] > 0;
		v1_ah = FALSE;
		v2_ah = FALSE;
		break;
	case IKE_ALG_INTEG:
		v1_esp = v1_ah = alg->id[IKEv1_ESP_ID] > 0;
		v2_esp = v2_ah = alg->id[IKEv2_ALG_ID] > 0;
		break;
	default:
		bad_case(alg->algo_type);
	}
	append(&buf, end, "  IKEv1:");
	append(&buf, end, (v1_ike
			   ? " IKE"
			   : "    "));
	append(&buf, end, (v1_esp
			   ? " ESP"
			   : "    "));
	append(&buf, end, (v1_ah
			   ? " AH"
			   : "   "));
	append(&buf, end, "  IKEv2:");
	append(&buf, end, (v2_ike
			   ? " IKE"
			   : "    "));
	append(&buf, end, (v2_esp
			   ? " ESP"
			   : "    "));
	append(&buf, end, (v2_ah
			   ? " AH"
			   : "   "));

	/*
	 * FIPS?
	 */
	{
		append(&buf, end, "  ");
		if (alg->fips) {
			append(&buf, end, "FIPS");
		} else {
			append(&buf, end, "    ");
		}
	}
	passert_ike_alg(alg, buf < end);

	/*
	 * Concatenate [key,...] or {key,...} with default
	 * marked with '*'.
	 */
	if (alg->algo_type == IKE_ALG_ENCRYPT) {
		const struct encrypt_desc *encr = encrypt_desc(alg);
		append(&buf, end, encr->keylen_omitted ? "  [" : "  {");
		const char *sep = "";
		for (const unsigned *keyp = encr->key_bit_lengths; *keyp; keyp++) {
			append(&buf, end, sep);
			if (*keyp == encr->keydeflen) {
				append(&buf, end, "*");
			}
			/* no large keys */
			passert_ike_alg(alg, *keyp < 1000 && buf + 3 < end);
			snprintf(buf, end - buf, "%d", *keyp);
			buf += strlen(buf);
			sep = ",";
		}
		append(&buf, end, encr->keylen_omitted ? "]" : "}");
		/* did fit */
	}
	passert_ike_alg(alg, buf < end);

	/*
	 * Concatenate (alias ...)
	 */
	{
		const char *start = buf;
		const char *sep = "  (";
		FOR_EACH_IKE_ALG_NAMEP(alg, name) {
			/* filter out NAME */
			if (!strcaseeq(*name, alg->name)) {
				append(&buf, end, sep);
				append(&buf, end, *name);
				sep = " ";
			}
		}
		if (*start) {
			append(&buf, end, ")");
		}
	}
	passert_ike_alg(alg, buf < end);
}

/*
 * Strip out any non-FIPS algorithms.
 *
 * This prevents checks being performed on algorithms that are.
 */
static void strip_nonfips(struct type_algorithms *algorithms)
{
	const struct ike_alg **end = algorithms->all.start;
	FOR_EACH_IKE_ALGP(&algorithms->all, algp) {
		const struct ike_alg *alg = *algp;
		/*
		 * Check FIPS before trying to run any tests.
		 */
		if (!alg->fips) {
			libreswan_log("%s algorithm %s: DISABLED; not FIPS compliant",
				      algorithms->all.name, alg->name);
			continue;
		}
		*end++ = alg;
	}
	algorithms->all.end = end;
}

void ike_alg_init(void)
{
	bool fips = libreswan_fipsmode();

	/*
	 * If needed, completely strip out non-FIPS algorithms.
	 * Prevents inconsistency where a non-FIPS algorithm is
	 * referring to something that's been disabled.
	 */
	if (fips) {
		for (enum ike_alg_type type = IKE_ALG_FLOOR;
		     type < IKE_ALG_ROOF; type++) {
			struct type_algorithms *algorithms = type_algorithms[type];
			if (algorithms) {
				passert(algorithms->type == type);
				strip_nonfips(algorithms);
			}
		}
	}

	/*
	 * Now verify what is left.
	 */
	for (enum ike_alg_type type = IKE_ALG_FLOOR;
	     type < IKE_ALG_ROOF; type++) {
		struct type_algorithms *algorithms = type_algorithms[type];
		if (algorithms) {
			passert(algorithms->type == type)
			check_algorithm_table(algorithms);
		}
	}
}
