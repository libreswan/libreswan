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
	enum_names *const ikev1_oakley_enum_names;
	enum_names *const ikev1_esp_enum_names;
	enum_names *const ikev2_enum_names;
	void (*desc_check)(const struct ike_alg*);
	bool (*desc_is_ike)(const struct ike_alg*);
};

static struct type_algorithms prf_algorithms;
static struct type_algorithms integ_algorithms;
static struct type_algorithms encrypt_algorithms;
static struct type_algorithms dh_algorithms;

static struct type_algorithms *const type_algorithms[] = {
	/*INVALID*/ NULL,
	&encrypt_algorithms,
	/*HASH*/ NULL,
	&prf_algorithms,
	&integ_algorithms,
	&dh_algorithms,
};

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
	return (const struct oakley_group_desc**)next_alg(&dh_algorithms.all,
							  (const struct ike_alg**)last);
}

bool ike_alg_is_ike(const struct ike_alg *alg)
{
	return type_algorithms[alg->algo_type]->desc_is_ike(alg);
}

bool ike_alg_enc_requires_integ(const struct encrypt_desc *enc_desc)
{
	return enc_desc != NULL && enc_desc->do_aead_crypt_auth == NULL;
}

/*
 *      return ike_algo object by {type, id}
 */

static const struct ike_alg *ikev1_oakley_lookup(struct type_algorithms *algorithms,
						 unsigned id)
{
	FOR_EACH_IKE_ALGP(&algorithms->all, algp) {
		const struct ike_alg *e = *algp;
		if (e->ikev1_oakley_id == id
		    && ike_alg_is_ike(e)) {
			DBG(DBG_CRYPT,
			    struct esb_buf buf;
			    DBG_log("IKEv1 Oakley lookup by IKEv1 id: %s=%u, found %s\n",
				    enum_showb(algorithms->ikev1_oakley_enum_names, id, &buf),
				    id, e->name));
			return e;
		}
	}
	DBG(DBG_CRYPT,
	    struct esb_buf buf;
	    DBG_log("IKEv1 Oakley lookup by IKEv1 id: %s=%u, not found\n",
		    enum_showb(algorithms->ikev1_oakley_enum_names, id, &buf),
		    id));
	return NULL;
}

const struct encrypt_desc *ikev1_get_ike_encrypt_desc(enum ikev1_encr_attribute id)
{
	return (const struct encrypt_desc *) ikev1_oakley_lookup(&encrypt_algorithms, id);
}

const struct prf_desc *ikev1_get_ike_prf_desc(enum ikev1_auth_attribute id)
{
	return (const struct prf_desc *) ikev1_oakley_lookup(&prf_algorithms, id);
}

const struct integ_desc *ikev1_get_ike_integ_desc(enum ikev1_auth_attribute id)
{
	return (const struct integ_desc *) ikev1_oakley_lookup(&integ_algorithms, id);
}

static const struct ike_alg *ikev1_esp_lookup(const struct algorithm_table *table, int id)
{
	FOR_EACH_IKE_ALGP(table, algp) {
		const struct ike_alg *e = *algp;
		if (e->ikev1_esp_id == id) {
			DBG(DBG_CRYPT, DBG_log("%s lookup by IKEv1 ESP id: %d, found %s\n",
					       table->name, id, e->name));
			return e;
		}
	}
	DBG(DBG_CRYPT, DBG_log("%s lookup by IKEv1 ESP id:%d, not found\n",
			       table->name, id));
	return NULL;
}

static const struct ike_alg *ikev2_lookup(const struct algorithm_table *table, int id)
{
	FOR_EACH_IKE_ALGP(table, algp) {
		const struct ike_alg *e = *algp;
		if (e->ikev2_id == id) {
			DBG(DBG_CRYPT, DBG_log("%s lookup by IKEv2 id: %d, found %s\n",
					       table->name, id, e->name));
			return e;
		}
	}
	DBG(DBG_CRYPT, DBG_log("%s lookup by IKEv2 id:%u, not found\n",
			       table->name, id));
	return NULL;
}

const struct encrypt_desc *ikev2_get_encrypt_desc(enum ikev2_trans_type_encr id)
{
	return (const struct encrypt_desc *) ikev2_lookup(&encrypt_algorithms.all, id);
}

const struct prf_desc *ikev2_get_prf_desc(enum ikev2_trans_type_prf id)
{
	return (const struct prf_desc *) ikev2_lookup(&prf_algorithms.all, id);
}

const struct integ_desc *ikev2_get_integ_desc(enum ikev2_trans_type_integ id)
{
	return (const struct integ_desc *) ikev2_lookup(&integ_algorithms.all, id);
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

/*
 * PRF [HASH] function.
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

static void hash_desc_check(const struct hash_desc *hash)
{
	passert(hash->common.algo_type == IKE_ALG_HASH);
	passert(hash->hash_digest_len > 0);
	passert(hash->hash_block_size > 0);
	if (hash->hash_ops) {
		passert(hash->hash_ops->digest_symkey != NULL &&
			hash->hash_ops->digest_bytes != NULL &&
			hash->hash_ops->final_bytes != NULL &&
			hash->hash_ops->symkey_to_symkey != NULL);
	}
	if (hash->hash_ops == &ike_alg_nss_hash_ops) {
		passert(hash->common.nss_mechanism > 0);
	}
}

static bool hash_desc_is_ike(const struct hash_desc *hash)
{
	return hash->hash_ops != NULL;
}

static void prf_desc_check(const struct ike_alg *alg)
{
	passert(alg->algo_type == IKE_ALG_PRF);
	const struct prf_desc *prf = (const struct prf_desc*)alg;
	passert(prf->prf_key_size > 0);
	passert(prf->prf_output_size > 0);
	if (prf->prf_ops != NULL) {
		passert(prf->prf_ops->init_symkey != NULL &&
			prf->prf_ops->init_bytes != NULL &&
			prf->prf_ops->digest_symkey != NULL &&
			prf->prf_ops->digest_bytes != NULL &&
			prf->prf_ops->final_symkey != NULL &&
			prf->prf_ops->final_bytes != NULL);
		/*
		 * IKEv1 IKE algorithms must have a hasher - used for
		 * things like computing IV.
		 */
		passert(prf->common.ikev1_oakley_id == 0
			|| prf->hasher != NULL);
	}
	if (prf->prf_ops == &ike_alg_hmac_prf_ops) {
		passert(prf->hasher != NULL);
		/* i.e., implemented */
		passert(hash_desc_is_ike(prf->hasher));
	}
	if (prf->hasher) {
		hash_desc_check(prf->hasher);
		passert(prf->prf_output_size == prf->hasher->hash_digest_len);
	}
	if (prf->prf_ops == &ike_alg_hmac_prf_ops) {
		passert(prf->hasher != NULL);
	}
	if (prf->prf_ops == &ike_alg_nss_prf_ops) {
		passert(prf->common.nss_mechanism > 0);
	}
}

static bool prf_desc_is_ike(const struct ike_alg *alg)
{
	passert(alg->algo_type == IKE_ALG_PRF);
	const struct prf_desc *prf = (const struct prf_desc*)alg;
	return prf->prf_ops != NULL;
}

static struct type_algorithms prf_algorithms = {
	.all = ALGORITHM_TABLE("PRF", prf_descriptors),
	.type = IKE_ALG_PRF,
	.ikev1_oakley_enum_names = &oakley_hash_names,
	.ikev1_esp_enum_names = NULL, /* ESP/AH uses IKE PRF */
	.ikev2_enum_names = &ikev2_trans_type_prf_names,
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
};

static void integ_desc_check(const struct ike_alg *alg)
{
	const struct integ_desc *integ = (const struct integ_desc*)alg;
	passert(integ->integ_key_size > 0);
	passert(integ->integ_output_size > 0);
	if (integ->prf) {
		passert(integ->integ_key_size == integ->prf->prf_key_size);
		passert(integ->integ_output_size <= integ->prf->prf_output_size);
		passert(prf_desc_is_ike(&integ->prf->common));
	}
}

static bool integ_desc_is_ike(const struct ike_alg *alg)
{
	passert(alg->algo_type == IKE_ALG_INTEG);
	const struct integ_desc *integ = (const struct integ_desc*)alg;
	return integ->prf != NULL;
}

static struct type_algorithms integ_algorithms = {
	.all = ALGORITHM_TABLE("INTEG", integ_descriptors),
	.type = IKE_ALG_INTEG,
	.ikev1_oakley_enum_names = &oakley_hash_names,
	.ikev1_esp_enum_names = &auth_alg_names,
	.ikev2_enum_names = &ikev2_trans_type_integ_names,
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
	const struct encrypt_desc *encrypt = (const struct encrypt_desc *)alg;
	/*
	 * Only implemented one way, if at all.
	 */
	passert((encrypt->do_crypt == NULL && encrypt->do_aead_crypt_auth == NULL)
		|| ((encrypt->do_crypt != NULL) != (encrypt->do_aead_crypt_auth != NULL)));
	/*
	 * - at least one key length
	 * - 0 terminated
	 * - in descending order
	 */
	passert(encrypt->key_bit_lengths[0] > 0);
	passert(encrypt->key_bit_lengths[elemsof(encrypt->key_bit_lengths) - 1] == 0);
	for (const unsigned *keyp = encrypt->key_bit_lengths; *keyp; keyp++) {
		/* at end, keyp[1] will be 0 */
		passert(keyp[0] > keyp[1]);
	}
	/*
	 * the default appears in the list
	 */
	passert(encrypt->keydeflen > 0);
	passert(encrypt_has_key_bit_length(encrypt, encrypt->keydeflen));
}

static bool encrypt_desc_is_ike(const struct ike_alg *alg)
{
	const struct encrypt_desc *encrypt = (const struct encrypt_desc *)alg;
	return (encrypt->do_crypt != NULL) != (encrypt->do_aead_crypt_auth != NULL);
}

static struct type_algorithms encrypt_algorithms = {
	.all = ALGORITHM_TABLE("ENCRYPT", encrypt_descriptors),
	.type = IKE_ALG_ENCRYPT,
	.ikev1_oakley_enum_names = &oakley_enc_names,
	.ikev1_esp_enum_names = &esp_transformid_names,
	.ikev2_enum_names = &ikev2_trans_type_encr_names,
	.desc_check = encrypt_desc_check,
	.desc_is_ike = encrypt_desc_is_ike,
};

/*
 * DH group
 */

static struct oakley_group_desc *dh_descriptors[] = {
	&oakley_group_modp1024,
	&oakley_group_modp1536,
	&oakley_group_modp2048,
	&oakley_group_modp3072,
	&oakley_group_modp4096,
	&oakley_group_modp6144,
	&oakley_group_modp8192,
#ifdef USE_DH22
	&oakley_group_dh22,
#endif
	&oakley_group_dh23,
	&oakley_group_dh24,
};

static void dh_desc_check(const struct ike_alg *alg)
{
	const struct oakley_group_desc *group = (const struct oakley_group_desc *)alg;
	passert(group->group > 0);
	passert(group->common.ikev2_id == group->group);
	passert(group->common.ikev1_oakley_id == group->group);
	/* more? */
}

static bool dh_desc_is_ike(const struct ike_alg *alg)
{
	passert(alg->algo_type == IKE_ALG_DH);
	return TRUE;
}

static struct type_algorithms dh_algorithms = {
	.all = ALGORITHM_TABLE("DH", dh_descriptors),
	.type = IKE_ALG_DH,
	.ikev1_oakley_enum_names = &oakley_enc_names,
	.ikev1_esp_enum_names = &esp_transformid_names,
	.ikev2_enum_names = &ikev2_trans_type_encr_names,
	.desc_check = dh_desc_check,
	.desc_is_ike = dh_desc_is_ike,
};

/*
 * Verify an algorithm table, pruning anything that isn't supported.
 */

static void check_enum_name(const char *what, int id, enum_names *names)
{
	if (id > 0) {
		const char *name = names ? enum_name(names, id) : "(NULL)";
		DBG(DBG_CRYPT, DBG_log("%s id: %d enum name: %s", what, id, name));
		passert(names != NULL);
		passert(name);
	} else {
		DBG(DBG_CRYPT, DBG_log("%s id: %d enum name: N/A", what, id));
	}
}

static void add_algorithms(bool fips, struct type_algorithms *algorithms)
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
				       alg->ikev1_oakley_id,
				       alg->ikev1_esp_id,
				       alg->ikev2_id));
		passert(alg->name);
		passert(alg->officname);
		passert(alg->algo_type == algorithms->type);

		/*
		 * Validate an IKE_ALG's IKEv1 and IKEv2 enum_name
		 * entries.
		 *
		 * struct ike_alg_encrypt_aes_ccm_8 et.al. do not
		 * define the IKEv1 field "common.ikev1_oakley_id" so need to
		 * handle that.
		 */
		passert(alg->ikev1_oakley_id > 0 || alg->ikev2_id > 0 || alg->ikev1_esp_id > 0);
		check_enum_name("IKEv1 OAKLEY", alg->ikev1_oakley_id,
				algorithms->ikev1_oakley_enum_names);
		check_enum_name("IKEv1 ESP_INFO", alg->ikev1_esp_id,
				algorithms->ikev1_esp_enum_names);
		check_enum_name("IKEv2", alg->ikev2_id,
				algorithms->ikev2_enum_names);

		/*
		 * Algorithm can't appear twice.
		 *
		 * Fudge up the ALL so that it only contain the
		 * previously verified algorithms and then use that
		 * for a search.  The search should fail.
		 */
		struct type_algorithms scratch = *algorithms;
		scratch.all.end = algp;
		passert(alg->ikev1_oakley_id == 0 ||
			ikev1_oakley_lookup(&scratch, alg->ikev1_oakley_id) == NULL);
		passert(alg->ikev1_esp_id == 0 ||
			ikev1_esp_lookup(&scratch.all, alg->ikev1_esp_id) == NULL);
		passert(alg->ikev2_id == 0 ||
			ikev2_lookup(&scratch.all, alg->ikev2_id) == NULL);

		/*
		 * Extra algorithm specific checks.
		 */
		passert(algorithms->desc_check);
		algorithms->desc_check(alg);
	}

	/*
	 * If FIPS, filter out anything non FIPS compliant.
	 */

	if (fips) {
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


	/*
	 * Completely filter out and flag any broken IKE algorithms.
	 *
	 * While, technically broken IKE algorithms only need to be
	 * removed from the IKE list (and left in ALL for ESP/AH), it
	 * is easier just remove them.  Arguably, it should instead
	 * passert().
	 *
	 * After applying this filter, common.do_ike_test becomes a
	 * proxy for a working native IKE algorithm.
	 */
	{
		const struct ike_alg **end = algorithms->all.start;
		FOR_EACH_IKE_ALGP(&algorithms->all, algp) {
			const struct ike_alg *alg = *algp;
			if (alg->do_ike_test != NULL
			    && !alg->do_ike_test(alg)) {
				loglog(RC_LOG_SERIOUS,
				       "%s algorithm %s: BROKEN; testing failed",
				       algorithms->all.name, alg->name);
				/*
				 * When FIPS, this is fatal.  When not
				 * FIPS, this must come close.
				 */
				passert(!fips);
				continue;
			}
			*end++ = alg;
		}
		algorithms->all.end = end;
	}

        /*
	 * Go through ALL algorithms identifying any suitable for IKE.
	 *
	 * Log the result as a pretty table.
	 */
	FOR_EACH_IKE_ALGP(&algorithms->all, algp) {
		const struct ike_alg *alg = *algp;

		/*
		 * Need to fix things like not even mentioning ESP/AH
		 * on the PRF line.
		 */
		bool v1_ike;
		bool v2_ike;
		passert(algorithms->desc_is_ike);
		if (algorithms->desc_is_ike(alg)) {
			v1_ike = alg->ikev1_oakley_id > 0;
			v2_ike = alg->ikev2_id > 0;
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
			v1_esp = v2_esp = v1_ah = v2_ah = FALSE;
			break;
		case IKE_ALG_ENCRYPT:
			v1_esp = alg->ikev1_esp_id > 0;
			v2_esp = alg->ikev2_id > 0;
			v1_ah = FALSE;
			v2_ah = FALSE;
			break;
		case IKE_ALG_INTEG:
			v1_esp = v1_ah = alg->ikev1_esp_id > 0;
			v2_esp = v2_ah = alg->ikev2_id > 0;
			break;
		default:
			bad_case(alg->algo_type);
		}
		libreswan_log("%s %s:%*s IKEv1: %3s %3s %2s IKEv2: %3s %3s %2s%s",
			      algorithms->all.name, alg->name,
			      (int)(19 - strlen(algorithms->all.name) - strlen(alg->name)), "",
			      v1_ike ? "IKE" : "",
			      v1_esp ? "ESP" : "",
			      v1_ah ? "AH" : "",
			      v2_ike ? "IKE" : "",
			      v2_esp ? "ESP" : "",
			      v2_ah ? "AH" : "",
			      alg->fips ? " FIPS: YES" : "");
	}
}

void ike_alg_init(void)
{
#ifdef FIPS_CHECK
	bool fips = libreswan_fipsmode();
#else
	bool fips = FALSE;
#endif
	for (enum ike_alg_type type = IKE_ALG_FLOOR;
	     type < IKE_ALG_ROOF; type++) {
		struct type_algorithms *algorithms = type_algorithms[type];
		if (algorithms) {
			passert(algorithms->type == type)
			add_algorithms(fips, algorithms);
		}
	}
}
