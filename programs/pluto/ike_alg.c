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

/* Oakley group description
 *
 * See:
 * RFC-2409 "The Internet key exchange (IKE)" Section 6
 * RFC-3526 "More Modular Exponential (MODP) Diffie-Hellman groups"
 */

/* magic signifier */
const struct oakley_group_desc unset_group = {
	.group = OAKLEY_GROUP_invalid,
};

static struct oakley_group_desc oakley_group[] = {
	/* modp768_modulus no longer supported - too weak */
	{
		.group = OAKLEY_GROUP_MODP1024,
		.gen = MODP_GENERATOR,
		.modp = MODP1024_MODULUS,
		.bytes = BYTES_FOR_BITS(1024),
	},
	{
		.group = OAKLEY_GROUP_MODP1536,
		.gen = MODP_GENERATOR,
		.modp = MODP1536_MODULUS,
		.bytes = BYTES_FOR_BITS(1536),
	},
	{
		.group = OAKLEY_GROUP_MODP2048,
		.gen = MODP_GENERATOR,
		.modp = MODP2048_MODULUS,
		.bytes = BYTES_FOR_BITS(2048),
	},
	{
		.group = OAKLEY_GROUP_MODP3072,
		.gen = MODP_GENERATOR,
		.modp = MODP3072_MODULUS,
		.bytes = BYTES_FOR_BITS(3072),
	},
	{
		.group = OAKLEY_GROUP_MODP4096,
		.gen = MODP_GENERATOR,
		.modp = MODP4096_MODULUS,
		.bytes = BYTES_FOR_BITS(4096),
	},
	{
		.group = OAKLEY_GROUP_MODP6144,
		.gen = MODP_GENERATOR,
		.modp = MODP6144_MODULUS,
		.bytes = BYTES_FOR_BITS(6144),
	},
	{
		.group = OAKLEY_GROUP_MODP8192,
		.gen = MODP_GENERATOR,
		.modp = MODP8192_MODULUS,
		.bytes = BYTES_FOR_BITS(8192),
	},
#ifdef USE_DH22
	{
		.group = OAKLEY_GROUP_DH22,
		.gen = MODP_GENERATOR_DH22,
		.modp = MODP1024_MODULUS_DH22,
		.bytes = BYTES_FOR_BITS(1024),
	},
#endif
	{
		.group = OAKLEY_GROUP_DH23,
		.gen = MODP_GENERATOR_DH23,
		.modp = MODP2048_MODULUS_DH23,
		.bytes = BYTES_FOR_BITS(2048),
	},
	{
		.group = OAKLEY_GROUP_DH24,
		.gen = MODP_GENERATOR_DH24,
		.modp = MODP2048_MODULUS_DH24,
		.bytes = BYTES_FOR_BITS(2048),
	},
};

const struct oakley_group_desc *lookup_group(u_int16_t group)
{
	int i;

	for (i = 0; i != elemsof(oakley_group); i++)
		if (group == oakley_group[i].group)
			return &oakley_group[i];

	return NULL;
}

const struct oakley_group_desc *next_oakley_group(const struct oakley_group_desc *group)
{
	if (group == NULL) {
		return &oakley_group[0];
	} else if (group < &oakley_group[elemsof(oakley_group) - 1]) {
		return group + 1;
	} else {
		return NULL;
	}
}

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
	struct algorithm_table ike;
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

static struct type_algorithms *const type_algorithms[] = {
	/*INVALID*/ NULL,
	&encrypt_algorithms,
	/*HASH*/ NULL,
	&prf_algorithms,
	&integ_algorithms,
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
	FOR_EACH_IKE_ALGP(&algorithms->ike, algp) {
		const struct ike_alg *e = *algp;
		if (e->ikev1_oakley_id == id) {
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
	.all = ALGORITHM_TABLE("Integrity", integ_descriptors),
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

static void encrypt_desc_check(const struct ike_alg *alg)
{
	const struct encrypt_desc *encrypt = (const struct encrypt_desc *)alg;
	/* if one, only one */
	passert((encrypt->do_crypt == NULL && encrypt->do_aead_crypt_auth == NULL)
		|| ((encrypt->do_crypt != NULL) != (encrypt->do_aead_crypt_auth != NULL)));
}

static bool encrypt_desc_is_ike(const struct ike_alg *alg)
{
	const struct encrypt_desc *encrypt = (const struct encrypt_desc *)alg;
	return (encrypt->do_crypt != NULL) != (encrypt->do_aead_crypt_auth != NULL);
}

static struct type_algorithms encrypt_algorithms = {
	.all = ALGORITHM_TABLE("Encryption", encrypt_descriptors),
	.type = IKE_ALG_ENCRYPT,
	.ikev1_oakley_enum_names = &oakley_enc_names,
	.ikev1_esp_enum_names = &esp_transformid_names,
	.ikev2_enum_names = &ikev2_trans_type_encr_names,
	.desc_check = encrypt_desc_check,
	.desc_is_ike = encrypt_desc_is_ike,
};

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
		 * Fudge up the ALL and IKE tables so that they only
		 * contain the previously verified algorithms.
		 */
		struct type_algorithms scratch = *algorithms;
		scratch.all.end = algp;
		scratch.ike = scratch.all;
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
	 * For simplicity, the IKE table is overallocated a little.
	 */
	size_t count = algorithms->all.end - algorithms->all.start;
	const struct ike_alg **ike_table = alloc_things(const struct ike_alg *,
							count, "ike_algorithms");
	size_t sizeof_name = strlen("IKE") + 1 + strlen(algorithms->all.name) + 1;
	char *name = alloc_things(char, sizeof_name, "ike name");
	snprintf(name, sizeof_name, "IKE %s", algorithms->all.name);
	algorithms->ike = (struct algorithm_table) {
		.start = ike_table,
		.end = ike_table,
		.name = name,
	};

	FOR_EACH_IKE_ALGP(&algorithms->all, algp) {
		const struct ike_alg *alg = *algp;

		const char *ike_enabled;
		passert(algorithms->desc_is_ike);
		if (algorithms->desc_is_ike(alg)) {
			*algorithms->ike.end++ = alg;
			ike_enabled = "ENABLED";
		} else {
			ike_enabled = "DISABLED (not supported)";
		}
		const char *esp_enabled = "ENABLED"; /* for now */

		libreswan_log("%s algorithm %s: IKE: %s; ESP/AH: %s%s",
			      algorithms->all.name, alg->name,
			      ike_enabled, esp_enabled,
			      alg->fips ? "; FIPS compliant" : "");
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
