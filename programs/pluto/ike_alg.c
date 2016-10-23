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
#include "defs.h"
#include "lswfips.h"

#include "log.h"
#include "alg_info.h"
#include "ike_alg.h"

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

#define FOR_EACH_IKE_ALGP(ALGORITHMS,A)					\
	for (const struct ike_alg **(A) = (ALGORITHMS).descriptors;		\
	     *(A) != NULL;						\
	     (A)++)

struct type_algorithms {
	const struct ike_alg **descriptors;
	enum ike_alg_type type;
	const char *const type_name;
	enum_names *const ikev1_enum_names;
	enum_names *const ikev2_enum_names;
	bool (*check_algorithm)(const struct ike_alg*);
};

static const struct type_algorithms prf_algorithms;
static const struct type_algorithms integ_algorithms;
static const struct type_algorithms encrypt_algorithms;

static const struct ike_alg **next_alg(const struct ike_alg **first,
				       const struct ike_alg **last)
{
	if (last == NULL) {
		return first;
	}
	passert(last >= first);
	last++;
	/* last < end */
	if (*last == NULL) {
		return NULL;
	}
	return last;
}

const struct encrypt_desc **next_ike_encrypt_desc(const struct encrypt_desc **last)
{
	return (const struct encrypt_desc**)next_alg(encrypt_algorithms.descriptors,
						     (const struct ike_alg**)last);
}

const struct hash_desc **next_ike_prf_desc(const struct hash_desc **last)
{
	return (const struct hash_desc**)next_alg(prf_algorithms.descriptors,
						  (const struct ike_alg**)last);
}

bool ike_alg_enc_requires_integ(const struct encrypt_desc *enc_desc)
{
	return enc_desc != NULL && enc_desc->do_aead_crypt_auth == NULL;
}

bool ike_alg_enc_present(int ealg)
{
	const struct encrypt_desc *enc_desc = ikev1_alg_get_encrypter(ealg);

	return enc_desc != NULL && enc_desc->enc_blocksize != 0;
}

/*	check if IKE hash algo is present */
bool ike_alg_hash_present(int halg)
{
	const struct hash_desc *hash_desc = ikev1_alg_get_hasher(halg);

	return hash_desc != NULL && hash_desc->hash_digest_len != 0;
}

/*
 *      return ike_algo object by {type, id}
 */

static const struct ike_alg *ikev1_lookup(const struct type_algorithms *algorithms,
					  unsigned id)
{
	FOR_EACH_IKE_ALGP(*algorithms, algp) {
		const struct ike_alg *e = *algp;
		if (e->algo_id == id) {
			DBG(DBG_CRYPT, DBG_log("%s lookup by IKEv1 id: %u, found %s\n",
					       algorithms->type_name, id, e->name));
			return e;
		}
	}
	DBG(DBG_CRYPT, DBG_log("%s lookup by IKEv1 id:%u, not found\n",
			       algorithms->type_name, id));
	return NULL;
}

const struct hash_desc *ikev1_alg_get_hasher(int alg)
{
	return (const struct hash_desc *) ikev1_lookup(&prf_algorithms, alg);
}

const struct encrypt_desc *ikev1_alg_get_encrypter(int alg)
{
	return (const struct encrypt_desc *) ikev1_lookup(&encrypt_algorithms, alg);
}

static const struct ike_alg *ikev2_lookup(const struct type_algorithms *algorithms,
					  unsigned id)
{
	FOR_EACH_IKE_ALGP(*algorithms, algp) {
		const struct ike_alg *e = *algp;
		if (e->algo_v2id == id) {
			DBG(DBG_CRYPT, DBG_log("%s lookup by IKEv2 id: %u, found %s\n",
					       algorithms->type_name, id, e->name));
			return e;
		}
	}
	DBG(DBG_CRYPT, DBG_log("%s lookup by IKEv2 id:%u, not found\n",
			       algorithms->type_name, id));
	return NULL;
}

const struct encrypt_desc *ikev2_alg_get_encrypter(int id)
{
	/*
	 * these types are mixed up, so go along with it :(
	 * IKEv2_ENCR_CAMELLIA_CBC_ikev1 == ESP_CAMELLIAv1
	 * IKEv2_ENCR_CAMELLIA_CBC == ESP_CAMELLIA
	 */
	if (id == IKEv2_ENCR_CAMELLIA_CBC_ikev1)
		id = IKEv2_ENCR_CAMELLIA_CBC;

	return (const struct encrypt_desc *) ikev2_lookup(&encrypt_algorithms, id);
}

const struct hash_desc *ikev2_alg_get_hasher(int id)
{
	return (const struct hash_desc *) ikev2_lookup(&prf_algorithms, id);
}

const struct hash_desc *ikev2_alg_get_integ(int id)
{
	return (const struct hash_desc *) ikev2_lookup(&integ_algorithms, id);
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

static struct hash_desc *prf_descriptors[] = {
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
#ifdef USE_AES
	&ike_alg_prf_aes_xcbc,
#endif
	NULL,
};

static bool check_prf_algorithm(const struct ike_alg *alg)
{
	const struct hash_desc *prf = (const struct hash_desc*)alg;
	passert(prf->hash_ctx_size <= sizeof(union hash_ctx));
	passert(prf->hash_init != NULL);
	passert(prf->hash_update != NULL);
	passert(prf->hash_final != NULL);
	return TRUE;
}

static const struct type_algorithms prf_algorithms = {
	.descriptors = (const struct ike_alg**)prf_descriptors,
	.type = IKE_ALG_HASH,
	.type_name = "PRF",
	.ikev1_enum_names = &oakley_hash_names,
	.ikev2_enum_names = &ikev2_trans_type_prf_names,
	.check_algorithm = check_prf_algorithm,
};

/*
 * Integrity.
 */

static struct hash_desc *integ_descriptors[] = {
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
#ifdef NOT_YET
	&ike_alg_integ_aes_xcbc,
#endif
#endif
	NULL,
};

static bool check_integ_algorithm(const struct ike_alg *alg)
{
	const struct hash_desc *integ = (const struct hash_desc*)alg;
	passert(integ->hash_integ_len > 0);
	return check_prf_algorithm(alg);
}

static const struct type_algorithms integ_algorithms = {
	.descriptors = (const struct ike_alg**)integ_descriptors,
	.type = IKE_ALG_INTEG,
	.type_name = "Integrity",
	/*
	 * IKEv1 uses the same HASH names for PRF and INTEG.
	 */
	.ikev1_enum_names = &oakley_hash_names,
	.ikev2_enum_names = &ikev2_trans_type_integ_names,
	.check_algorithm = check_integ_algorithm,
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
	NULL,
};

static bool check_encrypt_algorithm(const struct ike_alg *alg UNUSED)
{
	return TRUE;
}

static const struct type_algorithms encrypt_algorithms = {
	.descriptors = (const struct ike_alg**)encrypt_descriptors,
	.type_name = "Encryption",
	.type = IKE_ALG_ENCRYPT,
	.ikev1_enum_names = &oakley_enc_names,
	.ikev2_enum_names = &ikev2_trans_type_encr_names,
	.check_algorithm = check_encrypt_algorithm,
};

static void add_algorithms(bool fips, const struct type_algorithms *algorithms)
{
	const struct ike_alg **end = algorithms->descriptors;

	for (const struct ike_alg **algp = algorithms->descriptors; (*algp) != NULL; algp++) {
		/*
		 * Remove the next algorith to be tested, and NULL its
		 * entry.  This ensures that local lookups for this
		 * algorithm don't include this or following
		 * algorithms.
		 *
		 * If this algorithm passes it will be re-inserted at
		 * END.  END<=algp.
		 */
		const struct ike_alg *alg = *algp;
		*algp = NULL;

		DBG(DBG_CRYPT, DBG_log("%s algorithm %s; official name: %s, id: %d, v2id: %d",
				       algorithms->type_name, alg->name, alg->officname,
				       alg->algo_id, alg->algo_v2id));
		passert(alg->name);
		passert(alg->officname);

		/*
		 * passert(alg->algo_type >= 0 && alg->algo_type < IKE_ALG_ROOF);
		 *
		 * Avoid the bogus GCC 4.4 warning: "comparison of
		 * unsigned expression >= 0 is always true" by forcing
		 * the value to unsigned and testing that.  ISO C
		 * considers the integral type (sign, size) used to
		 * represent an enum implementation dependent, the GCC
		 * manual claims to use "signed int" by default.
		 */
		passert((unsigned)alg->algo_type < IKE_ALG_ROOF);
		passert(alg->algo_type == algorithms->type);

		/*
		 * Validate an IKE_ALG's IKEv1 and IKEv2 enum_name
		 * entries.
		 *
		 * struct ike_alg_encrypt_aes_ccm_8 et.al. do not
		 * define the IKEv1 field "common.algo_id" so need to
		 * handle that.
		 */
		passert(alg->algo_id > 0 || alg->algo_v2id > 0);
		if (alg->algo_id > 0) {
			passert(algorithms->ikev1_enum_names != NULL);
			const char *name = enum_name(algorithms->ikev1_enum_names, alg->algo_id);
			passert(name);
			DBG(DBG_CRYPT, DBG_log("id: %d IKEv1 enum name: %s",
					       alg->algo_id, name));
		}
		if (alg->algo_v2id > 0) {
			passert(algorithms->ikev2_enum_names != NULL);
			const char *name = enum_name(algorithms->ikev2_enum_names, alg->algo_v2id);
			passert(name);
			DBG(DBG_CRYPT, DBG_log("v2id: %d IKEv2 enum name: %s",
					       alg->algo_v2id, name));
		}

		/*
		 * Algorithm can't appear twice.
		 */
		passert(alg->algo_id == 0 || ikev1_lookup(algorithms, alg->algo_id) == NULL);
		passert(alg->algo_v2id == 0 || ikev2_lookup(algorithms, alg->algo_v2id) == NULL);

		/*
		 * Any other algorithm-type specific checks.
		 */
		if (!algorithms->check_algorithm(alg)) {
			libreswan_log("%s algorithm %s: DISABLED; internal check failed",
				      algorithms->type_name, alg->name);
			continue;
		}

		/*
		 * Check FIPS before trying to run any tests.
		 */
		if (fips && !alg->fips) {
			libreswan_log("%s algorithm %s: DISABLED; not FIPS compliant",
				      algorithms->type_name, alg->name);
			continue;
		}

		if (alg->do_test && !alg->do_test(alg)) {
			libreswan_log("%s algorithm %s: DISABLED; testing failed",
				      algorithms->type_name, alg->name);
			continue;
		}

		/* append to validated list */
		*end++ = alg;

		libreswan_log("%s algorithm %s: ENABLED%s%s",
			      algorithms->type_name, alg->name,
			      alg->fips ? "; FIPS compliant" : "",
			      alg->do_test ? "; tested" : "");

	}
}

void ike_alg_init(void)
{
#ifdef FIPS_CHECK
	bool fips = libreswan_fipsmode();
#else
	bool fips = FALSE;
#endif
	add_algorithms(fips, &encrypt_algorithms);
	add_algorithms(fips, &prf_algorithms);
	add_algorithms(fips, &integ_algorithms);
}
