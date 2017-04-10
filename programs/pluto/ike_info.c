/*
 * Algorithm info parsing and creation functions
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 *
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2015-2016 Andrew Cagney <cagney@gnu.org>
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

#include <limits.h>

#include "lswlog.h"
#include "lswalloc.h"
#include "alg_byname.h"

#include "alg_info.h"
#include "ike_alg.h"
#include "ike_alg_dh.h"
#include "ike_alg_aes.h"
#include "ike_alg_3des.h"
#include "ike_alg_sha1.h"
#include "ike_alg_sha2.h"
#include "ike_alg_md5.h"

#include "plutoalg.h" /* XXX: for ikev1_default_ike_info() */

static int snprint_ike_info(char *buf, size_t buflen, struct ike_info *ike_info,
			    bool fix_zero)
{
	const struct encrypt_desc *enc_desc = ike_info->ike_encrypt;
	passert(!fix_zero || enc_desc != NULL);
	const struct prf_desc *prf_desc = ike_info->ike_prf;
	passert(!fix_zero || prf_desc != NULL);

	int eklen = ike_info->ike_eklen;
	if (fix_zero && eklen == 0)
		eklen = enc_desc->keydeflen;

	struct esb_buf enc_buf, hash_buf, group_buf;
	return snprintf(buf, buflen,
			"%s(%d)_%03d-%s(%d)-%s(%d)",
			enum_show_shortb(&oakley_enc_names,
					 ike_info->ike_encrypt->common.ikev1_oakley_id,
					 &enc_buf),
			ike_info->ike_encrypt->common.ikev1_oakley_id, eklen,
			enum_show_shortb(&oakley_hash_names,
					 ike_info->ike_prf->common.ikev1_oakley_id,
					 &hash_buf),
			ike_info->ike_prf->common.ikev1_oakley_id,
			enum_show_shortb(&oakley_group_names,
					 ike_info->ike_dh_group->group,
					 &group_buf),
			ike_info->ike_dh_group->group);
}

void alg_info_snprint_ike_info(char *buf, size_t buflen,
			       struct ike_info *ike_info)
{
	snprint_ike_info(buf, buflen, ike_info, FALSE);
}

void alg_info_snprint_ike(char *buf, size_t buflen,
			  struct alg_info_ike *alg_info)
{
	char *ptr = buf;
	const char *sep = "";

	FOR_EACH_IKE_INFO(alg_info, ike_info) {
		if (ike_info->ike_encrypt != NULL &&
		    ike_info->ike_prf != NULL &&
		    ike_info->ike_dh_group != NULL) {
			if (strlen(sep) >= buflen) {
				DBG_log("alg_info_snprint_ike: buffer too short for separator");
				break;
			}
			strcpy(ptr, sep);
			ptr += strlen(sep);
			buflen -= strlen(sep);
			int ret = snprint_ike_info(ptr, buflen, ike_info, TRUE);
			if (ret < 0 || (size_t)ret >= buflen) {
				DBG_log("alg_info_snprint_ike: buffer too short for snprintf");
				break;
			}
			ptr += ret;
			buflen -= ret;
			sep = ", ";
		}
	}
}

/* snprint already parsed transform list (alg_info) */

void alg_info_ike_snprint(char *buf, size_t buflen,
			  const struct alg_info_ike *alg_info_ike)
{
	char *ptr = buf;
	char *be = buf + buflen;

	passert(buflen > 0);

	const char *sep = "";
	FOR_EACH_IKE_INFO(alg_info_ike, ike_info) {
		snprintf(ptr, be - ptr,
			 "%s%s(%d)_%03d-%s(%d)-%s(%d)",
			 sep, enum_short_name(&oakley_enc_names,
					      ike_info->ike_encrypt->common.ikev1_oakley_id),
			 ike_info->ike_encrypt->common.ikev1_oakley_id,
			 (int)ike_info->ike_eklen,
			 enum_short_name(&oakley_hash_names,
					 ike_info->ike_prf->common.ikev1_oakley_id),
			 ike_info->ike_prf->common.ikev1_oakley_id,
			 enum_short_name(&oakley_group_names,
					 ike_info->ike_dh_group->group),
			 ike_info->ike_dh_group->group
			);
		ptr += strlen(ptr);
		sep = ", ";
	}
}

/**
 *      Search oakley_enc_names for a match, eg:
 *              "3des_cbc" <=> "OAKLEY_3DES_CBC"
 *
 * @param str String containing ALG name (eg: AES, 3DES)
 * @return int Registered # of ALG if loaded or -1 on failure.
 */
static int ealg_getbyname_ike(const char *const str)
{
	if (str == NULL || *str == '\0')
		return -1;
	int ret = alg_enum_search(&oakley_enc_names, "OAKLEY_", "", str);
	if (ret < 0)
		ret = alg_enum_search(&oakley_enc_names, "OAKLEY_", "_CBC", str);
	return ret;
}

/**
 *      Search  oakley_hash_names for a match, eg:
 *              "md5" <=> "OAKLEY_MD5"
 * @param str String containing Hash name (eg: MD5, SHA1)
 * @param len Length of str (note: not NUL-terminated)
 * @return int Registered # of Hash ALG if loaded.
 */
static int aalg_getbyname_ike(const char *str)
{
	DBG(DBG_CONTROL, DBG_log("entering aalg_getbyname_ike()"));
	if (str == NULL || str == '\0')
		return -1;

	int ret = alg_enum_search(&oakley_hash_names, "OAKLEY_", "",  str);
	if (ret >= 0)
		return ret;

	/* Special value for no authentication since zero is already used. */
	if (strcaseeq(str, "null"))
		return INT_MAX;

	return -1;
}

/*
 * Raw add routine: only checks for no duplicates
 */
/* ??? much of this code is the same as raw_alg_info_esp_add (same bugs!) */
static void raw_alg_info_ike_add(struct alg_info_ike *alg_info,
				 const struct encrypt_desc *ealg, unsigned ek_bits,
				 const struct prf_desc *aalg,
				 const struct oakley_group_desc *dh_group)
{
	/*
	 * Check for overflows up front; could delay until after
	 * filters, but that complicates things.
	 */
	pexpect((unsigned) alg_info->ai.alg_info_cnt < elemsof(alg_info->ike));
	if ((unsigned)alg_info->ai.alg_info_cnt >= elemsof(alg_info->ike)) {
		loglog(RC_LOG_SERIOUS, "more than %zu IKE algorithms specified",
		       elemsof(alg_info->ike));
		/* drop it like a rock */
		return;
	}

	/*
	 * Initialize the new entry and use it as scratch.  If there's
	 * a problem just return.  Only when everything checks out is
	 * it added.
	 */
	struct ike_info *new_info = alg_info->ike + alg_info->ai.alg_info_cnt;
	*new_info = (struct ike_info) {
		.ike_eklen = ek_bits,
		.ike_encrypt = ealg,
		.ike_prf = aalg,
		.ike_dh_group = dh_group,
	};

	/*
	 * Check that the ALG_INFO spec is implemented as IKE_ALG.
	 *
	 * XXX: Should this also be filtering out IKEv1 and IKEv2 only
	 * algorithms?
	 *
	 * For the case of alg=0 / "null", should this have a real
	 * object?
	 *
	 * XXX: work-in-progress
	 */
	passert(new_info->ike_encrypt != NULL);
	passert(ike_alg_is_ike(&(new_info->ike_encrypt->common)));
	if (ek_bits != 0) {
		if (!encrypt_has_key_bit_length(new_info->ike_encrypt,
						ek_bits)) {
			loglog(RC_LOG_SERIOUS,
			       "ENCRYPT algorithm %s with key length %u is not supported",
			       new_info->ike_encrypt->common.name,
			       ek_bits);
			return;
		}
	}

	passert(new_info->ike_prf != NULL);

	if (ike_alg_enc_requires_integ(new_info->ike_encrypt)) {
		for (const struct integ_desc **algp = next_integ_desc(NULL);
		     algp != NULL; algp = next_integ_desc(algp)) {
			const struct integ_desc *alg = *algp;
			if (ike_alg_is_ike(&(alg)->common)
			    && alg->prf == new_info->ike_prf) {
				new_info->ike_integ = alg;
				break;
			}
		}
		if (new_info->ike_integ == NULL) {
			loglog(RC_LOG_SERIOUS,
			       "INTEG algorithm %s is not supported",
			       new_info->ike_prf->common.name);
			return;
		}
	}

	passert(new_info->ike_dh_group != NULL);

	/*
	 * don't add duplicates
	 *
	 * ??? why is 0 wildcard for ek_bits and ak_bits?
	 *
	 * keylen==0 is magic implying all key lengths should be
	 * included; so a zero key-length duplicates anything
	 *
	 * Perform the check after the algorithms have been found so
	 * that duplicates can be identified by simply comparing
	 * opaque pointers.
	 *
	 * XXX: work-in-progress
	 */
	FOR_EACH_IKE_INFO(alg_info, ike_info) {
		if (ike_info->ike_encrypt == new_info->ike_encrypt &&
		    (new_info->ike_eklen == 0 ||
		     ike_info->ike_eklen == new_info->ike_eklen) &&
		    ike_info->ike_prf == new_info->ike_prf &&
		    ike_info->ike_integ == new_info->ike_integ &&
		    ike_info->ike_dh_group == new_info->ike_dh_group) {
			return;
		}
	}

	/*
	 * All is good, add it.
	 */
	alg_info->ai.alg_info_cnt++;
	DBG(DBG_CRYPT,
	    DBG_log("raw_alg_info_ike_add() ealg=%s ek_bits=%d aalg=%s modp=%s, cnt=%d",
		    new_info->ike_encrypt->common.name, ek_bits,
		    new_info->ike_prf->common.name,
		    new_info->ike_dh_group->common.name,
		    alg_info->ai.alg_info_cnt));
}

/*
 * "ike_info" proposals are built built by first parsing the ike=
 * line, and second merging it with the below defaults when an
 * algorithm wasn't specified.
 *
 * Do not assume that these hard wired algorithms are actually valid.
 */

static const struct ike_alg *default_ikev1_groups[] = {
	&oakley_group_modp2048.common,
	&oakley_group_modp1536.common,
	NULL,
};
static const struct ike_alg *default_ikev2_groups[] = {
	&oakley_group_modp2048.common,
	NULL,
};

static const struct ike_alg *default_ike_ealgs[] = {
	&ike_alg_encrypt_aes_cbc.common,
	&ike_alg_encrypt_3des_cbc.common,
	NULL,
};

static const struct ike_alg *default_ike_aalgs[] = {
	&ike_alg_prf_sha2_256.common,
	&ike_alg_prf_sha2_512.common,
	&ike_alg_prf_sha1.common,
	&ike_alg_prf_md5.common,
	NULL,
};

struct alg_defaults {
	const struct ike_alg **ikev1;
	const struct ike_alg **ikev2;
};

struct ike_defaults {
	struct alg_defaults groups;
	struct alg_defaults ealgs;
	struct alg_defaults aalgs;
};

static const struct ike_defaults ike_defaults = {
	.groups = {
		.ikev1 = default_ikev1_groups,
		.ikev2 = default_ikev2_groups,
	},
	.ealgs = {
		.ikev1 = default_ike_ealgs,
		.ikev2 = default_ike_ealgs,
	},
	.aalgs = {
		.ikev1 = default_ike_aalgs,
		.ikev2 = default_ike_aalgs,
	},
};

/*
 * Given a list of default IKEv1/IKEv2 algorithms, allocate and return
 * the valid and selected subset of those algorithms.
 *
 * Or NULL if there are none.
 */
static const struct ike_alg **clone_valid(enum ike_alg_type type,
					  const struct parser_policy *policy,
					  const struct alg_defaults *algs)
{
	/*
	 * If there's a hint of IKEv1 being enabled then prefer its
	 * larger set of defaults.
	 *
	 * This should increase the odds of both ends interoperating.
	 * For instance, if IKEv2 defaults are preferred and one end
	 * has ikev2=never then, in aggressive mode, things don't work.
	 */
	const struct ike_alg **default_algs = (policy->ikev1
					       ? algs->ikev1
					       : algs->ikev2);

	/*
	 * Allocate the cloned array.  Keep things simple by assuming
	 * it is the same size as the original.
	 */
	int count = 1;
	for (const struct ike_alg **default_alg = default_algs;
	     *default_alg; default_alg++) {
		passert((*default_alg)->algo_type == type);
		count++;
	}
	const struct ike_alg **valid_algs = alloc_things(const struct ike_alg*, count,
							 "valid algs");

	/*
	 * Use VALID_ALG to add the valid algorithms into VALID_ALGS.
	 */
	const struct ike_alg **valid_alg = valid_algs;
	for (const struct ike_alg **default_alg = default_algs;
	     *default_alg; default_alg++) {
		const struct ike_alg *alg = *default_alg;
		/*
		 * Check that all the enabled protocols are
		 * supported.
		 *
		 * Done first since it is quick and fast.
		 */
		if (policy->ikev1 && alg->ikev1_oakley_id == 0) {
			DBG(DBG_CONTROL|DBG_CRYPT,
			    DBG_log("skipping default %s %s, missing ikev1 support",
				    ike_alg_type_name(type),
				    alg->name));
			continue;
		}
		if (policy->ikev2 && alg->id[IKEv2_ALG_ID] == 0) {
			DBG(DBG_CONTROL|DBG_CRYPT,
			    DBG_log("skipping default %s %s, missing ikev2 support",
				    ike_alg_type_name(type),
				    alg->name));
			continue;
		}
		/*
		 * Check that the algorithm is backed by an IKE
		 * (native) implementation.
		 *
		 * Having a valid ID (checked above) isn't sufficient.
		 * For instance, an IKEv2 ESP only algorithm will have
		 * a valid IKEv2 ID.
		 */
		if (!ike_alg_is_ike(alg)) {
			DBG(DBG_CONTROL|DBG_CRYPT,
			    DBG_log("skipping default %s %s, missing IKE implementation",
				    ike_alg_type_name(type),
				    alg->name));
			continue;
		}
		/*
		 * Check that the algorithm is valid.
		 *
		 * FIPS, for instance, will invalidate some algorithms
		 * during startup.
		 *
		 * Since it likely involves a lookup, it is left until
		 * last.
		 */
		if (!ike_alg_is_valid(alg)) {
			DBG(DBG_CONTROL|DBG_CRYPT,
			    DBG_log("skipping default %s %s, invalid",
				    ike_alg_type_name(type),
				    alg->name));
			continue;
		}
		DBG(DBG_CONTROL|DBG_CRYPT,
		    DBG_log("adding default %s %s",
			    ike_alg_type_name(type),
			    alg->name));
		/* save it */
		*valid_alg++ = alg;
	}
	*valid_alg = NULL;

	/*
	 * If, after filtering, nothing was added, return NULL rather
	 * than an empty array.
	 *
	 * Will this this ever happen? I.e., passert()?
	 */
	if (valid_alg == valid_algs) {
		pfree(valid_algs);
		loglog(RC_LOG_SERIOUS,
		       "no valid default %s algorithms",
		       ike_alg_type_name(type));
		return NULL;
	}

	return valid_algs;
}

/*
 * _Recursively_ add IKE alg info _with_ logic (policy) using
 * IKE_DEFAULTS.
 */

static void ike_add(const struct parser_policy *const policy,
		    const struct ike_defaults *const defaults,
		    struct alg_info *alg_info,
		    const struct encrypt_desc *ealg, int ek_bits,
		    const struct prf_desc *aalg,
		    const struct oakley_group_desc *dh_group)
{
	/*
	 * Note that the order in which things are recursively added -
	 * MODP, ENCR, PRF/HASH - affects test results.  It determines
	 * things like the order of proposals.
	 *
	 * See parser_alg_info_add().  It seems that modp_id=0,
	 * ealg_id=-1, aalg_id=-1, so check for anything <= 0.
	 */
	if (dh_group == NULL) {
		/*
		 * Recursively add the valid default groups.
		 */
		const struct ike_alg **valid_algs = clone_valid(IKE_ALG_DH, policy,
								&defaults->groups);
		if (valid_algs == NULL) {
			return;
		}
		for (const struct ike_alg **alg = valid_algs;
		     *alg; alg++) {
			ike_add(policy, defaults, alg_info,
				ealg, ek_bits,
				aalg, oakley_group_desc(*alg));
		}
		pfree(valid_algs);
	} else if (ealg == NULL) {
		/*
		 * Recursively add the valid default enc algs
		 */
		const struct ike_alg **valid_algs = clone_valid(IKE_ALG_ENCRYPT, policy,
								&defaults->ealgs);
		if (valid_algs == NULL) {
			return;
		}
		for (const struct ike_alg **alg = valid_algs;
		     *alg; alg++) {
			ike_add(policy, defaults, alg_info,
				encrypt_desc(*alg), ek_bits,
				aalg, dh_group);
		}
		pfree(valid_algs);
	} else if (aalg == NULL) {
		/*
		 * Recursively add the valid default PRF/HASH
		 * algorithms.
		 *
		 * Even AEAD algorithms need a PRF.
		 */
		const struct ike_alg **valid_algs = clone_valid(IKE_ALG_PRF, policy,
								&defaults->aalgs);
		if (valid_algs == NULL) {
			return;
		}
		for (const struct ike_alg **alg = valid_algs;
		     *alg; alg++) {
			ike_add(policy, defaults, alg_info,
				ealg, ek_bits,
				prf_desc(*alg), dh_group);
		}
		pfree(valid_algs);
	} else {
		raw_alg_info_ike_add((struct alg_info_ike *)alg_info,
				     ealg, ek_bits,
				     aalg, dh_group);
	}
}

struct alg_info_ike *ikev1_default_ike_info(void)
{
	static const struct ike_alg *default_ikev1_groups[] = {
		&oakley_group_modp2048.common,
		&oakley_group_modp1536.common,
		NULL,
	};
	static const struct ike_alg *default_ikev1_ealgs[] = {
		&ike_alg_encrypt_aes_cbc.common,
		&ike_alg_encrypt_3des_cbc.common,
		NULL,
	};
	static const struct ike_alg *default_ikev1_aalgs[] = {
		&ike_alg_prf_sha1.common,
		NULL,
	};
	static const struct ike_defaults spdb_defaults = {
		.groups = {
			.ikev1 = default_ikev1_groups,
		},
		.ealgs = {
			.ikev1 = default_ikev1_ealgs,
		},
		.aalgs = {
			.ikev1 = default_ikev1_aalgs,
		},
	};

	static const struct parser_policy policy = {
		.ikev1 = TRUE,
	};

	struct alg_info_ike *default_info = alloc_thing(struct alg_info_ike, "ike_info");
	ike_add(&policy, &spdb_defaults, &default_info->ai,
		NULL, 0, NULL, NULL);
	return default_info;
}

static void alg_info_ike_add(const struct parser_policy *const policy,
			     struct alg_info *alg_info,
			     int ealg_id, int ek_bits,
			     int aalg_id,
			     const struct oakley_group_desc *dh_group)
{
	/*
	 * Check that the ALG_INFO spec is implemented as IKE_ALG.
	 *
	 * XXX: Should this also be filtering out IKEv1 and IKEv2 only
	 * algorithms?
	 *
	 * For the case of alg=0 / "null", should this have a real
	 * object?
	 *
	 * XXX: work-in-progress
	 */
	const struct encrypt_desc *ealg = NULL;
	if (ealg_id > 0) {
		for (const struct encrypt_desc **algp = next_encrypt_desc(NULL);
		     algp != NULL; algp = next_encrypt_desc(algp)) {
			const struct encrypt_desc *alg = *algp;
			/*
			 * keylen==0 implies use default or defaults.
			 */
			if (ike_alg_is_ike(&(alg)->common)
			    && alg->common.ikev1_oakley_id == ealg_id) {
				ealg = alg;
				break;
			}
		}
		if (ealg == NULL) {
			struct esb_buf buf;
			loglog(RC_LOG_SERIOUS,
			       "ENCRYPT algorithm %s=%d is not supported",
			       enum_showb(&oakley_enc_names, ealg_id, &buf),
			       ealg_id);
			return;
		}
		if (ek_bits != 0) {
			if (!encrypt_has_key_bit_length(ealg, ek_bits)) {
				struct esb_buf buf;
				loglog(RC_LOG_SERIOUS,
				       "ENCRYPT algorithm %s with key length %u is not supported",
				       enum_showb(&oakley_enc_names, ealg_id, &buf),
				       ek_bits);
				return;
			}
		}
	}

	const struct prf_desc *aalg = NULL;
	if (aalg_id > 0) {
		for (const struct prf_desc **algp = next_prf_desc(NULL);
		     algp != NULL; algp = next_prf_desc(algp)) {
			const struct prf_desc *alg = *algp;
			if (ike_alg_is_ike(&(alg)->common)
			    && alg->common.ikev1_oakley_id == aalg_id) {
				aalg = alg;
				break;
			}
		}
		if (aalg == NULL) {
			struct esb_buf buf;
			loglog(RC_LOG_SERIOUS,
			       "PRF algorithm %s=%d is not supported",
			       enum_show_shortb(&oakley_hash_names, aalg_id, &buf),
			       aalg_id);
			return;
		}
	}

	ike_add(policy, &ike_defaults, alg_info,
		ealg, ek_bits, aalg, dh_group);
}

const struct parser_param ike_parser_param = {
	.protocol = "IKE",
	.ikev1_alg_id = IKEv1_OAKLEY_ID,
	.protoid = PROTO_ISAKMP,
	.alg_info_add = alg_info_ike_add,
	.ealg_getbyname = ealg_getbyname_ike,
	.aalg_getbyname = aalg_getbyname_ike,
	.group_byname = dh_alg_byname,
};

struct alg_info_ike *alg_info_ike_create_from_str(lset_t policy,
						  const char *alg_str,
						  char *err_buf, size_t err_buf_len)
{
	/*
	 *      alg_info storage should be sized dynamically
	 *      but this may require two passes to know
	 *      transform count in advance.
	 */
	struct alg_info_ike *alg_info_ike = alloc_thing(struct alg_info_ike, "alg_info_ike");

	return (struct alg_info_ike *)
		alg_info_parse_str(policy,
				   &alg_info_ike->ai,
				   alg_str,
				   err_buf, err_buf_len,
				   &ike_parser_param);
}
