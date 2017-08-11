/*
 * Algorithm info parsing and creation functions
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 *
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2015-2017 Andrew Cagney
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

#include "ike_alg.h"
#include "ike_alg_dh.h"
#include "ike_alg_aes.h"
#include "ike_alg_3des.h"
#include "ike_alg_sha1.h"
#include "ike_alg_sha2.h"
#include "ike_alg_null.h"
#include "alg_info.h"

#include "plutoalg.h" /* XXX: for ikev1_default_ike_info() */

static int snprint_ike_info(char *buf, size_t buflen,
			    const struct proposal_info *ike_info,
			    bool fix_zero)
{
	const struct encrypt_desc *enc_desc = ike_info->encrypt;
	passert(!fix_zero || enc_desc != NULL);
	const struct prf_desc *prf_desc = ike_info->prf;
	passert(!fix_zero || prf_desc != NULL);

	int eklen = ike_info->enckeylen;
	if (fix_zero && eklen == 0)
		eklen = enc_desc->keydeflen;

	struct esb_buf enc_buf, hash_buf, group_buf;
	return snprintf(buf, buflen,
			"%s(%d)_%03d-%s(%d)-%s(%d)",
			enum_show_shortb(&oakley_enc_names,
					 ike_info->encrypt->common.ikev1_oakley_id,
					 &enc_buf),
			ike_info->encrypt->common.ikev1_oakley_id, eklen,
			enum_show_shortb(&oakley_hash_names,
					 ike_info->prf->common.ikev1_oakley_id,
					 &hash_buf),
			ike_info->prf->common.ikev1_oakley_id,
			enum_show_shortb(&oakley_group_names,
					 ike_info->dh->group,
					 &group_buf),
			ike_info->dh->group);
}

void alg_info_snprint_ike_info(char *buf, size_t buflen,
			       const struct proposal_info *ike_info)
{
	snprint_ike_info(buf, buflen, ike_info, FALSE);
}

void alg_info_snprint_ike(char *buf, size_t buflen,
			  struct alg_info_ike *alg_info)
{
	if (alg_info == NULL) {
		PEXPECT_LOG("%s", "parameter alg_info unexpectedly NULL");
		/* return some bogus output */
		snprintf(buf, buflen,
			 "OOPS, parameter alg_info unexpectedly NULL");
		return;
	}

	char *ptr = buf;
	const char *sep = "";

	FOR_EACH_IKE_INFO(alg_info, ike_info) {
		if (ike_info->encrypt != NULL &&
		    ike_info->prf != NULL &&
		    ike_info->dh != NULL) {
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
	if (alg_info_ike == NULL) {
		PEXPECT_LOG("%s", "parameter alg_info_ike unexpectedly NULL");
		/* return some bogus output */
		snprintf(buf, buflen,
			 "OOPS, parameter alg_info unexpectedly NULL");
		return;
	}

	char *ptr = buf;
	char *be = buf + buflen;

	passert(buflen > 0);

	const char *sep = "";
	FOR_EACH_IKE_INFO(alg_info_ike, ike_info) {
		snprintf(ptr, be - ptr,
			 "%s%s(%d)_%03d-%s(%d)-%s(%d)",
			 sep, enum_short_name(&oakley_enc_names,
					      ike_info->encrypt->common.ikev1_oakley_id),
			 ike_info->encrypt->common.ikev1_oakley_id,
			 (int)ike_info->enckeylen,
			 enum_short_name(&oakley_hash_names,
					 ike_info->prf->common.ikev1_oakley_id),
			 ike_info->prf->common.ikev1_oakley_id,
			 enum_short_name(&oakley_group_names,
					 ike_info->dh->group),
			 ike_info->dh->group
			);
		ptr += strlen(ptr);
		sep = ", ";
	}
}

/*
 * Raw add routine: only checks for no duplicates
 */

static const char *raw_alg_info_ike_add(struct alg_info_ike *alg_info,
					const struct encrypt_desc *encrypt, unsigned ek_bits,
					const struct prf_desc *prf,
					const struct integ_desc *integ,
					const struct oakley_group_desc *dh_group,
					char *err_buf, size_t err_buf_len)
{
	/*
	 * Check that the ALG_INFO spec is implemented.
	 */

	passert(ike_alg_is_ike(&(encrypt->common)));
	passert(ek_bits == 0 || encrypt_has_key_bit_length(encrypt, ek_bits));
	passert(ike_alg_is_ike(&(prf->common)));

	/*
	 * This is a little loose.
	 */
	passert(integ != &ike_alg_integ_null || ike_alg_is_aead(encrypt));
	passert(integ == &ike_alg_integ_null || ike_alg_is_ike(&integ->common));

	passert(ike_alg_is_ike(&(dh_group->common)));

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
		if (ike_info->encrypt == encrypt &&
		    (ek_bits == 0 ||
		     ike_info->enckeylen == ek_bits) &&
		    ike_info->prf == prf &&
		    ike_info->integ == integ &&
		    ike_info->dh == dh_group) {
			DBG(DBG_CRYPT,
			    DBG_log("discarding duplicate ealg=%s ek_bits=%d aalg=%s modp=%s",
				    encrypt->common.name, ek_bits,
				    prf->common.name,
				    dh_group->common.name));
			return NULL;
		}
	}

	/*
	 * Finally, check for overflow.
	 */
	pexpect((unsigned) alg_info->ai.alg_info_cnt < elemsof(alg_info->ai.proposals));
	if ((unsigned)alg_info->ai.alg_info_cnt >= elemsof(alg_info->ai.proposals)) {
		snprintf(err_buf, err_buf_len,
			 "more than %zu IKE algorithms specified",
			 elemsof(alg_info->ai.proposals));
		/* drop it like a rock */
		return err_buf;
	}

	/*
	 * All is good, add it.
	 */
	struct proposal_info *new_info = alg_info->ai.proposals + alg_info->ai.alg_info_cnt;
	*new_info = (struct proposal_info) {
		.enckeylen = ek_bits,
		.encrypt = encrypt,
		.prf = prf,
		.integ = integ,
		.dh = dh_group,
	};
	alg_info->ai.alg_info_cnt++;
	DBG(DBG_CRYPT,
	    DBG_log("adding ealg=%s ek_bits=%d aalg=%s modp=%s, cnt=%d",
		    new_info->encrypt->common.name, ek_bits,
		    new_info->prf->common.name,
		    new_info->dh->common.name,
		    alg_info->ai.alg_info_cnt));

	return NULL;
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
static const struct ike_alg **clone_valid(const struct ike_alg_type *type,
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
		DBG(DBG_CONTROL,
		    DBG_log("no valid default %s algorithms",
			    ike_alg_type_name(type)));
		return NULL;
	}

	return valid_algs;
}

/*
 * _Recursively_ add IKE alg info _with_ logic (policy) using
 * IKE_DEFAULTS.
 */

static const char *ike_add(const struct parser_policy *const policy,
			   const struct ike_defaults *const defaults,
			   struct alg_info *alg_info,
			   const struct encrypt_desc *encrypt, int ek_bits,
			   const struct prf_desc *prf,
			   const struct integ_desc *integ,
			   const struct oakley_group_desc *dh_group,
			   char *err_buf, size_t err_buf_len)
{
	/*
	 * Note that the order in which things are recursively added -
	 * MODP, ENCR, PRF/HASH - affects test results.  It determines
	 * things like the order of proposals.
	 */
	if (dh_group == NULL) {
		/*
		 * Recursively add the valid default groups.
		 */
		const struct ike_alg **valid_algs = clone_valid(IKE_ALG_DH, policy,
								&defaults->groups);
		if (valid_algs == NULL) {
			return "no valid DH algorithms";
		}
		const char *error = NULL;
		for (const struct ike_alg **alg = valid_algs;
		     *alg && error == NULL; alg++) {
			error = ike_add(policy, defaults, alg_info,
					encrypt, ek_bits,
					prf, integ, oakley_group_desc(*alg),
					err_buf, err_buf_len);
		}
		pfree(valid_algs);
		return error;
	} else if (encrypt == NULL) {
		/*
		 * Recursively add the valid default enc algs
		 *
		 * If no encryption was specified, ek_bits must be 0.
		 */
		passert(ek_bits == 0);
		const struct ike_alg **valid_algs = clone_valid(IKE_ALG_ENCRYPT, policy,
								&defaults->ealgs);
		if (valid_algs == NULL) {
			return "no valid ENCRYPT algorithms";
		}
		const char *error = NULL;
		for (const struct ike_alg **alg = valid_algs;
		     *alg && error == NULL; alg++) {
			error = ike_add(policy, defaults, alg_info,
					encrypt_desc(*alg), ek_bits,
					prf, integ, dh_group,
					err_buf, err_buf_len);
		}
		pfree(valid_algs);
		return error;
	} else if (prf == NULL) {
		/*
		 * Recursively add the valid default PRF/HASH
		 * algorithms.
		 *
		 * Even AEAD algorithms need a PRF.
		 */
		const struct ike_alg **valid_algs = clone_valid(IKE_ALG_PRF, policy,
								&defaults->aalgs);
		if (valid_algs == NULL) {
			return "no valid PRF algorithms";
		}
		const char *error = NULL;
		for (const struct ike_alg **alg = valid_algs;
		     *alg && error == NULL; alg++) {
			error = ike_add(policy, defaults, alg_info,
					encrypt, ek_bits,
					prf_desc(*alg), integ, dh_group,
					err_buf, err_buf_len);
		}
		pfree(valid_algs);
		return error;
	} else if (integ == NULL) {
		/*
		 * The integrity is missing.
		 *
		 * For instance when parsing "aes" and defaults are
		 * being added for the PRF and integrity.
		 *
		 * Since .integ_byname isn't set in parser_params
		 * (NULL is always passed in), the odds of this
		 * happening are very good.
		 *
		 * Derive the 'default' using the PRF.
		 */
		if (ike_alg_is_aead(encrypt)) {
			integ = &ike_alg_integ_null;
		} else {
			passert(prf != NULL);
			passert(ike_alg_is_ike(&prf->common));
			for (const struct integ_desc **algp = next_integ_desc(NULL);
			     algp != NULL; algp = next_integ_desc(algp)) {
				const struct integ_desc *alg = *algp;
				if (alg->prf == prf) {
					integ = alg;
					break;
				}
			}
			if (integ == NULL) {
				snprintf(err_buf, err_buf_len,
					 "IKE integrity derived from PRF '%s' is not supported",
					 prf->common.name);
				return NULL;
			}
		}
		return ike_add(policy, defaults, alg_info,
			       encrypt, ek_bits,
			       prf, integ, dh_group,
			       err_buf, err_buf_len);
	} else if (integ == &ike_alg_integ_null
		   && !ike_alg_is_aead(encrypt)) {
		/*
		 * For instance, "aes-sha1-null-dh22" is invalid,
		 * while "aes_gcm-sha1-null-dh22" is valid.
		 *
		 * Since .integ_byname isn't set in parser_params
		 * (NULL is always passed in), the odds of this
		 * happening are very small.
		 */
		snprintf(err_buf, err_buf_len,
			 "non-AEAD IKE encryption algorithm '%s' cannot have a 'null' integrity algorithm",
			 encrypt->common.name);
		return NULL;
	} else {
		passert(encrypt != NULL);
		passert(prf != NULL);
		passert(integ != NULL);
		passert(dh_group != NULL);
		return raw_alg_info_ike_add((struct alg_info_ike *)alg_info,
					    encrypt, ek_bits,
					    prf, integ, dh_group,
					    err_buf, err_buf_len);
	}
}

struct alg_info_ike *ikev1_default_ike_info(void)
{
	static const struct parser_policy policy = {
		.ikev1 = TRUE,
	};

	struct alg_info_ike *default_info = alloc_thing(struct alg_info_ike, "ike_info");

	char err_buf[100] = "";
	if (ike_add(&policy, &ike_defaults, &default_info->ai,
		    NULL, 0, NULL, NULL, NULL,
		    err_buf, sizeof(err_buf)) != NULL) {
		PEXPECT_LOG("invalid IKEv1 default algorithms: %s", err_buf);
	}

	return default_info;
}

static const char *alg_info_ike_add(const struct parser_policy *const policy,
				    struct alg_info *alg_info,
				    const struct encrypt_desc *encrypt, int ek_bits,
				    const struct prf_desc *prf,
				    const struct integ_desc *integ,
				    const struct oakley_group_desc *dh_group,
				    char *err_buf, size_t err_buf_len)
{
	return ike_add(policy, &ike_defaults, alg_info,
		       encrypt, ek_bits, prf, integ, dh_group,
		       err_buf, err_buf_len);
}

const struct parser_param ike_parser_param = {
	.protocol = "IKE",
	.ikev1_alg_id = IKEv1_OAKLEY_ID,
	.protoid = PROTO_ISAKMP,
	.alg_info_add = alg_info_ike_add,
	.encrypt_alg_byname = encrypt_alg_byname,
	.prf_alg_byname = prf_alg_byname,
	.dh_alg_byname = dh_alg_byname,
};

struct alg_info_ike *alg_info_ike_create_from_str(const struct parser_policy *policy,
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
