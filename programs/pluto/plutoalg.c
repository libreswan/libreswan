/*
 * Kernel runtime algorithm handling interface definitions
 * Originally by: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * Reworked into openswan 2.x by Michael Richardson <mcr@xelerance.com>
 *
 * (C)opyright 2012 Paul Wouters <pwouters@redhat.com>
 * (C)opyright 2012-2013 Paul Wouters <paul@libreswan.org>
 * (C)opyright 2012-2013 D. Hugh Redelmeier
 * (C)opyright 2015-2017 Andrew Cagney <andrew.cagney@gmail.com>
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

#include <sys/types.h>
#include <stdlib.h>
#include <libreswan.h>
#include <libreswan/pfkeyv2.h>
#include <libreswan/passert.h>

#include "sysdep.h"
#include "constants.h"
#include "log.h"
#include "lswalloc.h"
#include "defs.h"
#include "id.h"
#include "connections.h"
#include "state.h"
#include "kernel_alg.h"
#include "alg_info.h"
#include "ike_alg.h"
#include "ike_alg_dh.h"
#include "plutoalg.h"
#include "crypto.h"
#include "spdb.h"
#include "db_ops.h"
#include "log.h"
#include "whack.h"

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

	/* support idXXX as syntax, matching iana numbers directly */

	int num_read = -1;
	if (sscanf(str, "id%d%n", &ret, &num_read) >= 1 &&
	    num_read == (int) strlen(str))
		return ret;

	return -1;
}

/*
 * Raw add routine: only checks for no duplicates
 */
/* ??? much of this code is the same as raw_alg_info_esp_add (same bugs!) */
static void raw_alg_info_ike_add(struct alg_info_ike *alg_info, int ealg_id,
				 unsigned ek_bits, int aalg_id,
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

	for (const struct encrypt_desc **algp = next_encrypt_desc(NULL);
	     algp != NULL; algp = next_encrypt_desc(algp)) {
		const struct encrypt_desc *alg = *algp;
		/*
		 * keylen==0 implies use default or defaults.
		 */
		if (ike_alg_is_ike(&(alg)->common)
		    && alg->common.ikev1_oakley_id == ealg_id) {
			new_info->ike_encrypt = alg;
			break;
		}
	}
	if (new_info->ike_encrypt == NULL) {
		struct esb_buf buf;
		loglog(RC_LOG_SERIOUS,
		       "ENCRYPT algorithm %s=%d is not supported",
		       enum_showb(&oakley_enc_names, ealg_id, &buf),
		       ealg_id);
		return;
	}
	if (ek_bits != 0) {
		if (!encrypt_has_key_bit_length(new_info->ike_encrypt,
						ek_bits)) {
			struct esb_buf buf;
			loglog(RC_LOG_SERIOUS,
			       "ENCRYPT algorithm %s with key length %u is not supported",
			       enum_showb(&oakley_enc_names, ealg_id, &buf),
			       ek_bits);
			return;
		}
	}

	for (const struct prf_desc **algp = next_prf_desc(NULL);
	     algp != NULL; algp = next_prf_desc(algp)) {
		const struct prf_desc *alg = *algp;
		if (ike_alg_is_ike(&(alg)->common)
		    && alg->common.ikev1_oakley_id == aalg_id) {
			new_info->ike_prf = alg;
			break;
		}
	}
	if (new_info->ike_prf == NULL) {
		struct esb_buf buf;
		loglog(RC_LOG_SERIOUS,
		       "PRF algorithm %s=%d is not supported",
		       enum_show_shortb(&oakley_hash_names, aalg_id, &buf),
		       aalg_id);
		return;
	}

	if (ike_alg_enc_requires_integ(new_info->ike_encrypt)) {
		for (const struct integ_desc **algp = next_integ_desc(NULL);
		     algp != NULL; algp = next_integ_desc(algp)) {
			const struct integ_desc *alg = *algp;
			if (ike_alg_is_ike(&(alg)->common)
			    && alg->common.ikev1_oakley_id == aalg_id) {
				new_info->ike_integ = alg;
				break;
			}
		}
		if (new_info->ike_integ == NULL) {
			struct esb_buf buf;
			loglog(RC_LOG_SERIOUS,
			       "INTEG algorithm %s=%d is not supported",
			       enum_show_shortb(&oakley_hash_names, aalg_id, &buf),
			       aalg_id);
			return;
		}
	}

	new_info->ike_dh_group = dh_group;
	if (new_info->ike_dh_group == NULL) {
		PEXPECT_LOG("%s", "missing DH GROUP");
		return;
	}

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
	DBG(DBG_CRYPT, DBG_log("raw_alg_info_ike_add() ealg_id=%d ek_bits=%d aalg_id=%d modp=%s, cnt=%d",
			       ealg_id, ek_bits, aalg_id,
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

static const enum ikev1_encr_attribute default_ike_ealgs[] = {
	OAKLEY_AES_CBC, OAKLEY_3DES_CBC,
};
static const enum ikev1_hash_attribute default_ike_aalgs[] = {
	OAKLEY_SHA2_256, OAKLEY_SHA2_512, OAKLEY_SHA1, OAKLEY_MD5,
};

/*
 * Strip out algorithms that aren't applicable.
 */
static const struct ike_alg **clone_valid(const struct parser_policy *policy,
					  const struct ike_alg **ikev1_algs,
					  const struct ike_alg **ikev2_algs)
{
	/*
	 * If there's a hint of IKEv1 being enabled then prefer its
	 * larger set of defaults.
	 *
	 * This should increase the odds of both ends interoperating.
	 * For instance, if IKEv2 defaults are prefered and one end
	 * has ikev2=never then, in agressive mode, things don't work.
	 */
	const struct ike_alg **default_algs = (policy->ikev1
					       ? ikev1_algs
					       : ikev2_algs);

	/*
	 * Allocate the cloned array.  Keep things simple by assuming
	 * it is the same size as the original.
	 */
	int count = 1;
	for (const struct ike_alg **default_alg = default_algs;
	     *default_alg; default_alg++) {
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
				    ike_alg_type_name(alg),
				    alg->name));
			continue;
		}
		if (policy->ikev2 && alg->ikev2_id == 0) {
			DBG(DBG_CONTROL|DBG_CRYPT,
			    DBG_log("skipping default %s %s, missing ikev2 support",
				    ike_alg_type_name(alg),
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
				    ike_alg_type_name(alg),
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
				    ike_alg_type_name(alg),
				    alg->name));
			continue;
		}
		DBG(DBG_CONTROL|DBG_CRYPT,
		    DBG_log("adding default %s %s",
			    ike_alg_type_name(alg),
			    alg->name));
		/* save it */
		*valid_alg++ = alg;
	}
	*valid_alg = NULL;
	return valid_algs;
}

/*
 * _Recursively_ add IKE alg info _with_ logic (policy):
 */

static void alg_info_ike_add(const struct parser_policy *const policy,
			     struct alg_info *alg_info,
			     int ealg_id, int ek_bits,
			     int aalg_id,
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
		const struct ike_alg **valid_groups = clone_valid(policy,
								  default_ikev1_groups,
								  default_ikev2_groups);
		for (const struct ike_alg **group = valid_groups;
		     *group; group++) {
			alg_info_ike_add(policy, alg_info,
					 ealg_id, ek_bits,
					 aalg_id, oakley_group_desc(*group));
		}
		pfree(valid_groups);
	} else if (ealg_id <= 0) {
		/*
		 * Recursively add the valid default enc algs
		 */
		for (int i = 0; i != elemsof(default_ike_ealgs); i++) {
			enum ikev1_encr_attribute id = default_ike_ealgs[i];
			bool valid = ikev1_get_ike_encrypt_desc(id) != NULL;

			if (DBGP(DBG_CONTROL|DBG_CRYPT)) {
				struct esb_buf buf;
				DBG_log("%s default ENCRYPT algorithm %s=%d",

					valid ? "adding" : "dropping invalid",
					enum_showb(&oakley_enc_names, id, &buf), id);
			}
			if (valid) {
				alg_info_ike_add(policy, alg_info,
						 id, ek_bits,
						 aalg_id, dh_group);
			}
		}
	} else if (aalg_id <= 0) {
		/*
		 * Recursively add the valid default PRF/HASH
		 * algorithms.
		 *
		 * Even AEAD algorithms need a PRF.
		 */
		for (int j = 0; j != elemsof(default_ike_aalgs); j++) {
			enum ikev1_hash_attribute id = default_ike_aalgs[j];
			bool valid = ikev1_get_ike_prf_desc(id) != NULL;

			if (DBGP(DBG_CONTROL|DBG_CRYPT)) {
				struct esb_buf buf;
				DBG_log("%s default PRF (HASH) algorithm %s=%d",
					valid ? "adding" : "dropping invalid",
					enum_showb(&oakley_hash_names, id, &buf), id);
			}
			if (valid) {
				alg_info_ike_add(policy, alg_info,
						 ealg_id, ek_bits,
						 id, dh_group);
			}
		}
	} else {
		raw_alg_info_ike_add((struct alg_info_ike *)alg_info,
				     ealg_id, ek_bits,
				     aalg_id, dh_group);
	}
}

static const struct oakley_group_desc *group_byname(const struct parser_policy *const policy,
						    char *err_buf, size_t err_buf_len,
						    const char *name)
{
	const struct oakley_group_desc *group = group_desc_byname(name);
	if (group == NULL) {
		snprintf(err_buf, err_buf_len,
			 "modp group '%s' not found",
			 name);
		return NULL;
	}
	/*
	 * If the connection is IKEv1|IKEv2 then this code will
	 * exclude anything not supported by both protocols.
	 */
	if (policy->ikev1 && group->common.ikev1_oakley_id == 0) {
		snprintf(err_buf, err_buf_len,
			 "modp group '%s' not supported by IKEv2",
			 name);
		return NULL;
	}
	if (policy->ikev2 && group->common.ikev2_id == 0) {
		snprintf(err_buf, err_buf_len,
			 "modp group '%s' not supported by IKEv1",
			 name);
		return NULL;
	}
	/*
	 * XXX: surely this is dead?
	 */
	if (group->group == 22) {
		snprintf(err_buf, err_buf_len,
			 "DH22 from RFC-5114 is no longer supported - see RFC-4307bis");
		return NULL;
	}
	/*
	 * Since the D-H calculation is performed in-process, IKE is
	 * always required.
	 */
	if (!ike_alg_is_ike(&group->common)) {
		snprintf(err_buf, err_buf_len,
			 "modp group '%s' not implemented",
			 name);
		return NULL;
	}
	return group;
}

const struct parser_param ike_parser_param = {
	.protoid = PROTO_ISAKMP,
	.alg_info_add = alg_info_ike_add,
	.ealg_getbyname = ealg_getbyname_ike,
	.aalg_getbyname = aalg_getbyname_ike,
	.group_byname = group_byname,
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

static bool kernel_alg_db_add(struct db_context *db_ctx,
			      const struct esp_info *esp_info,
			      lset_t policy,
			      bool logit)
{
	int ealg_i = SADB_EALG_NONE;

	if (policy & POLICY_ENCRYPT) {
		ealg_i = esp_info->transid;
		if (!ESP_EALG_PRESENT(ealg_i)) {
			if (logit) {
				loglog(RC_LOG_SERIOUS,
				       "requested kernel enc ealg_id=%d not present",
				       ealg_i);
			} else {
				DBG_log("requested kernel enc ealg_id=%d not present",
					ealg_i);
			}
			return FALSE;
		}
	}

	int aalg_i = alg_info_esp_aa2sadb(esp_info->auth);

	if (!ESP_AALG_PRESENT(aalg_i)) {
		DBG_log("kernel_alg_db_add() kernel auth aalg_id=%d not present",
			aalg_i);
		return FALSE;
	}

	if (policy & POLICY_ENCRYPT) {
		/*open new transformation */
		db_trans_add(db_ctx, ealg_i);

		/* add ESP auth attr (if present) */
		if (esp_info->auth != AUTH_ALGORITHM_NONE) {
			db_attr_add_values(db_ctx,
					   AUTH_ALGORITHM,
					   esp_info->auth);
		}

		/* add keylength if specified in esp= string */
		if (esp_info->enckeylen != 0) {
				db_attr_add_values(db_ctx,
						   KEY_LENGTH,
						   esp_info->enckeylen);
		} else {
			/* no key length - if required add default here and add another max entry */
			int def_ks = crypto_req_keysize(CRK_ESPorAH, ealg_i);

			if (def_ks != 0) {
				int max_ks = BITS_PER_BYTE *
					kernel_alg_esp_enc_max_keylen(ealg_i);

				db_attr_add_values(db_ctx,
					KEY_LENGTH,
					def_ks);
				/* add this trans again with max key size */
				if (def_ks != max_ks) {
					db_trans_add(db_ctx, ealg_i);
					if (esp_info->auth != AUTH_ALGORITHM_NONE) {
						db_attr_add_values(db_ctx,
							AUTH_ALGORITHM,
							esp_info->auth);
					}
					db_attr_add_values(db_ctx,
						KEY_LENGTH,
						max_ks);
				}
			}
		}
	} else if (policy & POLICY_AUTHENTICATE) {
		/* open new transformation */
		db_trans_add(db_ctx, aalg_i);

		/* add ESP auth attr */
		db_attr_add_values(db_ctx,
				   AUTH_ALGORITHM, esp_info->auth);
	}

	return TRUE;
}

/*
 *	Create proposal with runtime kernel algos, merging
 *	with passed proposal if not NULL
 *
 * ??? is this still true?  Certainly not free(3):
 *	for now this function does free() previous returned
 *	malloced pointer (this quirk allows easier spdb.c change)
 */
static struct db_context *kernel_alg_db_new(struct alg_info_esp *alg_info,
				     lset_t policy, bool logit)
{
	unsigned int trans_cnt = 0;
	int protoid = PROTO_RESERVED;

	if (policy & POLICY_ENCRYPT) {
		trans_cnt = (esp_ealg_num * esp_aalg_num);
		protoid = PROTO_IPSEC_ESP;
	} else if (policy & POLICY_AUTHENTICATE) {
		trans_cnt = esp_aalg_num;
		protoid = PROTO_IPSEC_AH;
	}

	DBG(DBG_EMITTING, DBG_log("kernel_alg_db_new() initial trans_cnt=%d",
				  trans_cnt));

	/*	pass aprox. number of transforms and attributes */
	struct db_context *ctx_new = db_prop_new(protoid, trans_cnt, trans_cnt * 2);

	/*
	 *      Loop: for each element (struct esp_info) of
	 *      alg_info, if kernel support is present then
	 *      build the transform (and attrs)
	 *
	 *      if NULL alg_info, propose everything ...
	 */

	bool success = TRUE;
	if (alg_info != NULL) {
		FOR_EACH_ESP_INFO(alg_info, esp_info) {
			if (!kernel_alg_db_add(ctx_new,
					esp_info,
					policy, logit))
				success = FALSE;	/* ??? should we break? */
		}
	} else {
		int ealg_i;

		ESP_EALG_FOR_EACH_DOWN(ealg_i) {
			struct esp_info tmp_esp_info;
			int aalg_i;

			tmp_esp_info.transid = ealg_i;
			tmp_esp_info.enckeylen = 0;
			ESP_AALG_FOR_EACH(aalg_i) {
				tmp_esp_info.auth =
					alg_info_esp_sadb2aa(aalg_i);
				kernel_alg_db_add(ctx_new, &tmp_esp_info,
						  policy, FALSE);
			}
		}
	}

	if (!success) {
		/* NO algorithms were found. oops */
		db_destroy(ctx_new);
		return NULL;
	}

	struct db_prop  *prop = db_prop_get(ctx_new);

	DBG(DBG_CONTROL | DBG_EMITTING,
		DBG_log("kernel_alg_db_new() will return p_new->protoid=%d, p_new->trans_cnt=%d",
			prop->protoid,
			prop->trans_cnt));

	unsigned int tn = 0;
	struct db_trans *t;
	for (t = prop->trans, tn = 0;
	     t != NULL && t[tn].transid != 0 && tn < prop->trans_cnt;
	     tn++) {
		DBG(DBG_CONTROL | DBG_EMITTING,
		    DBG_log("kernel_alg_db_new()     trans[%d]: transid=%d, attr_cnt=%d, attrs[0].type=%d, attrs[0].val=%d",
			    tn,
			    t[tn].transid, t[tn].attr_cnt,
			    t[tn].attrs ? t[tn].attrs[0].type.ipsec : 255,
			    t[tn].attrs ? t[tn].attrs[0].val : 255
			    ));
	}
	prop->trans_cnt = tn;

	return ctx_new;
}

bool ikev1_verify_esp(int ealg, unsigned int key_len, int aalg,
			const struct alg_info_esp *alg_info)
{
	if (alg_info == NULL)
		return TRUE;

	if (key_len == 0)
		key_len = crypto_req_keysize(CRK_ESPorAH, ealg);

	FOR_EACH_ESP_INFO(alg_info, esp_info) {
		if (esp_info->transid == ealg &&
		    (esp_info->enckeylen == 0 ||
		     key_len == 0 ||
		     esp_info->enckeylen == key_len) &&
		    esp_info->auth == aalg) {
			return TRUE;
		}
	}

	libreswan_log("ESP IPsec Transform [%s (%d), %s] refused",
		enum_name(&esp_transformid_names, ealg),
		key_len, enum_name(&auth_alg_names, aalg));
	return FALSE;
}

bool ikev1_verify_ah(int aalg, const struct alg_info_esp *alg_info)
{
	if (alg_info == NULL)
		return TRUE;

	FOR_EACH_ESP_INFO(alg_info, esp_info) {	/* really AH */
		if (esp_info->auth == aalg)
			return TRUE;
	}

	libreswan_log("AH IPsec Transform [%s] refused",
		enum_name(&ah_transformid_names, aalg));
	return FALSE;
}

void kernel_alg_show_status(void)
{
	unsigned sadb_id;

	whack_log(RC_COMMENT, "ESP algorithms supported:");
	whack_log(RC_COMMENT, " "); /* spacer */

	ESP_EALG_FOR_EACH(sadb_id) {
		const struct sadb_alg *alg_p = &esp_ealg[sadb_id];

		whack_log(RC_COMMENT,
			"algorithm ESP encrypt: id=%d, name=%s, ivlen=%d, keysizemin=%d, keysizemax=%d",
			sadb_id,
			enum_name(&esp_transformid_names, sadb_id),
			alg_p->sadb_alg_ivlen,
			alg_p->sadb_alg_minbits,
			alg_p->sadb_alg_maxbits);
	}

	ESP_AALG_FOR_EACH(sadb_id) {
		unsigned id = alg_info_esp_sadb2aa(sadb_id);
		const struct sadb_alg *alg_p = &esp_aalg[sadb_id];

		whack_log(RC_COMMENT,
			"algorithm AH/ESP auth: id=%d, name=%s, keysizemin=%d, keysizemax=%d",
			id,
			enum_name(&auth_alg_names, id),
			alg_p->sadb_alg_minbits,
			alg_p->sadb_alg_maxbits);
	}

	whack_log(RC_COMMENT, " "); /* spacer */
}

void kernel_alg_show_connection(const struct connection *c, const char *instance)
{
	const char *satype;

	switch (c->policy & (POLICY_ENCRYPT | POLICY_AUTHENTICATE)) {
	default:	/* shut up gcc */
	case 0u:
		satype = "noESPnoAH";
		break;

	case POLICY_ENCRYPT:
		satype = "ESP";
		break;

	case POLICY_AUTHENTICATE:
		satype = "AH";
		break;

	case POLICY_ENCRYPT | POLICY_AUTHENTICATE:
		satype = "ESP+AH";
		break;
	}

	const char *pfsbuf;
	struct esb_buf esb;

	if (c->policy & POLICY_PFS) {
		/* ??? 0 isn't a legitimate value for esp_pfsgroup */
		if (c->alg_info_esp != NULL && c->alg_info_esp->esp_pfsgroup != 0) {
			pfsbuf = enum_show_shortb(&oakley_group_names,
				c->alg_info_esp->esp_pfsgroup, &esb);
		} else {
			pfsbuf = "<Phase1>";
		}
	} else {
		pfsbuf = "<N/A>";
	}

	if (c->alg_info_esp != NULL) {
		char buf[1024];

		alg_info_esp_snprint(buf, sizeof(buf),
				     c->alg_info_esp);
		whack_log(RC_COMMENT,
			  "\"%s\"%s:   %s algorithms wanted: %s",
			  c->name,
			  instance, satype,
			  buf);

		alg_info_snprint_phase2(buf, sizeof(buf), c->alg_info_esp);
		whack_log(RC_COMMENT,
			  "\"%s\"%s:   %s algorithms loaded: %s",
			  c->name,
			  instance, satype,
			  buf);
	}

	const struct state *st = state_with_serialno(c->newest_ipsec_sa);

	if (st != NULL && st->st_esp.present) {
		whack_log(RC_COMMENT,
			  "\"%s\"%s:   %s algorithm newest: %s_%03d-%s; pfsgroup=%s",
			  c->name,
			  instance, satype,
			  enum_short_name(&esp_transformid_names,
				    st->st_esp.attrs.transattrs.encrypt),
			  st->st_esp.attrs.transattrs.enckeylen,
			  enum_short_name(&auth_alg_names,
				    st->st_esp.attrs.transattrs.integ_hash),
			  pfsbuf);
	}

	if (st != NULL && st->st_ah.present) {
		whack_log(RC_COMMENT,
			  "\"%s\"%s:   %s algorithm newest: %s; pfsgroup=%s",
			  c->name,
			  instance, satype,
			  enum_short_name(&auth_alg_names,
				    st->st_esp.attrs.transattrs.integ_hash),
			  pfsbuf);
	}
}

struct db_sa *kernel_alg_makedb(lset_t policy, struct alg_info_esp *ei,
				bool logit)
{
	if (ei == NULL) {
		struct db_sa *sadb;
		lset_t pm = POLICY_ENCRYPT | POLICY_AUTHENTICATE;

#if 0
		if (can_do_IPcomp)
			pm |= POLICY_COMPRESS;
#endif

		sadb = &ipsec_sadb[(policy & pm) >> POLICY_IPSEC_SHIFT];

		/* make copy, to keep from freeing the static policies */
		sadb = sa_copy_sa(sadb);
		sadb->parentSA = FALSE;

		DBG(DBG_CONTROL,
		    DBG_log("empty esp_info, returning defaults"));
		return sadb;
	}

	struct db_context *dbnew = kernel_alg_db_new(ei, policy, logit);

	if (dbnew == NULL) {
		libreswan_log("failed to translate esp_info to proposal, returning empty");
		return NULL;
	}

	struct db_prop *p = db_prop_get(dbnew);

	if (p == NULL) {
		libreswan_log("failed to get proposal from context, returning empty");
		db_destroy(dbnew);
		return NULL;
	}

	struct db_prop_conj pc = { .prop_cnt = 1, .props = p };

	struct db_sa t = { .prop_conj_cnt = 1, .prop_conjs = &pc };

	/* make a fresh copy */
	struct db_sa *n = sa_copy_sa(&t);
	n->parentSA = FALSE;

	db_destroy(dbnew);

	DBG(DBG_CONTROL,
	    DBG_log("returning new proposal from esp_info"));
	return n;
}

void fill_in_esp_info_ike_algs(struct esp_info *esp_info)
{
	for (const struct encrypt_desc **algp = next_encrypt_desc(NULL);
	     algp != NULL; algp = next_encrypt_desc(algp)) {
		if (esp_info->transid == (*algp)->common.ikev1_esp_id) {
			esp_info->esp_encrypt = (*algp);
		}
	}
	if (esp_info->esp_encrypt == NULL && DBGP(DBG_CONTROLMORE)) {
		struct esb_buf buf;
		DBG_log("XXX: ESP/AH ENCRYPT algorithm %s=%d not found",
			enum_showb(&esp_transformid_names,
				   esp_info->transid, &buf),
			esp_info->transid);
	}
	for (const struct integ_desc **algp = next_integ_desc(NULL);
	     algp != NULL; algp = next_integ_desc(algp)) {
		if (esp_info->auth == (*algp)->common.ikev1_esp_id) {
			esp_info->esp_integ = (*algp);
		}
	}
	if (esp_info->esp_integ == NULL && DBGP(DBG_CONTROLMORE)) {
		struct esb_buf buf;
		DBG_log("XXX: ESP/AH INTEG algorithm %s=%d not found",
			enum_showb(&auth_alg_names,
				   esp_info->auth, &buf),
			esp_info->auth);
	}
}
