/*
 * Algorithm lookup, for libreswan
 *
 * Copyright (C) 2017 Andrew Cagney <cagney@gnu.org>
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

#include <stdlib.h>

#include "lswlog.h"
#include "alg_info.h"
#include "alg_byname.h"
#include "ike_alg.h"

static const struct ike_alg *alg_byname(const struct parser_param *param,
					const struct parser_policy *const policy,
					enum ike_alg_type type,
					bool ike,
					char *err_buf, size_t err_buf_len,
					const char *name)
{
	const struct ike_alg *alg = ike_alg_byname(type, name);
	if (alg == NULL) {
		/*
		 * Known at all?  Poke around in the enum tables to
		 * see if it turns up.
		 */
		if (ike_alg_enum_match(type, param->ikev1_alg_id, name) >= 0
		    || ike_alg_enum_match(type, IKEv2_ALG_ID, name) >= 0) {
			snprintf(err_buf, err_buf_len,
				 "%s %s algorithm '%s' is not supported",
				 param->protocol, ike_alg_type_name(type), name);
		} else {
			snprintf(err_buf, err_buf_len,
				 "%s %s algorithm '%s' is not recognized",
				 param->protocol, ike_alg_type_name(type), name);
		}
		return NULL;
	}

	/*
	 * If the connection is IKEv1|IKEv2 then this code will
	 * exclude anything not supported by both protocols.
	 */
	if (policy->ikev1 && alg->id[param->ikev1_alg_id] == 0) {
		snprintf(err_buf, err_buf_len,
			 "%s %s algorithm '%s' is not supported by IKEv1",
			 param->protocol, ike_alg_type_name(type), name);
		return NULL;
	}
	if (policy->ikev2 && alg->id[IKEv2_ALG_ID] == 0) {
		snprintf(err_buf, err_buf_len,
			 "%s %s algorithm '%s' is not supported by IKEv2",
			 param->protocol, ike_alg_type_name(type), name);
		return NULL;
	}

	/*
	 * Since the IKE calculation is performed in-process, this is
	 * always required.
	 */
	if (ike && !ike_alg_is_ike(alg)) {
		snprintf(err_buf, err_buf_len,
			 "%s %s algorithm '%s' is not implemented",
			 "IKE", ike_alg_type_name(type), name);
		return NULL;
	}

	return alg;
}

const struct encrypt_desc *encrypt_alg_byname(const struct parser_param *param,
					      const struct parser_policy *const policy,
					      char *err_buf, size_t err_buf_len,
					      const char *name, size_t key_bit_length)
{
	const struct ike_alg *alg = alg_byname(param, policy, IKE_ALG_ENCRYPT,
					       param->ikev1_alg_id == IKEv1_OAKLEY_ID,
					       err_buf, err_buf_len, name);
	if (alg == NULL) {
		return NULL;
	}
	const struct encrypt_desc *encrypt = encrypt_desc(alg);
	if (!DBGP(IMPAIR_SEND_KEY_SIZE_CHECK) && key_bit_length > 0) {
		if (encrypt->keylen_omitted) {
			snprintf(err_buf, err_buf_len,
				 "%s does not take variable key lengths",
				 enum_short_name(&ikev2_trans_type_encr_names,
						 encrypt->common.id[IKEv2_ALG_ID]));
			return NULL;
		}
		if (!encrypt_has_key_bit_length(encrypt, key_bit_length)) {
			/*
			 * XXX: make list up to keep tests happy;
			 * should instead generate a real list from
			 * encrypt.
			 */
			snprintf(err_buf, err_buf_len,
				 "wrong encryption key length - key size must be 128 (default), 192 or 256");
			return NULL;
		}
	}
	return encrypt;
}

const struct prf_desc *prf_alg_byname(const struct parser_param *param,
				      const struct parser_policy *const policy,
				      char *err_buf, size_t err_buf_len,
				      const char *name)
{
	return prf_desc(alg_byname(param, policy, IKE_ALG_PRF,
				   param->ikev1_alg_id == IKEv1_OAKLEY_ID,
				   err_buf, err_buf_len,
				   name));
}

const struct integ_desc *integ_alg_byname(const struct parser_param *param,
					  const struct parser_policy *const policy,
					  char *err_buf, size_t err_buf_len,
					  const char *name)
{
	return integ_desc(alg_byname(param, policy, IKE_ALG_INTEG,
				     param->ikev1_alg_id == IKEv1_OAKLEY_ID,
				     err_buf, err_buf_len,
				     name));
}

const struct oakley_group_desc *dh_alg_byname(const struct parser_param *param,
					      const struct parser_policy *const policy,
					      char *err_buf, size_t err_buf_len,
					      const char *name)
{
	/*
	 * DH is always requires an in-tree implementation of the algorithm.
	 */
	return oakley_group_desc(alg_byname(param, policy, IKE_ALG_DH, TRUE,
					    err_buf, err_buf_len,
					    name));
}
