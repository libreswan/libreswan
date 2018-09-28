/*
 * Algorithm lookup, for libreswan
 *
 * Copyright (C) 2017 Andrew Cagney <cagney@gnu.org>
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

#include <stdlib.h>

#include "lswlog.h"
#include "alg_info.h"
#include "alg_byname.h"
#include "ike_alg.h"

bool alg_byname_ok(const struct proposal_parser *parser,
		   const struct ike_alg *alg, shunk_t print_name)
{
	const struct proposal_protocol *protocol = parser->protocol;
	const struct proposal_policy *policy = parser->policy;
	/*
	 * If the connection is IKEv1|IKEv2 then this code will
	 * exclude anything not supported by both protocols.
	 */
	if (policy->ikev1 && alg->id[protocol->ikev1_alg_id] < 0) {
		snprintf(parser->err_buf, parser->err_buf_len,
			 "%s %s algorithm '"PRI_SHUNK"' is not supported by IKEv1",
			 protocol->name, ike_alg_type_name(alg->algo_type),
			 PRI_shunk(print_name));
		return false;
	}
	if (policy->ikev2 && alg->id[IKEv2_ALG_ID] < 0) {
		snprintf(parser->err_buf, parser->err_buf_len,
			 "%s %s algorithm '"PRI_SHUNK"' is not supported by IKEv2",
			 protocol->name, ike_alg_type_name(alg->algo_type),
			 PRI_shunk(print_name));
		return false;
	}
	/*
	 * According to parser policy, is the algorithm "implemented"?
	 *
	 * For IKE, this checks things like an in-process
	 * implementation being present.  For ESP/AH this checks that
	 * it is is implemented in the kernel (well except for DH
	 * which is still requires an in-process implementation).
	 */
	passert(policy->alg_is_ok != NULL);
	if (!policy->alg_is_ok(alg)) {
		snprintf(parser->err_buf, parser->err_buf_len,
			 "%s %s algorithm '"PRI_SHUNK"' is not supported",
			 protocol->name, ike_alg_type_name(alg->algo_type),
			 PRI_shunk(print_name));
		return false;
	}
	/*
	 * Check that the algorithm is valid.
	 *
	 * FIPS, for instance, will invalidate some algorithms during
	 * startup.
	 *
	 * Since it likely involves a lookup, it is left until last.
	 */
	if (!ike_alg_is_valid(alg)) {
		snprintf(parser->err_buf, parser->err_buf_len,
			 "%s %s algorithm '"PRI_SHUNK"' is not valid",
			 protocol->name, ike_alg_type_name(alg->algo_type),
			 PRI_shunk(print_name));
		return false;
	}
	return true;
}

static const struct ike_alg *alg_byname(const struct proposal_parser *parser,
					const struct ike_alg_type *type,
					shunk_t name, shunk_t print_name)
{
	const struct proposal_protocol *protocol = parser->protocol;
	const struct ike_alg *alg = ike_alg_byname(type, name);
	if (alg == NULL) {
		/*
		 * Known at all?  Poke around in the enum tables to
		 * see if it turns up.
		 */
		if (ike_alg_enum_match(type, protocol->ikev1_alg_id, name) >= 0 ||
		    ike_alg_enum_match(type, IKEv2_ALG_ID, name) >= 0) {
			snprintf(parser->err_buf, parser->err_buf_len,
				 "%s %s algorithm '"PRI_SHUNK"' is not supported",
				 protocol->name, ike_alg_type_name(type),
				 PRI_shunk(print_name));
		} else {
			snprintf(parser->err_buf, parser->err_buf_len,
				 "%s %s algorithm '"PRI_SHUNK"' is not recognized",
				 protocol->name, ike_alg_type_name(type),
				 PRI_shunk(print_name));
		}
		return NULL;
	}

	/*
	 * Does it pass muster?
	 */
	if (!alg_byname_ok(parser, alg, print_name)) {
		passert(parser->err_buf[0] != '\0');
		return NULL;
	}

	return alg;
}

const struct ike_alg *encrypt_alg_byname(const struct proposal_parser *parser,
					 shunk_t name, size_t key_bit_length,
					 shunk_t print_name)
{
	const struct ike_alg *alg = alg_byname(parser, IKE_ALG_ENCRYPT, name,
					       print_name);
	if (alg == NULL) {
		return NULL;
	}
	const struct encrypt_desc *encrypt = encrypt_desc(alg);
	if (!IMPAIR(SEND_KEY_SIZE_CHECK) && key_bit_length > 0) {
		if (encrypt->keylen_omitted) {
			snprintf(parser->err_buf, parser->err_buf_len,
				 "%s does not take variable key lengths",
				 enum_short_name(&ikev2_trans_type_encr_names,
						 encrypt->common.id[IKEv2_ALG_ID]));
			if (!impair_proposal_errors(parser)) {
				return NULL;
			}
		}
		if (!encrypt_has_key_bit_length(encrypt, key_bit_length)) {
			/*
			 * XXX: make list up to keep tests happy;
			 * should instead generate a real list from
			 * encrypt.
			 */
			snprintf(parser->err_buf, parser->err_buf_len,
				 "wrong encryption key length - key size must be 128 (default), 192 or 256");
			if (!impair_proposal_errors(parser)) {
				return NULL;
			}
		}
	}
	return alg;
}

const struct ike_alg *prf_alg_byname(const struct proposal_parser *parser,
				     shunk_t name, size_t key_bit_length UNUSED,
				     shunk_t print_name)
{
	return alg_byname(parser, IKE_ALG_PRF, name, print_name);
}

const struct ike_alg *integ_alg_byname(const struct proposal_parser *parser,
				       shunk_t name, size_t key_bit_length UNUSED,
				       shunk_t print_name)
{
	return alg_byname(parser, IKE_ALG_INTEG, name, print_name);
}

const struct ike_alg *dh_alg_byname(const struct proposal_parser *parser,
				    shunk_t name, size_t key_bit_length UNUSED,
				    shunk_t print_name)
{
	return alg_byname(parser, IKE_ALG_DH, name, print_name);
}
