/*
 * Algorithm lookup, for libreswan
 *
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
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
#include "proposals.h"
#include "alg_byname.h"
#include "ike_alg.h"
#include "impair.h"

bool alg_byname_ok(struct proposal_parser *parser,
		   const struct ike_alg *alg, shunk_t print_name)
{
	const struct proposal_protocol *protocol = parser->protocol;
	const struct proposal_policy *policy = parser->policy;
	/*
	 * If the connection is IKEv1|IKEv2 then this code will
	 * exclude anything not supported by both protocols.
	 */
	switch (policy->version) {
	case IKEv1:
		/* IKEv1 has different IDs for ESP/IKE/AH */
		if (alg->id[protocol->ikev1_alg_id] < 0) {
			proposal_error(parser, "%s %s algorithm '"PRI_SHUNK"' is not supported by IKEv1",
				       protocol->name, ike_alg_type_name(alg->algo_type),
				       pri_shunk(print_name));
			return false;
		}
		break;
	case IKEv2:
		if (alg->id[IKEv2_ALG_ID] < 0) {
			proposal_error(parser, "%s %s algorithm '"PRI_SHUNK"' is not supported by IKEv2",
				       protocol->name, ike_alg_type_name(alg->algo_type),
				       pri_shunk(print_name));
			return false;
		}
		break;
	default:
		/* ignore */
		break;
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
		proposal_error(parser, "%s %s algorithm '"PRI_SHUNK"' is not supported",
			       protocol->name, ike_alg_type_name(alg->algo_type),
			       pri_shunk(print_name));
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
		proposal_error(parser, "%s %s algorithm '"PRI_SHUNK"' is not valid",
			       protocol->name, ike_alg_type_name(alg->algo_type),
			       pri_shunk(print_name));
		return false;
	}
	return true;
}

const struct ike_alg *alg_byname(struct proposal_parser *parser,
				 const struct ike_alg_type *type,
				 shunk_t name, shunk_t print_name)
{
	passert(parser->diag == NULL);
	const struct proposal_protocol *protocol = parser->protocol;
	const struct ike_alg *alg = ike_alg_byname(type, name);
	if (alg == NULL) {
		/*
		 * Known at all?  Poke around in the enum tables to
		 * see if it turns up.
		 */
		if (ike_alg_enum_match(type, protocol->ikev1_alg_id, name) >= 0 ||
		    ike_alg_enum_match(type, IKEv2_ALG_ID, name) >= 0) {
			proposal_error(parser, "%s %s algorithm '"PRI_SHUNK"' is not supported",
				       protocol->name, ike_alg_type_name(type),
				       pri_shunk(print_name));
		} else {
			proposal_error(parser, "%s %s algorithm '"PRI_SHUNK"' is not recognized",
				       protocol->name, ike_alg_type_name(type),
				       pri_shunk(print_name));
		}
		passert(parser->diag != NULL);
		DBGF(DBG_PROPOSAL_PARSER, "ike_alg_byname() failed: %s",
		     str_diag(parser->diag));
		return NULL;
	}

	/*
	 * Does it pass muster?
	 */
	if (!alg_byname_ok(parser, alg, print_name)) {
		passert(parser->diag != NULL);
		DBGF(DBG_PROPOSAL_PARSER, "alg_byname_ok() failed: %s",
		     str_diag(parser->diag));
		return NULL;
	}

	return alg;
}

const struct ike_alg *encrypt_alg_byname(struct proposal_parser *parser,
					 shunk_t name, size_t key_bit_length,
					 shunk_t print_name)
{
	const struct ike_alg *alg = alg_byname(parser, IKE_ALG_ENCRYPT, name,
					       print_name);
	if (alg == NULL) {
		return NULL;
	}
	const struct encrypt_desc *encrypt = encrypt_desc(alg);
	if (!impair.send_key_size_check && key_bit_length > 0) {
		if (encrypt->keylen_omitted) {
			proposal_error(parser, "%s encryption algorithm %s does not allow a key lengths",
				       parser->protocol->name,
				       encrypt->common.fqn);
			if (!impair_proposal_errors(parser)) {
				return NULL;
			}
		}
		if (!encrypt_has_key_bit_length(encrypt, key_bit_length)) {
			JAMBUF(buf) {
				jam(buf, "%s encryption algorithm %s with key length %zu invalid; valid key lengths:",
				    parser->protocol->name,
				    encrypt->common.fqn,
				    key_bit_length);
				/* reverse: table in descending order with trailing zeros */
				const char *sep = " ";
				for (int i = elemsof(encrypt->key_bit_lengths) - 1; i >= 0; i--) {
					if (encrypt->key_bit_lengths[i] > 0) {
						jam(buf, "%s%d", sep, encrypt->key_bit_lengths[i]);
						sep = ", ";
					}
				}
				proposal_error(parser, PRI_SHUNK, pri_shunk(jambuf_as_shunk(buf)));
			}
			if (!impair_proposal_errors(parser)) {
				return NULL;
			}
		}
	}
	return alg;
}
