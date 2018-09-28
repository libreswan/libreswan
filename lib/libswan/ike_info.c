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
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
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
#include "ike_alg_encrypt.h"
#include "ike_alg_integ.h"
#include "ike_alg_prf.h"
#include "ike_alg_dh.h"
#include "alg_info.h"

static bool ike_proposal_ok(const struct proposal_parser *parser,
			    const struct proposal_info *proposal)
{
	if (!proposal_aead_none_ok(parser, proposal)) {
		if (!impair_proposal_errors(parser)) {
			return false;
		}
	}

	/*
	 * Check that the ALG_INFO spec is implemented.
	 */

	impaired_passert(PROPOSAL_PARSER, proposal->encrypt != NULL);
	passert(proposal->encrypt == NULL || ike_alg_is_ike(&(proposal->encrypt->common)));
	passert(IMPAIR(PROPOSAL_PARSER) || proposal->enckeylen == 0 ||
		encrypt_has_key_bit_length(proposal->encrypt,
					   proposal->enckeylen));

	impaired_passert(PROPOSAL_PARSER, proposal->prf != NULL);
	passert(proposal->prf == NULL || ike_alg_is_ike(&(proposal->prf->common)));

	impaired_passert(PROPOSAL_PARSER, proposal->integ != NULL);
	passert(proposal->integ == &ike_alg_integ_none ||
		proposal->integ == NULL ||
		ike_alg_is_ike(&proposal->integ->common));

	impaired_passert(PROPOSAL_PARSER, proposal->dh != NULL);
	passert(proposal->dh == NULL || ike_alg_is_ike(&(proposal->dh->common)));
	if (proposal->dh == &ike_alg_dh_none) {
		snprintf(parser->err_buf, parser->err_buf_len,
			 "IKE DH algorithm 'none' not permitted");
		if (!impair_proposal_errors(parser)) {
			return false;
		}
	}

	return true;
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
#ifdef USE_AES
	&ike_alg_encrypt_aes_cbc.common,
#endif
#ifdef USE_3DES
	&ike_alg_encrypt_3des_cbc.common,
#endif
	NULL,
};

static const struct ike_alg *default_ike_aalgs[] = {
#ifdef USE_SHA2
	&ike_alg_prf_sha2_256.common,
	&ike_alg_prf_sha2_512.common,
#endif
#ifdef USE_SHA1
	&ike_alg_prf_sha1.common,
#endif
	NULL,
};

const struct proposal_defaults ikev1_ike_defaults = {
	.dh = default_ikev1_groups,
	.encrypt = default_ike_ealgs,
	.prf = default_ike_aalgs,
};

const struct proposal_defaults ikev2_ike_defaults = {
	.dh = default_ikev2_groups,
	.encrypt = default_ike_ealgs,
	.prf = default_ike_aalgs,
};

const struct proposal_protocol ike_proposal_protocol = {
	.name = "IKE",
	.ikev1_alg_id = IKEv1_OAKLEY_ID,
	.protoid = PROTO_ISAKMP,
	.ikev1_defaults = &ikev1_ike_defaults,
	.ikev2_defaults = &ikev2_ike_defaults,
	.proposal_ok = ike_proposal_ok,
	.encrypt_alg_byname = encrypt_alg_byname,
	.prf_alg_byname = prf_alg_byname,
	.integ_alg_byname = integ_alg_byname,
	.dh_alg_byname = dh_alg_byname,
};

struct alg_info_ike *alg_info_ike_create_from_str(const struct proposal_policy *policy,
						  const char *alg_str,
						  char *err_buf, size_t err_buf_len)
{
	/*
	 *      alg_info storage should be sized dynamically
	 *      but this may require two passes to know
	 *      transform count in advance.
	 */
	struct alg_info_ike *alg_info_ike = alloc_thing(struct alg_info_ike, "alg_info_ike");
	const struct proposal_parser parser = proposal_parser(policy,
							      &ike_proposal_protocol,
							      err_buf, err_buf_len);

	if (!alg_info_parse_str(&parser, &alg_info_ike->ai, shunk1(alg_str))) {
		passert(err_buf[0] != '\0');
		alg_info_free(&alg_info_ike->ai);
		return NULL;
	}

	return alg_info_ike;
}
