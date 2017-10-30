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

static bool ike_proposal_ok(const struct proposal_info *proposal,
			    char *err_buf, size_t err_buf_len)
{
	if (!DBGP(IMPAIR_ALLOW_NULL_NULL) &&
	    !proposal_aead_none_ok(proposal, err_buf, err_buf_len)) {
		return false;
	}

	passert(proposal->encrypt != NULL);
	passert(proposal->prf != NULL);
	passert(proposal->integ != NULL);

	/*
	 * Check that the ALG_INFO spec is implemented.
	 */
	passert(ike_alg_is_ike(&(proposal->encrypt->common)));
	passert(proposal->enckeylen == 0 ||
		encrypt_has_key_bit_length(proposal->encrypt,
					   proposal->enckeylen));
	passert(ike_alg_is_ike(&(proposal->prf->common)));

	/*
	 * This is a little loose.
	 */
	passert(proposal->integ != &ike_alg_integ_none ||
		ike_alg_is_aead(proposal->encrypt));
	passert(proposal->integ == &ike_alg_integ_none ||
		ike_alg_is_ike(&proposal->integ->common));

	passert(ike_alg_is_ike(&(proposal->dh->common)));

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
	&ike_alg_encrypt_aes_cbc.common,
#ifdef USE_3DES
	&ike_alg_encrypt_3des_cbc.common,
#endif
	NULL,
};

static const struct ike_alg *default_ike_aalgs[] = {
	&ike_alg_prf_sha2_256.common,
	&ike_alg_prf_sha2_512.common,
	&ike_alg_prf_sha1.common,
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

const struct parser_protocol ike_parser_protocol = {
	.name = "IKE",
	.ikev1_alg_id = IKEv1_OAKLEY_ID,
	.protoid = PROTO_ISAKMP,
	.ikev1_defaults = &ikev1_ike_defaults,
	.ikev2_defaults = &ikev2_ike_defaults,
	.proposal_ok = ike_proposal_ok,
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
				   &ike_parser_protocol);
}
