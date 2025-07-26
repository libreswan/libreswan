/*
 * Algorithm info parsing and creation functions
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 *
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 Paul Wouters <pwouters@redhat.com>
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
#include "ike_alg_kem.h"
#include "proposals.h"

static bool ike_proposal_ok(struct proposal_parser *parser,
			    const struct proposal *proposal)
{
	if (!proposal_aead_none_ok(parser, proposal)) {
		if (!impair_proposal_errors(parser)) {
			return false;
		}
	}

	/*
	 * Check that the ALG_INFO spec is implemented.
	 */

	impaired_passert(proposal_parser, parser->policy->logger,
			 next_algorithm(proposal, PROPOSAL_encrypt, NULL) != NULL);
	FOR_EACH_ALGORITHM(proposal, encrypt, alg) {
		const struct encrypt_desc *encrypt = encrypt_desc(alg->desc);
		passert(ike_alg_is_ike(&encrypt->common));
		passert(impair.proposal_parser ||
			alg->enckeylen == 0 ||
			encrypt_has_key_bit_length(encrypt,
						   alg->enckeylen));
	}

	impaired_passert(proposal_parser, parser->policy->logger,
			 next_algorithm(proposal, PROPOSAL_prf, NULL) != NULL);
	FOR_EACH_ALGORITHM(proposal, prf, alg) {
		const struct prf_desc *prf = prf_desc(alg->desc);
		passert(ike_alg_is_ike(&prf->common));
	}

	impaired_passert(proposal_parser, parser->policy->logger,
			 next_algorithm(proposal, PROPOSAL_integ, NULL) != NULL);
	FOR_EACH_ALGORITHM(proposal, integ, alg) {
		const struct integ_desc *integ = integ_desc(alg->desc);
		passert(integ == &ike_alg_integ_none ||
			ike_alg_is_ike(&integ->common));
	}

	impaired_passert(proposal_parser, parser->policy->logger,
			 next_algorithm(proposal, PROPOSAL_ke, NULL) != NULL);
	FOR_EACH_ALGORITHM(proposal, ke, alg) {
		const struct kem_desc *dh = dh_desc(alg->desc);
		passert(ike_alg_is_ike(&dh->common));
		if (dh == &ike_alg_kem_none) {
			proposal_error(parser, "IKE Key Exchange algorithm 'NONE' not permitted");
			if (!impair_proposal_errors(parser)) {
				return false;
			}
		}
	}

	return true;
}

/*
 * IKEv1:
 *
 * since ike= must have an encryption algorithm this is normally
 * ignored.
 *
 * "ike_info" proposals are built built by first parsing the ike=
 * line, and second merging it with the below defaults when an
 * algorithm wasn't specified.
 *
 * Do not assume that these hard wired algorithms are actually valid.
 */

const char default_ikev1_ike_proposals[] =
	"AES_CBC"
	","
	"3DES"
	;

static const struct ike_alg *default_ikev1_ike_prfs[] = {
#ifdef USE_SHA2
	&ike_alg_prf_sha2_256.common,
	&ike_alg_prf_sha2_512.common,
#endif
#ifdef USE_SHA1
	&ike_alg_prf_sha1.common,
#endif
	NULL,
};

static const struct ike_alg *default_ikev1_groups[] = {
	&ike_alg_kem_modp2048.common,
	&ike_alg_kem_modp1536.common,
	&ike_alg_kem_secp256r1.common,
	&ike_alg_kem_curve25519.common,
	NULL,
};

const struct proposal_defaults ikev1_ike_defaults = {
	.proposals[FIPS_MODE_ON] = default_ikev1_ike_proposals,
	.proposals[FIPS_MODE_OFF] = default_ikev1_ike_proposals,
	.ke = default_ikev1_groups,
	.prf = default_ikev1_ike_prfs,
};

/*
 * IKEv2:
 *
 * since ike= must have an encryption algorithm this is normally
 * ignored.
 *
 * "ike_info" proposals are built built by first parsing the ike=
 * line, and second merging it with the below defaults when an
 * algorithm wasn't specified.
 *
 * Do not assume that these hard wired algorithms are actually valid.
 *
 * The proposals expanded using the default algorithms.
 *
 * Note: Strongswan cherry-picks proposals (for instance will
 * pick AES_128 over AES_256 when both are in the same
 * proposal) so, for moment, don't merge things.
 */

static const char default_fips_on_ikev2_ike_proposals[] =
	"AES_GCM_16_256"
	","
	"AES_GCM_16_128"
	","
	"AES_CBC_256"
	","
	"AES_CBC_128"
	;

static const char default_fips_off_ikev2_ike_proposals[] =
	"AES_GCM_16_256"
	","
	"AES_GCM_16_128"
#ifdef USE_CHACHA
	","
	"CHACHA20_POLY1305" /*not-FIPS*/
#endif
	","
	"AES_CBC_256"
	","
	"AES_CBC_128"
	;

static const struct ike_alg *default_ikev2_ike_prfs[] = {
#ifdef USE_SHA2
	&ike_alg_prf_sha2_512.common,
	&ike_alg_prf_sha2_256.common,
#endif
	NULL,
};

static const struct ike_alg *default_ikev2_groups[] = {
	&ike_alg_kem_secp256r1.common,
	&ike_alg_kem_secp384r1.common,
	&ike_alg_kem_secp521r1.common,
#ifdef USE_DH31
	&ike_alg_kem_curve25519.common,
#endif
	&ike_alg_kem_modp4096.common,
	&ike_alg_kem_modp3072.common,
	&ike_alg_kem_modp2048.common,
	&ike_alg_kem_modp8192.common,
	NULL,
};

const struct proposal_defaults ikev2_ike_defaults = {
	.proposals[FIPS_MODE_ON] = default_fips_on_ikev2_ike_proposals,
	.proposals[FIPS_MODE_OFF] = default_fips_off_ikev2_ike_proposals,
	.prf = default_ikev2_ike_prfs,
	/* INTEG is derived from PRF when applicable */
	.ke = default_ikev2_groups,
};

/*
 * All together now ...
 */

static const struct proposal_protocol ikev1_ike_proposal_protocol = {
	.name = "IKE",
	.alg_id = IKEv1_OAKLEY_ID,
	.defaults = &ikev1_ike_defaults,
	.proposal_ok = ike_proposal_ok,
	.encrypt = true,
	.prf = true,
	.integ = true,
	.ke = true,
};

static const struct proposal_protocol ikev2_ike_proposal_protocol = {
	.name = "IKE",
	.alg_id = IKEv2_ALG_ID,
	.defaults = &ikev2_ike_defaults,
	.proposal_ok = ike_proposal_ok,
	.encrypt = true,
	.prf = true,
	.integ = true,
	.ke = true,
};

static const struct proposal_protocol *ike_proposal_protocol[] = {
	[IKEv1] = &ikev1_ike_proposal_protocol,
	[IKEv2] = &ikev2_ike_proposal_protocol,
};

struct proposal_parser *ike_proposal_parser(const struct proposal_policy *policy)
{
	return alloc_proposal_parser(policy, ike_proposal_protocol[policy->version]);
}
