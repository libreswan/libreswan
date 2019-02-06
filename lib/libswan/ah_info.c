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

#include <stdio.h>
#include <stdint.h>
#include <limits.h>

#include "lswalloc.h"
#include "lswlog.h"
#include "proposals.h"
#include "alg_byname.h"
#include "lswfips.h"

#include "ike_alg.h"
#include "ike_alg_integ.h"

static bool ah_proposal_ok(struct proposal_parser *parser,
			   const struct proposal *proposal)
{
	impaired_passert(PROPOSAL_PARSER,
			 next_algorithm(proposal, PROPOSAL_encrypt, NULL) == NULL);
	impaired_passert(PROPOSAL_PARSER,
			 next_algorithm(proposal, PROPOSAL_prf, NULL) == NULL);
	impaired_passert(PROPOSAL_PARSER,
			 next_algorithm(proposal, PROPOSAL_integ, NULL) != NULL);

	/* ah=null is invalid */
	if (!IMPAIR(ALLOW_NULL_NONE)) {
		FOR_EACH_ALGORITHM(proposal, integ, alg) {
			/* passerts */
			const struct integ_desc *integ = integ_desc(alg->desc);
			if (integ == &ike_alg_integ_none) {
				proposal_error(parser, "AH cannot have 'none' as the integrity algorithm");
				if (!impair_proposal_errors(parser)) {
					return false;
				}
			}
		}
	}

	return true;
}

static const struct ike_alg *default_ah_integ[] = {
#ifdef USE_SHA1
	&ike_alg_integ_sha1.common,
#endif
	NULL,
};

const struct proposal_defaults ah_defaults = {
	.integ = default_ah_integ,
};

const struct proposal_protocol ah_proposal_protocol = {
	.name = "AH",
	.ikev1_alg_id = IKEv1_ESP_ID,
	.protoid = PROTO_IPSEC_AH,
	.defaults = {
		[IKEv1] = &ah_defaults,
		[IKEv2] = &ah_defaults,
	},
	.proposal_ok = ah_proposal_ok,
	.integ_alg_byname = integ_alg_byname,
	.dh_alg_byname = dh_alg_byname,
};

/*
 * ??? why is this called _ah_ when almost everything refers to esp?
 * XXX: Because it is parsing an "ah" line which requires a different
 * parser configuration - encryption isn't allowed.
 *
 * ??? the only difference between
 * ah_proposals_create_from_str and alg_info_esp_create_from_str
 * is in the second argument to proposal_parser.
 *
 * XXX: On the other hand, since "struct ike_info" and "struct
 * esp_info" are effectively the same, they can be merged.  Doing
 * that, would eliminate the AH using ESP confusion.
 */

/* This function is tested in testing/algparse/algparse.c */

struct proposal_parser *ah_proposal_parser(const struct proposal_policy *policy)
{
	return alloc_proposal_parser(policy, &ah_proposal_protocol);
}
