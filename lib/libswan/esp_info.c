/* ESP parsing and creation functions, for libreswan
 *
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 *
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
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
#include "fips_mode.h"

#include "ike_alg.h"
#include "ike_alg_encrypt.h"
#include "ike_alg_integ.h"

/*
 * Add ESP alg info _with_ logic (policy):
 */
static bool esp_proposal_ok(struct proposal_parser *parser,
			    const struct proposal *proposal)
{
	if (!proposal_aead_none_ok(parser, proposal)) {
		if (!impair_proposal_errors(parser)) {
			return false;
		}
	}

	impaired_passert(proposal_parser, parser->policy->logger,
			 next_algorithm(proposal, PROPOSAL_encrypt, NULL) != NULL);
	impaired_passert(proposal_parser, parser->policy->logger,
			 next_algorithm(proposal, PROPOSAL_prf, NULL) == NULL);
	impaired_passert(proposal_parser, parser->policy->logger,
			 next_algorithm(proposal, PROPOSAL_integ, NULL) != NULL);
	return true;
}

/*
 * IKEv1:
 *
 * since esp= must have an encryption algorithm this is normally
 * ignored.
 */

static const char default_v1_esp_proposals[] =
	"AES_CBC" /*????*/
	","
	"AES_GCM_16_128"
	","
	"AES_GCM_16_256"
	","
	"3DES"
	;

static const struct ike_alg *default_v1_esp_integ[] = {
#ifdef USE_SHA1
	&ike_alg_integ_sha1.common,
#endif
#ifdef USE_SHA2
	&ike_alg_integ_sha2_512.common,
	&ike_alg_integ_sha2_256.common,
#endif
	NULL,
};

static const struct proposal_defaults v1_esp_defaults = {
	.proposals[FIPS_MODE_OFF] = default_v1_esp_proposals,
	.proposals[FIPS_MODE_ON] = default_v1_esp_proposals,
	.integ = default_v1_esp_integ,
};

/*
 * IKEv2:
 */

static const char default_fips_on_v2_esp_proposals[] =
	"AES_GCM_16_256"
	","
	"AES_GCM_16_128"
	","
	"AES_CBC_256"
	","
	"AES_CBC_128"
	;

static const char default_fips_off_v2_esp_proposals[] =
	"AES_GCM_16_256"
	","
	"AES_GCM_16_128"
	","
	"CHACHA20_POLY1305" /*non-FIPS*/
	","
	"AES_CBC_256"
	","
	"AES_CBC_128"
	;

static const struct ike_alg *default_v2_esp_integ[] = {
#ifdef USE_SHA2
	&ike_alg_integ_sha2_512.common,
	&ike_alg_integ_sha2_256.common,
#endif
	NULL,
};

static const struct proposal_defaults v2_esp_defaults = {
	.proposals[FIPS_MODE_ON] = default_fips_on_v2_esp_proposals,
	.proposals[FIPS_MODE_OFF] = default_fips_off_v2_esp_proposals,
	.integ = default_v2_esp_integ,
};

/*
 * All together now ...
 */

static const struct proposal_protocol esp_proposal_protocol = {
	.name = "ESP",
	.ikev1_alg_id = IKEv1_IPSEC_ID,
	.defaults = {
		[IKEv1] = &v1_esp_defaults,
		[IKEv2] = &v2_esp_defaults,
	},
	.proposal_ok = esp_proposal_ok,
	.encrypt = true,
	.integ = true,
	.dh = true,
};

/*
 * ??? the only difference between
 * alg_info_ah_create_from_str and esp_proposals_create_from_str
 * is in the second argument to proposal_parser.
 *
 * XXX: On the other hand, since "struct ike_info" and "struct
 * esp_info" are effectively the same, they can be merged.  Doing
 * that, would eliminate the AH using ESP confusion.
 */

/* This function is tested in testing/algparse/algparse.c */

struct proposal_parser *esp_proposal_parser(const struct proposal_policy *policy)
{
	return alloc_proposal_parser(policy, &esp_proposal_protocol);
}
