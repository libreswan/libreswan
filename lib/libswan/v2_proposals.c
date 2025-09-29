/* V2 algorithm proposal parsing, for libreswan
 *
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 D. Hugh Redelmeier <hugh@mimosa.com>
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
#include <string.h>
#include <limits.h>

#include "lswlog.h"
#include "lswalloc.h"
#include "constants.h"
#include "proposals.h"
#include "ike_alg.h"
#include "ike_alg_integ.h"
#include "ike_alg_kem.h"
#include "alg_byname.h"

/*
 * For all the algorithms, when an algorithm is missing (NULL), and
 * there are defaults, add them.
 */

static void merge_algorithms(struct proposal_parser *parser,
			     struct proposal *proposal,
			     const struct transform_type *transform_type,
			     struct verbose verbose)
{
	const struct ike_alg **defaults = parser->protocol->defaults->transform[transform_type->index];
	if (defaults == NULL) {
		return;
	}

	struct transform *transform = first_proposal_transform(proposal, transform_type);
	if (transform != NULL) {
		return;
	}

	for (const struct ike_alg **alg = defaults; (*alg) != NULL; alg++) {
		append_proposal_transform(parser, proposal,
					  transform_type, *alg, 0,
					  verbose);
	}
}

static bool merge_defaults(struct proposal_parser *parser,
			   struct proposal *proposal,
			   struct verbose verbose)
{
	const struct proposal_defaults *defaults = parser->protocol->defaults;
	for (const struct transform_type *type = transform_type_floor;
	     type < PMIN(transform_type_prf, transform_type_integ);
	     type++) {
		merge_algorithms(parser, proposal, type, verbose);
	}

	/*
	 * PRF/INTEG are weird; and, as of time of writing INTEG was
	 * ordered before PRF, which is backwards.
	 */
	merge_algorithms(parser, proposal, transform_type_prf, verbose);
	if (first_proposal_transform(proposal, transform_type_integ) == NULL) {
		if (proposal_encrypt_aead(proposal)) {
			/*
			 * Since AEAD, integrity is always 'none'.
			 */
			append_proposal_transform(parser, proposal,
						  transform_type_integ,
						  &ike_alg_integ_none.common, 0,
						  verbose);
		} else if (defaults->transform[PROPOSAL_TRANSFORM_integ] != NULL) {
			/*
			 * Merge in the defaults.
			 */
			merge_algorithms(parser, proposal, transform_type_integ, verbose);
		} else if (first_proposal_transform(proposal, transform_type_prf) != NULL &&
			   proposal_encrypt_norm(proposal)) {
			/*
			 * Since non-AEAD, use integrity algorithms
			 * that are implemented using the PRFs.
			 *
			 * Danger: transforms->data changes as the
			 * table grows; hence this strange construct
			 * and the need to re-index the table.
			 */
			volatile const struct transforms *transforms =
				proposal_transforms(proposal);
			for (unsigned t = 0; t < transforms->len; t++) {
				const struct transform *transform = &transforms->data[t];
				if (transform->type != transform_type_prf) {
					continue;
				}
				const struct ike_alg *prf = transform->desc;
				const struct integ_desc *integ = NULL;
				for (const struct integ_desc **integp = next_integ_desc(NULL);
				     integp != NULL; integp = next_integ_desc(integp)) {
					if ((*integp)->prf != NULL &&
					    &(*integp)->prf->common == prf) {
						integ = *integp;
						break;
					}
				}
				if (integ == NULL) {
					proposal_error(parser, "%s integrity derived from PRF %s is not supported",
						       parser->protocol->name,
						       prf->fqn);
					return false;
				}
				/*
				 * Since the proposal been stripped of
				 * duplicates, need to check for
				 * duplicate transforms here.
				 */
				bool duplicate = false;
				DATA_FOR_EACH(old, proposal_transforms(proposal)) {
					if (old->desc == &integ->common) {
						duplicate = true;
						break;
					}
				}
				if (!duplicate) {
					append_proposal_transform(parser, proposal,
								  transform_type_integ,
								  &integ->common, 0,
								  verbose);
				}
			}
		}
	}

	for (const struct transform_type *transform_type =
		     PMAX(transform_type_prf, transform_type_integ) + 1;
	     transform_type < transform_type_roof; transform_type++) {
		merge_algorithms(parser, proposal, transform_type, verbose);
	}
	return true;
}

static bool parse_ikev2_proposal(struct proposal_parser *parser,
				 struct proposal *proposal,
				 shunk_t input,
				 struct verbose verbose)
{
	if (!parse_proposal(parser, proposal, input, verbose)) {
		return false;
	}

	if (!merge_defaults(parser, proposal, verbose)) {
		vassert(parser->diag != NULL);
		return false;
	}

	/* back end? */
	if (!parser->protocol->proposal_ok(parser, proposal)) {
		vassert(parser->diag != NULL);
		return false;
	}

	return true;
}

bool v2_proposals_parse_str(struct proposal_parser *parser,
			    struct proposals *proposals,
			    shunk_t input,
			    struct verbose verbose)
{
	if (input.len == 0) {
		/* XXX: hack to keep testsuite happy */
		proposal_error(parser, "%s proposal is empty",
			       parser->protocol->name);
		return false;
	}

	do {
		/* find the next proposal */
		shunk_t raw_proposal = shunk_token(&input, NULL, ",");
		struct proposal *proposal = alloc_proposal(parser);
		if (!parse_ikev2_proposal(parser, proposal, raw_proposal, verbose)) {
			vassert(parser->diag != NULL);
			free_proposal(&proposal);
			return false;
		}
		/*
		 * XXX: should check that the proposal hasn't ended up
		 * empty.
		 */
		vassert(parser->diag == NULL);
		append_proposal(parser, proposals, &proposal, verbose);
	} while (input.ptr != NULL);
	return true;
}
