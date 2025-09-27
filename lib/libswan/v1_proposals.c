/* V1 algorithm proposal parsing, for libreswan
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

static bool add_proposal_defaults(struct proposal_parser *parser,
				  struct proposals *proposals,
				  const struct v1_proposal *proposal,
				  struct verbose verbose);

/*
 * Add the proposal defaults for the specific algorithm.
 */

static struct v1_proposal merge_alg_default(struct v1_proposal proposal,
					    const struct transform_type *type,
					    const struct ike_alg *default_alg)
{
	switch (type->index) {
#define T(TYPE)								\
		case PROPOSAL_TRANSFORM_##TYPE:				\
			proposal.TYPE = TYPE##_desc(default_alg);	\
			break
		T(kem);
		T(encrypt);
		T(prf);
		T(integ);
#undef T
	default:
		bad_case(type->index);
	}
	return proposal;
}

static bool add_alg_defaults(struct proposal_parser *parser,
			     struct proposals *proposals,
			     const struct v1_proposal *proposal,
			     const struct transform_type *transform_type,
			     struct verbose verbose)
{
	unsigned level = verbose.level;
	const struct ike_alg **default_algs = parser->protocol->defaults->transform[transform_type->index];
	/*
	 * Use VALID_ALG to add the valid algorithms into VALID_ALGS.
	 */
	for (const struct ike_alg **default_alg = default_algs;
	     *default_alg; default_alg++) {
		verbose.level = level;
		const struct ike_alg *alg = *default_alg;
		if (!alg_byname_ok(parser, alg,
				   shunk1(alg->fqn))) {
			vdbg("skipping default %s",
			     str_diag(parser->diag));
			pfree_diag(&parser->diag);
			continue;
		}
		/* add it */
		vdbg("adding default %s %s %s", transform_type->name, alg->type->story, alg->fqn);
		verbose.level++;
		struct v1_proposal merged_proposal = merge_alg_default(*proposal,
								       transform_type,
								       (*default_alg));
		if (!add_proposal_defaults(parser, proposals, &merged_proposal, verbose)) {
			vassert(parser->diag != NULL);
			return false;
		}
	}
	return true;
}

/*
 * Validate the proposal and, suppressing duplicates, add it to the
 * proposal list.
 */

static bool add_proposal(struct proposal_parser *parser,
			 struct proposals *proposals,
			 const struct v1_proposal *proposal,
			 struct verbose verbose)
{
	struct proposal *new = alloc_proposal(parser);
	if (proposal->encrypt != NULL) {
		append_proposal_transform(parser, new, transform_type_encrypt,
					  &proposal->encrypt->common,
					  proposal->enckeylen,
					  verbose);
	}
#define A(NAME)								\
	if (proposal->NAME != NULL) {					\
		append_proposal_transform(parser, new,			\
					  transform_type_##NAME,	\
					  &proposal->NAME->common,	\
					  0/*enckeylen*/,		\
					  verbose);			\
	}
	A(prf);
	A(integ);
	A(kem);
#undef A
	/* back end? */
	if (!proposal->protocol->proposal_ok(parser, new)) {
		free_proposal(&new);
		return false;
	}
	append_proposal(parser, proposals, &new, verbose);
	return true;
}

/*
 * For all the algorithms, when an algorithm is missing (NULL), and
 * there are defaults, add them.
 */

static bool add_proposal_defaults(struct proposal_parser *parser,
				  struct proposals *proposals,
				  const struct v1_proposal *proposal,
				  struct verbose verbose)
{
	const struct proposal_defaults *defaults = parser->protocol->defaults;
	/*
	 * Note that the order in which things are recursively added -
	 * MODP, ENCR, PRF/HASH - affects test results.  It determines
	 * things like the order of proposals.
	 */
	if (proposal->kem == NULL &&
	    defaults->transform[PROPOSAL_TRANSFORM_kem] != NULL) {
		return add_alg_defaults(parser, proposals, proposal,
					transform_type_kem,
					verbose);
	} else if (proposal->encrypt == NULL &&
		   defaults->transform[PROPOSAL_TRANSFORM_encrypt] != NULL) {
		return add_alg_defaults(parser, proposals, proposal,
					transform_type_encrypt,
					verbose);
	} else if (proposal->prf == NULL &&
		   defaults->transform[PROPOSAL_TRANSFORM_prf] != NULL) {
		return add_alg_defaults(parser, proposals, proposal,
					transform_type_prf,
					verbose);
	} else if (proposal->integ == NULL &&
		   proposal->encrypt != NULL &&
		   encrypt_desc_is_aead(proposal->encrypt)) {
		/*
		 * Since AEAD, integrity is always 'none'.
		 */
		struct v1_proposal merged_proposal = *proposal;
		merged_proposal.integ = &ike_alg_integ_none;
		return add_proposal_defaults(parser, proposals, &merged_proposal, verbose);
	} else if (proposal->integ == NULL &&
		   defaults->transform[PROPOSAL_TRANSFORM_integ] != NULL) {
		return add_alg_defaults(parser, proposals, proposal,
					transform_type_integ,
					verbose);
	} else if (proposal->integ == NULL &&
		   proposal->prf != NULL &&
		   proposal->encrypt != NULL &&
		   !encrypt_desc_is_aead(proposal->encrypt)) {
		/*
		 * Since non-AEAD, use an integrity algorithm that is
		 * implemented using the PRF.
		 */
		struct v1_proposal merged_proposal = *proposal;
		for (const struct integ_desc **algp = next_integ_desc(NULL);
		     algp != NULL; algp = next_integ_desc(algp)) {
			const struct integ_desc *alg = *algp;
			if (alg->prf == proposal->prf) {
				merged_proposal.integ = alg;
				break;
			}
		}
		if (merged_proposal.integ == NULL) {
			proposal_error(parser, "%s integrity derived from PRF %s is not supported",
				       proposal->protocol->name,
				       proposal->prf->common.fqn);
			return false;
		}
		return add_proposal_defaults(parser, proposals, &merged_proposal, verbose);
	} else {
		return add_proposal(parser, proposals, proposal, verbose);
	}
}

static bool parse_ikev1_proposal(struct proposal_parser *parser,
				 struct proposals *proposals,
				 struct proposal *scratch_proposal,
				 shunk_t proposal,
				 struct verbose verbose)
{
	/*
	 * Catch the obvious case of a proposal containing '+' early.
	 * Vis:
	 *
	 *   ike=aes-sha1+sha2
	 *
	 * Complaining about '+' is hopefully less confusing then,
	 * later, complaining about duplicate transform types or bad
	 * lookups.
	 *
	 * Note that this doesn't catch all cases.  For instance:
	 *
	 *   ike=aes-prf=sha1;prf=sha2
	 *
	 * That's handled further down.
	 */
	if (proposal.len > 0 && memchr(proposal.ptr, '+', proposal.len) != NULL) {
		proposal_error(parser, "'+' invalid, IKEv1 proposals do not support multiple transforms of the same type");
		return false;
	}

	if (!parse_proposal(parser, scratch_proposal, proposal, verbose)) {
		return false;
	}

	/*
	 * Catch:
	 *
	 *   ike=aes-prf=sha1;prf=sha2
	 *
	 * Here, it's assumed that the only way to get multiple
	 * transforms of the same type is to use '='.  Don't reject
	 * '=' outright though as correct use of '=' is reasonable.
	 */
	for (const struct transform_type *transform_type = transform_type_floor;
	     transform_type < transform_type_roof; transform_type++) {
		struct transform_algorithms *algorithms =
			transform_algorithms(scratch_proposal, transform_type);
		if (algorithms != NULL && algorithms->len > 1) {
			proposal_error(parser, "IKEv1 does not support multiple transforms of the same type ('=' invalid)");
			return false;
		}
	}

	/*
	 * Merge is a misnomer.
	 *
	 * Because IKEv1 does not allow multiple algorithms for a
	 * transform this call gets to expand all combinations of the
	 * defaults into lots of little proposals.
	 */
	struct v1_proposal v1 = v1_proposal(scratch_proposal);
	return add_proposal_defaults(parser, proposals, &v1, verbose);
}

bool v1_proposals_parse_str(struct proposal_parser *parser,
			    struct proposals *proposals,
			    shunk_t alg_str,
			    struct verbose verbose)
{
	if (alg_str.len == 0) {
		/* XXX: hack to keep testsuite happy */
		proposal_error(parser, "%s proposal is empty", parser->protocol->name);
		return false;
	}

	shunk_t prop_ptr = alg_str;
	do {
		/* find the next proposal */
		shunk_t proposal = shunk_token(&prop_ptr, NULL, ",");
		/* parse it */
		struct proposal *scratch_proposal = alloc_proposal(parser);
		if (!parse_ikev1_proposal(parser, proposals, scratch_proposal, proposal, verbose)) {
			free_proposal(&scratch_proposal);
			vassert(parser->diag != NULL);
			return false;
		}
		free_proposal(&scratch_proposal);
	} while (prop_ptr.ptr != NULL);
	return true;
}
