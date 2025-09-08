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
			     enum proposal_transform transform,
			     const struct ike_alg **defaults)
{
	if (defaults == NULL) {
		return;
	}
	if (first_transform_algorithm(proposal, transform) != NULL) {
		return;
	}
	for (const struct ike_alg **alg = defaults; (*alg) != NULL; alg++) {
		append_proposal_transform(parser, proposal, transform, *alg, 0);
	}
}

static bool merge_defaults(struct proposal_parser *parser,
			   struct proposal *proposal)
{
	const struct proposal_defaults *defaults = parser->protocol->defaults;
	merge_algorithms(parser, proposal, PROPOSAL_TRANSFORM_encrypt, defaults->encrypt);
	merge_algorithms(parser, proposal, PROPOSAL_TRANSFORM_prf, defaults->prf);
	if (first_transform_algorithm(proposal, PROPOSAL_TRANSFORM_integ) == NULL) {
		if (proposal_encrypt_aead(proposal)) {
			/*
			 * Since AEAD, integrity is always 'none'.
			 */
			append_proposal_transform(parser, proposal,
						  PROPOSAL_TRANSFORM_integ,
						  &ike_alg_integ_none.common, 0);
		} else if (defaults->integ != NULL) {
			/*
			 * Merge in the defaults.
			 */
			merge_algorithms(parser, proposal, PROPOSAL_TRANSFORM_integ,
					 defaults->integ);
		} else if (first_transform_algorithm(proposal, PROPOSAL_TRANSFORM_prf) != NULL &&
			   proposal_encrypt_norm(proposal)) {
			/*
			 * Since non-AEAD, use integrity algorithms
			 * that are implemented using the PRFs.
			 */
			FOR_EACH_ALGORITHM(proposal, prf, prf) {
				const struct integ_desc *integ = NULL;
				for (const struct integ_desc **integp = next_integ_desc(NULL);
				     integp != NULL; integp = next_integ_desc(integp)) {
					if ((*integp)->prf != NULL &&
					    &(*integp)->prf->common == prf->desc) {
						integ = *integp;
						break;
					}
				}
				if (integ == NULL) {
					proposal_error(parser, "%s integrity derived from PRF %s is not supported",
						       parser->protocol->name,
						       prf->desc->fqn);
					return false;
				}
				append_proposal_transform(parser, proposal,
							  PROPOSAL_TRANSFORM_integ,
							  &integ->common, 0);
			}
		}
	}
	merge_algorithms(parser, proposal, PROPOSAL_TRANSFORM_kem, defaults->kem);
	return true;
}

static bool parse_transform_algorithms(struct proposal_parser *parser,
				       struct proposal *proposal,
				       enum proposal_transform transform,
				       struct proposal_tokenizer *tokens)
{
	const struct logger *logger = parser->policy->logger;
	const struct ike_alg_type *transform_type = proposal_transform_type[transform];
	PASSERT(logger, transform_type != NULL);
	name_buf tb;
	ldbgf(DBG_PROPOSAL_PARSER, logger, "parsing %s(%d) of type %s",
	      str_enum_short(&proposal_transform_names, transform, &tb),
	      transform, transform_type->name);

	PASSERT(logger, parser->diag == NULL); /* so far so good */
	if (!parse_proposal_transform(parser, proposal, transform,
				      tokens->curr.token)) {
		return false;
	}

	passert(parser->diag == NULL); /* still good */
	proposal_next_token(tokens);
	while (tokens->prev.delim == '+') {
		if (!parse_proposal_transform(parser, proposal, transform,
					      tokens->curr.token)) {
			return false;
		}
		passert(parser->diag == NULL);
		proposal_next_token(tokens);
	}

	remove_duplicate_algorithms(parser, proposal, transform);
	return true;
}

static bool parse_encrypt_transforms(struct proposal_parser *parser,
				     struct proposal *proposal,
				     struct proposal_tokenizer *tokens)
{
	/*
	 * Encryption.
	 *
	 * When encryption is part of the proposal, at least one
	 * (encryption algorithm) token should be present, further
	 * tokens are optional.
	 *
	 * Each token is then converted to an encryption algorithm and
	 * added to the proposal, and any invalid algorithm causing
	 * the whole proposal to be rejected.
	 *
	 * However, when either ignore IGNORE_PARSER_ERRORS or IMPAIR,
	 * invalid algorithms are instead skipped and this can result
	 * in a proposal with no encryption algorithm.
	 *
	 * For instance, the encryption algorithm "AES_GCM" might be
	 * invalid on some IPsec stacks.  Normally this proposal will
	 * be rejected, but when IGNORE_PARSER_ERRORS (for default
	 * proposals) the code will instead stumble on.
	 */

	/* first encryption algorithm token is expected */
	if (!parse_proposal_encrypt_transform(parser, proposal, tokens)) {
		passert(parser->diag != NULL);
		return false;
	}
	passert(parser->diag == NULL);

	/* further encryption algorithm tokens are optional */
	while (tokens->prev.delim == '+') {
		if (!parse_proposal_encrypt_transform(parser, proposal, tokens)) {
			passert(parser->diag != NULL);
			return false;
		}
		passert(parser->diag == NULL);
	}

	remove_duplicate_algorithms(parser, proposal, PROPOSAL_TRANSFORM_encrypt);
	return true;
}

static bool parse_prf_transforms(struct proposal_parser *parser,
				 struct proposal *proposal,
				 struct proposal_tokenizer *tokens)
{
	const struct logger *logger = parser->policy->logger;

	/*
	 * Try to parse:
	 *
	 *     <encr>-<PRF>...
	 *
	 * If it succeeds, assume the proposal is <encr>-<prf>-<kem>
	 * and not <encr>-<integ>-<prf>-<kem>.  The merge code will
	 * fill <integ> in with either NONE (AEAD) or the <prf>s
	 * converted to integ.
	 *
	 * If it fails, code below will try <encr>-<integ>-<prf>.
	 *
	 * This means, to specify integrity, the full integrity
	 * algorithm name is needed.  This means that
	 * aes_gcm-none-sha1-dh21 is easy but anything else is a pain.
	 * Hopefully this is ok as specifying integrity different to
	 * the PRF isn't something to encourage.
	 */

	struct proposal_tokenizer prf_tokens = (*tokens);
	if (parse_transform_algorithms(parser, proposal, PROPOSAL_TRANSFORM_prf, &prf_tokens)) {
		/* advance */
		ldbgf(DBG_PROPOSAL_PARSER, logger,
		      "<encr>-<PRF> succeeded, advancing tokens");
		(*tokens) = prf_tokens;
		return true;
	}

	if (!PEXPECT(logger, parser->protocol->integ)) {
		/* doesn't actually happen */
		return false;
	}

	/*
	 * Since <encr>-<PRF> failed, and integrity is expected, try:
	 *
	 *    <encr>-<INTEG>[-<PRF>]...
	 *
	 * But only after first reverting the work on PRFs.  Should
	 * the INTEG fail to parse, return the PRF diag (better
	 * message).
	 */

	diag_t prf_diag = NULL;
	discard_proposal_transform("<encr>-<PRF>", parser, proposal,
				   PROPOSAL_TRANSFORM_prf,
				   /*save the diag*/&prf_diag);

	if (!parse_transform_algorithms(parser, proposal, PROPOSAL_TRANSFORM_integ, tokens)) {
		ldbgf(DBG_PROPOSAL_PARSER, logger,
		      "both <encr>-<PRF> and <encr>-<INTEG> failed, returning earlier PRF error '%s' and discarding INTEG error '%s')",
		      str_diag(prf_diag), str_diag(parser->diag));
		pfree_diag(&parser->diag);
		parser->diag = prf_diag;
		return false;
	}

	pfree_diag(&prf_diag);

	if (tokens->curr.token.ptr == NULL /*more?*/ ||
	    tokens->prev.delim == ';' /*;KEM>*/) {
		return true;
	}

	if (!parse_transform_algorithms(parser, proposal, PROPOSAL_TRANSFORM_prf, tokens)) {
		ldbgf(DBG_PROPOSAL_PARSER, logger,
		      "<encr>-<integ>-<PRF> failed '%s'", str_diag(parser->diag));
		return false;
	}

	return true;
}

static bool parse_ikev2_transform(struct proposal_parser *parser,
				  struct proposal *proposal,
				  enum proposal_transform transform,
				  struct proposal_tokenizer *tokens)
{
	const struct logger *logger = parser->policy->logger;

	switch (transform) {

	case PROPOSAL_TRANSFORM_encrypt:
		if (parser->protocol->encrypt) {
			if (!parse_encrypt_transforms(parser, proposal, tokens)) {
				return false;
			}
		}
		break;

	case PROPOSAL_TRANSFORM_prf:
		if (parser->protocol->prf) {
			if (!parse_prf_transforms(parser, proposal, tokens)) {
				return false;
			}
		}
		break;

	case PROPOSAL_TRANSFORM_integ:
		if (parser->protocol->integ &&
		    !parser->protocol->prf) {
			if (!parse_transform_algorithms(parser, proposal, transform, tokens)) {
				ldbgf(DBG_PROPOSAL_PARSER, logger,
				      "either <encr>-<INTEG>... or <INTEG>... or failed: %s",
				      str_diag(parser->diag));
				return false;
			}
		}
		break;

	case PROPOSAL_TRANSFORM_kem:
		/*
		 * Parse:
		 *
		 *    ...;<DH>
		 *    <encr>-<prf>-<DH> (IKE)
		 *    <encr>-<integ>-<prf>-<DH> (IKE)
		 *    <encr>-<integ>-<DH> (ESP)
		 *    <integ>-<DH> (AH)
		 *
		 * But only when <encr>-<PRF> didn't succeed.
		 */
		if (parser->protocol->kem) {
			if (!parse_transform_algorithms(parser, proposal, PROPOSAL_TRANSFORM_kem, tokens)) {
				ldbgf(DBG_PROPOSAL_PARSER, logger,
				      "...<kem> failed: %s", str_diag(parser->diag));
				return false;
			}
		}
		break;

	case PROPOSAL_TRANSFORM_addke1:
	case PROPOSAL_TRANSFORM_addke2:
	case PROPOSAL_TRANSFORM_addke3:
	case PROPOSAL_TRANSFORM_addke4:
	case PROPOSAL_TRANSFORM_addke5:
	case PROPOSAL_TRANSFORM_addke6:
	case PROPOSAL_TRANSFORM_addke7:
		/*
		 * Parse additional key exchanges.
		 */
		if (parser->policy->addke) {
			if (!parse_transform_algorithms(parser, proposal, transform, tokens)) {
				name_buf tb;
				ldbgf(DBG_PROPOSAL_PARSER, logger,
				      "...<%s> failed: %s",
				      str_enum_short(&proposal_transform_names, transform, &tb),
				      str_diag(parser->diag));
				return false;
			}
		}
		break;
	}

	return true;
}

static bool parse_proposal(struct proposal_parser *parser,
			   struct proposal *proposal, shunk_t input)
{
	const struct logger *logger = parser->policy->logger;

	if (LDBGP(DBG_PROPOSAL_PARSER, logger)) {
		LDBG_log(logger, "proposal: '"PRI_SHUNK"'", pri_shunk(input));
	}

	struct proposal_tokenizer tokens = proposal_first_token(input, "-;+");

	/* hack to stop non ADDKE reporting missing ADDKE */
	enum proposal_transform ceiling = (parser->policy->addke ? PROPOSAL_TRANSFORM_addke7 :
					   PROPOSAL_TRANSFORM_kem);

	for (enum proposal_transform transform = PROPOSAL_TRANSFORM_FLOOR;
	     transform <= ceiling; transform++) {

		if (tokens.curr.token.ptr == NULL) {
			break;
		}

		/* when ';' skip forward to KEM */
		if (tokens.prev.delim == ';') {
			if (transform > PROPOSAL_TRANSFORM_kem) {
				name_buf tb;
				proposal_error(parser, "unexpected ';', expecting '-' followed by %s transform",
					       str_enum_short(&proposal_transform_names, transform, &tb));
				return false;
			}
			transform = PROPOSAL_TRANSFORM_kem;
		}

		if (!parse_ikev2_transform(parser, proposal, transform, &tokens)) {
			return false;
		}
	}

	/* end of token stream? */
	if (tokens.curr.token.ptr != NULL) {
		proposal_error(parser, "%s proposal contains unexpected '"PRI_SHUNK"'",
			       parser->protocol->name,
			       pri_shunk(tokens.curr.token));
		passert(parser->diag != NULL);
		return false;
	}

	return true;
}

static bool parse_ikev2_proposal(struct proposal_parser *parser,
				 struct proposal *proposal, shunk_t input)
{
	if (!parse_proposal(parser, proposal, input)) {
		return false;
	}

	if (!merge_defaults(parser, proposal)) {
		passert(parser->diag != NULL);
		return false;
	}

	/* back end? */
	if (!parser->protocol->proposal_ok(parser, proposal)) {
		passert(parser->diag != NULL);
		return false;
	}

	return true;
}

bool v2_proposals_parse_str(struct proposal_parser *parser,
			    struct proposals *proposals,
			    shunk_t input)
{
	const struct logger *logger = parser->policy->logger;
	ldbgf(DBG_PROPOSAL_PARSER, logger, "parsing '"PRI_SHUNK"' for %s",
	      pri_shunk(input), parser->protocol->name);

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
		if (!parse_ikev2_proposal(parser, proposal, raw_proposal)) {
			passert(parser->diag != NULL);
			free_proposal(&proposal);
			return false;
		}
		/*
		 * XXX: should check that the proposal hasn't ended up
		 * empty.
		 */
		passert(parser->diag == NULL);
		append_proposal(proposals, &proposal);
	} while (input.ptr != NULL);
	return true;
}
