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

/*
 * Add the proposal defaults for the specific algorithm.
 */

typedef struct v1_proposal merge_alg_default_t(struct v1_proposal proposal,
					       const struct ike_alg *default_alg);

static struct v1_proposal merge_dh_default(struct v1_proposal proposal,
					   const struct ike_alg *default_alg)
{
	proposal.kem = kem_desc(default_alg);
	return proposal;
}

static struct v1_proposal merge_encrypt_default(struct v1_proposal proposal,
						const struct ike_alg *default_alg)
{
	proposal.encrypt = encrypt_desc(default_alg);
	return proposal;
}

static struct v1_proposal merge_prf_default(struct v1_proposal proposal,
					    const struct ike_alg *default_alg)
{
	proposal.prf = prf_desc(default_alg);
	return proposal;
}

static struct v1_proposal merge_integ_default(struct v1_proposal proposal,
					      const struct ike_alg *default_alg)
{
	proposal.integ = integ_desc(default_alg);
	return proposal;
}

static bool add_proposal_defaults(struct proposal_parser *parser,
				  const struct proposal_defaults *defaults,
				  struct proposals *proposals,
				  const struct v1_proposal *proposal);

static bool add_alg_defaults(struct proposal_parser *parser,
			     const struct proposal_defaults *defaults,
			     struct proposals *proposals,
			     const struct v1_proposal *proposal,
			     const struct ike_alg_type *type,
			     const struct ike_alg **default_algs,
			     merge_alg_default_t *merge_alg_default)
{
	const struct logger *logger = parser->policy->logger;
	/*
	 * Use VALID_ALG to add the valid algorithms into VALID_ALGS.
	 */
	for (const struct ike_alg **default_alg = default_algs;
	     *default_alg; default_alg++) {
		const struct ike_alg *alg = *default_alg;
		if (!alg_byname_ok(parser, alg,
				   shunk1(alg->fqn))) {
			ldbgf(DBG_PROPOSAL_PARSER, logger,
			      "skipping default %s",
			      str_diag(parser->diag));
			pfree_diag(&parser->diag);
			continue;
		}
		/* add it */
		ldbgf(DBG_PROPOSAL_PARSER, logger,
		      "adding default %s %s",
		      type->story, alg->fqn);
		struct v1_proposal merged_proposal = merge_alg_default(*proposal,
									 *default_alg);
		if (!add_proposal_defaults(parser, defaults,
					   proposals, &merged_proposal)) {
			passert(parser->diag != NULL);
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
			 const struct v1_proposal *proposal)
{
	struct proposal *new = alloc_proposal(parser);
	if (proposal->encrypt != NULL) {
		append_transform_algorithm(parser, new, PROPOSAL_TRANSFORM_encrypt,
					   &proposal->encrypt->common, proposal->enckeylen);
	}
#define A(NAME)								\
	if (proposal->NAME != NULL) {					\
		append_transform_algorithm(parser, new,			\
					   PROPOSAL_TRANSFORM_##NAME,	\
					   &proposal->NAME->common,	\
					   0/*enckeylen*/);		\
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
	append_proposal(proposals, &new);
	return true;
}

/*
 * For all the algorithms, when an algorithm is missing (NULL), and
 * there are defaults, add them.
 */

static bool add_proposal_defaults(struct proposal_parser *parser,
				  const struct proposal_defaults *defaults,
				  struct proposals *proposals,
				  const struct v1_proposal *proposal)
{
	/*
	 * Note that the order in which things are recursively added -
	 * MODP, ENCR, PRF/HASH - affects test results.  It determines
	 * things like the order of proposals.
	 */
	if (proposal->kem == NULL &&
	    defaults != NULL && defaults->kem != NULL) {
		return add_alg_defaults(parser, defaults,
					proposals, proposal,
					&ike_alg_kem, defaults->kem,
					merge_dh_default);
	} else if (proposal->encrypt == NULL &&
		   defaults != NULL && defaults->encrypt != NULL) {
		return add_alg_defaults(parser, defaults,
					proposals, proposal,
					&ike_alg_encrypt, defaults->encrypt,
					merge_encrypt_default);
	} else if (proposal->prf == NULL &&
		   defaults != NULL && defaults->prf != NULL) {
		return add_alg_defaults(parser, defaults,
					proposals, proposal,
					&ike_alg_prf, defaults->prf,
					merge_prf_default);
	} else if (proposal->integ == NULL &&
		   proposal->encrypt != NULL &&
		   encrypt_desc_is_aead(proposal->encrypt)) {
		/*
		 * Since AEAD, integrity is always 'none'.
		 */
		struct v1_proposal merged_proposal = *proposal;
		merged_proposal.integ = &ike_alg_integ_none;
		return add_proposal_defaults(parser, defaults,
					     proposals, &merged_proposal);
	} else if (proposal->integ == NULL &&
		   defaults != NULL && defaults->integ != NULL) {
		return add_alg_defaults(parser, defaults,
					proposals, proposal,
					&ike_alg_integ, defaults->integ,
					merge_integ_default);
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
		return add_proposal_defaults(parser, defaults,
					     proposals, &merged_proposal);
	} else {
		return add_proposal(parser, proposals, proposal);
	}
}

static bool merge_default_proposals(struct proposal_parser *parser,
				    struct proposals *proposals,
				    const struct v1_proposal *proposal)
{
	/*
	 * If there's a hint of IKEv1 being enabled then prefer its
	 * larger set of defaults.
	 *
	 * This should increase the odds of both ends interoperating.
	 *
	 * For instance, the IKEv2 defaults were preferred and one end
	 * has ikev2=never then, in aggressive mode, things don't
	 * work.
	 */
	const struct proposal_defaults *defaults = proposal->protocol->defaults;
	return add_proposal_defaults(parser, defaults,
				     proposals, proposal);
}

static bool parser_proposals_add(struct proposal_parser *parser,
				 struct proposal_tokenizer *tokens,
				 struct v1_proposal proposal,
				 struct proposals *proposals)
{
	if (parser->protocol->encrypt &&
	    tokens->curr.token.ptr != NULL &&
	    tokens->prev.delim != ';'/*not ;KEM*/) {
		const struct ike_alg *encrypt;
		int encrypt_keylen;
		if (!proposal_parse_encrypt(parser, tokens, &encrypt, &encrypt_keylen)) {
			passert(parser->diag != NULL);
			return false;
		}
		proposal.encrypt = encrypt_desc(encrypt);
		proposal.enckeylen = encrypt_keylen;
	}

	if (parser->protocol->prf &&
	    tokens->curr.token.ptr != NULL &&
	    tokens->prev.delim != ';'/*not ;KEM*/) {
		shunk_t prf = tokens[0].curr.token;
		proposal.prf = prf_desc(alg_byname(parser, &ike_alg_prf, prf, prf));
		if (parser->diag != NULL) {
			return false;
		}
		proposal_next_token(tokens);
	}

	/*
	 * By default, don't allow IKE's [...]-<prf>-<integ>-[....].
	 * Instead fill in integrity using the above PRF.
	 *
	 * XXX: The parser and output isn't consistent in that for ESP
	 * it parses <encry>-<integ> but for IKE it parses
	 * <encr>-<prf>.  This seems to lead to confusion when
	 * printing proposals - ike=aes_gcm-sha1 gets mis-read as as
	 * using sha1 as integrity.  ike-aes_gcm-none-sha1 would
	 * clarify this but that makes for a fun parse.
	 */
	bool lookup_integ = (!parser->protocol->prf && parser->protocol->integ);
	if (lookup_integ &&
	    tokens->curr.token.ptr != NULL &&
	    tokens->prev.delim != ';'/*not ;KEM*/) {
		shunk_t integ = tokens[0].curr.token;
		proposal.integ = integ_desc(alg_byname(parser, &ike_alg_integ, integ, integ));
		if (parser->diag != NULL) {
			if (tokens->next.token.ptr != NULL) {
				/*
				 * This alg should have been
				 * integrity, since the next would be
				 * DH; error applies.
				 */
				passert(parser->diag != NULL);
				return false;
			}
			if (tokens->next.token.ptr == NULL &&
			    !parser->protocol->prf) {
				/*
				 * Only one arg, integrity is preferred
				 * to DH (and no PRF); error applies.
				 */
				passert(parser->diag != NULL);
				return false;
			}
			/* let DH try */
			pfree_diag(&parser->diag);
		} else {
			proposal_next_token(tokens);
		}
	}

	if (parser->protocol->kem && tokens->curr.token.ptr != NULL) {
		shunk_t ke = tokens[0].curr.token;
		proposal.kem = kem_desc(alg_byname(parser, &ike_alg_kem, ke, ke));
		if (parser->diag != NULL) {
			return false;
		}
		proposal_next_token(tokens);
	}

	if (tokens->curr.token.ptr != NULL) {
		proposal_error(parser, "%s proposals contain unexpected '"PRI_SHUNK"'",
			       parser->protocol->name,
			       pri_shunk(tokens[0].curr.token));
		return false;
	}

	return merge_default_proposals(parser, proposals, &proposal);
}

bool v1_proposals_parse_str(struct proposal_parser *parser,
			    struct proposals *proposals,
			    shunk_t alg_str)
{
	const struct logger *logger = parser->policy->logger;
	ldbgf(DBG_PROPOSAL_PARSER, logger,
	      "parsing '"PRI_SHUNK"' for %s",
	      pri_shunk(alg_str), parser->protocol->name);

	if (alg_str.len == 0) {
		/* XXX: hack to keep testsuite happy */
		proposal_error(parser, "%s proposal is empty", parser->protocol->name);
		return false;
	}

	shunk_t prop_ptr = alg_str;
	do {
		/* find the next proposal */
		shunk_t prop = shunk_token(&prop_ptr, NULL, ",");
		/* parse it */
		struct proposal_tokenizer tokens = proposal_first_token(prop, "-;");
		struct v1_proposal proposal = {
			.protocol = parser->protocol,
		};
		if (!parser_proposals_add(parser, &tokens, proposal, proposals)) {
			passert(parser->diag != NULL);
			return false;
		}
	} while (prop_ptr.ptr != NULL);
	return true;
}
