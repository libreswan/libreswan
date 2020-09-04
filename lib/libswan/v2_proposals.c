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
#include "ike_alg_dh.h"
#include "alg_byname.h"

/*
 * No questions hack to either return 'false' for parsing token
 * failed, or 'true' and warn because forced parsing is enabled.
 */
static bool warning_or_false(struct proposal_parser *parser,
			     const char *what, shunk_t print)
{
	pexpect(parser->error[0] != '\0');
	bool result;
	if (parser->policy->ignore_parser_errors) {
		/*
		 * XXX: the algorithm might be unknown, or might be
		 * known but not enabled due to FIPS, or ...?
		 */
		log_message(RC_LOG, parser->policy->logger,
			    "ignoring %s %s %s algorithm '"PRI_SHUNK"'",
			    enum_name(&ike_version_names, parser->policy->version),
			    parser->protocol->name, /* ESP|IKE|AH */
			    what, pri_shunk(print));
		result = true;
	} else {
		DBGF(DBG_PROPOSAL_PARSER,
		     "lookup for %s algorithm '"PRI_SHUNK"' failed",
		     what, pri_shunk(print));
		result = false;
	}
	return result;
}

/*
 * For all the algorithms, when an algorithm is missing (NULL), and
 * there are defaults, add them.
 */

static void merge_algorithms(struct proposal_parser *parser,
			     struct proposal *proposal,
			     enum proposal_algorithm algorithm,
			     const struct ike_alg **defaults)
{
	if (defaults == NULL) {
		return;
	}
	if (next_algorithm(proposal, algorithm, NULL) != NULL) {
		return;
	}
	for (const struct ike_alg **alg = defaults; (*alg) != NULL; alg++) {
		append_algorithm(parser, proposal, *alg, 0);
	}
}

static bool merge_defaults(struct proposal_parser *parser,
			   struct proposal *proposal)
{
	pexpect(parser->policy->version < elemsof(parser->protocol->defaults));
	const struct proposal_defaults *defaults =
		parser->protocol->defaults[parser->policy->version];
	merge_algorithms(parser, proposal, PROPOSAL_encrypt, defaults->encrypt);
	merge_algorithms(parser, proposal, PROPOSAL_prf, defaults->prf);
	if (next_algorithm(proposal, PROPOSAL_integ, NULL) == NULL) {
		if (proposal_encrypt_aead(proposal)) {
			/*
			 * Since AEAD, integrity is always 'none'.
			 */
			append_algorithm(parser, proposal,
					 &ike_alg_integ_none.common, 0);
		} else if (defaults->integ != NULL) {
			/*
			 * Merge in the defaults.
			 */
			merge_algorithms(parser, proposal, PROPOSAL_integ,
					 defaults->integ);
		} else if (next_algorithm(proposal, PROPOSAL_prf, NULL) != NULL &&
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
				append_algorithm(parser, proposal,
						 &integ->common, 0);
			}
		}
	}
	merge_algorithms(parser, proposal, PROPOSAL_dh, defaults->dh);
	return true;
}

static bool parse_alg(struct proposal_parser *parser,
		      struct proposal *proposal,
		      const struct ike_alg_type *alg_type,
		      shunk_t token)
{
	if (token.len == 0) {
		/* will error at end */
		return false;
	}
	const struct ike_alg *alg = alg_byname(parser, alg_type, token,
					       token/*print*/);
	if (alg == NULL) {
		return warning_or_false(parser, ike_alg_type_name(alg_type), token);
	}
	append_algorithm(parser, proposal, alg, 0/*enckeylen*/);
	return true;
}

static bool parse_proposal(struct proposal_parser *parser,
			   struct proposals *proposals, shunk_t input)
{
	if (DBGP(DBG_PROPOSAL_PARSER)) {
		DBG_log("proposal: '"PRI_SHUNK"'", pri_shunk(input));
	}

	char error[sizeof(parser->error)] = "";
	struct proposal *proposal = alloc_proposal(parser);

	struct proposal_tokenizer tokens = proposal_first_token(input, "-;+");

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
	 * invalid on some IPsec stacks.  Normally this proposal will be
	 * rejected, but when IGNORE_PARSER_ERRORS (for default
	 * proposals) the code will instead stumble on.
	 */
	if (parser->protocol->encrypt) {
		/* first encryption algorithm token is expected */
		const struct ike_alg *encrypt;
		int encrypt_keylen;
		if (!proposal_parse_encrypt(parser, &tokens, &encrypt, &encrypt_keylen)) {
			free_proposal(&proposal);
			return false;
		}
		error[0] = parser->error[0] = '\0';
		append_algorithm(parser, proposal, encrypt, encrypt_keylen);
		/* further encryption algorithm tokens are optional */
		while (tokens.prev_term == '+' &&
		       proposal_parse_encrypt(parser, &tokens, &encrypt, &encrypt_keylen)) {
			error[0] = parser->error[0] = '\0';
			append_algorithm(parser, proposal, encrypt, encrypt_keylen);
		}
		/* deal with all encryption algorithm tokens being skipped */
		if (next_algorithm(proposal, PROPOSAL_encrypt, NULL) == NULL) {
			if (parser->policy->ignore_parser_errors) {
				DBGF(DBG_PROPOSAL_PARSER, "all encryption algorithms skipped; stumbling on");
				free_proposal(&proposal);
				return true;
			}
			if (!impair.proposal_parser) {
				pexpect_fail(parser->policy->logger, HERE,
					     "all encryption algorithms skipped");
				free_proposal(&proposal);
				return false;
			}
		}
	}

#define PARSE_ALG(STOP, ALG)						\
	if (error[0] == '\0' && parser->error[0] != '\0') {		\
		strcpy(error, parser->error);				\
		DBGF(DBG_PROPOSAL_PARSER, "saved first error: %s", error); \
	}								\
	if (tokens.prev_term != STOP &&				\
	    parser->protocol->ALG &&					\
	    parse_alg(parser, proposal,	&ike_alg_##ALG,	tokens.this)) { \
		error[0] = parser->error[0] = '\0';			\
		proposal_next_token(&tokens);				\
		while (tokens.prev_term == '+' &&			\
		       parse_alg(parser, proposal,			\
				 &ike_alg_##ALG, tokens.this)) {	\
			error[0] = parser->error[0] = '\0';		\
			proposal_next_token(&tokens);			\
		}							\
	}

	PARSE_ALG(';', prf);
	/*
	 * By default, don't allow ike=...-<prf>-<integ>-... but do
	 * allow esp=...-<integ>.  In the case of IKE, when integrity
	 * is required, it is filled in using the PRF.
	 *
	 * XXX: The parser and output isn't consistent in that for ESP
	 * it parses <encry>-<integ> but for IKE it parses
	 * <encr>-<prf>.  This seems to lead to confusion when
	 * printing proposals - ike=aes_gcm-sha1 gets mis-read as as
	 * using sha1 as integrity.  ike-aes_gcm-none-sha1 would
	 * clarify this but that makes for a fun parse.
	 */
	if (!parser->protocol->prf || impair.proposal_parser) {
		PARSE_ALG(';', integ);
	}
	PARSE_ALG('\0', dh);
	if (error[0] != '\0') {
		DBGF(DBG_PROPOSAL_PARSER, "return first error: %s", error);
		free_proposal(&proposal);
		strcpy(parser->error, error);
		return false;
	}
	if (parser->error[0] != '\0') {
		DBGF(DBG_PROPOSAL_PARSER, "return last error: %s", parser->error);
		free_proposal(&proposal);
		return false;
	}
	if (tokens.this.ptr != NULL) {
		proposal_error(parser, "%s proposal contains unexpected '"PRI_SHUNK"'",
			       parser->protocol->name,
			       pri_shunk(tokens.this));
		free_proposal(&proposal);
		return false;
	}
	if (!impair.proposal_parser &&
	    !merge_defaults(parser, proposal)) {
		free_proposal(&proposal);
		return false;
	}
	/* back end? */
	if (!parser->protocol->proposal_ok(parser, proposal)) {
		free_proposal(&proposal);
		return false;
	}
	append_proposal(proposals, &proposal);
	return true;
}

bool v2_proposals_parse_str(struct proposal_parser *parser,
			    struct proposals *proposals,
			    shunk_t input)
{
	DBGF(DBG_PROPOSAL_PARSER, "parsing '"PRI_SHUNK"' for %s",
	     pri_shunk(input), parser->protocol->name);

	if (input.len == 0) {
		/* XXX: hack to keep testsuite happy */
		proposal_error(parser, "%s proposal is empty",
			       parser->protocol->name);
		return false;
	}

	do {
		/* find the next proposal */
		shunk_t proposal = shunk_token(&input, NULL, ",");
		if (!parse_proposal(parser, proposals, proposal)) {
			pexpect(parser->error[0] != '\0');
			return false;
		}
	} while (input.len > 0);
	return true;
}
