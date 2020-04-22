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
		parser->policy->warning("ignoring %s %s %s algorithm '"PRI_SHUNK"'",
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
					proposal_error(parser, "%s integrity derived from PRF '%s' is not supported",
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

/*
 * tokenize <input> into <delim><alg><next_delim><input>
 */

struct token {
	char delim;
	char next_delim;
	shunk_t alg;
	shunk_t input;
};

static void next(struct token *token)
{
	token->delim = token->next_delim;
	token->alg = shunk_token(&token->input, &token->next_delim, "-;+");
	if (DBGP(DBG_PROPOSAL_PARSER)) {
		if (token->alg.ptr == NULL) {
			DBG_log("delim: n/a  alg: end-of-input");
		} else {
			DBG_log("delim: '%c' alg: '"PRI_SHUNK"'",
				token->delim, pri_shunk(token->alg));
		}
	}
}

/*
 * Try to parse any of <ealg>-<ekeylen>, <ealg>_<ekeylen>,
 * <ealg><ekeylen>, or <ealg> using some look-ahead.
 */

static int parse_eklen(struct proposal_parser *parser, shunk_t buf)
{
	/* convert -<eklen> if present */
	char *end = NULL;
	long eklen = strtol(buf.ptr, &end, 10);
	if (buf.ptr + buf.len != end) {
		proposal_error(parser, "encryption key length '"PRI_SHUNK"' contains a non-numeric character",
			       pri_shunk(buf));
		return 0;
	}
	if (eklen >= INT_MAX) {
		proposal_error(parser, "encryption key length '"PRI_SHUNK"' WAY too big",
			       pri_shunk(buf));
		return 0;
	}
	if (eklen == 0) {
		proposal_error(parser, "encryption key length is zero");
		return 0;
	}
	return eklen;
}

static bool parse_encrypt(struct proposal_parser *parser,
			  struct proposal *proposal, struct token *token)
{
	if (token->alg.len == 0) {
		return false;
	}
	/*
	 * Does it match <ealg>-<eklen>?
	 *
	 * Use lookahead to check <eklen> first.  If it starts with a
	 * digit then just assume <ealg>-<ealg> and error out if it is
	 * not so.
	 */
	{
		shunk_t ealg = token->alg;
		struct token lookahead = *token;
		next(&lookahead);
		if (lookahead.delim == '-' &&
		    lookahead.alg.len > 0 &&
		    hunk_char_isdigit(lookahead.alg, 0)) {
			shunk_t eklen = lookahead.alg;
			/* assume <ealg>-<eklen> */
			int enckeylen = parse_eklen(parser, eklen);
			if (enckeylen <= 0) {
				pexpect(parser->error[0] != '\0');
				return false;
			}
			/* print "<ealg>-<eklen>" in errors */
			shunk_t print = shunk2(ealg.ptr, eklen.ptr + eklen.len - ealg.ptr);
			const struct ike_alg *alg = encrypt_alg_byname(parser, ealg,
								       enckeylen, print);
			if (alg == NULL) {
				DBGF(DBG_PROPOSAL_PARSER, "<ealg>byname('"PRI_SHUNK"') with <eklen>='"PRI_SHUNK"' failed: %s",
				     pri_shunk(ealg), pri_shunk(eklen), parser->error);
				return false;
			}
			*token = lookahead;
			append_algorithm(parser, proposal, alg, enckeylen);
			return true;
		}
	}
	/*
	 * Does it match <ealg> (without any _<eklen> suffix?)
	 */
	const shunk_t print = token->alg;
	{
		shunk_t ealg = token->alg;
		const struct ike_alg *alg = encrypt_alg_byname(parser, ealg,
							       0/*enckeylen*/, print);
		if (alg != NULL) {
			append_algorithm(parser, proposal, alg, 0/*enckeylen*/);
			return true;
		}
	}
	/* buffer still contains error from <ealg> lookup */
	pexpect(parser->error[0] != '\0');
	/*
	 * Does it match <ealg><eklen> or <ealg>_<eklen>?  Strip
	 * trailing digits from <ealg> to form <eklen> and then try
	 * doing a lookup.
	 */
	{
		shunk_t ealg = token->alg;
		size_t end = ealg.len;
		while (end > 0 && hunk_char_isdigit(ealg, end-1)) {
			end--;
		}
		if (end == ealg.len) {
			/*
			 * no trailing <eklen> digits and <ealg> was
			 * rejected by above); error still contains
			 * message from not finding just <ealg>.
			 */
			return warning_or_false(parser, "encryption", print);
		}
		/* try to convert */
		shunk_t eklen = shunk_slice(ealg, end, ealg.len);
		int enckeylen = parse_eklen(parser, eklen);
		if (enckeylen <= 0) {
			pexpect(parser->error[0] != '\0');
			return false;
		}
		/*
		 * trim <eklen> from <ealg>; and then trim any
		 * trailing '_'
		 */
		ealg = shunk_slice(ealg, 0, end);
		if (hunk_char_ischar(ealg, ealg.len-1, "_")) {
			ealg = shunk_slice(ealg, 0, ealg.len-1);
		}
		/* try again */
		const struct ike_alg *alg = encrypt_alg_byname(parser, ealg,
							       enckeylen, print);
		if (alg != NULL) {
			append_algorithm(parser, proposal, alg, enckeylen);
			return true;
		}
	}
	return warning_or_false(parser, "encryption", print);
}

static bool parse_proposal(struct proposal_parser *parser,
			   struct proposals *proposals, shunk_t input)
{
	if (DBGP(DBG_PROPOSAL_PARSER)) {
		DBG_log("proposal: '"PRI_SHUNK"'", pri_shunk(input));
	}

	char error[sizeof(parser->error)] = "";
	struct proposal *proposal = alloc_proposal(parser);

	struct token token = {
		.input = input,
	};
	next(&token);

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
		if (!parse_encrypt(parser, proposal, &token)) {
			free_proposal(&proposal);
			return false;
		}
		error[0] = parser->error[0] = '\0';
		next(&token);
		/* further encryption algorithm tokens are optional */
		while (token.delim == '+' &&
		       parse_encrypt(parser, proposal, &token)) {
			error[0] = parser->error[0] = '\0';
			next(&token);
		}
		/* deal with all encryption algorithm tokens being skipped */
		if (next_algorithm(proposal, PROPOSAL_encrypt, NULL) == NULL) {
			if (parser->policy->ignore_parser_errors) {
				DBGF(DBG_PROPOSAL_PARSER, "all encryption algorithms skipped; stumbling on");
				free_proposal(&proposal);
				return true;
			}
			if (!impair.proposal_parser) {
				PEXPECT_LOG("all encryption algorithms skipped");
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
	if (token.delim != STOP &&					\
	    parser->protocol->ALG &&					\
	    parse_alg(parser, proposal,	&ike_alg_##ALG,	token.alg)) {	\
		error[0] = parser->error[0] = '\0';			\
		next(&token);						\
		while (token.delim == '+' &&				\
		       parse_alg(parser, proposal, &ike_alg_##ALG, token.alg)) { \
			error[0] = parser->error[0] = '\0';		\
			next(&token);					\
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
	if (token.alg.ptr != NULL) {
		proposal_error(parser, "'"PRI_SHUNK"' unexpected",
			 pri_shunk(token.alg));
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
	DBG(DBG_PROPOSAL_PARSER,
	    DBG_log("parsing '"PRI_SHUNK"' for %s",
		    pri_shunk(input), parser->protocol->name));

	if (input.len == 0) {
		/* XXX: hack to keep testsuite happy */
		proposal_error(parser, "String ended with invalid char, just after \"\"");
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
