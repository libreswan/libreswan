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
		append_algorithm(parser, proposal, algorithm, *alg, 0);
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
			append_algorithm(parser, proposal, PROPOSAL_integ,
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
						       prf->desc->name);
					return false;
				}
				append_algorithm(parser, proposal, PROPOSAL_integ,
						 &integ->common, 0);
			}
		}
	}
	merge_algorithms(parser, proposal, PROPOSAL_dh, defaults->dh);
	return true;
}

static bool parse_alg(struct proposal_parser *parser,
		      struct proposal *proposal,
		      enum proposal_algorithm algorithm,
		      alg_byname_fn *alg_byname,
		      shunk_t token, int enckeylen, shunk_t print,
		      const char *what)
{
	if (alg_byname == NULL) {
		/* n/a */
		return false;
	}
	if (token.len == 0) {
		/* will error at end */
		return false;
	}
	const struct ike_alg *alg = alg_byname(parser, token, enckeylen, print);
	if (alg == NULL) {
		if (DBGP(DBG_PROPOSAL_PARSER)) {
			DBG_log("%s_byname('"PRI_SHUNK"') failed: %s",
				what, PRI_shunk(token),
				parser->error);
		}
		pexpect(parser->error[0] != '\0');
		return false;
	}
	DBGF(DBG_PROPOSAL_PARSER, "adding %s algorithm %s[_%d]",
	     what, alg->name, enckeylen);
	append_algorithm(parser, proposal, algorithm, alg, enckeylen);
	return true;
}

/*
 * tokenize <input> into <delim><alg><input>
 */

struct token {
	char delim;
	shunk_t alg;
	shunk_t input;
};

static void next(struct token *token)
{
	if (token->delim == '\0') {
		/* first call, set delim to something bogus */
		token->delim = ' ';
	} else {
		token->delim = token->input.ptr != NULL ? token->input.ptr[-1] : ' ';
	}
	token->alg = shunk_strsep(&token->input, "-;+");
	if (DBGP(DBG_PROPOSAL_PARSER)) {
		if (token->alg.ptr == NULL) {
			DBG_log("delim: n/a  alg: end-of-input");
		} else {
			DBG_log("delim: '%c' alg: '"PRI_SHUNK"'",
				token->delim, PRI_shunk(token->alg));
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
			       PRI_shunk(buf));
		return 0;
	}
	if (eklen >= INT_MAX) {
		proposal_error(parser, "encryption key length '"PRI_SHUNK"' WAY too big",
			       PRI_shunk(buf));
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
	alg_byname_fn *alg_byname = parser->protocol->encrypt_alg_byname;
	if (alg_byname == NULL) {
		return false;
	}
	if (token->alg.len == 0) {
		return false;
	}
	shunk_t ealg = token->alg;
	/* try <ealg=token>-<eklen=lookahead> using look-ahead? */
	struct token lookahead = *token;
	next(&lookahead);
	if (lookahead.delim == '-' &&
	    lookahead.alg.len > 0 &&
	    isdigit(lookahead.alg.ptr[0])) {
		shunk_t eklen = lookahead.alg;
		/* assume <ealg>-<eklen> */
		int enckeylen = parse_eklen(parser, eklen);
		if (enckeylen <= 0) {
			pexpect(parser->error[0] != '\0');
			return false;
		}
		/* print "<ealg>-<eklen>" in errors */
		shunk_t print_name = shunk2(ealg.ptr, eklen.ptr + eklen.len - ealg.ptr);
		if (!parse_alg(parser, proposal, PROPOSAL_encrypt, alg_byname,
			       ealg, enckeylen, print_name, "encrypt")) {
			return false;
		}
		*token = lookahead;
		return true;
	}
	/* try <ealg> (no key len) */
	shunk_t print_name = token->alg;
	if (!parse_alg(parser, proposal, PROPOSAL_encrypt, alg_byname,
		       ealg, 0, print_name, "encrypt")) {
		/*
		 * Could it be <ealg><eklen> or <ealg>_<eklen>?  Work
		 * backwards skipping any digits.
		 */
		shunk_t end = shunk2(ealg.ptr + ealg.len, 0);
		while (end.ptr > ealg.ptr && isdigit(end.ptr[-1])) {
			end.ptr--;
			end.len++;
		}
		if (end.len == 0) {
			/*
			 * no trailing <eklen> and <ealg> was rejected
			 */
			pexpect(parser->error[0] != '\0');
			return false;
		}
		/* try to convert */
		int enckeylen = parse_eklen(parser, end);
		if (enckeylen <= 0) {
			pexpect(parser->error[0] != '\0');
			return false;
		}
		/*
		 * trim <eklen> from <ealg>; and then trim any
		 * trailing '_'
		 */
		ealg.len = end.ptr - ealg.ptr;
		if (end.ptr > ealg.ptr && end.ptr[-1] == '_') {
			ealg.len -= 1;
		}
		/* try again */
		if (!parse_alg(parser, proposal, PROPOSAL_encrypt, alg_byname,
			       ealg, enckeylen, print_name, "encrypt")) {
			return false;
		}
	}
	return true;
}

static bool parse_proposal(struct proposal_parser *parser,
			   struct proposals *proposals, shunk_t input)
{
	if (DBGP(DBG_PROPOSAL_PARSER)) {
		DBG_log("proposal: '"PRI_SHUNK"'", PRI_shunk(input));
	}

	char error[sizeof(parser->error)] = "";
	struct proposal *proposal = alloc_proposal(parser);

	struct token token = {
		.input = input,
	};
	next(&token);
	/*
	 * Encryption is not optional.
	 */
	bool lookup_encrypt = parser->protocol->encrypt_alg_byname != NULL;
	if (lookup_encrypt) {
		if (!parse_encrypt(parser, proposal, &token)) {
			free_proposal(&proposal);
			return false;
		}
		error[0] = parser->error[0] = '\0';
		next(&token);
		while (token.delim == '+' &&
		       parse_encrypt(parser, proposal, &token)) {
			error[0] = parser->error[0] = '\0';
			next(&token);
		}
	}
#define PARSE_ALG(STOP, ALG)						\
	if (error[0] == '\0' && parser->error[0] != '\0') {		\
		strcpy(error, parser->error);				\
		DBGF(DBG_PROPOSAL_PARSER, "saved first error: %s", error); \
	}								\
	if (token.delim != STOP &&					\
	    parse_alg(parser, proposal, PROPOSAL_##ALG,			\
		      parser->protocol->ALG##_alg_byname,		\
		      token.alg, 0, token.alg, #ALG)) {			\
		error[0] = parser->error[0] = '\0';			\
		next(&token);						\
		while (token.delim == '+' &&				\
		       parse_alg(parser, proposal, PROPOSAL_##ALG,	\
				 parser->protocol->ALG##_alg_byname,	\
				 token.alg, 0, token.alg, #ALG)) {	\
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
	if (parser->protocol->prf_alg_byname == NULL ||
	    IMPAIR(PROPOSAL_PARSER)) {
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
			 PRI_shunk(token.alg));
		free_proposal(&proposal);
		return false;
	}
	if (!IMPAIR(PROPOSAL_PARSER) &&
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
		    PRI_shunk(input), parser->protocol->name));

	/* use default if no string */
	if (input.ptr == NULL) {
		struct proposal *proposal = alloc_proposal(parser);
		if (!merge_defaults(parser, proposal)) {
			free_proposal(&proposal);
			return false;
		}
		append_proposal(proposals, &proposal);
		return true;
	}

	if (input.len == 0) {
		/* XXX: hack to keep testsuite happy */
		proposal_error(parser, "String ended with invalid char, just after \"\"");
		return false;
	}

	do {
		/* find the next proposal */
		shunk_t proposal = shunk_strsep(&input, ",");
		if (!parse_proposal(parser, proposals, proposal)) {
			pexpect(parser->error[0] != '\0');
			return false;
		}
	} while (input.len > 0);
	return true;
}
