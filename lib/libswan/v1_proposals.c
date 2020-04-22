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
#include "ike_alg_dh.h"
#include "alg_byname.h"

/*
 * Add the proposal defaults for the specific algorithm.
 */

typedef struct v1_proposal merge_alg_default_t(struct v1_proposal proposal,
					       const struct ike_alg *default_alg);

static struct v1_proposal merge_dh_default(struct v1_proposal proposal,
					   const struct ike_alg *default_alg)
{
	proposal.dh = dh_desc(default_alg);
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
	/*
	 * Use VALID_ALG to add the valid algorithms into VALID_ALGS.
	 */
	for (const struct ike_alg **default_alg = default_algs;
	     *default_alg; default_alg++) {
		const struct ike_alg *alg = *default_alg;
		if (!alg_byname_ok(parser, alg,
				   shunk1(alg->fqn))) {
			DBG(DBG_PROPOSAL_PARSER,
			    DBG_log("skipping default %s",
				    parser->error));
			parser->error[0] = '\0';
			continue;
		}
		/* add it */
		DBG(DBG_PROPOSAL_PARSER,
		    DBG_log("adding default %s %s",
			    ike_alg_type_name(type),
			    alg->fqn));
		struct v1_proposal merged_proposal = merge_alg_default(*proposal,
									 *default_alg);
		if (!add_proposal_defaults(parser, defaults,
					   proposals, &merged_proposal)) {
			passert(parser->error[0] != '\0');
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
		append_algorithm(parser, new,
				 &proposal->encrypt->common,
				 proposal->enckeylen);
	}
#define A(NAME)								\
	if (proposal->NAME != NULL) {					\
		append_algorithm(parser, new, &proposal->NAME->common,	\
				 0/*enckeylen*/);			\
	}
	A(prf);
	A(integ);
	A(dh);
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
	if (proposal->dh == NULL &&
	    defaults != NULL && defaults->dh != NULL) {
		return add_alg_defaults(parser, defaults,
					proposals, proposal,
					&ike_alg_dh, defaults->dh,
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
			proposal_error(parser, "%s integrity derived from PRF '%s' is not supported",
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
	passert(parser->policy->version < elemsof(proposal->protocol->defaults));
	const struct proposal_defaults *defaults =
		proposal->protocol->defaults[parser->policy->version];
	return add_proposal_defaults(parser, defaults,
				     proposals, proposal);
}

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

/*
 * Try to parse any of <ealg>-<ekeylen>, <ealg>_<ekeylen>,
 * <ealg><ekeylen>, or <ealg>.  Strings like aes_gcm_16 and
 * aes_gcm_16_256 end up in alg[0], while strings like aes_gcm_16-256
 * end up in alg[0]-alg[1].
 */

struct token {
	char sep;
	shunk_t alg;
};

static bool parse_encrypt(struct proposal_parser *parser,
			  struct token **tokens,
			  struct v1_proposal *proposal)
{
	shunk_t ealg = (*tokens)[0].alg;
	shunk_t eklen = (*tokens)[1].alg;
	if (eklen.len > 0 && hunk_char_isdigit(eklen, 0)) {
		/* assume <ealg>-<eklen> */
		int enckeylen = parse_eklen(parser, eklen);
		if (enckeylen <= 0) {
			passert(parser->error[0] != '\0');
			return false;
		}
		/* print <alg>-<len> */
		shunk_t print_name = shunk2(ealg.ptr, eklen.ptr + eklen.len - ealg.ptr);
		proposal->enckeylen = enckeylen;
		proposal->encrypt =
			encrypt_desc(encrypt_alg_byname(parser,
							ealg, proposal->enckeylen,
							print_name));
		/* Was <ealg>-<eklen> rejected? */
		if (parser->error[0] != '\0') {
			return false;
		}
		*tokens += 2; /* consume both tokens */
		return true;
	}
	/* try <ealg> */
	shunk_t print_name = ealg;
	proposal->encrypt =
		encrypt_desc(encrypt_alg_byname(parser,
						ealg, proposal->enckeylen,
						print_name));
	if (parser->error[0] != '\0') {
		/*
		 * Could it be <ealg><eklen> or <ealg>_<eklen>?  Work
		 * backwards skipping any digits.
		 */
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
			passert(parser->error[0] != '\0');
			return false;
		}
		/* try to convert */
		shunk_t eklen = shunk_slice(ealg, end, ealg.len);
		int enckeylen = parse_eklen(parser, eklen);
		if (enckeylen <= 0) {
			passert(parser->error[0] != '\0');
			return false;
		}
		proposal->enckeylen = enckeylen;
		/*
		 * trim <eklen> from <ealg>; and then trim any
		 * trailing '_'
		 */
		ealg = shunk_slice(ealg, 0, end);
		if (hunk_char_ischar(ealg, ealg.len-1, "_")) {
			ealg = shunk_slice(ealg, 0, end-1);
		}
		/* try again */
		parser->error[0] = '\0';
		proposal->encrypt =
			encrypt_desc(encrypt_alg_byname(parser,
							ealg, proposal->enckeylen,
							print_name));
		if (parser->error[0] != '\0') {
			return false;
		}
	}
	*tokens += 1; /* consume one token */
	return true;
}

static bool parser_proposals_add(struct proposal_parser *parser,
				 struct token *tokens, struct v1_proposal proposal,
				 struct proposals *proposals)
{
	LSWDBGP(DBG_PROPOSAL_PARSER, buf) {
		lswlogs(buf, "algs:");
		for (struct token *token = tokens; token->alg.ptr != NULL; token++) {
			lswlogf(buf, " algs[%tu] = '"PRI_SHUNK"'",
				token - tokens, pri_shunk(token->alg));
		}
	}

	bool lookup_encrypt = parser->protocol->encrypt;
	if (!lookup_encrypt && impair.proposal_parser) {
		/* Force lookup, will discard any error. */
		lookup_encrypt = true;
	}
	if (lookup_encrypt && tokens->alg.ptr != NULL && tokens->sep != ';') {
		if (!parse_encrypt(parser, &tokens, &proposal)) {
			if (impair.proposal_parser) {
				/* ignore the lookup and stumble on */
				parser->error[0] = '\0';
			} else {
				passert(parser->error[0] != '\0');
				return false;
			}
		}
	}

	bool lookup_prf = parser->protocol->prf;
	if (!lookup_prf && impair.proposal_parser) {
		/*
		 * When impaired, only force PRF lookup when the the
		 * token after this one is a valid INTEG algorithm.
		 * Otherwise something like ah=sha1 gets parsed as
		 * ah=[encr]-sha1-[integ]-[dh] instead of
		 * ah=[encr]-[prf]-sha1-[dh].
		 */
		shunk_t prf = tokens[0].alg;
		shunk_t integ = tokens[1].alg;
		if (prf.ptr != NULL && integ.ptr != NULL) {
			lookup_prf = (alg_byname(parser, IKE_ALG_INTEG, integ, integ)
				      != NULL);
			parser->error[0] = '\0';
		}
	}
	if (lookup_prf && tokens->alg.ptr != NULL && tokens->sep != ';') {
		shunk_t prf = tokens[0].alg;
		proposal.prf = prf_desc(alg_byname(parser, IKE_ALG_PRF, prf, prf));
		if (parser->error[0] != '\0') {
			return false;
		}
		tokens += 1; /* consume one arg */
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
	if (!lookup_integ && impair.proposal_parser) {
		/* force things */
		lookup_integ = true;
	}
	if (lookup_integ && tokens->alg.ptr != NULL && tokens->sep != ';') {
		shunk_t integ = tokens[0].alg;
		proposal.integ = integ_desc(alg_byname(parser, IKE_ALG_INTEG, integ, integ));
		if (parser->error[0] != '\0') {
			if (tokens[1].alg.ptr != NULL) {
				/*
				 * This alg should have been
				 * integrity, since the next would be
				 * DH; error applies.
				 */
				passert(parser->error[0] != '\0');
				return false;
			}
			if (tokens[1].alg.ptr == NULL &&
			    !parser->protocol->prf) {
				/*
				 * Only one arg, integrity is preferred
				 * to DH (and no PRF); error applies.
				 */
				passert(parser->error[0] != '\0');
				return false;
			}
			/* let DH try */
			parser->error[0] = '\0';
		} else {
			tokens += 1; /* consume one arg */
		}
	}

	bool lookup_dh = parser->protocol->dh || impair.proposal_parser;
	if (lookup_dh && tokens->alg.ptr != NULL) {
		shunk_t dh = tokens[0].alg;
		proposal.dh = dh_desc(alg_byname(parser, IKE_ALG_DH, dh, dh));
		if (parser->error[0] != '\0') {
			return false;
		}
		tokens += 1; /* consume one arg */
	}

	if (tokens->alg.ptr != NULL) {
		proposal_error(parser, "'"PRI_SHUNK"' unexpected",
			       pri_shunk(tokens[0].alg));
		return false;
	}

	if (impair.proposal_parser) {
		return add_proposal(parser, proposals, &proposal);
	} else {
		return merge_default_proposals(parser, proposals, &proposal);
	}
}

bool v1_proposals_parse_str(struct proposal_parser *parser,
			    struct proposals *proposals,
			    shunk_t alg_str)
{
	DBG(DBG_PROPOSAL_PARSER,
	    DBG_log("parsing '"PRI_SHUNK"' for %s",
		    pri_shunk(alg_str), parser->protocol->name));

	if (alg_str.len == 0) {
		/* XXX: hack to keep testsuite happy */
		proposal_error(parser, "String ended with invalid char, just after \"\"");
		return false;
	}

	shunk_t prop_ptr = alg_str;
	do {
		/* find the next proposal */
		shunk_t prop = shunk_token(&prop_ptr, NULL, ",");
		/* parse it */
		struct token tokens[8];
		zero(&tokens);
		struct token *token = tokens;
		shunk_t alg_ptr = prop;
		char last_sep = '\0';
		do {
			if (token + 1 >= tokens+elemsof(tokens)) {
				/* space for NULL? */
				proposal_error(parser, "proposal too long");
				return false;
			}
			/* find the next alg */
			char alg_sep;
			shunk_t alg = shunk_token(&alg_ptr, &alg_sep, "-;,");
			*token++ = (struct token) {
				.alg = alg,
				.sep = last_sep,
			};
			last_sep = alg_sep; /* separator before this token */
		} while (alg_ptr.len > 0);
		struct v1_proposal proposal = {
			.protocol = parser->protocol,
		};
		if (!parser_proposals_add(parser, tokens, proposal,
					  proposals)) {
			passert(parser->error[0] != '\0');
			return false;
		}
	} while (prop_ptr.len > 0);
	return true;
}
