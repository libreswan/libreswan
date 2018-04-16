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
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
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
#include "alg_info.h"
#include "ike_alg.h"
#include "alg_byname.h"
#include "ike_alg_none.h"

/*
 * Add the proposal defaults for the specific algorithm.
 */

typedef struct proposal_info merge_alg_default_t(struct proposal_info proposal,
						 const struct ike_alg *default_alg);

static struct proposal_info merge_dh_default(struct proposal_info proposal,
					     const struct ike_alg *default_alg)
{
	proposal.dh = oakley_group_desc(default_alg);
	return proposal;
}

static struct proposal_info merge_encrypt_default(struct proposal_info proposal,
						  const struct ike_alg *default_alg)
{
	proposal.encrypt = encrypt_desc(default_alg);
	return proposal;
}

static struct proposal_info merge_prf_default(struct proposal_info proposal,
					      const struct ike_alg *default_alg)
{
	proposal.prf = prf_desc(default_alg);
	return proposal;
}

static struct proposal_info merge_integ_default(struct proposal_info proposal,
						const struct ike_alg *default_alg)
{
	proposal.integ = integ_desc(default_alg);
	return proposal;
}

static bool add_proposal_defaults(const struct proposal_parser *parser,
				  const struct proposal_defaults *defaults,
				  struct alg_info *alg_info,
				  const struct proposal_info *proposal);

static bool add_alg_defaults(const struct proposal_parser *parser,
			     const struct proposal_defaults *defaults,
			     struct alg_info *alg_info,
			     const struct proposal_info *proposal,
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
				   shunk1(alg->name))) {
			DBG(DBG_PROPOSAL_PARSER,
			    DBG_log("skipping default %s",
				    parser->err_buf));
			parser->err_buf[0] = '\0';
			continue;
		}
		/* add it */
		DBG(DBG_PROPOSAL_PARSER,
		    DBG_log("adding default %s %s",
			    ike_alg_type_name(type),
			    alg->name));
		struct proposal_info merged_proposal = merge_alg_default(*proposal,
									 *default_alg);
		if (!add_proposal_defaults(parser, defaults,
					   alg_info, &merged_proposal)) {
			passert(parser->err_buf[0] != '\0');
			return false;
		}
	}
	return true;
}

/*
 * Validate the proposal and, suppressing duplicates, add it to the
 * proposal list.
 */

static bool add_proposal(const struct proposal_parser *parser,
			 struct alg_info *alg_info,
			 const struct proposal_info *proposal)
{
	/* duplicate? */
	FOR_EACH_PROPOSAL_INFO(alg_info, existing_proposal) {
		/*
		 * key length 0 is like a wild-card (it actually means
		 * propose default and strongest key lengths) so if
		 * either is zero just treat it as a match.
		 */
		if (existing_proposal->encrypt == proposal->encrypt &&
		    existing_proposal->prf == proposal->prf &&
		    existing_proposal->integ == proposal->integ &&
		    existing_proposal->dh == proposal->dh &&
		    (existing_proposal->enckeylen == proposal->enckeylen ||
		     existing_proposal->enckeylen == 0 ||
		     proposal->enckeylen == 0)) {
			if (IMPAIR(PROPOSAL_PARSER)) {
				libreswan_log("IMPAIR: including duplicate %s proposal encrypt=%s enckeylen=%zu prf=%s integ=%s dh=%s",
					      proposal->protocol->name,
					      proposal->encrypt != NULL ? proposal->encrypt->common.name : "n/a",
					      proposal->enckeylen,
					      proposal->prf != NULL ? proposal->prf->common.name : "n/a",
					      proposal->integ != NULL ? proposal->integ->common.name : "n/a",
					      proposal->dh != NULL ? proposal->dh->common.name : "n/a");
			} else {
				DBG(DBG_CRYPT,
				    DBG_log("discarding duplicate %s proposal encrypt=%s enckeylen=%zu prf=%s integ=%s dh=%s",
					    proposal->protocol->name,
					    proposal->encrypt != NULL ? proposal->encrypt->common.name : "n/a",
					    proposal->enckeylen,
					    proposal->prf != NULL ? proposal->prf->common.name : "n/a",
					    proposal->integ != NULL ? proposal->integ->common.name : "n/a",
					    proposal->dh != NULL ? proposal->dh->common.name : "n/a"));
				return true;
			}
		}
	}

	/* Overflow? */
	if ((unsigned)alg_info->alg_info_cnt >= elemsof(alg_info->proposals)) {
		snprintf(parser->err_buf, parser->err_buf_len,
			 "more than %zu %s algorithms specified",
			 elemsof(alg_info->proposals),
			 proposal->protocol->name);
		/* drop it like a rock */
		return false;
	}

	/* back end? */
	if (!proposal->protocol->proposal_ok(parser, proposal)) {
		return false;
	}

	alg_info->proposals[alg_info->alg_info_cnt++] = *proposal;
	return true;
}

/*
 * For all the algorithms, when an algorithm is missing (NULL), and
 * there are defaults, add them.
 */

static bool add_proposal_defaults(const struct proposal_parser *parser,
				  const struct proposal_defaults *defaults,
				  struct alg_info *alg_info,
				  const struct proposal_info *proposal)
{
	/*
	 * Note that the order in which things are recursively added -
	 * MODP, ENCR, PRF/HASH - affects test results.  It determines
	 * things like the order of proposals.
	 */
	if (proposal->dh == NULL &&
	    defaults != NULL && defaults->dh != NULL) {
		return add_alg_defaults(parser, defaults,
					alg_info, proposal,
					&ike_alg_dh, defaults->dh,
					merge_dh_default);
	} else if (proposal->encrypt == NULL &&
		   defaults != NULL && defaults->encrypt != NULL) {
		return add_alg_defaults(parser, defaults,
					alg_info, proposal,
					&ike_alg_encrypt, defaults->encrypt,
					merge_encrypt_default);
	} else if (proposal->prf == NULL &&
		   defaults != NULL && defaults->prf != NULL) {
		return add_alg_defaults(parser, defaults,
					alg_info, proposal,
					&ike_alg_prf, defaults->prf,
					merge_prf_default);
	} else if (proposal->integ == NULL &&
		   proposal->encrypt != NULL && ike_alg_is_aead(proposal->encrypt)) {
		/*
		 * Since AEAD, integrity is always 'none'.
		 */
		struct proposal_info merged_proposal = *proposal;
		merged_proposal.integ = &ike_alg_integ_none;
		return add_proposal_defaults(parser, defaults,
					     alg_info, &merged_proposal);
	} else if (proposal->integ == NULL &&
		   defaults != NULL && defaults->integ != NULL) {
		return add_alg_defaults(parser, defaults,
					alg_info, proposal,
					&ike_alg_integ, defaults->integ,
					merge_integ_default);
	} else if (proposal->integ == NULL &&
		   proposal->prf != NULL &&
		   proposal->encrypt != NULL && !ike_alg_is_aead(proposal->encrypt)) {
		/*
		 * Since non-AEAD, use an integrity algorithm that is
		 * implemented using the PRF.
		 */
		struct proposal_info merged_proposal = *proposal;
		for (const struct integ_desc **algp = next_integ_desc(NULL);
		     algp != NULL; algp = next_integ_desc(algp)) {
			const struct integ_desc *alg = *algp;
			if (alg->prf == proposal->prf) {
				merged_proposal.integ = alg;
				break;
			}
		}
		if (merged_proposal.integ == NULL) {
			snprintf(parser->err_buf, parser->err_buf_len,
				 "%s integrity derived from PRF '%s' is not supported",
				 proposal->protocol->name,
				 proposal->prf->common.name);
			return false;
		}
		return add_proposal_defaults(parser, defaults,
					     alg_info, &merged_proposal);
	} else {
		return add_proposal(parser, alg_info, proposal);
	}
}

static bool merge_default_proposals(const struct proposal_parser *parser,
				    struct alg_info *alg_info,
				    const struct proposal_info *proposal)
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
	const struct proposal_defaults *defaults = (parser->policy->ikev1
						    ? proposal->protocol->ikev1_defaults
						    : proposal->protocol->ikev2_defaults);
	return add_proposal_defaults(parser, defaults,
				     alg_info, proposal);
}

static const struct ike_alg *lookup_byname(const struct proposal_parser *parser,
					   alg_byname_fn *alg_byname,
					   shunk_t name,
					   size_t key_bit_length,
					   const char *what)
{
	if (name.len > 0) {
		if (alg_byname != NULL) {
			const struct ike_alg *alg = alg_byname(parser, name, key_bit_length);
			if (alg == NULL) {
				DBG(DBG_PROPOSAL_PARSER,
				    DBG_log("%s_byname('"PRISHUNK"') failed: %s",
					    what, SHUNKF(name),
					    parser->err_buf));
				passert(parser->err_buf[0] != '\0');
				return NULL;
			}
			DBG(DBG_PROPOSAL_PARSER,
			    DBG_log("%s_byname('"PRISHUNK"') returned '%s'",
				    what, SHUNKF(name), alg->name));
			return alg;
		} else {
			DBG(DBG_PROPOSAL_PARSER,
			    DBG_log("ignoring %s '"PRISHUNK"'",
				    what, SHUNKF(name)));
			return NULL;
		}
	}
	return NULL;
}

static int parse_eklen(char *err_buf, size_t err_buf_len,
		       shunk_t buf)
{
	/* convert -<eklen> if present */
	char *end = NULL;
	long eklen = strtol(buf.ptr, &end, 10);
	if (buf.ptr + buf.len != end) {
		snprintf(err_buf, err_buf_len,
			 "encryption key length '"PRISHUNK"' contains a non-numeric character",
			 SHUNKF(buf));
		return 0;
	}
	if (eklen >= INT_MAX) {
		snprintf(err_buf, err_buf_len,
			 "encryption key length '"PRISHUNK"' WAY too big",
			 SHUNKF(buf));
		return 0;
	}
	if (eklen == 0) {
		snprintf(err_buf, err_buf_len,
			 "encryption key length is zero");
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

static bool parse_encrypt(const struct proposal_parser *parser,
			  struct token **tokens,
			  struct proposal_info *proposal)
{
	shunk_t ealg = (*tokens)[0].alg;
	shunk_t eklen = (*tokens)[1].alg;
	if (eklen.len > 0 && isdigit(eklen.ptr[0])) {
		/* assume <ealg>-<eklen> */
		int enckeylen = parse_eklen(parser->err_buf,
					    parser->err_buf_len,
					    eklen);
		if (enckeylen <= 0) {
			passert(parser->err_buf[0] != '\0');
			return false;
		}
		proposal->enckeylen = enckeylen;
		proposal->encrypt =
			encrypt_desc(lookup_byname(parser,
						   encrypt_alg_byname,
						   ealg, proposal->enckeylen,
						   "encryption"));
		/* Was <ealg>-<eklen> rejected? */
		if (parser->err_buf[0] != '\0') {
			return false;
		}
		*tokens += 2; /* consume both tokens */
		return true;
	}
	/* try <ealg> */
	proposal->encrypt =
		encrypt_desc(lookup_byname(parser,
					   encrypt_alg_byname,
					   ealg, proposal->enckeylen,
					   "encryption"));
	if (parser->err_buf[0] != '\0') {
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
			passert(parser->err_buf[0] != '\0');
			return false;
		}
		/* try to convert */
		int enckeylen = parse_eklen(parser->err_buf, parser->err_buf_len, end);
		if (enckeylen <= 0) {
			passert(parser->err_buf[0] != '\0');
			return false;
		}
		proposal->enckeylen = enckeylen;
		/*
		 * trim <eklen> from <ealg>; and then trim any
		 * trailing '_'
		 */
		ealg.len = end.ptr - ealg.ptr;
		if (end.ptr > ealg.ptr && end.ptr[-1] == '_') {
			ealg.len -= 1;
		}
		/* try again */
		parser->err_buf[0] = '\0';
		proposal->encrypt =
			encrypt_desc(lookup_byname(parser,
						   encrypt_alg_byname,
						   ealg, proposal->enckeylen,
						   "encryption"));
		if (parser->err_buf[0] != '\0') {
			return false;
		}
	}
	*tokens += 1; /* consume one token */
	return true;
}

static bool parser_alg_info_add(const struct proposal_parser *parser,
				struct token *tokens, struct proposal_info proposal,
				struct alg_info *alg_info)
{
	LSWDBGP(DBG_PROPOSAL_PARSER, buf) {
		lswlogs(buf, "algs:");
		for (struct token *token = tokens; token->alg.ptr != NULL; token++) {
			lswlogf(buf, " algs[%zu] = '"PRISHUNK"'",
				token - tokens, SHUNKF(token->alg));
		}
	}

	bool lookup_encrypt = parser->protocol->encrypt_alg_byname != NULL;
	if (!lookup_encrypt && IMPAIR(PROPOSAL_PARSER)) {
		/* Force lookup, will discard any error. */
		lookup_encrypt = true;
	}
	if (lookup_encrypt && tokens->alg.ptr != NULL && tokens->sep != ';') {
		if (!parse_encrypt(parser, &tokens, &proposal)) {
			if (IMPAIR(PROPOSAL_PARSER)) {
				/* ignore the lookup and stumble on */
				parser->err_buf[0] = '\0';
			} else {
				passert(parser->err_buf[0] != '\0');
				return false;
			}
		}
	}

	bool lookup_prf = parser->protocol->prf_alg_byname != NULL;
	if (!lookup_prf && IMPAIR(PROPOSAL_PARSER)) {
		/*
		 * Only force PRF lookup when the folloing token looks
		 * like an INTEG algorithm.  Otherwise something like
		 * ah=sha1 gets parsed as ah=[encr]-sha1-[integ]-[dh].
		 */
		if (tokens[0].alg.ptr != NULL && tokens[1].alg.ptr != NULL) {
			(void) lookup_byname(parser, integ_alg_byname,
					     tokens[1].alg, 0, "integrity");
			lookup_prf = parser->err_buf[0] == '\0';
			parser->err_buf[0] = '\0';
		}
	}
	if (lookup_prf && tokens->alg.ptr != NULL && tokens->sep != ';') {
		shunk_t prf = tokens[0].alg;
		proposal.prf = prf_desc(lookup_byname(parser,
						      prf_alg_byname,
						      prf, 0, "PRF"));
		if (parser->err_buf[0] != '\0') {
			return false;
		}
		tokens += 1; /* consume one arg */
	}

	bool lookup_integ = parser->protocol->integ_alg_byname != NULL;
	if (!lookup_integ && IMPAIR(PROPOSAL_PARSER)) {
		/* force things */
		lookup_integ = true;
	}
	if (lookup_integ && tokens->alg.ptr != NULL && tokens->sep != ';') {
		shunk_t integ = tokens[0].alg;
		proposal.integ = integ_desc(lookup_byname(parser,
							  integ_alg_byname,
							  integ, 0, "integrity"));
		if (parser->err_buf[0] != '\0') {
			if (tokens[1].alg.ptr != NULL) {
				/*
				 * This alg should have been
				 * integrity, since the next would be
				 * DH; error applies.
				 */
				passert(parser->err_buf[0] != '\0');
				return false;
			}
			if (tokens[1].alg.ptr == NULL &&
			    parser->protocol->prf_alg_byname == NULL) {
				/*
				 * Only one arg, integrity is prefered
				 * to DH (and no PRF); error applies.
				 */
				passert(parser->err_buf[0] != '\0');
				return false;
			}
			/* let DH try */
			parser->err_buf[0] = '\0';
		} else {
			tokens += 1; /* consume one arg */
		}
	}

	bool lookup_dh = parser->protocol->dh_alg_byname || IMPAIR(PROPOSAL_PARSER);
	if (lookup_dh && tokens->alg.ptr != NULL) {
		shunk_t dh = tokens[0].alg;
		proposal.dh = oakley_group_desc(lookup_byname(parser,
							      dh_alg_byname,
							      dh, 0, "DH"));
		if (parser->err_buf[0] != '\0') {
			return false;
		}
		tokens += 1; /* consume one arg */
	}

	if (tokens->alg.ptr != NULL) {
		snprintf(parser->err_buf, parser->err_buf_len,
			 "'"PRISHUNK"' unexpected",
			 SHUNKF(tokens[0].alg));
		return false;
	}

	if (IMPAIR(PROPOSAL_PARSER)) {
		return add_proposal(parser, alg_info, &proposal);
	} else {
		return merge_default_proposals(parser, alg_info, &proposal);
	}
}


bool alg_info_parse_str(const struct proposal_parser *parser,
			struct alg_info *alg_info,
			shunk_t alg_str)
{
	DBG(DBG_PROPOSAL_PARSER,
	    DBG_log("parsing '"PRISHUNK"' for %s",
		    SHUNKF(alg_str), parser->protocol->name));

	/* use default if no string */
	if (alg_str.ptr == NULL) {
		const struct proposal_info proposal = {
			.protocol = parser->protocol,
		};
		return merge_default_proposals(parser, alg_info, &proposal);
	}

	if (alg_str.len == 0) {
		/* XXX: hack to keep testsuite happy */
		snprintf(parser->err_buf, parser->err_buf_len,
			 "String ended with invalid char, just after \"\"");
		return false;
	}

	shunk_t prop_ptr = alg_str;
	do {
		/* find the next proposal */
		shunk_t prop = shunk_token(&prop_ptr, ",");
		/* parse it */
		struct token tokens[8];
		zero(&tokens);
		struct token *token = tokens;
		char last_sep = '\0';
		shunk_t alg_ptr = prop;
		do {
			if (token + 1 >= tokens+elemsof(tokens)) {
				/* space for NULL? */
				snprintf(parser->err_buf, parser->err_buf_len,
					 "proposal too long");
				return false;
			}
			/* find the next alg */
			shunk_t alg = shunk_token(&alg_ptr, "-;,");
			*token++ = (struct token) {
				.alg = alg,
				.sep = last_sep,
			};
			last_sep = alg.ptr[alg.len]; /* save separator */
		} while (alg_ptr.len > 0);
		struct proposal_info proposal = {
			.protocol = parser->protocol,
		};
		if (!parser_alg_info_add(parser, tokens, proposal,
					 alg_info)) {
			passert(parser->err_buf[0] != '\0');
			return false;
		}
	} while (prop_ptr.len > 0);
	return true;
}

struct proposal_parser proposal_parser(const struct proposal_policy *policy,
				       const struct proposal_protocol *protocol,
				       char *err_buf, size_t err_buf_len)
{
	const struct proposal_parser parser = {
		.policy = policy,
		.protocol = protocol,
		.err_buf = err_buf,
		.err_buf_len = err_buf_len,
	};
	err_buf[0] = '\0';
	return parser;
}

bool proposal_aead_none_ok(const struct proposal_parser *parser,
			   const struct proposal_info *proposal)
{
	if (IMPAIR(ALLOW_NULL_NULL)) {
		return true;
	}

	if (proposal->encrypt != NULL && ike_alg_is_aead(proposal->encrypt)
	    && proposal->integ != NULL && proposal->integ != &ike_alg_integ_none) {
		/*
		 * For instance, esp=aes_gcm-sha1" is invalid.
		 */
		snprintf(parser->err_buf, parser->err_buf_len,
			 "AEAD %s encryption algorithm '%s' must have 'none' as the integrity algorithm",
			 proposal->protocol->name,
			 proposal->encrypt->common.name);
		return false;
	}

	if (proposal->encrypt != NULL && !ike_alg_is_aead(proposal->encrypt)
	    && proposal->integ != NULL && proposal->integ == &ike_alg_integ_none) {
		/*
		 * For instance, esp=aes_cbc-none" is invalid.
		 */
		snprintf(parser->err_buf, parser->err_buf_len,
			 "non-AEAD %s encryption algorithm '%s' cannot have 'none' as the integrity algorithm",
			 proposal->protocol->name,
			 proposal->encrypt->common.name);
		return false;
	}

	return true;
}

/*
 * alg_info struct can be shared by several connections instances,
 * handle free() with ref_cnts.
 *
 * Use alg_info_free() if the value returned by *_parse_str() is found
 * to be (semantically) bogus.
 */

void alg_info_free(struct alg_info *alg_info)
{
	passert(alg_info);
	passert(alg_info->ref_cnt == 0);
	pfree(alg_info);
}

void alg_info_addref(struct alg_info *alg_info)
{
	alg_info->ref_cnt++;
}

void alg_info_delref(struct alg_info *alg_info)
{
	passert(alg_info->ref_cnt != 0);
	alg_info->ref_cnt--;
	if (alg_info->ref_cnt == 0)
		alg_info_free(alg_info);
}

size_t lswlog_proposal_info(struct lswlog *log,
			    const struct proposal_info *proposal)
{
 	size_t size = 0;
 	const char *sep = "";

	if (proposal->encrypt != NULL) {
		size += lswlogs(log, sep); sep = "-";
		size += lswlogs(log, proposal->encrypt->common.fqn);
		if (proposal->enckeylen != 0) {
			size += lswlogf(log, "_%zd", proposal->enckeylen);
		}
	} else if (IMPAIR(PROPOSAL_PARSER)) {
		size += lswlogs(log, sep); sep = "-";
		size += lswlogs(log, "[ENCRYPT]");
	}

	if (proposal->prf != NULL) {
		size += lswlogs(log, sep); sep = "-";
		size += lswlogs(log, proposal->prf->common.fqn);
	} else if (IMPAIR(PROPOSAL_PARSER)) {
		size += lswlogs(log, sep); sep = "-";
		size += lswlogs(log, "[PRF]");
	}

	if (proposal->integ != NULL && proposal->prf == NULL) {
		size += lswlogs(log, sep); sep = "-";
		size += lswlogs(log, proposal->integ->common.fqn);
	} else if (!(proposal->integ == &ike_alg_integ_none && ike_alg_is_aead(proposal->encrypt)) &&
		   proposal->integ != NULL && proposal->integ->prf != proposal->prf) {
		size += lswlogs(log, sep); sep = "-";
		size += lswlogs(log, proposal->integ->common.fqn);
	} else if (IMPAIR(PROPOSAL_PARSER)) {
		size += lswlogs(log, sep); sep = "-";
		if (proposal->integ != NULL) {
			size += lswlogs(log, proposal->integ->common.fqn);
		} else {
			size += lswlogs(log, "[INTEG]");
		}
	}

	if (proposal->dh != NULL) {
		size += lswlogs(log, sep); sep = "-";
		size += lswlogs(log, proposal->dh->common.fqn);
	} else if (IMPAIR(PROPOSAL_PARSER)) {
		size += lswlogs(log, sep); sep = "-";
		size += lswlogs(log, "[DH]");
	}

	return size;
}

size_t lswlog_alg_info(struct lswlog *log, const struct alg_info *alg_info)
{
	size_t size = 0;
	const char *sep = "";
	FOR_EACH_PROPOSAL_INFO(alg_info, proposal) {
		size += lswlogs(log, sep);
		size += lswlog_proposal_info(log, proposal);
		sep = ", ";
	}
	return size;
}

/*
 * For IKEv1, pluto handles at most one pre-determined ESP/AH DH
 * algorithm.  The code doesn't handle any negotiation.
 *
 * When "PFS", either no algorithm is specifed and the IKE SA's DH is
 * used, or a single DH algorithm is specified at the end of the line
 * and be separated using ";".
 *
 * When "no-PFS", this should probably log and discard the DH
 * algorithm.  Later, if ever.
 *
 * Because the parser is far more liberal, this gets enforced after
 * the event.
 */

bool ikev1_one_alg_info_dh_hack(const struct proposal_parser *parser,
				struct alg_info_esp *aie,
				const char *alg_str)
{
	if (aie->ai.alg_info_cnt <= 0) {
		/* let caller deal with no proposals. */
		return true;
	}

	/* find any DH */
	struct proposal_info *first = NULL;
	FOR_EACH_ESP_INFO(aie, alg) {
		if (alg->dh != NULL) {
			first = alg;
			break;
		}
	}
	if (first == NULL) {
		return true;
	}

	struct proposal_info *last = &aie->ai.proposals[aie->ai.alg_info_cnt-1];

	char *first_semi = alg_str != NULL ? strchr(alg_str, ';') : NULL;
	char *last_comma = alg_str != NULL ? strrchr(alg_str, ',') : NULL;

	/*
	 * Can't have ;DH,... - as ;DH must appear last.
	 *
	 * Use a character check as esp=aes-sha1;dh21,aes-sha1-dh21
	 * will be reduced to just esp=aes-sha1;dh21.
	 */
	if (first_semi != NULL && last_comma != NULL && first_semi < last_comma) {
		snprintf(parser->err_buf, parser->err_buf_len,
			 "%s DH algorithm '%s' must be specified last",
			 parser->protocol->name,
			 first->dh->common.fqn);
		return false;
	}

	/*
	 * Can't have -DH,..;DH - as ;DH must be the only proposal.
	 *
	 * Because duplicates like esp=aes-sha1-dh21,aes-sha1;dh21 get
	 * reduced to just esp=aes-sha1;dh21, this isn't 100%
	 * reliable.
	 */
	if (first_semi != NULL && first != last) {
		snprintf(parser->err_buf, parser->err_buf_len,
			 "%s DH algorithm must appear once after last proposal",
			 first->protocol->name);
		return false;
	}

	/*
	 * All the DH entries must match last (since first!=NULL there
	 * is at least one before last).
	 */
	if (first != last && last->dh == NULL) {
		/* esp=aes-sha1-dh21,aes-sha1 */
		snprintf(parser->err_buf, parser->err_buf_len,
			 "%s DH algorithm '%s' must be specified last",
			 parser->protocol->name,
			 first->dh->common.fqn);
		if (!impair_proposal_errors(parser)) {
			return false;
		}
	}
	if (first != last && last->dh != NULL) {
		/* esp=aes-sha1-dh21,aes-sha1-dh22 */
		FOR_EACH_ESP_INFO(aie, alg) {
			if (alg->dh != last->dh) {
				if (alg->dh == NULL) {
					snprintf(parser->err_buf, parser->err_buf_len,
						 "%s DH algorithm must appear once after last proposal",
						 first->protocol->name);
				} else {
					snprintf(parser->err_buf, parser->err_buf_len,
						 "%s DH algorithm '%s' must be specified last",
						 parser->protocol->name,
						 first->dh->common.fqn);
				}
				if (!impair_proposal_errors(parser)) {
					return false;
				} else {
					break; /* report first */
				}
			}
		}
	}

	/*
	 * Now go through and force all DHs to a consistent value.
	 *
	 * This way, something printing an individual proposal will
	 * include the common DH; and for IKEv2 it can just pick up
	 * that DH.
	 */
	if (!IMPAIR(PROPOSAL_PARSER)) {
		FOR_EACH_ESP_INFO(aie, esp_info) {
			esp_info->dh = last->dh;
		}
	}

	return true;
}

/*
 * For IKEv2, because pluto's CHILD SA code doesn't implement INVALID
 * KE, at most one DH algorithm can be specified.  However, unlike
 * IKEv1, DH+NONE is permitted and the requirement that it appear last
 * is not enforced.
 *
 * PFS makes things messy: a line like esp=aes,aes;dh22 can be
 * interpreted as esp=aes;PFS,aes;dh22 (invalid) or
 * esp=ah;none-ah;dh22 (ok).
 */

bool ikev2_one_alg_info_dh_hack(const struct proposal_parser *parser,
				struct alg_info_esp *aie)
{
	if (aie->ai.alg_info_cnt <= 0) {
		/* let caller deal with no proposals. */
		return true;
	}

	const struct oakley_group_desc *dh = &unset_group; /* dummy */
	const bool pfs = parser->policy->pfs;
	FOR_EACH_ESP_INFO(aie, alg) {
		/*
		 * Always allow 'none'; and when no PFS DH=NULL gets
		 * interpreted as 'none'.
		 */
		if (alg->dh == &ike_alg_dh_none ||
		    (!pfs && alg->dh == NULL)) {
			continue;
		}
		/*
		 * Save the first real DH (when PFS, this includes
		 * NULL), and from then on check it is consistent.
		 */
		if (dh == &unset_group) {
			dh = alg->dh;
		} else if (alg->dh != dh) {
			if (alg->dh != NULL && dh != NULL) {
				snprintf(parser->err_buf, parser->err_buf_len,
					 "multiple conflicting DH algorithms (%s, %s) are not supported",
					 dh->common.fqn, alg->dh->common.fqn);
			} else {
				pexpect(pfs);
				snprintf(parser->err_buf, parser->err_buf_len,
					 "combining PFS (use IKE SA's DH algorithm) with an explicit DH algorithm (%s) is not supported",
					 dh != NULL ? dh->common.fqn :
					 alg->dh != NULL ? alg->dh->common.fqn : "???");
			}
			return false;
		}
	}
	return true;
}

bool impair_proposal_errors(const struct proposal_parser *parser)
{
	pexpect(parser->err_buf[0] != '\0');
	if (IMPAIR(PROPOSAL_PARSER)) {
		libreswan_log("IMPAIR: ignoring proposal error: %s",
			      parser->err_buf);
		parser->err_buf[0] = '\0';
		return true;
	} else {
		return false;
	}
}
