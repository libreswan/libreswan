/*
 * Algorithm info parsing and creation functions
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 *
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2015-2020 Andrew Cagney <cagney@gnu.org>
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

struct proposal {
	/*
	 * The algorithm entries.
	 */
	struct algorithm *algorithms[PROPOSAL_TRANSFORM_ROOF];
	/*
	 * Which protocol is this proposal intended for?
	 */
	const struct proposal_protocol *protocol;
	struct proposal *next;
};

struct proposals {
	bool defaulted;
	struct proposal *proposals;
};

struct proposal_parser *alloc_proposal_parser(const struct proposal_policy *policy,
					      const struct proposal_protocol *protocol)
{
	struct proposal_parser *parser = alloc_thing(struct proposal_parser, "parser");
	parser->policy = policy;
	parser->protocol = protocol;
	parser->diag = NULL;
	return parser;
}

void free_proposal_parser(struct proposal_parser **parser)
{
	pfree_diag(&(*parser)->diag);
	pfree(*parser);
	*parser = NULL;
}

bool proposal_encrypt_aead(const struct proposal *proposal)
{
	if (proposal->algorithms[PROPOSAL_TRANSFORM_encrypt] == NULL) {
		return false;
	}
	FOR_EACH_ALGORITHM(proposal, encrypt, alg) {
		const struct encrypt_desc *encrypt = encrypt_desc(alg->desc);
		if (!encrypt_desc_is_aead(encrypt)) {
			return false;
		}
	}
	return true;
}

bool proposal_encrypt_norm(const struct proposal *proposal)
{
	if (proposal->algorithms[PROPOSAL_TRANSFORM_encrypt] == NULL) {
		return false;
	}
	FOR_EACH_ALGORITHM(proposal, encrypt, alg) {
		const struct encrypt_desc *encrypt = encrypt_desc(alg->desc);
		if (encrypt_desc_is_aead(encrypt)) {
			return false;
		}
	}
	return true;
}

bool proposal_integ_none(const struct proposal *proposal)
{
	/* interpret NULL as NONE */
	FOR_EACH_ALGORITHM(proposal, integ, alg) {
		const struct integ_desc *integ = integ_desc(alg->desc);
		if (integ != &ike_alg_integ_none) {
			return false;
		}
	}
	return true;
}

bool proposal_aead_none_ok(struct proposal_parser *parser,
			   const struct proposal *proposal)
{
	if (impair.allow_null_none) {
		return true;
	}

	if (proposal->algorithms[PROPOSAL_TRANSFORM_encrypt] == NULL) {
		return true;
	}

	/* are any and all encrypt algorithms AEAD? */
	bool aead = proposal_encrypt_aead(proposal);
	bool norm = proposal_encrypt_norm(proposal);

	if (!aead && !norm) {
		proposal_error(parser, "AEAD and non-AEAD %s encryption algorithm cannot be combined",
			       proposal->protocol->name);
		return false;
	}

	/* are any and all integ algorithms NONE? */
	bool none = proposal_integ_none(proposal);

	if (aead && !none) {
		const struct ike_alg *encrypt = proposal->algorithms[PROPOSAL_TRANSFORM_encrypt]->desc;
		/*
		 * At least one of the integrity algorithms wasn't
		 * NONE.  For instance, esp=aes_gcm-sha1" is invalid.
		 */
		proposal_error(parser, "AEAD %s encryption algorithm %s must have 'NONE' as the integrity algorithm",
			       proposal->protocol->name,
			       encrypt->fqn);
		return false;
	}

	if (norm && none) {
		const struct ike_alg *encrypt = proposal->algorithms[PROPOSAL_TRANSFORM_encrypt]->desc;
		/*
		 * Not AEAD and either there was no integrity
		 * algorithm (implying NONE) or at least one integrity
		 * algorithm was NONE.  For instance,
		 * esp=aes_cbc-none" is invalid.
		 */
		proposal_error(parser, "non-AEAD %s encryption algorithm %s cannot have 'NONE' as the integrity algorithm",
			       proposal->protocol->name,
			       encrypt->fqn);
		return false;
	}

	return true;
}

/*
 * Proposals struct can be shared by a connection template and its
 * instances.  Fortunately, the connection template is only deleted
 * after all instances.
 */

void free_proposals(struct proposals **proposals)
{
	if ((*proposals) != NULL) {
		free_proposal(&(*proposals)->proposals);
		pfree((*proposals));
		*proposals = NULL;
	}
}
struct proposal *next_proposal(const struct proposals *proposals,
			       struct proposal *last)
{
	if (last == NULL) {
		return proposals->proposals;
	} else {
		return last->next;
	}
}

unsigned nr_proposals(const struct proposals *proposals)
{
	unsigned nr = 0;
	FOR_EACH_PROPOSAL(proposals, proposal) {
		nr++;
	}
	return nr;
}

void append_proposal(struct proposals *proposals, struct proposal **proposal)
{
	struct proposal **end = &proposals->proposals;
	/* check for duplicates */
	while ((*end) != NULL) {
		bool same = true;
		for (enum proposal_transform pa = PROPOSAL_TRANSFORM_FLOOR;
		     same && pa < PROPOSAL_TRANSFORM_ROOF; pa++) {
			struct algorithm *old = (*end)->algorithms[pa];
			struct algorithm *new = (*proposal)->algorithms[pa];
			while (same) {
				if (new == NULL && old == NULL) {
					break;
				}
				if (new == NULL || old == NULL) {
					same = false;
					break;
				}
				if (new->desc != old->desc) {
					same = false;
					break;
				}
				/*
				 * If list already contains encryption
				 * with ENCKEYLEN=0 then new is a
				 * duplicate as 0 generates all keys.
				 * Ignore reverse vis aes128,aes.
				 */
				if (old->desc->type == &ike_alg_encrypt &&
				    (old->enckeylen != 0 &&
				     new->enckeylen != old->enckeylen)) {
					same = false;
					break;
				}
				new = new->next;
				old = old->next;
			}
		}
		if (same) {
			ldbg(&global_logger, "discarding duplicate proposal");
			free_proposal(proposal);
			return;
		}
		end = &(*end)->next;
	}
	*end = *proposal;
	*proposal = NULL;
}

struct v1_proposal v1_proposal(const struct proposal *proposal)
{
	struct v1_proposal v1 = {
		.protocol = proposal->protocol,
#define D(ALG) .ALG = proposal->algorithms[PROPOSAL_TRANSFORM_##ALG] != NULL ? ALG##_desc(proposal->algorithms[PROPOSAL_TRANSFORM_##ALG]->desc) : NULL
		D(encrypt),
		D(prf),
		D(integ),
		D(kem),
#undef D
	};
	v1.enckeylen = proposal->algorithms[PROPOSAL_TRANSFORM_encrypt] != NULL ? proposal->algorithms[PROPOSAL_TRANSFORM_encrypt]->enckeylen : 0;

	return v1;
}

struct algorithm *next_algorithm(const struct proposal *proposal,
				 enum proposal_transform algorithm,
				 struct algorithm *last)
{
	if (last == NULL) {
		/*
		 * Hack, there should there a way to index algorithm
		 * types; however the old enum proved very dangerous.
		 */
		passert(algorithm < elemsof(proposal->algorithms));
		return proposal->algorithms[algorithm];
	} else {
		return last->next;
	}
}

void free_algorithms(struct proposal *proposal,
		     enum proposal_transform algorithm)
{
	passert(algorithm < elemsof(proposal->algorithms));
	struct algorithm *alg = proposal->algorithms[algorithm];
	while (alg != NULL) {
		struct algorithm *del = alg;
		alg = alg->next;
		pfree(del);
	}
	proposal->algorithms[algorithm] = NULL;
}

struct proposal *alloc_proposal(const struct proposal_parser *parser)
{
	struct proposal *proposal = alloc_thing(struct proposal, "proposal");
	proposal->protocol = parser->protocol;
	return proposal;
}

void free_proposal(struct proposal **proposals)
{
	struct proposal *proposal = *proposals;
	while (proposal != NULL) {
		struct proposal *del = proposal;
		proposal = proposal->next;
		for (enum proposal_transform algorithm = PROPOSAL_TRANSFORM_FLOOR;
		     algorithm < PROPOSAL_TRANSFORM_ROOF; algorithm++) {
			free_algorithms(del, algorithm);
		}
		pfree(del);
	}
	*proposals = NULL;
}


/*
 * XXX: hack, need to come up with a type safe way of mapping an
 * ike_alg onto an index.
 */
static enum proposal_transform ike_to_proposal_algorithm(const struct ike_alg *alg)
{
	if (alg->type == &ike_alg_encrypt) {
		return PROPOSAL_TRANSFORM_encrypt;
	} else if (alg->type == &ike_alg_prf) {
		return PROPOSAL_TRANSFORM_prf;
	} else if (alg->type == &ike_alg_integ) {
		return PROPOSAL_TRANSFORM_integ;
	} else if (alg->type == &ike_alg_kem) {
		return PROPOSAL_TRANSFORM_kem;
	} else {
		llog_passert(&global_logger, HERE,
			     "unexpected algorithm type %s",
			     alg->type->name);
	}
}

void append_algorithm_for(struct proposal_parser *parser,
			  struct proposal *proposal,
			  enum proposal_transform proposal_algorithm,
			  const struct ike_alg *alg,
			  int enckeylen)
{
	const struct logger *logger = parser->policy->logger;
	if (alg == NULL) {
		ldbgf(DBG_PROPOSAL_PARSER, logger, "no algorithm to append");
		return;
	}
	passert(proposal_algorithm < elemsof(proposal->algorithms));
	/* find end */
	struct algorithm **end = &proposal->algorithms[proposal_algorithm];
	while ((*end) != NULL) {
		end = &(*end)->next;
	}
	/* append */
	struct algorithm new_algorithm = {
		.desc = alg,
		.enckeylen = enckeylen,
	};
	ldbgf(DBG_PROPOSAL_PARSER, logger, "appending %s %s %s[_%d]",
	      parser->protocol->name,
	      alg->type->story,
	      alg->fqn,
	      enckeylen);
	*end = clone_thing(new_algorithm, "alg");
}

void append_algorithm(struct proposal_parser *parser,
		      struct proposal *proposal,
		      const struct ike_alg *alg,
		      int enckeylen)
{
	append_algorithm_for(parser, proposal,
			     ike_to_proposal_algorithm(alg),
			     alg,
			     enckeylen);
}

void remove_duplicate_algorithms(struct proposal_parser *parser,
				 struct proposal *proposal,
				 enum proposal_transform algorithm)
{
	passert(algorithm < elemsof(proposal->algorithms));
	/* XXX: not efficient */
	for (struct algorithm *alg = proposal->algorithms[algorithm];
	     alg != NULL; alg = alg->next) {
		struct algorithm **dup = &alg->next;
		while ((*dup) != NULL) {
			/*
			 * Since enckeylen=0 is a wildcard there's no
			 * point following it enckeylen=128 say; OTOH
			 * enckeylen=128 then enckeylen=0 is ok as
			 * latter picks up 192 and 256.
			 */
			if (alg->desc == (*dup)->desc &&
			    (alg->desc->type != &ike_alg_encrypt ||
			     alg->enckeylen == 0 ||
			     alg->enckeylen == (*dup)->enckeylen)) {
				struct algorithm *dead = (*dup);
				LLOG_JAMBUF(parser->policy->stream, parser->policy->logger, buf) {
					jam(buf, "discarding duplicate %s %s %s",
					    parser->protocol->name,
					    dead->desc->type->story,
					    dead->desc->fqn);
					if (dead->enckeylen != 0) {
						jam(buf, "_%d", dead->enckeylen);
					}
				}
				(*dup) = (*dup)->next; /* remove */
				pfree(dead);
			} else {
				dup = &(*dup)->next; /* advance */
			}
		}
	}
}

static const char *jam_proposal_algorithm(struct jambuf *buf,
					  const struct proposal *proposal,
					  enum proposal_transform proposal_algorithm,
					  const char *algorithm_separator)
{
	const char *separator = algorithm_separator;
	for (struct algorithm *algorithm = next_algorithm(proposal, proposal_algorithm, NULL);
	     algorithm != NULL; algorithm = next_algorithm(proposal, proposal_algorithm, algorithm)) {
		jam_string(buf, separator); separator = "+"; algorithm_separator = "-";
		jam_string(buf, algorithm->desc->fqn);
		if (algorithm->enckeylen != 0) {
			jam(buf, "_%d", algorithm->enckeylen);
		}
	}
	return algorithm_separator;
}

void jam_proposal(struct jambuf *buf,
		  const struct proposal *proposal)
{
	const char *algorithm_separator = "";
	for (enum proposal_transform proposal_algorithm = PROPOSAL_TRANSFORM_FLOOR;
	     proposal_algorithm < PROPOSAL_TRANSFORM_ROOF; proposal_algorithm++) {

		/*
		 * Should integrity be skipped?
		 */

		if (proposal_algorithm == PROPOSAL_TRANSFORM_integ) {

			/*
			 * Don't include -NONE- as it gives the
			 * appearance of no integrity.
			 *
			 * But for output compat reasons, do include
			 * NONE when there's no PRF.
			 */
			if (proposal_encrypt_aead(proposal) &&
			    proposal_integ_none(proposal) &&
			    next_algorithm(proposal, PROPOSAL_TRANSFORM_prf, NULL) != NULL) {
				continue;
			}

			/*
			 * Walk INTEG and PRF to see if they are
			 * consistent; when they are skip integ.
			 */
			struct algorithm *integ = NULL;
			struct algorithm *prf = NULL;
			bool integ_matches_prf = true;
			while (true) {
				prf = next_algorithm(proposal, PROPOSAL_TRANSFORM_prf, prf);
				integ = next_algorithm(proposal, PROPOSAL_TRANSFORM_integ, integ);
				if (prf == NULL && integ == NULL) {
					break;
				}
				if (prf == NULL || integ == NULL) {
					/* i.e., only one is present */
					integ_matches_prf = false;
					break;
				}
				if (&integ_desc(integ->desc)->prf->common != prf->desc) {
					/* i.e., prf and integ are different */
					integ_matches_prf = false;
					break;
				}
			}
			if (integ_matches_prf) {
				continue;
			}
		}

		algorithm_separator = jam_proposal_algorithm(buf, proposal, proposal_algorithm, algorithm_separator);
	}
}

void jam_proposals(struct jambuf *buf, const struct proposals *proposals)
{
	const char *sep = "";
	FOR_EACH_PROPOSAL(proposals, proposal) {
		jam_string(buf, sep);
		jam_proposal(buf, proposal);
		sep = ", ";
	}
}

/*
 * When PFS=no ignore any DH algorithms, and when PFS=yes reject
 * mixing implicit and explicit DH.
 */
static bool proposals_pfs_vs_ke_check(struct proposal_parser *parser,
				      struct proposals *proposals)
{
	/*
	 * Scrape the proposals searching for a Key Exchange
	 * algorithms of interest.
	 */

	const struct proposal *first_null_ke = NULL;
	const struct proposal *first_none_ke = NULL;
	const struct ike_alg *first_ke = NULL;
	const struct ike_alg *second_ke = NULL;
	FOR_EACH_PROPOSAL(proposals, proposal) {
		if (proposal->algorithms[PROPOSAL_TRANSFORM_kem] == NULL) {
			if (first_null_ke == NULL) {
				first_null_ke = proposal;
			}
		} else if (proposal->algorithms[PROPOSAL_TRANSFORM_kem]->desc == &ike_alg_kem_none.common) {
			if (first_none_ke == NULL) {
				first_none_ke = proposal;
			}
		} else if (first_ke == NULL) {
			first_ke = proposal->algorithms[PROPOSAL_TRANSFORM_kem]->desc;
		} else if (second_ke == NULL &&
			   first_ke != proposal->algorithms[PROPOSAL_TRANSFORM_kem]->desc) {
			second_ke = proposal->algorithms[PROPOSAL_TRANSFORM_kem]->desc;
		}
	}

	if (first_ke == NULL && first_none_ke == NULL) {
		/* no DH is always ok */
		return true;
	}

	/*
	 * Try to generate very specific errors first.  For instance,
	 * given PFS=no esp=aes,aes;dh21, an error stating that dh21
	 * is not valid because of PFS is more helpful than an error
	 * saying that all or no proposals need PFS.
	 */

	/*
	 * Since PFS=NO overrides any DH, don't silently ignore it.
	 * Check this early so that a conflict with PFS=no code gets
	 * reported before anything else.
	 */
	if (!parser->policy->pfs && (first_ke != NULL || first_none_ke != NULL)) {
		FOR_EACH_PROPOSAL(proposals, proposal) {
			const struct ike_alg *ke = NULL;
			if (proposal->algorithms[PROPOSAL_TRANSFORM_kem] != NULL) {
				ke = proposal->algorithms[PROPOSAL_TRANSFORM_kem]->desc;
			}
			if (ke == &ike_alg_kem_none.common) {
				llog(parser->policy->stream, parser->policy->logger,
				     "ignoring redundant %s Key Exchange algorithm 'NONE' as PFS policy is disabled",
				     parser->protocol->name);
			} else if (ke != NULL) {
				llog(parser->policy->stream, parser->policy->logger,
				     "ignoring %s Key Exchange algorithm '%s' as PFS policy is disabled",
				     parser->protocol->name, ke->fqn);
			}
			free_algorithms(proposal, PROPOSAL_TRANSFORM_kem);
		}
		return true;
	}

	/*
	 * Since at least one proposal included KE, all proposals
	 * should.  Having a proposal with no KE (i.e., NULL pointer)
	 * is an error.
	 *
	 * (The converse, no proposals including KE was handled right
	 * at the start).
	 */
	if (first_null_ke != NULL) {
		/* KE was specified */
		proposal_error(parser, "either all or no %s proposals should specify Key Exchange",
			       parser->protocol->name);
		return false;
	}

	switch (parser->policy->version) {

	case IKEv1:
		/*
		 * IKEv1 only allows one KE algorithm.
		 */
		if (first_ke != NULL && second_ke != NULL) {
			proposal_error(parser, "more than one IKEv1 %s Key Exchange algorithm (%s, %s) is not allowed in quick mode",
				       parser->protocol->name,
				       first_ke->fqn,
				       second_ke->fqn);
			return false;
		}
		break;

	case IKEv2:
		/*
		 * IKEv2, only implements one KE algorithm for Child SAs.
		 */
		if (first_ke != NULL && second_ke != NULL) {
			proposal_error(parser, "more than one IKEv2 %s Key Exchange algorithm (%s, %s) requires unimplemented CREATE_CHILD_SA INVALID_KE",
				       parser->protocol->name,
				       first_ke->fqn,
				       second_ke->fqn);
			return false;
		}
		break;

	default:
		/* ignore */
		break;
	}

	return true;
}

void proposal_error(struct proposal_parser *parser, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	passert(parser->diag == NULL);
	parser->diag = diag_va_list(fmt, ap);
	va_end(ap);
}

struct proposals *proposals_from_str(struct proposal_parser *parser,
				     const char *str)
{
	struct proposals *proposals = alloc_thing(struct proposals, "proposals");
	if (str == NULL) {
		proposals->defaulted = true;
		/* may still be null */
		enum fips_mode fips_mode = get_fips_mode(parser->policy->logger);
		str = parser->protocol->defaults->proposals[fips_mode];
		PASSERT(parser->policy->logger, str != NULL);
	}
	bool ok = false;
	switch (parser->policy->version) {
	case IKEv1: ok = v1_proposals_parse_str(parser, proposals, shunk1(str)); break;
	case IKEv2: ok = v2_proposals_parse_str(parser, proposals, shunk1(str)); break;
	default:
		bad_case(parser->policy->version);
	}
	if (!ok) {
		free_proposals(&proposals);
		return NULL;
	}
	if (proposals->proposals == NULL) {
		free_proposals(&proposals);
		return NULL;
	}
	if (parser->policy->check_pfs_vs_ke &&
	    !proposals_pfs_vs_ke_check(parser, proposals)) {
		passert(parser->diag != NULL);
		free_proposals(&proposals);
		return NULL;
	}
	return proposals;
}

bool default_proposals(const struct proposals *proposals)
{
	return proposals == NULL || proposals->defaulted;
}

/*
 * Try to parse any of <ealg>-<ekeylen>, <ealg>_<ekeylen>,
 * <ealg><ekeylen>, or <ealg> using some look-ahead.
 */

static int parse_proposal_eklen(struct proposal_parser *parser, shunk_t print, shunk_t buf)
{
	passert(parser->diag == NULL);
	/* convert -<eklen> if present */
	char *end = NULL;
	long eklen = strtol(buf.ptr, &end, 10);
	if (buf.ptr + buf.len != end) {
		proposal_error(parser, "%s encryption algorithm '"PRI_SHUNK"' key length contains a non-numeric character",
			       parser->protocol->name,
			       pri_shunk(print));
		return 0;
	}
	if (eklen >= INT_MAX) {
		proposal_error(parser, "%s encryption algorithm '"PRI_SHUNK"' key length WAY too big",
			       parser->protocol->name,
			       pri_shunk(print));
		return 0;
	}
	if (eklen == 0) {
		proposal_error(parser, "%s encryption key length is zero",
			       parser->protocol->name);
		return 0;
	}
	return eklen;
}

bool proposal_parse_encrypt(struct proposal_parser *parser,
			    struct proposal_tokenizer *tokens,
			    const struct ike_alg **encrypt,
			    int *encrypt_keylen)
{
	const struct logger *logger = parser->policy->logger;
	if (tokens->this.len == 0) {
		proposal_error(parser, "%s encryption algorithm is empty",
			       parser->protocol->name);
		return false;
	}

	/*
	 * Does it match <ealg>-<eklen>?
	 *
	 * Use the tokens NEXT lookahead to check <eklen> first.  If
	 * it starts with a digit then just assume <ealg>-<ealg> and
	 * error out if it is not so.
	 */
	if (tokens->this_term == '-' &&
	    tokens->next.len > 0 &&
	    char_isdigit(hunk_char(tokens->next, 0))) {
		/* assume <ealg>-<eklen> */
		shunk_t ealg = tokens->this;
		shunk_t eklen = tokens->next;
		/* print "<ealg>-<eklen>" in errors */
		shunk_t print = shunk2(ealg.ptr, eklen.ptr + eklen.len - ealg.ptr);
		int enckeylen = parse_proposal_eklen(parser, print, eklen);
		if (enckeylen <= 0) {
			passert(parser->diag != NULL);
			return false;
		}
		const struct ike_alg *alg = encrypt_alg_byname(parser, ealg,
							       enckeylen, print);
		if (alg == NULL) {
			ldbgf(DBG_PROPOSAL_PARSER, logger,
			      "<ealg>byname('"PRI_SHUNK"') with <eklen>='"PRI_SHUNK"' failed: %s",
			      pri_shunk(ealg), pri_shunk(eklen), str_diag(parser->diag));
			return false;
		}
		/* consume <ealg>-<eklen> */
		proposal_next_token(tokens);
		proposal_next_token(tokens);
		// append_algorithm(parser, proposal, alg, enckeylen);
		*encrypt = alg; *encrypt_keylen = enckeylen;
		return true;
	}

	/*
	 * Does it match <ealg> (without any _<eklen> suffix?)
	 */
	const shunk_t print = tokens->this;
	shunk_t ealg = tokens->this;
	const struct ike_alg *alg = encrypt_alg_byname(parser, ealg,
						       0/*enckeylen*/, print);
	if (alg != NULL) {
		/* consume <ealg> */
		proposal_next_token(tokens);
		// append_algorithm(parser, proposal, alg, 0/*enckeylen*/);
		*encrypt = alg; *encrypt_keylen = 0;
		return true;
	}

	/* buffer still contains error from <ealg> lookup */
	passert(parser->diag != NULL);

	/*
	 * See if there's a trailing <eklen> in <ealg>.  If there
	 * isn't then the lookup error above can be returned.
	 */
	size_t end = ealg.len;
	while (end > 0 && char_isdigit(hunk_char(ealg, end-1))) {
		end--;
	}
	if (end == ealg.len) {
		/*
		 * no trailing <eklen> digits and <ealg> was rejected
		 * by above); error still contains message from not
		 * finding just <ealg>.
		 */
		passert(parser->diag != NULL);
		return false; // warning_or_false(parser, "encryption", print);
	}

	/* buffer still contains error from <ealg> lookup */
	passert(parser->diag != NULL);
	pfree_diag(&parser->diag);

	/*
	 * Try parsing the <eklen> found in <ealg>.  For something
	 * like aes_gcm_16, above lookup should have found the
	 * algorithm so isn't a problem here.
	 */
	shunk_t eklen = hunk_slice(ealg, end, ealg.len);
	int enckeylen = parse_proposal_eklen(parser, print, eklen);
	if (enckeylen <= 0) {
		passert(parser->diag != NULL);
		return false;
	}

	/*
	 * The <eklen> in <ealg><eklen> or <ealg>_<eklen> parsed; trim
	 * <eklen> from <ealg> and then try the lookup.
	 */
	ealg = hunk_slice(ealg, 0, end);
	if (hunk_char(ealg, ealg.len-1) == '_') {
		ealg = hunk_slice(ealg, 0, end-1);
	}
	pfree_diag(&parser->diag); /* zap old error */
	alg = encrypt_alg_byname(parser, ealg, enckeylen, print);
	if (alg == NULL) {
		passert(parser->diag != NULL);
		return false; // warning_or_false(parser, "encryption", print);
	}

	/* consume <ealg> */
	proposal_next_token(tokens);
	// append_algorithm(parser, proposal, alg, enckeylen);
	*encrypt = alg; *encrypt_keylen = enckeylen;
	return true;
}

struct proposal_tokenizer proposal_first_token(shunk_t input, const char *delims)
{
	struct proposal_tokenizer token = {
		.input = input,
		.delims = delims,
	};
	/* parse next */
	proposal_next_token(&token);
	/* next<-this; parse next */
	proposal_next_token(&token);
	return token;
}

void proposal_next_token(struct proposal_tokenizer *tokens)
{
	struct logger *logger = &global_logger;

	/* shuffle terminators */
	tokens->prev_term = tokens->this_term;
	tokens->this_term = tokens->next_term;
	/* shuffle tokens */
	tokens->this = tokens->next;
	tokens->next = shunk_token(&tokens->input, &tokens->next_term, tokens->delims);
	if (LDBGP(DBG_PROPOSAL_PARSER, logger)) {
		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
			jam(buf, "token: ");
			if (tokens->prev_term != '\0') {
				jam(buf, "'%c'", tokens->prev_term);
			} else {
				jam(buf, "''");
			}
			jam(buf, " ");
			if (tokens->this.ptr == NULL) {
				jam(buf, "<null>");
			} else {
				jam(buf, "\""PRI_SHUNK"\"", pri_shunk(tokens->this));
			}
			jam(buf, " ");
			if (tokens->this_term != '\0') {
				jam(buf, "'%c'", tokens->this_term);
			} else {
				jam(buf, "''");
			}
			jam(buf, " ");
			if (tokens->next.ptr == NULL) {
				jam(buf, "<null>");
			} else {
				jam(buf, "\""PRI_SHUNK"\"", pri_shunk(tokens->next));
			}
			jam(buf, " ");
			if (tokens->next_term != '\0') {
				jam(buf, "'%c'", tokens->next_term);
			} else {
				jam(buf, "''");
			}
		}
	}
}
