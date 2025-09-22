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

static bool ignore_transform_lookup_error(struct proposal_parser *parser,
					  const struct transform_type *transform_type,
					  shunk_t token);

struct proposal {
	bool impaired;
	/*
	 * The algorithm entries.
	 */
	struct transform_algorithms *algorithms[PROPOSAL_TRANSFORM_ROOF];
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
	if (first_proposal_transform(proposal, transform_type_encrypt) == NULL) {
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
	if (first_proposal_transform(proposal, transform_type_encrypt) == NULL) {
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

	if (first_proposal_transform(proposal, transform_type_encrypt) == NULL) {
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
		const struct ike_alg *encrypt =
			first_proposal_transform(proposal, transform_type_encrypt)->desc;
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
		const struct ike_alg *encrypt =
			first_proposal_transform(proposal, transform_type_encrypt)->desc;
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

bool proposal_transform_ok(struct proposal_parser *parser,
			   const struct proposal *proposal,
			   const struct transform_type *transform_type,
			   bool expected)
{
	const struct logger *logger = parser->policy->logger;

	if (first_proposal_transform(proposal, transform_type) != NULL) {
		if (expected) {
			return true;
		}

		if (proposal->impaired) {
			llog(IMPAIR_STREAM, logger, "%s proposal has unexpected %s transform",
			     proposal->protocol->name,
			     transform_type->name);
			return true;
		}

		llog_pexpect(logger, HERE, "%s proposal has unexpected %s transform",
			     proposal->protocol->name,
			     transform_type->name);
		return false;
	}

	if (!expected) {
		return true;
	}

	if (proposal->impaired) {
		llog(IMPAIR_STREAM, logger, "%s proposal missing %s transform",
		     proposal->protocol->name,
		     transform_type->name);
		return true;
	}

	proposal_error(parser, "%s proposal missing %s transform",
		       proposal->protocol->name,
		       transform_type->name);
	return false;
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
		for (const struct transform_type *type = transform_type_floor;
		     same && type < transform_type_roof; type++) {
			struct transform_algorithms *old_algs = (*end)->algorithms[type->index];
			struct transform_algorithms *new_algs = (*proposal)->algorithms[type->index];
			if ((old_algs == NULL || old_algs->len == 0) &&
			    (new_algs == NULL || new_algs->len == 0)) {
				continue;
			}
			if (old_algs == NULL || new_algs == NULL) {
				same = false;
				break;
			}
			if (old_algs->len != new_algs->len) {
				same = false;
				break;
			}
			for (unsigned n = 0; n < old_algs->len; n++) {
				struct transform_algorithm *old = &old_algs->item[n];
				struct transform_algorithm *new = &new_algs->item[n];
				if (old->desc != new->desc) {
					same = false;
					break;
				}
				/*
				 * Check ENCKEYLEN match.
				 *
				 * Since OLD with ENCKEYLEN=0 means
				 * all key lengths, any NEW ENCKEYLEN
				 * will match. For instance,
				 * aes,aes128.
				 *
				 * Hence only check when OLD
				 * ENCKEYLEN!=0.  For instance,
				 * aes128,aes256.
				 *
				 * XXX: don't try to handle aes,aes128
				 * as it is too late.
				 */
				if (old->desc->type == &ike_alg_encrypt &&
				    (old->enckeylen != 0 &&
				     new->enckeylen != old->enckeylen)) {
					same = false;
					break;
				}
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
#define D(ALG) .ALG = (first_proposal_transform(proposal, transform_type_##ALG) == NULL ? NULL : \
		       ALG##_desc(first_proposal_transform(proposal, transform_type_##ALG)->desc))
		D(encrypt),
		D(prf),
		D(integ),
		D(kem),
#undef D
		.enckeylen = (first_proposal_transform(proposal, transform_type_encrypt) == NULL ? 0 :
			      first_proposal_transform(proposal, transform_type_encrypt)->enckeylen),

	};
	return v1;
}

struct transform_algorithms *transform_algorithms(const struct proposal *proposal,
						  const struct transform_type *type)
{
	return proposal->algorithms[type->index];
}

struct transform_algorithm *first_proposal_transform(const struct proposal *proposal,
						      const struct transform_type *type)
{
	struct transform_algorithms *algorithms = proposal->algorithms[type->index];
	if (algorithms == NULL) {
		return NULL;
	}
	if (algorithms->len == 0) {
		return NULL;
	}
	return &algorithms->item[0];
}

static void pfree_transforms(struct proposal *proposal,
			     const struct transform_type *type)
{
	passert(type->index < elemsof(proposal->algorithms));
	pfreeany(proposal->algorithms[type->index]);
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
		for (const struct transform_type *type = transform_type_floor;
		     type < transform_type_roof; type++) {
			pfree_transforms(del, type);
		}
		pfree(del);
	}
	*proposals = NULL;
}

const struct transform_type transform_types[PROPOSAL_TRANSFORM_ROOF + 1] = {
#define S(E) [PROPOSAL_TRANSFORM_##E] = {		\
		.index = PROPOSAL_TRANSFORM_##E,	\
		.name = #E,				\
		.alg = &ike_alg_##E,			\
	}
	S(encrypt),
	S(prf),
	S(integ),
	S(kem),
	S(sn),
#undef S
#define S(E) [PROPOSAL_TRANSFORM_##E] = {		\
		.index = PROPOSAL_TRANSFORM_##E,	\
		.name = #E,				\
		.alg = &ike_alg_kem, }
	S(addke1),
	S(addke2),
	S(addke3),
	S(addke4),
	S(addke5),
	S(addke6),
	S(addke7),
#undef S
};

static const struct transform_type *transform_type_by_name(shunk_t name)
{
	for (const struct transform_type *type = transform_type_floor;
	     type < transform_type_roof; type++) {
		if (hunk_strcaseeq(name, type->name)) {
			return type;
		}
	}
	return NULL;
}

void append_proposal_transform(struct proposal_parser *parser,
			       struct proposal *proposal,
			       const struct transform_type *transform_type,
			       const struct ike_alg *transform,
			       int enckeylen)
{
	const struct logger *logger = parser->policy->logger;
	if (transform == NULL) {
		llog_pexpect(logger, HERE,
			     "no %s %s algorithm to append",
			     parser->protocol->name,
			     transform_type->name);
		return;
	}

	PASSERT(logger, transform_type->alg == transform->type);

	/* grow */
	PASSERT(logger, transform_type->index < elemsof(proposal->algorithms));
	struct transform_algorithm *end = grow_items(proposal->algorithms[transform_type->index]);

	*end = (struct transform_algorithm) {
		.type = transform_type,
		.desc = transform,
		.enckeylen = enckeylen,
	};

	ldbgf(DBG_PROPOSAL_PARSER, logger, "append %s %s %s %s[_%d]",
	      parser->protocol->name,
	      transform_type->name,
	      transform->type->story,
	      transform->fqn,
	      enckeylen);
}

/*
 * Note: duplicates are only removed after all transform's algorithms
 * have all parsed.
 *
 * Stops bogus errors when making multiple attempts at parsing the
 * transform algoritithms, for instance as a PRF and then as INTEG.
 */
void remove_duplicate_algorithms(struct proposal_parser *parser,
				 struct proposal *proposal,
				 const struct transform_type *transform_type)
{
	const struct logger *logger = parser->policy->logger;

	PASSERT(logger, transform_type->index < elemsof(proposal->algorithms));
	struct transform_algorithms *algs = proposal->algorithms[transform_type->index];
	if (algs == NULL || algs->len == 0) {
		return;
	}

	unsigned new_len = 1;	/* keep/skip the first */
	for (unsigned n = 1; n < algs->len; n++) {
		const struct transform_algorithm *new = &algs->item[n];
		bool duplicate = false;
		for (unsigned o = 0; o < n; o++) {
			const struct transform_algorithm *old = &algs->item[o];
			if (old->desc != new->desc) {
				continue;
			}
			/*
			 * Since enckeylen=0 is a wildcard there's no
			 * point following it with a non-zero keylen,
			 * for instance aes,aes128.
			 *
			 * The reverse, aes128,aes is ok.  It is
			 * giving preference to aes128 over other aes
			 * combinations.
			 */
			if (old->enckeylen == 0 ||
			    old->enckeylen == new->enckeylen) {
				LLOG_JAMBUF(parser->policy->stream, parser->policy->logger, buf) {
					jam(buf, "discarding duplicate %s %s %s",
					    parser->protocol->name,
					    new->desc->type->story,
					    new->desc->fqn);
					if (new->enckeylen != 0) {
						jam(buf, "_%d", new->enckeylen);
					}
				}
				duplicate = true;
				break;
			}
		}
		if (duplicate) {
			continue;
		}
		algs->item[new_len++] = (*new);
	}
	algs->len = new_len;
}

static const char *jam_proposal_algorithm(struct jambuf *buf,
					  const struct proposal *proposal,
					  const struct transform_type *type,
					  const char *algorithm_separator)
{
	const char *separator = algorithm_separator;
	ITEMS_FOR_EACH(algorithm, proposal->algorithms[type->index]) {
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

	for (const struct transform_type *type = transform_type_floor;
	     type < PMIN(transform_type_prf, transform_type_integ);
	     type++) {
		algorithm_separator = jam_proposal_algorithm(buf, proposal, type,
							     algorithm_separator);
	}

	/*
	 * Does it look like the INTEG was generated from the PRF?
	 *
	 * When it is, the INTEG is suppressed.
	 */

	struct transform_algorithms *prf_algs = proposal->algorithms[PROPOSAL_TRANSFORM_prf];
	struct transform_algorithms *integ_algs = proposal->algorithms[PROPOSAL_TRANSFORM_integ];
	bool encrypt_is_empty = (first_proposal_transform(proposal, transform_type_encrypt) == NULL);
	bool prf_is_empty = (first_proposal_transform(proposal, transform_type_prf) == NULL);
	bool integ_is_empty = (first_proposal_transform(proposal, transform_type_integ) == NULL);
	bool integ_matches_prf = false;
	if (!prf_is_empty && !integ_is_empty &&
	    prf_algs->len == integ_algs->len) {
		integ_matches_prf = true; /* hopefully */
		for (unsigned n = 0; n < integ_algs->len; n++) {
			struct transform_algorithm *prf  = &prf_algs->item[n];
			struct transform_algorithm *integ  = &integ_algs->item[n];
			if (&integ_desc(integ->desc)->prf->common != prf->desc) {
				/* i.e., prf and integ are different */
				integ_matches_prf = false;
				break;
			}
		}
	}

	/*
	 * For output compatibility reasons, the INTEG is shown before
	 * the PRF; but not when it matches the PRF; and not when it
	 * is NONE (ike=aes_gcm-none gives the impression that there
	 * is no integrity).
	 */

	if (encrypt_is_empty ||
	    (proposal_encrypt_aead(proposal) && !proposal_integ_none(proposal)) ||
	    (proposal_encrypt_norm(proposal) && !integ_matches_prf)) {
		algorithm_separator = jam_proposal_algorithm(buf, proposal,
							     transform_type_integ,
							     algorithm_separator);
	}

	algorithm_separator = jam_proposal_algorithm(buf, proposal,
						     transform_type_prf,
						     algorithm_separator);

	for (const struct transform_type *type = PMAX(transform_type_prf + 1,
						      transform_type_integ + 1);
	     type < transform_type_roof; type++) {
		algorithm_separator = jam_proposal_algorithm(buf, proposal, type,
							     algorithm_separator);
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
		struct transform_algorithm *first_kem =
			first_proposal_transform(proposal, transform_type_kem);
		if (first_kem == NULL) {
			if (first_null_ke == NULL) {
				first_null_ke = proposal;
			}
		} else if (first_kem->desc == &ike_alg_kem_none.common) {
			if (first_none_ke == NULL) {
				first_none_ke = proposal;
			}
		} else if (first_ke == NULL) {
			first_ke = first_kem->desc;
		} else if (second_ke == NULL && first_ke != first_kem->desc) {
			second_ke = first_kem->desc;
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
			struct transform_algorithm *first_kem =
				first_proposal_transform(proposal, transform_type_kem);
			if (first_kem != NULL) {
				ke = first_kem->desc;
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
			pfree_transforms(proposal, transform_type_kem);
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

bool parse_proposal_encrypt_transform(struct proposal_parser *parser,
				      struct proposal *proposal,
				      struct proposal_tokenizer *tokens)
{
	if (tokens->curr.token.len == 0) {
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
	if (tokens->curr.delim == '-' &&
	    tokens->next.token.len > 0 &&
	    char_isdigit(hunk_char(tokens->next.token, 0))) {
		/* assume <ealg>-<eklen> */
		shunk_t ealg = tokens->curr.token;
		shunk_t eklen = tokens->next.token;
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
			return ignore_transform_lookup_error(parser, transform_type_encrypt, print);
		}

		append_proposal_transform(parser, proposal,
					  transform_type_encrypt,
					  alg, enckeylen);
		/* consume <ealg>-<eklen> */
		proposal_next_token(tokens);
		proposal_next_token(tokens);
		return true;
	}

	/*
	 * Does the token match <ealg> (without any _<eklen> suffix?)
	 */
	shunk_t token = tokens->curr.token;
	const struct ike_alg *alg = encrypt_alg_byname(parser, token,
						       0/*enckeylen*/,
						       /*print*/token);
	if (alg != NULL) {
		append_proposal_transform(parser, proposal,
					  transform_type_encrypt,
					  alg, 0);
		/* consume <ealg> */
		proposal_next_token(tokens);
		return true;
	}

	/* buffer still contains error from <ealg> lookup */
	passert(parser->diag != NULL);

	/*
	 * See if there's a trailing <eklen> in <ealg>.  If there
	 * isn't then the lookup error above can be returned.
	 */
	size_t end = token.len;
	while (end > 0 && char_isdigit(hunk_char(token, end-1))) {
		end--;
	}
	if (end == token.len) {
		/*
		 * No trailing <eklen> digits and <ealg> was rejected
		 * by above); error still contains message from not
		 * finding just <ealg>.
		 */
		passert(parser->diag != NULL);
		return ignore_transform_lookup_error(parser, transform_type_encrypt,
						     tokens->curr.token);
	}

	/*
	 * Buffer still contains error from simple <ealg> lookup;
	 * discard it.
	 */
	passert(parser->diag != NULL);
	pfree_diag(&parser->diag);

	/*
	 * Try parsing the <eklen> found in <token>.  For something
	 * like aes_gcm_16, above lookup should have found the
	 * algorithm so isn't a problem here.
	 *
	 * Always treat this as an error.
	 */
	shunk_t eklen = hunk_slice(token, end, token.len);
	int enckeylen = parse_proposal_eklen(parser, token, eklen);
	if (enckeylen <= 0) {
		passert(parser->diag != NULL);
		return false;
	}

	passert(parser->diag == NULL);

	/*
	 * The <eklen> in <ealg><eklen> or <ealg>_<eklen> parsed; trim
	 * <eklen> from <ealg> and then try the lookup.
	 */
	shunk_t ealg = hunk_slice(token, 0, end);
	if (hunk_char(ealg, ealg.len-1) == '_') {
		ealg = hunk_slice(ealg, 0, ealg.len-1);
	}
	alg = encrypt_alg_byname(parser, ealg, enckeylen, /*print*/token);
	if (alg == NULL) {
		passert(parser->diag != NULL);
		return ignore_transform_lookup_error(parser, transform_type_encrypt, token);
	}

	append_proposal_transform(parser, proposal,
				  transform_type_encrypt,
				  alg, enckeylen);
	/* consume <ealg> */
	proposal_next_token(tokens);
	return true;
}

/*
 * No questions hack to either return 'false' for parsing a transform
 * failed (because it isn't known), or 'true' and warn because forced
 * parsing is enabled.
 */

bool ignore_transform_lookup_error(struct proposal_parser *parser,
				   const struct transform_type *transform_type,
				   shunk_t token)
{
	const struct logger *logger = parser->policy->logger;
	passert(parser->diag != NULL);
	if (parser->policy->ignore_transform_lookup_error) {
		/*
		 * XXX: the algorithm might be unknown, or might be
		 * known but not enabled due to FIPS, or ...?
		 */
		name_buf vb;
		llog(RC_LOG, logger,
		     "ignoring %s %s %s '"PRI_SHUNK"': %s",
		     str_enum_long(&ike_version_names, parser->policy->version, &vb),
		     parser->protocol->name, /* ESP|IKE|AH */
		     transform_type->name,
		     pri_shunk(token),
		     str_diag(parser->diag));
		pfree_diag(&parser->diag);
		return true;
	}

	ldbgf(DBG_PROPOSAL_PARSER, logger,
	      "lookup for %s '"PRI_SHUNK"' failed: %s",
	      transform_type->name,
	      pri_shunk(token),
	      str_diag(parser->diag));
	return false;
}

bool parse_proposal_transform(struct proposal_parser *parser,
			      struct proposal *proposal,
			      const struct transform_type *transform_type,
			      shunk_t token)
{
	const struct logger *logger = parser->policy->logger;
	PASSERT(logger, parser->diag == NULL);
	PASSERT(logger, transform_type != NULL);

	if (token.len == 0) {
		proposal_error(parser, "%s %s is empty",
			       parser->protocol->name,
			       transform_type->alg->story);
		return false;
	}

	ldbgf(DBG_PROPOSAL_PARSER, logger, "parsing transform '%s' of type '%s': "PRI_SHUNK,
	      transform_type->name,
	      transform_type->alg->name,
	      pri_shunk(token));

	const struct ike_alg *alg = alg_byname(parser, transform_type->alg,
					       token, token/*print*/);
	if (alg == NULL) {
		return ignore_transform_lookup_error(parser, transform_type, token);
	}

	append_proposal_transform(parser, proposal, transform_type, alg, 0/*enckeylen*/);
	return true;
}

void discard_proposal_transform(const char *what, struct proposal_parser *parser,
				struct proposal *proposal,
				const struct transform_type *type,
				diag_t *diag)
{
	const struct logger *logger = parser->policy->logger;
	/* toss the result, but save the error */
	ldbgf(DBG_PROPOSAL_PARSER, logger,
	      "%s failed, saving error '%s' and tossing result",
	      what, str_diag(parser->diag));
	pfree_transforms(proposal, type);
	if (diag != NULL) {
		(*diag) = parser->diag;
		parser->diag = NULL;
	} else {
		pfree_diag(&parser->diag);
	}
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

static void jam_token(struct jambuf *buf, const char *wrap,
		      struct proposal_term term)
{
	jam_string(buf, " ");
	jam_string(buf, wrap);
	if (term.token.ptr == NULL) {
		jam_string(buf, "<null>");
	} else {
		jam_string(buf, "\"");
		jam_shunk(buf, term.token);
		jam_string(buf, "\"");
	}
	jam_string(buf, "'");
	if (term.delim != '\0') {
		jam_char(buf, term.delim);
	}
	jam_string(buf, "'");
	jam_string(buf, wrap);
}

void proposal_next_token(struct proposal_tokenizer *tokens)
{
	struct logger *logger = &global_logger;

	/* shuffle tokens */
	tokens->prev = tokens->curr;
	tokens->curr = tokens->next;
	/* parse new next */
	tokens->next.token = shunk_token(&tokens->input, &tokens->next.delim, tokens->delims);
	if (LDBGP(DBG_PROPOSAL_PARSER, logger)) {
		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
			jam_string(buf, "tokens:");
			jam_token(buf, "", tokens->prev);
			jam_token(buf, "*", tokens->curr);
			jam_token(buf, "", tokens->next);
			jam_string(buf, " ");
			if (tokens->input.ptr == NULL) {
				jam_string(buf, "<null>");
			} else {
				jam_string(buf, "\"");
				jam_shunk(buf, tokens->input);
				jam_string(buf, "\"");
			}
		}
	}
}

static bool parse_transform_algorithms(struct proposal_parser *parser,
				       struct proposal *proposal,
				       const struct transform_type *transform_type,
				       struct proposal_tokenizer *tokens)
{
	const struct logger *logger = parser->policy->logger;
	PASSERT(logger, transform_type != NULL);
	ldbgf(DBG_PROPOSAL_PARSER, logger, "parsing %s of type %s",
	      transform_type->name,
	      transform_type->alg->name);

	PASSERT(logger, parser->diag == NULL); /* so far so good */
	if (!parse_proposal_transform(parser, proposal,
				      transform_type,
				      tokens->curr.token)) {
		return false;
	}

	passert(parser->diag == NULL); /* still good */
	proposal_next_token(tokens);
	while (tokens->prev.delim == '+') {
		if (!parse_proposal_transform(parser, proposal,
					      transform_type,
					      tokens->curr.token)) {
			return false;
		}
		passert(parser->diag == NULL);
		proposal_next_token(tokens);
	}

	remove_duplicate_algorithms(parser, proposal, transform_type);
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

	remove_duplicate_algorithms(parser, proposal, transform_type_encrypt);
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
	if (parse_transform_algorithms(parser, proposal, transform_type_prf, &prf_tokens)) {
		/* advance */
		ldbgf(DBG_PROPOSAL_PARSER, logger,
		      "<encr>-<PRF> succeeded, advancing tokens");
		(*tokens) = prf_tokens;
		return true;
	}

	/*
	 * XXX: IKEv1 IKE proposals only allow a PRF (i.e., not
	 * ike=<encr>-<integ> or ike=<encr>-<prf>-<integ>.  Hence,
	 * when the PRF lookup fails, reject the proposal.
	 */
	if (!parser->protocol->integ) {
		PEXPECT(logger, parser->diag != NULL);
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
				   transform_type_prf,
				   /*save the diag*/&prf_diag);

	if (!parse_transform_algorithms(parser, proposal, transform_type_integ, tokens)) {
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

	if (!parse_transform_algorithms(parser, proposal, transform_type_prf, tokens)) {
		ldbgf(DBG_PROPOSAL_PARSER, logger,
		      "<encr>-<integ>-<PRF> failed '%s'", str_diag(parser->diag));
		return false;
	}

	return true;
}

enum transform_typed_how {
	TRANSFORM_TYPE_EXPLICIT,
	TRANSFORM_TYPE_IMPLICIT,
};

static bool parse_proposal_transforms(struct proposal_parser *parser,
				      struct proposal *proposal,
				      const struct transform_type *transform_type,
				      enum transform_typed_how typed_how,
				      struct proposal_tokenizer *tokens)
{
	const struct logger *logger = parser->policy->logger;
	ldbgf(DBG_PROPOSAL_PARSER, logger,
	      "parsing transforms %s%s"PRI_SHUNK"...",
	      transform_type->name,
	      (typed_how == TRANSFORM_TYPE_IMPLICIT ? ":" :
	       typed_how == TRANSFORM_TYPE_EXPLICIT ? "=" :
	       "?"),
	      pri_shunk(tokens->curr.token));

	switch (transform_type->index) {

	case PROPOSAL_TRANSFORM_encrypt:
		if (parser->protocol->encrypt) {
			return parse_encrypt_transforms(parser, proposal, tokens);
		}
		break;

	case PROPOSAL_TRANSFORM_prf:
		if (parser->protocol->prf) {
			return parse_prf_transforms(parser, proposal, tokens);
		}
		break;

	case PROPOSAL_TRANSFORM_integ:
		if ((parser->protocol->integ && !parser->protocol->prf) ||
		    (parser->protocol->integ && typed_how == TRANSFORM_TYPE_EXPLICIT)) {
			return parse_transform_algorithms(parser, proposal,
							  transform_type, tokens);
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
			return parse_transform_algorithms(parser, proposal,
							  transform_type, tokens);
		}
		break;

	case PROPOSAL_TRANSFORM_sn:
		if (typed_how == TRANSFORM_TYPE_EXPLICIT) {
			return parse_transform_algorithms(parser, proposal,
							  transform_type, tokens);
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
			return parse_transform_algorithms(parser, proposal,
							  transform_type, tokens);
		}
		break;
	}

	if (typed_how == TRANSFORM_TYPE_EXPLICIT) {
		/* just in-case DELIM is NUL */
		proposal_error(parser, "%s proposal contains unexpected explicit "PRI_SHUNK"%c",
			       parser->protocol->name,
			       pri_shunk(tokens->prev.token),
			       tokens->prev.delim);
		return false;
	}

	return true;
}

bool parse_proposal(struct proposal_parser *parser,
		    struct proposal *proposal, shunk_t input)
{
	const struct logger *logger = parser->policy->logger;

	if (LDBGP(DBG_PROPOSAL_PARSER, logger)) {
		LDBG_log(logger, "proposal: '"PRI_SHUNK"'", pri_shunk(input));
	}

	struct proposal_tokenizer tokens = proposal_first_token(input, "-;+=!");

	/* hack to stop non ADDKE reporting missing ADDKE */
	const struct transform_type *transform_roof =
		(parser->policy->addke ? transform_type_roof :
		 transform_type_addke1);

	const struct transform_type *transform_type = transform_type_floor;

	while (tokens.curr.token.ptr != NULL) {

		const char prev_delim[] = { tokens.prev.delim, '\0', };
		const char curr_delim[] = { tokens.curr.delim, '\0', };
		ldbgf(DBG_PROPOSAL_PARSER, logger, "examining '%s' \""PRI_SHUNK"\" '%s', transform=%s",
		      prev_delim,
		      pri_shunk(tokens.curr.token),
		      curr_delim,
		      transform_type->name);

		if (tokens.curr.delim == '!') {

			const struct transform_type *tmp =
				transform_type_by_name(tokens.curr.token);
			if (tmp == NULL) {
				proposal_error(parser, "proposal %s transform '"PRI_SHUNK"' unrecognized",
					       proposal->protocol->name,
					       pri_shunk(tokens.curr.token));
				return false;
			}

			/* advance to TRANSFORMS after '!' */
			transform_type = tmp;
			proposal_next_token(&tokens);
			proposal->impaired = true;

			/* go directly to the algorithm parser */
			if (tokens.curr.token.len == 0 &&
			    tokens.curr.token.ptr != NULL &&
			    proposal->algorithms[transform_type->index] == NULL) {
				llog(IMPAIR_STREAM, logger, "forcing empty %s proposal %s transform",
				     proposal->protocol->name,
				     transform_type->name);
				proposal->algorithms[transform_type->index] =
					alloc_thing(struct transform_algorithms,
						    "empty transforms");
				/* skip empty transform */
				proposal_next_token(&tokens);
			} else {
				llog(IMPAIR_STREAM, logger, "forcing %s proposal %s transform",
				     proposal->protocol->name,
				     transform_type->name);
				if (!parse_transform_algorithms(parser, proposal,
								transform_type, &tokens)) {
					return false;
				}
			}

			continue;

		}

		enum transform_typed_how typed_how;

		if (tokens.curr.delim == '=') {

			/*
			 * Check for '=' before ';' so that ';foo=bar'
			 * is allowed anywhere.
			 */

			const struct transform_type *tmp =
				transform_type_by_name(tokens.curr.token);
			if (tmp == NULL) {
				proposal_error(parser, "transform '"PRI_SHUNK"' unrecognized",
					       pri_shunk(tokens.curr.token));
				return false;
			}

			if (tmp >= transform_roof) {
				proposal_error(parser, "transform '"PRI_SHUNK"' invalid",
					       pri_shunk(tokens.curr.token));
				return false;
			}

			ldbgf(DBG_PROPOSAL_PARSER, logger,
			      "switching from '%s' transforms to '%s' transforms",
			      transform_type->name,
			      tmp->name);

			/* advance to TRANSFORMS after '=' */
			proposal_next_token(&tokens);
			transform_type = tmp;
			typed_how = TRANSFORM_TYPE_EXPLICIT;

		} else if (tokens.prev.delim == ';' &&
			   transform_type <= transform_type_kem) {

			ldbgf(DBG_PROPOSAL_PARSER, logger,
			      "skipping from transform '%s' to ;KEM",
			      transform_type->name);

			/* treat ;... like KEM=... */
			transform_type = transform_type_kem;
			typed_how = TRANSFORM_TYPE_EXPLICIT;

		} else if (tokens.prev.delim != ';' &&
			   transform_type < transform_roof) {

			typed_how = TRANSFORM_TYPE_IMPLICIT;

		} else {
			proposal_error(parser,
				       "%s proposal contains unexpected '%s"PRI_SHUNK"%s', expecting ';<transform>=...'",
				       parser->protocol->name,
				       prev_delim,
				       pri_shunk(tokens.curr.token),
				       curr_delim);
			return false;
		}

		PASSERT(logger, (transform_type >= transform_types &&
				 transform_type < transform_type_roof));

		if (!parse_proposal_transforms(parser, proposal,
					       transform_type,
					       typed_how, &tokens)) {
			return false;
		}

		transform_type++;
	}

	return true;
}
