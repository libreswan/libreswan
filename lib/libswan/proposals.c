/*
 * Algorithm info parsing and creation functions
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
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

struct proposal {
	/*
	 * The algorithm entries.
	 */
	struct algorithm *algorithms[PROPOSAL_ALGORITHM_ROOF];
	/*
	 * Which protocol is this proposal intended for?
	 */
	const struct proposal_protocol *protocol;
	struct proposal *next;
};

struct proposals {
	bool defaulted;
	int ref_cnt;
	struct proposal *proposals;
};

struct proposal_parser *alloc_proposal_parser(const struct proposal_policy *policy,
					      const struct proposal_protocol *protocol)
{
	struct proposal_parser *parser = alloc_thing(struct proposal_parser, "parser");
	parser->policy = policy;
	parser->protocol = protocol;
	parser->error[0] = '\0';
	return parser;
}

void free_proposal_parser(struct proposal_parser **parser)
{
	pfree(*parser);
	*parser = NULL;
}

bool proposal_encrypt_aead(const struct proposal *proposal)
{
	if (proposal->algorithms[PROPOSAL_encrypt] == NULL) {
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
	if (proposal->algorithms[PROPOSAL_encrypt] == NULL) {
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

	if (proposal->algorithms[PROPOSAL_encrypt] == NULL) {
		return true;
	}

	/* are any and all encrypt algorithms AEAD? */
	bool aead = proposal_encrypt_aead(proposal);
	bool norm = proposal_encrypt_norm(proposal);

	if (!aead && !norm) {
		proposal_error(parser, "AEAD and non-AEAD %s encryption algorithm can not be combined",
			       proposal->protocol->name);
		return false;
	}

	/* are any and all integ algorithms NONE? */
	bool none = proposal_integ_none(proposal);

	if (aead && !none) {
		const struct ike_alg *encrypt = proposal->algorithms[PROPOSAL_encrypt]->desc;
		/*
		 * At least one of the integrity algorithms wasn't
		 * NONE.  For instance, esp=aes_gcm-sha1" is invalid.
		 */
		proposal_error(parser, "AEAD %s encryption algorithm '%s' must have 'NONE' as the integrity algorithm",
			       proposal->protocol->name,
			       encrypt->fqn);
		return false;
	}

	if (norm && none) {
		const struct ike_alg *encrypt = proposal->algorithms[PROPOSAL_encrypt]->desc;
		/*
		 * Not AEAD and either there was no integrity
		 * algorithm (implying NONE) or at least one integrity
		 * algorithm was NONE.  For instance,
		 * esp=aes_cbc-none" is invalid.
		 */
		proposal_error(parser, "non-AEAD %s encryption algorithm '%s' cannot have 'NONE' as the integrity algorithm",
			       proposal->protocol->name,
			       encrypt->fqn);
		return false;
	}

	return true;
}


/*
 * proposals struct can be shared by several connections instances,
 * handle free() with ref_cnts.
 */

void proposals_addref(struct proposals **proposals)
{
	if ((*proposals) != NULL) {
		(*proposals)->ref_cnt++;
	}
}

void proposals_delref(struct proposals **proposals)
{
	if ((*proposals) != NULL) {
		if ((*proposals)->ref_cnt == 0) {
			free_proposal(&(*proposals)->proposals);
			pfree((*proposals));
		} else {
			(*proposals)->ref_cnt--;
		}
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

unsigned nr_proposals(struct proposals *proposals)
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
		for (enum proposal_algorithm pa = 0;
		     same && pa < PROPOSAL_ALGORITHM_ROOF; pa++) {
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
				if (old->desc->algo_type == IKE_ALG_ENCRYPT &&
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
			dbg("discarding duplicate proposal");
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
#define D(ALG) .ALG = proposal->algorithms[PROPOSAL_##ALG] != NULL ? ALG##_desc(proposal->algorithms[PROPOSAL_##ALG]->desc) : NULL
		D(encrypt),
		D(prf),
		D(integ),
		D(dh),
#undef D
	};
	v1.enckeylen = proposal->algorithms[PROPOSAL_encrypt] != NULL ? proposal->algorithms[PROPOSAL_encrypt]->enckeylen : 0;

	return v1;
}

struct algorithm *next_algorithm(const struct proposal *proposal,
				 enum proposal_algorithm algorithm,
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
		     enum proposal_algorithm algorithm)
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

struct proposal *alloc_proposal(struct proposal_parser *parser)
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
		for (enum proposal_algorithm algorithm = 0;
		     algorithm < PROPOSAL_ALGORITHM_ROOF;
		     algorithm++) {
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
static enum proposal_algorithm ike_to_proposal_algorithm(const struct ike_alg *alg)
{
	if (alg->algo_type == IKE_ALG_ENCRYPT) {
		return PROPOSAL_encrypt;
	} else if (alg->algo_type == IKE_ALG_PRF) {
		return PROPOSAL_prf;
	} else if (alg->algo_type == IKE_ALG_INTEG) {
		return PROPOSAL_integ;
	} else if (alg->algo_type == IKE_ALG_DH) {
		return PROPOSAL_dh;
	} else {
		PASSERT_FAIL("unexpected algorithm type %s",
			     ike_alg_type_name(alg->algo_type));
	}
}

void append_algorithm(struct proposal_parser *parser,
		      struct proposal *proposal,
		      const struct ike_alg *alg,
		      int enckeylen)
{
	enum proposal_algorithm algorithm = ike_to_proposal_algorithm(alg);
	passert(algorithm < elemsof(proposal->algorithms));
	struct algorithm **end = &proposal->algorithms[algorithm];
	/* find end, and check for duplicates */
	while ((*end) != NULL) {
		/*
		 * enckeylen=0 acts as a wildcard
		 */
		if (alg == (*end)->desc &&
		    (alg->algo_type != IKE_ALG_ENCRYPT ||
		     ((*end)->enckeylen == 0 ||
		      enckeylen == (*end)->enckeylen))) {
			parser->policy->warning("discarding duplicate algorithm '%s'",
						alg->fqn);
			return;
		}
		end = &(*end)->next;
	}
	struct algorithm new_algorithm = {
		.desc = alg,
		.enckeylen = enckeylen,
	};
	DBGF(DBG_PROPOSAL_PARSER, "appending %s algorithm %s[_%d]",
	     ike_alg_type_name(alg->algo_type), alg->fqn, enckeylen);
	*end = clone_thing(new_algorithm, "alg");
}

void jam_proposal(struct lswlog *log,
		  const struct proposal *proposal)
{
	const char *ps = "";

	const char *as = "";

	as = ps;
	FOR_EACH_ALGORITHM(proposal, encrypt, alg) {
		const struct encrypt_desc *encrypt = encrypt_desc(alg->desc);
		lswlogs(log, as); ps = "-"; as = "+";
		lswlogs(log, encrypt->common.fqn);
		if (alg->enckeylen != 0) {
			lswlogf(log, "_%d", alg->enckeylen);
		}
	}

	as = ps;
	FOR_EACH_ALGORITHM(proposal, prf, alg) {
		const struct prf_desc *prf = prf_desc(alg->desc);
		lswlogs(log, as); ps = "-"; as = "+";
		lswlogs(log, prf->common.fqn);
	}

	bool print_integ = (impair.proposal_parser ||
			    /* no PRF */
			    next_algorithm(proposal, PROPOSAL_prf, NULL) == NULL ||
			    /* AEAD should have NONE */
			    (proposal_encrypt_aead(proposal) && !proposal_integ_none(proposal)));
	if (!print_integ && proposal_encrypt_norm(proposal)) {
		/* non-AEAD should have matching PRF and INTEG */
		for (struct algorithm *integ = next_algorithm(proposal, PROPOSAL_integ, NULL),
			     *prf = next_algorithm(proposal, PROPOSAL_prf, NULL);
		     !print_integ && (integ != NULL || prf != NULL);
		     integ = next_algorithm(proposal, PROPOSAL_integ, integ),
			     prf = next_algorithm(proposal, PROPOSAL_prf, prf)) {
			print_integ = (integ == NULL || prf == NULL ||
				       &integ_desc(integ->desc)->prf->common != prf->desc);
		}
	}
	as = ps;
	if (print_integ) {
		FOR_EACH_ALGORITHM(proposal, integ, alg) {
			const struct integ_desc *integ = integ_desc(alg->desc);
			lswlogs(log, as); ps = "-"; as = "+";
			lswlogs(log, integ->common.fqn);
		}
	}

	as = ps;
	FOR_EACH_ALGORITHM(proposal, dh, alg) {
		const struct dh_desc *dh = dh_desc(alg->desc);
		lswlogs(log, as); ps = "-"; as = "+";
		lswlogs(log, dh->common.fqn);
	}
}

void jam_proposals(struct lswlog *log, const struct proposals *proposals)
{
	const char *sep = "";
	FOR_EACH_PROPOSAL(proposals, proposal) {
		lswlogs(log, sep);
		fmt_proposal(log, proposal);
		sep = ", ";
	}
}

/*
 * When PFS=no ignore any DH algorithms, and when PFS=yes reject
 * mixing implicit and explicit DH.
 */
static bool proposals_pfs_vs_dh_check(struct proposal_parser *parser,
				      struct proposals *proposals)
{
	/* scrape the proposals for dh algorithms */
	const struct proposal *first_null = NULL;
	const struct proposal *first_none = NULL;
	const struct ike_alg *first_dh = NULL;
	const struct ike_alg *second_dh = NULL;
	FOR_EACH_PROPOSAL(proposals, proposal) {
		if (proposal->algorithms[PROPOSAL_dh] == NULL) {
			if (first_null == NULL) {
				first_null = proposal;
			}
		} else if (proposal->algorithms[PROPOSAL_dh]->desc == &ike_alg_dh_none.common) {
			if (first_none == NULL) {
				first_none = proposal;
			}
		} else if (first_dh == NULL) {
			first_dh = proposal->algorithms[PROPOSAL_dh]->desc;
		} else if (second_dh == NULL &&
			   first_dh != proposal->algorithms[PROPOSAL_dh]->desc) {
			second_dh = proposal->algorithms[PROPOSAL_dh]->desc;
		}
	}

	if (first_dh == NULL && first_none == NULL) {
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
	if (!parser->policy->pfs && (first_dh != NULL || first_none != NULL)) {
		FOR_EACH_PROPOSAL(proposals, proposal) {
			const struct ike_alg *dh = NULL;
			if (proposal->algorithms[PROPOSAL_dh] != NULL) {
				dh = proposal->algorithms[PROPOSAL_dh]->desc;
			}
			if (dh == &ike_alg_dh_none.common) {
				parser->policy->warning("ignoring redundant %s DH algorithm NONE as PFS policy is disabled",
							parser->protocol->name);
			} else if (dh != NULL) {
				parser->policy->warning("ignoring %s DH algorithm %s as PFS policy is disabled",
							parser->protocol->name,
							dh->fqn);
			}
			free_algorithms(proposal, PROPOSAL_dh);
		}
		return true;
	}

	/*
	 * Since at least one proposal included DH, all proposals
	 * should.  A proposal without DH is an error.
	 *
	 * (The converse, no proposals including DH was handled right
	 * at the start).
	 */
	if (first_null != NULL) {
		/* DH was specified */
		proposal_error(parser, "either all or no %s proposals should specify DH",
			       parser->protocol->name);
		if (!impair_proposal_errors(parser)) {
			return false;
		}
	}

	switch (parser->policy->version) {

	case IKEv1:
		/*
		 * IKEv1 only allows one DH algorithm.
		 */
		if (first_dh != NULL && second_dh != NULL) {
			proposal_error(parser, "more than one IKEv1 %s DH algorithm (%s, %s) is not allowed in quick mode",
				       parser->protocol->name,
				       first_dh->fqn,
				       second_dh->fqn);
			if (!impair_proposal_errors(parser)) {
				return false;
			}
		}
		break;

	case IKEv2:
		/*
		 * IKEv2, only implements one DH algorithm.
		 */
		if (first_dh != NULL && second_dh != NULL) {
			proposal_error(parser, "more than one IKEv2 %s DH algorithm (%s, %s) requires unimplemented CHILD_SA INVALID_KE",
				       parser->protocol->name,
				       first_dh->fqn,
				       second_dh->fqn);
			if (!impair_proposal_errors(parser)) {
				return false;
			}
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
	vsnprintf(parser->error, sizeof(parser->error), fmt, ap);
	va_end(ap);
}

bool impair_proposal_errors(struct proposal_parser *parser)
{
	pexpect(parser->error[0] != '\0');
	if (impair.proposal_parser) {
		libreswan_log("IMPAIR: ignoring proposal error: %s",
			      parser->error);
		parser->error[0] = '\0';
		return true;
	} else {
		return false;
	}
}

struct proposals *proposals_from_str(struct proposal_parser *parser,
				     const char *str)
{
	struct proposals *proposals = alloc_thing(struct proposals, "proposals");
	unsigned parser_version = parser->policy->parser_version;
	if (parser_version == 0) {
		parser_version = parser->policy->version;
	}
	if (str == NULL) {
		proposals->defaulted = true;
		/* may still be null */
		str = parser->protocol->defaults[parser->policy->version]->proposals;
	}
	bool ok;
	switch (parser_version) {
	case 2: ok = v2_proposals_parse_str(parser, proposals, shunk1(str)); break;
	default: ok = v1_proposals_parse_str(parser, proposals, shunk1(str)); break;
	}
	if (!ok) {
		proposals_delref(&proposals);
		return NULL;
	}
	if (proposals->proposals == NULL) {
		proposals_delref(&proposals);
		return NULL;
	}
	if (parser->policy->check_pfs_vs_dh &&
	    !proposals_pfs_vs_dh_check(parser, proposals)) {
		pexpect(parser->error[0] != '\0');
		proposals_delref(&proposals);
		return NULL;
	}
	return proposals;
}

bool default_proposals(struct proposals *proposals)
{
	return proposals == NULL || proposals->defaulted;
}
