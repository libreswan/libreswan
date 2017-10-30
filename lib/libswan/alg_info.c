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
#include "ike_alg_null.h"

/*
 *	Creates a new alg_info by parsing passed string
 */
enum parser_state {
	ST_INI_EA,      /* parse ike= or esp= string */
	ST_INI_AA,      /* parse ah= string */
	ST_EA,          /* encrypt algo   */
	ST_EA_END,
	ST_EK,          /* enc. key length */
	ST_EK_END,
	ST_AA,          /* auth algo */
	ST_AA_END,
	ST_MODP,        /* modp spec */
	ST_END,
	ST_EOF,
};

/* XXX:jjo to implement different parser for ESP and IKE */
#define ALG_SIZE 30
struct parser_context {
	unsigned state;
	const struct parser_protocol *protocol;
	const struct parser_policy *policy;
	char ealg_buf[ALG_SIZE];
	char eklen_buf[ALG_SIZE];
	char aalg_buf[ALG_SIZE];
	char modp_buf[ALG_SIZE];
	char *ealg_str;
	char *eklen_str;
	char *aalg_str;
	char *modp_str;
	int ch;	/* character that stopped parsing */
};

static const char *parser_state_names[] = {
	"ST_INI_EA",
	"ST_INI_AA",
	"ST_EA",
	"ST_EA_END",
	"ST_EK",
	"ST_EK_END",
	"ST_AA",
	"ST_AA_END",
	"ST_MOPD",
	"ST_END",
	"ST_EOF",
};

static const char *parser_state_name(enum parser_state state)
{
	passert(state < elemsof(parser_state_names));
	return parser_state_names[state];
}

static inline void parser_set_state(struct parser_context *p_ctx,
				    enum parser_state state)
{
	p_ctx->state = state;
}

static void parser_init(struct parser_context *ctx,
			const struct parser_policy *policy,
			const struct parser_protocol *protocol)
{
	*ctx = (struct parser_context) {
		.protocol = protocol,
		.policy = policy,
		.state = (protocol->encrypt_alg_byname
			  ? ST_INI_EA
			  : ST_INI_AA),
		/*
		 * DANGER: this is a pointer to a very small buffer on
		 * the stack.
		 */
		.ealg_str = ctx->ealg_buf,
		.eklen_str = ctx->eklen_buf,
		.aalg_str = ctx->aalg_buf,
		.modp_str = ctx->modp_buf,
	};
}

static err_t parser_machine(struct parser_context *p_ctx)
{
	int ch = p_ctx->ch;

	/* chars that end algo strings */
	switch (ch) {
	case '\0':		/* end-of-string */
	case ',':	/* algo string separator */
		switch (p_ctx->state) {
		case ST_EA:
		case ST_EK:
		case ST_AA:
		case ST_MODP:
		{
			enum parser_state next_state = 0;

			switch (ch) {
			case '\0':
				next_state = ST_EOF;
				break;
			case ',':
				next_state = ST_END;
				break;
			}
			parser_set_state(p_ctx, next_state);
			return NULL;
		}
		default:
			return "String ended with invalid char";
		}
	}

	for (;;) {
		DBG(DBG_CONTROLMORE,
		    DBG_log("state=%s ealg_buf='%s' eklen_buf='%s' aalg_buf='%s' modp_buf='%s'",
			    parser_state_name(p_ctx->state),
			    p_ctx->ealg_buf,
			    p_ctx->eklen_buf,
			    p_ctx->aalg_buf,
			    p_ctx->modp_buf));
		/*
		 * There are three ways out of this switch:
		 * - break: successful termination of the function
		 * - return diag: unsuccessful termination of the function
		 * - continue: repeat the switch
		 */
		switch (p_ctx->state) {
		case ST_INI_EA:
			if (isspace(ch))
				break;
			if (isalnum(ch)) {
				*(p_ctx->ealg_str++) = ch;
				parser_set_state(p_ctx, ST_EA);
				break;
			}
			return "No alphanum. char initially found";

		case ST_INI_AA:
			if (isspace(ch))
				break;
			if (isalnum(ch)) {
				*(p_ctx->aalg_str++) = ch;
				parser_set_state(p_ctx, ST_AA);
				break;
			}
			return "No alphanum. char initially found";

		case ST_EA:
			if (isalnum(ch) || ch == '_') {
				/*
				 * accept all of <ealg>[_<eklen>]
				 */
				*(p_ctx->ealg_str++) = ch;
				break;
			}
			if (ch == '-') {
				*(p_ctx->ealg_str++) = '\0';
				parser_set_state(p_ctx, ST_EA_END);
				break;
			}
			return "No valid char found after enc alg string";

		case ST_EA_END:
			if (isdigit(ch)) {
				/*
				 * Given legacy <ealg>-<eklen>, save
				 * <eklen>.
				 */
				parser_set_state(p_ctx, ST_EK);
				continue;
			}
			if (isalpha(ch)) {
				parser_set_state(p_ctx, ST_AA);
				continue;
			}
			return "No alphanum char found after enc alg separator";

		case ST_EK:
			if (isdigit(ch)) {
				*(p_ctx->eklen_str++) = ch;
				break;
			}
			if (ch == '-') {
				*(p_ctx->eklen_str++) = '\0';
				parser_set_state(p_ctx, ST_EK_END);
				break;
			}
			return "Non digit or valid separator found while reading enc keylen";

		case ST_EK_END:
			if (isalpha(ch)) {
				parser_set_state(p_ctx, ST_AA);
				continue;
			}
			return "Non alpha char found after enc keylen end separator";

		case ST_AA:
			if (ch == ';' || ch == '-') {
				*(p_ctx->aalg_str++) = 0;
				parser_set_state(p_ctx, ST_AA_END);
				break;
			}
			if (isalnum(ch) || ch == '_') {
				*(p_ctx->aalg_str++) = ch;
				break;
			}
			return "Non alphanum or valid separator found in auth string";

		case ST_AA_END:
			/*
			 * Only allow modpXXXX string if we have
			 * a modp_getbyname method
			 */
			if (p_ctx->protocol->dh_alg_byname != NULL && isalpha(ch)) {
				parser_set_state(p_ctx, ST_MODP);
				continue;
			}
			return "Invalid modulus";

		case ST_MODP:
			if (isalnum(ch) || ch == '_') {
				*(p_ctx->modp_str++) = ch;
				break;
			}
			return "Non alphanum char found after in modp string";

		case ST_END:
		case ST_EOF:
			break;
		}
		return NULL;
	}
}

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

static const char *add_proposal_defaults(const struct parser_policy *policy,
					 const struct proposal_defaults *defaults,
					 struct alg_info *alg_info,
					 const struct proposal_info *proposal,
					 char *err_buf, size_t err_buf_len);


static const char *add_alg_defaults(const struct parser_policy *policy,
				    const struct proposal_defaults *defaults,
				    struct alg_info *alg_info,
				    const struct proposal_info *proposal,
				    const struct ike_alg_type *type,
				    const struct ike_alg **default_algs,
				    merge_alg_default_t *merge_alg_default,
				    char *err_buf, size_t err_buf_len)
{
	/*
	 * Use VALID_ALG to add the valid algorithms into VALID_ALGS.
	 */
	for (const struct ike_alg **default_alg = default_algs;
	     *default_alg; default_alg++) {
		const struct ike_alg *alg = *default_alg;
		char buf[LOG_WIDTH] = "";
		if (!alg_byname_ok(proposal->protocol, policy, alg,
				   alg->name, buf, sizeof(buf))) {
			DBG(DBG_CONTROL|DBG_CRYPT,
			    DBG_log("skipping default %s", buf));
			continue;
		}
		/* add it */
		DBG(DBG_CONTROL|DBG_CRYPT,
		    DBG_log("adding default %s %s",
			    ike_alg_type_name(type),
			    alg->name));
		struct proposal_info merged_proposal = merge_alg_default(*proposal,
									 *default_alg);
		const char *error = add_proposal_defaults(policy, defaults,
							  alg_info, &merged_proposal,
							  err_buf, err_buf_len);
		if (error != NULL) {
			return error;
		}
	}
	return NULL;
}

/*
 * For all the algorithms, when an algorithm is missing (NULL), and
 * there are defaults, add them.
 */

static const char *add_proposal_defaults(const struct parser_policy *policy,
					 const struct proposal_defaults *defaults,
					 struct alg_info *alg_info,
					 const struct proposal_info *proposal,
					 char *err_buf, size_t err_buf_len)
{
	/*
	 * Note that the order in which things are recursively added -
	 * MODP, ENCR, PRF/HASH - affects test results.  It determines
	 * things like the order of proposals.
	 */
	if (proposal->dh == NULL &&
	    defaults != NULL && defaults->dh != NULL) {
		return add_alg_defaults(policy, defaults,
					alg_info, proposal,
					&ike_alg_dh, defaults->dh,
					merge_dh_default,
					err_buf, err_buf_len);
	} else if (proposal->encrypt == NULL &&
		   defaults != NULL && defaults->encrypt != NULL) {
		return add_alg_defaults(policy, defaults,
					alg_info, proposal,
					&ike_alg_encrypt, defaults->encrypt,
					merge_encrypt_default,
					err_buf, err_buf_len);
	} else if (proposal->prf == NULL &&
		   defaults != NULL && defaults->prf != NULL) {
		return add_alg_defaults(policy, defaults,
					alg_info, proposal,
					&ike_alg_prf, defaults->prf,
					merge_prf_default,
					err_buf, err_buf_len);
	} else if (proposal->integ == NULL &&
		   proposal->encrypt != NULL && ike_alg_is_aead(proposal->encrypt)) {
		/*
		 * Since AEAD, integrity is always 'none'.
		 */
		struct proposal_info merged_proposal = *proposal;
		merged_proposal.integ = &ike_alg_integ_none;
		return add_proposal_defaults(policy, defaults,
					     alg_info, &merged_proposal,
					     err_buf, err_buf_len);
	} else if (proposal->integ == NULL &&
		   defaults != NULL && defaults->integ != NULL) {
		return add_alg_defaults(policy, defaults,
					alg_info, proposal,
					&ike_alg_integ, defaults->integ,
					merge_integ_default,
					err_buf, err_buf_len);
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
			snprintf(err_buf, err_buf_len,
				 "%s integrity derived from PRF '%s' is not supported",
				 proposal->protocol->name,
				 proposal->prf->common.name);
			return err_buf;
		}
		return add_proposal_defaults(policy, defaults,
					     alg_info, &merged_proposal,
					     err_buf, err_buf_len);
	} else {

		/* duplicate? */
		FOR_EACH_PROPOSAL_INFO(alg_info, existing_proposal) {
			/*
			 * key length 0 is like a wild-card (it actually means
			 * propose default and strongest key lengths)
			 * so if either is zero just treat it as a
			 * match.
			 */
			if (existing_proposal->encrypt == proposal->encrypt &&
			    existing_proposal->prf == proposal->prf &&
			    existing_proposal->integ == proposal->integ &&
			    existing_proposal->dh == proposal->dh &&
			    (existing_proposal->enckeylen == proposal->enckeylen ||
			     existing_proposal->enckeylen == 0 ||
			     proposal->enckeylen == 0)) {
				DBG(DBG_CRYPT,
				    DBG_log("discarding duplicate %s proposal encrypt=%s enckeylen=%zu prf=%s integ=%s dh=%s",
					    proposal->protocol->name,
					    proposal->encrypt != NULL ? proposal->encrypt->common.name : "n/a",
					    proposal->enckeylen,
					    proposal->prf != NULL ? proposal->prf->common.name : "n/a",
					    proposal->integ != NULL ? proposal->integ->common.name : "n/a",
					    proposal->dh != NULL ? proposal->dh->common.name : "n/a"));
				return NULL;
			}
		}

		/* Overflow? */
		if ((unsigned)alg_info->alg_info_cnt >= elemsof(alg_info->proposals)) {
			snprintf(err_buf, err_buf_len,
				 "more than %zu %s algorithms specified",
				 elemsof(alg_info->proposals),
				 proposal->protocol->name);
			/* drop it like a rock */
			return err_buf;
		}

		/* back end? */
		if (!proposal->protocol->proposal_ok(proposal, err_buf, err_buf_len)) {
			passert(err_buf[0] != '\0');
			return err_buf;
		}

		alg_info->proposals[alg_info->alg_info_cnt++] = *proposal;
		return NULL;
	}
}

static const char *merge_default_proposals(const struct parser_policy *policy,
					   struct alg_info *alg_info,
					   const struct proposal_info *proposal,
					   char *err_buf, size_t err_buf_len)
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
	const struct proposal_defaults *defaults = (policy->ikev1
						    ? proposal->protocol->ikev1_defaults
						    : proposal->protocol->ikev2_defaults);
	return add_proposal_defaults(policy, defaults,
				     alg_info, proposal,
				     err_buf, err_buf_len);
}

static const struct ike_alg *lookup_byname(struct parser_context *p_ctx,
					   char *err_buf, size_t err_buf_len,
					   const struct ike_alg *(alg_byname)(const struct parser_protocol *protocol,
									      const struct parser_policy *const policy,
									      char *err_buf, size_t err_buf_len,
									      const char *name,
									      size_t key_bit_length),
					   const char *name,
					   size_t key_bit_length,
					   const char *what)
{
	err_buf[0] = '\0';
	if (name[0] != '\0') {
		if (alg_byname != NULL) {
			const struct ike_alg *alg = alg_byname(p_ctx->protocol,
							       p_ctx->policy,
							       err_buf, err_buf_len,
							       name, key_bit_length);
			if (alg == NULL) {
				DBG(DBG_CONTROLMORE,
				    DBG_log("%s_byname('%s') failed: %s",
					    what, name, err_buf));
				passert(err_buf[0]);
				return NULL;
			}
			DBG(DBG_CONTROLMORE,
			    DBG_log("%s_byname('%s') returned '%s'",
				    what, name, alg->name));
			return alg;
		} else {
			DBG(DBG_CONTROLMORE,
			    DBG_log("ignoring %s '%s'", what, name));
			return NULL;
		}
	}
	return NULL;
}

static int parse_eklen(char *err_buf, size_t err_buf_len,
			const char *eklen_buf)
{
	/* convert -<eklen> if present */
	long eklen = strtol(eklen_buf, NULL, 10);
	if (eklen >= INT_MAX) {
		snprintf(err_buf, err_buf_len,
			 "encryption key length '%s' WAY too big",
			 eklen_buf);
		return 0;
	}
	if (eklen == 0) {
		snprintf(err_buf, err_buf_len,
			 "encryption key length is zero");
		return 0;
	}
	return eklen;
}

static const char *parser_alg_info_add(struct parser_context *p_ctx,
				       struct proposal_info proposal,
				       char *err_buf, size_t err_buf_len,
				       struct alg_info *alg_info)
{
	DBG(DBG_CONTROLMORE,
	    DBG_log("add ealg_buf='%s' eklen_buf='%s' aalg_buf='%s' modp_buf='%s'",
		    p_ctx->ealg_buf,
		    p_ctx->eklen_buf,
		    p_ctx->aalg_buf,
		    p_ctx->modp_buf));

	/*
	 * Try the raw EALG string with "-<eklen>" if present.
	 * Strings like aes_gcm_16 and aes_gcm_16_256 end up in
	 * <ealg>, while strings like aes_gcm_16-256 end up in
	 * <ealg>-<eklen>.
	 */
	if (p_ctx->eklen_buf[0] != '\0') {
		/* convert -<eklen> if present */
		int enckeylen = parse_eklen(err_buf, err_buf_len, p_ctx->eklen_buf);
		if (enckeylen <= 0) {
			passert(err_buf[0] != '\0');
			return err_buf;
		}
		proposal.enckeylen = enckeylen;
	}
	proposal.encrypt =
		encrypt_desc(lookup_byname(p_ctx, err_buf, err_buf_len,
					   p_ctx->protocol->encrypt_alg_byname,
					   p_ctx->ealg_buf, proposal.enckeylen,
					   "encryption"));
	if (err_buf[0] != '\0') {
		/* Was <ealg>-<eklen> rejected? */
		if (proposal.enckeylen > 0) {
			passert(p_ctx->eklen_buf[0] != '\0');
			return err_buf;
		}
		passert(p_ctx->eklen_buf[0] == '\0');
		/* Could it be <ealg><eklen>? */
		char *end = &p_ctx->ealg_buf[strlen(p_ctx->ealg_buf) > 0 ?  strlen(p_ctx->ealg_buf) - 1 : 0];
		if (!isdigit(*end)) {
			/* <eklen> was rejected */
			return err_buf;
		}
		/*
		 * Trailing digit so assume that <ealg> is really
		 * <ealg>_<eklen> or <ealg><eklen>, strip of the
		 * <eklen> and try again.
		 */
		do {
			if (end == p_ctx->ealg_buf) {
				/* <ealg> missing */
				return err_buf;
			}
			end--;
		} while (isdigit(*end));
		/* save for logging */
		jam_str(p_ctx->eklen_buf, sizeof(p_ctx->eklen_buf), end + 1);

		int enckeylen = parse_eklen(err_buf, err_buf_len, end + 1);

		if (enckeylen <= 0) {
			passert(err_buf[0] != '\0');
			return err_buf;
		}
		proposal.enckeylen = enckeylen;
		/*
		 * strip optional "_" when "<ealg>_<eklen>"
		 */
		if (end > p_ctx->ealg_buf && *end == '_') {
			end--;
		}
		/* truncate and try again */
		end[1] = '\0';
		err_buf[0] = '\0';
		proposal.encrypt = encrypt_desc(lookup_byname(p_ctx, err_buf, err_buf_len,
							      p_ctx->protocol->encrypt_alg_byname,
							      p_ctx->ealg_buf, proposal.enckeylen,
							      "encryption"));
		if (err_buf[0] != '\0') {
			return err_buf;
		}
	}

	proposal.prf = prf_desc(lookup_byname(p_ctx, err_buf, err_buf_len,
					      p_ctx->protocol->prf_alg_byname,
					      p_ctx->aalg_buf, 0,
					      "PRF"));
	if (err_buf[0] != '\0') {
		return err_buf;
	}

	proposal.integ = integ_desc(lookup_byname(p_ctx, err_buf, err_buf_len,
						  p_ctx->protocol->integ_alg_byname,
						  p_ctx->aalg_buf, 0,
						  "integrity"));
	if (err_buf[0] != '\0') {
		return err_buf;
	}

	proposal.dh = oakley_group_desc(lookup_byname(p_ctx, err_buf, err_buf_len,
						      p_ctx->protocol->dh_alg_byname,
						      p_ctx->modp_buf, 0,
						      "group"));
	if (err_buf[0] != '\0') {
		return err_buf;
	}

	if (p_ctx->protocol->alg_info_add == NULL) {
		return merge_default_proposals(p_ctx->policy,
					       alg_info, &proposal,
					       err_buf, err_buf_len);
	}

	return p_ctx->protocol->alg_info_add(p_ctx->policy,
					  alg_info,
					  proposal.encrypt, proposal.enckeylen,
					  proposal.prf, proposal.integ,
					  proposal.dh,
					  err_buf, err_buf_len);
}

/*
 * on success: returns alg_info
 * on failure: alg_info_free(alg_info) and return NULL;
 */
struct alg_info *alg_info_parse_str(const struct parser_policy *policy,
				    struct alg_info *alg_info,
				    const char *alg_str,
				    char *err_buf, size_t err_buf_len,
				    const struct parser_protocol *protocol)
{
	DBG(DBG_CONTROL,
	    DBG_log("parsing '%s' for %s", alg_str, protocol->name));

	struct parser_context ctx;
	int ret;
	const char *ptr;

	err_buf[0] = '\0';

	parser_init(&ctx, policy, protocol);

	const struct proposal_info proposal = {
		.protocol = protocol,
	};

	/* use default if no (NULL) string */
	if (alg_str == NULL) {
		merge_default_proposals(ctx.policy,
					alg_info, &proposal,
					err_buf, err_buf_len);
		return alg_info;
	}

	ptr = alg_str;
	do {
		ctx.ch = *ptr++;
		{
			err_t pm_ugh = parser_machine(&ctx);
			if (pm_ugh != NULL) {
				snprintf(err_buf, err_buf_len,
					 "%s, just after \"%.*s\" (state=%s)",
					 pm_ugh,
					 (int)(ptr - alg_str - 1), alg_str,
					 parser_state_name(ctx.state));
				alg_info_free(alg_info);
				return NULL;
			}
		}
		ret = ctx.state;
		switch (ret) {
		case ST_END:
		case ST_EOF:
			{
				char error[100] = ""; /* arbitrary */
				err_t ugh = parser_alg_info_add(&ctx, proposal,
								error, sizeof(error),
								alg_info);
				if (ugh != NULL) {
					snprintf(err_buf, err_buf_len,
						 "%s, enc_alg=\"%s\"(%s), auth_alg=\"%s\", modp=\"%s\"",
						 ugh, ctx.ealg_buf,
						 ctx.eklen_buf[0] != '\0' ? ctx.eklen_buf : "0",
						 ctx.aalg_buf,
						 ctx.modp_buf);
					alg_info_free(alg_info);
					return NULL;
				}
			}
			/* zero out for next run (ST_END) */
			parser_init(&ctx, policy, protocol);
			break;

		default:
			/* ??? this is nonsense: in either case, break will happen */
			if (ctx.ch != '\0')
				break;
		}
	} while (ret < ST_EOF);
	return alg_info;
}

bool proposal_aead_none_ok(const struct proposal_info *proposal,
			   char *err_buf, size_t err_buf_len)
{
	if (proposal->encrypt != NULL && ike_alg_is_aead(proposal->encrypt)
	    && proposal->integ != NULL && proposal->integ != &ike_alg_integ_none) {
		/*
		 * For instance, esp=aes_gcm-sha1" is invalid.
		 */
		snprintf(err_buf, err_buf_len,
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
		snprintf(err_buf, err_buf_len,
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
		size += lswlogf(log, "%s%s", sep, proposal->encrypt->common.fqn);
		sep = "-";
		if (proposal->enckeylen != 0) {
			size += lswlogf(log, "_%zd", proposal->enckeylen);
		}
	}
	if (proposal->prf != NULL) {
		size += lswlogf(log, "%s%s", sep, proposal->prf->common.fqn);
		sep = "-";
	} else if (proposal->integ != NULL) {
		size += lswlogf(log, "%s%s", sep, proposal->integ->common.fqn);
		sep = "-";
	}
	if (proposal->dh != NULL) {
		size += lswlogf(log, "%s%s", sep, proposal->dh->common.fqn);
		sep = "-";	/* sep not subsequently used */
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
