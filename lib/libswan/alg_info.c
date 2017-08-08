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
struct parser_context {
	unsigned state;
	const struct parser_param *param;
	const struct parser_policy *policy;
	char ealg_buf[20];
	char eklen_buf[20];
	char aalg_buf[20];
	char modp_buf[20];
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
			const struct parser_param *param)
{
	*ctx = (struct parser_context) {
		.param = param,
		.policy = policy,
		.state = (param->encrypt_alg_byname
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
			if (p_ctx->param->dh_alg_byname != NULL && isalpha(ch)) {
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

static const struct ike_alg *lookup_byname(struct parser_context *p_ctx,
					   char *err_buf, size_t err_buf_len,
					   const struct ike_alg *(alg_byname)(const struct parser_param *param,
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
			const struct ike_alg *alg = alg_byname(p_ctx->param,
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
				       char *err_buf, size_t err_buf_len,
				       struct alg_info *alg_info)
{
	DBG(DBG_CONTROLMORE,
	    DBG_log("add ealg_buf='%s' eklen_buf='%s' aalg_buf='%s' modp_buf='%s'",
		    p_ctx->ealg_buf,
		    p_ctx->eklen_buf,
		    p_ctx->aalg_buf,
		    p_ctx->modp_buf));

	struct proposal_info proposal = { .enckeylen = 0, };

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
					   p_ctx->param->encrypt_alg_byname,
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
		strcpy(p_ctx->eklen_buf, end + 1);
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
							      p_ctx->param->encrypt_alg_byname,
							      p_ctx->ealg_buf, proposal.enckeylen,
							      "encryption"));
		if (err_buf[0] != '\0') {
			return err_buf;
		}
	}

	proposal.prf = prf_desc(lookup_byname(p_ctx, err_buf, err_buf_len,
					      p_ctx->param->prf_alg_byname,
					      p_ctx->aalg_buf, 0,
					      "PRF"));
	if (err_buf[0] != '\0') {
		return err_buf;
	}

	proposal.integ = integ_desc(lookup_byname(p_ctx, err_buf, err_buf_len,
						  p_ctx->param->integ_alg_byname,
						  p_ctx->aalg_buf, 0,
						  "integrity"));
	if (err_buf[0] != '\0') {
		return err_buf;
	}

	proposal.dh = oakley_group_desc(lookup_byname(p_ctx, err_buf, err_buf_len,
						      p_ctx->param->dh_alg_byname,
						      p_ctx->modp_buf, 0,
						      "group"));
	if (err_buf[0] != '\0') {
		return err_buf;
	}

	return p_ctx->param->alg_info_add(p_ctx->policy,
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
				    const struct parser_param *param)
{
	DBG(DBG_CONTROL,
	    DBG_log("parsing '%s' for %s", alg_str, param->protocol));

	struct parser_context ctx;
	int ret;
	const char *ptr;

	alg_info->alg_info_protoid = param->protoid;
	err_buf[0] = '\0';

	parser_init(&ctx, policy, param);

	/* use default if null string */
	if (*alg_str == '\0') {
		param->alg_info_add(ctx.policy, alg_info,
				    NULL, 0,
				    NULL, NULL, NULL,
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
				err_t ugh = parser_alg_info_add(&ctx, error, sizeof(error),
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
			parser_init(&ctx, policy, param);
			break;

		default:
			/* ??? this is nonsense: in either case, break will happen */
			if (ctx.ch != '\0')
				break;
		}
	} while (ret < ST_EOF);
	return alg_info;
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

size_t lswlog_proposal_info(struct lswlog *log, struct proposal_info *proposal)
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
		sep = "-";
	}
	return size;
}
