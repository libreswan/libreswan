/*
 * Algorithm info parsing and creation functions
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
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
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>

#include <ctype.h>
#include <libreswan.h>
#include <libreswan/passert.h>
#include <libreswan/pfkeyv2.h>

#include "constants.h"
#include "alg_info.h"
#include "lswlog.h"
#include "lswalloc.h"

#include "lswconf.h"

/* abstract reference */
struct oakley_group_desc;

#define MAX_ALG_ALIASES 16

typedef struct alg_alias {
	const char *alg;
	const char *alias_set[MAX_ALG_ALIASES];
} alg_alias;

/*
 * Aliases should NOT be used to match a base cipher to a key size,
 * as that would change the meaning of the loaded connection. For
 * examples aes cannot become an alias for aes128 or else a responder
 * with esp=aes would reject aes256.
 */
static const alg_alias auth_alg_aliases[] = {
	/* alg */	/* aliases */
	{ "sha2_256",	{ "sha2", NULL } },
	{ "sha1",	{ "sha", NULL } },
	{ "sha1",	{ "sha1_96", NULL } },
	{ NULL, { NULL } }
};

static const alg_alias esp_trans_aliases[] = {
	/* alg */	/* aliases */
	{ "aes_ccm_a",	{ "aes_ccm_8",  NULL } },
	{ "aes_ccm_b",	{ "aes_ccm_12", NULL } },
	{ "aes_ccm_c",	{ "aes_ccm_16", "aes_ccm", NULL } },
	{ "aes_gcm_a",	{ "aes_gcm_8", NULL } },
	{ "aes_gcm_b",	{ "aes_gcm_12", NULL } },
	{ "aes_gcm_c",	{ "aes_gcm_16", "aes_gcm", NULL } },
	{ "aes_ctr",	{ "aesctr", NULL } },
	{ "aes",	{ "aes_cbc", NULL } },
	{ NULL, { NULL } }
};

/*
 * sadb/ESP aa attrib converters - conflicting for v1 and v2
 */
enum ipsec_authentication_algo alg_info_esp_aa2sadb(
	enum ikev1_auth_attribute auth)
{
	/* ??? this switch looks a lot like one in parse_ipsec_sa_body */
	switch (auth) {
	case AUTH_ALGORITHM_HMAC_MD5: /* 2 */
		return AH_MD5;

	case AUTH_ALGORITHM_HMAC_SHA1:
		return AH_SHA;

	case AUTH_ALGORITHM_HMAC_SHA2_256: /* 5 */
		return AH_SHA2_256;

	case AUTH_ALGORITHM_HMAC_SHA2_384:
		return AH_SHA2_384;

	case AUTH_ALGORITHM_HMAC_SHA2_512:
		return AH_SHA2_512;

	case AUTH_ALGORITHM_HMAC_RIPEMD:
		return AH_RIPEMD;

	case AUTH_ALGORITHM_AES_XCBC: /* 9 */
		return AH_AES_XCBC_MAC;

	/* AH_RSA not supported */
	case AUTH_ALGORITHM_SIG_RSA:
		return AH_RSA;

	case AUTH_ALGORITHM_AES_128_GMAC:
		return AH_AES_128_GMAC;

	case AUTH_ALGORITHM_AES_192_GMAC:
		return AH_AES_192_GMAC;

	case AUTH_ALGORITHM_AES_256_GMAC:
		return AH_AES_256_GMAC;

	case AUTH_ALGORITHM_NULL_KAME:
	case AUTH_ALGORITHM_NONE: /* private use 251 */
		return AH_NONE;

	default:
		bad_case(auth);
	}
}

/*
 * should change all algorithms to use IKEv2 numbers, and translate
 * at edges only
 */
enum ikev1_auth_attribute alg_info_esp_v2tov1aa(enum ikev2_trans_type_integ ti)
{
	switch (ti) {
	case IKEv2_AUTH_NONE:
		return AUTH_ALGORITHM_NONE;

	case IKEv2_AUTH_HMAC_MD5_96:
		return AUTH_ALGORITHM_HMAC_MD5;

	case IKEv2_AUTH_HMAC_SHA1_96:
		return AUTH_ALGORITHM_HMAC_SHA1;

	case IKEv2_AUTH_HMAC_SHA2_256_128:
		return AUTH_ALGORITHM_HMAC_SHA2_256;

	case IKEv2_AUTH_HMAC_SHA2_256_128_TRUNCBUG:
		return AUTH_ALGORITHM_HMAC_SHA2_256_TRUNCBUG;

	case IKEv2_AUTH_HMAC_SHA2_384_192:
		return AUTH_ALGORITHM_HMAC_SHA2_384;

	case IKEv2_AUTH_HMAC_SHA2_512_256:
		return AUTH_ALGORITHM_HMAC_SHA2_512;

	/* IKEv2 does not do RIPEMD */

	case IKEv2_AUTH_AES_XCBC_96:
		return AUTH_ALGORITHM_AES_XCBC;

	/* AH_RSA */

	case IKEv2_AUTH_AES_128_GMAC:
		return AUTH_ALGORITHM_AES_128_GMAC;

	case IKEv2_AUTH_AES_192_GMAC:
		return AUTH_ALGORITHM_AES_192_GMAC;

	case IKEv2_AUTH_AES_256_GMAC:
		return AUTH_ALGORITHM_AES_256_GMAC;

	/* invalid or not yet supported */
	case IKEv2_AUTH_DES_MAC:
	case IKEv2_AUTH_KPDK_MD5:
	case IKEv2_AUTH_INVALID:

	/* not available as IPSEC AH / ESP auth - IKEv2 only */
	case IKEv2_AUTH_HMAC_MD5_128:
	case IKEv2_AUTH_HMAC_SHA1_160:
	case IKEv2_AUTH_AES_CMAC_96:
	default:
		bad_case(ti);
	}
}

/*
 * XXX This maps IPSEC AH Transform Identifiers to IKE Integrity Algorithm
 * Transform IDs. But IKEv1 and IKEv2 tables don't match fully! See:
 *
 * http://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-7
 * http://www.iana.org/assignments/isakmp-registry/isakmp-registry.xhtml#isakmp-registry-7
 * http://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-6
 *
 * Callers of this function should get fixed
 */
int alg_info_esp_sadb2aa(int sadb_aalg)
{
	int auth = 0;

	/* md5 and sha1 entries are "off by one" */
	switch (sadb_aalg) {
	/* 0-1 RESERVED */
	case SADB_AALG_MD5HMAC: /* 2 */
		auth = AUTH_ALGORITHM_HMAC_MD5; /* 1 */
		break;
	case SADB_AALG_SHA1HMAC: /* 3 */
		auth = AUTH_ALGORITHM_HMAC_SHA1; /* 2 */
		break;
	/* 4 - SADB_AALG_DES */
	case SADB_X_AALG_SHA2_256HMAC:
		auth = AUTH_ALGORITHM_HMAC_SHA2_256;
		break;
	case SADB_X_AALG_SHA2_384HMAC:
		auth = AUTH_ALGORITHM_HMAC_SHA2_384;
		break;
	case SADB_X_AALG_SHA2_512HMAC:
		auth = AUTH_ALGORITHM_HMAC_SHA2_512;
		break;
	case SADB_X_AALG_RIPEMD160HMAC:
		auth = AUTH_ALGORITHM_HMAC_RIPEMD;
		break;
	case SADB_X_AALG_AES_XCBC_MAC:
		auth = AUTH_ALGORITHM_AES_XCBC;
		break;
	case SADB_X_AALG_RSA: /* unsupported by us */
		auth = AUTH_ALGORITHM_SIG_RSA;
		break;
	case SADB_X_AALG_AH_AES_128_GMAC:
		auth = AUTH_ALGORITHM_AES_128_GMAC;
		break;
	case SADB_X_AALG_AH_AES_192_GMAC:
		auth = AUTH_ALGORITHM_AES_192_GMAC;
		break;
	case SADB_X_AALG_AH_AES_256_GMAC:
		auth = AUTH_ALGORITHM_AES_256_GMAC;
		break;
	/* private use numbers */
	case SADB_X_AALG_NULL:
		auth = AUTH_ALGORITHM_NULL_KAME;
		break;
	default:
		/* which would hopefully be true  */
		auth = sadb_aalg;
	}
	return auth;
}

/*
 * Search enum_name array with string, uppercased, prefixed, and postfixed
 */
int alg_enum_search(enum_names *ed, const char *prefix,
		const char *postfix, const char *name,
		size_t name_len)
{
	char buf[64];
	size_t prelen = strlen(prefix);
	size_t postlen = strlen(postfix);

	if (prelen + name_len + postlen >= sizeof(buf))
		return -1;	/* cannot match */

	memcpy(buf, prefix, prelen);
	memcpy(buf + prelen, name, name_len);
	memcpy(buf + prelen + name_len, postfix, postlen + 1);	/* incl. NUL */

	return enum_search(ed, buf);
}

/*
 * Search esp_transformid_names for a match, eg:
 *	"3des" <=> "ESP_3DES"
 */
static int ealg_getbyname_esp(const char *const str, size_t len)
{
	if (str == NULL || *str == '\0')
		return -1;

	return alg_enum_search(&esp_transformid_names, "ESP_", "", str, len);
}

/*
 * Search auth_alg_names for a match, eg:
 *	"md5" <=> "AUTH_ALGORITHM_HMAC_MD5"
 */
static int aalg_getbyname_esp(const char *str, size_t len)
{
	int ret = -1;
	static const char null_esp[] = "null";

	if (str == NULL || *str == '\0')
		return -1;

	ret = alg_enum_search(&auth_alg_names, "AUTH_ALGORITHM_HMAC_", "",
			str, len);
	if (ret >= 0)
		return ret;
	ret = alg_enum_search(&auth_alg_names, "AUTH_ALGORITHM_", "",
			str, len);
	if (ret >= 0)
		return ret;

	/*
	 * INT_MAX is used as the special value for "no authentication"
	 * since 0 is already used.
	 * ??? this is extremely ugly.
	 */
	if (len == sizeof(null_esp)-1 && strncaseeq(str, null_esp, len))
		return INT_MAX;

	return ret;
}

/* if str is a known alias, return the real alg */
static const char *alg_find_alias(const alg_alias *alias, const char *str)
{
	const alg_alias *aa;
	int i;

	for (aa = alias; aa->alg != NULL; aa++) {
		const char *const *aset = aa->alias_set;

		for (i = 0; i < MAX_ALG_ALIASES && aset[i] != NULL; i++) {
			if (strcaseeq(str, aset[i]))
				return aa->alg;
		}
	}

	return NULL;
}

static int ealg_getbyname_or_alias_esp(const char *str, size_t len)
{
	const char *astr = alg_find_alias(esp_trans_aliases, str);

	return astr == NULL ?
		ealg_getbyname_esp(str, len) :
		ealg_getbyname_esp(astr, strlen(astr));
}

static int aalg_getbyname_or_alias_esp(const char *str, size_t len)
{
	const char *astr = alg_find_alias(auth_alg_aliases, str);

	return astr == NULL ?
		aalg_getbyname_esp(str, len) :
		aalg_getbyname_esp(astr, strlen(astr));
}

static int modp_getbyname_esp(const char *const str, size_t len)
{
	int ret = alg_enum_search(&oakley_group_names, "OAKLEY_GROUP_", "",
			str, len);

	if (ret < 0)
		ret = alg_enum_search(&oakley_group_names, "OAKLEY_GROUP_",
				" (extension)", str, len);
	return ret;
}

void alg_info_free(struct alg_info *alg_info)
{
	pfreeany(alg_info);
}

/*
 * Raw add routine: only checks for no duplicates
 */
/* ??? much of this code is the same as raw_alg_info_ike_add (same bugs!) */
static void raw_alg_info_esp_add(struct alg_info_esp *alg_info,
				int ealg_id, unsigned ek_bits,
				int aalg_id, unsigned ak_bits)
{
	struct esp_info *esp_info = alg_info->esp;
	int cnt = alg_info->ai.alg_info_cnt;
	int i;

	/* don't add duplicates */
	/* ??? why is 0 wildcard for ek_bits and ak_bits? */
	for (i = 0; i < cnt; i++) {
		if (esp_info[i].transid == ealg_id &&
		    (ek_bits == 0 || esp_info[i].enckeylen == ek_bits) &&
		    esp_info[i].auth == aalg_id &&
		    (ak_bits == 0 || esp_info[i].authkeylen == ak_bits))
			return;
	}

	/* check for overflows */
	/* ??? passert seems dangerous */
	passert(cnt < (int)elemsof(alg_info->esp));

	esp_info[cnt].transid = ealg_id;
	esp_info[cnt].enckeylen = ek_bits;
	esp_info[cnt].auth = aalg_id;
	esp_info[cnt].authkeylen = ak_bits;

	/* sadb values */
	esp_info[cnt].encryptalg = ealg_id;
	esp_info[cnt].authalg = alg_info_esp_aa2sadb(aalg_id);
	alg_info->ai.alg_info_cnt++;
}

/*
 * Add ESP alg info _with_ logic (policy):
 */
static void alg_info_esp_add(struct alg_info *alg_info,
			int ealg_id, int ek_bits,
			int aalg_id, int ak_bits,
			int modp_id UNUSED)
{
	/* Policy: default to AES */
	if (ealg_id == 0)
		ealg_id = ESP_AES;

	if (ealg_id > 0) {

		if (aalg_id > 0) {
			if (aalg_id == INT_MAX)
				aalg_id = 0;
			raw_alg_info_esp_add((struct alg_info_esp *)alg_info,
					ealg_id, ek_bits,
					aalg_id, ak_bits);
		} else {
			/* Policy: default to MD5 and SHA1 */
			raw_alg_info_esp_add((struct alg_info_esp *)alg_info,
					ealg_id, ek_bits,
					AUTH_ALGORITHM_HMAC_MD5, ak_bits);
			raw_alg_info_esp_add((struct alg_info_esp *)alg_info,
					ealg_id, ek_bits,
					AUTH_ALGORITHM_HMAC_SHA1, ak_bits);
		}
	}
}

/*
 * Add AH alg info _with_ logic (policy):
 */
static void alg_info_ah_add(struct alg_info *alg_info,
			int ealg_id, int ek_bits,
			int aalg_id, int ak_bits,
			int modp_id UNUSED)
{
	/* ah=null is invalid */
	if (aalg_id > 0) {
		raw_alg_info_esp_add((struct alg_info_esp *)alg_info,
				ealg_id, ek_bits,
				aalg_id, ak_bits);
	} else {
		/* Policy: default to MD5 and SHA1 */
		raw_alg_info_esp_add((struct alg_info_esp *)alg_info,
				ealg_id, ek_bits,
				AUTH_ALGORITHM_HMAC_MD5, ak_bits);
		raw_alg_info_esp_add((struct alg_info_esp *)alg_info,
				ealg_id, ek_bits,
				AUTH_ALGORITHM_HMAC_SHA1, ak_bits);
	}
}

static const char *parser_state_esp_names[] = {
	"ST_INI",
	"ST_INI_AA",
	"ST_EA",
	"ST_EA_END",
	"ST_EK",
	"ST_EK_END",
	"ST_AA",
	"ST_AA_END",
	"ST_AK",
	"ST_AK_END",
	"ST_MOPD",
	"ST_END",
	"ST_EOF",
	"ST_ERR"
};

static const char *parser_state_name_esp(enum parser_state_esp state)
{
	return parser_state_esp_names[state];
}

const struct parser_context empty_p_ctx;	/* full of zeros and NULLs */

static inline void parser_set_state(struct parser_context *p_ctx,
				enum parser_state_esp state)
{
	if (state != p_ctx->state) {
		p_ctx->old_state = p_ctx->state;
		p_ctx->state = state;
	}

}

static err_t parser_machine(struct parser_context *p_ctx)
{
	int ch = p_ctx->ch;

	/* special 'absolute' cases */
	p_ctx->err = "No error.";

	/* chars that end algo strings */
	switch (ch) {
	case '\0':		/* end-of-string */
	case ',':	/* algo string separator */
		switch (p_ctx->state) {
		case ST_EA:
		case ST_EK:
		case ST_AA:
		case ST_AK:
		case ST_MODP:
		{
			enum parser_state_esp next_state = 0;

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
		/*
		 * There are three ways out of this switch:
		 * - break: successful termination of the function
		 * - return diag: unsuccessful termination of the function
		 * - continue: repeat the switch
		 */
		switch (p_ctx->state) {
		case ST_INI:
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
			if (isalpha(ch) || ch == '_') {
				*(p_ctx->ealg_str++) = ch;
				break;
			}
			if (isdigit(ch)) {
				/* bravely switch to enc keylen */
				*(p_ctx->ealg_str) = 0;
				parser_set_state(p_ctx, ST_EK);
				continue;
			}
			if (ch == '-') {
				*(p_ctx->ealg_str) = 0;
				parser_set_state(p_ctx, ST_EA_END);
				break;
			}
			return "No valid char found after enc alg string";

		case ST_EA_END:
			if (isdigit(ch)) {
				/* bravely switch to enc keylen */
				parser_set_state(p_ctx, ST_EK);
				continue;
			}
			if (isalpha(ch)) {
				parser_set_state(p_ctx, ST_AA);
				continue;
			}
			return "No alphanum char found after enc alg separator";

		case ST_EK:
			if (ch == '-') {
				parser_set_state(p_ctx, ST_EK_END);
				break;
			}
			if (isdigit(ch)) {
				p_ctx->eklen = p_ctx->eklen * 10 + ch - '0';
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
			if (ch == '-') {
				*(p_ctx->aalg_str++) = 0;
				parser_set_state(p_ctx, ST_AA_END);
				break;
			}
			if (ch == ';') {
				*(p_ctx->aalg_str++) = 0;
				parser_set_state(p_ctx, ST_AK_END);
				break;
			}
			if (isalnum(ch) || ch == '_') {
				*(p_ctx->aalg_str++) = ch;
				break;
			}
			return "Non alphanum or valid separator found in auth string";

		case ST_AA_END:
			if (isdigit(ch)) {
				parser_set_state(p_ctx, ST_AK);
				continue;
			}
			/*
			 * Only allow modpXXXX string if we have
			 * a modp_getbyname method
			 */
			if (p_ctx->modp_getbyname != NULL && isalpha(ch)) {
				parser_set_state(p_ctx, ST_MODP);
				continue;
			}
			return "Non initial digit found for auth keylen";

		case ST_AK:
			if (ch == '-' || ch == ';') {
				parser_set_state(p_ctx, ST_AK_END);
				break;
			}
			if (isdigit(ch)) {
				p_ctx->aklen = p_ctx->aklen * 10 + ch - '0';
				break;
			}
			return "Non digit found for auth keylen";

		case ST_AK_END:
			/*
			 * Only allow modpXXXX string if we have
			 * a modp_getbyname method
			 */
			if (p_ctx->modp_getbyname != NULL && isalpha(ch)) {
				parser_set_state(p_ctx, ST_MODP);
				continue;
			}
			return "Non alpha char found after auth keylen";

		case ST_MODP:
			if (isalnum(ch)) {
				*(p_ctx->modp_str++) = ch;
				break;
			}
			return "Non alphanum char found after in modp string";

		case ST_END:
		case ST_EOF:
		case ST_ERR:
			break;
		}
		return NULL;
	}
}

/*
 * Must be called for each "new" char, with new
 * character in ctx.ch
 */
static void parser_init_esp(struct parser_context *p_ctx)
{
	*p_ctx = empty_p_ctx;

	p_ctx->protoid = PROTO_IPSEC_ESP;
	p_ctx->ealg_str = p_ctx->ealg_buf;
	p_ctx->aalg_str = p_ctx->aalg_buf;
	p_ctx->modp_str = p_ctx->modp_buf;
	p_ctx->ealg_permit = TRUE;
	p_ctx->aalg_permit = TRUE;
	p_ctx->state = ST_INI;

	p_ctx->ealg_getbyname = ealg_getbyname_or_alias_esp;
	p_ctx->aalg_getbyname = aalg_getbyname_or_alias_esp;

}

/*
 * Must be called for each "new" char, with new
 * character in ctx.ch
 */
static void parser_init_ah(struct parser_context *p_ctx)
{
	*p_ctx = empty_p_ctx;

	p_ctx->protoid = PROTO_IPSEC_AH;
	p_ctx->aalg_str = p_ctx->aalg_buf;
	p_ctx->ealg_permit = FALSE;
	p_ctx->aalg_permit = TRUE;
	p_ctx->modp_str = p_ctx->modp_buf;
	p_ctx->state = ST_INI_AA;

	p_ctx->aalg_getbyname = aalg_getbyname_or_alias_esp;

}

static err_t parser_alg_info_add(struct parser_context *p_ctx,
			struct alg_info *alg_info,
			void (*alg_info_add)(struct alg_info *alg_info,
					int ealg_id, int ek_bits,
					int aalg_id, int ak_bits,
					int modp_id),
			const struct oakley_group_desc *(*lookup_group)
			(u_int16_t group))
{
#define COMMON_KEY_LENGTHS(x) (x == 0 || x == 128 || x == 192 || x == 256)
	int ealg_id, aalg_id;
	int modp_id = 0;

	ealg_id = aalg_id = -1;
	if (p_ctx->ealg_permit && p_ctx->ealg_buf[0] != '\0') {
		ealg_id = p_ctx->ealg_getbyname(p_ctx->ealg_buf,
					strlen(p_ctx->ealg_buf));
		if (ealg_id < 0) {
			return "enc_alg not found";
		}

		/* reject things we know but don't like */
		switch(p_ctx->protoid) {
		case PROTO_ISAKMP:
			switch(ealg_id) {
			case OAKLEY_DES_CBC:
			case OAKLEY_IDEA_CBC:
			case OAKLEY_BLOWFISH_CBC:
			case OAKLEY_RC5_R16_B64_CBC:
				return "IKE cipher not implemented";
			}
			break;
		case PROTO_IPSEC_ESP:
			switch(ealg_id) {
			case ESP_reserved:
			case ESP_DES_IV64:
			case ESP_DES:
			case ESP_RC5:
			case ESP_IDEA:
			case ESP_BLOWFISH:
			case ESP_3IDEA:
			case ESP_DES_IV32:
			case ESP_RC4:
			case ESP_ID17:
				/*
				 * kernel uses IKEv1, where it is camellia
				 * - case ESP_RESERVED_FOR_IEEE_P1619_XTS_AES:
				 */
				return "ESP cipher not implemented";
			}
			break;
		}

		/*
		 * Enforce RFC restrictions in key size, documented in
		 * ietf_constants.h
		 * If using --impair-send-key-size-check this check is bypassed
		 * for testing purposes.
		 */
		if (p_ctx->eklen != 0 && !DBGP(IMPAIR_SEND_KEY_SIZE_CHECK)) {
			switch(p_ctx->protoid) {
			case PROTO_ISAKMP:
				switch(ealg_id) {
				case OAKLEY_3DES_CBC:
					return "3DES does not take variable key lengths";
				case OAKLEY_CAST_CBC:
					if (p_ctx->eklen != 128) {
						return "CAST is only supported for 128 bits (to avoid padding)";
					}
					break;
				case OAKLEY_AES_CBC:
				case OAKLEY_CAMELLIA_CBC:
				case OAKLEY_SERPENT_CBC:
				case OAKLEY_TWOFISH_CBC:
				case OAKLEY_TWOFISH_CBC_SSH:
					if (!COMMON_KEY_LENGTHS(p_ctx->eklen)) {
						return "wrong encryption key length - key size must be 128 (default), 192 or 256";
					}
					break;
				}
				break;
			case PROTO_IPSEC_ESP:
				switch(ealg_id) {
				case ESP_3DES:
					return "3DES does not take variable key lengths";
				case ESP_NULL:
					return "NULL does not take variable key lengths";
				case ESP_CAST:
					if (!COMMON_KEY_LENGTHS(p_ctx->eklen)) {
						return "CAST is only supported for 128 bits (to avoid padding)";
					}
					break;
				case ESP_CAMELLIA: /* this value is not used here, due to mixup in v1 and v2 */
				case ESP_CAMELLIAv1: /* this value is hit instead */
				case ESP_AES:
				case ESP_AES_CTR:
				case ESP_AES_GCM_8:
				case ESP_AES_GCM_12:
				case ESP_AES_GCM_16:
				case ESP_AES_CCM_8:
				case ESP_AES_CCM_12:
				case ESP_AES_CCM_16:
				case ESP_TWOFISH:
				case ESP_SERPENT:
					if (!COMMON_KEY_LENGTHS(p_ctx->eklen)) {
						return "wrong encryption key length - key size must be 128 (default), 192 or 256";
					}
					break;
#if 0
				case ESP_SEED_CBC:
					if (p_ctx->eklen != 128) {
						return "wrong encryption key length - SEED-CBC key size must be 128";
					}
					break;
#endif
				}
				break;
			}
		}

	}
	if (p_ctx->aalg_permit && *p_ctx->aalg_buf != '\0') {
		aalg_id = p_ctx->aalg_getbyname(p_ctx->aalg_buf,
					strlen(p_ctx->aalg_buf));
		if (aalg_id < 0) {
			return "hash_alg not found";
		}

		/* some code stupidly uses INT_MAX for "null" */
		if (aalg_id == AH_NONE || aalg_id == AH_NULL || aalg_id == INT_MAX) {
			if (p_ctx->protoid == PROTO_IPSEC_AH)
				return "AH cannot have null authentication";
			/* aalg can and must be only be null for AEAD ciphers */
			switch (p_ctx->protoid) {
			case PROTO_IPSEC_ESP:
				switch(ealg_id) {
				case ESP_AES_GCM_8:
				case ESP_AES_GCM_12:
				case ESP_AES_GCM_16:
				case ESP_AES_CCM_8:
				case ESP_AES_CCM_12:
				case ESP_AES_CCM_16:
					break; /* ok */
				default:
					return "non-AEAD ESP cipher cannot have null authentication";
				}
				break;
			case PROTO_ISAKMP:
				switch(ealg_id) {
				case IKEv2_ENCR_AES_CCM_8:
				case IKEv2_ENCR_AES_CCM_12:
				case IKEv2_ENCR_AES_CCM_16:
				case IKEv2_ENCR_AES_GCM_8:
				case IKEv2_ENCR_AES_GCM_12:
				case IKEv2_ENCR_AES_GCM_16:
					break; /* ok */
				default:
					return "non-AEAD IKE cipher cannot have null authentication";
				}
				break;
			case PROTO_IPSEC_AH:
				return "AH cannot have null authentication";
			}
		} else {
			/* auth is non-null, so we cannot have AEAD ciphers */
			switch (p_ctx->protoid) {
			case PROTO_IPSEC_ESP:
				switch(ealg_id) {
				case ESP_AES_GCM_8:
				case ESP_AES_GCM_12:
				case ESP_AES_GCM_16:
				case ESP_AES_CCM_8:
				case ESP_AES_CCM_12:
				case ESP_AES_CCM_16:
					return "AEAD ESP cipher must have null authentication";
				default:
					break; /* ok */
				}
				break;
			case PROTO_ISAKMP:
				switch(ealg_id) {
				case IKEv2_ENCR_AES_CCM_8:
				case IKEv2_ENCR_AES_CCM_12:
				case IKEv2_ENCR_AES_CCM_16:
				case IKEv2_ENCR_AES_GCM_8:
				case IKEv2_ENCR_AES_GCM_12:
				case IKEv2_ENCR_AES_GCM_16:
					return "AEAD IKE cipher must have null authentication";
				default:
					break; /* ok */
				}
				break;
			}
		}

		if (! DBGP(IMPAIR_SEND_KEY_SIZE_CHECK)) {
			switch(aalg_id) {
			case AH_NULL:
				if (ealg_id == -1)
					return "Encryption and authentication cannot both be null";
				break;
			default:
				if (p_ctx->aklen != 0)
					return "authentication algorithm does not take a variable key size";
				break;
			}
		}

	}

	if (p_ctx->modp_getbyname != NULL && *p_ctx->modp_buf != '\0') {
		modp_id = p_ctx->modp_getbyname(p_ctx->modp_buf,
					strlen(p_ctx->modp_buf));
		if (modp_id < 0) {
			return "modp group not found";
		}


		if (modp_id != 0 && lookup_group(modp_id) == NULL) {
			return "found modp group id, but not supported";
		}
	}

	(*alg_info_add)(alg_info,
			ealg_id, p_ctx->eklen,
			aalg_id, p_ctx->aklen,
			modp_id);
	return NULL;
}
#undef COMMON_KEY_LENGTHS

/*
 * on success: returns alg_info
 * on failure: pfree(alg_info) and return NULL;
 */
struct alg_info *alg_info_parse_str(
	unsigned protoid,
	struct alg_info *alg_info,
	const char *alg_str,
	char *err_buf, size_t err_buf_len,
	void (*parser_init)(struct parser_context *p_ctx),
	void (*alg_info_add)(struct alg_info *alg_info,
		int ealg_id, int ek_bits,
		int aalg_id, int ak_bits,
		int modp_id),
	const struct oakley_group_desc *(*lookup_group)(u_int16_t group))
{
	struct parser_context ctx;
	int ret;
	const char *ptr;

	alg_info->alg_info_protoid = protoid;
	err_buf[0] = '\0';

	(*parser_init)(&ctx);

	/* use default if null string */
	if (*alg_str == '\0')
		(*alg_info_add)(alg_info, 0, 0, 0, 0, 0);

	ptr = alg_str;
	do {
		ctx.ch = *ptr++;
		{
			err_t pm_ugh = parser_machine(&ctx);

			if (pm_ugh != NULL) {
				ctx.err = pm_ugh;
				parser_set_state(&ctx, ST_ERR);
			}
		}
		ret = ctx.state;
		switch (ret) {
		case ST_END:
		case ST_EOF:
			{
				err_t ugh = parser_alg_info_add(&ctx,
						alg_info,
						alg_info_add,
						lookup_group);

				if (ugh != NULL) {
					snprintf(err_buf, err_buf_len,
						"%s, enc_alg=\"%s\"(%d), auth_alg=\"%s\", modp=\"%s\"",
						ugh, ctx.ealg_buf, ctx.eklen, ctx.aalg_buf,
						ctx.modp_buf);
					pfree(alg_info);
					return NULL;
				}
			}
			/* zero out for next run (ST_END) */
			(*parser_init)(&ctx);
			break;

		case ST_ERR:
			snprintf(err_buf, err_buf_len,
				"%s, just after \"%.*s\" (old_state=%s)",
				ctx.err,
				(int)(ptr - alg_str - 1), alg_str,
				parser_state_name_esp(ctx.old_state));

			pfree(alg_info);
			return NULL;
		default:
			if (!ctx.ch)
				break;
		}
	} while (ret < ST_EOF);
	return alg_info;
}

static bool alg_info_discover_pfsgroup_hack(struct alg_info_esp *aie,
					char *esp_buf,
					char *err_buf, size_t err_buf_len)
{
	char *pfs_name = index(esp_buf, ';');

	err_buf[0] = '\0';
	aie->esp_pfsgroup = OAKLEY_GROUP_invalid;	/* default */
	if (pfs_name != NULL) {
		*pfs_name++ = '\0';

		/* if pfs string not null AND first char is not '0' */
		if (*pfs_name != '\0' && pfs_name[0] != '0') {
			int ret = modp_getbyname_esp(pfs_name, strlen(pfs_name));

			if (ret < 0) {
				/* Bomb if pfsgroup not found */
				snprintf(err_buf, err_buf_len,
					"pfsgroup \"%s\" not found",
					pfs_name);
				return FALSE;
			}
			aie->esp_pfsgroup = ret;
		}
	}

	return TRUE;
}

/* This function is tested in testing/lib/libswan/algparse.c */
struct alg_info_esp *alg_info_esp_create_from_str(const char *alg_str,
						char *err_buf, size_t err_buf_len)
{
	/*
	 * alg_info storage should be sized dynamically
	 * but this may require two passes to know
	 * transform count in advance.
	 */
	struct alg_info_esp *alg_info_esp = alloc_thing(struct alg_info_esp,
							"alg_info_esp");
	char esp_buf[256];	/* XXX should be changed to match parser max */

	jam_str(esp_buf, sizeof(esp_buf), alg_str);

	if (!alg_info_discover_pfsgroup_hack(alg_info_esp, esp_buf,
					err_buf, err_buf_len)) {
		pfree(alg_info_esp);
		return NULL;
	}

	return (struct alg_info_esp *)
		alg_info_parse_str(
			PROTO_IPSEC_ESP,
			&alg_info_esp->ai,
			esp_buf,
			err_buf, err_buf_len,
			parser_init_esp,
			alg_info_esp_add,
			NULL);
}

/* This function is tested in testing/lib/libswan/algparse.c */
/* ??? why is this called _ah_ when almost everything refers to esp? */
/* ??? the only difference between this and alg_info_esp is in two parameters to alg_info_parse_str */
struct alg_info_esp *alg_info_ah_create_from_str(const char *alg_str,
						char *err_buf, size_t err_buf_len)
{
	/*
	 * alg_info storage should be sized dynamically
	 * but this may require two passes to know
	 * transform count in advance.
	 */
	struct alg_info_esp *alg_info_esp = alloc_thing(struct alg_info_esp, "alg_info_esp");
	char esp_buf[256];	/* ??? big enough? */

	jam_str(esp_buf, sizeof(esp_buf), alg_str);

	if (!alg_info_discover_pfsgroup_hack(alg_info_esp, esp_buf, err_buf, err_buf_len)) {
		pfree(alg_info_esp);
		return NULL;
	}

	return (struct alg_info_esp *)
		alg_info_parse_str(
			PROTO_IPSEC_AH,
			&alg_info_esp->ai,
			esp_buf,
			err_buf, err_buf_len,
			parser_init_ah,
			alg_info_ah_add,
			NULL);
}

/*
 * alg_info struct can be shared by
 * several connections instances,
 * handle free() with ref_cnts
 */
void alg_info_addref(struct alg_info *alg_info)
{
	if (alg_info != NULL) {
		alg_info->ref_cnt++;
	}
}
void alg_info_delref(struct alg_info **alg_info_p)
{
	struct alg_info *alg_info = *alg_info_p;

	if (alg_info != NULL) {
		passert(alg_info->ref_cnt != 0);
		alg_info->ref_cnt--;
		if (alg_info->ref_cnt == 0) {
			alg_info_free(alg_info);
		}
		*alg_info_p = NULL;
	}
}

/* snprint already parsed transform list (alg_info) */
void alg_info_snprint(char *buf, size_t buflen,
		const struct alg_info *alg_info)
{
	char *ptr = buf;
	char *be = buf + buflen;

	passert(buflen > 0);

	switch (alg_info->alg_info_protoid) {
	case PROTO_IPSEC_ESP:
	{
		struct alg_info_esp *alg_info_esp =
			(struct alg_info_esp *)alg_info;
		struct esp_info *esp_info;
		int cnt;

		ALG_INFO_ESP_FOREACH(alg_info_esp, esp_info, cnt) {
			snprintf(ptr, be - ptr, "%s(%d)_%03d-%s(%d)_%03u",
				strip_prefix(enum_name(&esp_transformid_names,
						esp_info->transid),
					"ESP_"),
				esp_info->transid,
				(int)esp_info->enckeylen,
				strip_prefix(strip_prefix(enum_name(&auth_alg_names,
								esp_info->auth),
							"AUTH_ALGORITHM_HMAC_"),
						"AUTH_ALGORITHM_"),
				esp_info->auth,
				(unsigned)esp_info->authkeylen);
			ptr += strlen(ptr);
			if (cnt > 0) {
				snprintf(ptr, be - ptr, ", ");
				ptr += strlen(ptr);
			}
		}
		if (alg_info_esp->esp_pfsgroup != OAKLEY_GROUP_invalid) {
			snprintf(ptr, be - ptr, "; pfsgroup=%s(%d)",
				strip_prefix(enum_name(&oakley_group_names,
						alg_info_esp->esp_pfsgroup),
					"OAKLEY_GROUP_"),
				alg_info_esp->esp_pfsgroup);
			ptr += strlen(ptr);	/* ptr not subsequently used */
		}
		break;
	}

	case PROTO_IPSEC_AH:
	{
		struct alg_info_esp *alg_info_esp =
			(struct alg_info_esp *)alg_info;
		struct esp_info *esp_info;
		int cnt;

		ALG_INFO_ESP_FOREACH(alg_info_esp, esp_info, cnt) {
			snprintf(ptr, be - ptr, "%s(%d)_%03u",
				strip_prefix(strip_prefix(enum_name(&auth_alg_names,
								esp_info->auth),
						"AUTH_ALGORITHM_HMAC_"),
					"AUTH_ALGORITHM_"),
				esp_info->auth,
				(unsigned)esp_info->authkeylen);
			ptr += strlen(ptr);
			if (cnt > 0) {
				snprintf(ptr, be - ptr, ", ");
				ptr += strlen(ptr);
			}
		}
		if (alg_info_esp->esp_pfsgroup != OAKLEY_GROUP_invalid) {
			snprintf(ptr, be - ptr, "; pfsgroup=%s(%d)",
				strip_prefix(enum_name(&oakley_group_names, alg_info_esp->esp_pfsgroup),
				   "OAKLEY_GROUP_"),
				alg_info_esp->esp_pfsgroup);
			ptr += strlen(ptr);	/* ptr not subsequently used */
		}
		break;
	}

	case PROTO_ISAKMP:
	{
		struct alg_info_ike *alg_info_ike =
			(struct alg_info_ike *)alg_info;
		struct ike_info *ike_info;
		int cnt;

		ALG_INFO_IKE_FOREACH(alg_info_ike, ike_info, cnt) {
			snprintf(ptr, be - ptr,
				"%s(%d)_%03d-%s(%d)_%03d-%s(%d)",
				strip_prefix(enum_name(&oakley_enc_names, ike_info->ike_ealg),
					"OAKLEY_"),
				ike_info->ike_ealg,
				(int)ike_info->ike_eklen,
				strip_prefix(enum_name(&oakley_hash_names, ike_info->ike_halg),
					"OAKLEY_"),
				ike_info->ike_halg,
				(int)ike_info->ike_hklen,
				strip_prefix(enum_name(&oakley_group_names, ike_info->ike_modp),
					"OAKLEY_GROUP_"),
				ike_info->ike_modp
				);
			ptr += strlen(ptr);
			if (cnt > 0) {
				snprintf(ptr, be - ptr, ", ");
				ptr += strlen(ptr);
			}
		}
		break;
	}

	default:
		snprintf(buf, be - ptr, "INVALID protoid=%d\n",
			alg_info->alg_info_protoid);
		ptr += strlen(ptr);	/* ptr not subsequently used */
		break;
	}
}
