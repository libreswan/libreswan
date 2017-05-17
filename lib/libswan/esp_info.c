/*
 * Algorithm info parsing and creation functions
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 *
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2015-2016 Andrew Cagney <cagney@gnu.org>
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
#include <stdint.h>
#include <limits.h>

#include "constants.h"  /* some how sucks in u_int8_t for pfkeyv2.h */
#include "libreswan/pfkeyv2.h"
#include "lswalloc.h"
#include "lswlog.h"
#include "alg_info.h"
#include "ike_alg.h"
#include "kernel_alg.h"
#include "lswfips.h"

/*
 * Search esp_transformid_names for a match, eg:
 *	"3des" <=> "ESP_3DES"
 */
static int ealg_getbyname_esp(const char *const str)
{
	if (str == NULL || *str == '\0')
		return -1;

	return alg_enum_search(&esp_transformid_names, "ESP_", "", str);
}

/*
 * Search auth_alg_names for a match, eg:
 *	"md5" <=> "AUTH_ALGORITHM_HMAC_MD5"
 */
static int aalg_getbyname_esp(const char *str)
{
	int ret = -1;
	static const char null_esp[] = "null";

	if (str == NULL || *str == '\0')
		return -1;

	ret = alg_enum_search(&auth_alg_names, "AUTH_ALGORITHM_HMAC_", "", str);
	if (ret >= 0)
		return ret;
	ret = alg_enum_search(&auth_alg_names, "AUTH_ALGORITHM_", "", str);
	if (ret >= 0)
		return ret;

	/*
	 * INT_MAX is used as the special value for "no authentication"
	 * since 0 is already used.
	 * ??? this is extremely ugly.
	 */
	if (strcaseeq(str, null_esp))
		return INT_MAX;

	return ret;
}

static int modp_getbyname_esp(const char *const str)
{
	int ret = alg_enum_search(&oakley_group_names, "OAKLEY_GROUP_", "", str);

	if (ret < 0)
		ret = alg_enum_search(&oakley_group_names, "OAKLEY_GROUP_",
				      " (extension)", str);
	return ret;
}

/*
 * Raw add routine: only checks for no duplicates
 */
/* ??? much of this code is the same as raw_alg_info_ike_add (same bugs!) */
static void raw_alg_info_esp_add(struct alg_info_esp *alg_info,
				int ealg_id, unsigned ek_bits,
				int aalg_id)
{
	struct esp_info *esp_info = alg_info->esp;
	int cnt = alg_info->ai.alg_info_cnt;
	int i;

	/* don't add duplicates */
	/* ??? why is 0 wildcard for ek_bits and ak_bits? */
	for (i = 0; i < cnt; i++) {
		if (esp_info[i].transid == ealg_id &&
		    (ek_bits == 0 || esp_info[i].enckeylen == ek_bits) &&
		    esp_info[i].auth == aalg_id)
			return;
	}

	/* check for overflows */
	/* ??? passert seems dangerous */
	passert(cnt < (int)elemsof(alg_info->esp));

	esp_info[cnt].transid = ealg_id;
	esp_info[cnt].enckeylen = ek_bits;
	esp_info[cnt].auth = aalg_id;

	/* sadb values */
	esp_info[cnt].encryptalg = ealg_id;
	esp_info[cnt].authalg = alg_info_esp_aa2sadb(aalg_id);
	alg_info->ai.alg_info_cnt++;
}

/*
 * Add ESP alg info _with_ logic (policy):
 */
static const char *alg_info_esp_add(const struct parser_policy *const policy UNUSED,
				    struct alg_info *alg_info,
				    const struct encrypt_desc *encrypt UNUSED,
				    int ealg_id, int ek_bits,
				    int aalg_id,
				    const struct prf_desc *prf UNUSED,
				    const struct integ_desc *integ UNUSED,
				    const struct oakley_group_desc *dh_group UNUSED,
				    char *err_buf UNUSED, size_t err_buf_len UNUSED)
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
					aalg_id);
		} else {
			/*
			 * Policy: default to MD5 and SHA1
			 *
			 * XXX: this should use the ike_alg DB and
			 * code like plutoalg.c:clone_valid() to
			 * select the default algorithm list.
			 *
			 * XXX: this adds INTEG to AEAD algorithms;
			 * the IKE_ALG DB can be used to identify when
			 * this is the case
			 */
			if (!libreswan_fipsmode()) {
				raw_alg_info_esp_add((struct alg_info_esp *)alg_info,
						     ealg_id, ek_bits,
						     AUTH_ALGORITHM_HMAC_MD5);
			}
			raw_alg_info_esp_add((struct alg_info_esp *)alg_info,
					ealg_id, ek_bits,
					AUTH_ALGORITHM_HMAC_SHA1);
		}
	}
	return NULL;
}

/*
 * Add AH alg info _with_ logic (policy):
 */
static const char *alg_info_ah_add(const struct parser_policy *const policy UNUSED,
				   struct alg_info *alg_info,
				   const struct encrypt_desc *encrypt UNUSED,
				   int ealg_id, int ek_bits,
				   int aalg_id,
				   const struct prf_desc *prf UNUSED,
				   const struct integ_desc *integ UNUSED,
				   const struct oakley_group_desc *dh_group UNUSED,
				   char *err_buf UNUSED, size_t err_buf_len UNUSED)
{
	/* ah=null is invalid */
	if (aalg_id > 0) {
		raw_alg_info_esp_add((struct alg_info_esp *)alg_info,
				ealg_id, ek_bits,
				aalg_id);
	} else {
		/*
		 * Policy: default to MD5 and SHA1
		 *
		 * XXX: this should use the IKE_ALG DB and code like
		 * plutoalg.c:clone_valid() to select the default
		 * algorithm list.
		 */
		if (!libreswan_fipsmode()) {
			raw_alg_info_esp_add((struct alg_info_esp *)alg_info,
					     ealg_id, ek_bits,
					     AUTH_ALGORITHM_HMAC_MD5);
		}
		raw_alg_info_esp_add((struct alg_info_esp *)alg_info,
				ealg_id, ek_bits,
				AUTH_ALGORITHM_HMAC_SHA1);
	}
	return NULL;
}

const struct parser_param esp_parser_param = {
	.protocol = "ESP",
	.ikev1_alg_id = IKEv1_ESP_ID,
	.protoid = PROTO_IPSEC_ESP,
	.alg_info_add = alg_info_esp_add,
	.ealg_getbyname = ealg_getbyname_esp,
	.aalg_getbyname = aalg_getbyname_esp,
};

const struct parser_param ah_parser_param = {
	.protocol = "AH",
	.ikev1_alg_id = IKEv1_ESP_ID,
	.protoid = PROTO_IPSEC_AH,
	.alg_info_add = alg_info_ah_add,
	.aalg_getbyname = aalg_getbyname_esp,
};

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
			int ret = modp_getbyname_esp(pfs_name);

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
struct alg_info_esp *alg_info_esp_create_from_str(lset_t policy,
						  const char *alg_str,
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
		alg_info_parse_str(policy,
				   &alg_info_esp->ai,
				   esp_buf,
				   err_buf, err_buf_len,
				   &esp_parser_param);
}

/* This function is tested in testing/lib/libswan/algparse.c */
/* ??? why is this called _ah_ when almost everything refers to esp? */
/* ??? the only difference between this and alg_info_esp is in two parameters to alg_info_parse_str */
struct alg_info_esp *alg_info_ah_create_from_str(lset_t policy,
						 const char *alg_str,
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
		alg_info_parse_str(policy,
				   &alg_info_esp->ai,
				   esp_buf,
				   err_buf, err_buf_len,
				   &ah_parser_param);
}

/* snprint already parsed transform list (alg_info) */
void alg_info_esp_snprint(char *buf, size_t buflen,
			  const struct alg_info_esp *alg_info_esp)
{
	char *ptr = buf;
	char *be = buf + buflen;

	passert(buflen > 0);

	switch (alg_info_esp->ai.alg_info_protoid) {
	case PROTO_IPSEC_ESP:
	{
		const char *sep = "";
		FOR_EACH_ESP_INFO(alg_info_esp, esp_info) {
			snprintf(ptr, be - ptr,
				 "%s%s(%d)_%03d-%s(%d)", sep,
				 enum_short_name(&esp_transformid_names,
						 esp_info->transid),
				 esp_info->transid,
				 (int)esp_info->enckeylen,
				 strip_prefix(enum_short_name(&auth_alg_names,
							      esp_info->auth),
					      "HMAC_"),
				 esp_info->auth);
			ptr += strlen(ptr);
			sep = ", ";
		}
		if (alg_info_esp->esp_pfsgroup != OAKLEY_GROUP_invalid) {
			snprintf(ptr, be - ptr, "; pfsgroup=%s(%d)",
				enum_short_name(&oakley_group_names,
						alg_info_esp->esp_pfsgroup),
				alg_info_esp->esp_pfsgroup);
			ptr += strlen(ptr);	/* ptr not subsequently used */
		}
		break;
	}

	case PROTO_IPSEC_AH:
	{
		const char *sep = "";
		FOR_EACH_ESP_INFO(alg_info_esp, esp_info) {
			snprintf(ptr, be - ptr,
				 "%s%s(%d)", sep,
				 strip_prefix(enum_short_name(&auth_alg_names,
							      esp_info->auth),
					      "HMAC_"),
				 esp_info->auth);
			ptr += strlen(ptr);
			sep = ", ";
		}
		if (alg_info_esp->esp_pfsgroup != OAKLEY_GROUP_invalid) {
			snprintf(ptr, be - ptr, "; pfsgroup=%s(%d)",
				enum_short_name(&oakley_group_names, alg_info_esp->esp_pfsgroup),
				alg_info_esp->esp_pfsgroup);
			ptr += strlen(ptr);	/* ptr not subsequently used */
		}
		break;
	}

	default:
		snprintf(buf, be - ptr, "INVALID protoid=%d\n",
			alg_info_esp->ai.alg_info_protoid);
		ptr += strlen(ptr);	/* ptr not subsequently used */
		break;
	}
}

static int snprint_esp_info(char *ptr, size_t buflen, const char *sep,
			    const struct esp_info *esp_info)
{
	unsigned eklen = esp_info->enckeylen;

	return snprintf(ptr, buflen, "%s%s(%d)_%03d-%s(%d)",
			sep,
			enum_short_name(&esp_transformid_names,
					       esp_info->transid),
			esp_info->transid, eklen,
			strip_prefix(enum_short_name(&auth_alg_names,
						esp_info->auth),
				"HMAC_"),
			esp_info->auth);
}

void alg_info_snprint_esp_info(char *buf, size_t buflen,
			       const struct esp_info *esp_info)
{
	snprint_esp_info(buf, buflen, "", esp_info);
}

/*
 * print which ESP algorithm has actually been selected, based upon which
 * ones are actually loaded.
 */
static void alg_info_snprint_esp(char *buf, size_t buflen,
				 struct alg_info_esp *alg_info)
{
	if (alg_info == NULL) {
		PEXPECT_LOG("%s", "parameter alg_info unexpectedly NULL");
		/* return some bogus output */
		snprintf(buf, buflen,
			 "OOPS, parameter alg_info unexpectedly NULL");
		return;
	}

	char *ptr = buf;
	const char *sep = "";

	passert(buflen >= sizeof("none"));

	jam_str(buf, buflen, "none");

	FOR_EACH_ESP_INFO(alg_info, esp_info) {
		err_t ugh = check_kernel_encrypt_alg(esp_info->transid, 0);

		if (ugh != NULL) {
			DBG_log("esp algid=%d not available: %s",
				esp_info->transid, ugh);
			continue;
		}

		if (!kernel_alg_esp_auth_ok(esp_info->auth, NULL)) {
			DBG_log("auth algid=%d not available",
				esp_info->auth);
			continue;
		}

		int ret = snprint_esp_info(ptr, buflen, sep, esp_info);

		if (ret < 0 || (size_t)ret >= buflen) {
			DBG_log("alg_info_snprint_esp: buffer too short for snprintf");
			break;
		}
		ptr += ret;
		buflen -= ret;
		sep = ", ";
	}
}

/*
 * print which AH algorithm has actually been selected, based upon which
 * ones are actually loaded.
 */
static void alg_info_snprint_ah(char *buf, size_t buflen,
				struct alg_info_esp *alg_info)
{
	if (alg_info == NULL) {
		PEXPECT_LOG("%s", "parameter alg_info unexpectedly NULL");
		/* return some bogus output */
		snprintf(buf, buflen,
			 "OOPS, parameter alg_info unexpectedly NULL");
		return;
	}

	char *ptr = buf;
	const char *sep = "";

	passert(buflen >= sizeof("none"));
	jam_str(buf, buflen, "none");

	FOR_EACH_ESP_INFO(alg_info, esp_info) {
		if (!kernel_alg_esp_auth_ok(esp_info->auth, NULL)) {
			DBG_log("auth algid=%d not available",
				esp_info->auth);
			continue;
		}

		int ret = snprintf(ptr, buflen, "%s%s(%d)",
			       sep,
			       strip_prefix(enum_name(&auth_alg_names,
							esp_info->auth),
					"HMAC_"),
			       esp_info->auth);

		if (ret < 0 || (size_t)ret >= buflen) {
			DBG_log("alg_info_snprint_ah: buffer too short for snprintf");
			break;
		}
		ptr += ret;
		buflen -= ret;
		sep = ", ";
	}
}

void alg_info_snprint_phase2(char *buf, size_t buflen,
			     struct alg_info_esp *alg_info)
{
	switch (alg_info->ai.alg_info_protoid) {
	case PROTO_IPSEC_ESP:
		alg_info_snprint_esp(buf, buflen, alg_info);
		break;

	case PROTO_IPSEC_AH:
		alg_info_snprint_ah(buf, buflen, alg_info);
		break;

	default:
		bad_case(alg_info->ai.alg_info_protoid);
	}
}
