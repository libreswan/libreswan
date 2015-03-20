/* Algorithm info parsing and creation functions
 *
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 Paul Wouters <pwouters@redhat.com>
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

#ifndef ALG_INFO_H
#define ALG_INFO_H

#include "constants.h"

/*
 *	Creates a new alg_info by parsing passed string
 */
enum parser_state_esp {
	ST_INI,         /* parse esp= string */
	ST_INI_AA,      /* parse ah= string */
	ST_EA,          /* encrypt algo   */
	ST_EA_END,
	ST_EK,          /* enc. key length */
	ST_EK_END,
	ST_AA,          /* auth algo */
	ST_AA_END,
	ST_AK,          /* auth. key length */
	ST_AK_END,
	ST_MODP,        /* modp spec */
	ST_END,
	ST_EOF,
	ST_ERR
};

/* XXX:jjo to implement different parser for ESP and IKE */
struct parser_context {
	unsigned state, old_state;
	unsigned protoid;
	char ealg_buf[16];
	char aalg_buf[16];
	char modp_buf[16];
	int (*ealg_getbyname)(const char *const str, int len);
	int (*aalg_getbyname)(const char *const str, int len);
	int (*modp_getbyname)(const char *const str, int len);
	char *ealg_str;
	char *aalg_str;
	char *modp_str;
	int eklen;
	int aklen;
	bool ealg_permit;
	bool aalg_permit;
	int ch;
	const char *err;
};

struct esp_info {
	bool esp_default;
	u_int8_t transid;       /* ESP transform (AES, 3DES, etc.)*/
	u_int16_t auth;         /* AUTH */
	u_int32_t enckeylen;    /* keylength for ESP transform (bytes)*/
	u_int32_t authkeylen;   /* keylength for AUTH (bytes)*/
	u_int8_t encryptalg;    /* normally  encryptalg=transid */
	u_int16_t authalg;      /* normally  authalg=auth+1
	                         * Paul: apparently related to magic at
	                         * lib/libswan/alg_info.c alg_info_esp_aa2sadb() */
};

struct ike_info {
	bool ike_default;
	u_int16_t ike_ealg;             /* encrytion algorithm - bit 15set for reserved*/
	u_int8_t ike_halg;              /* hash algorithm */
	size_t ike_eklen;               /* how many bits required by encryption algo */
	size_t ike_hklen;               /* how many bits required by hash algo */
	oakley_group_t ike_modp;        /* which modp group to use */
};

#define ALG_INFO_COMMON \
	int alg_info_cnt;               \
	int ref_cnt;                    \
	unsigned alg_info_protoid

struct alg_info {
	ALG_INFO_COMMON;
};

struct alg_info_esp {
	ALG_INFO_COMMON;
	struct esp_info esp[128];
	int esp_pfsgroup;
};

struct alg_info_ike {
	ALG_INFO_COMMON;
	struct ike_info ike[128];
};

#define ESPTOINFO(X) (struct alg_info *)X
#define IKETOINFO(X) (struct alg_info *)X

#define esp_ealg_id transid
#define esp_aalg_id auth
#define esp_ealg_keylen enckeylen       /* bits */
#define esp_aalg_keylen authkeylen      /* bits */

extern enum ipsec_authentication_algo alg_info_esp_aa2sadb(
	enum ikev1_auth_attribute auth);
extern int alg_info_esp_sadb2aa(int sadb_aalg);
extern enum ikev1_auth_attribute alg_info_esp_v2tov1aa(enum ikev2_trans_type_integ ti);

extern void alg_info_free(struct alg_info *alg_info);
extern void alg_info_addref(struct alg_info *alg_info);
extern void alg_info_delref(struct alg_info **alg_info);

extern struct alg_info_esp * alg_info_esp_create_from_str(const char *alg_str,
						   err_t *err_p);

extern struct alg_info_esp * alg_info_ah_create_from_str(const char *alg_str,
						  err_t *err_p);

extern int alg_info_parse(const char *str);
extern int alg_info_snprint(char *buf, int buflen,
		     struct alg_info *alg_info);

extern void alg_info_snprint_ike(char *buf, size_t buflen,
			  struct alg_info_ike *alg_info);
#define ALG_INFO_ESP_FOREACH(ai, ai_esp, i) \
	for (i = (ai)->alg_info_cnt, ai_esp = (ai)->esp; i--; ai_esp++)
#define ALG_INFO_IKE_FOREACH(ai, ai_ike, i) \
	for (i = (ai)->alg_info_cnt, ai_ike = (ai)->ike; i--; ai_ike++)

extern int alg_enum_search_prefix(enum_names *ed, const char *prefix,
				  const char *str, int str_len);
extern int alg_enum_search_ppfix(enum_names *ed, const char *prefix,
				 const char *postfix, const char *str,
				 int str_len);

struct parser_context;	/* so it isn't local to the function prototype */
struct oakley_group_desc;	/* so it isn't local to the function prototype */

extern int alg_info_parse_str(struct alg_info *alg_info,
			      const char *alg_str,
			      const char **err_p,
			      void (*parser_init)(
				      struct parser_context *p_ctx),
			      void (*alg_info_add)(struct alg_info *alg_info,
						   int ealg_id, int ek_bits,
						   int aalg_id, int ak_bits,
						   int modp_id),
			      const struct oakley_group_desc *(*lookup_group_f)(
				      u_int16_t group));

#endif /* ALG_INFO_H */
