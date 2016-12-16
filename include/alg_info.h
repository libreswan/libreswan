/* Algorithm info parsing and creation functions
 *
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2015-2016 Andrew Cagney <andrew.cagney@gmail.com>
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
 * Parameters to tune the parser.
 */
struct parser_context;
struct alg_info;
struct oakley_group_desc;

struct parser_policy {
	bool ikev1;
	bool ikev2;
};

struct parser_param {
	unsigned protoid;
	void (*parser_init)(struct parser_context *p_ctx);
	void (*alg_info_add)(const struct parser_policy *const policy,
			     struct alg_info *alg_info,
			     int ealg_id, int ek_bits,
			     int aalg_id,
			     int modp_id);
	const struct oakley_group_desc *(*group_byname)(const struct parser_policy *const policy,
							char *err_buf, size_t err_buf_len,
							const char *name);
};

/*
 *	Creates a new alg_info by parsing passed string
 */
enum parser_state {
	ST_INI,         /* parse esp= string */
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
	unsigned state, old_state;
	const struct parser_param *param;
	struct parser_policy policy;
	char ealg_buf[16];
	char aalg_buf[16];
	char modp_buf[16];
	int (*ealg_getbyname)(const char *const str);
	int (*aalg_getbyname)(const char *const str);
	char *ealg_str;
	char *aalg_str;
	char *modp_str;
	int eklen;
	bool ealg_permit;
	bool aalg_permit;
	int ch;	/* character that stopped parsing */
};

struct esp_info {
	/*
	 * The encryption algorithm and key length; if required by
	 * ESP.
	 *
	 * Because struct encrypt_desc still specifies multiple key
	 * lengths, ENCKEYLEN is still required.
	 */
	const struct encrypt_desc *esp_encrypt;
	u_int8_t transid;       /* enum ipsec_cipher_algo: ESP transform (AES, 3DES, etc.)*/
	u_int32_t enckeylen;    /* keylength for ESP transform (bytes) */
	/*
	 * The authentication algorithm; if required by ESP/AH.
	 */
	const struct integ_desc *esp_integ;
	u_int16_t auth;         /* enum ikev1_auth_attribute: AUTH */
	/*
	 * The above mapped onto SADB/KLIPS/PFKEYv2 equivalent and
	 * used by the kernel backends.
	 */
	u_int8_t encryptalg;    /* enum sadb_ealg: normally  encryptalg=transid */
	u_int16_t authalg;	/* enum sadb_aalg: normally  authalg=auth+1
				 * Paul: apparently related to magic at
				 * lib/libswan/alg_info.c alg_info_esp_aa2sadb()
				 */
};

struct ike_info {
	/*
	 * Encryption.
	 *
	 * Because struct encrypt_desc still specifies multiple key
	 * lengths, ENCKEYLEN is still required.
	 */
	const struct encrypt_desc *ike_encrypt;
	size_t ike_eklen;               /* how many bits required by encryption algo */
	/*
	 * Integrity and PRF.
	 */
	const struct prf_desc *ike_prf;
	const struct integ_desc *ike_integ;
	/*
	 * DH Group
	 */
	const struct oakley_group_desc *ike_dh_group;
};

/* common prefix of struct alg_info_esp and struct alg_info_ike */
struct alg_info {
	int alg_info_cnt;
	int ref_cnt;
	unsigned alg_info_protoid;
};

struct alg_info_esp {
	struct alg_info ai;	/* common prefix */
	struct esp_info esp[128];
	enum ike_trans_type_dh esp_pfsgroup;
};

struct alg_info_ike {
	struct alg_info ai;	/* common prefix */
	struct ike_info ike[128];
};

extern enum ipsec_authentication_algo alg_info_esp_aa2sadb(
	enum ikev1_auth_attribute auth);
extern int alg_info_esp_sadb2aa(int sadb_aalg);

extern void alg_info_free(struct alg_info *alg_info);
extern void alg_info_addref(struct alg_info *alg_info);
extern void alg_info_delref(struct alg_info *alg_info);

extern struct alg_info_esp *alg_info_esp_create_from_str(lset_t policy,
							 const char *alg_str,
							 char *err_buf, size_t err_buf_len);

extern struct alg_info_esp *alg_info_ah_create_from_str(lset_t policy,
							const char *alg_str,
							char *err_buf, size_t err_buf_len);

void alg_info_ike_snprint(char *buf, size_t buflen,
			  const struct alg_info_ike *alg_info_ike);
void alg_info_esp_snprint(char *buf, size_t buflen,
			  const struct alg_info_esp *alg_info_esp);

extern void alg_info_snprint_ike(char *buf, size_t buflen,
			  struct alg_info_ike *alg_info);

void alg_info_snprint_ike_info(char *buf, size_t buflen,
			       struct ike_info *alg_info);

void alg_info_snprint_esp_info(char *buf, size_t buflen,
			       const struct esp_info *esp_info);
void alg_info_snprint_phase2(char *buf, size_t buflen,
			     struct alg_info_esp *alg_info);

/*
 * Iterate through the elements of an ESP or IKE table.
 *
 * Use __typeof__ instead of const to get around ALG_INFO some times
 * being const and sometimes not.
 */

#define FOR_EACH_ESP_INFO(ALG_INFO, ESP_INFO)				\
	for (__typeof__((ALG_INFO)->esp[0]) *(ESP_INFO) = (ALG_INFO)->esp; \
	     (ESP_INFO) < (ALG_INFO)->esp + (ALG_INFO)->ai.alg_info_cnt; \
	     (ESP_INFO)++)

#define FOR_EACH_IKE_INFO(ALG_INFO, IKE_INFO)				\
	for (__typeof__((ALG_INFO)->ike[0]) *(IKE_INFO) = (ALG_INFO)->ike; \
	     (IKE_INFO) < (ALG_INFO)->ike + (ALG_INFO)->ai.alg_info_cnt; \
	     (IKE_INFO)++)

extern int alg_enum_search(enum_names *ed, const char *prefix,
			   const char *postfix, const char *name);

struct oakley_group_desc;	/* so it isn't local to the function prototype */

extern const struct parser_context empty_p_ctx;	/* full of zeros and NULLs */

/*
 * on success: returns alg_info
 * on failure: pfree(alg_info) and return NULL;
 *
 * POLICY should be used to guard algorithm supported checks.  For
 * instance: if POLICY=IKEV1, then IKEv1 support is required (IKEv2 is
 * don't care); and if POLICY=IKEV1|IKEV2, then both IKEv1 and IKEv2
 * support is required.
 *
 * Parsing with POLICY=IKEV1, but then proposing the result using
 * IKEv2 is a program error.  The IKEv2 sould complain loudly and
 * hopefully not crash.
 *
 * Parsing with POLICY='0' is allowed. It will accept the algorithms
 * unconditionally (spi.c seems to need this).
 */
struct alg_info *alg_info_parse_str(lset_t policy,
				    struct alg_info *alg_info,
				    const char *alg_str,
				    char *err_buf, size_t err_buf_len,
				    const struct parser_param *param);

#endif /* ALG_INFO_H */
