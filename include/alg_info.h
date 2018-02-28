/* Algorithm info parsing and creation functions
 *
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 Paul Wouters <pwouters@redhat.com>
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

#ifndef ALG_INFO_H
#define ALG_INFO_H

#include "constants.h"
#include "ike_alg.h"

struct parser_context;
struct alg_info;
struct lswlog;
struct parser_protocol;
struct proposal_info;

/*
 * Parameters to tune the parser.
 */

struct parser_policy {
	bool ikev1;
	bool ikev2;
	/*
	 * According to current policy, is the algorithm ok
	 * (supported)?  If it isn't return FALSE.
	 *
	 * For instance, an IKE algorithm requires in-process support;
	 * while an ESP/AH algorithm requires kernel support.
	 */
	bool (*alg_is_ok)(const struct ike_alg *alg);
};

/*
 * Defaults to fill in.
 */

struct proposal_defaults {
	const struct ike_alg **dh;
	const struct ike_alg **prf;
	const struct ike_alg **integ;
	const struct ike_alg **encrypt;
};

/*
 * Parameters to set the parser's basic behaviour - ESP/AH/IKE.
 */

struct parser_protocol {
	const char *name;
	enum ike_alg_key ikev1_alg_id;

	/*
	 * Lists of defaults.
	 */
	const struct proposal_defaults *ikev1_defaults;
	const struct proposal_defaults *ikev2_defaults;

	/*
	 * Is the proposal OK?
	 *
	 * This is the final check, if this succeeds then the proposal
	 * is added.
	 */
	bool (*proposal_ok)(const struct proposal_info *proposal,
			    char *err_buf, size_t err_buf_len);

	/*
	 * XXX: Is the proto-id needed?  Parser should be protocol
	 * agnostic.
	 */
	unsigned protoid;

	/*
	 * This lookup functions must set err and return null if NAME
	 * isn't valid.
	 */
	const struct ike_alg *(*encrypt_alg_byname)(const struct parser_protocol *protocol,
						    const struct parser_policy *const policy,
						    char *err_buf, size_t err_buf_len,
						    const char *name, size_t bit_length);
	const struct ike_alg *(*prf_alg_byname)(const struct parser_protocol *protocol,
						const struct parser_policy *const policy,
						char *err_buf, size_t err_buf_len,
						const char *name, size_t key_bit_length);
	const struct ike_alg *(*integ_alg_byname)(const struct parser_protocol *protocol,
						  const struct parser_policy *const policy,
						  char *err_buf, size_t err_buf_len,
						  const char *name, size_t key_bit_length);
	const struct ike_alg *(*dh_alg_byname)(const struct parser_protocol *protocol,
					       const struct parser_policy *const policy,
					       char *err_buf, size_t err_buf_len,
					       const char *name, size_t key_bit_length);
};

/*
 * A proposal as decoded by the parser.
 */

struct proposal_info {
	/*
	 * The encryption algorithm and key length.
	 *
	 * Because struct encrypt_desc still specifies multiple key
	 * lengths, ENCKEYLEN is still required.
	 */
	const struct encrypt_desc *encrypt;
	size_t enckeylen;    /* keylength for ESP transform (bits) */
	/*
	 * The integrity and PRF algorithms.
	 */
	const struct prf_desc *prf;
	const struct integ_desc *integ;
	/*
	 * PFS/DH negotiation.
	 */
	const struct oakley_group_desc *dh;
	/*
	 * Which protocol is this proposal intended for?
	 */
	const struct parser_protocol *protocol;
};

/* common prefix of struct alg_info_esp and struct alg_info_ike */
struct alg_info {
	int alg_info_cnt;
	int ref_cnt;
	struct proposal_info proposals[128];
};

struct alg_info_esp {
	struct alg_info ai;	/* common prefix */
	const struct oakley_group_desc *esp_pfsgroup;
};

struct alg_info_ike {
	struct alg_info ai;	/* common prefix */
};

extern void alg_info_free(struct alg_info *alg_info);
extern void alg_info_addref(struct alg_info *alg_info);
extern void alg_info_delref(struct alg_info *alg_info);

extern struct alg_info_ike *alg_info_ike_create_from_str(const struct parser_policy *policy,
							 const char *alg_str,
							 char *err_buf, size_t err_buf_len);

extern struct alg_info_esp *alg_info_esp_create_from_str(const struct parser_policy *policy,
							 const char *alg_str,
							 char *err_buf, size_t err_buf_len);

extern struct alg_info_esp *alg_info_ah_create_from_str(const struct parser_policy *policy,
							const char *alg_str,
							char *err_buf, size_t err_buf_len);

size_t lswlog_proposal_info(struct lswlog *log, const struct proposal_info *proposal);
size_t lswlog_alg_info(struct lswlog *log, const struct alg_info *alg_info);

/*
 * Iterate through the elements of an ESP or IKE table.
 *
 * Use __typeof__ instead of const to get around ALG_INFO some times
 * being const and sometimes not.
 *
 * XXX: yes, they are the same!
 */

#define FOR_EACH_PROPOSAL_INFO(ALG_INFO, PROPOSAL_INFO)			\
	for (__typeof__((ALG_INFO)->proposals[0]) *(PROPOSAL_INFO) = (ALG_INFO)->proposals; \
	     (PROPOSAL_INFO) < (ALG_INFO)->proposals + (ALG_INFO)->alg_info_cnt; \
	     (PROPOSAL_INFO)++)

#define FOR_EACH_ESP_INFO(ALG_INFO, ESP_INFO)		\
	FOR_EACH_PROPOSAL_INFO(&((ALG_INFO)->ai), ESP_INFO)

#define FOR_EACH_IKE_INFO(ALG_INFO, IKE_INFO)		\
	FOR_EACH_PROPOSAL_INFO(&((ALG_INFO)->ai), IKE_INFO)

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
 * IKEv2 is a program error.  The IKEv2 should complain loudly and,
 * we hope, not crash.
 *
 * Parsing with POLICY='0' is allowed. It will accept the algorithms
 * unconditionally (spi.c seems to need this).
 */
struct alg_info *alg_info_parse_str(const struct parser_policy *policy,
				    struct alg_info *alg_info,
				    const char *alg_str,
				    char *err_buf, size_t err_buf_len,
				    const struct parser_protocol *protocol);

/*
 * Check that encrypt==AEAD and/or integ==none don't contradict.
 */
bool proposal_aead_none_ok(const struct proposal_info *proposal,
			   char *err_buf, size_t err_buf_len);

struct alg_info_esp *alg_info_discover_pfsgroup_hack(struct alg_info_esp *aie,
						     const char *alg_str,
						     char *err_buf, size_t err_buf_len);

bool alg_unimpaired(char *err);

#endif /* ALG_INFO_H */
