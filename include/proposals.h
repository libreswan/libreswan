/* Proposals, for libreswan
 *
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2015-2019 Andrew Cagney
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

#ifndef PROPOSALS_H
#define PROPOSALS_H

#include "lswcdefs.h"
#include "constants.h"
#include "ike_alg.h"
#include "shunk.h"

struct alg_info;
struct proposal_protocol;
struct proposal;
struct proposals;
struct proposal_policy;
struct proposal_parser;

/*
 * XXX: needs to be merged with IKE_ALG_TYPE.
 */
enum proposal_algorithm {
	PROPOSAL_encrypt,
	PROPOSAL_prf,
	PROPOSAL_integ,
	PROPOSAL_dh,
	PROPOSAL_ALGORITHM_ROOF,
};

/*
 * Everything combined.
 */
struct proposal_parser {
	const struct proposal_protocol *protocol;
	const struct proposal_param *param;
	const struct proposal_policy *policy;
	/* need to eliminate hardwired size */
	char error[200];
};

/*
 * Parameters to tune the parser.
 */

struct proposal_policy {
	enum ike_version version;
	unsigned parser_version;
	bool pfs; /* For CHILD SA, use DH from IKE SA */
	bool check_pfs_vs_dh;
	/*
	 * According to current policy, is the algorithm ok
	 * (supported)?  If it isn't return FALSE.
	 *
	 * For instance, an IKE algorithm requires in-process support;
	 * while an ESP/AH algorithm requires kernel support.
	 */
	bool (*alg_is_ok)(const struct ike_alg *alg);
	/*
	 * Print a warning.  Signature needs to match libreswan_log.
	 */
	int (*warning)(const char *fmt, ...) PRINTF_LIKE(1);
};

/*
 * Defaults the parser uses to fill things in.
 */

struct proposal_defaults {
	const struct ike_alg **dh;
	const struct ike_alg **prf;
	const struct ike_alg **integ;
	const struct ike_alg **encrypt;
};

/*
 * The protocol - ESP/AH/IKE - the parser is processing.
 */

typedef const struct ike_alg *(alg_byname_fn)(struct proposal_parser *parser,
					      shunk_t name, size_t key_bit_length,
					      shunk_t print_name);

struct proposal_protocol {
	const char *name;
	enum ike_alg_key ikev1_alg_id;

	/*
	 * Lists of defaults for each IKE version.
	 */
	const struct proposal_defaults *defaults[IKE_VERSION_ROOF];

	/*
	 * Is the proposal OK?
	 *
	 * This is the final check, if this succeeds then the proposal
	 * is added.
	 */
	bool (*proposal_ok)(struct proposal_parser *parser,
			    const struct proposal *proposal);

	/*
	 * XXX: Is the proto-id needed?  Parser should be protocol
	 * agnostic.
	 */
	unsigned protoid;

	/*
	 * This lookup functions must set err and return null if NAME
	 * isn't valid.
	 */
	alg_byname_fn *encrypt_alg_byname;
	alg_byname_fn *prf_alg_byname;
	alg_byname_fn *integ_alg_byname;
	alg_byname_fn *dh_alg_byname;
};

/*
 * A proposal as decoded by the parser.
 */

struct algorithm {
	const struct ike_alg *desc;
	/*
	 * Because struct encrypt_desc still specifies multiple key
	 * lengths, ENCKEYLEN is still required.
	 */
	int enckeylen; /* only one! */
	struct algorithm *next;
};

/* return counts of encrypt=aead and integ=none */
bool proposal_encrypt_aead(const struct proposal *proposal);
bool proposal_encrypt_norm(const struct proposal *proposal);
bool proposal_integ_none(const struct proposal *proposal);

unsigned nr_proposals(struct proposals *proposals);

extern void proposals_addref(struct proposals **proposals);
extern void proposals_delref(struct proposals **proposals);

extern struct proposal *alloc_proposal(struct proposal_parser *parser);
extern void free_proposal(struct proposal **proposal);

void free_algorithms(struct proposal *proposal, enum proposal_algorithm algorithm);
void append_proposal(struct proposals *proposals, struct proposal *proposal);
void append_algorithm(struct proposal *proposal, enum proposal_algorithm algorithm,
		      const struct ike_alg *alg, int enckeylen);

struct proposal_parser *alloc_proposal_parser(const struct proposal_policy *policy,
					      const struct proposal_protocol *protocol);
void free_proposal_parser(struct proposal_parser **parser);
struct proposal_parser *ike_proposal_parser(const struct proposal_policy *policy);
struct proposal_parser *esp_proposal_parser(const struct proposal_policy *policy);
struct proposal_parser *ah_proposal_parser(const struct proposal_policy *policy);

/*
 * XXX: useful?
 */
struct ike_proposals {
	struct proposals *p;
};

struct child_proposals {
	struct proposals *p;
};

void fmt_proposal(struct lswlog *log,
		  const struct proposal *proposal);
void fmt_proposals(struct lswlog *log, const struct proposals *proposals);

/*
 * Iterate through all the proposals and the proposal's algorithms.
 *
 * Use __typeof__ instead of const to get around ALG_INFO some times
 * being const and sometimes not.
 */

struct proposal *next_proposal(const struct proposals *proposals,
				     struct proposal *last_proposal);

#define FOR_EACH_PROPOSAL(PROPOSALS, PROPOSAL)				\
	for (struct proposal *PROPOSAL = next_proposal(PROPOSALS, NULL); \
	     PROPOSAL != NULL;						\
	     PROPOSAL = next_proposal(PROPOSALS, PROPOSAL))

struct algorithm *next_algorithm(const struct proposal *proposal,
				 enum proposal_algorithm algorithm,
				 struct algorithm *last);

#define FOR_EACH_ALGORITHM(PROPOSAL, TYPE, ALGORITHM)	\
	for (struct algorithm *ALGORITHM = next_algorithm(PROPOSAL, PROPOSAL_##TYPE, NULL); \
	     ALGORITHM != NULL; ALGORITHM = next_algorithm(PROPOSAL, PROPOSAL_##TYPE, ALGORITHM))

/*
 * Error indicated by err_buf[0] != '\0'.
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

struct proposals *proposals_from_str(struct proposal_parser *parser,
				     const char *str);

bool v1_proposals_parse_str(struct proposal_parser *parser,
			    struct proposals *proposals,
			    shunk_t alg_str);
bool v2_proposals_parse_str(struct proposal_parser *parser,
			    struct proposals *proposals,
			    shunk_t alg_str);

/*
 * Check that encrypt==AEAD and/or integ==none don't contradict.
 */
bool proposal_aead_none_ok(struct proposal_parser *parser,
			   const struct proposal *proposal);

void proposal_error(struct proposal_parser *parser,
		    const char *message, ...) PRINTF_LIKE(2);

bool impair_proposal_errors(struct proposal_parser *parser);

/*
 * Convert a generic proposal back into something the IKEv1 code can
 * digest.
 */
struct v1_proposal {
	int enckeylen;
	const struct encrypt_desc *encrypt;
	const struct prf_desc *prf;
	const struct integ_desc *integ;
	const struct oakley_group_desc *dh;
	const struct proposal_protocol *protocol;
};

struct v1_proposal v1_proposal(const struct proposal *proposal);

#endif /* PROPOSALS_H */
