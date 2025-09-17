/* Proposals, for libreswan
 *
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 Paul Wouters <pwouters@redhat.com>
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

#ifndef PROPOSALS_H
#define PROPOSALS_H

/*
 * XXX: rename v[23]_proposal to proposal_v[12].
 */

#include "lswcdefs.h"
#include "constants.h"
#include "ike_alg.h"
#include "shunk.h"
#include "diag.h"
#include "fips_mode.h"

struct jambuf;
struct alg_info;
struct proposal_protocol;
struct proposal;
struct proposals;
struct proposal_policy;
struct proposal_parser;
enum stream;

/*
 * Can this be merged with IKEv2's transform type?
 */
enum proposal_transform {
#define PROPOSAL_TRANSFORM_FLOOR (PROPOSAL_TRANSFORM_encrypt)
	PROPOSAL_TRANSFORM_encrypt,
	PROPOSAL_TRANSFORM_prf,
	PROPOSAL_TRANSFORM_integ,
	PROPOSAL_TRANSFORM_kem,
	PROPOSAL_TRANSFORM_sn,
	PROPOSAL_TRANSFORM_addke1,
	PROPOSAL_TRANSFORM_addke2,
	PROPOSAL_TRANSFORM_addke3,
	PROPOSAL_TRANSFORM_addke4,
	PROPOSAL_TRANSFORM_addke5,
	PROPOSAL_TRANSFORM_addke6,
	PROPOSAL_TRANSFORM_addke7,
#define PROPOSAL_TRANSFORM_ROOF (PROPOSAL_TRANSFORM_addke7+1)
};

extern const struct enum_names proposal_transform_names;
/* map transform onto its type */
extern const struct ike_alg_type *proposal_transform_type[PROPOSAL_TRANSFORM_ROOF];

/*
 * Everything combined.
 */
struct proposal_parser {
	const struct proposal_protocol *protocol;
	const struct proposal_param *param;
	const struct proposal_policy *policy;
	diag_t diag;
};

/*
 * Parameters to tune the parser.
 */

struct proposal_policy {
	enum ike_version version;
	bool pfs; /* For CHILD SA, use DH from IKE SA */
	bool addke;	/* allow ADDKE* algorithms */
	bool check_pfs_vs_ke;

	/*
	 * Ignore (but log) when an algorithm lookup fails.
	 *
	 * For instance, an algorithm may be compiled out, or FIPS may
	 * have stripped an algorithm.
	 */
	bool ignore_transform_lookup_error;

	/*
	 * According to current policy, is the algorithm ok
	 * (supported)?  If it isn't return FALSE.
	 *
	 * For instance, an IKE algorithm requires in-process support;
	 * while an ESP/AH algorithm requires kernel support.
	 */
	bool (*alg_is_ok)(const struct ike_alg *alg, const struct logger *logger);
	/*
	 * logging context
	 */
	const struct logger *logger;
	enum stream stream;
};

/*
 * Defaults the parser uses to fill things in.
 */

struct proposal_defaults {
	/*
	 * Proposals to parse when the parser is called with a NULL
	 * proposals string.
	 *
	 * Code needs FIPS and non-FIPS variants.
	 */
	const char *proposals[FIPS_MODE_ROOF];
	/*
	 * Algorithms to add to the proposal when they were not
	 * specified by the proposal string.
	 */
	const struct ike_alg **transform[PROPOSAL_TRANSFORM_ROOF];
};

/*
 * The protocol - ESP/AH/IKE - the parser is processing.
 */

typedef const struct ike_alg *(alg_byname_fn)(struct proposal_parser *parser,
					      shunk_t name, size_t key_bit_length,
					      shunk_t print_name);

struct proposal_protocol {
	const char *name;
	enum ike_alg_key alg_id;
	const struct proposal_defaults *defaults;

	/*
	 * Is the proposal OK?
	 *
	 * This is the final check, if this succeeds then the proposal
	 * is added.
	 */
	bool (*proposal_ok)(struct proposal_parser *parser,
			    const struct proposal *proposal);

	/*
	 * What algorithms are expected?
	 */
	bool encrypt;
	bool prf;
	bool integ;
	bool kem;
};

/*
 * A proposal as decoded by the parser.
 */

struct transform_algorithm {
	const struct ike_alg *desc;
	/*
	 * Because struct encrypt_desc still specifies multiple key
	 * lengths, ENCKEYLEN is still required.
	 */
	int enckeylen; /* only one! */
};

struct transform_algorithms {
	unsigned len;
	struct transform_algorithm item[];
};

/* return counts of encrypt=aead and integ=none */
bool proposal_encrypt_aead(const struct proposal *proposal);
bool proposal_encrypt_norm(const struct proposal *proposal);
bool proposal_integ_none(const struct proposal *proposal);

unsigned nr_proposals(const struct proposals *proposals);
bool default_proposals(const struct proposals *proposals);

void free_proposals(struct proposals **proposals);

extern struct proposal *alloc_proposal(const struct proposal_parser *parser);
extern void free_proposal(struct proposal **proposal);

void free_algorithms(struct proposal *proposal, enum proposal_transform algorithm);
void append_proposal(struct proposals *proposals, struct proposal **proposal);
void append_proposal_transform(struct proposal_parser *parser,
			       struct proposal *proposal,
			       enum proposal_transform transform,
			       const struct ike_alg *alg,
			       int enckeylen);
void remove_duplicate_algorithms(struct proposal_parser *parser,
				 struct proposal *proposal,
				 enum proposal_transform algorithm);

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

void jam_proposal(struct jambuf *log,
		  const struct proposal *proposal);
void jam_proposals(struct jambuf *log, const struct proposals *proposals);

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

/* the first algorithm, or NULL */
struct transform_algorithm *first_transform_algorithm(const struct proposal *proposal,
						      enum proposal_transform transform);
struct transform_algorithms *transform_algorithms(const struct proposal *proposal,
						  enum proposal_transform transform);

#define FOR_EACH_ALGORITHM(PROPOSAL, TYPE, ALGORITHM)			\
	ITEMS_FOR_EACH(ALGORITHM, transform_algorithms(PROPOSAL, PROPOSAL_TRANSFORM_##TYPE))

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
 * Post parsing checks that the proposal is ok (yea *_ok() is a pretty
 * lame naming schema).
 */

/* encrypt==AEAD and/or integ==none are consistent */
bool proposal_aead_none_ok(struct proposal_parser *parser,
			   const struct proposal *proposal);

/* proposal has at least one expected transform */
bool proposal_transform_ok(struct proposal_parser *parser,
			   const struct proposal *proposal,
			   enum proposal_transform transform,
			   bool expected);

/*
 * Record a proposal error.
 *
 * XXX: now that there's diag_t, perhaps this can be replaced?
 */

void proposal_error(struct proposal_parser *parser,
		    const char *message, ...) PRINTF_LIKE(2);

/*
 * Convert a generic proposal back into something the IKEv1 code can
 * digest.
 */
struct v1_proposal {
	int enckeylen;
	const struct encrypt_desc *encrypt;
	const struct prf_desc *prf;
	const struct integ_desc *integ;
	const struct kem_desc *kem;
	const struct proposal_protocol *protocol;
};

struct v1_proposal v1_proposal(const struct proposal *proposal);

/*
 * INTERNAL: tokenize <input> into <delim_before><current><delim_after><input>
 */

struct proposal_term {
	shunk_t token;
	char delim;
};

struct proposal_tokenizer {
	struct proposal_term prev;
	struct proposal_term curr;
	struct proposal_term next;
	shunk_t input;
	const char *delims;
};

struct proposal_tokenizer proposal_first_token(shunk_t input, const char *delim);
void proposal_next_token(struct proposal_tokenizer *token);

bool parse_proposal_encrypt_transform(struct proposal_parser *parser,
				      struct proposal *proposal,
				      struct proposal_tokenizer *tokens);

bool parse_proposal_transform(struct proposal_parser *parser,
			      struct proposal *proposal,
			      enum proposal_transform transform,
			      shunk_t token);

bool parse_proposal(struct proposal_parser *parser,
		    struct proposal *proposal, shunk_t input);

void discard_proposal_transform(const char *what,
				struct proposal_parser *parser,
				struct proposal *proposal,
				enum proposal_transform transform,
				diag_t *diag);

#endif /* PROPOSALS_H */
