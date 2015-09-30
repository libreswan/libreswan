/* Security Policy Data Base (such as it is)
 *
 * Copyright (C) 1998,1999,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2015 Andrew Cagney <andrew.cagney@gmail.com>
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

#ifndef _SPDB_H_
#define _SPDB_H_

#include "packet.h"

/* database of SA properties */

/* Attribute type and value pair.
 * Note: only "basic" values are represented so far.
 * v2 is drastically simplified: there is only one attribute type
 * and it applies to any v2 protocols.
 * ??? this use of union is very scary.
 */
struct db_attr {
	union {
		enum ikev1_oakley_attr oakley;	/* ISAKMP_ATTR_AF_TV is implied;
						 * 0 for end
						 */
		enum ikev1_ipsec_attr ipsec;
		enum ikev2_trans_attr_type v2;	/* all v2 protocols */
	} type;
	u_int16_t val;
};

/*
 * The logic of IKEv1 proposals is described in
 * RFC2408 "Internet Security Association and Key Management Protocol (ISAKMP)"
 * especially in Section 4.2 "Security Association Establishment"
 * and Section 3.5 "Proposal Payload"
 * and Section 3.6 "Transform Payload"
 *
 * On the wire:
 *
 *     An SA has one or more Proposals.
 *
 *     Each Proposal has a Protocol ID (serial number).
 *     They must be monotonically non-decreasing.
 *     If there are multiple protocols with the same Protocol ID,
 *     all of them must apply on not together (conjunction).
 *     Protocols with different IDs are alternatives (disjunction).
 *
 *     Each proposal has one or more Transforms.
 *     Each Transform has a Transform ID (serial number).
 *     These are monotonically increasing (no duplicates).
 *     As such, each is an alternative.
 *
 *     Each Transform has one or more Attributes.
 *
 * Our in-program representation:
 */

/* transform: an array of attributes */
struct db_trans {
	u_int16_t transid;	/* Transform-Id */
	struct db_attr *attrs;	/* [attr_cnt] attributes */
	unsigned int attr_cnt;	/* number of attributes */
};

/*
 * IKEv1 proposal: an array of transforms (alternatives)
 * Example: several different ESP transforms, any of which is OK.
 */
struct db_prop {
	u_int8_t protoid;	/* Protocol-Id */
	struct db_trans *trans;	/* [trans_cnt] transforms (disjunction) */
	unsigned int trans_cnt;	/* number of transforms */
	/* SPI size and value isn't part of DB */
};

/*
 * IKEv1 conjunction of proposals: array of proposals, all of which must be used.
 * Example: one is ESP, another is AH, result is ESP and AH.
 */
struct db_prop_conj {
	struct db_prop *props;	/* [prop_cnt] proposals (conjunction) */
	unsigned int prop_cnt;	/* number of proposals */
};

/*
 * The logic of IKEv2 Security Association Payloads is described in
 * RFC5996bis section 3.3.
 * An SA may contain multiple proposals; these are alternatives,
 * in decreasing preference order.
 * Each proposal contains a single IPsec protocol (IKE, ESP, or AH).
 * Each proposal may contain multiple transforms.
 * Each transform may contain multiple attributes.
 *
 * Each proposal is numbered, starting from one and increasing by one.
 * Within each proposal, transforms of the same type (eg. ENCR, INTEG, ESN)
 * are alternatives and each of the types that appear in the SA
 * must appear in the matching SA.
 *
 * Combined-mode ciphers handle both integrity and encryption in a single
 * (encryption) algorithm and thus their proposal must offer either no
 * integrity algorithm or the "none" integrity algorithm.
 *
 * To offer both combined-mode and non-combined mode ciphers, separate
 * proposals are required.
 */

/* IKEv2 transform */
struct db_v2_trans {
	enum ikev2_trans_type transform_type;
	u_int16_t transid;	/* Transform-Id */
	struct db_attr *attrs;	/* [attr_cnt] attributes */
	unsigned int attr_cnt;	/* number of attributes */
};

/*
 * IKEv2 proposal
 * transforms are OR of each unique transform_type
 * ??? that description is suspect.  How about:
 * ??? A proposal A matches a proposal B iff
 * ??? (1) all transform types present in A are present in the B, and
 * ??? (2) for each transform type present in A, at least one
 * ???     of the transforms of that type in A matches a transform in B.
 * ??? In other words, all of the transforms with a particular
 * ??? type form a disjunction, and the proposal is a conjunction
 * ??? of these disjunctions.
 *
 * ??? if this is a disjunction (OR) why is it called *_conj?
 * ??? this should probably be called db_v2_prop.
 */

struct db_v2_prop_conj {
	u_int8_t propnum;
	u_int8_t protoid;	/* Protocol-Id: enum ikev2_trans_type */
	struct db_v2_trans *trans;	/* [trans_cnt] transforms (OR) */
	unsigned int trans_cnt;	/* number of transforms */
	/* SPI size and value isn't part of DB */
};

/*
 * conjunction (AND) of proposals - IKEv2
 * this is, for instance, ESP+AH, etc.
 * ??? If this is multiple proposals why is it called *_prop?
 * ??? This should probably be called db_v2_prop_conj
 */
struct db_v2_prop {
	struct db_v2_prop_conj *props;	/* [prop_cnt] conjunctive proposals (AND) */
	unsigned int prop_cnt;		/* number of conjunctive proposals */
};

/*
 * Security Association
 *
 * Heap memory is owned by one pointer, usually st->st_sadb.
 * Other pointers' lifetimes must nest within this allocation duration.
 * If "dynamic" is false, things are not on the heap and must not be mutated.
 * V2 uses the V1 substructures and then converts them with sa_v2_convert().
 * If the v2 substructures are present, they are based on the v1 substructures
 * and conversion will not be required.
 */
struct db_sa {
	bool dynamic;	/* set if these items were unshared on heap */
	bool parentSA;	/* set if this is a parent/oakley */
	struct db_prop_conj *prop_conjs;	/* v1: [prop_conj_cnt] conjunctions of proposals (disjunction) */
	unsigned int prop_conj_cnt;	/* v1: number of conjunctions of proposals */

	struct db_v2_prop *v2_prop_disj;	/* v2: [v2_prop_disj_cnt] */
	unsigned int v2_prop_disj_cnt;	/* v2: number of elements... OR */
};

/*
 * IKE policies.
 *
 * For IKEv2, it is described using IKEv1 constructs (e.g., constants
 * such as OAKLEY_...), and then converted to IKEv2 using
 * sa_v2_convert().  There really should be a pure IKEv2 table.
 *
 * am == agressive mode
 */
extern struct db_sa *IKEv1_oakley_sadb(lset_t x, struct connection *c);
extern struct db_sa *IKEv1_oakley_am_sadb(lset_t x, struct connection *c);
extern struct db_sa *IKEv2_oakley_sadb(lset_t x);

/*
 * Terminated by OAKLEY_GROUP_invalid.  Must contain all groups found
 * in IKEv2_oakley_sadb.
 */
extern const enum ike_trans_type_dh IKEv2_oakley_sadb_groups[];
extern const enum ike_trans_type_dh IKEv2_oakley_sadb_default_group;

/* The ipsec sadb is subscripted by a bitset with members
 * from POLICY_ENCRYPT, POLICY_AUTHENTICATE, POLICY_COMPRESS
 */
extern struct db_sa ipsec_sadb[1 << 3];

/* for db_sa */
#define AD_SAp(x)    .prop_conjs = (x), .prop_conj_cnt = elemsof(x), \
	.parentSA = TRUE
#define AD_SAc(x)    .prop_conjs = (x), .prop_conj_cnt = elemsof(x), \
	.parentSA = FALSE
#define AD_NULL     .prop_conjs = NULL, .prop_conj_cnt = 0,

/* for db_trans */
#define AD_TR(p, x) .transid = (p), .attrs = (x), .attr_cnt = elemsof(x)

/* for db_prop */
#define AD_PR(p, x) .protoid = (p), .trans = (x), .trans_cnt = elemsof(x)

/* for db_prop_conj */
#define AD_PC(x) .props = (x), .prop_cnt = elemsof(x)

extern bool ikev1_out_sa(pb_stream *outs,
		   struct db_sa *sadb,
		   struct state *st,
		   bool oakley_mode,
		   bool aggressive_mode,
		   enum next_payload_types_ikev1 np);

#if 0
extern complaint_t accept_oakley_auth_method(struct state *st,  /* current state object */
					     u_int32_t amethod, /* room for larger values */
					     bool credcheck);   /* whether we can check credentials now */
#endif

extern lset_t preparse_isakmp_sa_body(pb_stream sa_pbs /* by value! */);

extern notification_t parse_isakmp_sa_body(pb_stream *sa_pbs,           /* body of input SA Payload */
					   const struct isakmp_sa *sa,  /* header of input SA Payload */
					   pb_stream *r_sa_pbs,         /* if non-NULL, where to emit winning SA */
					   bool selection,              /* if this SA is a selection, only one tranform can appear */
					   struct state *st);           /* current state object */

/* initialize a state with the aggressive mode parameters */
extern int init_aggr_st_oakley(struct state *st, lset_t policy);

extern notification_t parse_ipsec_sa_body(pb_stream *sa_pbs,            /* body of input SA Payload */
					  const struct isakmp_sa *sa,   /* header of input SA Payload */
					  pb_stream *r_sa_pbs,          /* if non-NULL, where to emit winning SA */
					  bool selection,               /* if this SA is a selection, only one tranform can appear */
					  struct state *st);            /* current state object */

extern void free_sa_attr(struct db_attr *attr);
extern void free_sa(struct db_sa **sapp);
extern struct db_sa *sa_copy_sa(struct db_sa *sa);
extern struct db_sa *sa_copy_sa_first(struct db_sa *sa);
extern struct db_sa *sa_merge_proposals(struct db_sa *a, struct db_sa *b);

/* in spdb_print.c - normally never used in pluto */
extern void sa_log(struct db_sa *f);

extern void sa_v2_log(struct db_sa *f);

/* IKEv1 <-> IKEv2 things */
extern void sa_v2_convert(struct db_sa **sapp);

#endif /*  _SPDB_H_ */
