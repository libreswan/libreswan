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
 * ??? this use of union is very scary.
 */
struct db_attr {
	union {
		enum ikev1_oakley_attr oakley;	/* ISAKMP_ATTR_AF_TV is implied;
						 * 0 for end
						 */
		enum ikev1_ipsec_attr ipsec;
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
 * Security Association
 *
 * Heap memory is owned by one pointer, usually st->st_sadb.
 * Other pointers' lifetimes must nest within this allocation duration.
 * If "dynamic" is false, things are not on the heap and must not be mutated.
 */
struct db_sa {
	bool dynamic;	/* set if these items were unshared on heap */
	bool parentSA;	/* set if this is a parent/oakley */
	struct db_prop_conj *prop_conjs;	/* v1: [prop_conj_cnt] conjunctions of proposals (disjunction) */
	unsigned int prop_conj_cnt;	/* v1: number of conjunctions of proposals */
};

/*
 * IKE policies.
 *
 * am == aggressive mode
 */
extern struct db_sa *IKEv1_oakley_sadb(lset_t x, const struct connection *c);
extern struct db_sa *IKEv1_oakley_am_sadb(lset_t x, const struct connection *c);

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
		   const struct db_sa *sadb,
		   struct state *st,
		   bool oakley_mode,
		   bool aggressive_mode,
		   enum next_payload_types_ikev1 np);

extern lset_t preparse_isakmp_sa_body(pb_stream sa_pbs /* by value! */);

extern notification_t parse_isakmp_sa_body(pb_stream *sa_pbs,           /* body of input SA Payload */
					   const struct isakmp_sa *sa,  /* header of input SA Payload */
					   pb_stream *r_sa_pbs,         /* if non-NULL, where to emit winning SA */
					   bool selection,              /* if this SA is a selection, only one transform can appear */
					   struct state *st);           /* current state object */

/* initialize a state with the aggressive mode parameters */
extern bool init_aggr_st_oakley(struct state *st, lset_t policy);

extern notification_t parse_ipsec_sa_body(pb_stream *sa_pbs,            /* body of input SA Payload */
					  const struct isakmp_sa *sa,   /* header of input SA Payload */
					  pb_stream *r_sa_pbs,          /* if non-NULL, where to emit winning SA */
					  bool selection,               /* if this SA is a selection, only one transform can appear */
					  struct state *st);            /* current state object */

extern void free_sa_attr(struct db_attr *attr);
extern void free_sa(struct db_sa **sapp);
extern struct db_sa *sa_copy_sa(struct db_sa *sa);
extern struct db_sa *sa_copy_sa_first(struct db_sa *sa);
extern struct db_sa *sa_merge_proposals(struct db_sa *a, struct db_sa *b);

/* in spdb_print.c - normally never used in pluto */
extern void sa_log(struct db_sa *f);

struct alg_info_ike;
struct alg_info_esp;

extern struct db_sa *oakley_alg_makedb(struct alg_info_ike *ai,
				       enum ikev1_auth_method auth_method,
				       bool single_dh);

extern struct db_sa *kernel_alg_makedb(lset_t policy,
				       struct alg_info_esp *ei,
				       bool logit);

#endif /*  _SPDB_H_ */
