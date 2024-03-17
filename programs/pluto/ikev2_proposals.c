/* IKEv2 SA (Secure Association) Payloads, for libreswan
 *
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2012,2107 Antony Antony <antony@phenome.org>
 * Copyright (C) 2012-2013,2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2019 D. Hugh Redelmeier <hugh@mimosa.com>
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
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "sysdep.h"
#include "constants.h"

#include "defs.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"	/* needs id.h */
#include "state.h"
#include "packet.h"
#include "keys.h"
#include "kernel.h"	/* needs connections.h */
#include "log.h"
#include "whack.h"	/* for RC_LOG_SERIOUS */
#include "plutoalg.h"
#include "ikev2_proposals.h"
#include "crypto.h"

#include "kernel_alg.h"
#include "ike_alg.h"
#include "ike_alg_integ.h"
#include "ike_alg_dh.h"
#include "demux.h"
#include "ikev2.h"
#include "rnd.h"
#include "ikev2_message.h"		/* for build_ikev2_critical() */
#include "nat_traversal.h"

static void append_transform(struct ikev2_proposal *proposal,
			     enum ikev2_trans_type type, unsigned id,
			     unsigned attr_keylen);

/*
 * Two possible attribute formats (fixed and variable).  In IKEv2 the
 * attribute type determines the format that an attribute must use (in
 * IKEv1 it was the value that determined this).
 */

static bool v2_out_attr_fixed(struct pbs_out *pbs, enum ikev2_trans_attr_type type,
			      unsigned long val)
{
	pexpect((val >> 16) == 0);
	pexpect((type & ISAKMP_ATTR_AF_MASK) == 0);
	/* set the short-form attribute format bit */
	struct ikev2_trans_attr attr = {
		.isatr_type = type | ISAKMP_ATTR_AF_TV,
		.isatr_lv = val,
	};
	if (!out_struct(&attr, &ikev2_trans_attr_desc, pbs, NULL)) {
		llog(RC_LOG, pbs->outs_logger, "%s() for attribute %d failed", __func__, type);
		return false;
	}
	return true;
}

static bool v2_out_attr_variable(struct pbs_out *pbs,
				 enum ikev2_trans_attr_type type,
				 chunk_t chunk)
{
	pexpect((type & ISAKMP_ATTR_AF_MASK) == 0);
	/* clear the short-form attribute format bit */
	struct ikev2_trans_attr attr = {
		.isatr_type = type & ~ISAKMP_ATTR_AF_TV,
		.isatr_lv = chunk.len,
	};
	if (!pexpect(out_struct(&attr, &ikev2_trans_attr_desc, pbs, NULL))) {
		return false;
	}
	if (!pexpect(out_hunk(chunk, pbs, "attribute value"))) {
		return false;
	}
	return true;
}

/*
 * Raw (IETF numbered) chosen proposal/transform.
 */
struct ikev2_transform {
	/*
	 * The transform's id.  Zero is included in legitimate values.
	 */
	unsigned id;
	/*
	 * If greater-than-zero, the transform's keylen attribute
	 * (otherwise the attribute is absent).
	 */
	unsigned attr_keylen;
	/*
	 * Marker to indicate that the transform was implied rather
	 * than valid.
	 */
	bool implied;
	/*
	 * Marker to indicate that the transform is valid.  The first
	 * invalid transform acts as a sentinel.
	 *
	 * Transform iterators assume that there's an extra invalid
	 * transform at the end of a transform array.
	 */
	bool valid;
};

/*
 * An array of all the transforms of a specific transform type.
 *
 * The array includes an extra sentinel transform element -
 * SENTINEL_TRANSFORM which is always invalid.
 *
 * FOR_EACH_TRANSFORM(TRANSFORM,TRANSFORMS) iterates over the valid
 * elements; on loop exit, TRANSFORM points at the first invalid
 * entry, or SENTINEL_TRANSFORM if the array is full.
 *
 * To append entries use append_transform().
 */

struct ikev2_transforms {
	struct ikev2_transform transform[10 + 1]; /* 10 ought to be enough */
};

#define SENTINEL_TRANSFORM(TRANSFORMS) \
	((TRANSFORMS)->transform + elemsof((TRANSFORMS)->transform) - 1)

#define FOR_EACH_TRANSFORM(TRANSFORM,TRANSFORMS)			\
	for ((TRANSFORM) = &(TRANSFORMS)->transform[0];			\
	     (TRANSFORM)->valid && (TRANSFORM) < SENTINEL_TRANSFORM(TRANSFORMS); \
	     (TRANSFORM)++)

struct ikev2_spi {
	size_t size;
	uint8_t bytes[COOKIE_SIZE>IPSEC_DOI_SPI_SIZE ? COOKIE_SIZE : IPSEC_DOI_SPI_SIZE];	/* space for largest SPI */
};

struct ikev2_proposal {
	/*
	 * The proposal number for this proposal, or zero implying
	 * that the propnum should be auto-assigned.
	 *
	 * A chosen proposal always has a non-zero propnum.
	 *
	 * Yes, this is field is signed (IETF propnum is a uint16_t).
	 * It keeps it compatible with code using <0 for errors, 0 for
	 * no match, and >0 for a match.
	 */
	int propnum;
	/*
	 * The protocol ID.
	 */
	enum ikev2_sec_proto_id protoid;
	/*
	 * The SPI received from the remote end.
	 *
	 * Only used when capturing the chosen proposal.
	 */
	struct ikev2_spi remote_spi;
	/*
	 * The transforms.
	 */
	struct ikev2_transforms transforms[IKEv2_TRANS_TYPE_ROOF];
};

#define FOR_EACH_TRANSFORMS_TYPE(TYPE,TRANSFORMS,PROPOSAL)		\
	for ((TYPE) = 1, (TRANSFORMS) = &(PROPOSAL)->transforms[(TYPE)];	\
	     (TYPE) < elemsof((PROPOSAL)->transforms);			\
	     (TYPE)++, (TRANSFORMS)++)

struct ikev2_proposal_match {
	/*
	 * Set of local transform types to expect in the remote
	 * proposal.
	 *
	 * If the local proposal includes INTEG=NONE and/or DH=NONE
	 * then including INTEG and/or DH transforms in the remote
	 * proposal is OPTIONAL.  When the transform is missing, NONE
	 * is implied.
	 */
	lset_t required_transform_types;
	lset_t optional_transform_types;
	/*
	 * Location of the sentinel transform for each transform type.
	 * MATCHING_TRANSFORMS starts out with this value.
	 */
	struct ikev2_transform *sentinel_transform[IKEv2_TRANS_TYPE_ROOF];
	/*
	 * Set of transform types in the remote proposal that matched
	 * at least one local transform of the same type.
	 *
	 * Note: MATCHED <= REQUIRED | OPTIONAL
	 */
	lset_t matched_transform_types;
	/*
	 * Pointer to the best matched transform within the local
	 * proposal, or the (invalid) sentinel transform.
	 */
	const struct ikev2_transform *matching_transform[IKEv2_TRANS_TYPE_ROOF];
};

struct ikev2_proposals {
	/*
	 * The number of elements in the PROPOSAL array.  When
	 * iterating over the array this is the hard upper bound.
	 *
	 * Because PROPOSAL[0] exists but is ignored (PROPOSAL is
	 * treated as one-based) ROOF is one more than the number of
	 * proposals.
	 *
	 * Yes, this field is signed (IETF propnum is a uint16_t).  It
	 * keeps it compatible with code using <0 for errors, 0 for no
	 * match, and >0 for a match.
	 */
	int roof;
	/*
	 * An array of proposals.  So that the array index matches the
	 * IETF propnum, the array is 1-based (PROPOSAL[0] exists but
	 * is ignored).
	 */
	struct ikev2_proposal *proposal;
};

/*
 * Iterate over all the proposals.
 *
 * PROPNUM is an int.
 */
#define FOR_EACH_V2_PROPOSAL(PROPNUM, PROPOSAL, PROPOSALS)		\
	for ((PROPNUM) = 1,						\
		     (PROPOSAL) = &(PROPOSALS)->proposal[(PROPNUM)];	\
	     (PROPNUM) < (PROPOSALS)->roof;				\
	     (PROPNUM)++, (PROPOSAL)++)

/*
 * Iterate over the sub-range [BASE..BOUND) of proposals, but also
 * bound sub-range by [1..ROOF).
 *
 * PROPNUM, BASE, BOUND are all ints.
 */
#define FOR_EACH_V2_PROPOSAL_IN_RANGE(PROPNUM, PROPOSAL, PROPOSALS, BASE, BOUND) \
	for ((PROPNUM) = ((BASE) > 0 ? (BASE) : 1),			\
		     (PROPOSAL) = &(PROPOSALS)->proposal[(PROPNUM)];	\
	     (PROPNUM) < (BOUND) && (PROPNUM) < (PROPOSALS)->roof;	\
	     (PROPNUM)++, (PROPOSAL)++)

/*
 * Print <TRANSFORM> to the buffer.
 */
static void jam_transform(struct jambuf *buf, enum ikev2_trans_type type,
			  const struct ikev2_transform *transform)
{
	jam_enum_enum_short(buf, &v2_transform_ID_enums,
			    type, transform->id);
	if (transform->attr_keylen > 0) {
		jam(buf, "_%d", transform->attr_keylen);
	}
}

static const char *trans_type_name(enum ikev2_trans_type type)
{
	return enum_name_short(&ikev2_trans_type_names, type);
}

static void jam_trans_types(struct jambuf *buf, lset_t types)
{
	jam_lset_short(buf, &ikev2_trans_type_names, "+", types);
}

/* <TRANSFORM-TYPE> "=" <TRANSFORM> */
static void jam_type_transform(struct jambuf *buf, enum ikev2_trans_type type,
			       const struct ikev2_transform *transform)
{
	jam_string(buf, trans_type_name(type));
	jam_string(buf, "=");
	jam_transform(buf, type, transform);
}

static const char *protoid_name(enum ikev2_sec_proto_id protoid)
{
	return enum_name_short(&ikev2_proposal_protocol_id_names, protoid);
}

/* <TRANSFORM> { "+" <TRANSFORM> }+ */
static void jam_transforms(struct jambuf *buf, enum ikev2_trans_type type,
			   const struct ikev2_transforms *transforms)
{	char *sep = "";
	const struct ikev2_transform *transform;
	FOR_EACH_TRANSFORM(transform, transforms) {
		jam_string(buf, sep);
		jam_transform(buf, type, transform);
		sep = "+";
	};
}

static void jam_v2_proposal(struct jambuf *buf, int propnum,
			    const struct ikev2_proposal *proposal)
{
	if (propnum != 0) {
		jam(buf, "%d:", propnum);
	}
	jam(buf, "%s=", protoid_name(proposal->protoid));
	const char *sep = "";
	enum ikev2_trans_type type;
	const struct ikev2_transforms *transforms;
	FOR_EACH_TRANSFORMS_TYPE(type, transforms, proposal) {
		if (transforms->transform[0].valid) {
			/* at least one transform */
			jam_string(buf, sep);
			/*
			 * XXX: hack so that ...-ESN:YES+NO is logged.
			 * Other fields are self explanatory.
			 */
			if (type == IKEv2_TRANS_TYPE_ESN) {
				jam_string(buf, "ESN:");
			}
			jam_transforms(buf, type, transforms);
			sep = "-";
		}
	}
	if (proposal->remote_spi.size > 0) {
		passert(proposal->remote_spi.size <= sizeof(proposal->remote_spi.bytes));
		jam_string(buf, " SPI=");
		jam_hex_bytes(buf, proposal->remote_spi.bytes, proposal->remote_spi.size);
	}
}

static void jam_chosen_proposal(struct jambuf *buf,
				struct ikev2_proposal *best_proposal,
				struct jambuf *proposals)
{
	jam_string(buf, "proposal ");
	jam_v2_proposal(buf, best_proposal->propnum, best_proposal);
	jam_string(buf, " chosen from remote proposals ");
	jam_jambuf(buf, proposals);
}

void DBG_log_ikev2_proposal(const char *prefix,
			    const struct ikev2_proposal *proposal)
{
	LLOG_JAMBUF(DEBUG_STREAM, &global_logger, buf) {
		jam(buf, "%s ikev2_proposal: ", prefix);
		jam_v2_proposal(buf, proposal->propnum, proposal);
	}
}

static void jam_v2_proposals(struct jambuf *buf,
			     const struct ikev2_proposals *proposals)
{
	passert(proposals->proposal[0].protoid == 0);
	const char *proposal_sep = "";
	int propnum;
	const struct ikev2_proposal *proposal;
	FOR_EACH_V2_PROPOSAL(propnum, proposal, proposals) {
		jam_string(buf, proposal_sep);
		proposal_sep = " ";
		jam_v2_proposal(buf, propnum, proposal);
	}
}

void llog_v2_proposals(lset_t rc_flags, struct logger *logger,
		       const struct ikev2_proposals *proposals,
		       const char *title)
{
	int propnum;
	const struct ikev2_proposal *proposal;
	llog(rc_flags, logger, "%s:", title);
	FOR_EACH_V2_PROPOSAL(propnum, proposal, proposals) {
		LLOG_JAMBUF(rc_flags, logger, buf) {
			jam_string(buf, "  ");
			jam_v2_proposal(buf, propnum, proposal);
		}
	}
}

/*
 * Compare the initiator's proposal's transforms against local
 * proposals [LOCAL_PROPNUM_BASE .. LOCAL_PROPNUM_BOUND) finding the
 * earliest match.
 *
 * Returns:
 *
 *    -v2_notification_t: if things go wrong
 *    0: if nothing matches
 *    [LOCAL_PROPNUM_BASE, LOCAL_PROPNUM_BOUND): if there is a match
 *
 * As the remote proposal is parsed and validated, a description of it
 * is accumulated in REMOTE_JAM_BUF.
 */

static int process_transforms(struct pbs_in *prop_pbs, struct jambuf *remote_jam_buf,
			      unsigned remote_propnum, int num_remote_transforms,
			      enum ikev2_sec_proto_id remote_protoid,
			      const struct ikev2_proposals *local_proposals,
			      const int local_propnum_base, const int local_propnum_bound,
			      struct ikev2_proposal_match *matching_local_proposals,
			      struct logger *logger)
{
	dbg("Comparing remote proposal %u containing %d transforms against local proposal [%d..%d] of %d local proposals",
	    remote_propnum, num_remote_transforms,
	    local_propnum_base, local_propnum_bound - 1,
	    local_proposals->roof - 1);

	/*
	 * The MATCHING_LOCAL_PROPOSALS table contains one entry per
	 * local proposal.  Each entry points to the best matching or
	 * sentinel transforms for that proposal.
	 *
	 * Initially the MATCHING_TRANSFORM[TRANS_TYPE]s point to the
	 * proposal's sentinel transforms making an upper bound on
	 * searches.  If a transform matches, then the pointer is
	 * updated (reduced) accordingly.
	 */
	{
		int local_propnum;
		const struct ikev2_proposal *local_proposal;
		FOR_EACH_V2_PROPOSAL_IN_RANGE(local_propnum, local_proposal, local_proposals,
					      local_propnum_base, local_propnum_bound) {
			struct ikev2_proposal_match *matching_local_proposal = &matching_local_proposals[local_propnum];
			/* clear matched */
			matching_local_proposal->matched_transform_types = LEMPTY;
			/* start with the sentinels */
			passert(sizeof(matching_local_proposal->matching_transform) ==
				sizeof(matching_local_proposal->sentinel_transform));
			memcpy(matching_local_proposal->matching_transform,
			       matching_local_proposal->sentinel_transform,
			       sizeof(matching_local_proposal->sentinel_transform));
		}
	}

	/*
	 * Track all the remote transform types included in the
	 * proposal.
	 */
	lset_t proposed_remote_transform_types = LEMPTY;
	/*
	 * Track the remote transform types that matched at least one
	 * local proposal.
	 *
	 * IF there is a "proposed remote transform type" missing from
	 * this set THEN the remote proposal can't have matched (note
	 * that the coverse does not hold).
	 *
	 * See quick check below.
	 */
	lset_t matched_remote_transform_types = LEMPTY;

	/*
	 * Track the first integrity transform's transID.  Needed to
	 * check for a mixup of NONE and non-NONE integrity
	 * transforms.
	 *
	 * Since 0 (NONE) is a valid integrity transID value, start
	 * with -1.
	 */
	int first_integrity_transid = -1;
	const char *remote_transform_sep = "";

	int remote_transform_nr;
	for (remote_transform_nr = 0;
	     remote_transform_nr < num_remote_transforms;
	     remote_transform_nr++) {
		jam_string(remote_jam_buf, remote_transform_sep);
		remote_transform_sep = ";";

		/* first the transform */
		struct ikev2_trans remote_trans;
		struct pbs_in trans_pbs;
		diag_t d = pbs_in_struct(prop_pbs, &ikev2_trans_desc,
					 &remote_trans, sizeof(remote_trans),
					 &trans_pbs);
		if (d != NULL) {
			llog_diag(RC_LOG, logger, &d,
				 "remote proposal %u transform %d is corrupt",
				 remote_propnum, remote_transform_nr);
			jam_string(remote_jam_buf, "[corrupt-transform]");
			return -v2N_INVALID_SYNTAX; /* fatal */
		}

		/* ignore unknown transform types. */
		if (remote_trans.isat_type == 0) {
			return -v2N_INVALID_SYNTAX; /* fatal */
		}
		if (remote_trans.isat_type >= IKEv2_TRANS_TYPE_ROOF) {
			return 0; /* try next proposal */
		}
		enum ikev2_trans_type type = remote_trans.isat_type;

		struct ikev2_transform remote_transform = {
			.id = remote_trans.isat_transid,
			.valid = true,
		};

		/* followed by attributes */
		while (pbs_left(&trans_pbs) != 0) {
			struct pbs_in attr_pbs;
			struct ikev2_trans_attr attr;
			diag_t d = pbs_in_struct(&trans_pbs, &ikev2_trans_attr_desc,
						 &attr, sizeof(attr), &attr_pbs);
			if (d != NULL) {
				llog_diag(RC_LOG, logger, &d,
					 "remote proposal %u transform %d contains corrupt attribute",
					 remote_propnum, remote_transform_nr);
				jam_string(remote_jam_buf, "[corrupt-attribute]");
				return -v2N_INVALID_SYNTAX; /* fatal */
			}

			/*
			 * This switch checks both the attribute's
			 * type and its encoding.  Hence ORing the
			 * encoding with the type.
			 */
			switch (attr.isatr_type) {
			case IKEv2_KEY_LENGTH | ISAKMP_ATTR_AF_TV:
				remote_transform.attr_keylen = attr.isatr_lv;
				break;
			default:
				llog(RC_LOG, logger, "remote proposal %u transform %d has unknown attribute %d or unexpeced attribute encoding",
					    remote_propnum, remote_transform_nr,
					    attr.isatr_type & ISAKMP_ATTR_RTYPE_MASK);
				jam_string(remote_jam_buf, "[unknown-attribute]");
				return 0; /* try next proposal */
			}
		}

		/*
		 * Accumulate the proposal's transforms in remote_buf.
		 */
		jam_type_transform(remote_jam_buf, type, &remote_transform);

		/*
		 * Remember each remote transform type found.
		 */
		proposed_remote_transform_types |= LELEM(type);

		/*
		 * Detect/reject things like: INTEG=NONE INTEG=HASH
		 * INTEG=NONE.
		 */
		if (type == IKEv2_TRANS_TYPE_INTEG) {
			if (first_integrity_transid < 0) {
				first_integrity_transid = remote_trans.isat_transid;
			} else if (first_integrity_transid == IKEv2_INTEG_NONE ||
				   remote_trans.isat_transid == IKEv2_INTEG_NONE) {
				llog(RC_LOG, logger, "remote proposal %u transform %d has more than 'none' integrity %d %d",
					    remote_propnum, remote_transform_nr,
					    first_integrity_transid, remote_trans.isat_transid);
				jam_string(remote_jam_buf, "[mixed-integrity]");
				return 0; /* try next proposal */
			}
		}

		/*
		 * Find the proposals that match and flag them.
		 */
		int local_propnum;
		struct ikev2_proposal *local_proposal;
		FOR_EACH_V2_PROPOSAL_IN_RANGE(local_propnum, local_proposal, local_proposals,
					      local_propnum_base, local_propnum_bound) {
			if (local_proposal->protoid == remote_protoid) {
				/*
				 * Search the proposal for transforms of this
				 * type that match.  Limit the search to
				 * transforms before the last match.
				 */
				passert(type < elemsof(local_proposal->transforms)); /* aka IKEv2_TRANS_TYPE_ROOF */
				const struct ikev2_transforms *local_transforms = &local_proposal->transforms[type];
				struct ikev2_proposal_match *matching_local_proposal = &matching_local_proposals[local_propnum];
				passert(type < elemsof(matching_local_proposal->matching_transform)); /* aka IKEv2_TRANS_TYPE_ROOF */
				const struct ikev2_transform **matching_local_transform = &matching_local_proposal->matching_transform[type];
				/*
				 * The matching local transform always
				 * points into the local transform
				 * array (which includes includes the
				 * sentinel transform at the array
				 * end).
				 */
				passert(*matching_local_transform >= &local_transforms->transform[0]);
				passert(*matching_local_transform < &local_transforms->transform[elemsof(local_transforms->transform)]);
				/*
				 * See if this match improves things.
				 */
				const struct ikev2_transform *local_transform;
				FOR_EACH_TRANSFORM(local_transform, local_transforms) {
					if (local_transform >= *matching_local_transform) {
						break;
					}
					if (local_transform->id == remote_transform.id &&
					    local_transform->attr_keylen == remote_transform.attr_keylen) {
						LDBGP_JAMBUF(DBG_BASE, &global_logger, buf) {
							jam(buf, "remote proposal %u transform %d (",
							    remote_propnum, remote_transform_nr);
							jam_type_transform(buf, type, &remote_transform);
							jam(buf, ") matches local proposal %d type %d (%s) transform %td",
							    local_propnum,
							    type, trans_type_name(type),
							    local_transform - local_transforms->transform);
						}
						/*
						 * Update the sentinel
						 * with this new best
						 * match for this
						 * local proposal.
						 */
						*matching_local_transform = local_transform;
						/*
						 * Also record that
						 * the local transform
						 * type has
						 * successfully
						 * matched.
						 */
						matched_remote_transform_types |= LELEM(type);
						matching_local_proposal->matched_transform_types |= LELEM(type);
						break;
					}
				}
			}
		}
	}

	/*
	 * Quick check that all the proposed transform types had at
	 * least one match.
	 *
	 * For instance, if the remote proposal includes one or more
	 * ESP transforms, then at least one of the local proposals
	 * must have matched the ESP.  If none did (either they didn't
	 * include ESP or had the wrong ESP) then the proposal can be
	 * rejected out-of-hand.
	 *
	 * This works because:
	 *
	 * - "matched remote transform types" == union of all "matched
	 *   local transform types"
	 *
	 * - "matched remote transform types" <= "proposed remote
	 *   transform types".
	 */
	lset_t unmatched_remote_transform_types = proposed_remote_transform_types & ~matched_remote_transform_types;
	LDBGP_JAMBUF(DBG_BASE, &global_logger, buf) {
		jam(buf, "remote proposal %u proposed transforms: ",
			remote_propnum);
		jam_trans_types(buf, proposed_remote_transform_types);
		jam(buf, "; matched: ");
		jam_trans_types(buf, matched_remote_transform_types);
		jam(buf, "; unmatched: ");
		jam_trans_types(buf, unmatched_remote_transform_types);
	}
	if (unmatched_remote_transform_types) {
		LDBGP_JAMBUF(DBG_BASE, &global_logger, buf) {
			jam(buf, "remote proposal %u does not match; unmatched remote transforms: ",
				remote_propnum);
			jam_trans_types(buf, unmatched_remote_transform_types);
		}
		return 0;
	}

	int local_propnum;
	struct ikev2_proposal *local_proposal;
	FOR_EACH_V2_PROPOSAL_IN_RANGE(local_propnum, local_proposal, local_proposals,
				      local_propnum_base, local_propnum_bound) {
		struct ikev2_proposal_match *matching_local_proposal = &matching_local_proposals[local_propnum];
		LDBGP_JAMBUF(DBG_BASE, &global_logger, log) {
			jam(log, "comparing remote proposal %u containing ",
			    remote_propnum);
			jam_trans_types(log, proposed_remote_transform_types);
			jam(log, " transforms to local proposal %d",
			    local_propnum);
			jam(log, "; required: ");
			jam_trans_types(log, matching_local_proposal->
					required_transform_types);
			jam(log, "; optional: ");
			jam_trans_types(log, matching_local_proposal->
					optional_transform_types);
			jam(log, "; matched: ");
			jam_trans_types(log, matching_local_proposal->
					matched_transform_types);
		}
		/*
		 * Using the set relationships:
		 *
		 *   0 == required_local & optional_local
		 *   matched_local <= required_local + optional_local
		 *   matched_local <= proposed_remote
		 *
		 * the following can be computed:
		 *
		 *   unmatched = proposed_remote - matched_local
		 *
		 *     unmatched is zero IFF all the proposed remote
		 *     transforms matched this local proposal.
		 */
		lset_t unmatched =
			(proposed_remote_transform_types
			 & ~matching_local_proposal->matched_transform_types);
		/*
		 *   missing = required_local - matched_local
		 *
		 *     missing is zero IFF all the required local
		 *     transforms were matched
		 *
		 *     Optional transforms are not included.
		 */
		lset_t missing =
			(matching_local_proposal->required_transform_types
			 & ~matching_local_proposal->matched_transform_types);
		/*
		 * vis:
		 *
		 *         Local Proposal: ENCR=AEAD+INTEG=NONE
		 *     required_local = ENCR; optional_local = INTEG
		 *     unmatched = proposed_remote - matched_local
		 *     missing = ENCR - matched_local
		 *
		 *      Remote            Matched     Unmatched  Missing Accept
		 *   INTEG=NONE           INTEG       -          ENCR
		 *   INTEG!NONE           -           INTEG      ENCR
		 *   ENCR=AEAD            ENCR        -          -       Yes
		 *   ENCR!AEAD            -           ENCR       ENCR
		 *   ENCR=AEAD+INTEG=NONE ENCR+INTEG  -          -       Yes
		 *   ENCR!AEAD+INTEG=NONE INTEG       ENCR       ENCR
		 *   ENCR=AEAD+INTEG!NONE ENCR        INTEG      -
		 *   ENCR!AEAD+INTEG!NONE -           ENCR+INTEG ENCR
		 *   ENCR=AEAD+ESP=NO     ENCR        ESP        -
		 *   ENCR!AEAD+ESP=NO     -           ESP+ENCR   ENCR
		 *
		 *          Local Proposal: ENCR!AEAD+INTEG!NONE
		 *     required_local = ENCR+INTEG; optional_local =
		 *     unmatched = proposed_remote - matched_local
		 *     missing = ENCR+INTEG - matched_local
		 *
		 *   Remote Proposal      Matched    Unmatched  Missing    Accept
		 *   INTEG=NONE           -          INTEG      ENCR+INTEG
		 *   INTEG!NONE           INTEG      -          ENCR
		 *   ENCR=AEAD            -          ENCR       ENCR+INTEG
		 *   ENCR!AEAD            ENCR       -          INTEG
		 *   ENCR=AEAD+INTEG=NONE -          ENCR+INTEG ENCR+INTEG
		 *   ENCR!AEAD+INTEG=NONE ENCR       INTEG      INTEG
		 *   ENCR=AEAD+INTEG!NONE INTEG      ENCR       ENCR
		 *   ENCR!AEAD+INTEG!NONE ENCR+INTEG -          -          Yes
		 *   ENCR=AEAD+ESP=NO     -          ENCR+ESP   ENCR+INTEG
		 *   ENCR!AEAD+ESP=NO     ENCR       INTEG+ESP  INTEG
		 */
		if (unmatched || missing) {
			LDBGP_JAMBUF(DBG_BASE, &global_logger, log) {
				jam(log, "remote proposal %d does not match local proposal %d; unmatched transforms: ",
					remote_propnum, local_propnum);
				jam_trans_types(log, unmatched);
				jam(log, "; missing transforms: ");
				jam_trans_types(log, missing);
			}
		} else {
			dbg("remote proposal %u matches local proposal %d",
			    remote_propnum, local_propnum);
			return local_propnum;
		}
	}

	dbg("remote proposal %u matches no local proposals", remote_propnum); /*  */
	return 0;
}

static size_t proto_spi_size(enum ikev2_sec_proto_id protoid)
{
	switch (protoid) {
	case IKEv2_SEC_PROTO_IKE:
		return COOKIE_SIZE;
	case IKEv2_SEC_PROTO_AH:
	case IKEv2_SEC_PROTO_ESP:
		return IPSEC_DOI_SPI_SIZE;
	default:
		return 0;
	}
}


/*
 * Process all the transforms, returning:
 *
 *    -v2_notification_t: the failure notification
 *    0: no proposal matched
 *    [1..LOCAL_PROPOSALS->ROOF): best match so far
 */

static int ikev2_process_proposals(struct pbs_in *sa_payload,
				   bool expect_ike,
				   bool expect_spi,
				   bool expect_accepted,
				   const struct ikev2_proposals *local_proposals,
				   struct ikev2_proposal *best_proposal,
				   struct jambuf *remote_jam_buf,
				   struct logger *logger)
{
	/*
	 * An array to track the best proposals/transforms found so
	 * far.
	 *
	 * The MATCHING_LOCAL_PROPOSALS table contains one entry per
	 * local proposal, and each entry contains a pointer best
	 * matching transform, or the sentinel transform.
	 *
	 * The required, optional, and sentinel fields are initialized
	 * here.  The remaining fields are initialized each time a
	 * remote proposal is parsed.
	 *
	 * Must be freed.
	 */
	struct ikev2_proposal_match *matching_local_proposals =
		alloc_things(struct ikev2_proposal_match, local_proposals->roof,
			     "matching_local_proposals");
	{
		int local_propnum;
		struct ikev2_proposal *local_proposal;
		FOR_EACH_V2_PROPOSAL(local_propnum, local_proposal, local_proposals) {
			struct ikev2_proposal_match *matching_local_proposal = &matching_local_proposals[local_propnum];
			enum ikev2_trans_type type;
			struct ikev2_transforms *local_transforms;
			lset_t all_transform_types = LEMPTY;
			lset_t optional_transform_types = LEMPTY;
			FOR_EACH_TRANSFORMS_TYPE(type, local_transforms, local_proposal) {
				/*
				 * Find the sentinel transform for
				 * this transform-type.
				 */
				struct ikev2_transform *sentinel_transform;
				FOR_EACH_TRANSFORM(sentinel_transform, local_transforms) {
					all_transform_types |= LELEM(type);
					/*
					 * When INTEG=NONE and/or
					 * DH=NONE is included in a
					 * local proposal, the
					 * transform is optional and,
					 * when missing from a remote
					 * proposal, NONE is implied.
					 */
					if ((type == IKEv2_TRANS_TYPE_INTEG &&
					     sentinel_transform->id == IKEv2_INTEG_NONE) ||
					    (type == IKEv2_TRANS_TYPE_DH &&
					     sentinel_transform->id == OAKLEY_GROUP_NONE)) {
						optional_transform_types |= LELEM(type);
					}
				}
				/* save the sentinel */
				passert(!sentinel_transform->valid);
				matching_local_proposal->sentinel_transform[type] = sentinel_transform;
				dbg("local proposal %d type %s has %td transforms",
				    local_propnum, trans_type_name(type),
				    sentinel_transform - local_transforms->transform);
			}
			/*
			 * A proposal's transform type can't be both
			 * required an optional.
			 *
			 * Since a proposal containing DH=NONE +
			 * DH=MODP2048 is valid, REQUIRED gets
			 * computed (INTEG=NONE + INTEG=SHA1 isn't
			 * valid but that should only happen when
			 * impaired).
			 */
			matching_local_proposal->optional_transform_types = optional_transform_types;
			matching_local_proposal->required_transform_types = all_transform_types & ~optional_transform_types;
			LDBGP_JAMBUF(DBG_BASE, &global_logger, buf) {
				jam(buf, "local proposal %d transforms: required: ",
					local_propnum);
				jam_trans_types(buf, matching_local_proposal->
						required_transform_types);
				jam(buf, "; optional: ");
				jam_trans_types(buf, matching_local_proposal->
						optional_transform_types);
			}
		}
	}

	/*
	 * This loop contains no "return" statements.  Instead it
	 * always enters at the top and exits at the bottom.  This
	 * simplfies the dealing with buffers allocated above.
	 *
	 * On loop exit, MATCHING_LOCAL_PROPNUM contains one of:
	 *
	 *    -v2_notification_t: failure notification
	 *    0: no proposal matched
	 *    [1..LOCAL_PROPOSALS->ROOF): best match so far
	 */
	int matching_local_propnum = 0;
	int next_propnum = 1;
	const char *remote_proposal_sep = "";
	struct ikev2_prop remote_proposal;

	do {
		/* Read the next proposal */
		struct pbs_in proposal_pbs;
		diag_t d = pbs_in_struct(sa_payload, &ikev2_prop_desc,
					 &remote_proposal, sizeof(remote_proposal),
					 &proposal_pbs);
		if (d != NULL) {
			llog_diag(RC_LOG, logger, &d, "proposal %d corrupt", next_propnum);
			jam_string(remote_jam_buf, " [corrupt-proposal]");
			matching_local_propnum = -v2N_INVALID_SYNTAX; /* fatal */
			break;
		}
		jam_string(remote_jam_buf, remote_proposal_sep);
		remote_proposal_sep = " ";
		jam(remote_jam_buf, "%d:", remote_proposal.isap_propnum);
		jam_string(remote_jam_buf, protoid_name(remote_proposal.isap_protoid));
		jam_string(remote_jam_buf, ":");

		/*
		 * Validate the Last Substruc and Proposal Num.
		 *
		 * RFC 7296: 3.3.1. Proposal Substructure: When a
		 * proposal is made, the first proposal in an SA
		 * payload MUST be 1, and subsequent proposals MUST be
		 * one more than the previous proposal (indicating an
		 * OR of the two proposals).  When a proposal is
		 * accepted, the proposal number in the SA payload
		 * MUST match the number on the proposal sent that was
		 * accepted.
		 */
		if (expect_accepted) {
			/* There can be only one accepted proposal. */
			if (remote_proposal.isap_lp != v2_PROPOSAL_LAST) {
				llog(RC_LOG, logger, "Error: more than one accepted proposal received.");
				jam_string(remote_jam_buf, "[too-many-accepted-proposals]");
				matching_local_propnum = -v2N_INVALID_SYNTAX; /* fatal */
				break;
			}
			if (remote_proposal.isap_propnum < 1 || remote_proposal.isap_propnum >= local_proposals->roof) {
				llog(RC_LOG, logger, "Error: invalid accepted proposal.");
				jam_string(remote_jam_buf, "[invalid-accepted-proposal]");
				matching_local_propnum = -v2N_INVALID_SYNTAX; /* fatal */
				break;
			}
		} else {
			if (next_propnum != remote_proposal.isap_propnum) {
				llog(RC_LOG, logger, "proposal number was %u but %u expected",
					      remote_proposal.isap_propnum,
					      next_propnum);
				jam_string(remote_jam_buf, "[wrong-protonum]");
				matching_local_propnum = -v2N_INVALID_SYNTAX; /* fatal */
				break;
			}
			next_propnum++;
		}

		/*
		 * Validate the Protocol ID
		 *
		 * RFC 7296: 3.3.1. Proposal Substructure: Specifies
		 * the IPsec protocol identifier for the current
		 * negotiation.
		 */
		if (expect_ike) {
			if (remote_proposal.isap_protoid != IKEv2_SEC_PROTO_IKE) {
				llog(RC_LOG, logger, "proposal %d has unexpected Protocol ID %d; expected IKE",
					    remote_proposal.isap_propnum,
					    remote_proposal.isap_protoid);
				jam_string(remote_jam_buf, "[unexpected-protoid]");
				continue;
			}
		} else {
			if (remote_proposal.isap_protoid != IKEv2_SEC_PROTO_AH &&
			    remote_proposal.isap_protoid != IKEv2_SEC_PROTO_ESP) {
				llog(RC_LOG, logger, "proposal %d has unexpected Protocol ID %d; expected AH or ESP",
					    remote_proposal.isap_propnum,
					    remote_proposal.isap_protoid);
				jam_string(remote_jam_buf, "[unexpected-protoid]");
				continue;
			}
		}

		/*
		 * Validate the Security Parameter Index (SPI):
		 *
		 * RFC 7296: 3.3.1. Proposal Substructure: SPI Size:
		 * For an initial IKE SA negotiation, this field MUST be
		 * zero; the SPI is obtained from the outer header.
		 * During subsequent negotiations, it is equal to the
		 * size, in octets, of the SPI of the corresponding
		 * protocol (8 for IKE, 4 for ESP and AH).
		 */
		/* Read any SPI. */
		struct ikev2_spi remote_spi = {
			.size = (expect_spi ? proto_spi_size(remote_proposal.isap_protoid) : 0),
		};
		if (remote_proposal.isap_spisize != remote_spi.size) {
			llog(RC_LOG, logger, "proposal %d has incorrect SPI size (%u), expected %zu; ignored",
				      remote_proposal.isap_propnum,
				      remote_proposal.isap_spisize,
				      remote_spi.size);
			jam_string(remote_jam_buf, "[spi-size]");
			continue;
		}
		if (remote_spi.size > 0) {
			diag_t d = pbs_in_bytes(&proposal_pbs, remote_spi.bytes,
						remote_spi.size, "remote SPI");
			if (d != NULL) {
				llog_diag(RC_LOG, logger, &d, "proposal %d contains corrupt SPI",
					 remote_proposal.isap_propnum);
				matching_local_propnum = -v2N_INVALID_SYNTAX; /* fatal */
				jam_string(remote_jam_buf, "[corrupt-spi]");
				break;
			}
		}

		int local_propnum_base;
		int local_propnum_bound;
		if (expect_accepted) {
			local_propnum_base = remote_proposal.isap_propnum;
			local_propnum_bound = remote_proposal.isap_propnum + 1;
		} else {
			local_propnum_base = 1; /*or 0*/
			local_propnum_bound = (matching_local_propnum
					       ? matching_local_propnum
					       : local_proposals->roof);
		}
		int match = process_transforms(&proposal_pbs, remote_jam_buf,
					       remote_proposal.isap_propnum,
					       remote_proposal.isap_numtrans,
					       remote_proposal.isap_protoid,
					       local_proposals,
					       local_propnum_base,
					       local_propnum_bound,
					       matching_local_proposals,
					       logger);

		if (match < 0) {
			/* capture the error and bail */
			matching_local_propnum = match;
			break;
		}

		if (match > 0) {
			passert(match < local_proposals->roof);
			/* mark what happened */
			if (matching_local_propnum == 0) {
				/* first match */
				jam_string(remote_jam_buf, "[first-match]");
			} else {
				/* second or further match */
				jam_string(remote_jam_buf, "[better-match]");
			}
			/* capture the new best proposal */
			matching_local_propnum = match;
			/* blat best with a new value */
			*best_proposal = (struct ikev2_proposal) {
				.propnum = remote_proposal.isap_propnum,
				.protoid = remote_proposal.isap_protoid,
				.remote_spi = remote_spi,
			};
			/*
			 * store the matching transforms in the very
			 * first transform entry of BEST_TRANSFORMS
			 */
			enum ikev2_trans_type type;
			struct ikev2_transforms *best_transforms;
			const struct ikev2_proposal_match *matching_local_proposal =
				&matching_local_proposals[matching_local_propnum];
			FOR_EACH_TRANSFORMS_TYPE(type, best_transforms, best_proposal) {
				const struct ikev2_transform *matching_transform = matching_local_proposal->matching_transform[type];
				passert(matching_transform != NULL);
				if (!matching_transform->valid &&
				    LHAS(matching_local_proposal->optional_transform_types, type)) {
					/*
					 * DH=NONE and/or INTEG=NONE
					 * is implied.
					 */
					unsigned id;
					switch (type) {
					case IKEv2_TRANS_TYPE_INTEG:
						id = IKEv2_INTEG_NONE;
						break;
					case IKEv2_TRANS_TYPE_DH:
						id = OAKLEY_GROUP_NONE;
						break;
					default:
						bad_case(type);
					}
					best_transforms->transform[0] = (struct ikev2_transform) {
						.id = id,
						.valid = false,
						.implied = true,
					};
				} else {
					/*
					 * When no match, this will
					 * copy the sentinel transform
					 * setting !valid.
					 */
					best_transforms->transform[0] = *matching_transform;
				}
			}
		}
	} while (remote_proposal.isap_lp == v2_PROPOSAL_NON_LAST);

	pfree(matching_local_proposals);
	return matching_local_propnum;
}

/*
 * Compare all remote proposals against all local proposals finding
 * and returning the "first" local proposal to match.
 *
 * The need to load all the remote proposals into buffers is avoided
 * by processing them in a single pass.  This is a tradeoff.  Since each
 * remote proposal in turn is compared against all local proposals
 * (and not each local proposal in turn compared against all remote
 * proposals) a local proposal matching only the last remote proposal
 * takes more comparisons.  On the other hand, mallocing and pointer
 * juggling is avoided.
 */
v2_notification_t process_v2SA_payload(const char *what,
				       struct pbs_in *sa_payload,
				       bool expect_ike,
				       bool expect_spi,
				       bool expect_accepted,
				       bool opportunistic,
				       struct ikev2_proposal **chosen_proposal,
				       const struct ikev2_proposals *local_proposals,
				       struct logger *logger)
{
	dbg("comparing remote proposals against %s %d local proposals",
	    what, local_proposals->roof - 1);

	passert(*chosen_proposal == NULL);

	/*
	 * The chosen proposal.  If there was a match, and no errors,
	 * it will be returned via CHOSEN_PROPOSAL (and STF_OK).
	 * Otherwise it must be freed.
	 */
	struct ikev2_proposal *best_proposal = alloc_thing(struct ikev2_proposal, "best proposal");

	/*
	 * Process and accumulate the entire set of proposals (in
	 * ascii form).
	 */
	v2_notification_t notification = v2N_NOTHING_WRONG;
	JAMBUF(remote_jam_buf) {
		int matching_local_propnum = ikev2_process_proposals(sa_payload,
								     expect_ike, expect_spi,
								     expect_accepted,
								     local_proposals,
								     best_proposal,
								     remote_jam_buf,
								     logger);

		if (matching_local_propnum < 0) {
			/*
			 * best_local_proposal is -v2_notification_t
			 * indicating corruption.
			 *
			 * Dump the proposals so far.  The detailed
			 * error reason will have already been logged.
			 */
			LLOG_JAMBUF(RC_LOG, logger, buf) {
				jam_string(buf, "partial list of remote proposals: ");
				jam_jambuf(buf, remote_jam_buf);
			}
			notification = -matching_local_propnum;
		} else if (matching_local_propnum == 0) {
			/* no luck */
			if (expect_accepted) {
				LLOG_JAMBUF(RC_LOG, logger, buf) {
					jam_string(buf, "remote accepted the invalid proposal ");
					jam_jambuf(buf, remote_jam_buf);
				}
			} else {
				LLOG_JAMBUF(RC_LOG, logger, buf) {
					jam_string(buf, "no local proposal matches remote proposals ");
					jam_jambuf(buf, remote_jam_buf);
				}
			}
			notification = v2N_NO_PROPOSAL_CHOSEN;
		} else {
			if (expect_accepted) {
				pexpect(matching_local_propnum == best_proposal->propnum);
				/* don't log on initiator's end - redundant */
				LDBGP_JAMBUF(DBG_BASE, logger, buf) {
					jam_string(buf, "remote accepted the proposal ");
					jam_jambuf(buf, remote_jam_buf);
				}
			} else {
				if (opportunistic) {
					LDBGP_JAMBUF(DBG_BASE, logger, buf) {
						jam_chosen_proposal(buf, best_proposal,
								    remote_jam_buf);
					}
				} else {
					LLOG_JAMBUF(RC_LOG, logger, buf) {
						jam_chosen_proposal(buf, best_proposal,
								    remote_jam_buf);
					}
				}
			}

			/* transfer ownership of BEST_PROPOSAL to caller */
			*chosen_proposal = best_proposal;
			best_proposal = NULL;
			notification = v2N_NOTHING_WRONG;
		}
	}

	pfreeany(best_proposal); /* only free if still owned by us */

	if (notification == v2N_NOTHING_WRONG) {
		passert(*chosen_proposal != NULL);
	} else {
		passert(*chosen_proposal == NULL);
	}

	return notification;
}

static bool emit_transform_header(struct pbs_out *proposal_pbs,
				  enum ikev2_trans_type transform_type,
				  unsigned transform_id,
				  bool is_last_transform,
				  struct pbs_out *transform_pbs)
{
	struct ikev2_trans trans = {
		.isat_type = transform_type,
		.isat_transid = transform_id,
		.isat_lt = is_last_transform ? v2_TRANSFORM_LAST : v2_TRANSFORM_NON_LAST,
	};
	if (!pbs_out_struct(proposal_pbs, &ikev2_trans_desc,
			    &trans, sizeof(trans), transform_pbs)) {
		/* already logged */
		return false; /*fatal*/
	}

	return true;
}

static bool emit_transform_attributes(struct pbs_out *transform_pbs,
				      enum ikev2_sec_proto_id protoid,
				      enum ikev2_trans_type transform_type,
				      const struct ikev2_transform *transform)
{
	enum impair_emit impair_key_length_attribute =
		(protoid == IKEv2_SEC_PROTO_IKE
		 ? impair.ike_key_length_attribute
		 : impair.child_key_length_attribute);
	if (transform_type != IKEv2_TRANS_TYPE_ENCR ||
	    impair_key_length_attribute == IMPAIR_EMIT_NO) {
		/* XXX: should be >= 0; so that '0' can be sent? */
		/* XXX: screw key-lengths for other types? */
		if (transform->attr_keylen > 0) {
			if (!v2_out_attr_fixed(transform_pbs, IKEv2_KEY_LENGTH,
					       transform->attr_keylen)) {
				return false;
			}
		}
	} else {
		switch (impair_key_length_attribute) {
		case IMPAIR_EMIT_NO:
			llog_passert(transform_pbs->outs_logger, HERE,
				     "%s", "should have been handled");
			break;
		case IMPAIR_EMIT_EMPTY:
			llog(RC_LOG, transform_pbs->outs_logger,
			     "IMPAIR: emitting variable-size key-length attribute with no key");
			if (!v2_out_attr_variable(transform_pbs, IKEv2_KEY_LENGTH, EMPTY_CHUNK)) {
				return false;
			}
			break;
		case IMPAIR_EMIT_OMIT:
			llog(RC_LOG, transform_pbs->outs_logger,
			     "IMPAIR: omitting fixed-size key-length attribute");
			break;
		case IMPAIR_EMIT_DUPLICATE:
			llog(RC_LOG, transform_pbs->outs_logger,
			     "IMPAIR: duplicating key-length attribute");
			for (unsigned dup = 0; dup < 2; dup++) {
				/* regardless of value */
				if (!v2_out_attr_fixed(transform_pbs, IKEv2_KEY_LENGTH,
						       transform->attr_keylen)) {
					return false;
				}
			}
			break;
		case IMPAIR_EMIT_ROOF:
		default:
		{
			uint16_t keylen = impair_key_length_attribute - IMPAIR_EMIT_ROOF; /* remove bias */
			llog(RC_LOG, transform_pbs->outs_logger,
			     "IMPAIR: emitting fixed-length key-length attribute with %u key", keylen);
			if (!v2_out_attr_fixed(transform_pbs, IKEv2_KEY_LENGTH, keylen)) {
				return false;
			}
			break;
		}
		}
	}
	return true;
}

static bool emit_transform(struct pbs_out *proposal_pbs,
			   enum ikev2_sec_proto_id protoid,
			   enum ikev2_trans_type transform_type,
			   bool last_transform,
			   const struct ikev2_transform *transform)
{
	struct pbs_out transform_pbs;
	if (!emit_transform_header(proposal_pbs, transform_type,
				   transform->id, last_transform,
				   &transform_pbs)) {
		return false;
	}
	if (!emit_transform_attributes(&transform_pbs, protoid,
				       transform_type, transform)) {
		return false;
	}
	close_output_pbs(&transform_pbs); /* set len */
	return true;
}

/*
 * Emit the proposal exactly as specified.
 *
 * It's assumed the caller knows what they are doing.  For instance
 * passing the correct value/size in for the SPI.
 */

static int walk_transforms(struct pbs_out *proposal_pbs, int nr_trans,
			   const struct ikev2_proposal *proposal,
			   unsigned propnum,
			   bool allow_single_transform_none,
			   struct logger *logger)
{
	const char *what = proposal_pbs != NULL ? "emitting proposal" : "counting transforms";
	/*
	 * Total up the number of transforms that will go across the
	 * wire.  Make allowance for INTEGRITY which might be
	 * excluded.
	 */
	int trans_nr = 0;
	enum ikev2_trans_type transform_type;
	const struct ikev2_transforms *transforms;
	FOR_EACH_TRANSFORMS_TYPE(transform_type, transforms, proposal) {
		/*
		 * ...=NONE should be excluded when the only transform
		 * being sent by the initiator.
		 *
		 * ...=NONE should be included when there are other
		 * transforms vis DI=NONE + DN=MODP1024.
		 *
		 * ...=NONE should be included in the response when
		 * the intiator sent NONE.
		 */
		bool multiple_transforms = (transforms->transform[0].valid &&
					    transforms->transform[1].valid);
		bool allow_transform_none = (multiple_transforms ||
					     allow_single_transform_none);
		const struct ikev2_transform *transform;
		FOR_EACH_TRANSFORM(transform, transforms) {

			enum_buf esb_type; /* same scope */
			const char *transform_type_name =
				str_enum_short(&ikev2_trans_type_names, transform_type, &esb_type);
			enum_buf esb_id; /* same scope */
			const char *transform_id_name =
				str_enum_enum_short(&v2_transform_ID_enums,
						    transform_type, transform->id, &esb_id);

			enum impair_v2_transform impairment;
			unsigned none;
			switch (transform_type) {
			case IKEv2_TRANS_TYPE_INTEG:
				/*
				 * When pluto initiates with an AEAD
				 * proposal, since INTEG=NONE is
				 * implied, that transform is excluded
				 * by default (as recommended by the
				 * RFC).
				 *
				 * When pluto receives and selects an
				 * AEAD proposal that includes
				 * INTEG=NONE it needs to include it
				 * in the accepted proposal response
				 * (as also recommended by the RFC?).
				 */
				impairment = impair.v2_proposal_integ;
				none = IKEv2_INTEG_NONE; /* always zero */
				break;
			case IKEv2_TRANS_TYPE_DH:
				/*
				 * CHILD SA proposals are allowed to
				 * include the transform DH=NONE to
				 * indicate that there is no DH.  If
				 * selected, the responder should then
				 * also include it in the response.
				 */
				impairment = impair.v2_proposal_dh;
				none = OAKLEY_GROUP_NONE; /* always zero */
				break;
			default:
				impairment = IMPAIR_v2_TRANSFORM_NO;
				none = -1; /* don't match */
				break;
			}

			switch (impairment) {
			case IMPAIR_v2_TRANSFORM_ALLOW_NONE:
				if (transform->id == none) {
					llog(RC_LOG, logger, "IMPAIR: proposal %d transform %s=%s included when %s",
						    propnum, transform_type_name, transform_id_name, what);
				}
				break;
			case IMPAIR_v2_TRANSFORM_DROP_NONE:
				if (transform->id == none) {
					llog(RC_LOG, logger, "IMPAIR: proposal %d transform %s=%s excluded when %s",
						    propnum, transform_type_name, transform_id_name, what);
					continue;
				}
				break;
			case IMPAIR_v2_TRANSFORM_OMIT:
				llog(RC_LOG, logger, "IMPAIR: proposal %d transform %s=%s excluded when %s",
					    propnum, transform_type_name, transform_id_name, what);
				continue;
			case IMPAIR_v2_TRANSFORM_NO:
				if (transform->id == none) {
					dbg("%s %s=%s when %s (multiple %d; allow single %d)",
					    allow_transform_none ? "allow" : "discard",
					    transform_type_name, transform_id_name, what,
					    multiple_transforms, allow_single_transform_none);
					if (!allow_transform_none) {
						continue;
					}
				}
				break;
			default:
				bad_case(impairment);
			}

			trans_nr++;
			if (proposal_pbs != NULL) {
				bool is_last_transform = trans_nr == nr_trans;
				if (!emit_transform(proposal_pbs, proposal->protoid,
						    transform_type, is_last_transform,
						    transform)) {
					return -1;
				}
			}
		}
	}

	const struct impair_unsigned *add_impaired_transform =
		(proposal->protoid == IKEv2_SEC_PROTO_IKE ? &impair.ikev2_add_ike_transform :
		 &impair.ikev2_add_child_transform);
	if (propnum == 1 && add_impaired_transform->enabled) {
		trans_nr++;
		if (proposal_pbs != NULL) {
			bool is_last_transform = trans_nr == nr_trans;
			unsigned type_id = add_impaired_transform->value;
			enum ikev2_trans_type transform_type = (type_id >> 16) & 0xff;
			unsigned transform_id = (type_id & 0xffff);
			enum_buf typeb, idb;
			llog(RC_LOG, logger, "IMPAIR: adding transform type %s (0x%x) id %s (0x%x)",
			     str_enum_short(&ikev2_trans_type_names, transform_type, &typeb),
			     transform_type,
			     str_enum_enum(&v2_transform_ID_enums, transform_type, transform_id, &idb),
			     transform_id);
			if (!emit_transform_header(proposal_pbs, transform_type, transform_id,
						   is_last_transform,
						   NULL/*no nested PBS*/)) {
				return -1;
			}
		}
	}

	return trans_nr;
}

static bool emit_proposal(struct pbs_out *sa_pbs,
			  const struct ikev2_proposal *proposal,
			  unsigned propnum,
			  shunk_t local_spi,
			  enum ikev2_last_proposal last_proposal,
			  bool allow_single_transform_none)
{
	int numtrans = walk_transforms(NULL, -1, proposal, propnum,
				       allow_single_transform_none, sa_pbs->outs_logger);
	if (numtrans < 0) {
		return false;
	}

	enum ikev2_sec_proto_id proposal_protoid = proposal->protoid;
	if (impair.v2_proposal_protoid.enabled) {
		enum_buf ebo, ebn;
		enum ikev2_sec_proto_id protoid = impair.v2_proposal_protoid.value;
		llog(RC_LOG, sa_pbs->outs_logger, "IMPAIR: changing proposal substructure Protocol ID from %s to %s (%u)",
		     str_enum_short(&ikev2_proposal_protocol_id_names, proposal_protoid, &ebo),
		     str_enum_short(&ikev2_proposal_protocol_id_names, protoid, &ebn),
		     protoid);
		proposal_protoid = protoid;
	}

	struct ikev2_prop prop = {
		.isap_lp = last_proposal,
		.isap_propnum = propnum,
		.isap_protoid = proposal_protoid,
		.isap_spisize = local_spi.len,
		.isap_numtrans = numtrans,
	};

	struct pbs_out proposal_pbs;
	if (!out_struct(&prop, &ikev2_prop_desc, sa_pbs, &proposal_pbs)) {
		return false;
	}

	if (local_spi.len > 0) {
		pexpect(local_spi.len == proto_spi_size(proposal->protoid));
		if (!pbs_out_hunk(&proposal_pbs, local_spi, "our spi")) {
			/* already logged */
			return false;
		}
	}

	if (walk_transforms(&proposal_pbs, numtrans, proposal, propnum,
			    allow_single_transform_none, sa_pbs->outs_logger) < 0) {
		return false;
	}

	close_output_pbs(&proposal_pbs);
	return true;
}

bool emit_v2SA_proposals(struct pbs_out *pbs,
			 const struct ikev2_proposals *proposals,
			 const shunk_t local_spi)
{
	dbg("Emitting ikev2_proposals ...");

	/* SA header out */
	struct ikev2_sa sa = {
		.isasa_critical = build_ikev2_critical(false, pbs->outs_logger),
	};
	struct pbs_out sa_pbs;
	if (!out_struct(&sa, &ikev2_sa_desc, pbs, &sa_pbs))
		return false;

	int propnum;
	const struct ikev2_proposal *proposal;
	FOR_EACH_V2_PROPOSAL(propnum, proposal, proposals) {
		/*
		 * Initiator doesn't normally send a single
		 * transform=NONE.
		 */
		if (!emit_proposal(&sa_pbs, proposal, propnum, local_spi,
				   (propnum < proposals->roof - 1
				    ? v2_PROPOSAL_NON_LAST
				    : v2_PROPOSAL_LAST),
				   false/*allow-single-transform=none*/)) {
			return false;
		}
	}

	close_output_pbs(&sa_pbs);
	return true;
}

bool emit_v2SA_proposal(struct pbs_out *pbs,
			const struct ikev2_proposal *proposal,
			shunk_t local_spi)
{
	dbg("emitting ikev2_proposal ...");
	passert(pbs != NULL);

	/* SA header out */
	struct ikev2_sa sa = {
		.isasa_critical = ISAKMP_PAYLOAD_NONCRITICAL,
	};
	struct pbs_out sa_pbs;
	if (!out_struct(&sa, &ikev2_sa_desc, pbs, &sa_pbs)) {
		return false;
	}

	/*
	 * Responder will include TRANSFORM=NONE if it was sent by the
	 * initiator.
	 */
	if (!emit_proposal(&sa_pbs, proposal, proposal->propnum,
			   local_spi, v2_PROPOSAL_LAST,
			   true/*allow-single-transform=NONE*/)) {
		return false;
	}

	close_output_pbs(&sa_pbs);
	return true;
}

bool ikev2_proposal_to_trans_attrs(const struct ikev2_proposal *proposal,
				   struct trans_attrs *ta_out, struct logger *logger)
{
	dbg("converting proposal to internal trans attrs");

	/*
	 * Start with an empty TA.
	 */
	struct trans_attrs ta = {
		.ta_encrypt = NULL,
	};

	/*
	 * blank TA_OUT, and only update it on success.
	 */
	*ta_out = ta;

	enum ikev2_trans_type type;
	const struct ikev2_transforms *transforms;
	FOR_EACH_TRANSFORMS_TYPE(type, transforms, proposal) {
		/*
		 * Accepted transform is in [0] valid proposals would
		 * be in [1...].
		 */
		pexpect(!transforms->transform[1].valid); /* zero or 1 */
		const struct ikev2_transform *transform = &transforms->transform[0];
		if (transform->valid || transform->implied) {
			switch (type) {
			case IKEv2_TRANS_TYPE_ENCR: {
				const struct encrypt_desc *encrypt =
					ikev2_get_encrypt_desc(transform->id);
				if (encrypt == NULL) {
					esb_buf buf;
					llog_pexpect(logger, HERE,
						     "accepted IKEv2 proposal contains unexpected ENCRYPT %s",
						     enum_show(&ikev2_trans_type_encr_names,
							       transform->id, &buf));
					return false;
				}
				ta.ta_encrypt = encrypt;
				ta.enckeylen = (transform->attr_keylen > 0
						? (unsigned)transform->attr_keylen
						: ta.ta_encrypt->keydeflen);
				break;
			}
			case IKEv2_TRANS_TYPE_PRF: {
				const struct prf_desc *prf = ikev2_get_prf_desc(transform->id);
				if (prf == NULL) {
					/*
					 * Since we only propose
					 * algorithms we know about so
					 * the lookup should always
					 * succeed.
					 */
					esb_buf buf;
					llog_pexpect(logger, HERE,
						     "accepted IKEv2 proposal contains unexpected PRF %s",
						     enum_show(&ikev2_trans_type_prf_names,
							       transform->id, &buf));
					return false;
				}
				ta.ta_prf = prf;
				break;
			}
			case IKEv2_TRANS_TYPE_INTEG:
			{
				const struct integ_desc *integ = ikev2_get_integ_desc(transform->id);
				if (integ == NULL) {
					/*
					 * Since we only propse
					 * algorithms we know about so
					 * the lookup should always
					 * succeed.
					 */
					esb_buf buf;
					llog_pexpect(logger, HERE,
						     "accepted IKEv2 proposal contains unexpected INTEG %s",
						     enum_show(&ikev2_trans_type_integ_names,
							       transform->id, &buf));
					return false;
				}
				ta.ta_integ = integ;
				break;
			}
			case IKEv2_TRANS_TYPE_DH: {
				const struct dh_desc *group =
					ikev2_get_dh_desc(transform->id);
				if (group == NULL) {
					/*
					 * Assuming pluto, and not the
					 * kernel, is going to do the
					 * DH calculation, then not
					 * finding the DH group is
					 * likely really bad.
					 */
					esb_buf buf;
					llog_pexpect(logger, HERE,
						     "accepted IKEv2 proposal contains unexpected DH %s",
						     enum_show(&oakley_group_names,
							       transform->id, &buf));
					return false;
				}
				ta.ta_dh = group;
				break;
			}
			case IKEv2_TRANS_TYPE_ESN:
				switch (transform->id) {
				case IKEv2_ESN_YES:
					ta.esn_enabled = true;
					break;
				case IKEv2_ESN_NO:
					ta.esn_enabled = false;
					break;
				default:
					ta.esn_enabled = false;
					llog_pexpect(logger, HERE,
						     "accepted IKEv2 proposal contains unexpected ESN %d",
						     transform->id);
					return false;
				}
				break;
			default:
				llog_pexpect(logger, HERE,
					     "accepted IKEv2 proposal contains unexpected trans type %d",
					     type);
				return false;
			}
		}
	}

	*ta_out = ta;
	return true;
}

bool ikev2_proposal_to_proto_info(const struct ikev2_proposal *proposal,
				  struct ipsec_proto_info *proto_info,
				  struct logger *logger)


{
	/*
	 * Start with ZERO for everything.
	 */
	if (!pexpect(sizeof(proto_info->outbound.spi) == proposal->remote_spi.size))
		return false;

	memcpy(&proto_info->outbound.spi, proposal->remote_spi.bytes,
	       sizeof(proto_info->outbound.spi));

	/*
	 * Use generic code to convert everything.
	 */
	struct trans_attrs ta;
	if (!ikev2_proposal_to_trans_attrs(proposal, &ta, logger)) {
		return false;
	}

	proto_info->trans_attrs = ta;
	proto_info->inbound.last_used =
	proto_info->outbound.last_used =
		realnow();

	return true;
}

static void add_missing_transform(struct ikev2_proposal *proposal,
				  const struct ikev2_proposal *accepted_proposal,
				  enum ikev2_trans_type trans_type,
				  const struct ike_alg *transform)
{
	/* fill in DH=NULL when missing */
	const struct ikev2_transform *accepted_transform =
		&accepted_proposal->transforms[trans_type].transform[0];
	if (accepted_transform->valid) {
		dbg("XXX: transform already valid for %s", transform->fqn);
		return;
	}
	dbg("XXX: adding transform %s", transform->fqn);
	append_transform(proposal, trans_type, transform->id[IKEv2_ALG_ID], 0);
}

static void force_transform(struct ikev2_proposal *proposal,
			    enum ikev2_trans_type trans_type,
			    const struct ike_alg *transform)
{
	zero_thing(proposal->transforms[trans_type]);
	append_transform(proposal, trans_type, transform->id[IKEv2_ALG_ID], 0);
}

static struct ikev2_proposals *proposals_from_accepted(const char *story,
						       const struct ikev2_proposal *accepted_proposal,
						       const struct dh_desc *default_dh,
						       bool ms_dh_downgrade/*aka add none*/,
						       struct logger *logger)
{
	struct ikev2_proposals *proposals = alloc_thing(struct ikev2_proposals, story);
	const struct dh_desc *dh[3] = {NULL}; /*[0] is ignored*/

	/*
	 * Figure out the DH; or NONE when not specified.
	 */
	unsigned dhc = 0;
	FOR_EACH_THING(d,
		       ikev2_proposal_first_dh(accepted_proposal),
		       default_dh, &ike_alg_dh_none) {
		if (d != NULL) {
			dhc++;
			PASSERT(logger, dhc < elemsof(dh));
			dh[dhc] = d;
			ldbg(logger, "XXX: using DH[%u] %s", dhc, dh[dhc]->common.fqn);
			break;
		}
	}

	/* also add ms-downgrade if needed */
	if (ms_dh_downgrade && dh[0] != &ike_alg_dh_none) {
		/* space for duplicate proposal with none */
		dhc++;
		PASSERT(logger, dhc < elemsof(dh));
		dh[dhc] = &ike_alg_dh_none;
		ldbg(logger, "XXX: using DH[%u] %s", dhc, dh[dhc]->common.fqn);
	}


	/* +1 for empty proposal[0]; */
	proposals->roof = 1 + dhc;
	proposals->proposal = alloc_things(struct ikev2_proposal, proposals->roof, story);
	/*
	 * Copy over the proposal; duplicating if necessary.
	 */
	for (int p = 1; p < proposals->roof; p++) {
		struct ikev2_proposal *proposal = &proposals->proposal[p];
		/* copy ... */
		*proposal = *accepted_proposal;
		/* reset some fields */
		proposal->propnum = 0; /* auto assign */
		zero_thing(proposal->remote_spi); /* will negotiate */
		/*
		 * Fill in INTEG=NONE and DH=NONE when there are no
		 * transforms of that type.
		 *
		 * By being present they can match a proposal that has
		 * decided to include the optional and only NONE
		 * transform (by default they are omitted when
		 * emitting the proposal).
		 */
		dbg("XXX: adding missing integ?");
		add_missing_transform(proposal, accepted_proposal,
				      IKEv2_TRANS_TYPE_INTEG,
				      &ike_alg_integ_none.common);
		/* ... and forcing DH */
		force_transform(proposal, IKEv2_TRANS_TYPE_DH, &dh[p]->common);
	}
	LDBGP_JAMBUF(DBG_BASE, logger, buf) {
		jam_string(buf, story);
		jam_string(buf, " ");
		jam_v2_proposals(buf, proposals);
	}
	return proposals;
}

void free_ikev2_proposals(struct ikev2_proposals **proposals)
{
	if (proposals == NULL || *proposals == NULL) {
		return;
	}
	pfree((*proposals)->proposal);
	pfree((*proposals));
	*proposals = NULL;
}

void free_ikev2_proposal(struct ikev2_proposal **proposal)
{
	if (proposal == NULL || *proposal == NULL) {
		return;
	}
	pfree(*proposal);
	*proposal = NULL;
}

static void append_transform(struct ikev2_proposal *proposal,
			     enum ikev2_trans_type type, unsigned id,
			     unsigned attr_keylen)
{
	struct ikev2_transforms *transforms = &proposal->transforms[type];
	/* find the end */
	struct ikev2_transform *transform;
	FOR_EACH_TRANSFORM(transform, transforms) {
	}
	/*
	 * Overflow? Since this is only called from static code and
	 * local input it can be strict.
	 */
	passert(transform < SENTINEL_TRANSFORM(transforms));
	/*
	 * Corruption?  transform+1<=sentinel from above passert.
	 */
	passert(!(transform+0)->valid);
	passert(!(transform+1)->valid);
	*transform = (struct ikev2_transform) {
		.id = id,
		.attr_keylen = attr_keylen,
		.valid = true,
	};
}

/*
 * Append one or more encrypt transforms depending on KEYLEN.
 *
 * If problems, return false.
 */
static bool append_encrypt_transform(struct ikev2_proposal *proposal,
				     const struct encrypt_desc *encrypt,
				     unsigned keylen,
				     struct logger *logger)
{
	const char *protocol = enum_name_short(&ikev2_proposal_protocol_id_names, proposal->protoid);
	if (proposal->protoid == 0 || protocol == NULL) {
		llog_pexpect(logger, HERE, "%s", "IKEv2 ENCRYPT transform protocol unknown");
		return false;
	}
	if (encrypt == NULL) {
		llog_pexpect(logger, HERE, "IKEv2 %s ENCRYPT transform has no encrypt algorithm", protocol);
		return false;
	}
	if (encrypt->common.id[IKEv2_ALG_ID] == 0) {
		llog(RC_LOG_SERIOUS, logger,
			    "IKEv2 %s %s ENCRYPT transform is not supported",
			    protocol, encrypt->common.fqn);
		return false;
	}
	if (keylen > 0 && !encrypt_has_key_bit_length(encrypt, keylen)) {
		llog_pexpect(logger, HERE, "IKEv2 %s %s ENCRYPT transform has an invalid key length of %u",
			     protocol, encrypt->common.fqn, keylen);
		return false;
	}

	if (keylen > 0) {
		append_transform(proposal, IKEv2_TRANS_TYPE_ENCR,
				 encrypt->common.id[IKEv2_ALG_ID], keylen);
	} else if (encrypt->keylen_omitted) {
		/*
		 * 3DES and NULL do not expect the key length
		 * attribute - it's redundant as there is only one
		 * valid key length.
		 */
		dbg("omitting IKEv2 %s %s ENCRYPT transform key-length",
		    protocol, encrypt->common.fqn);
		append_transform(proposal, IKEv2_TRANS_TYPE_ENCR,
				 encrypt->common.id[IKEv2_ALG_ID], 0);
	} else if (encrypt->keydeflen == encrypt_max_key_bit_length(encrypt)) {
		passert(encrypt->keydeflen > 0);
		dbg("forcing IKEv2 %s %s ENCRYPT transform key length: %u",
		    protocol, encrypt->common.fqn, encrypt->keydeflen);
		append_transform(proposal, IKEv2_TRANS_TYPE_ENCR,
				 encrypt->common.id[IKEv2_ALG_ID], encrypt->keydeflen);
	} else {
		/*
		 * XXX:
		 *
		 * Should the parser, or something else have taken
		 * care of this?  If a keylen of zero makes it all the
		 * way through to here then, isn't that the intent?
		 *
		 * The problem is that, for some algorithms, keylen=0
		 * is interpreted as propose two key-lengths.
		 * Describing that in the parser could get tricky,
		 * perhaps the info should contain an array of ENCRYPT
		 * algorithms?
		 *
		 * XXX: There's a rumor that strongswan proposes
		 * AES_000, this won't match that.
		 *
		 * Could this be better handled by searching the
		 * algorithm database for anything matching the
		 * encryption algorithm and marked as a default.
		 *
		 * Also muddying the waters is ESP that proposes a
		 * smaller key in preference to a larger one.
		 *
		 * If one of these keys turns out to be 0 or a
		 * duplicate then the worst that happens is a bogus or
		 * redundant proposal is made.
		 */
		unsigned keymaxlen = encrypt_max_key_bit_length(encrypt);
		passert(encrypt->keydeflen > 0);
		passert(keymaxlen > 0);
		/* equal handled above */
		passert(keymaxlen > encrypt->keydeflen);
		switch (proposal->protoid) {
		case IKEv2_SEC_PROTO_IKE:
			dbg("forcing IKEv2 %s %s ENCRYPT transform high-to-low key lengths: %u %u",
			    protocol, encrypt->common.fqn,
			    keymaxlen, encrypt->keydeflen);
			append_transform(proposal, IKEv2_TRANS_TYPE_ENCR,
					 encrypt->common.id[IKEv2_ALG_ID], keymaxlen);
			append_transform(proposal, IKEv2_TRANS_TYPE_ENCR,
					 encrypt->common.id[IKEv2_ALG_ID], encrypt->keydeflen);
			break;
		case IKEv2_SEC_PROTO_ESP:
			dbg("forcing IKEv2 %s %s ENCRYPT transform low-to-high key lengths: %u %u",
			    protocol, encrypt->common.fqn,
			    encrypt->keydeflen, keymaxlen);
			append_transform(proposal, IKEv2_TRANS_TYPE_ENCR,
					 encrypt->common.id[IKEv2_ALG_ID], encrypt->keydeflen);
			append_transform(proposal, IKEv2_TRANS_TYPE_ENCR,
					 encrypt->common.id[IKEv2_ALG_ID], keymaxlen);
			break;
		default:
			/* presumably AH */
			llog(RC_LOG, logger, "dropping local IKEv2 %s %s ENCRYPT transform with wrong protocol",
				    protocol, encrypt->common.fqn);
			break;
		}
	}
	return true;
}

static struct ikev2_proposal *ikev2_proposal_from_proposal_info(const struct proposal *proposal,
								enum ikev2_sec_proto_id protoid,
								struct ikev2_proposals *v2_proposals,
								const struct dh_desc *force_dh,
								const struct dh_desc *default_dh,
								struct logger *logger)
{
	/*
	 * Both initialize and empty this proposal (might
	 * contain partially constructed stuff from an earlier
	 * iteration).
	 */
	struct ikev2_proposal *v2_proposal = &v2_proposals->proposal[v2_proposals->roof];
	*v2_proposal = (struct ikev2_proposal) {
		.protoid = protoid,
		.propnum = v2_proposals->roof,
	};

	/*
	 * Encryption.
	 */
	FOR_EACH_ALGORITHM(proposal, encrypt, alg) {
		const struct encrypt_desc *encrypt = encrypt_desc(alg->desc);
		if (!append_encrypt_transform(v2_proposal, encrypt,
					      alg->enckeylen, logger)) {
			return NULL;
		}
	}

	/*
	 * PRF.
	 */
	FOR_EACH_ALGORITHM(proposal, prf, alg) {
		const struct prf_desc *prf = prf_desc(alg->desc);
		append_transform(v2_proposal, IKEv2_TRANS_TYPE_PRF,
				 prf->common.id[IKEv2_ALG_ID], 0);
	}

	/*
	 * Integrity.
	 */
	FOR_EACH_ALGORITHM(proposal, integ, alg) {
		const struct integ_desc *integ = integ_desc(alg->desc);
		/*
		 * This includes INTEG=NONE which will then be omitted
		 * when emitted, and treated as optional when
		 * accepted.
		 */
		append_transform(v2_proposal, IKEv2_TRANS_TYPE_INTEG,
				 integ->common.id[IKEv2_ALG_ID], 0);
	}

	/*
	 * DH.
	 */
	if (force_dh != NULL) {
		/*
		 * For instance, since the IKE_AUTH Child SA proposal
		 * does not include DH it is forced to NONE (the emit
		 * code then drops it).
		 *
		 * For instance, ms_dh_downgrade forces a proposal to
		 * NONE.
		 *
		 * For instance, a rekey forces the proposal to the
		 * previously negotiated DH.
		 */
		append_transform(v2_proposal, IKEv2_TRANS_TYPE_DH,
				 force_dh->common.id[IKEv2_ALG_ID], 0);
	} else if (next_algorithm(proposal, PROPOSAL_dh, NULL) != NULL) {
		/*
		 * For instance, a CREATE_CHILD_SA(NEW) proposal where
		 * DH was specified on the esp= line.
		 */
		FOR_EACH_ALGORITHM(proposal, dh, alg) {
			const struct dh_desc *dh = dh_desc(alg->desc);
			/*
			 * WHILE DH=NONE is included in the proposal it is
			 * omitted when emitted.
			 */
			append_transform(v2_proposal, IKEv2_TRANS_TYPE_DH,
					 dh->common.id[IKEv2_ALG_ID], 0);
		}
	} else if (default_dh != NULL) {
		/*
		 * For instance, either a CREATE_CHILD_SA(NEW) where
		 * the esp= line does not specify DH, or a
		 * CREATE_CHILD_SA(REKEY) for the IKE_AUTH child where
		 * DH wasn't negotiated.
		 */
		append_transform(v2_proposal, IKEv2_TRANS_TYPE_DH,
				 default_dh->common.id[IKEv2_ALG_ID], 0);
	}

	return v2_proposal;
}

/*
 * Transform the IKE proposals into something IKEv2 likes.
 *
 * If the default alg_info_ike includes unknown algorithms those get
 * dropped, which can lead to no proposals.
 */

struct ikev2_proposals *ikev2_proposals_from_proposals(enum ikev2_sec_proto_id protoid,
						       const struct proposals *proposals,
						       struct logger *logger)
{
	const char *name = enum_name_short(&ikev2_proposal_protocol_id_names, protoid);
	passert(name != NULL);
	dbg("generating IKEv2 %s proposals", name);
	passert(proposals != NULL);
	struct ikev2_proposals *v2_proposals = alloc_thing(struct ikev2_proposals, "v2 proposals");
	/* +1 as proposal[0] is empty */
	int v2_proposals_roof = nr_proposals(proposals) + 1;
	v2_proposals->proposal = alloc_things(struct ikev2_proposal,
					      v2_proposals_roof,
					      "v2 proposal");
	v2_proposals->roof = 1; /* i.e., empty: [1,1) */

	FOR_EACH_PROPOSAL(proposals, proposal) {
		LDBGP_JAMBUF(DBG_BASE, &global_logger, buf) {
			jam(buf, "converting %s proposal ", name);
			jam_proposal(buf, proposal);
			jam_string(buf, " to ikev2 ...");
		}

		passert(v2_proposals->roof < v2_proposals_roof);
		struct ikev2_proposal *v2_proposal =
			ikev2_proposal_from_proposal_info(proposal,
							  protoid,
							  v2_proposals,
							  /*force_dh*/NULL,
							  /*default_dh*/NULL,
							  logger);
		if (v2_proposal != NULL) {
			if (DBGP(DBG_BASE)) {
				DBG_log_ikev2_proposal("... ", v2_proposal);
			}
			v2_proposals->roof++;
		}
	}
	return v2_proposals;
}

static void add_esn_transforms(struct ikev2_proposal *proposal,
			       const struct connection *c)
{
	passert(!proposal->transforms[IKEv2_TRANS_TYPE_ESN].transform[0].valid);
	if (c->config->esn.yes) {
		append_transform(proposal, IKEv2_TRANS_TYPE_ESN, IKEv2_ESN_YES, 0);
	}
	if (c->config->esn.no) {
		append_transform(proposal, IKEv2_TRANS_TYPE_ESN, IKEv2_ESN_NO, 0);
	}
}

static struct ikev2_proposals *get_v2_child_proposals(struct connection *c,
						      const char *why,
						      bool strip_dh,
						      const struct dh_desc *default_dh,
						      struct logger *logger)
{
	if (!pexpect(c->config->child_sa.proposals.p != NULL)) {
		return NULL;
	}

	ldbg(logger, "constructing ESP/AH proposals for %s with strip_dh=%s ms_dh_downgrade=%s default_dh=%s",
	     why, bool_str(strip_dh), bool_str(c->config->ms_dh_downgrade),
	     default_dh->common.fqn);

	struct ikev2_proposals *v2_proposals = alloc_thing(struct ikev2_proposals,
							   "ESP/AH proposals");
	/*
	 * If necessary, allocate space for two copies of all
	 * proposals.  When MS_DH_DOWNGRADE, a second pass will add
	 * any proposals with DH with DH removed.
	 *
	 * proposal[0] is empty so +1
	 */
	unsigned nr_passes =
		(strip_dh && default_dh == &ike_alg_dh_none ? 1 :
		 c->config->ms_dh_downgrade ? 2 :
		 1);
	int v2_proposals_roof =
		1 + nr_passes * nr_proposals(c->config->child_sa.proposals.p);
	v2_proposals->proposal = alloc_things(struct ikev2_proposal, v2_proposals_roof,
					      "ESP/AH proposal");

	/* start filling it on, from 1 */
	v2_proposals->roof = 1;

	enum ikev2_sec_proto_id protoid;
	switch (c->config->child_sa.encap_proto) {
	case ENCAP_PROTO_ESP:
		protoid = IKEv2_SEC_PROTO_ESP;
		break;
	case ENCAP_PROTO_AH:
		protoid = IKEv2_SEC_PROTO_AH;
		break;
	default:
		bad_enum(logger, &encap_proto_names, c->config->child_sa.encap_proto);
	}

	/*
	 * WHen MS_DH_DOWNGRADE, first pass adds proposals verbatim,
	 * and the second pass adds proposals with NONE.
	 */

	for (unsigned pass = 1; pass <= nr_passes; pass++) {

		FOR_EACH_PROPOSAL(c->config->child_sa.proposals.p, proposal) {

			LDBGP_JAMBUF(DBG_BASE, &global_logger, log) {
				jam(log, "converting proposal ");
				jam_proposal(log, proposal);
				jam(log, " to ikev2 pass %u ...", pass);
			}

			PASSERT(logger, v2_proposals->roof < v2_proposals_roof);

			/*
			 * If the pass=1 proposal no DH, then there's
			 * no point duplicating it with no DH during
			 * pass=2.
			 */
			if (pass == 2 && default_dh == &ike_alg_dh_none &&
			    next_algorithm(proposal, PROPOSAL_dh, NULL) == NULL) {
				/*
				 * First pass didn't include DH.
				 */
				continue;
			}

			/*
			 * The first pass, when strip_dh, forces DH to
			 * the default (it is probably the IKE SAs
			 * DH).
			 *
			 * The second pass (for ms-dh-downgrade)
			 * forces the DH to &ike_alg_none.
			 */
			const struct dh_desc *force_dh =
				(pass == 2 ? &ike_alg_dh_none :
				 strip_dh ? default_dh :
				 NULL);

			struct ikev2_proposal *v2_proposal =
				ikev2_proposal_from_proposal_info(proposal,
								  protoid,
								  v2_proposals,
								  force_dh,
								  default_dh,
								  logger);
			if (v2_proposal != NULL) {
				add_esn_transforms(v2_proposal, c);
				if (DBGP(DBG_BASE)) {
					DBG_log_ikev2_proposal("... ", v2_proposal);
				}
				v2_proposals->roof++;
			}
		}
	}
	return v2_proposals;
}

/*
 * Return the first valid DH proposal that is supported.
 */

const struct dh_desc *ikev2_proposal_first_dh(const struct ikev2_proposal *proposal)
{
	const struct ikev2_transforms *transforms = &proposal->transforms[IKEv2_TRANS_TYPE_DH];
	for (unsigned t = 0; t < transforms->transform[t].valid; t++) {
		int groupnum = transforms->transform[t].id;
		const struct dh_desc *group = ikev2_get_dh_desc(groupnum);
		if (!pexpect(group != NULL)/*double-negative*/) {
			/*
			 * Things screwed up (this group should have
			 * been pruned earlier), rather than crash,
			 * continue looking for a valid group.
			 */
			continue;
		}

		if (group == &ike_alg_dh_none) {
			dbg("ignoring DH=none when looking for first DH");
			continue;
		}

		return group;
	}
	return NULL;
}

const struct dh_desc *ikev2_proposals_first_dh(const struct ikev2_proposals *proposals)
{
	int propnum;
	const struct ikev2_proposal *proposal;
	FOR_EACH_V2_PROPOSAL(propnum, proposal, proposals) {
		const struct dh_desc *dh = ikev2_proposal_first_dh(proposal);
		if (dh != NULL) {
			return dh;
		}
	}
	return NULL;
}

/*
 * Is the modp group in the proposal set?
 *
 * It's the caller's problem to check that it is actually supported.
 */
bool ikev2_proposals_include_modp(const struct ikev2_proposals *proposals,
				  oakley_group_t modp)
{
	int propnum;
	const struct ikev2_proposal *proposal;
	FOR_EACH_V2_PROPOSAL(propnum, proposal, proposals) {
		const struct ikev2_transforms *transforms = &proposal->transforms[IKEv2_TRANS_TYPE_DH];
		const struct ikev2_transform *transform;
		FOR_EACH_TRANSFORM(transform, transforms) {
			if (transform->id == modp) {
				return true;
			}
		}
	}
	dbg("no first MODP (DH) transform found");
	return false;
}

void ikev2_copy_child_spi_from_proposal(const struct ikev2_proposal *accepted_ike_proposal,
					ike_spi_t *cookie)
{
	passert(accepted_ike_proposal->remote_spi.size == COOKIE_SIZE);
	/* st_icookie is an array of len COOKIE_SIZE. only accept this length */
	memcpy(&cookie->bytes, accepted_ike_proposal->remote_spi.bytes, COOKIE_SIZE);
}

struct ikev2_proposals *get_v2_IKE_AUTH_new_child_proposals(struct connection *c)
{
	return get_v2_child_proposals(c, "loading config",
				      /*strip_dh*/true,
				      /*default_dh*/&ike_alg_dh_none,
				      c->logger);
}

/*
 * Use the CREATE_CHILD_SA proposal suite - the
 * proposal generated during IKE_AUTH will have been
 * stripped of DH.
 *
 * XXX: If the IKE SA's DH changes, then the child
 * proposals will be re-generated.  Should the child
 * proposals instead be somehow stored in state and
 * dragged around?
 */

struct ikev2_proposals *get_v2_CREATE_CHILD_SA_new_child_proposals(struct ike_sa *ike,
								   struct child_sa *larval_child)
{
	struct connection *cc = larval_child->sa.st_connection; /*not IKE's connection*/
	struct logger *logger = larval_child->sa.logger;

	const struct dh_desc *ike_dh = ike->sa.st_oakley.ta_dh;

	struct ikev2_proposals *proposals;
	if (cc->config->pfs_rekey_workaround &&
	    cc->config->child_sa.pfs) {
		/*
		 * Alternate behaviour for 5.0.
		 *
		 * When PFS, force the Child SA to use the IKE SA's
		 * DH.
		 */
		proposals = get_v2_child_proposals(cc, "new Child SA",
						   /*strip-dh*/true,
						   ike_dh, logger);
	} else if (cc->config->child_sa.pfs) {
		/*
		 * Propose the full ESP= line.  If the proposal
		 * contains no DH, use the IKE SA's DH.
		 *
		 * When the connection with PFS=YES is loaded, the
		 * proposal parser requires that all or no proposals
		 * contain DH.  This means that the below will add IKE
		 * DH to all or no proposals.
		 *
		 * This is the old 4.x behaviour.
		 */
		proposals = get_v2_child_proposals(cc, "pfs-rekey-workaround",
						   /*strip_dh*/false,
						   ike_dh, logger);
	} else {
		/*
		 * Propose the full ESP= line with no PFS.
		 *
		 * When a connection with PFS=NO is loaded, the
		 * proposal parser rejects any proposal with DH.
		 * Hence there should be none.  Regardless, explicitly
		 * strip the proposals.
		 */
		proposals = get_v2_child_proposals(cc, "new Child SA",
						   /*strip-dh*/true,
						   &ike_alg_dh_none,
						   logger);
	}

	llog_v2_proposals(LOG_STREAM/*not-whack*/|RC_LOG, logger, proposals,
			  "Child SA proposals (new child)");
	return proposals;
}

/*
 * Construct a proposal suite for rekeying the Child SA using the ESP
 * line, the previously ACCEPTED_PROPSAL, and the IKE SA's DH.
 *
 * Normally the previously ACCEPTED_PROPOSAL is used as the starting
 * point.  When it does not contain PFS, the PFS from the IKE SA's DH
 * is used.
 *
 * When MS_DH_DOWNGRADE, all proposals with non-none DH are repeated
 * with none dh.
 *
 * When PFS_REKEY_WORKAROUND, the original ESP= line, instead of the
 * accepted_proposal, is used.
 */

struct ikev2_proposals *get_v2_CREATE_CHILD_SA_rekey_child_proposals(struct ike_sa *ike,
								     struct child_sa *established_child,
								     struct logger *logger)
{
	struct connection *cc = established_child->sa.st_connection;

	/*
	 * The IKE SA's DH, when DH is required by PFS=YES, and the
	 * proposal does not specify DH, this will be used.
	 */

	const struct dh_desc *ike_dh = ike->sa.st_oakley.ta_dh;

	/*
	 * A rekeing Child SA should use the proposals accepted
	 * earlier (possibly with DH added).  Extract that as
	 * ACCEPTED_DH.
	 *
	 * Two things complicate this:
	 * - the need to possibly add DH
	 * - the need to possibly remove DH
	 */

	const struct ikev2_proposal *accepted_proposal =
		established_child->sa.st_v2_accepted_proposal;
	const struct dh_desc *accepted_dh = ikev2_proposal_first_dh(accepted_proposal);

	/*
	 * Normally, with PFS=YES, the Child SA's previously accepted
	 * proposal has ACCEPTED_DH.  The only exception is the Child
	 * SA created during IKE_AUTH.  Since DH isn't negotiated it
	 * is NULL.
	 *
	 * Since such a Child SA has PFS=YES, the proposal must ensure
	 * that DH is included when rekeying.
	 */
	bool ike_auth_child_rekey_needs_dh = (cc->config->child_sa.pfs &&
					      accepted_dh == NULL);

	/*
	 * See if the proposal contains DH.
	 *
	 * During connection load, when PFS=YES, the proposal parser
	 * requires that either ALL or NO proposals have DH.  Hence
	 * the need to only look at the first proposal.
	 */
	struct proposal *proposal = next_proposal(cc->config->child_sa.proposals.p, NULL);
	const struct algorithm *proposal_dh = next_algorithm(proposal, PROPOSAL_dh, NULL);

	struct ikev2_proposals *proposals;
	if (ike_auth_child_rekey_needs_dh && cc->config->pfs_rekey_workaround) {
		/*
		 * Use the accepted proposal but with the IKE SA's DH
		 * forced.
		 *
		 * This was >=4.6 behaviour and is off by default.
		 */
		proposals = proposals_from_accepted("rekey IKE SA CHILD",
						    accepted_proposal,
						    ike_dh,
						    cc->config->ms_dh_downgrade,
						    logger);
	} else if (ike_auth_child_rekey_needs_dh && proposal_dh == NULL) {
		/*
		 * The proposal does not include DH, but DH needs to
		 * be added as part of the rekey.
		 *
		 * Re-propose the accepted proposal but with the
		 * mising DH filled in by the IKE SA's DH.
		 *
		 * The alternative would be to re-send all the
		 * original proposals with IKE SA DH added (which was
		 * <=4.5 behaviour).
		 *
		 * This was part of >=4.6 behaviour.
		 */
		proposals = proposals_from_accepted("rekey IKE SA CHILD", accepted_proposal,
						    ike_dh,
						    cc->config->ms_dh_downgrade,
						    logger);
	} else if (ike_auth_child_rekey_needs_dh) {
		/*
		 * Since the proposals include DH, and there's no easy
		 * way of figuring out which of the proposals and DH
		 * were chosen, just re-send everything.
		 */
		PEXPECT(logger, proposal_dh != NULL);
		proposals = get_v2_child_proposals(cc, "pfs-rekey-workaround",
						   /*strip_dh*/false,
						   /*default-ignored*/&ike_alg_dh_none,
						   logger);
	} else {
		/*
		 * Use the previously accepted proposal.  If the
		 * previous proposal included DH then so too will this
		 * rekey.
		 *
		 * This behaviour is unchanged.
		 */
		PEXPECT(logger, (cc->config->child_sa.pfs == (accepted_dh != NULL)));
		proposals = proposals_from_accepted("rekey CHILD",
						    accepted_proposal,
						    &ike_alg_dh_none,
						    cc->config->ms_dh_downgrade,
						    logger);
	}

	LDBGP_JAMBUF(DBG_BASE, logger, buf) {
		jam_string(buf, "rekey CHILD ");
		jam_v2_proposals(buf, proposals);
	}
	return proposals;
}

struct ikev2_proposals *get_v2_CREATE_CHILD_SA_rekey_ike_proposals(struct ike_sa *established_ike,
								   struct logger *logger)
{
	return proposals_from_accepted("rekey IKE",
				       established_ike->sa.st_v2_accepted_proposal,
				       /*default_dh-ignored*/&ike_alg_dh_none,
				       /*ms_dh_downgrade*/false,
				       logger);
}
