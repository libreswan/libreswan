/* Security Policy Data Base/structure output
 *
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2012 Antony Antony <antony@phenome.org>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 D. Hugh Redelmeier <hugh@mimosa.com>
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
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libreswan.h>
#include "libreswan/pfkeyv2.h"

#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"	/* needs id.h */
#include "state.h"
#include "packet.h"
#include "keys.h"
#include "secrets.h"
#include "kernel.h"	/* needs connections.h */
#include "log.h"
#include "spdb.h"
#include "whack.h"	/* for RC_LOG_SERIOUS */
#include "plutoalg.h"

#include "sha1.h"
#include "md5.h"
#include "crypto.h" /* requires sha1.h and md5.h */

#include "alg_info.h"
#include "kernel_alg.h"
#include "ike_alg.h"
#include "db_ops.h"
#include "demux.h"
#include "ikev2.h"
#include "rnd.h"

#include "nat_traversal.h"

/* Taken from ikev1_spdb_struct.c, as the format is similar */
/* Note: cloned from out_attr, with the same bugs */
static bool ikev2_out_attr(enum ikev2_trans_attr_type type,
			   unsigned long val,
			   pb_stream *pbs)
{
	struct ikev2_trans_attr attr;

	/*
	 * IKEv2 the type determines the format that an attribute must
	 * use (in IKEv1 it was the value that determined this).
	 */
	switch (type) {

	case IKEv2_KEY_LENGTH:
		passert((val >> 16) == 0);
		passert((type & ISAKMP_ATTR_AF_MASK) == 0);
		/* set the short-form attribute format bit */
		attr.isatr_type = type | ISAKMP_ATTR_AF_TV;
		attr.isatr_lv = val;
		if (!out_struct(&attr, &ikev2_trans_attr_desc, pbs, NULL))
			return FALSE;
		break;

	default:
		/*
		 * Since there are no IKEv2 long-form attributes,
		 * there is no long-form code.
		 */
		bad_case(type);

	}
	return TRUE;
}

/*
 * Convert an IKEv1 HASH algorithm to IKEv2 INTEG.
 *
 * Not to be confused with converting an IKEv1 HASH algorithm to an
 * IKEv2 PRF, which is handled by ike_alg.h.
 */
static enum ikev2_trans_type_integ v1hash_to_v2integ(enum ikev1_hash_attribute hash)
{
	switch (hash) {
	case OAKLEY_MD5:
		return IKEv2_AUTH_HMAC_MD5_96;

	case OAKLEY_SHA1:
		return IKEv2_AUTH_HMAC_SHA1_96;

	case OAKLEY_SHA2_256:
		return IKEv2_AUTH_HMAC_SHA2_256_128;

	case OAKLEY_SHA2_384:
		return IKEv2_AUTH_HMAC_SHA2_384_192;

	case OAKLEY_SHA2_512:
		return IKEv2_AUTH_HMAC_SHA2_512_256;

	case OAKLEY_AES_XCBC:
		return IKEv2_AUTH_AES_XCBC_96;

	default:
		loglog(RC_LOG_SERIOUS, "IKEv1 HASH %d -> IKEv2 INTEG failed",
		       hash);
		return IKEv2_AUTH_INVALID;
	}
}

/*
 * Convert an IKEv1 (ESP/AH/CHILD) payload AUTH attribute to IKEv2
 * INTEG.
 *
 * Not to be confused with converting the IKEv1 HASH algorithm to
 * IKEv2 INTEG as performed by the above.
 */
static enum ikev2_trans_type_integ v1auth_to_v2integ(enum ikev1_auth_attribute auth)
{
	switch (auth) {
	case AUTH_ALGORITHM_HMAC_MD5:
		return IKEv2_AUTH_HMAC_MD5_96;

	case AUTH_ALGORITHM_HMAC_SHA1:
		return IKEv2_AUTH_HMAC_SHA1_96;

	case AUTH_ALGORITHM_HMAC_SHA2_256:
		return IKEv2_AUTH_HMAC_SHA2_256_128;

	case AUTH_ALGORITHM_HMAC_SHA2_384:
		return IKEv2_AUTH_HMAC_SHA2_384_192;

	case AUTH_ALGORITHM_HMAC_SHA2_512:
		return IKEv2_AUTH_HMAC_SHA2_512_256;

	case AUTH_ALGORITHM_AES_XCBC:
		return IKEv2_AUTH_AES_XCBC_96;

	default:
		loglog(RC_LOG_SERIOUS, "IKEv1 AUTH %d -> IKEv2 INTEG failed",
		       auth);
		return IKEv2_AUTH_INVALID;
	}
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
	 * Marker to indicate that the transform is valid.  The first
	 * invalid transform acts as a sentinel.
	 *
	 * Transform iterators assume that there's an extra invalid
	 * transform at the end of a transform array.
	 */
	bool valid;
};

/*
 * Upper bound on transforms-per-type.
 *
 * The transform array is declared with an extra sentinel element.
 */

struct ikev2_transforms {
	struct ikev2_transform transform[4 + 1];
};

/*
 * Transform iterator that always stops on the last (sentinel)
 * element).
 */
#define FOR_EACH_TRANSFORM(TRANSFORM,TRANSFORMS)			\
	for ((TRANSFORM) = &(TRANSFORMS)->transform[0];			\
	     (TRANSFORM)->valid && (TRANSFORM) < ((TRANSFORMS)->transform + elemsof((TRANSFORMS)->transform) - 1); \
	     (TRANSFORM)++)

struct ikev2_spi {
	uint8_t bytes[8];
	/*
	 * Number of meaningful bytes in above.
	 */
	size_t size;
};

struct ikev2_proposal {
	/*
	 * The proposal number for this proposal, or zero implying
	 * that the propnum should be auto-assigned.
	 *
	 * A chosen proposal always has a non-zero propnum.
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

struct ikev2_proposals {
	int nr;
	struct ikev2_proposal *proposal;
	bool on_heap;
};

struct print {
	size_t pos;	/* index of '\0' in buf */
	char buf[1024];
};

static struct print *print_buf()
{
	return alloc_thing(struct print, "print buf");
}

static void print_join(struct print *buf, int n)
{
	const size_t max = sizeof(buf->buf);
	/*
	 * The caller used the unsigned expression:
	 *
	 *    sizeof(buf->buf) - buf->pos
	 *
	 * to determine the amount of space left.  The below is a
	 * "better late than never" assertion that the unsigned
	 * expression didn't underflow.
	 */
	passert(buf->pos <= max);
	if (n < 0) {
		/*
		 * What else to do?
		 *
		 * A negative value either indicates an "output error"
		 * (will that happen?); or a very old, non-compliant,
		 * s*printf() implementation that returns -1 instead
		 * of the required size.
		 */
		pexpect(n >= 0);
	} else if (buf->pos + n >= max) {
		/* buffer overflow: add ... as indicator */
		strcpy(&buf->buf[max - sizeof("...")], "...");
		buf->pos = max;
	} else {
		buf->pos += n;
	}
}

static void print_string(struct print *buf, const char *string)
{
	print_join(buf, snprintf(buf->buf + buf->pos, sizeof(buf->buf) - buf->pos,
				 "%s", string));
}

static void print_value(struct print *buf, const char *prefix, int value)
{
	print_join(buf, snprintf(buf->buf + buf->pos, sizeof(buf->buf) - buf->pos,
				 "%s%d", prefix, value));
}

static void print_name_value(struct print *buf, const char *prefix,
			     const char *name, int value)
{
	print_join(buf, snprintf(buf->buf + buf->pos, sizeof(buf->buf) - buf->pos,
				 "%s%s(%d)", prefix, name, value));
}

/*
 * Pretty print a single transform to the buffer.
 */
static void print_transform(struct print *buf, const char *prefix,
			    enum ikev2_trans_type type,
			    const struct ikev2_transform *transform)
{
	print_name_value(buf, prefix,
			 enum_name(ikev2_transid_val_descs[type],
				   transform->id),
			 transform->id);
	if (transform->attr_keylen > 0) {
		print_join(buf,
			   snprintf(buf->buf + buf->pos, sizeof(buf->buf) - buf->pos,
				    "_%d", transform->attr_keylen));
	}
}

static const char *trans_type_name(enum ikev2_trans_type type)
{
	return strip_prefix(enum_name(&ikev2_trans_type_names, type), "TRANS_TYPE_");
}

static const char *protoid_name(enum ikev2_sec_proto_id protoid)
{
	return strip_prefix(enum_name(&ikev2_sec_proto_id_names, protoid),
			    "IKEv2_SEC_PROTO_");
}

/*
 * Print <TRANSFORM-TYPE> [ "=" TRANSFORM , ... ].
 */
static void print_transforms(struct print *buf, const char *prefix,
			     enum ikev2_trans_type type,
			     const struct ikev2_transforms *transforms)
{
	print_string(buf, prefix);
	print_string(buf, trans_type_name(type));
	char *sep = "=";
	const struct ikev2_transform *transform;
	FOR_EACH_TRANSFORM(transform, transforms) {
		print_transform(buf, sep, type, transform);
		sep = ",";
	};
}

void DBG_log_ikev2_proposal(const char *prefix,
			    struct ikev2_proposal *proposal)
{
	struct print *buf = print_buf();
	print_name_value(buf, "PROTOID=", protoid_name(proposal->protoid),
			 proposal->protoid);
	if (proposal->propnum > 0) {
		print_value(buf, " PROTONUM=", proposal->propnum);
	}
	if (proposal->remote_spi.size > 0) {
		pexpect(proposal->remote_spi.size <= sizeof(proposal->remote_spi.size));
		print_string(buf, " SPI=");
		size_t i;
		const char *sep = "[";
		for (i = 0; (i < proposal->remote_spi.size
			     && i < sizeof(proposal->remote_spi.size));
		     i++) {
			print_value(buf, sep, proposal->remote_spi.bytes[i]);
			sep = " ";
		}
		print_string(buf, "]");
	}
	enum ikev2_trans_type type;
	const struct ikev2_transforms *transforms;
	FOR_EACH_TRANSFORMS_TYPE(type, transforms, proposal) {
		if (transforms->transform[0].valid) {
			/* at least one transform */
			print_transforms(buf, " ", type, transforms);
		}
	}
	DBG_log("%s ikev2_proposal:%s", prefix, buf->buf);
	pfree(buf);
}

void DBG_log_ikev2_proposals(const char *prefix,
			     struct ikev2_proposals *proposals)
{
	int p;
	DBG_log("%s ikev2_proposals:", prefix);
	DBG_log("  allocation: %s", (proposals->on_heap ? "heap" : "static"));
	for (p = 0; p < proposals->nr; p++) {
		int propnum = p + 1;
		const struct ikev2_proposal *proposal = &proposals->proposal[p];
		if (proposal->propnum) {
			DBG_log("  proposal: %d (%d)", propnum, proposal->propnum);
		} else {
			DBG_log("  proposal: %d", propnum);
		}
		{
			struct print *buf = print_buf();
			print_name_value(buf, "protoid=",
					 protoid_name(proposal->protoid),
					 proposal->protoid);
			DBG_log("    %s", buf->buf);
			pfree(buf);
		}
		enum ikev2_trans_type type;
		const struct ikev2_transforms *transforms;
		FOR_EACH_TRANSFORMS_TYPE(type, transforms, proposal) {
			struct print *buf = print_buf();
			print_transforms(buf, "", type, transforms);
			DBG_log("    %s", buf->buf);
			pfree(buf);
		}
	}
}

/*
 * Compare the initiator's proposal's transforms against the first
 * NUM_LOCAL_PROPOSALS finding the earliest match.
 *
 * Return the matching proposal # (an index into
 * MATCHING_LOCAL_PROPOSALS which contains the details) or a -STF_FAIL
 * status or NUM_LOCAL_PROPOSALS for no match.
 *
 * As the remote proposal is parsed and validated, a description of it
 * is accumulated in REMOTE_PRINT_BUF.
 */

static int process_transforms(pb_stream *prop_pbs, struct print *remote_print_buf,
			      int remote_proposal_nr, int num_remote_transforms,
			      enum ikev2_sec_proto_id remote_protoid,
			      struct ikev2_proposal *local_proposals,
			      const int num_local_proposals,
			      int (*matching_local_proposals)[IKEv2_TRANS_TYPE_ROOF])
{
	DBG(DBG_CONTROL,
	    DBG_log("Comparing remote proposal %d with %d transforms against %d local proposals",
		    remote_proposal_nr, num_remote_transforms, num_local_proposals));

	lset_t transform_types_found = LEMPTY;

	/*
	 * The MATCHING_LOCAL_PROPOSALS[PROPOSAL][TYPE] table contains
	 * the index of the the best matched transform for each
	 * transform-type for each local proposal.
	 *
	 * Initially, each index is set to the proposal's
	 * transform-type's first invalid entry (making an upper-bound
	 * for searches).  If a transform matches, the index is
	 * updated (reduced) accordingly.
	 */
	{
		int local_proposal_nr;
		for (local_proposal_nr = 0;
		     local_proposal_nr < num_local_proposals;
		     local_proposal_nr++) {
			struct ikev2_proposal *local_proposal = &local_proposals[local_proposal_nr];
			enum ikev2_trans_type type;
			struct ikev2_transforms *local_transforms;
			FOR_EACH_TRANSFORMS_TYPE(type, local_transforms, local_proposal) {
				struct ikev2_transform *local_transform;
				FOR_EACH_TRANSFORM(local_transform, local_transforms) {
					matching_local_proposals[local_proposal_nr][type]++;
				};
				DBG(DBG_CONTROLMORE,
				    DBG_log("local proposal %d type %s has %d transforms",
					    local_proposal_nr, trans_type_name(type),
					    matching_local_proposals[local_proposal_nr][type]));
			}
		}
	}

	/*
	 * Track the first integrity transform's transID.  Needed to
	 * check for a mixup of NULL and non-NULL integrity
	 * transforms.
	 *
	 * Since 0 (NULL) is a valid integrity transID value, start
	 * with -1.
	 */
	int first_integrity_transid = -1;
	const char *remote_buf_prefix = "";

	int remote_transform_nr;
	for (remote_transform_nr = 0;
	     remote_transform_nr < num_remote_transforms;
	     remote_transform_nr++) {

		/* first the transform */
		struct ikev2_trans remote_trans;
		pb_stream trans_pbs;
		if (!in_struct(&remote_trans, &ikev2_trans_desc,
			       prop_pbs, &trans_pbs)) {
			libreswan_log("remote proposal %d transform %d is corrupt",
				      remote_proposal_nr, remote_transform_nr);
			print_string(remote_print_buf, "[corrupt-transform]");
			return -(STF_FAIL + v2N_INVALID_SYNTAX); /* bail */
		}

		struct ikev2_transform remote_transform = {
			.id = remote_trans.isat_transid,
			.valid = TRUE,
		};
		enum ikev2_trans_type type = remote_trans.isat_type;

		/* followed by attributes */
		while (pbs_left(&trans_pbs) != 0) {
			pb_stream attr_pbs;
			struct ikev2_trans_attr attr;
			if (!in_struct(&attr, &ikev2_trans_attr_desc,
				       &trans_pbs,
				       &attr_pbs)) {
				libreswan_log("remote proposal %d transform %d contains corrupt attribute",
					      remote_proposal_nr, remote_transform_nr);
				print_string(remote_print_buf, "[corrupt-attribute]");
				return -(STF_FAIL + v2N_INVALID_SYNTAX); /* bail */
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
				libreswan_log("remote proposal %d transform %d has unknown attribute %d or unexpeced attribute encoding",
					      remote_proposal_nr, remote_transform_nr,
					      attr.isatr_type & ISAKMP_ATTR_RTYPE_MASK);
				print_string(remote_print_buf, "[unknown-attribute]");
				return num_local_proposals; /* try next proposal */
			}
		}

		/*
		 * Detect/reject things like: INTEG=NULL INTEG=HASH
		 * INTEG=NULL
		 */
		if (type == IKEv2_TRANS_TYPE_INTEG) {
			if (first_integrity_transid < 0) {
				first_integrity_transid = remote_trans.isat_transid;
			} else if (first_integrity_transid == 0 || remote_trans.isat_transid == 0) {
				libreswan_log("remote proposal %d transform %d has too much NULL integrity %d %d",
					      remote_proposal_nr, remote_transform_nr,
					      first_integrity_transid, remote_trans.isat_transid);
				print_string(remote_print_buf, "[mixed-integrity]");
				return num_local_proposals; /* try next proposal */
			}
		}

		/* Remember each transform type found. */
		transform_types_found |= LELEM(type);

		/*
		 * Accumulate the proposal's transforms in remote_buf.
		 */
		print_transform(remote_print_buf, remote_buf_prefix,
				type, &remote_transform);
		remote_buf_prefix = ",";

		/*
		 * Find the proposals that match and flag them.
		 */
		int local_proposal_nr;
		for (local_proposal_nr = 0; local_proposal_nr < num_local_proposals; local_proposal_nr++) {
			struct ikev2_proposal *local_proposal = &local_proposals[local_proposal_nr];
			if (local_proposal->protoid == remote_protoid) {
				/*
				 * Search the proposal for transforms of this
				 * type that match.  Limit the search to
				 * transforms before the last match.
				 */
				struct ikev2_transforms *local_transforms = &local_proposal->transforms[type];
				struct ikev2_transform *local_transform;
				FOR_EACH_TRANSFORM(local_transform, local_transforms) {
					int local_transform_nr = local_transform - local_transforms->transform;
					if (local_transform_nr >= matching_local_proposals[local_proposal_nr][type]) {
						break;
					}
					if (local_transform->id == remote_transform.id
					    && local_transform->attr_keylen == remote_transform.attr_keylen) {
						DBG(DBG_CONTROLMORE,
						    struct print *buf = print_buf();
						    print_transform(buf, "", type, &remote_transform);
						    DBG_log("remote proposal %d transform %d (%s) matches local proposal %d transform %d",
							    remote_proposal_nr, remote_transform_nr,
							    buf->buf, local_proposal_nr, local_transform_nr);
						    pfree(buf));
						matching_local_proposals[local_proposal_nr][type] = local_transform_nr;
						break;
					}
				}
			}
		}
	}

	/* XXX: Use a set to speed up the comparison?  */
	int local_proposal_nr;
	for (local_proposal_nr = 0; local_proposal_nr < num_local_proposals; local_proposal_nr++) {
		struct ikev2_proposal *local_proposal = &local_proposals[local_proposal_nr];
		DBG(DBG_CONTROLMORE, DBG_log("Seeing if local proposal %d matched", local_proposal_nr));
		enum ikev2_trans_type type;
		struct ikev2_transforms *local_transforms;
		FOR_EACH_TRANSFORMS_TYPE(type, local_transforms, local_proposal) {
			/*
			 * HACK to allow missing NULL integrity:
			 * 
			 * If the proposal lacks integrity and the
			 * only local transform is null-integrity then
			 * ignore the problem.  Presumably all the
			 * local auth transforms are AEAD and so will
			 * only match something valid.
			 */
			if (type == IKEv2_TRANS_TYPE_INTEG
			    && !(transform_types_found & LELEM(type))
			    && local_transforms->transform[0].valid
			    && !local_transforms->transform[1].valid
			    && local_transforms->transform[0].id == 0) {
				DBG(DBG_CONTROL, DBG_log("allowing no NULL integrity"));
				continue;
			}
			int type_proposed = ((transform_types_found & LELEM(type)) != 0);
			int type_matched = local_transforms->transform[matching_local_proposals[local_proposal_nr][type]].valid;
			if (type_proposed != type_matched) {
				DBG(DBG_CONTROLMORE, DBG_log("local proposal %d type %s failed: %s and %s",
							     local_proposal_nr, trans_type_name(type),
							     type_proposed ? "proposed" : "not-proposed",
							     type_matched ? "matched" : "not-matched"));
				break;
			}
		}
		/* loop finished? */
		if (type == IKEv2_TRANS_TYPE_ROOF) {
			DBG(DBG_CONTROL,
			    DBG_log("remote proposal %d matches local proposal %d",
				    remote_proposal_nr, local_proposal_nr));
			return local_proposal_nr;
		}
	}

	DBG(DBG_CONTROL, DBG_log("Remote proposal %d matches no local proposals", remote_proposal_nr));
	return num_local_proposals;
}

static size_t proto_spi_size(enum ikev2_sec_proto_id protoid)
{
	switch (protoid) {
	case IKEv2_SEC_PROTO_IKE:
		return 8;
	case IKEv2_SEC_PROTO_AH:
	case IKEv2_SEC_PROTO_ESP:
		return 4;
	default:
		return 0;
	}
}


/*
 * Compare all remote proposals against all local proposals finding
 * and returning the "first" local proposal to match.
 *
 * The need to load all the remote proposals into buffers is avoided
 * by processing them in a single.  This is a tradeoff.  Since each
 * remote proposal in turn is compared against all local proposals
 * (and not each local proposal in turn compared against all remote
 * proposals) a local proposal matching only the last remote proposal
 * takes more comparisons.  Othe other and mallocing an pointer
 * jugging is avoided.
 */
stf_status ikev2_process_sa_payload(const char *what,
				    pb_stream *sa_payload,
				    bool ike, bool initial, bool accepted,
				    struct ikev2_proposal **chosen_proposal,
				    struct ikev2_proposals *local_proposals)
{
	DBG(DBG_CONTROL, DBG_log("Comparing remote proposals against %s %d local proposals",
				 what, local_proposals->nr));

	/*
	 * The chosen proposal.  If there was a match, and no errors,
	 * it will be returned via CHOSEN_PROPOSAL (and STF_OK).
	 * Otherwise it must be freed.
	 */
	struct ikev2_proposal *best_proposal = alloc_thing(struct ikev2_proposal, "best proposal");

	/*
	 * Array to track best proposals/transforms.
	 *
	 * Must be freed.
	 */
	int (*matching_local_proposals)[IKEv2_TRANS_TYPE_ROOF];
	matching_local_proposals = alloc_bytes(sizeof(matching_local_proposals[0]) * local_proposals->nr,
					       "matching_local_proposals");

	/*
	 * Buffer to accumulate the entire proposal (in ascii form).
	 *
	 * Must be freed.
	 */
	struct print *remote_proposals_buf = print_buf();

	/*
	 * This loop contains no "return" statements.  Instead it
	 * always enters at the top and exits at the bottom.  This
	 * simplfies the dealing with buffers allocated above.
	 *
	 * On loop exit, the result is one of:
	 *
	 *    -ve - the STF_FAIL status
	 *    [0..LOCAL_PROPOSALS->NR) - chosen proposal
	 *    LOCAL_PROPOSALS->NR - no proposal chosen
	 */
	int best_local_proposal = local_proposals->nr;
	int next_propnum = 1;
	struct ikev2_prop remote_proposal;
	do {
		/* Read the next proposal */
		pb_stream proposal_pbs;
		if (!in_struct(&remote_proposal, &ikev2_prop_desc, sa_payload,
			       &proposal_pbs)) {
			libreswan_log("proposal %d corrupt", next_propnum);
			print_string(remote_proposals_buf, " [corrupt-proposal]");
			best_local_proposal = -(STF_FAIL + v2N_INVALID_SYNTAX);
			break;
		}
		print_string(remote_proposals_buf, " ");
		print_string(remote_proposals_buf, protoid_name(remote_proposal.isap_protoid));
		print_string(remote_proposals_buf, ":");

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
		if (accepted) {
			/* There can be only one accepted proposal.  */
			if (remote_proposal.isap_lp != v2_PROPOSAL_LAST) {
				libreswan_log("Error: more than one proposal received.");
				print_string(remote_proposals_buf, "[too-many-proposals]");
				best_local_proposal = -(STF_FAIL + v2N_INVALID_SYNTAX);
				break;
			}
		} else {
			if (next_propnum != remote_proposal.isap_propnum) {
				libreswan_log("proposal number was %u but %u expected",
					      remote_proposal.isap_propnum,
					      next_propnum);
				print_string(remote_proposals_buf, "[wrong-protonum]");
				best_local_proposal = -(STF_FAIL + v2N_INVALID_SYNTAX);
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
		if (ike && remote_proposal.isap_protoid != IKEv2_SEC_PROTO_IKE) {
			libreswan_log("proposal %d has unexpected Protocol ID %d, expected IKE",
				      remote_proposal.isap_propnum,
				      (unsigned)remote_proposal.isap_protoid);
			print_string(remote_proposals_buf, "[unexpected-protoid]");
			continue;
		}

		/*
		 * Validate the Security Parameter Index (SPI):
		 *
		 * RFC 7296: 3.3.1. Proposal Substructure: For an
		 * initial IKE SA negotiation, this field MUST be
		 * zero; the SPI is obtained from the outer header.
		 * During subsequent negotiations, it is equal to the
		 * size, in octets, of the SPI of the corresponding
		 * protocol (8 for IKE, 4 for ESP and AH).
		 */
		/* Read any SPI.  */
		struct ikev2_spi remote_spi = {
			.size = (initial ? 0 : proto_spi_size(remote_proposal.isap_protoid)), 
		};
		if (!initial && remote_spi.size == 0) {
			libreswan_log("proposal %d has unrecognized Protocol ID %u; ignored",
				      remote_proposal.isap_propnum,
				      (unsigned)remote_proposal.isap_protoid);
			print_string(remote_proposals_buf, "[unknown-protocol]");
			continue;
		}
		if (remote_proposal.isap_spisize > sizeof(remote_spi.bytes)) {
			libreswan_log("proposal %d has huge SPI size (%u); ignored",
				      remote_proposal.isap_propnum,
				      (unsigned)remote_proposal.isap_spisize);
			print_string(remote_proposals_buf, "[spi-huge]");
			/* best_local_proposal = -(STF_FAIL + v2N_INVALID_SYNTAX); */
			continue;
		}
		if (remote_proposal.isap_spisize != remote_spi.size) {
			libreswan_log("proposal %d has incorrect SPI size (%u), expected %zd; ignored",
				      remote_proposal.isap_propnum,
				      (unsigned)remote_proposal.isap_spisize,
				      remote_spi.size);
			print_string(remote_proposals_buf, "[spi-size]");
			/* best_local_proposal = -(STF_FAIL + v2N_INVALID_SYNTAX); */
			continue;
		}
		if (remote_spi.size > 0) {
			if (!in_raw(remote_spi.bytes, remote_spi.size, &proposal_pbs, "remote SPI")) {
				libreswan_log("proposal %d contains corrupt SPI",
					      remote_proposal.isap_propnum);
				best_local_proposal = -(STF_FAIL + v2N_INVALID_SYNTAX);
				print_string(remote_proposals_buf, "[corrupt-spi]");
				break;
			}
		}

		int match = process_transforms(&proposal_pbs, remote_proposals_buf,
					       remote_proposal.isap_propnum,
					       remote_proposal.isap_numtrans,
					       remote_proposal.isap_protoid,
					       local_proposals->proposal,
					       best_local_proposal,
					       matching_local_proposals);
		if (match < 0) {
			/* capture the error and bail */
			best_local_proposal = match;
			break;
		} else if (match < best_local_proposal) {
			/* mark what happend */
			if (best_local_proposal == local_proposals->nr) {
				/* good */
				print_string(remote_proposals_buf, "[match]");
			} else {
				/* better */
				print_string(remote_proposals_buf, "[better-match]");
			}
			/* capture the new best proposal  */
			best_local_proposal = match;
			/* blat best with a new value */
			*best_proposal = (struct ikev2_proposal) {
				.propnum = remote_proposal.isap_propnum,
				.protoid = remote_proposal.isap_protoid,
				.remote_spi = remote_spi,
			};
			enum ikev2_trans_type type;
			struct ikev2_transforms *best_transforms;
			FOR_EACH_TRANSFORMS_TYPE(type, best_transforms, best_proposal) {
				int tt = matching_local_proposals[best_local_proposal][type];
				struct ikev2_transform *matching_transform = &local_proposals->proposal[best_local_proposal].transforms[type].transform[tt];
				if (matching_transform->valid) {
					best_transforms->transform[0] = *matching_transform;
				}
			}
		} else {
			/* no improvement */
			passert(match == best_local_proposal);
		}

	} while (remote_proposal.isap_lp == v2_PROPOSAL_NON_LAST);

	stf_status status;
	if (best_local_proposal < 0) {
		/*
		 * best_local_proposal is -STF_FAIL status indicating
		 * corruption.
		 *
		 * Dump the proposal so far.  The detailed error
		 * reason will have already been logged.
		 */
		libreswan_log("parsed proposals: %s", remote_proposals_buf->buf);
		status = -best_local_proposal;
	} else if (best_local_proposal >= local_proposals->nr) {
		/* no luck */
		libreswan_log("no proposals matched: %s", remote_proposals_buf->buf);
		status = STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
	} else {
		/*
		 * For the moment don't libreswan_log() this as it
		 * gets written to the console, altering output, and
		 * causing test noise.
		 */
		DBG(DBG_CONTROL, DBG_log("proposals: %s", remote_proposals_buf->buf));
		/* transfer ownership of BEST_PROPOSAL to caller */
		*chosen_proposal = best_proposal;
		best_proposal = NULL;
		status = STF_OK;
	}

	pfree(matching_local_proposals);
	pfreeany(best_proposal); /* only free if still owned by us */
	pfree(remote_proposals_buf);

	return status;
}

static bool emit_transform(pb_stream *r_proposal_pbs,
			   enum ikev2_trans_type type, bool last,
			   struct ikev2_transform *transform)
{
	struct ikev2_trans trans = {
		.isat_type = type,
		.isat_transid = transform->id,
		.isat_lt = last ? v2_TRANSFORM_LAST : v2_TRANSFORM_NON_LAST,
	};
	pb_stream trans_pbs;
	if (!out_struct(&trans, &ikev2_trans_desc,
			r_proposal_pbs, &trans_pbs)) {
		libreswan_log("out_struct() of transform failed");
		return FALSE;
	}
	if (transform->attr_keylen > 0) {
		if (!ikev2_out_attr(IKEv2_KEY_LENGTH,
				    transform->attr_keylen,
				    &trans_pbs)) {
			libreswan_log("ikev2_out_attr() of transfor attribute failed");
			return FALSE;
		}
	}
	close_output_pbs(&trans_pbs); /* set len */
	return TRUE;
}

/*
 * Emit the proposal exactly as specified.
 *
 * It's assumed the caller knows what they are doing.  For instance
 * passing the correct value/size in for the SPI.
 */
static bool emit_proposal(pb_stream *sa_pbs, struct ikev2_proposal *proposal,
			  unsigned propnum, chunk_t *local_spi,
			  enum ikev2_last_proposal last_proposal)
{
	int numtrans = 0;
	enum ikev2_trans_type type;
	struct ikev2_transforms *transforms;

	FOR_EACH_TRANSFORMS_TYPE(type, transforms, proposal) {
		struct ikev2_transform *transform;
		FOR_EACH_TRANSFORM(transform, transforms) {
			numtrans++;
		}
	}
	struct ikev2_prop prop = {
		.isap_lp = last_proposal,
		.isap_propnum = propnum,
		.isap_protoid = proposal->protoid,
		.isap_spisize = (local_spi != NULL ? local_spi->len : 0),
		.isap_numtrans = numtrans,
	};

	pb_stream proposal_pbs;
	if (!out_struct(&prop, &ikev2_prop_desc, sa_pbs, &proposal_pbs)) {
		return FALSE;
	}

	if (local_spi != NULL) {
		pexpect(local_spi->len > 0);
		pexpect(local_spi->len == proto_spi_size(proposal->protoid));
		if (!out_chunk(*local_spi, &proposal_pbs, "our spi"))
			return FALSE;
	}

	FOR_EACH_TRANSFORMS_TYPE(type, transforms, proposal) {
		struct ikev2_transform *transform;
		FOR_EACH_TRANSFORM(transform, transforms) {
			bool last = --numtrans == 0;
			if (!emit_transform(&proposal_pbs, type, last, transform))
				return FALSE;
		}
	}
	close_output_pbs(&proposal_pbs);
	return TRUE;
}

bool ikev2_emit_sa_proposals(pb_stream *pbs,
			     struct ikev2_proposals *proposals,
			     chunk_t *local_spi,
			     enum next_payload_types_ikev2 next_payload_type)
{
	DBG(DBG_CONTROL, DBG_log("Emitting ikev2_proposals ..."));

	/* SA header out */
	struct ikev2_sa sa = {
		.isasa_np = next_payload_type,
		.isasa_critical = ISAKMP_PAYLOAD_NONCRITICAL,
	};
	if (DBGP(IMPAIR_SEND_BOGUS_PAYLOAD_FLAG)) {
		libreswan_log(" setting bogus ISAKMP_PAYLOAD_LIBRESWAN_BOGUS flag in ISAKMP payload");
		sa.isasa_critical |= ISAKMP_PAYLOAD_LIBRESWAN_BOGUS;
	}
	pb_stream sa_pbs;
	if (!out_struct(&sa, &ikev2_sa_desc, pbs, &sa_pbs))
		return FALSE;

	int lp;
	for (lp = 0; lp < proposals->nr; lp++) {
		struct ikev2_proposal *proposal = &proposals->proposal[lp];
		unsigned propnum = lp + 1;
		if (!emit_proposal(&sa_pbs, proposal, propnum, local_spi,
				   (lp < proposals->nr - 1
				    ? v2_PROPOSAL_NON_LAST
				    : v2_PROPOSAL_LAST))) {
			return FALSE;
		}
	}

	close_output_pbs(&sa_pbs);
	return TRUE;
}

bool ikev2_emit_sa_proposal(pb_stream *pbs, struct ikev2_proposal *proposal,
			    chunk_t *local_spi,
			    enum next_payload_types_ikev2 next_payload_type)
{
	DBG(DBG_CONTROL, DBG_log("Emitting ikev2_proposal_proposal ..."));
	passert(pbs != NULL);

	/* SA header out */
	struct ikev2_sa sa = {
		.isasa_np = next_payload_type,
		.isasa_critical = ISAKMP_PAYLOAD_NONCRITICAL,
	};
	pb_stream sa_pbs;
	if (!out_struct(&sa, &ikev2_sa_desc, pbs, &sa_pbs)) {
		return FALSE;
	}

	if (!emit_proposal(&sa_pbs, proposal, proposal->propnum,
			   local_spi, v2_PROPOSAL_LAST)) {
		return FALSE;
	}

	close_output_pbs(&sa_pbs);
	return TRUE;
}

struct trans_attrs ikev2_proposal_to_trans_attrs(struct ikev2_proposal *proposal)
{
	DBG(DBG_CONTROL, DBG_log("converting proposal to internal trans attrs"));
	struct trans_attrs ta = { .encrypt = 0 };
	enum ikev2_trans_type type;
	struct ikev2_transforms *transforms;
	FOR_EACH_TRANSFORMS_TYPE(type, transforms, proposal) {
		pexpect(!transforms->transform[1].valid); /* zero or 1 */
		if (transforms->transform[0].valid) {
			struct ikev2_transform *transform = transforms->transform;
			switch (type) {
			case IKEv2_TRANS_TYPE_ENCR:
				ta.encrypt = transform->id;
				ta.enckeylen = transform->attr_keylen;
				ta.encrypter = (struct encrypt_desc *)ikev2_alg_find(IKE_ALG_ENCRYPT,
										     ta.encrypt);
				if (ta.encrypter == NULL) {
					/* everything should be in alg_info.  */
					DBG(DBG_CONTROLMORE,
					    DBG_log("ikev2_alg_find(IKG_ALG_ENCRYPT,%d) failed, assuming ESP/AH",
						    ta.encrypt));
				}
				if (ta.enckeylen <= 0) {
					if (ta.encrypter != NULL) {
						ta.enckeylen = ta.encrypter->keydeflen;
					} else {
						DBG(DBG_CONTROL,
						    DBG_log("unknown key size for ENCRYPT algorithm %d",
							    ta.encrypt));
					}
				}
			break;
			case IKEv2_TRANS_TYPE_PRF:
				ta.prf_hash = transform->id;
				ta.prf_hasher = (struct hash_desc *)ikev2_alg_find(IKE_ALG_HASH,
										   ta.prf_hash);
				if (ta.prf_hasher == NULL) {
					/* everything should be in alg_info.  */
					DBG(DBG_CONTROLMORE,
					    DBG_log("ikev2_alg_find(IKG_ALG_HASH,%d) failed, assuming ESP/AH",
						    ta.prf_hash));
				}
				break;
			case IKEv2_TRANS_TYPE_INTEG:
				if (transform->id == 0) {
					/*passert(ikev2_encr_aead(proposal->transforms[IKEv2_TRANS_TYPE_ENCR].id);*/
					DBG(DBG_CONTROL, DBG_log("ignoring NULL integrity"));
				} else {
					ta.integ_hash = transform->id;
					ta.integ_hasher = (struct hash_desc *)ikev2_alg_find(IKE_ALG_INTEG,
											     ta.integ_hash);
					if (ta.integ_hasher == NULL) {
						/* everything should be in alg_info.  */
						DBG(DBG_CONTROLMORE,
						    DBG_log("ikev2_alg_find(IKG_ALG_INTEG,%d) failed, assuming ESP/AH",
							    ta.integ_hash));
					}
				}
				break;
			case IKEv2_TRANS_TYPE_DH:
				ta.groupnum = transform->id;
				ta.group = lookup_group(ta.groupnum);
				if (ta.group == NULL) {
					/*
					 * Assuming pluto, and not the
					 * kernel, is going to do the
					 * DH calculation, then not
					 * finding the DH group is
					 * likely really bad.
					 *
					 * Stumble on as caller will
					 * quickly passert.
					 */
					DBG(DBG_CONTROLMORE,
					    DBG_log("lookup_group(%d) failed",
						    ta.integ_hash));
				}
				break;
			case IKEv2_TRANS_TYPE_ESN:
				switch (transform->id) {
				case IKEv2_ESN_ENABLED:
					ta.esn_enabled = TRUE;
					break;
				case IKEv2_ESN_DISABLED:
					ta.esn_enabled = FALSE;
					break;
				default:
					ta.esn_enabled = FALSE;
					loglog(RC_LOG_SERIOUS, "accepted proposal contains invalid ESN %d",
					       transform->id);
					break;
				}
				break;
			default:
				bad_case(type);
			}
		}
	}
	return ta;
}

bool ikev2_proposal_to_proto_info(struct ikev2_proposal *proposal,
				  struct ipsec_proto_info *proto_info)
{
	/*
	 * Quick hack to convert much of the stuff.
	 */
	struct trans_attrs ta = ikev2_proposal_to_trans_attrs(proposal);

	pexpect(sizeof(proto_info->attrs.spi) == proposal->remote_spi.size);
	memcpy(&proto_info->attrs.spi, proposal->remote_spi.bytes,
	       sizeof(proto_info->attrs.spi));

	/*
	 * This is REALLY not correct, because this is not an IKE
	 * algorithm
	 *
	 * XXX maybe we can leave this to ikev2 child key derivation
	 */
	DBG_log("XXX: All algorithms should be in our database, even when not implemented");
	if (proposal->protoid == IKEv2_SEC_PROTO_ESP) {
		if (ta.encrypter != NULL) {
			err_t ugh;
			ugh = check_kernel_encrypt_alg(ta.encrypt, ta.enckeylen);
			if (ugh != NULL) {
				libreswan_log("ESP algo %d with key_len %d is not valid (%s)", ta.encrypt, ta.enckeylen, ugh);
				/*
				 * Only realising that the algorithm
				 * is invalid now is pretty lame!
				 */
				return FALSE;
			}
		} else {
			/*
			 * We did not find a userspace encrypter, so
			 * we should be esp=null or a kernel-only
			 * algorithm without userland struct.
			 */
			switch(ta.encrypt) {
			case IKEv2_ENCR_NULL:
				break; /* ok */
			case IKEv2_ENCR_CAST:
				break; /* CAST is ESP only, not IKE */
			case IKEv2_ENCR_AES_CTR:
			case IKEv2_ENCR_CAMELLIA_CTR:
			case IKEv2_ENCR_CAMELLIA_CCM_A:
			case IKEv2_ENCR_CAMELLIA_CCM_B:
			case IKEv2_ENCR_CAMELLIA_CCM_C:
				/* no IKE struct encrypt_desc yet */
				/* FALL THROUGH */
			case IKEv2_ENCR_AES_CBC:
			case IKEv2_ENCR_CAMELLIA_CBC:
			case IKEv2_ENCR_CAMELLIA_CBC_ikev1: /* IANA ikev1/ipsec-v3 fixup */
				/* these all have mandatory key length attributes */
				if (ta.enckeylen == 0) {
					loglog(RC_LOG_SERIOUS, "Missing mandatory KEY_LENGTH attribute - refusing proposal");
					return FALSE;
				}
				break;
			default:
				loglog(RC_LOG_SERIOUS, "Did not find valid ESP encrypter for %d - refusing proposal", ta.encrypt);
				pexpect(ta.encrypt == IKEv2_ENCR_NULL); /* fire photon torpedo! */
				return FALSE;
			}
		}
	}

	/*
	 * this is really a mess having so many different numbers for
	 * auth algorithms.
	 */
	proto_info->attrs.transattrs = ta;

	/*
	 * here we obtain auth value for esp, but lose what is correct
	 * to be sent in the proposal
	 */
	proto_info->attrs.transattrs.integ_hash = alg_info_esp_v2tov1aa(ta.integ_hash);
	proto_info->present = TRUE;
	proto_info->our_lastused = mononow();
	proto_info->peer_lastused = mononow();

	proto_info->attrs.encapsulation = ENCAPSULATION_MODE_TUNNEL;

	return TRUE;
}

void free_ikev2_proposals(struct ikev2_proposals **proposals)
{
	if (proposals == NULL || *proposals == NULL) {
		return;
	}
	if ((*proposals)->on_heap) {
		pfree((*proposals)->proposal);
		pfree((*proposals));
	}
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
	FOR_EACH_TRANSFORM(transform, transforms) { }
	pexpect(!transform->valid);
	*transform = (struct ikev2_transform) {
		.id = id,
		.attr_keylen = attr_keylen,
		.valid = TRUE,
	};
}

/*
 * Define macros to save some typing, perhaps avoid some duplication
 * errors, and ease the pain of occasionally rearanging these data
 * structures.
 */

#define ENCR_AES_CBC_128 { .id = IKEv2_ENCR_AES_CBC, .attr_keylen = 128, .valid = TRUE, }
#define ENCR_AES_CBC_256 { .id = IKEv2_ENCR_AES_CBC, .attr_keylen = 256, .valid = TRUE, }
#define ENCR_AES_GCM16_128 { .id = IKEv2_ENCR_AES_GCM_8, .attr_keylen = 128, .valid = TRUE, }
#define ENCR_AES_GCM16_256 { .id = IKEv2_ENCR_AES_GCM_16, .attr_keylen = 256, .valid = TRUE, }
#define ENCR_3DES { .id = IKEv2_ENCR_3DES, .valid = TRUE, }

#define PRF_SHA2_256 { .id = IKEv2_PRF_HMAC_SHA2_256, .valid = TRUE, }
#define PRF_AES128_XCBC { .id = IKEv2_PRF_AES128_XCBC, .valid = TRUE, }
#define PRF_SHA1 { .id = IKEv2_PRF_HMAC_SHA1, .valid = TRUE, }
#define PRF_MD5 { .id = IKEv2_PRF_HMAC_MD5, .valid = TRUE, }

#define AUTH_NONE { .id = IKEv2_AUTH_NONE, .valid = TRUE, }
#define AUTH_SHA2_256_128 { .id = IKEv2_AUTH_HMAC_SHA2_256_128, .valid = TRUE, }
#define AUTH_AES_XCBC_96 { .id = IKEv2_AUTH_AES_XCBC_96, .valid = TRUE, }
#define AUTH_SHA1_96 { .id = IKEv2_AUTH_HMAC_SHA1_96, .valid = TRUE, }
#define AUTH_MD5_96 { .id = IKEv2_AUTH_HMAC_MD5_96, .valid = TRUE, }

#define DH_MODP1536 { .id = OAKLEY_GROUP_MODP1536, .valid = TRUE, }
#define DH_MODP2048 { .id = OAKLEY_GROUP_MODP2048, .valid = TRUE, }
#define DH_MODP4096 { .id = OAKLEY_GROUP_MODP4096, .valid = TRUE, }
#define DH_MODP8192 { .id = OAKLEY_GROUP_MODP8192, .valid = TRUE, }

#define ESN_NO { .id = IKEv2_ESN_DISABLED, .valid = TRUE, }
#define ESN_YES { .id = IKEv2_ESN_ENABLED, .valid = TRUE, }

#define TR(T, ...) { .transform = { T, __VA_ARGS__ } }

static struct ikev2_proposal default_ikev2_ike_proposal[] = {
	/*
	 * IKEv2 proposal #0:
	 * AES_GCM[256]
	 * NULL
	 * SHA1,SHA2_256
	 * MODP2048, MODP4096, MODP8192
	 *
	 * Note: Strongswan cherry-picks proposals (for instance will
	 * pick AES_128 over AES_256 when both are in the same
	 * proposal) so, for moment, don't merge things.
	 */
	{
		.protoid = IKEv2_SEC_PROTO_IKE,
		.transforms = {
			[IKEv2_TRANS_TYPE_ENCR] = TR(ENCR_AES_GCM16_256),
			[IKEv2_TRANS_TYPE_INTEG] = TR(AUTH_NONE),
			[IKEv2_TRANS_TYPE_PRF] = TR(PRF_SHA1, PRF_SHA2_256),
			[IKEv2_TRANS_TYPE_DH] = TR(DH_MODP2048, DH_MODP4096, DH_MODP8192),
		},
	},
        /*
	 * IKEv2 proposal #1:
	 * AES_GCM[128]
	 * NULL
	 * SHA1,SHA2_256
	 * MODP2048, MODP4096, MODP8192
	 *
	 * Note: Strongswan cherry-picks proposals (for instance will
	 * pick AES_128 over AES_256 when both are in the same
	 * proposal) so, for moment, don't merge things.
	 */
	{
		.protoid = IKEv2_SEC_PROTO_IKE,
		.transforms = {
			[IKEv2_TRANS_TYPE_ENCR] = TR(ENCR_AES_GCM16_128),
			[IKEv2_TRANS_TYPE_INTEG] = TR(AUTH_NONE),
			[IKEv2_TRANS_TYPE_PRF] = TR(PRF_SHA1, PRF_SHA2_256),
			[IKEv2_TRANS_TYPE_DH] = TR(DH_MODP2048, DH_MODP4096, DH_MODP8192),
		},
	},
        /*
	 * IKEv2 proposal #2:
	 * AES_CBC[256]
	 * SHA1, SHA2_256, AES_XCBC
	 * MODP1536, MODP2048
	 * INTEG????
	 *
	 * Note: Strongswan cherry-picks proposals (for instance will
	 * pick AES_128 over AES_256 when both are in the same
	 * proposal) so, for moment, don't merge things.
	 */
	{
		.protoid = IKEv2_SEC_PROTO_IKE,
		.transforms = {
			[IKEv2_TRANS_TYPE_ENCR] = TR(ENCR_AES_CBC_256),
			[IKEv2_TRANS_TYPE_INTEG] = TR(AUTH_SHA1_96, AUTH_SHA2_256_128, AUTH_AES_XCBC_96),
			[IKEv2_TRANS_TYPE_PRF] = TR(PRF_SHA1, PRF_SHA2_256, PRF_AES128_XCBC),
			[IKEv2_TRANS_TYPE_DH] = TR(DH_MODP1536, DH_MODP2048),
		},
	},
        /*
	 * IKEv2 proposal #3:
	 * AES_CBC[128]
	 * SHA1, SHA2_256, AES_XCBC
	 * MODP1536, MODP2048
	 * INTEG????
	 *
	 * Note: Strongswan cherry-picks proposals (for instance will
	 * pick AES_128 over AES_256 when both are in the same
	 * proposal) so, for moment, don't merge things.
	 */
	{
		.protoid = IKEv2_SEC_PROTO_IKE,
		.transforms = {
			[IKEv2_TRANS_TYPE_ENCR] = TR(ENCR_AES_CBC_128),
			[IKEv2_TRANS_TYPE_INTEG] = TR(AUTH_SHA1_96, AUTH_SHA2_256_128, AUTH_AES_XCBC_96),
			[IKEv2_TRANS_TYPE_PRF] = TR(PRF_SHA1, PRF_SHA2_256, PRF_AES128_XCBC),
			[IKEv2_TRANS_TYPE_DH] = TR(DH_MODP1536, DH_MODP2048),
		},
	},
};

static struct ikev2_proposals default_ikev2_ike_proposals = {
	.proposal = default_ikev2_ike_proposal,
	.nr = elemsof(default_ikev2_ike_proposal),
};

/*
 * Transform an alg_info_ike into an array of ikev2 proposals.
 *
 * WARNING: alg_info_ike is IKEv1
 *
 * If alg_info_ike includes unknown algorithms those get dropped,
 * which can lead to no proposals.
 */
void ikev2_proposals_from_alg_info_ike(const char *what,
				       struct alg_info_ike *alg_info_ike,
				       struct ikev2_proposals **result)
{
	if (*result != NULL) {
		DBG(DBG_CONTROL, DBG_log("already determined %s proposals", what));
		return;
	}

	if (alg_info_ike == NULL) {
		DBG(DBG_CONTROL, DBG_log("selecting default %s proposals", what));
		*result = &default_ikev2_ike_proposals;
		DBG(DBG_CONTROL, DBG_log_ikev2_proposals(what, *result));
		return;
	}

	DBG(DBG_CONTROL, DBG_log("constructing %s proposals", what));
	struct ikev2_proposals *proposals = alloc_thing(struct ikev2_proposals, "proposals");
	int max_proposals = alg_info_ike->ai.alg_info_cnt;
	proposals->proposal = alloc_bytes(sizeof(struct ikev2_proposal) * max_proposals, "propsal");
	proposals->on_heap = TRUE;

	struct ike_info *ike_info;
	int ixxxx;
	ALG_INFO_IKE_FOREACH(alg_info_ike, ike_info, ixxxx) {
		DBG(DBG_CONTROL,
		    char buf[1024];
		    alg_info_snprint_ike_info(buf, sizeof(buf), ike_info);
		    DBG_log("converting ike_info %s to ikev2 ...", buf));

		/*
		 * Both initialize and empty this proposal (might
		 * contain partially constructed stuff from an earlier
		 * iteration).
		 */
		passert(proposals->nr < max_proposals);
		struct ikev2_proposal *proposal = &proposals->proposal[proposals->nr];
		*proposal = (struct ikev2_proposal) {
			.protoid =  IKEv2_SEC_PROTO_IKE,
		};

		struct encrypt_desc *ealg = ike_alg_get_encrypter(ike_info->ike_ealg);
		if (ealg == NULL) {
			if (ike_info->ike_ealg) {
				loglog(RC_LOG_SERIOUS, "dropping proposal containing unknown encrypt algorithm %d", ike_info->ike_ealg);
				continue;
			}
		} else {
			if (ike_info->ike_eklen) {
				append_transform(proposal, IKEv2_TRANS_TYPE_ENCR,
						 ealg->common.algo_v2id, ike_info->ike_eklen);
			} else if (!crypto_req_keysize(CRK_IKEv2, ealg->common.algo_v2id)) {
				/*
				 * XXX: crypto_req_keysize(), seems to
				 * be the easiest way to determine if
				 * a zero keylen is valid in a
				 * proposal.  If it is, just propose
				 * that.
				 */
				DBG(DBG_CONTROL, DBG_log("allowing a zero key because crypto_req_keysize() says so"));
				append_transform(proposal, IKEv2_TRANS_TYPE_ENCR,
						 ealg->common.algo_v2id, 0);
			} else {
				/*
				 * XXX: The parser, or something else,
				 * should have taken care of this.  If
				 * a keylen of zero makes it all the
				 * way through to here then, isn't
				 * that the intent?
				 *
				 * XXX: There's a rumor that
				 * strongswan proposes AES_000, this
				 * won't match that.
				 */
				DBG_log("XXX: emiting short keylen before long keylen; should be other way round");
				if (ealg->keydeflen && (ealg->keydeflen < ealg->keymaxlen)) {
					DBG(DBG_CONTROL, DBG_log("forcing a default key of %u",
								 ealg->keydeflen));
					append_transform(proposal, IKEv2_TRANS_TYPE_ENCR,
							 ealg->common.algo_v2id, ealg->keydeflen);
				}
				if (ealg->keymaxlen) {
					DBG(DBG_CONTROL, DBG_log("forcing a max key of %u", ealg->keymaxlen));
					append_transform(proposal, IKEv2_TRANS_TYPE_ENCR,
							 ealg->common.algo_v2id, ealg->keymaxlen);
				}
			}
		}

		struct hash_desc *halg = ike_alg_get_hasher(ike_info->ike_halg);
		if (halg == NULL) {
			if (ike_info->ike_halg) {
				loglog(RC_LOG_SERIOUS, "dropping proposal containing unknown hash algorithm %d", ike_info->ike_halg);
				continue;
			}
		} else {
			append_transform(proposal, IKEv2_TRANS_TYPE_PRF,
					 halg->common.algo_v2id, 0);
			if (ike_alg_enc_requires_integ(ealg)) {
				/*
				 * Use the IKEv1 HASH algorithm,
				 * projected onto IKEv2 INTEG, as the
				 * integrity.
				 */
				append_transform(proposal, IKEv2_TRANS_TYPE_INTEG,
						 v1hash_to_v2integ(ike_info->ike_halg), 0);
			} else {
				/*
				 * Include NULL integrity in the
				 * proposal so that if it is proposed
				 * there is something to match and
				 * send back.
				 */
				append_transform(proposal, IKEv2_TRANS_TYPE_INTEG,
						 0, 0);
			}
		}

		const struct oakley_group_desc *group = lookup_group(ike_info->ike_modp);
		if (group == NULL) {
			if (ike_info->ike_modp > 0) {
				loglog(RC_LOG_SERIOUS, "dropping proposal containing unknown modp group %d", ike_info->ike_modp);
				continue;
			}
		} else {
			append_transform(proposal, IKEv2_TRANS_TYPE_DH,
					 ike_info->ike_modp, 0);
		}

		DBG(DBG_CONTROL,
		    DBG_log_ikev2_proposal("... ", proposal));
		proposals->nr++;
	}
	*result = proposals;
	DBG(DBG_CONTROL, DBG_log_ikev2_proposals(what, *result));
}

static struct ikev2_proposal ikev2_esn_no_esp_proposal[] = {
	{
		.protoid = IKEv2_SEC_PROTO_ESP,
		.transforms = {
			[IKEv2_TRANS_TYPE_ENCR] = TR(ENCR_AES_CBC_128),
			[IKEv2_TRANS_TYPE_INTEG] = TR(AUTH_SHA1_96),
			[IKEv2_TRANS_TYPE_ESN] = TR(ESN_NO),
		},
	},
	{
		.protoid = IKEv2_SEC_PROTO_ESP,
		.transforms = {
			[IKEv2_TRANS_TYPE_ENCR] = TR(ENCR_AES_CBC_128),
			[IKEv2_TRANS_TYPE_INTEG] = TR(AUTH_MD5_96),
			[IKEv2_TRANS_TYPE_ESN] = TR(ESN_NO),
		},
	},
	{
		.protoid = IKEv2_SEC_PROTO_ESP,
		.transforms = {
			[IKEv2_TRANS_TYPE_ENCR] = TR(ENCR_3DES),
			[IKEv2_TRANS_TYPE_INTEG] = TR(AUTH_SHA1_96),
			[IKEv2_TRANS_TYPE_ESN] = TR(ESN_NO),
		},
	},
	{
		.protoid = IKEv2_SEC_PROTO_ESP,
		.transforms = {
			[IKEv2_TRANS_TYPE_ENCR] = TR(ENCR_3DES),
			[IKEv2_TRANS_TYPE_INTEG] = TR(AUTH_MD5_96),
			[IKEv2_TRANS_TYPE_ESN] = TR(ESN_NO),
		},
	},
};
static struct ikev2_proposals ikev2_esn_no_esp_proposals = {
	.proposal = ikev2_esn_no_esp_proposal,
	.nr = elemsof(ikev2_esn_no_esp_proposal),
};

static struct ikev2_proposal ikev2_esn_no_ah_proposal[] = {
	{
		.protoid = IKEv2_SEC_PROTO_AH,
		.transforms = {
			[IKEv2_TRANS_TYPE_INTEG] = TR(AUTH_SHA1_96),
			[IKEv2_TRANS_TYPE_ESN] = TR(ESN_NO),
		},
	},
	{
		.protoid = IKEv2_SEC_PROTO_AH,
		.transforms = {
			[IKEv2_TRANS_TYPE_INTEG] = TR(AUTH_MD5_96),
			[IKEv2_TRANS_TYPE_ESN] = TR(ESN_NO),
		},
	},
};
static struct ikev2_proposals ikev2_esn_no_ah_proposals = {
	.proposal = ikev2_esn_no_ah_proposal,
	.nr = elemsof(ikev2_esn_no_ah_proposal),
};

static void add_esn_transforms(struct ikev2_proposal *proposal, lset_t policy)
{
	passert(!proposal->transforms[IKEv2_TRANS_TYPE_ESN].transform[0].valid);
	if (policy & POLICY_ESN_YES) {
		append_transform(proposal, IKEv2_TRANS_TYPE_ESN, IKEv2_ESN_ENABLED, 0);
	}
	if (policy & POLICY_ESN_NO) {
		append_transform(proposal, IKEv2_TRANS_TYPE_ESN, IKEv2_ESN_DISABLED, 0);
	}
}

void ikev2_proposals_from_alg_info_esp(const char *what,
				       struct alg_info_esp *alg_info_esp,
				       lset_t policy,
				       struct ikev2_proposals **result)
{
	if (*result != NULL) {
		DBG(DBG_CONTROL, DBG_log("already determined %s proposals", what));
		return;
	}

	if (alg_info_esp == NULL) {
		DBG(DBG_CONTROL, DBG_log("selecting default %s proposals", what));
		lset_t esp_ah = policy & (POLICY_ENCRYPT | POLICY_AUTHENTICATE);
		struct ikev2_proposals *esn_no_proposals;
		switch (esp_ah) {
		case POLICY_ENCRYPT:
			esn_no_proposals = &ikev2_esn_no_esp_proposals;
			break;
		case POLICY_AUTHENTICATE:
			esn_no_proposals = &ikev2_esn_no_ah_proposals;
			break;
		default:
			/*
			 * For moment this function does not support
			 * AH+ESP.  Assert the assumption.
			 */
			bad_case(policy);
		}
		switch (policy & (POLICY_ESN_NO | POLICY_ESN_YES)) {
		case 0: /* screwup */
		case POLICY_ESN_NO:
			*result = esn_no_proposals;
			break;
		case POLICY_ESN_YES:
		case (POLICY_ESN_YES|POLICY_ESN_NO): {
			/*
			 * Clone the ESN_NO proposals and fix up the
			 * ESN bits.
			 */
			struct ikev2_proposals *proposals = alloc_thing(struct ikev2_proposal,
									"cloned ESP/AH proposals");
			proposals->on_heap = TRUE;
			proposals->nr = esn_no_proposals->nr;
			proposals->proposal = clone_bytes(esn_no_proposals->proposal,
							  sizeof(esn_no_proposals->proposal[0]) * esn_no_proposals->nr,
							  "ESP/AH proposals");
			struct ikev2_proposal *proposal;
			for (proposal = &proposals->proposal[0];
			     proposal < &proposals->proposal[proposals->nr];
			     proposal++) {
				/* invalidate the existing ESN_NO proposal */
				proposal->transforms[IKEv2_TRANS_TYPE_ESN].transform[0] = (struct ikev2_transform) { .valid = FALSE };
				add_esn_transforms(proposal, policy);
			}
			*result = proposals;
			break;
		}
		default:
			bad_case(policy);
		}
		DBG(DBG_CONTROL, DBG_log_ikev2_proposals(what, *result));
		return;
	}

	DBG(DBG_CONTROL, DBG_log("constructing %s proposals", what));

	struct ikev2_proposals *proposals = alloc_thing(struct ikev2_proposals, "proposals");
	int max_proposals = alg_info_esp->ai.alg_info_cnt;
	proposals->proposal = alloc_bytes(sizeof(struct ikev2_proposal) * max_proposals, "propsal");
	proposals->on_heap = TRUE;

	const struct esp_info *esp_info;
	int ixxxx;
	ALG_INFO_ESP_FOREACH(alg_info_esp, esp_info, ixxxx) {
		DBG(DBG_CONTROL,
		    char buf[1024];
		    alg_info_snprint_esp_info(buf, sizeof(buf), esp_info);
		    DBG_log("converting esp_info %s to ikev2 ...", buf));

		/*
		 * Both initialize and empty this proposal (might
		 * contain partially constructed stuff from an earlier
		 * iteration).
		 */
		passert(proposals->nr < max_proposals);
		struct ikev2_proposal *proposal = &proposals->proposal[proposals->nr];
		static struct ikev2_proposal zero_proposal;	/* naturally zero */
		*proposal = zero_proposal;

		switch (policy & (POLICY_ENCRYPT | POLICY_AUTHENTICATE)) {
		case POLICY_ENCRYPT:
			proposal->protoid = IKEv2_SEC_PROTO_ESP;

			unsigned ealg = esp_info->transid;
			if (!ESP_EALG_PRESENT(ealg)) {
				loglog(RC_LOG_SERIOUS, "requested kernel enc ealg_id=%u not present",
				        ealg);
				continue;
			}
			pexpect(ealg != 0);

			/*
			 * IANA ikev1 / ipsec-v3 fixup; presumably
			 * everything else is both IKEv1 and IKEv2?
			 */
			if (ealg == IKEv2_ENCR_CAMELLIA_CBC_ikev1) {
				ealg = IKEv2_ENCR_CAMELLIA_CBC;
			}

			if (esp_info->enckeylen > 0) {
				append_transform(proposal, IKEv2_TRANS_TYPE_ENCR, ealg, esp_info->enckeylen);
			} else {
				/*
				 * no key length - if required add
				 * default here and add another max
				 * entry
				 */
				unsigned ekeylen = crypto_req_keysize(CRK_ESPorAH,
								      esp_info->transid);
				append_transform(proposal, IKEv2_TRANS_TYPE_ENCR, ealg, ekeylen);
				if (ekeylen) {
					unsigned ekeylen2 = BITS_PER_BYTE * kernel_alg_esp_enc_max_keylen(esp_info->transid);
					if (ekeylen2 != ekeylen) {
						append_transform(proposal, IKEv2_TRANS_TYPE_ENCR, ealg, ekeylen2);
					}
				}
			}
			
			/* add ESP auth attr (if present) */
			if (esp_info->auth != AUTH_ALGORITHM_NONE) {
				unsigned aalg = alg_info_esp_aa2sadb(esp_info->auth);
				if (!ESP_AALG_PRESENT(aalg)) {
					loglog(RC_LOG_SERIOUS, "kernel_alg_db_add() kernel auth aalg_id=%d not present",
					       aalg);
					continue;
				}
				enum ikev2_trans_type_integ integ = v1auth_to_v2integ(esp_info->auth);
				append_transform(proposal, IKEv2_TRANS_TYPE_INTEG, integ, 0);
			}
			break;

		case POLICY_AUTHENTICATE:
			proposal->protoid = IKEv2_SEC_PROTO_AH;
			int aalg = alg_info_esp_aa2sadb(esp_info->auth);
			if (!ESP_AALG_PRESENT(aalg)) {
				loglog(RC_LOG_SERIOUS, "kernel_alg_db_add() kernel auth aalg_id=%d not present",
				       aalg);
				continue;
			}
			enum ikev2_trans_type_integ integ = v1auth_to_v2integ(esp_info->auth);
			if (integ != 0) {
				append_transform(proposal, IKEv2_TRANS_TYPE_INTEG, integ, 0);
			}
			break;

		default:
			bad_case(policy);

		}

		add_esn_transforms(proposal, policy);

		DBG(DBG_CONTROL,
		    DBG_log_ikev2_proposal("... ", proposal));
		proposals->nr++;
	}

	*result = proposals;
	DBG(DBG_CONTROL, DBG_log_ikev2_proposals(what, *result));
}


struct ipsec_proto_info *ikev2_esp_or_ah_proto_info(struct state *st, lset_t policy)
{
	/* ??? this code won't support AH + ESP */
	switch (policy & (POLICY_ENCRYPT | POLICY_AUTHENTICATE)) {
	case POLICY_ENCRYPT:
		return &st->st_esp;
	case POLICY_AUTHENTICATE:
		return &st->st_ah;
	default:
		bad_case(policy);
		return NULL;
	}
}

ipsec_spi_t ikev2_esp_or_ah_spi(const struct spd_route *spd_route, lset_t policy)
{
	int ipprotoid;
	switch (policy & (POLICY_ENCRYPT | POLICY_AUTHENTICATE)) {
	case POLICY_ENCRYPT:
		ipprotoid = IPPROTO_ESP;
		break;
	case POLICY_AUTHENTICATE:
		ipprotoid = IPPROTO_AH;
		break;
	default:
		bad_case(policy);
	}
	return get_ipsec_spi(0 /* avoid this # */,
			     ipprotoid, spd_route,
			     TRUE /* tunnel */);
}

/*
 * Return the first valid MODP proposal that is supported.
 */
const struct oakley_group_desc *ikev2_proposals_first_modp(struct ikev2_proposals *proposals)
{
	int p;
	for (p = 0; p < proposals->nr; p++) {
		struct ikev2_proposal *proposal = &proposals->proposal[p];
		struct ikev2_transforms *transforms = &proposal->transforms[IKEv2_TRANS_TYPE_DH];
		int t;
		for (t = 0; t < transforms->transform[t].valid; t++) {
			int groupnum = transforms->transform[t].id;
			const struct oakley_group_desc *group = lookup_group(groupnum);
			if (group == NULL) {
				/*
				 * Things screwed up (this group
				 * should have been pruned earlier),
				 * rather than crash, continue looking
				 * for a valid group.
				 */
				DBG(DBG_CONTROL, DBG_log("proposals include unsupported group %d", groupnum));
				continue;
			}
			return group;
		}
	}
	DBG(DBG_CONTROL, DBG_log("No valid MODP (DH) transform found"));
	/* return something that should be supported.  */
	const struct oakley_group_desc *group = lookup_group(OAKLEY_GROUP_MODP2048);
	passert(group != NULL);
	return group;
}

/*
 * Is the modp group in the proposal set?
 *
 * It's the caller's problem to check that it is actually supported.
 */
bool ikev2_proposals_include_modp(struct ikev2_proposals *proposals,
				  oakley_group_t modp)
{
	int p;
	for (p = 0; p < proposals->nr; p++) {
		struct ikev2_proposal *proposal = &proposals->proposal[p];
		struct ikev2_transforms *transforms = &proposal->transforms[IKEv2_TRANS_TYPE_DH];
		struct ikev2_transform *transform;
		FOR_EACH_TRANSFORM(transform, transforms) {
			if (transform->id == modp) {
				return TRUE;
			}
		}
	}
	DBG(DBG_CONTROL, DBG_log("No first MODP (DH) transform found"));
	return FALSE;
}
