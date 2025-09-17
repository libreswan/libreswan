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
 * Copyright (C) 2020 Nupur Agrawal <nupur202000@gmail.com>
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

#ifndef IKEV2_SA_PAYLOAD_H
#define IKEV2_SA_PAYLOAD_H

void vdbg_ikev2_proposal(struct verbose verbose, const char *prefix,
			 const struct ikev2_proposal *proposal);

void llog_v2_proposals(enum stream stream, const struct logger *logger,
		       const struct ikev2_proposals *proposals,
		       const char *title);

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
				       bool limit_logging/*because-oe?*/,
				       struct ikev2_proposal **chosen_proposal,
				       const struct ikev2_proposals *local_proposals,
				       struct verbose verbose);

bool emit_v2SA_proposals(struct pbs_out *pbs,
			 const struct ikev2_proposals *proposals,
			 const shunk_t local_spi);

bool emit_v2SA_proposal(struct pbs_out *pbs,
			const struct ikev2_proposal *proposal,
			shunk_t local_spi);

bool ikev2_proposal_to_trans_attrs(const struct ikev2_proposal *proposal,
				   struct trans_attrs *ta_out, struct logger *logger);

bool ikev2_proposal_to_proto_info(const struct ikev2_proposal *proposal,
				  struct ipsec_proto_info *proto_info,
				  struct logger *logger);

void free_ikev2_proposals(struct ikev2_proposals **proposals);

void free_ikev2_proposal(struct ikev2_proposal **proposal);

/*
 * Convert the proposal to something IKEv2 likes.
 */

struct ikev2_proposals *ikev2_proposals_from_proposals(enum ikev2_sec_proto_id protoid,
						       const struct proposals *proposals,
						       struct verbose verbose);

/*
 * On-demand compute and return the IKE proposals for the connection.
 *
 * If the default alg_info_ike includes unknown algorithms those get
 * dropped, which can lead to no proposals.
 *
 * Never returns NULL (see passert).
 */

struct ikev2_proposals *get_v2_IKE_AUTH_new_child_proposals(struct connection *c);

struct ikev2_proposals *get_v2_CREATE_CHILD_SA_new_child_proposals(struct ike_sa *ike,
								   struct child_sa *larval_child,
								   struct verbose verbose);
struct ikev2_proposals *get_v2_CREATE_CHILD_SA_rekey_child_proposals(struct ike_sa *ike,
								     struct child_sa *established_child,
								     struct verbose verbose);
struct ikev2_proposals *get_v2_CREATE_CHILD_SA_rekey_ike_proposals(struct ike_sa *ike,
								   struct verbose verbose);

/*
 * Return the first valid DH proposal that is supported.
 */

const struct kem_desc *ikev2_proposal_first_kem(const struct ikev2_proposal *proposal,
						struct verbose verbose);
const struct kem_desc *ikev2_proposals_first_kem(const struct ikev2_proposals *proposals,
						 struct verbose verbose);

/*
 * Is the Key Exchange Method in the proposal set?
 *
 * It's the caller's problem to check that it is actually supported.
 */
bool ikev2_proposals_include_kem(const struct ikev2_proposals *proposals,
				 enum ikev2_trans_type_kem kem);

void ikev2_copy_child_spi_from_proposal(const struct ikev2_proposal *accepted_ike_proposal,
					ike_spi_t *cookie);

void set_ikev2_accepted_proposal(struct ike_sa *ike,
				 enum ikev2_trans_type_encr sr_encr,
				 enum ikev2_trans_type_prf sr_prf,
				 enum ikev2_trans_type_integ sr_integ,
				 enum ikev2_trans_type_kem sr_kem,
				 unsigned sr_enc_keylen);

#endif
