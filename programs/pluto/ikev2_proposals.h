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

#ifndef IKEV2_SA_PAYLOAD_H
#define IKEV2_SA_PAYLOAD_H

void DBG_log_ikev2_proposal(const char *prefix,
			    const struct ikev2_proposal *proposal);

void llog_v2_proposals(lset_t rc_flags, struct logger *logger,
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
				       bool opportunistic,
				       struct ikev2_proposal **chosen_proposal,
				       const struct ikev2_proposals *local_proposals,
				       struct logger *logger);

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
						       struct logger *logger);

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
								   struct child_sa *larval_child);
struct ikev2_proposals *get_v2_CREATE_CHILD_SA_rekey_child_proposals(struct ike_sa *ike,
								     struct child_sa *established_child,
								     struct logger *logger);
struct ikev2_proposals *get_v2_CREATE_CHILD_SA_rekey_ike_proposals(struct ike_sa *ike,
								   struct logger *logger);

/*
 * Return the first valid DH proposal that is supported.
 */

const struct dh_desc *ikev2_proposal_first_dh(const struct ikev2_proposal *proposal);
const struct dh_desc *ikev2_proposals_first_dh(const struct ikev2_proposals *proposals);

/*
 * Is the modp group in the proposal set?
 *
 * It's the caller's problem to check that it is actually supported.
 */
bool ikev2_proposals_include_modp(const struct ikev2_proposals *proposals,
				  oakley_group_t modp);

void ikev2_copy_child_spi_from_proposal(const struct ikev2_proposal *accepted_ike_proposal,
					ike_spi_t *cookie);

#endif
