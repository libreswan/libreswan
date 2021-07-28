/* IKEv2 CHILD SA routines, for libreswan
 *
 * Copyright (C) 2021  Andrew cagney
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

#ifndef IKEV2_CHILD_H
#define IKEV2_CHILD_H

struct child_sa;
struct msg_digest;
struct ike_sa;
struct pbs_out;

/*
 * Result of processing CHILD SA payloads.  Don't use STF_STATUS as it
 * is too ill defined.  Caller needs to see this and decide what
 * action to take.
 *
 * Caller needs to check returned v2_notification_t to see if it is
 * fatal.  See RFC.
 */

stf_status process_v2_childs_sa_payload(const char *what, struct ike_sa *ike,
					struct child_sa *larval_child,
					struct msg_digest *md,
					bool expect_accepted_proposal);

bool emit_v2_child_request_payloads(const struct child_sa *larval_child,
				    const struct ikev2_proposals *child_proposals,
				    ipsec_spi_t local_spi,
				    struct pbs_out *outpbs);
stf_status emit_v2_child_response_payloads(struct ike_sa *ike,
					   struct child_sa *child,
					   struct msg_digest *request_md,
					   struct pbs_out *outpbs);
v2_notification_t process_v2_child_response_payloads(struct ike_sa *ike,
						     struct child_sa *larval_child,
						     struct msg_digest *response_md);

void v2_child_sa_established(struct ike_sa *ike, struct child_sa *child);

v2_notification_t assign_v2_responders_child_client(struct child_sa *child,
						    struct msg_digest *md);

v2_notification_t process_v2_IKE_AUTH_response_child_sa_payloads(struct ike_sa *ike,
								 struct msg_digest *md);

v2_notification_t process_v2_IKE_AUTH_request_child_sa_payloads(struct ike_sa *ike,
								struct msg_digest *md,
								struct pbs_out *sk_pbs);

struct ipsec_proto_info *ikev2_child_sa_proto_info(struct child_sa *child);

bool compute_v2_ipcomp_cpi(struct child_sa *child);

#endif
