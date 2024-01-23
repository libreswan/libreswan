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

v2_notification_t process_v2_childs_sa_payload(const char *what, struct ike_sa *ike,
					       struct child_sa *larval_child,
					       struct msg_digest *md,
					       const struct ikev2_proposals *child_proposals,
					       bool expect_accepted_proposal);

/*
 * Work the initiator and responder Child SAs through to being
 * established.
 *
 * XXX: some, but not all the code lies here - there's still random
 * snippets scattered across IKE_AUTH and CREATE_CHILD_SA, sigh.
 */

bool prep_v2_child_for_request(struct child_sa *larval_child);

bool emit_v2_child_request_payloads(const struct ike_sa *ike,
				    const struct child_sa *larval_child,
				    const struct ikev2_proposals *child_proposals,
				    struct pbs_out *outpbs);
v2_notification_t process_v2_child_request_payloads(struct ike_sa *ike,
						    struct child_sa *larval_child,
						    struct msg_digest *request_md,
						    struct pbs_out *sk_pbs);
v2_notification_t process_v2_child_response_payloads(struct ike_sa *ike,
						     struct child_sa *larval_child,
						     struct msg_digest *response_md);

void v2_child_sa_established(struct ike_sa *ike, struct child_sa *child);

v2_notification_t process_v2_IKE_AUTH_response_child_sa_payloads(struct ike_sa *ike,
								 struct msg_digest *md);

bool process_any_v2_IKE_AUTH_request_child_sa_payloads(struct ike_sa *ike,
						       struct msg_digest *md,
						       struct pbs_out *sk_pbs);

/*
 * Macro as that handles const CHILD.
 */
#define ikev2_child_sa_proto_info(CHILD)				\
	({								\
		/* evaluate once */					\
		typeof(CHILD) child_ = (CHILD);				\
		enum encap_proto encap_proto =				\
			child_->sa.st_connection->config->child_sa.encap_proto; \
		/* handle const CHILD */				\
		(encap_proto == ENCAP_PROTO_ESP ? &child_->sa.st_esp : \
		 encap_proto == ENCAP_PROTO_AH ? &child_->sa.st_ah :	\
		 NULL);							\
	})

void llog_v2_child_sa_established(struct ike_sa *ike, struct child_sa *child);

#endif
