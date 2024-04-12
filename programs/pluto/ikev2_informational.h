/* IKEv2 informational exchange, for Libreswan
 *
 * Copyright (C) 2021  Andrew Cagney
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

#ifndef IKEV2_INFORMATIONAL_H
#define IKEV2_INFORMATIONAL_H

stf_status process_v2_INFORMATIONAL_request(struct ike_sa *ike,
					    struct child_sa *null_child,
					    struct msg_digest *md);

typedef bool emit_v2_INFORMATIONAL_request_payload_fn(struct ike_sa *ike,
						      struct child_sa *child,
						      struct pbs_out *pbs);

extern bool record_v2_INFORMATIONAL_request(const char *name,
					    struct logger *logger,
					    struct ike_sa *ike,
					    struct child_sa *child,
					    emit_v2_INFORMATIONAL_request_payload_fn *emit_payloads);

typedef bool emit_v2_INFORMATIONAL_response_payload_fn(struct ike_sa *ike,
						       struct child_sa *child,
						       struct msg_digest *md,
						       struct pbs_out *pbs);

extern bool record_v2_INFORMATIONAL_response(const char *name,
					     struct logger *logger,
					     struct ike_sa *ike,
					     struct child_sa *child,
					     struct msg_digest *md,
					     emit_v2_INFORMATIONAL_response_payload_fn *emit_payloads);

extern const struct v2_exchange v2_INFORMATIONAL_exchange;

#endif
