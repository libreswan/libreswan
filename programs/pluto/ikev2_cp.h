/* IKEv2 Configuration Payload, for libreswan
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

#ifndef IKEV2_CP_H
#define IKEV2_CP_H

#include <stdbool.h>

struct child_sa;
struct pbs_out;

bool send_v2CP_request(const struct connection *cc, bool this_end_behind_nat);
bool need_v2CP_response(const struct connection *cc, bool this_end_behind_nat);

bool emit_v2CP_request(const struct child_sa *child, struct pbs_out *outpbs);
bool emit_v2CP_response(const struct child_sa *child, struct pbs_out *outpbs);

bool process_v2_IKE_AUTH_request_v2CP_request_payload(struct ike_sa *ike, struct child_sa *child,
						      struct payload_digest *cp_payload);
bool process_v2CP_response_payload(struct ike_sa *ike, struct child_sa *child, struct payload_digest *cp_pd);

void ldbg_cp(struct logger *logger, const struct connection *cc, const char *fmt, ...)
	PRINTF_LIKE(3);

#endif
