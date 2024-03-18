/* IKEv2 Traffic Selectors, for libreswan
 *
 * Copyright (C) 2018  Andrew cagney
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

#ifndef IKEV2_TS_H
#define IKEV2_TS_H

#include "ip_range.h"

struct msg_digest;
struct connection;
struct child_sa;
struct pbs_out;

bool process_v2TS_response_payloads(struct child_sa *child,
				    struct msg_digest *md);

bool process_v2TS_request_payloads(struct child_sa *child,
				   const struct msg_digest *md);

bool emit_v2TS_response_payloads(struct pbs_out *outpbs, const struct child_sa *cst);
bool emit_v2TS_request_payloads(struct pbs_out *outpbs, const struct child_sa *cst);

bool verify_rekey_child_request_ts(struct child_sa *child, struct msg_digest *md);

#endif
