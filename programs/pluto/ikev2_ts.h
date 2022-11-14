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
#include "packet.h"	/* for pb_stream */

struct msg_digest;
struct traffic_selector;
struct spd_end;
struct connection;
struct child_sa;
struct state;

void dbg_v2_ts(const struct traffic_selector *ts, const char *prefix, ...) PRINTF_LIKE(2);

bool v2_process_ts_response(struct child_sa *child,
			    struct msg_digest *md);

bool v2_process_request_ts_payloads(struct child_sa *child,
				    const struct msg_digest *md);

bool emit_v2TS_response_payloads(struct pbs_out *outpbs, const struct child_sa *cst);
bool emit_v2TS_request_payloads(struct pbs_out *outpbs, const struct child_sa *cst);

bool verify_rekey_child_request_ts(struct child_sa *child, struct msg_digest *md);

#endif
