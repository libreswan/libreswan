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
struct end;
struct connection;
struct child_sa;
struct state;

/*
 * IKEv2, this struct will be mapped into a ikev2_ts1 payload
 * It contains either a v4/v6 range OR a sec_label
 */
struct traffic_selector {
	uint8_t ts_type;
	uint8_t ipprotoid;
	uint16_t startport;
	uint16_t endport;
	ip_range net;	/* for now, always happens to be a CIDR */
	/*
	 * shares memory with any of:
	 * - the struct pbs_in's buffer
	 * - end.sec_label
	 * - st.*sec_label
	 * - acquire's sec_label
	 */
	shunk_t sec_label;
};

void dbg_v2_ts(const struct traffic_selector *ts, const char *prefix, ...) PRINTF_LIKE(2);

bool v2_process_ts_response(struct child_sa *child,
			    struct msg_digest *md);

bool v2_process_request_ts_payloads(struct child_sa *child,
				    const struct msg_digest *md);

struct traffic_selector traffic_selector_from_end(const struct end *e, const char *what);

stf_status emit_v2TS_payloads(struct pbs_out *outpbs, const struct child_sa *cst);

bool child_rekey_responder_ts_verify(struct child_sa *child, struct msg_digest *md);

#endif
