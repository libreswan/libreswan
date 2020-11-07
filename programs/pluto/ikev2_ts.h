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

/* IKEv2, this struct will be mapped into a ikev2_ts1 payload  */
struct traffic_selector {
	uint8_t ts_type;
	uint8_t ipprotoid;
	uint16_t startport;
	uint16_t endport;
	ip_range net;	/* for now, always happens to be a CIDR */

	/**
	 * `sec_ctx` is the security label (if any) that is associated with
	 * this Traffic Selector.
	 * 
	 * There are 2 cases where `sec_ctx` is non-NULL:
	 *
	 *  1. If `ts_type` == `IKEv2_TS_SECLABEL`
	 *
	 *  2. If `ts_type` corresponds to an address range _and_ the security
	 *     label is used in conjunction with the other parameters in this 
	 *     Traffic Selector.
	 */
	struct xfrm_user_sec_ctx_ike *sec_ctx;
};

void ikev2_print_ts(const struct traffic_selector *ts);

bool v2_process_ts_response(struct child_sa *child,
			    struct msg_digest *md);

bool v2_process_ts_request(struct child_sa *child,
			   const struct msg_digest *md);

/**
 * ikev2_make_ts: Create a Traffic Selector data structure using the given
 * endpoint specification and IPsec SA security label.
 *
 * @param[in]	e		Endpoint specification.
 * @param[in]	sec_ctx		Security label from a IPsec SA.
 *
 * @return	New Traffic Selector.
 */
struct traffic_selector ikev2_make_ts(struct end const *e, struct xfrm_user_sec_ctx_ike *sec_ctx);

stf_status v2_emit_ts_payloads(const struct child_sa *cst,
			       pb_stream *outpbs,
			       const struct connection *c);

bool child_rekey_responder_ts_verify(struct child_sa *child, struct msg_digest *md);

#endif
