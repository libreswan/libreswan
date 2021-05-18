/* IKEv2 Mobile IKE (MOBIKE), for libreswan
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
 */

#ifndef IKEV2_MOBIKE_H
#define IKEV2_MOBIKE_H

extern void ikev2_addr_change(struct state *st);

extern void record_deladdr(ip_address *ip, char *a_type);
extern void record_newaddr(ip_address *ip, char *a_type);

stf_status add_mobike_response_payloads(chunk_t *cookie2,	/* freed by us */
					struct msg_digest *md,
					pb_stream *pbs);
bool process_mobike_resp(struct msg_digest *md);

struct mobike {
	ip_endpoint remote;
	const struct iface_endpoint *interface;
};

void mobike_switch_remote(struct msg_digest *md, struct mobike *est_remote);
void mobike_reset_remote(struct state *st, struct mobike *est_remote);

/* can an established state initiate or respond to mobike probe */
bool mobike_check_established(const struct state *st);

#endif
