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

struct v2SK_payload;

extern void ikev2_addr_change(struct state *st);

extern void record_deladdr(ip_address *ip, char *a_type, struct logger *logger);
extern void record_newaddr(ip_address *ip, char *a_type, struct logger *logger);

bool process_v2N_mobike_requests(struct ike_sa *ike, struct msg_digest *md, struct pbs_out *pbs);

void mobike_possibly_send_recorded(struct ike_sa *ike, struct msg_digest *md);

#endif
