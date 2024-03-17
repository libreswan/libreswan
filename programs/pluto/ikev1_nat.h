/* IKEv2 nat traversal, for libreswan
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

#ifndef IKEV1_NAT_H
#define IKEV1_NAT_H

/*
 * NAT-D
 */
extern bool ikev1_nat_traversal_add_natd(struct pbs_out *outs,
					 const struct msg_digest *md);

bool v1_nat_traversal_add_initiator_natoa(struct pbs_out *outs, struct state *st);

/*
 * move initiator endpoints (src, dst) to NAT ports.
 */

void v1_maybe_natify_initiator_endpoints(struct state *st,
					 where_t where);

extern void ikev1_natd_init(struct state *st, struct msg_digest *md);

/**
 * Vendor ID
 */
bool nat_traversal_insert_vid(struct pbs_out *outs, const struct connection *c);
void set_nat_traversal(struct state *st, const struct msg_digest *md);

/**
 * NAT-OA
 */

void nat_traversal_natoa_lookup(struct msg_digest *md,
				struct hidden_variables *hv,
				struct logger *logger);

#endif


