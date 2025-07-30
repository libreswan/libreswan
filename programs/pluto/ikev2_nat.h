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

#ifndef IKEV2_NAT_H
#define IKEV2_NAT_H

/*
 * NAT-D
 */

extern bool v2_nat_detected(struct ike_sa *ike, struct msg_digest *md);

/*
 * move initiator endpoints (src, dst) to NAT ports.
 */

void ikev2_nat_change_port_lookup(struct msg_digest *md, struct state *st);
bool ikev2_natify_initiator_endpoints(struct ike_sa *ike, where_t where);

bool ikev2_out_natd(const ip_endpoint *local_endpoint,
		    const ip_endpoint *remote_endpoint,
		    const ike_spis_t *ike_spis,
		    struct pbs_out *outs);

bool ikev2_out_nat_v2n(struct pbs_out *outs, struct state *st,
		       const ike_spi_t *ike_responder_spi);

#endif


