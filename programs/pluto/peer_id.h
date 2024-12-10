/* information about connections between hosts and clients
 *
 * Copyright (C) 2022 Andrew Cagney
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

#ifndef PEER_ID_H
#define PEER_ID_H

#include "lset.h"
#include "diag.h"

struct state;
struct id;
struct ike_sa;

bool refine_host_connection_of_state_on_responder(struct ike_sa *ike,
						  lset_t proposed_authbys,
						  const struct id *peer_id,
						  const struct id *tarzan_id);

diag_t update_peer_id(struct ike_sa *ike,
		      const struct id *peer_id,
		      const struct id *tarzan_id);

diag_t update_peer_id_certs(struct ike_sa *ike);

struct connection_id_score {
	int wildcards;
	int pathlen;
};

bool compare_connection_id(const struct connection *c,
			   const struct connection *d,
			   struct connection_id_score *score,
			   struct verbose verbose);

diag_t unpack_id(enum ike_id_type kind, struct id *peer,
		 const struct pbs_in *id_pbs);

#endif
