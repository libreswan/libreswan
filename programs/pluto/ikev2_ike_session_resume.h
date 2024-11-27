/* IKEv2 Session Resumption RFC 5723
 *
 * Copyright (C) 2020 Nupur Agrawal <nupur202000@gmail.com>
 * Copyright (C) 2024 Andrew Cagney
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

#ifndef IKEV2_IKE_SESSION_RESUME_H
#define IKEV2_IKE_SESSION_RESUME_H

#include <stdbool.h>
#include "shunk.h"
#include "chunk.h"
#include "pluto_timing.h"

struct session;
struct jambuf;
struct ike_sa;
struct pbs_out;
struct pbs_in;
struct child_policy;
struct connection;
struct prf_desc;
struct payload_digest;

void pfree_session(struct session **session);
void jam_session(struct jambuf *buf, const struct session *session);

struct ike_sa *initiate_v2_IKE_SESSION_RESUME_request(struct connection *c,
						      const struct child_policy *policy,
						      const threadtime_t *inception,
						      shunk_t sec_label,
						      bool background);

extern const struct v2_exchange v2_IKE_SESSION_RESUME_exchange;

/* XXX: needed by IKE_AUTH when sending initiator ticker. */
bool emit_v2N_TICKET_LT_OPAQUE(struct ike_sa *ike, struct pbs_out *pbs);

bool process_v2N_TICKET_LT_OPAQUE(struct ike_sa *ike,
				  const struct payload_digest *pd);

void init_ike_session_resume(struct logger *logger);
void shutdown_ike_session_resume(struct logger *logger);

#endif
