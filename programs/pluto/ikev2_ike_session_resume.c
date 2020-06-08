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

#include "ikev2_ike_session_resume.h"
#include "connections.h"
#include "log.h"
#include "show.h"

struct session {
	/*
	 * Local IKE SA parameters used to re-animate the
	 * initiating session-revival IKE SA.
	 */
	co_serial_t sr_serialco;
	id_buf peer_id;

	chunk_t sk_d_old;

	enum ikev2_trans_type_encr sr_encr;
	enum ikev2_trans_type_prf sr_prf;
	enum ikev2_trans_type_integ sr_integ;
	enum ike_trans_type_dh sr_dh;
	unsigned sr_enc_keylen;

	enum keyword_auth sr_auth_method;

	/*
	 * time that ticket was received, and peer specified lifetime;
	 * our_expire+server_expire is expiration.
	 */
	monotime_t sr_our_expire;
	deltatime_t sr_server_expire;

	/*
	 * Blob from peer that contains their equivalent and needs to
	 * be sent in the IKE_SESSION_RESUME request so that they can
	 * re-animating their SA.
	 */
	chunk_t ticket;
};

void pfree_session(struct session **session)
{
	if (*session == NULL) {
		return;
	}
	free_chunk_content(&(*session)->ticket);
	free_chunk_content(&(*session)->sk_d_old);
	pfree((*session));
	(*session) = NULL;
}

void jam_session(struct jambuf *buf, const struct session *session)
{
	jam_string(buf, "ticket: ");
	if (session == NULL) {
		jam_string(buf, "none");
	} else {
		jam(buf, "%zu bytes", session->ticket.len);
		jam_string(buf, " expires: ");
		monotime_t expire =
			monotime_add(session->sr_our_expire,
				     session->sr_server_expire);
		jam_monotime(buf, expire);
	}
}
