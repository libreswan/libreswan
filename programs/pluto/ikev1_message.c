/* IKEv1 message contents, for libreswan
 *
 * Copyright (C) 2019 Andrew Cagney
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

#include "shunk.h"
#include "id.h"

#include "connections.h"
#include "packet.h"
#include "ikev1_message.h"
#include "diag.h"
#include "lswlog.h"
#include "unpack.h"
#include "demux.h"
#include "crypt_ke.h"

struct isakmp_ipsec_id build_v1_id_payload(const struct host_end *end, shunk_t *body)
{
	struct isakmp_ipsec_id id_hd = {
		.isaiid_idtype = id_to_payload(&end->id, &end->addr, body),
	};
	return id_hd;
}

bool out_raw(const void *bytes, size_t len, struct pbs_out *outs, const char *name)
{
	if (!pbs_out_raw(outs, bytes, len, name)) {
		/* already logged */
		return false;
	}
	return true;
}

bool ikev1_justship_nonce(chunk_t *n, struct pbs_out *outs,
			  const char *name)
{
	return ikev1_out_generic_chunk(&isakmp_nonce_desc, outs, *n, name);
}

bool ikev1_ship_nonce(chunk_t *n, chunk_t *nonce,
		      struct pbs_out *outs, const char *name)
{
	unpack_nonce(n, nonce);
	return ikev1_justship_nonce(n, outs, name);
}

v1_notification_t accept_v1_nonce(struct logger *logger,
				  struct msg_digest *md, chunk_t *dest,
				  const char *name)
{
	struct pbs_in *nonce_pbs = &md->chain[ISAKMP_NEXT_NONCE]->pbs;
	size_t len = pbs_left(nonce_pbs);

	if (len < IKEv1_MINIMUM_NONCE_SIZE || IKEv1_MAXIMUM_NONCE_SIZE < len) {
		llog(RC_LOG, logger, "%s length not between %d and %d",
			    name, IKEv1_MINIMUM_NONCE_SIZE, IKEv1_MAXIMUM_NONCE_SIZE);
		return v1N_PAYLOAD_MALFORMED; /* ??? */
	}
	replace_chunk(dest, pbs_in_left(nonce_pbs), "nonce");
	passert(len == dest->len);
	return v1N_NOTHING_WRONG;
}

/*
 * package up the calculate KE value, and emit it as a KE payload.
 * used by IKEv1: main, aggressive, and quick (in PFS mode).
 */
bool ikev1_justship_KE(struct logger *logger, chunk_t *g, struct pbs_out *outs)
{
	switch (impair.ke_payload) {
	case IMPAIR_EMIT_NO:
		return ikev1_out_generic_chunk(&isakmp_keyex_desc, outs, *g,
					       "keyex value");
	case IMPAIR_EMIT_OMIT:
		llog(RC_LOG, logger, "IMPAIR: sending no KE (g^x) payload");
		return true;
	case IMPAIR_EMIT_EMPTY:
		llog(RC_LOG, logger, "IMPAIR: sending empty KE (g^x)");
		return ikev1_out_generic_chunk(&isakmp_keyex_desc, outs,
					       EMPTY_CHUNK, "empty KE");
	default:
	{
		struct pbs_out z;
		uint8_t byte = impair.ke_payload - IMPAIR_EMIT_ROOF;
		llog(RC_LOG, logger, "IMPAIR: sending bogus KE (g^x) == %u value to break DH calculations", byte);
		/* Only used to test sending/receiving bogus g^x */
		return ikev1_out_generic(&isakmp_keyex_desc, outs, &z) &&
			pbs_out_repeated_byte(&z, byte, g->len, "fake g^x") &&
			(close_output_pbs(&z), true);
	}
	}
}

bool ikev1_ship_KE(struct state *st, struct dh_local_secret *local_secret,
		   chunk_t *g, struct pbs_out *outs)
{
	unpack_KE_from_helper(st, local_secret, g);
	return ikev1_justship_KE(st->logger, g, outs);
}
