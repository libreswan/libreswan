/* IKEv2 KE routes, for libreswan.
 *
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2014,2018 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2015 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2018,2020-2025 Andrew Cagney
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
 *
 */

#include "ikev2_ke.h"

#include "impair.h"
#include "ike_alg.h"

#include "log.h"
#include "packet.h"

/*
 * package up the calculated KE value, and emit it as a KE payload.
 * used by IKEv2: parent, child (PFS)
 */
bool emit_v2KE(shunk_t ke, const struct kem_desc *kem, struct pbs_out *outs)
{
	if (impair.ke_payload == IMPAIR_EMIT_OMIT) {
		llog(RC_LOG, outs->logger, "IMPAIR: omitting KE payload");
		return true;
	}


	struct ikev2_ke v2ke = {
		.isak_kem = kem->ikev2_alg_id,
	};

	struct pbs_out ke_pbs;
	if (!pbs_out_struct(outs, v2ke, &ikev2_ke_desc, &ke_pbs))
		return false;

	if (impair.ke_payload >= IMPAIR_EMIT_ROOF) {
		uint8_t byte = impair.ke_payload - IMPAIR_EMIT_ROOF;
		llog(RC_LOG, outs->logger,
		     "IMPAIR: sending bogus KE (g^x) == %u value to break DH calculations", byte);
		/* Only used to test sending/receiving bogus g^x */
		if (!pbs_out_repeated_byte(&ke_pbs, byte, ke.len, "ikev2 impair KE (g^x) == 0")) {
			/* already logged */
			return false; /*fatal*/
		}
	} else if (impair.ke_payload == IMPAIR_EMIT_EMPTY) {
		llog(RC_LOG, outs->logger, "IMPAIR: sending an empty KE value");
		if (!pbs_out_zero(&ke_pbs, 0, "ikev2 impair KE (g^x) == empty")) {
			/* already logged */
			return false; /*fatal*/
		}
	} else {
		if (!pbs_out_hunk(&ke_pbs, ke, "ikev2 g^x"))
			return false;
	}

	close_pbs_out(&ke_pbs);
	return true;
}
