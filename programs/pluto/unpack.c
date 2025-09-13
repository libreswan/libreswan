/* unpack generic parts of a message, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002,2010-2017 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2006  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010-2011 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2018 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2014-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017-2018 Antony Antony <antony@phenome.org>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
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

#include "ike_alg.h"
#include "id.h"
#include "ip_info.h"

#include "defs.h"		/* for so_serial_t */
#include "demux.h"
#include "unpack.h"
#include "log.h"
#include "packet.h"
#include "state.h"
#include "connections.h"

/* accept_KE
 *
 * Check and accept DH public value (Gi or Gr) from peer's message.
 * According to RFC2409 "The Internet key exchange (IKE)" 5:
 *  The Diffie-Hellman public value passed in a KE payload, in either
 *  a phase 1 or phase 2 exchange, MUST be the length of the negotiated
 *  Diffie-Hellman group enforced, if necessary, by prepending the
 *  value with zeros.
 */

bool extract_KE(struct state *st/*ike-or-child*/,
		const struct kem_desc *kem,
		struct msg_digest *md)
{
	const struct logger *logger = st->logger;

	/*
	 * Cross the streams, initiator expects responder's KE and
	 * vice-versa.
	 */

	chunk_t *dest;
	unsigned bytes;
	const char *peer;
	const char *name;

	switch (st->st_sa_role) {
	case SA_RESPONDER:
		bytes = kem->initiator_bytes;
		dest = &st->st_gi;
		name = "Gi";
		peer = "initiator";
		break;
	case SA_INITIATOR:
		bytes = kem->responder_bytes;
		dest = &st->st_gr;
		name = "Gr";
		peer = "responder";
		break;
	default:
		bad_case(st->st_sa_role);
	}

	/*
	 * basic checks
	 */

	if (PBAD(logger, kem == NULL)) {
		return false;
	}

	unsigned payload_nr = (st->st_ike_version == IKEv1 ? ISAKMP_NEXT_KE :
			       ISAKMP_NEXT_v2KE);
	const struct payload_digest *kd = md->chain[payload_nr];
	if (kd == NULL) {
		name_buf xn;
		llog(RC_LOG, logger, "%s %s message missing KE payload",
		     peer, str_enum_enum_short(&exchange_type_names, st->st_ike_version, md->hdr.isa_xchg, &xn));
		return false;
	}

	if (kd->next != NULL) {
		name_buf xn;
		llog(RC_LOG, logger, "%s %s message contains multiple KE payloads",
		     peer, str_enum_enum_short(&exchange_type_names, st->st_ike_version, md->hdr.isa_xchg, &xn));
		return false;
	}

	shunk_t ke = pbs_in_left(&kd->pbs);
	if (ke.len != bytes) {
		name_buf xn;
		llog(RC_LOG, logger, "%s %s KE payload is %zu bytes; %u required",
		     peer, str_enum_enum_short(&exchange_type_names, st->st_ike_version, md->hdr.isa_xchg, &xn),
		     ke.len, bytes);
		return false;
	}

	replace_chunk(dest, ke, name);
	if (LDBGP(DBG_CRYPT, logger)) {
		name_buf xn;
		LDBG_log(logger, "%s %s contained %u byte KE:",
			 peer, str_enum_enum_short(&exchange_type_names, st->st_ike_version, md->hdr.isa_xchg, &xn),
			 bytes);
		LDBG_hunk(logger, ke);
	}

	return true;
}

void unpack_nonce(chunk_t *n, chunk_t *nonce)
{
	/* steal away */
	free_chunk_content(n);
	*n = *nonce;
	*nonce = empty_chunk;
}
