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

/* accept_KE
 *
 * Check and accept DH public value (Gi or Gr) from peer's message.
 * According to RFC2409 "The Internet key exchange (IKE)" 5:
 *  The Diffie-Hellman public value passed in a KE payload, in either
 *  a phase 1 or phase 2 exchange, MUST be the length of the negotiated
 *  Diffie-Hellman group enforced, if necessary, by pre-pending the
 *  value with zeros.
 */

bool unpack_KE(chunk_t *dest, const char *val_name,
	       const struct dh_desc *gr,
	       struct payload_digest *ke_pd,
	       struct logger *logger)
{
	if (ke_pd == NULL) {
		llog(RC_LOG_SERIOUS, logger, "KE missing");
		return false;
	}
	struct pbs_in *pbs = &ke_pd->pbs;
	if (pbs_left(pbs) != gr->bytes) {
		llog(RC_LOG_SERIOUS, logger,
			    "KE has %u byte DH public value; %u required",
			    (unsigned) pbs_left(pbs), (unsigned) gr->bytes);
		return false;
	}
	replace_chunk(dest, clone_hunk(pbs_in_left_as_shunk(pbs), val_name));
	if (DBGP(DBG_CRYPT)) {
		DBG_log("DH public value received:");
		DBG_dump_hunk(NULL, *dest);
	}
	return true;
}

void unpack_nonce(chunk_t *n, chunk_t *nonce)
{
	replace_chunk(n, *nonce); /* steal away */
	*nonce = empty_chunk;
}

/*
 * Decode the ID payload of Phase 1 (main_inI3_outR3 and main_inR3)
 * Clears *peer to avoid surprises.
 * Note: what we discover may oblige Pluto to switch connections.
 * We must be called before SIG or HASH are decoded since we
 * may change the peer's RSA key or ID.
 */

diag_t unpack_peer_id(enum ike_id_type kind, struct id *peer, const struct pbs_in *id_pbs)
{
	size_t left = pbs_left(id_pbs);

	*peer = (struct id) {.kind = kind };	/* clears everything */

	switch (kind) {

	/* ident types mostly match between IKEv1 and IKEv2 */
	case ID_IPV4_ADDR:
	case ID_IPV6_ADDR:
	{
		/* failure mode for initaddr is probably inappropriate address length */
		const struct ip_info *afi = (kind == ID_IPV4_ADDR ? &ipv4_info :
					     kind == ID_IPV6_ADDR ? &ipv6_info :
					     NULL);
		struct pbs_in in_pbs = *id_pbs;
		diag_t d = pbs_in_address(&in_pbs, &peer->ip_addr, afi, "peer ID");
		if (d != NULL) {
			return d;
		}
		break;
	}

	/* seems odd to continue as ID_FQDN? */
	case ID_USER_FQDN:
#if 0
		if (memchr(id_pbs->cur, '@', left) == NULL) {
			llog(RC_LOG_SERIOUS, logger,
				    "peer's ID_USER_FQDN contains no @: %.*s",
				    (int) left, id_pbs->cur);
			/* return FALSE; */
		}
#endif
		if (memchr(id_pbs->cur, '\0', left) != NULL) {
			esb_buf b;
			return diag("Phase 1 (Parent)ID Payload of type %s contains a NUL",
				    enum_show(&ike_id_type_names, kind, &b));
		}
		/* ??? ought to do some more sanity check, but what? */
		peer->name = chunk2(id_pbs->cur, left);
		break;

	case ID_FQDN:
		if (memchr(id_pbs->cur, '\0', left) != NULL) {
			esb_buf b;
			return diag("Phase 1 (Parent)ID Payload of type %s contains a NUL",
				    enum_show(&ike_id_type_names, kind, &b));
		}
		/* ??? ought to do some more sanity check, but what? */
		peer->name = chunk2(id_pbs->cur, left);
		break;

	case ID_KEY_ID:
		peer->name = chunk2(id_pbs->cur, left);
		if (DBGP(DBG_BASE)) {
			DBG_dump_hunk("KEY ID:", peer->name);
		}
		break;

	case ID_DER_ASN1_DN:
		peer->name = chunk2(id_pbs->cur, left);
		if (DBGP(DBG_BASE)) {
		    DBG_dump_hunk("DER ASN1 DN:", peer->name);
		}
		break;

	case ID_NULL:
		if (left != 0) {
			if (DBGP(DBG_BASE)) {
				DBG_dump("unauthenticated NULL ID:", id_pbs->cur, left);
			}
		}
		break;

	default:
	{
		esb_buf b;
		return diag("Unsupported identity type (%s) in Phase 1 (Parent) ID Payload",
			    enum_show(&ike_id_type_names, kind, &b));
	}
	}

	return NULL;
}
