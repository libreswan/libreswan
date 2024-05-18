/* identify the PEER, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2010,2013-2017 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 Simon Deziel <simon@xelerance.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2011-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2015-2019 Andrew Cagney
 * Copyright (C) 2016-2018 Antony Antony <appu@phenome.org>
 * Copyright (C) 2017 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
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

#include "ikev2_peer_id.h"

#include "defs.h"
#include "state.h"
#include "connections.h"
#include "log.h"
#include "demux.h"
#include "unpack.h"
#include "pluto_x509.h"
#include "peer_id.h"
#include "ikev2_certreq.h"

static diag_t decode_v2_peer_id(const char *peer, struct payload_digest *const id_peer, struct id *peer_id)
{
	if (id_peer == NULL) {
		return diag("authentication failed: %s did not include ID payload", peer);
	}

	diag_t d = unpack_peer_id(id_peer->payload.v2id.isai_type /* Peers Id Kind */,
				  peer_id, &id_peer->pbs);
	if (d != NULL) {
		return diag_diag(&d, "authentication failed: %s ID payload invalid: ", peer);
	}

	id_buf idb;
	esb_buf esb;
	dbg("%s ID is %s: '%s'", peer,
	    str_enum(&ike_id_type_names, peer_id->kind, &esb),
	    str_id(peer_id, &idb));

	return NULL;
}

diag_t ikev2_responder_decode_initiator_id(struct ike_sa *ike, struct msg_digest *md)
{
	/* c = ike->sa.st_connection; <- not yet known */
	passert(ike->sa.st_sa_role == SA_RESPONDER);

	struct id peer_id;
	diag_t d = decode_v2_peer_id("initiator", md->chain[ISAKMP_NEXT_v2IDi], &peer_id);
	if (d != NULL) {
		return d;
	}

	/* You Tarzan, me Jane? */
	struct id tarzan_id_val;	/* may be unset */
	struct id *tarzan_id = NULL;	/* tarzan ID pointer (or NULL) */
	{
		const struct payload_digest *const tarzan_pld = md->chain[ISAKMP_NEXT_v2IDr];

		if (tarzan_pld != NULL) {
			diag_t d = unpack_peer_id(tarzan_pld->payload.v2id.isai_type,
						  &tarzan_id_val, &tarzan_pld->pbs);
			if (d != NULL) {
				return diag_diag(&d, "IDr payload extraction failed: ");
			}
			tarzan_id = &tarzan_id_val;
			id_buf idb;
			dbg("received IDr - our alleged ID '%s'", str_id(tarzan_id, &idb));
		}
	}

	/*
	 * Convert the proposed connections into something this
	 * responder might accept.
	 *
	 * + DIGITAL_SIGNATURE code seems a bit dodgy, should this be
	 * looking inside the auth proposal to see what is actually
	 * required?
	 *
	 * + the legacy ECDSA_SHA2* methods also seem to be a bit
	 * dodgy, shouldn't they also specify the SHA algorithm so
	 * that can be matched?
	 */

	if (md->chain[ISAKMP_NEXT_v2AUTH] == NULL) {
		return NULL; // Cannot refine without knowing peer ID
	}
	enum ikev2_auth_method atype =
		md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2auth.isaa_auth_method;
	enum keyword_auth proposed_authbys;
	switch (atype) {
	case IKEv2_AUTH_RSA_DIGITAL_SIGNATURE:
		proposed_authbys = LELEM(AUTH_RSASIG);
		break;
	case IKEv2_AUTH_ECDSA_SHA2_256_P256:
	case IKEv2_AUTH_ECDSA_SHA2_384_P384:
	case IKEv2_AUTH_ECDSA_SHA2_512_P521:
		proposed_authbys = LELEM(AUTH_ECDSA);
		break;
	case IKEv2_AUTH_SHARED_KEY_MAC:
		proposed_authbys = LELEM(AUTH_PSK);
		break;
	case IKEv2_AUTH_NULL:
		proposed_authbys = LELEM(AUTH_NULL);
		break;
	case IKEv2_AUTH_DIGITAL_SIGNATURE:
		proposed_authbys = LELEM(AUTH_RSASIG) | LELEM(AUTH_ECDSA);
		break;
	default:
		dbg("ikev2 skipping refine_host_connection due to unknown policy");
		return NULL;
	}

	/*
	 * IS_MOST_REFINED is subtle.
	 *
	 * IS_MOST_REFINED: the state's (possibly updated) connection
	 * is known to be the best there is (best can include the
	 * current connection).
	 *
	 * !IS_MOST_REFINED: is less specific.  For IKEv1, the search
	 * didn't find a best; for IKEv2 it can additionally mean that
	 * there was no search because the initiator proposed
	 * AUTH_NULL.  AUTH_NULL never switches as it is assumed
	 * that the perfect connection was chosen during IKE_SA_INIT.
	 *
	 * Either way, !IS_MOST_REFINED leads to a same_id() and other
	 * checks.
	 *
	 * This may change st->st_connection!
	 * Our caller might be surprised!
	 */
       if (!LHAS(proposed_authbys, AUTH_NULL)) {
	       refine_host_connection_of_state_on_responder(ike, proposed_authbys,
							    &peer_id, tarzan_id);
       }

       return update_peer_id(ike, &peer_id, tarzan_id);
}

diag_t ikev2_initiator_decode_responder_id(struct ike_sa *ike, struct msg_digest *md)
{
	passert(ike->sa.st_sa_role == SA_INITIATOR);

	struct id responder_id;
 	diag_t d = decode_v2_peer_id("responder", md->chain[ISAKMP_NEXT_v2IDr], &responder_id);
	if (d != NULL) {
		return d;
	}

	/* start considering connection */
	return update_peer_id(ike, &responder_id, NULL/*tarzan isn't interesting*/);

}
