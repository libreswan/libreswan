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

static diag_t decode_v2ID(const char *peer,
			  const struct payload_digest *const pd,
			  struct id *id,
			  struct logger *logger)
{
	if (pbad(pd == NULL)) {
		return diag("INTERNAL ERROR");
	}

	diag_t d = unpack_id(/*ID kind*/pd->payload.v2id.isai_type,
			     id, &pd->pbs, logger);
	if (d != NULL) {
		return diag_diag(&d, "authentication failed: %s ID payload invalid: ", peer);
	}

	id_buf idb;
	esb_buf esb;
	ldbg(logger, "%s ID is %s: '%s'", peer,
	     str_enum_short(&ike_id_type_names, id->kind, &esb),
	     str_id(id, &idb));

	return NULL;
}

diag_t ikev2_responder_decode_v2ID_payloads(struct ike_sa *ike,
					    struct msg_digest *md,
					    struct id *initiator_id,
					    struct id *responder_id)
{
	/* c = ike->sa.st_connection; <- not yet known */
	passert(ike->sa.st_sa_role == SA_RESPONDER);
	zero(initiator_id);
	zero(responder_id);

	const struct payload_digest *const IDi = md->chain[ISAKMP_NEXT_v2IDi];
	if (IDi == NULL) {
		return diag("authentication failed: initiator did not include IDi payload");
	}

	diag_t d = decode_v2ID("initiator", IDi, initiator_id, ike->sa.logger);
	if (d != NULL) {
		return d;
	}

	/* You Tarzan, me Jane? */
	const struct payload_digest *IDr = md->chain[ISAKMP_NEXT_v2IDr];
	if (IDr != NULL) {
		diag_t d = decode_v2ID("responder", IDr, responder_id, ike->sa.logger);
		if (d != NULL) {
			return d;
		}
		id_buf idb;
		ldbg(ike->sa.logger,
		     "received IDr - our alleged ID '%s'", str_id(responder_id, &idb));
	}

	return NULL;
}

diag_t ikev2_initiator_decode_responder_id(struct ike_sa *ike, struct msg_digest *md)
{
	passert(ike->sa.st_sa_role == SA_INITIATOR);

	const struct payload_digest *const IDr = md->chain[ISAKMP_NEXT_v2IDr];
	if (IDr == NULL) {
		return diag("authentication failed: responder did not include IDr payload");
	}

	struct id responder_id;
 	diag_t d = decode_v2ID("responder", IDr, &responder_id, ike->sa.logger);
	if (d != NULL) {
		return d;
	}

	/* start considering connection */
	return update_peer_id(ike, &responder_id,
			      NULL/*tarzan isn't interesting*/);

}
