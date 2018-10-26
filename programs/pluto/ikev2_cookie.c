/* IKEv2 cookie calculation, for Libreswan
 *
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi
 * Copyright (C) 2012-2018 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012-2018 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013-2016 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2015-2018 Andrew Cagney
 * Copyright (C) 2017-2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
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

#include "lswlog.h"

#include "defs.h"
#include "rnd.h"
#include "ikev2_cookie.h"
#include "demux.h"
#include "ike_alg_hash.h"	/* for sha2 */
#include "crypt_hash.h"
#include "ikev2_send.h"

/*
 * That the cookie size of 32-bytes happens to match
 * SHA2_256_DIGEST_SIZE is just a happy coincidence.
 */
typedef struct {
	uint8_t bytes[32];
} v2_cookie_t;

static uint8_t v2_cookie_secret[sizeof(v2_cookie_t)];

void refresh_v2_cookie_secret(void)
{
	get_rnd_bytes(v2_cookie_secret, sizeof(v2_cookie_secret));
	DBG(DBG_PRIVATE,
	    DBG_dump("v2_cookie_secret",
		     v2_cookie_secret, sizeof(v2_cookie_secret)));
}

/*
 * Cookie = <VersionIDofSecret> | Hash(Ni | IPi | SPIi | <secret>)
 * where <secret> is a randomly generated secret known only to us
 *
 * Our implementation does not use <VersionIDofSecret> which means
 * once a day and while under DOS attack, we could fail a few cookies
 * until the peer restarts from scratch.
 */
static bool compute_v2_cookie_from_md(v2_cookie_t *cookie,
				      struct msg_digest *md)
{
	chunk_t SPIi = chunk(md->hdr.isa_icookie, IKE_SA_SPI_SIZE);
	chunk_t Ni = same_in_pbs_left_as_chunk(&md->chain[ISAKMP_NEXT_v2Ni]->pbs);

	/*
	 * RFC 5996 Section 2.10 Nonces used in IKEv2 MUST be randomly
	 * chosen, MUST be at least 128 bits in size, and MUST be at
	 * least half the key size of the negotiated pseudorandom
	 * function (PRF).  (We can check for minimum 128bit length)
	 */

	/*
	 * XXX: Note that we check the nonce size in accept_v2_nonce()
	 * so this check is extra. I guess since we need to extract
	 * the nonce to calculate the cookie, it is cheap to check
	 * here and reject.
	 */

	if (Ni.len < IKEv2_MINIMUM_NONCE_SIZE || IKEv2_MAXIMUM_NONCE_SIZE < Ni.len) {
		/*
		 * If this were a DDOS, we cannot afford to log.  We
		 * do log if we are debugging.
		 */
		DBGF(DBG_MASK, "Dropping message with insufficient length Nonce");
		return false;
	}

	struct crypt_hash *ctx = crypt_hash_init(&ike_alg_hash_sha2_256,
						 "IKEv2 cookie", DBG_CRYPT);

	crypt_hash_digest_chunk(ctx, "Ni", Ni);

	chunk_t IPi = same_ip_address_as_chunk(&md->sender);
	crypt_hash_digest_chunk(ctx, "IPi", IPi);

	crypt_hash_digest_chunk(ctx, "SPIi", SPIi);

	crypt_hash_digest_bytes(ctx, "<secret>", v2_cookie_secret,
				sizeof(v2_cookie_secret));

	/* happy coincidence? */
	pexpect(sizeof(cookie->bytes) == SHA2_256_DIGEST_SIZE);
	crypt_hash_final_bytes(&ctx, cookie->bytes, sizeof(cookie->bytes));

	DBG(DBG_CRYPT,
	    DBG_dump("computed dcookie: HASH(Ni | IPi | SPIi | <secret>)",
		     cookie->bytes, sizeof(cookie->bytes)));

	return true;
}

bool v2_reject_cookie(struct msg_digest *md, bool require_dcookie)
{
	struct payload_digest *seen_dcookie = NULL;

	/* Process NOTIFY payloads, including checking for a DCOOKIE */
	for (struct payload_digest *ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
		if (ntfy->payload.v2n.isan_type == v2N_COOKIE) {
			if (seen_dcookie == NULL) {
				DBG(DBG_CONTROLMORE,
					DBG_log("Received a NOTIFY payload of type COOKIE - we will verify the COOKIE"));
				seen_dcookie = ntfy;
				if (ntfy != md->chain[ISAKMP_NEXT_v2N]) {
					/* ??? Should this error be logged?  Might make DDOS worse. */
					DBG(DBG_CONTROL, DBG_log("ERROR: NOTIFY payload of type COOKIE is not the first payload"));
					/* accept dcookie anyway */
				}
			} else {
				/* ??? Should this error be logged?  Might make DDOS worse. */
				DBG(DBG_CONTROL,
					DBG_log("ignoring second NOTIFY payload of type COOKIE"));
			}
		}
	}

	/*
	 * The RFC states we should ignore unexpected cookies. We
	 * purposefully violate the RFC and validate the cookie
	 * anyway. This prevents an attacker from being able to inject
	 * a lot of data used later to HMAC
	 */
	if (seen_dcookie != NULL || require_dcookie) {
		v2_cookie_t cookie;
		if (!compute_v2_cookie_from_md(&cookie, md)) {
			return true; /* reject cookie */
		}
		/* easier to manipulate */
		chunk_t dc = chunk(&cookie, sizeof(cookie));

		if (seen_dcookie != NULL) {
			/* we received a dcookie: verify that it is the one we sent */

			DBG(DBG_CONTROLMORE,
			    DBG_log("received a DOS cookie in I1 verify it"));
			if (seen_dcookie->payload.v2n.isan_spisize != 0) {
				DBG(DBG_CONTROLMORE, DBG_log(
					"DOS cookie contains non-zero length SPI - message discarded"
				));
				return true; /* reject cookie */
			}

			const pb_stream *dc_pbs = &seen_dcookie->pbs;
			chunk_t idc = {.ptr = dc_pbs->cur, .len = pbs_left(dc_pbs)};

			DBG(DBG_CONTROLMORE,
			    DBG_dump_chunk("received cookie", idc);
			    DBG_dump_chunk("computed cookie", dc));

			if (!chunk_eq(idc, dc)) {
				DBG(DBG_CONTROLMORE, DBG_log(
					"mismatch in DOS v2N_COOKIE: dropping message (possible attack)"
				));
				return true; /* reject cookie */
			}
			DBG(DBG_CONTROLMORE, DBG_log(
				"dcookie received matched computed one"));
		} else {
			/* we are under DOS attack and I1 contains no COOKIE */
			DBG(DBG_CONTROLMORE,
			    DBG_log("busy mode on. received I1 without a valid dcookie");
			    DBG_log("send a dcookie and forget this state"));
			send_v2_notification_from_md(md, v2N_COOKIE, &dc);
			return true; /* reject cookie */
		}
	} else {
		DBG(DBG_CONTROLMORE,
		    DBG_log("anti-DDoS cookies not required (and no cookie received)"));
	}
	return false; /* love the cookie */
}
