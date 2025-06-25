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
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017-2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2020 Nupur Agrawal <nupur202000@gmail.com>
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

#include "defs.h"
#include "rnd.h"
#include "ikev2_cookie.h"
#include "demux.h"
#include "ike_alg_hash.h"	/* for sha2 */
#include "crypt_hash.h"
#include "ikev2_send.h"
#include "log.h"
#include "state.h"
#include "ikev2.h"
#include "ikev2_ike_sa_init.h"
#include "ikev2_notification.h"

/*
 * That the cookie size of 32-bytes happens to match
 * SHA2_256_DIGEST_SIZE is just a happy coincidence.
 */
typedef struct {
	uint8_t bytes[32];
} v2_cookie_t;

static v2_cookie_t v2_cookie_secret;

void refresh_v2_cookie_secret(struct logger *logger)
{
	get_rnd_bytes(&v2_cookie_secret, sizeof(v2_cookie_secret));
	if (LDBGP(DBG_CRYPT, logger)) {
		LDBG_log(logger, "%s:", __func__);
		LDBG_thing(logger, v2_cookie_secret);
	}
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
				      struct msg_digest *md,
				      shunk_t Ni)
{
	struct crypt_hash *ctx = crypt_hash_init("IKEv2 COOKIE",
						 &ike_alg_hash_sha2_256,
						 md->logger);

	crypt_hash_digest_hunk(ctx, "Ni", Ni);

	ip_address sender = endpoint_address(md->sender);
	shunk_t IPi = address_as_shunk(&sender);
	crypt_hash_digest_hunk(ctx, "IPi", IPi);

	crypt_hash_digest_thing(ctx, "SPIi", md->hdr.isa_ike_initiator_spi);

	crypt_hash_digest_thing(ctx, "<secret>", v2_cookie_secret);

	/* happy coincidence? */
	pexpect(sizeof(cookie->bytes) == SHA2_256_DIGEST_SIZE);
	crypt_hash_final_bytes(&ctx, cookie->bytes, sizeof(cookie->bytes));

	return true;
}

bool v2_rejected_initiator_cookie(struct msg_digest *md,
				  bool me_want_cookie)
{
	struct logger *logger = md->logger;

	/* establish some home truths, but don't barf */
	if (!pexpect(md->hdr.isa_msgid == 0) ||
	    !pexpect(v2_msg_role(md) == MESSAGE_REQUEST) ||
	    !pexpect((md->hdr.isa_xchg == ISAKMP_v2_IKE_SA_INIT) ||
		     (md->hdr.isa_xchg == ISAKMP_v2_IKE_SESSION_RESUME)) ||
	    !pexpect(md->hdr.isa_flags & ISAKMP_FLAGS_v2_IKE_I)) {
		return true; /* reject cookie */
	}

	/*
	 * Expect the cookie notification to be first, and don't
	 * bother checking for things like duplicates.
	 */
	struct payload_digest *cookie_digest = NULL;
	if (md->hdr.isa_np == ISAKMP_NEXT_v2N &&
	    pexpect(md->chain[ISAKMP_NEXT_v2N] != NULL) &&
	    md->chain[ISAKMP_NEXT_v2N]->payload.v2n.isan_type == v2N_COOKIE) {
		cookie_digest = md->chain[ISAKMP_NEXT_v2N];
		pexpect(cookie_digest == md->pd[PD_v2N_COOKIE]);
	}
	if (!me_want_cookie && cookie_digest == NULL) {
		dbg("DDOS disabled and no cookie sent, continuing");
		return false; /* all ok!?! */
	}
	pexpect(me_want_cookie || cookie_digest != NULL);

	/*
	 * Paranoid mode is on - either DDOS or there's a cookie (or
	 * both).  So need to compute a cookie, but to do that v2Ni is
	 * needed ...
	 *
	 * Annoyingly this is the only reason why the payload needs to
	 * be parsed - the cookie is first so parsing the full packet
	 * shouldn't be needed.
	 *
	 * RFC 5996 Section 2.10 Nonces used in IKEv2 MUST be randomly
	 * chosen, MUST be at least 128 bits in size, and MUST be at
	 * least half the key size of the negotiated pseudorandom
	 * function (PRF) (We can check for minimum 128bit length).
	 */
	if (md->chain[ISAKMP_NEXT_v2Ni] == NULL) {
		llog_md(md, "DDOS cookie requires Ni paylod - dropping message");
		return true; /* reject cookie */
	}
	shunk_t Ni = pbs_in_left(&md->chain[ISAKMP_NEXT_v2Ni]->pbs);
	if (Ni.len < IKEv2_MINIMUM_NONCE_SIZE || IKEv2_MAXIMUM_NONCE_SIZE < Ni.len) {
		llog_md(md, "DOS cookie failed as Ni payload invalid - dropping message");
		return true; /* reject cookie */
	}

	/* Most code paths require our cookie, compute it. */
	v2_cookie_t my_cookie;
	if (!compute_v2_cookie_from_md(&my_cookie, md, Ni)) {
		return true; /* reject cookie */
	}
	shunk_t local_cookie = shunk2(&my_cookie, sizeof(my_cookie));

	/* No cookie? demand one */
	if (me_want_cookie && cookie_digest == NULL) {
		send_v2N_response_from_md(md, v2N_COOKIE, &local_cookie,
					  "DOS mode is on, initial request must include a COOKIE");
		return true; /* reject cookie */
	}

	/* done: !me_want_cookie && cookie_digest == NULL */
	/* done: me_want_cookie && cookie_digest == NULL */
	passert(cookie_digest != NULL);

	/*
	 * Check that the cookie notification is well constructed.
	 * Mainly for own sanity.
	 *
	 * Since they payload is understood ISAKMP_PAYLOAD_CRITICAL
	 * should be ignored.
	 */
	struct ikev2_notify *cookie_header = &cookie_digest->payload.v2n;
	if (cookie_header->isan_protoid != 0 ||
	    cookie_header->isan_spisize != 0 ||
	    cookie_header->isan_length != sizeof(v2_cookie_t) + sizeof(struct ikev2_notify)) {
		llog_md(md, "DOS cookie notification corrupt, or invalid - dropping message");
		return true; /* reject cookie */
	}
	shunk_t remote_cookie = pbs_in_left(&cookie_digest->pbs);

	if (LDBGP(DBG_BASE, logger)) {
		LDBG_log_hunk(logger, "received cookie:", remote_cookie);
		LDBG_log_hunk(logger, "computed cookie:", local_cookie);
	}

	if (!hunk_eq(local_cookie, remote_cookie)) {
		llog_md(md, "DOS cookies do not match - dropping message");
		return true; /* reject cookie */
	}
	dbg("cookies match");

	return false; /* love the cookie */
}

static stf_status resume_IKE_SA_INIT_with_cookie(struct ike_sa *ike)
{
	if (!record_v2_IKE_SA_INIT_request(ike)) {
		return STF_INTERNAL_ERROR;
	}
	return STF_OK;
}

stf_status process_v2_IKE_SA_INIT_response_v2N_COOKIE(struct ike_sa *ike,
						      struct child_sa *child,
						      struct msg_digest *md)
{
	PEXPECT(ike->sa.logger, child == NULL);
	if (!PEXPECT(ike->sa.logger, md->pd[PD_v2N_COOKIE] != NULL)) {
		return STF_INTERNAL_ERROR;
	}
	const struct pbs_in *cookie_pbs = &md->pd[PD_v2N_COOKIE]->pbs;

	/*
	 * Cookie exchanges are not logged when the connection is OE.
	 */
	lset_t rc_flags = (!is_opportunistic(ike->sa.st_connection) ? RC_LOG :
			   LDBGP(DBG_BASE, ike->sa.logger) ? DEBUG_STREAM :
			   LEMPTY);

	/*
	 * Responder replied with N(COOKIE) for DOS avoidance.  See
	 * rfc5996bis-04 2.6.
	 *
	 * Responder SPI ought to have been 0 (but might not be).  Our
	 * state should not advance.  Instead we should send our I1
	 * packet with the same cookie.
	 */

	/*
	 * RFC-7296 Section 2.6: The data associated with this
	 * notification MUST be between 1 and 64 octets in length
	 * (inclusive)
	 */
	shunk_t cookie = pbs_in_left(cookie_pbs);
	if (cookie.len > IKEv2_MAX_COOKIE_SIZE) {
		if (rc_flags != LEMPTY) {
			llog(rc_flags, ike->sa.logger, "IKEv2 COOKIE notify payload too big - packet dropped");
		}
		return STF_IGNORE;
	}
	if (cookie.len < 1) {
		if (rc_flags != LEMPTY) {
			llog(rc_flags, ike->sa.logger, "IKEv2 COOKIE notify payload too small - packet dropped");
		}
		return STF_IGNORE;
	}

	/*
	 * There's at least this notify payload, is there more than
	 * one?
	 */
	if (md->chain[ISAKMP_NEXT_v2N]->next != NULL) {
		ldbg(ike->sa.logger, "ignoring other notify payloads");
	}

	replace_chunk(&ike->sa.st_dcookie, cookie, "DDOS cookie");
	if (LDBGP(DBG_BASE, ike->sa.logger)) {
		LDBG_log(ike->sa.logger, "IKEv2 cookie received");
		LDBG_hunk(ike->sa.logger, ike->sa.st_dcookie);
	}

	if (rc_flags != LEMPTY) {
		llog(rc_flags, ike->sa.logger,
		     "received anti-DDOS COOKIE response, resending IKE_SA_INIT request with COOKIE payload");
	}

	/*
	 * restart the IKE SA with new information
	 */
	schedule_reinitiate_v2_ike_sa_init(ike, resume_IKE_SA_INIT_with_cookie);
	return STF_OK;
}

stf_status process_v2_IKE_SESSION_RESUME_response_v2N_COOKIE(struct ike_sa *ike,
							     struct child_sa *child UNUSED,
							     struct msg_digest *md UNUSED)
{
	llog_pexpect(ike->sa.logger, HERE, "not implemented");
	return STF_FATAL;
}
