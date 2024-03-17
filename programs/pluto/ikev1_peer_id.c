/* IKEv1 peer ID, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2010,2013-2016 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2008-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2011 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2008 Hiren Joshi <joshihirenn@gmail.com>
 * Copyright (C) 2009 Anthony Tong <atong@TrustedCS.com>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
 * Copyright (C) 2019-2021 Andrew Cagney <cagney@gnu.org>
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
#include "demux.h"
#include "state.h"
#include "connections.h"
#include "ikev1_peer_id.h"
#include "log.h"
#include "unpack.h"
#include "pluto_x509.h"
#include "ikev1_xauth.h"
#include "keys.h"
#include "ike_alg_hash.h"
#include "secrets.h"
#include "peer_id.h"
#include "ikev1_cert.h"

static bool decode_peer_id(struct state *st, struct msg_digest *md, struct id *peer);

bool ikev1_decode_peer_id_initiator(struct state *st, struct msg_digest *md)
{
	struct id peer[1]; /* hack for pointer */
	if (!decode_peer_id(st, md, peer)) {
		/* already logged */
		return false;
	}

	diag_t d = update_peer_id(pexpect_ike_sa(st), peer, NULL/*tarzan*/);
	if (d != NULL) {
		llog_diag(RC_LOG_SERIOUS, st->logger, &d, "%s", "");
		return false;
	}

	return true;
}

bool ikev1_decode_peer_id_aggr_mode_responder(struct state *st,
					      struct msg_digest *md)
{
	struct id peer;
	if (!decode_peer_id(st, md, &peer)) {
		/* already logged */
		return false;
	}

	diag_t d = update_peer_id(pexpect_ike_sa(st),  &peer, NULL/*tarzan*/);
	if (d != NULL) {
		llog_diag(RC_LOG_SERIOUS, st->logger, &d, "%s", "");
		return false;
	}

	return true;
}

/*
 * note: may change which connection is referenced by md->v1_st->st_connection.
 * But only if we are a Main Mode Responder.
 */

bool ikev1_decode_peer_id_main_mode_responder(struct state *st, struct msg_digest *md)
{
	struct id peer_id; /* pointer hack */
	if (!decode_peer_id(st, md, &peer_id)) {
		/* already logged */
		return false;
	}

	/*
	 * Now that we've decoded the ID payload, let's see if we
	 * need to switch connections.
	 * Aggressive mode cannot switch connections.
	 * We must not switch horses if we initiated:
	 * - if the initiation was explicit, we'd be ignoring user's intent
	 * - if opportunistic, we'll lose our HOLD info
	 */

	/* Main Mode Responder */
	uint16_t auth = xauth_calcbaseauth(st->st_oakley.auth);

	/*
	 * Translate the IKEv1 policy onto IKEv2(?) auth enum.
	 * Saves duplicating the checks for v1 and v2, and the
	 * v1 policy is a subset of the v2 policy.
	 */

	lset_t proposed_authbys;
	switch (auth) {
	case OAKLEY_PRESHARED_KEY:
		proposed_authbys = LELEM(AUTH_PSK);
		break;
	case OAKLEY_RSA_SIG:
		proposed_authbys = LELEM(AUTH_RSASIG);
		break;
		/* Not implemented */
	case OAKLEY_DSS_SIG:
	case OAKLEY_RSA_ENC:
	case OAKLEY_RSA_REVISED_MODE:
	case OAKLEY_ECDSA_P256:
	case OAKLEY_ECDSA_P384:
	case OAKLEY_ECDSA_P521:
	default:
		dbg("ikev1 ike_decode_peer_id bad_case due to not supported policy");
		return false;
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
	refine_host_connection_of_state_on_responder(st, proposed_authbys, &peer_id,
						     /* IKEv1 does not support 'you Tarzan, me Jane' */NULL);

	diag_t d = update_peer_id(pexpect_ike_sa(st), &peer_id, NULL/*tarzan*/);
	if (d != NULL) {
		llog_diag(RC_LOG_SERIOUS, st->logger, &d, "%s", "");
		return false;
	}

	return true;
}

static bool decode_peer_id(struct state *st, struct msg_digest *md, struct id *peer)
{
	/* check for certificate requests */
	decode_v1_certificate_requests(st, md);

	const struct payload_digest *const id_pld = md->chain[ISAKMP_NEXT_ID];
	const struct isakmp_id *const id = &id_pld->payload.id;

	/*
	 * I think that RFC2407 (IPSEC DOI) 4.6.2 is confused.
	 * It talks about the protocol ID and Port fields of the ID
	 * Payload, but they don't exist as such in Phase 1.
	 * We use more appropriate names.
	 * isaid_doi_specific_a is in place of Protocol ID.
	 * isaid_doi_specific_b is in place of Port.
	 * Besides, there is no good reason for allowing these to be
	 * other than 0 in Phase 1.
	 */
	if (st->hidden_variables.st_nat_traversal != LEMPTY &&
	    id->isaid_doi_specific_a == IPPROTO_UDP &&
	    (id->isaid_doi_specific_b == 0 ||
	     id->isaid_doi_specific_b == NAT_IKE_UDP_PORT)) {
		dbg("protocol/port in Phase 1 ID Payload is %d/%d. accepted with port_floating NAT-T",
		    id->isaid_doi_specific_a, id->isaid_doi_specific_b);
	} else if (!(id->isaid_doi_specific_a == 0 &&
		     id->isaid_doi_specific_b == 0) &&
		   !(id->isaid_doi_specific_a == IPPROTO_UDP &&
		     id->isaid_doi_specific_b == IKE_UDP_PORT)) {
		log_state(RC_LOG_SERIOUS, st,
			  "protocol/port in Phase 1 ID Payload MUST be 0/0 or %d/%d but are %d/%d (attempting to continue)",
			  IPPROTO_UDP, IKE_UDP_PORT,
			  id->isaid_doi_specific_a,
			  id->isaid_doi_specific_b);
		/*
		 * We have turned this into a warning because of bugs
		 * in other vendors' products. Specifically CISCO
		 * VPN3000.
		 */
		/* return false; */
	}

	diag_t d = unpack_peer_id(id->isaid_idtype, peer, &id_pld->pbs);
	if (d != NULL) {
		llog_diag(RC_LOG, st->logger, &d, "%s", "");
		return false;
	}

	/*
	 * For interop with SoftRemote/aggressive mode we need to remember some
	 * things for checking the hash
	 */
	st->st_peeridentity_protocol = id->isaid_doi_specific_a;
	st->st_peeridentity_port = ntohs(id->isaid_doi_specific_b);

	id_buf buf;
	enum_buf b;
	log_state(RC_LOG, st, "Peer ID is %s: '%s'",
		  str_enum(&ike_id_type_names, id->isaid_idtype, &b),
		  str_id(peer, &buf));

	return true;
}

/*
 * Process the Main Mode ID Payload and the Authenticator
 * (Hash or Signature Payload).
 * XXX: This is used by aggressive mode too, move to ikev1.c ???
 */
stf_status oakley_auth(struct msg_digest *md, bool initiator)
{
	struct state *st = md->v1_st;
	stf_status r = STF_OK;

	/*
	 * Hash the ID Payload.
	 * main_mode_hash requires idpl->cur to be at end of payload
	 * so we temporarily set if so.
	 */
	struct crypt_mac hash;
	{
		struct pbs_in *idpl = &md->chain[ISAKMP_NEXT_ID]->pbs;
		uint8_t *old_cur = idpl->cur;

		idpl->cur = idpl->roof;
		/* authenticating other end, flip role! */
		hash = main_mode_hash(st, initiator ? SA_RESPONDER : SA_INITIATOR, idpl);
		idpl->cur = old_cur;
	}

	switch (st->st_oakley.auth) {
	case OAKLEY_PRESHARED_KEY:
	{
		struct pbs_in *const hash_pbs = &md->chain[ISAKMP_NEXT_HASH]->pbs;

		/*
		 * XXX: looks a lot like the hack CHECK_QUICK_HASH(),
		 * except this one doesn't return.  Strong indicator
		 * that CHECK_QUICK_HASH should be changed to a
		 * function and also not magically force caller to
		 * return.
		 */
		if (pbs_left(hash_pbs) != hash.len ||
			!memeq(hash_pbs->cur, hash.ptr, hash.len)) {
			if (DBGP(DBG_CRYPT)) {
				DBG_dump("received HASH:",
					 hash_pbs->cur, pbs_left(hash_pbs));
			}
			log_state(RC_LOG_SERIOUS, st,
				  "received Hash Payload does not match computed value");
			/* XXX Could send notification back */
			r = STF_FAIL_v1N + v1N_INVALID_HASH_INFORMATION;
		} else {
			dbg("received message HASH_%s data ok",
			    initiator ? "R" : "I" /*reverse*/);
		}
		break;
	}

	case OAKLEY_RSA_SIG:
	{
		shunk_t signature = pbs_in_left(&md->chain[ISAKMP_NEXT_SIG]->pbs);
		diag_t d = authsig_and_log_using_pubkey(ike_sa(st, HERE),
							&hash, signature,
							&ike_alg_hash_sha1, /*always*/
							&pubkey_signer_raw_rsa,
							NULL/*legacy-signature-name*/);
		if (d != NULL) {
			llog_diag(RC_LOG_SERIOUS, st->logger, &d, "%s", "");
			dbg("received message SIG_%s data did not match computed value",
			    initiator ? "R" : "I" /*reverse*/);
			r = STF_FAIL_v1N + v1N_INVALID_KEY_INFORMATION;
		}
		break;
	}
	/* These are the only IKEv1 AUTH methods we support */
	default:
		bad_case(st->st_oakley.auth);
	}

	if (r == STF_OK)
		dbg("authentication succeeded");
	return r;
}
