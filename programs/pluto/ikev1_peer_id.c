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

static bool decode_peer_id(struct ike_sa *ike, struct msg_digest *md, struct id *peer);

bool ikev1_decode_peer_id_initiator(struct ike_sa *ike, struct msg_digest *md)
{
	struct id peer;
	if (!decode_peer_id(ike, md, &peer)) {
		/* already logged */
		return false;
	}

	diag_t d = update_peer_id(ike, &peer, NULL/*IKEv2:tarzan*/);
	if (d != NULL) {
		llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
		pfree_diag(&d);
		return false;
	}

	return true;
}

bool ikev1_decode_peer_id_aggr_mode_responder(struct ike_sa *ike,
					      struct msg_digest *md)
{
	struct id initiator_id;
	if (!decode_peer_id(ike, md, &initiator_id)) {
		/* already logged */
		return false;
	}

	diag_t d = update_peer_id(ike,  &initiator_id, NULL/*IKEv2:tarzan*/);
	if (d != NULL) {
		llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
		pfree_diag(&d);
		return false;
	}

	return true;
}

/*
 * note: may change which connection is referenced by md->v1_st->st_connection.
 * But only if we are a Main Mode Responder.
 */

bool ikev1_decode_peer_id_main_mode_responder(struct ike_sa *ike, struct msg_digest *md)
{
	struct id initiator_id;
	if (!decode_peer_id(ike, md, &initiator_id)) {
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
	uint16_t auth = xauth_calcbaseauth(ike->sa.st_oakley.auth);

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
		ldbg(ike->sa.logger,
		     "ikev1 ike_decode_peer_id bad_case due to not supported policy");
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
	 * This may change ike->sa.st_connection!
	 * Our caller might be surprised!
	 */
	refine_host_connection_of_state_on_responder(ike, proposed_authbys, &initiator_id,
						     /* IKEv1 does not support 'you Tarzan, me Jane' */NULL);

	diag_t d = update_peer_id(ike, &initiator_id, NULL/*tarzan*/);
	if (d != NULL) {
		llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
		pfree_diag(&d);
		return false;
	}

	return true;
}

static bool decode_peer_id(struct ike_sa *ike, struct msg_digest *md, struct id *peer)
{
	/* check for certificate requests */
	decode_v1_certificate_requests(ike, md);

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
	if (ike->sa.hidden_variables.st_nat_traversal != LEMPTY &&
	    id->isaid_doi_specific_a == IPPROTO_UDP &&
	    (id->isaid_doi_specific_b == 0 ||
	     id->isaid_doi_specific_b == NAT_IKE_UDP_PORT)) {
		ldbg(ike->sa.logger,
		     "protocol/port in Phase 1 ID Payload is %d/%d. accepted with port_floating NAT-T",
		     id->isaid_doi_specific_a, id->isaid_doi_specific_b);
	} else if (!(id->isaid_doi_specific_a == 0 &&
		     id->isaid_doi_specific_b == 0) &&
		   !(id->isaid_doi_specific_a == IPPROTO_UDP &&
		     id->isaid_doi_specific_b == IKE_UDP_PORT)) {
		llog(RC_LOG, ike->sa.logger,
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

	diag_t d = unpack_id(id->isaid_idtype, peer, &id_pld->pbs, ike->sa.logger);
	if (d != NULL) {
		llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
		pfree_diag(&d);
		return false;
	}

	/*
	 * For interop with SoftRemote/aggressive mode we need to remember some
	 * things for checking the hash
	 */
	ike->sa.st_peeridentity_protocol = id->isaid_doi_specific_a;
	ike->sa.st_peeridentity_port = ntohs(id->isaid_doi_specific_b);

	id_buf buf;
	name_buf b;
	llog(RC_LOG, ike->sa.logger, "Peer ID is %s: '%s'",
	     str_enum_short(&ike_id_type_names, id->isaid_idtype, &b),
	     str_id(peer, &buf));

	return true;
}

/*
 * Process the Main Mode ID Payload and the Authenticator
 * (Hash or Signature Payload).
 * XXX: This is used by aggressive mode too, move to ikev1.c ???
 */
stf_status oakley_auth(struct ike_sa *ike, struct msg_digest *md,
		       enum sa_role sa_role, shunk_t id_payload)
{
	stf_status r = STF_OK;

	/*
	 * Hash the ID Payload.
	 *
	 * main_mode_hash() expects the entire ID payload, i.e., up to
	 * .raw.  Hence pbs_in_all.
	 */
	struct crypt_mac hash = main_mode_hash(ike, sa_role, id_payload);

	switch (ike->sa.st_oakley.auth) {
	case OAKLEY_PRESHARED_KEY:
	{
		shunk_t pbs_hash = pbs_in_left(&md->chain[ISAKMP_NEXT_HASH]->pbs);

		/*
		 * XXX: looks a lot like the hack CHECK_QUICK_HASH(),
		 * except this one doesn't return.  Strong indicator
		 * that CHECK_QUICK_HASH should be changed to a
		 * function and also not magically force caller to
		 * return.
		 */
		if (hunk_eq(pbs_hash, hash)) {
			ldbg(ike->sa.logger, "received message HASH_%s data ok",
			     (sa_role == SA_INITIATOR ? "I" :
			      sa_role == SA_RESPONDER ? "R" :
			      "???"));
		} else {
			if (LDBGP(DBG_CRYPT, ike->sa.logger)) {
				LDBG_log(ike->sa.logger, "received HASH:");
				LDBG_hunk(ike->sa.logger, pbs_hash);
			}
			llog(RC_LOG, ike->sa.logger,
			     "received Hash Payload does not match computed value");
			/* XXX Could send notification back */
			r = STF_FAIL_v1N + v1N_INVALID_HASH_INFORMATION;
		}
		break;
	}

	case OAKLEY_RSA_SIG:
	{
		shunk_t signature = pbs_in_left(&md->chain[ISAKMP_NEXT_SIG]->pbs);
		diag_t d = authsig_and_log_using_pubkey(ike, &hash, signature,
							&ike_alg_hash_sha1, /*always*/
							&pubkey_signer_raw_rsa,
							NULL/*legacy-signature-name*/);
		if (d != NULL) {
			llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
			pfree_diag(&d);
			ldbg(ike->sa.logger, "received message SIG_%s data did not match computed value",
			     (sa_role == SA_INITIATOR ? "I" :
			      sa_role == SA_RESPONDER ? "R" :
			      "???"));
			r = STF_FAIL_v1N + v1N_INVALID_KEY_INFORMATION;
		}
		break;
	}
	/* These are the only IKEv1 AUTH methods we support */
	default:
		bad_case(ike->sa.st_oakley.auth);
	}

	if (r == STF_OK)
		ldbg(ike->sa.logger, "authentication succeeded");
	return r;
}
