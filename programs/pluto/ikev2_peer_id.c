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

static diag_t responder_match_initiator_id_counted(struct ike_sa *ike,
						   struct id peer_id,
						   struct id *tarzan_id,
						   struct msg_digest *md, int depth)
{
	if (depth > 10) {
		/* should not happen, but it would be nice to survive */
		return diag("decoding IKEv2 peer ID failed due to confusion");
	}

	bool must_switch = false;

	/* start considering connection */

	struct connection *c = ike->sa.st_connection;

	/*
	 * If there are certs, try re-running the id check.
	 */
	bool initiator_cert_id_ok = false;
	if (ike->sa.st_remote_certs.verified != NULL) {
		if (match_certs_id(ike->sa.st_remote_certs.verified,
				   &c->spd.that.id /*ID_FROMCERT => updated*/,
				   ike->sa.st_logger)) {
			dbg("X509: CERT and ID matches current connection");
			initiator_cert_id_ok = true;
		} else {
			log_state(RC_LOG, &ike->sa, "Peer CERT payload SubjectAltName does not match peer ID for this connection");
			if (!LIN(POLICY_ALLOW_NO_SAN, c->policy)) {
				diag_t d = diag("X509: connection failed due to unmatched IKE ID in certificate SAN");
				llog_diag(RC_LOG, ike->sa.st_logger, &d, "%s", "");
				must_switch = true;
			} else {
				log_state(RC_LOG, &ike->sa, "X509: connection allows unmatched IKE ID and certificate SAN");
			}
		}
	}

	/* process any CERTREQ payloads */
	ikev2_decode_cr(md, ike->sa.st_logger);

	/*
	 * Figure out the authentication, use both what the initiator
	 * suggested and what the current connection contains.
	 */
	uint16_t auth = md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2auth.isaa_auth_method;
	enum keyword_authby authby = AUTHBY_NEVER;

	switch (auth) {
	case IKEv2_AUTH_RSA:
		authby = AUTHBY_RSASIG;
		break;
	case IKEv2_AUTH_PSK:
		authby = AUTHBY_PSK;
		break;
	case IKEv2_AUTH_NULL:
		authby = AUTHBY_NULL;
		break;
	case IKEv2_AUTH_DIGSIG:
		if (c->policy & POLICY_RSASIG) {
			authby = AUTHBY_RSASIG;
			break;
		}
		if (c->policy & POLICY_ECDSA) {
			authby = AUTHBY_ECDSA;
			break;
		}
		/* FALL THROUGH */
	case IKEv2_AUTH_NONE:
	default:
		dbg("ikev2 skipping refine_host_connection due to unknown policy");
	}

	/*
	 * Now that we've decoded the ID payload, let's see if we
	 * need to switch connections.
	 * We must not switch horses if we initiated:
	 * - if the initiation was explicit, we'd be ignoring user's intent
	 * - if opportunistic, we'll lose our HOLD info
	 */

	if (authby != AUTHBY_NEVER) {
		struct connection *r = NULL;
		id_buf peer_str;
		bool fromcert = peer_id.kind == ID_DER_ASN1_DN;

		if (authby != AUTHBY_NULL) {
			r = refine_host_connection(
				md->st, &peer_id, tarzan_id, FALSE /*initiator*/,
				LEMPTY /* auth_policy */, authby, &fromcert);
		}

		if (r == NULL) {
			/* no "improvement" on c found */
			if (DBGP(DBG_BASE)) {
				id_buf peer_str;
				DBG_log("no suitable connection for peer '%s'",
					str_id(&peer_id, &peer_str));
			}
			/* can we continue with what we had? */
			if (must_switch) {
				return diag("Peer ID '%s' is not specified on the certificate SubjectAltName (SAN) and no better connection found",
					    str_id(&peer_id, &peer_str));
			}
			/* if X.509, we should have valid peer/san */
			if (ike->sa.st_remote_certs.verified != NULL && !initiator_cert_id_ok) {
				return diag("`Peer ID '%s' is not specified on the certificate SubjectAltName (SAN) and no better connection found",
					    str_id(&peer_id, &peer_str));
			}
			if (!initiator_cert_id_ok &&
			    !same_id(&c->spd.that.id, &peer_id) &&
			    c->spd.that.id.kind != ID_FROMCERT) {
				if (LIN(POLICY_AUTH_NULL, c->policy) &&
				    tarzan_id != NULL && tarzan_id->kind == ID_NULL) {
					log_state(RC_LOG, &ike->sa,
						  "Peer ID '%s' expects us to have ID_NULL and connection allows AUTH_NULL - allowing",
						  str_id(&peer_id, &peer_str));
					ike->sa.st_peer_wants_null = TRUE;
				} else {
					id_buf peer_str;
					return diag("Peer ID '%s' mismatched on first found connection and no better connection found",
						    str_id(&peer_id, &peer_str));
				}
			} else {
				dbg("peer ID matches and no better connection found - continuing with existing connection");
			}
		} else if (r != c) {
			/* r is an improvement on c -- replace */
			connection_buf cb, rb;
			log_state(RC_LOG, &ike->sa,
				  "switched from "PRI_CONNECTION" to "PRI_CONNECTION,
				  pri_connection(c, &cb),
				  pri_connection(r, &rb));
			if (r->kind == CK_TEMPLATE || r->kind == CK_GROUP) {
				/* instantiate it, filling in peer's ID */
				r = rw_instantiate(r, &c->spd.that.host_addr,
						   NULL, &peer_id);
			}

			update_state_connection(md->st, r);
			/* redo from scratch so we read and check CERT payload */
			dbg("retrying ikev2_decode_peer_id_and_certs() with new conn");
			return responder_match_initiator_id_counted(ike, peer_id, tarzan_id, md, depth + 1);
		} else if (must_switch) {
			id_buf peer_str;
			return diag("Peer ID '%s' mismatched on first found connection and no better connection found",
				    str_id(&peer_id, &peer_str));
		}

		if (c->spd.that.has_id_wildcards) {
			duplicate_id(&c->spd.that.id, &peer_id);
			c->spd.that.has_id_wildcards = FALSE;
		} else if (fromcert) {
			dbg("copying ID for fromcert");
			duplicate_id(&c->spd.that.id, &peer_id);
		}
	}

	dn_buf dnb;
	dbg("offered CA: '%s'", str_dn_or_null(c->spd.this.ca, "%none", &dnb));

	return NULL;
}

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
	    enum_show(&ike_id_type_names, peer_id->kind, &esb),
	    str_id(peer_id, &idb));

	return NULL;
}

diag_t ikev2_responder_decode_initiator_id(struct ike_sa *ike, struct msg_digest *md)
{
	passert(ike->sa.st_sa_role == SA_RESPONDER);

	struct id initiator_id;
	diag_t d = decode_v2_peer_id("initiator", md->chain[ISAKMP_NEXT_v2IDi], &initiator_id);
	if (d != NULL) {
		return d;
	}

	/* You Tarzan, me Jane? */
	struct id tarzan_id;	/* may be unset */
	struct id *tip = NULL;	/* tarzan ID pointer (or NULL) */
	{
		const struct payload_digest *const tarzan_pld = md->chain[ISAKMP_NEXT_v2IDr];

		if (tarzan_pld != NULL) {
			dbg("received IDr payload - extracting our alleged ID");
			diag_t d = unpack_peer_id(tarzan_pld->payload.v2id.isai_type,
						  &tarzan_id, &tarzan_pld->pbs);
			if (d != NULL) {
				return diag_diag(&d, "IDr payload extraction failed: ");
			}
			tip = &tarzan_id;
		}
	}

	return responder_match_initiator_id_counted(ike, initiator_id, tip, md, 0);
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

	struct connection *c = ike->sa.st_connection;

	/*
	 * If there are certs, try running the id check.
	 */
	bool responder_cert_id_ok = false;
	if (ike->sa.st_remote_certs.verified != NULL) {
		if (match_certs_id(ike->sa.st_remote_certs.verified,
				   &c->spd.that.id /*ID_FROMCERT => updated*/,
				   ike->sa.st_logger)) {
			dbg("X509: CERT and ID matches current connection");
			responder_cert_id_ok = true;
		} else {
			log_state(RC_LOG, &ike->sa, "Peer CERT payload SubjectAltName does not match peer ID for this connection");
			if (!LIN(POLICY_ALLOW_NO_SAN, c->policy)) {
				return diag("X509: connection failed due to unmatched IKE ID in certificate SAN");
			} else {
				log_state(RC_LOG, &ike->sa, "X509: connection allows unmatched IKE ID and certificate SAN");
			}
		}
	}

	/* process any CERTREQ payloads */
	ikev2_decode_cr(md, ike->sa.st_logger);

	/*
	 * Now that we've decoded the ID payload, let's see if we
	 * need to switch connections.
	 * We must not switch horses if we initiated:
	 * - if the initiation was explicit, we'd be ignoring user's intent
	 * - if opportunistic, we'll lose our HOLD info
	 */
	if (!responder_cert_id_ok &&
	    !same_id(&c->spd.that.id, &responder_id) &&
	    c->spd.that.id.kind != ID_FROMCERT) {
		id_buf expect, found;
		return diag("we require IKEv2 peer to have ID '%s', but peer declares '%s'",
			    str_id(&c->spd.that.id, &expect),
			    str_id(&responder_id, &found));
	}

	if (c->spd.that.id.kind == ID_FROMCERT) {
		if (responder_id.kind != ID_DER_ASN1_DN) {
			return diag("peer ID is not a certificate type");
		}
		duplicate_id(&c->spd.that.id, &responder_id);
	}

	dn_buf dnb;
	dbg("offered CA: '%s'", str_dn_or_null(c->spd.this.ca, "%none", &dnb));

	return NULL;
}
