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
						   lset_t authbys,
						   struct id peer_id,
						   struct id *tarzan_id)
{
	/* c = ike->sa.st_connection; <- not yet known */

	/*
	 * XXX: Why skip refine_host_connection*() when AUTHBY_NULL?
	 *
	 * For instance, IKE_SA_INIT chooses a permanent connection
	 * but then IKE_AUTH proposes AUTHBY_NULL.
	 */

	bool no_refinement = true;

	if (!LHAS(authbys, AUTHBY_NULL)) {
		struct connection *r = NULL;
		r = refine_host_connection_on_responder(&ike->sa, authbys,
							&peer_id, tarzan_id);
		no_refinement = (r == NULL);
		if (r != NULL && r != ike->sa.st_connection) {
			/*
			 * We are changing st->st_connection!
			 * Our caller might be surprised!
			 *
			 * XXX: Code was trying to avoid instantiating
			 * the refined connection; it ran into
			 * problems:
			 *
			 * - it made for convoluted code trying to
			 *   figure out the cert/id
			 *
			 * - it resulted in wrong log lines (it was
			 *   against the old connection).
			 *
			 * Should this be moved into above call, it is
			 * identical between IKEv[12]?
			 *
			 * Should the ID be fully updated here?
			 */
			struct connection *c = ike->sa.st_connection;
			if (r->kind == CK_TEMPLATE || r->kind == CK_GROUP) {
				/*
				 * XXX: is r->kind == CK_GROUP ever
				 * true?  refine_host_connection*()
				 * skips POLICY_GROUP so presumably
				 * this is testing for a GROUP
				 * instance.
				 *
				 * Instantiate it, filling in peer's
				 * ID.
				 */
				r = rw_instantiate(r, &c->spd.that.host_addr,
						   NULL, &peer_id);
			}
			/* r is an improvement on c -- replace */
			connswitch_state_and_log(&ike->sa, r);
		}
	}

	/* check for certificates; XXX: duplicate comment+code? */

	bool remote_cert_matches_id = false;
	struct id remote_cert_id = empty_id;
	if (ike->sa.st_remote_certs.verified != NULL) {
		struct connection *c = ike->sa.st_connection;

		/* end cert is at the front; move to where? */
		struct certs *certs = ike->sa.st_remote_certs.verified;
		CERTCertificate *end_cert = certs->cert;
		dbg("rhc: comparing certificate: %s", end_cert->subjectName);
		diag_t d = match_end_cert_id(ike->sa.st_remote_certs.verified,
					     &c->spd.that.id, &remote_cert_id);

		if (d == NULL) {
			dbg("X509: CERT and ID matches current connection");
			if (remote_cert_id.kind != ID_NONE) {
				replace_connection_that_id(c, &remote_cert_id);
			}
		} else if (LIN(POLICY_ALLOW_NO_SAN, c->policy)) {
			dbg("X509: CERT and ID don't match but POLICY_ALLOW_NO_SAN");
			llog_diag(RC_LOG_SERIOUS, ike->sa.st_logger, &d, "%s", "");
			llog_sa(RC_LOG, ike, "X509: connection allows unmatched IKE ID and certificate SAN");
			replace_connection_that_id(c, &peer_id);
		} else {
			llog_diag(RC_LOG_SERIOUS, ike->sa.st_logger, &d, "%s", "");
			diag_t d = diag("X509: connection failed due to unmatched IKE ID in certificate SAN");
			llog_diag(RC_LOG, ike->sa.st_logger, &d, "%s", "");
			id_buf peer_idb;
			return diag("Peer ID '%s' is not specified on the certificate SubjectAltName (SAN) and no better connection found",
				    str_id(&peer_id, &peer_idb));
		}
		remote_cert_matches_id = true;
	}

	if (no_refinement) {
		/*
		 * no "improvement" on c found.
		 *
		 * XXX: not really:
		 *
		 * - the other end proposed AUTHBY_NULL so no attempt
                 *   was made to improve the connection improve was
                 *   made
		 *
		 *   this seems weird; what happens if IKE_SA_INIT
		 *   chooses something more permanent but the IKE_AUTH
		 *   message proposes NULL?
		 *
		 * - refine_host_connection() returned NULL so,
		 *   presumably, not even C was acceptable
		 *
		 *   here, it looks like the code is trying to propose
		 *   a more helpful message which while convolted is
		 *   useful
		 */
		if (DBGP(DBG_BASE)) {
			id_buf peer_idb;
			DBG_log("no suitable connection for peer '%s'",
				str_id(&peer_id, &peer_idb));
		}
		/* if X.509, we should have valid peer/san */
		if (ike->sa.st_remote_certs.verified != NULL && !remote_cert_matches_id) {
			id_buf peer_idb;
			return diag("`Peer ID '%s' is not specified on the certificate SubjectAltName (SAN) and no better connection found",
				    str_id(&peer_id, &peer_idb));
		}
		struct connection *c = ike->sa.st_connection;
		if (!remote_cert_matches_id &&
		    !same_id(&c->spd.that.id, &peer_id) &&
		    c->spd.that.id.kind != ID_FROMCERT) {
			if (LIN(POLICY_AUTH_NULL, c->policy) &&
			    tarzan_id != NULL && tarzan_id->kind == ID_NULL) {
				id_buf peer_idb;
				llog_sa(RC_LOG, ike,
					"Peer ID '%s' expects us to have ID_NULL and connection allows AUTH_NULL - allowing",
					str_id(&peer_id, &peer_idb));
				ike->sa.st_peer_wants_null = true;
			} else {
				id_buf peer_idb;
				return diag("Peer ID '%s' mismatched on first found connection and no better connection found",
					    str_id(&peer_id, &peer_idb));
			}
		} else {
			dbg("peer ID matches and no better connection found - continuing with existing connection");
		}
	}

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

	/*
	 * Process any CERTREQ payloads.
	 *
	 * These are used as hints when selecting a better connection
	 * based on ID.
	 */
	decode_v2_certificate_requests(&ike->sa, md);

	/*
	 * Convert the proposed connections into something this
	 * responder might accept.
	 *
	 * DIGSIG seems a bit of a dodge, should this be looking
	 * inside the auth proposal?
	 */

	enum ikev2_auth_method atype =
		md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2auth.isaa_auth_method;
	enum keyword_authby authbys;
	switch (atype) {
	case IKEv2_AUTH_RSA:
		authbys = LELEM(AUTHBY_RSASIG);
		break;
	case IKEv2_AUTH_PSK:
		authbys = LELEM(AUTHBY_PSK);
		break;
	case IKEv2_AUTH_NULL:
		authbys = LELEM(AUTHBY_NULL);
		break;
	case IKEv2_AUTH_DIGSIG:
		authbys = LELEM(AUTHBY_RSASIG) | LELEM(AUTHBY_ECDSA);
		break;
	default:
		dbg("ikev2 skipping refine_host_connection due to unknown policy");
		return NULL;
	}

	return responder_match_initiator_id_counted(ike, authbys, initiator_id, tip);
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
	bool remote_cert_matches_id = false;
	if (ike->sa.st_remote_certs.verified != NULL) {
		struct id cert_id = empty_id;
		diag_t d = match_end_cert_id(ike->sa.st_remote_certs.verified,
					     &c->spd.that.id, &cert_id);
		if (d == NULL) {
			dbg("X509: CERT and ID matches current connection");
			if (cert_id.kind != ID_NONE) {
				replace_connection_that_id(c, &cert_id);
			}
			remote_cert_matches_id = true;
		} else if (!LIN(POLICY_ALLOW_NO_SAN, c->policy)) {
			return diag_diag(&d, "X509: authentication failed; ");
		} else {
			llog_diag(RC_LOG_SERIOUS, ike->sa.st_logger, &d, "%s", "");
			log_state(RC_LOG, &ike->sa, "X509: connection allows unmatched IKE ID and certificate SAN");
		}
	}

	/* process any CERTREQ payloads */
	decode_v2_certificate_requests(&ike->sa, md);

	/*
	 * Now that we've decoded the ID payload, let's see if we
	 * need to switch connections.
	 * We must not switch horses if we initiated:
	 * - if the initiation was explicit, we'd be ignoring user's intent
	 * - if opportunistic, we'll lose our HOLD info
	 */
	if (!remote_cert_matches_id &&
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
		replace_connection_that_id(c, &responder_id);
	}

	dn_buf dnb;
	dbg("offered CA: '%s'", str_dn_or_null(c->local->host.ca, "%none", &dnb));

	return NULL;
}
