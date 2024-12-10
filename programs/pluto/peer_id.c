/* information about connections between hosts and clients
 *
 * Copyright (C) 1998-2002,2010,2013,2018 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009-2011 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Bart Trojanowski <bart@jukie.net>
 * Copyright (C) 2010 Shinichi Furuso <Shinichi.Furuso@jp.sony.com>
 * Copyright (C) 2010,2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2017 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Philippe Vouters <Philippe.Vouters@laposte.net>
 * Copyright (C) 2012 Bram <bram-bcrafjna-erqzvar@spam.wizbit.be>
 * Copyright (C) 2013 Kim B. Heino <b@bbbs.net>
 * Copyright (C) 2013,2017 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013,2018 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2015-2020 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2016-2020 Andrew Cagney <cagney@gnu.org>
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
 */

#include "lset.h"
#include "id.h"

#include "defs.h"
#include "state.h"
#include "connections.h"
#include "peer_id.h"
#include "log.h"
#include "secrets.h"
#include "iface.h"
#include "keys.h"
#include "nss_cert_verify.h"
#include "pluto_x509.h"
#include "instantiate.h"
#include "orient.h"		/* for oriented()! */
#include "ip_info.h"

/*
 * This is to support certificates with SAN using wildcard, eg SAN
 * contains DNS:*.vpnservice.com where our leftid=*.vpnservice.com
 */
static bool idr_wildmatch(const struct host_end *this, const struct id *idr, struct logger *logger)
{
	/*
	 * Check if the IDr sent by the peer is a valid SAN of our
	 * cert.  This way the peer can indicate which of our many
	 * identities it wants to authenticate against.
	 */
	if (this->config->cert.nss_cert != NULL &&
	    (idr->kind == ID_FQDN || idr->kind == ID_DER_ASN1_DN)) {
		diag_t d = cert_verify_subject_alt_name("our",
							this->config->cert.nss_cert,
							idr);
		if (d == NULL) {
			return true;
		}
		llog(RC_LOG, logger, "%s", str_diag(d));
		pfree_diag(&d);
	}

	const struct id *wild = &this->id;

	/* if not both ID_FQDN, fall back to same_id (no wildcarding possible) */
	if (idr->kind != ID_FQDN || wild->kind != ID_FQDN)
		return same_id(wild, idr);

	size_t wl = wild->name.len;
	const char *wp = (const char *) wild->name.ptr;

	/* if wild has no *, fall back to same_id (no wildcard present) */
	if (wl == 0 || wp[0] != '*')
		return same_id(wild, idr);

	while (wp[wl - 1] == '.')
		wl--;	/* strip trailing dot */

	size_t il = idr->name.len;
	const char *ip = (const char *) idr->name.ptr;
	while (il > 0 && ip[il - 1] == '.')
		il--;	/* strip trailing dot */

	/*
	 * ??? should we require that the * match only whole components?
	 * wl-1 == il ||   // total match
	 * wl > 1 && wp[1] == '.' ||   // wild included leading "."
	 * ip[il-(wl-1) - 1] == '.'   // match preceded by "."
	 */

	return wl-1 <= il && strncaseeq(&wp[1], &ip[il-(wl-1)], wl-1);
}

/*
 * Extracts the peer's ca from the chained list of public keys.
 */
static asn1_t get_peer_ca(struct pubkey_list *const *pubkey_db,
			   const struct id *peer_id)
{
	struct pubkey_list *p;

	for (p = *pubkey_db; p != NULL; p = p->next) {
		struct pubkey *key = p->key;
		if (key->content.type == &pubkey_type_rsa && same_id(peer_id, &key->id))
			return key->issuer;
	}
	return null_shunk;
}

/*
 * During the IKE_SA_INIT exchange, the responder state's connection
 * is chosen based on the initiator's address (perhaps with minor
 * tweaks).
 *
 * Now, in the IKE_SA_INIT, with the ID and validated certificates
 * known, it is possible to improve on this choice.
 *
 * XXX: since IKE_SA_INIT can be childless, the Child SA's Traffic
 * Selectors should not be used.  They will be examined later when
 * selecting a connection matching the Child SA.
 *
 * The IKEv1 Main Mode responder, described below, is essentially the
 * same (hence it shares this code).

 * ??? NOTE: THESE IMPORTANT COMMENTS DO NOT REFLECT ANY CHANGES MADE
 * AFTER FreeS/WAN.
 *
 * Comments in the code describe the (tricky!) matching criteria.
 *
 * In RFC 2409 "The Internet Key Exchange (IKE)",
 * in 5.1 "IKE Phase 1 Authenticated With Signatures", describing Main
 * Mode:
 *
 *         Initiator                          Responder
 *        -----------                        -----------
 *         HDR, SA                     -->
 *                                     <--    HDR, SA
 *         HDR, KE, Ni                 -->
 *                                     <--    HDR, KE, Nr
 *         HDR*, IDii, [ CERT, ] SIG_I -->
 *                                     <--    HDR*, IDir, [ CERT, ] SIG_R
 *
 * In 5.4 "Phase 1 Authenticated With a Pre-Shared Key":
 *
 *               HDR, SA             -->
 *                                   <--    HDR, SA
 *               HDR, KE, Ni         -->
 *                                   <--    HDR, KE, Nr
 *               HDR*, IDii, HASH_I  -->
 *                                   <--    HDR*, IDir, HASH_R
 *
 * - the Responder receives the IDii payload:
 *   + [PSK] after using PSK to decode this message
 *   + before sending its IDir payload
 *   + before using its ID in HASH_R computation
 *   + [DSig] before using its private key to sign SIG_R
 *   + before using the Initiator's ID in HASH_I calculation
 *   + [DSig] before using the Initiator's public key to check SIG_I
 *
 * refine_host_connection can choose a different connection, as long
 * as nothing already used is changed.
 */

#define dbg_rhc(FORMAT, ...) pdbg(verbose.logger, "rhc:%*s "FORMAT, verbose.level*2, "", ##__VA_ARGS__)

struct score {
	bool matching_peer_id;
	int v1_requested_ca_pathlen;
	int peer_pathlen;
	int wildcards;
	struct connection *connection;
};

static bool score_host_connection(const struct ike_sa *ike,
				  lset_t proposed_authbys,
				  const struct id *peer_id,
				  const struct id *tarzan_id,
				  asn1_t peer_ca,
				  struct score *score,
				  struct verbose verbose)
{
	struct connection *c = ike->sa.st_connection;
	struct connection *d = score->connection;
	PEXPECT(ike->sa.logger, oriented(d));
	PEXPECT(ike->sa.logger, !is_group(d));

	/*
	 * First all the "easy" skips.
	 */

	/*
	 * An instantiated connection with ID_NULL is never better.
	 * (it's identity was never authenticated).
	 *
	 * The exception being the current connection instance which
	 * is allowed to have no authentication.
	 */

	if (c != d && is_instance(d) && d->remote->host.id.kind == ID_NULL) {
		connection_buf cb;
		dbg_rhc("skipping ID_NULL instance "PRI_CONNECTION"",
			pri_connection(d, &cb));
		return false;
	}

	if (ike->sa.st_remote_certs.groundhog && !d->remote->config->host.groundhog) {
		connection_buf cb;
		dbg_rhc("skipping non-groundhog instance "PRI_CONNECTION"",
			pri_connection(d, &cb));
		return false;
	}

	/*
	 * An Opportunistic connection is never better.
	 *
	 * The exception being the current connection instance which
	 * is allowed to be opportunistic.
	 */

	if (c != d && is_opportunistic(d)) {
		connection_buf cb;
		dbg_rhc("skipping opportunistic connection "PRI_CONNECTION"",
			pri_connection(d, &cb));
		return false;
	}

	/*
	 * Only consider template and parent instances sec_label
	 * connections.
	 */

	if (is_labeled_child(d)) {
		connection_buf cb;
		dbg_rhc("skipping labeled child "PRI_CONNECTION,
			pri_connection(d, &cb));
		return false;
	}

	/*
	 * Ignore group connections.
	 */

	if (is_group(d)) {
		connection_buf cb;
		dbg_rhc("skipping group template connection "PRI_CONNECTION,
			pri_connection(d, &cb));
		return false;
	}

	/*
	 * XXX: are these two bogus?
	 *
	 * C was chosen only when the address was known so there's no
	 * reason to think that XAUTH_SERVER is correct.
	 */

	if (d->local->host.config->xauth.server != c->local->host.config->xauth.server) {
		/* Disallow IKEv2 CP or IKEv1 XAUTH mismatch */
		dbg_rhc("skipping because mismatched xauth_server");
		return false;
	}

	if (d->local->host.config->xauth.client != c->local->host.config->xauth.client) {
		/* Disallow IKEv2 CP or IKEv1 XAUTH mismatch */
		dbg_rhc("skipping because mismatched xauth_client");
		return false;
	}

	/*
	 * 'You Tarzan, me Jane' check based on
	 * received IDr (remember, this is the
	 * responder).
	 */
	if (tarzan_id != NULL) {
		id_buf tzb;
		esb_buf tzesb;
		dbg_rhc("peer expects us to be %s (%s) according to its IDr payload",
			str_id(tarzan_id, &tzb),
			str_enum(&ike_id_type_names, tarzan_id->kind, &tzesb));
		id_buf usb;
		esb_buf usesb;
		dbg_rhc("this connection's local id is %s (%s)",
			str_id(&d->local->host.id, &usb),
			str_enum(&ike_id_type_names, d->local->host.id.kind, &usesb));
		/* ??? pexpect(d->spd->spd_next == NULL); */
		if (!idr_wildmatch(&d->local->host, tarzan_id, ike->sa.logger)) {
			dbg_rhc("skipping because peer IDr payload does not match our expected ID");
			return false;
		}
	} else {
		dbg_rhc("no IDr payload received from peer");
	}

	/*
	 * The proposed authentication must match the
	 * policy of this connection.
	 */
	switch (ike->sa.st_ike_version) {
	case IKEv1:
		if (d->config->aggressive) {
			dbg_rhc("skipping because AGGRESSIVE isn't right");
			return false;	/* differ about aggressive mode */
		}
		if (LHAS(proposed_authbys, AUTH_PSK)) {
			if (!(d->remote->host.config->auth == AUTH_PSK)) {
				/* there needs to be a key */
				dbg_rhc("skipping because no PSK in POLICY");
				return false;
			}
			if (get_connection_psk(d) == NULL) {
				/* there needs to be a key */
				dbg_rhc("skipping because PSK and no secret");
				return false; /* no secret */
			}
		}
		if (LHAS(proposed_authbys, AUTH_RSASIG)) {
			if (!(d->remote->host.config->auth == AUTH_RSASIG)) {
				dbg_rhc("skipping because not RSASIG in POLICY");
				return false;	/* no key */
			}
			if (get_local_private_key(d, &pubkey_type_rsa,
						  ike->sa.logger) == NULL) {
				/*
				 * We must at least be able to find
				 * our private key.
				 */
				dbg_rhc("skipping because RSASIG and no private key");
				return false;	/* no key */
			}
		}
		break;
	case IKEv2:
		/*
		 * We need to check if leftauth and
		 * rightauth match, but we only know
		 * what the remote end has sent in the
		 * IKE_AUTH request.
		 *
		 * XXX: this is too strict.  For
		 * instance, given a connection that
		 * allows both both ECDSA and RSASIG
		 * then because .auth=rsasig
		 * (preferred) the below will reject
		 * ECDSA?
		 */
		if (!LHAS(proposed_authbys, d->remote->host.config->auth)) {
			dbg_rhc("skipping because mismatched authby");
			return false;
		}
		/* check that the chosen one has a key */
		switch (d->remote->host.config->auth) {
		case AUTH_PSK:
			/*
			 * XXX: This tries to find the
			 * PSK for what is potentially
			 * a template!
			 */
			if (get_connection_psk(d) == NULL) {
				/* need a key */
#if 0
				dbg_rhc("skipping because PSK and no secret");
				return false; /* no secret */
#else
				dbg_rhc("has no PSK; why?");
			}
#endif
			break;
		case AUTH_RSASIG:
			if (get_local_private_key(d, &pubkey_type_rsa,
						  ike->sa.logger) == NULL) {
				dbg_rhc("skipping because RSASIG and no private key");
				return false;	/* no key */
			}
			break;
		case AUTH_ECDSA:
			if (get_local_private_key(d, &pubkey_type_ecdsa,
						  ike->sa.logger) == NULL) {
				dbg_rhc("skipping because ECDSA and no private key");
				return false;	/* no key */
			}
			break;
		default:
		{
			lset_buf eb;
			dbg_rhc("%s so no authby checks performed",
				str_lset_short(&keyword_auth_names, "+",
					       proposed_authbys, &eb));
			break;
		}
		}
		break;
	}

	/*
	 * Does the ID match?
	 *
	 * WILDCARDS gives the match a score (smaller
	 * is better): 0 for a perfect match, non-zero
	 * when things like certificate wild cards
	 * were used.
	 */

	score->matching_peer_id = match_id(peer_id,
					   &d->remote->host.id,
					   &score->wildcards,
					   verbose);

	/*
	 * Check if peer_id matches, exactly or after
	 * instantiation.
	 *
	 * Check for the match but also check to see
	 * if it's the %fromcert + peer id match
	 * result. - matt
	 */
	if (!score->matching_peer_id) {
		/* must be checking certs */
		if (d->remote->host.id.kind != ID_FROMCERT) {
			dbg_rhc("skipping because peer_id does not match and that.id.kind is not a cert");
			return false;
		}
	}

	/*
	 * IKEv2 doesn't have v1_requested_ca so can be ignored.
	 *
	 * match_v1_requested_ca() succeeds when there's no
	 * .st_v1_requested_ca to match.
	 */
	score->v1_requested_ca_pathlen = 0;
	if (ike->sa.st_ike_version == IKEv1) {
		if (!match_v1_requested_ca(ike, d->local->host.config->ca,
					   &score->v1_requested_ca_pathlen,
					   verbose)) {
			dbg_rhc("skipping because match_v1_requested_ca() failed");
			return false;
		}

		dbg_rhc("v1_requested_ca_pathlen=%d", score->v1_requested_ca_pathlen);
	}

	/*
	 * XXX: When there are no certificates at all
	 * (PEER_CA and THAT.CA are NULL; REQUESTED_CA
	 * is NULL), these lookups return TRUE and
	 * *_pathlen==0 - a perfect match.
	 */
	bool matching_peer_ca = trusted_ca(peer_ca,
					   ASN1(d->remote->host.config->ca),
					   &score->peer_pathlen,
					   verbose);

	dbg_rhc("matching_peer_ca=%s(%d)",
		bool_str(matching_peer_ca), score->peer_pathlen);
	verbose.level++;

	/*
	 * Both matching_peer_ca and
	 * matched_v1_requested_ca are required.
	 *
	 * XXX: Remember, when there are no
	 * certificates, both are forced to TRUE.
	 *
	 * For IKEv2, MATCHED_V1_REQUESTED_CA is always true.
	 */
	if (!matching_peer_ca) {
		dbg_rhc("skipping because !matching_peer_ca");
		return false;
	}

	/*
	 * Paul: We need to check all the other relevant policy bits,
	 * like compression, pfs, etc.
	 *
	 * XXX: This is the IKE SA, so compression doesn't apply.
	 * However the negotiated crypto suite does and should be
	 * checked.
	 */

	return true;
}

/*
 * If the connection passes all tests and the Peer ID was an exact
 * match (this includes an ID only match).
 */

static bool exact_id_match(struct score score)
{
	return (score.connection != NULL &&
		score.matching_peer_id &&
		score.wildcards == 0 &&
		score.peer_pathlen == 0 &&
		score.v1_requested_ca_pathlen == 0 &&
		(is_permanent(score.connection) ||
		 is_instance(score.connection)));
}

static bool better_score(struct score best, struct score score, struct logger *logger)
{
	if (best.connection == NULL) {
		return true;
	}

	/*
	 * If it was a non-exact (wildcard) match, we'll remember it
	 * as best_found in case an exact match doesn't come along.
	 */
	if (score.wildcards != best.wildcards) {
		return (score.wildcards < best.wildcards);
	}

	/*
	 * ??? the logic involving *_pathlen looks wrong.
	 *
	 * ??? which matters more peer_pathlen or v1_requested_ca_pathlen
	 * minimization?
	 *
	 * XXX: presumably peer as we're more worried about
	 * authenticating the peer using the best match?
	 */
	if (score.peer_pathlen != best.peer_pathlen) {
		return (score.peer_pathlen < best.peer_pathlen);
	}

	if (score.v1_requested_ca_pathlen != best.v1_requested_ca_pathlen) {
		return (score.v1_requested_ca_pathlen < best.v1_requested_ca_pathlen);
	}

	/*
	 * Prefer an existing instance over a template and/or
	 * permanent.  Presumably so that established connections are
	 * re-used.  Also matches legacy behaviour where instances
	 * were checked before templates.
	 *
	 * This leaves the question of permanent vs template open.
	 */
	if (is_instance(score.connection) && !is_instance(best.connection)) {
		PEXPECT(logger, (is_permanent(best.connection) ||
				 is_template(best.connection)));
		return true;
	}

	/* equal scores is not better */
	return false;
}

static struct connection *refine_host_connection_on_responder(const struct ike_sa *ike,
							      lset_t proposed_authbys,
							      const struct id *peer_id,
							      const struct id *tarzan_id,
							      struct verbose verbose)
{
	struct connection *c = ike->sa.st_connection;

	PASSERT(ike->sa.logger, !LHAS(proposed_authbys, AUTH_NEVER));
	PASSERT(ike->sa.logger, !LHAS(proposed_authbys, AUTH_UNSET));

	/*
	 * XXX: should, instead, C be a permanent or template as it
	 * would avoid unnecessary instantiation.
	 *
	 * Remember is_instance() includes labeled_parent().
	 */
	PEXPECT(ike->sa.logger, is_instance(c) || is_permanent(c));

	/*
	 * Find the PEER's CA, check the per-state DB first.
	 */
	PEXPECT(ike->sa.logger, ike->sa.st_remote_certs.processed);
	asn1_t peer_ca = get_peer_ca(&ike->sa.st_remote_certs.pubkey_db, peer_id);
	if (hunk_isempty(peer_ca)) {
		peer_ca = get_peer_ca(&pluto_pubkeys, peer_id);
	}

	/*
	 * Find a connection with that matches the peer based on
	 * address, ID, and other bells and whistles.
	 *
	 * During IKE_SA_INIT the connection was chosen based on the
	 * peer's address.  Now its time to refine that connection,
	 * looking for something that also matches the information,
	 * noteably the proof-of-identity, provided by IKE_AUTH (For
	 * IKEv1 main mode, things are the same, just the exchange
	 * names are changed).
	 *
	 * The preference is for an existing instance and then an
	 * instantiated template.
	 *
	 * We need to match:
	 *
	 * - peer_id (slightly complicated by instantiation)
	 * - if PSK auth, the key must not change (we used it to decode message)
	 * - policy-as-used must be acceptable to new connection
	 * - if initiator, also:
	 *   + our ID must not change (we sent it in previous message)
	 *   + our RSA key must not change (we used in in previous message)
	 *
	 * PASS 0: Score the existing connection to kick-start the
	 * search and check for an instant winner
	 *
	 * PASS 1: Match anything with the exact same SRC->DST. This
	 * list contains instantiated templates and oriented permanent
	 * connections.
	 *
	 * PASS 2: Match matching SRC->%any.  This list contains
	 * oriented template connections (since the remote address is
	 * %any).
	 */

	struct score best = {0};

	struct score c_score = { .connection = c, };
	if (score_host_connection(ike,
				  proposed_authbys,
				  peer_id, tarzan_id, peer_ca,
				  &c_score, verbose)) {
		best = c_score;
		if (exact_id_match(best)) {
			dbg_rhc("returning initial connection because exact (peer) ID match");
			return best.connection;
		}
	}

	ip_address local = c->iface->local_address;
	FOR_EACH_THING(remote, endpoint_address(ike->sa.st_remote_endpoint), unset_address) {

		verbose.level = 1;
		address_buf lb, rb;
		dbg_rhc("trying connections matching %s->%s",
			str_address(&local, &lb), str_address(&remote, &rb));

		struct connection_filter hpf = {
			.host_pair = {
				.local = &local,
				.remote = &remote,
			},
			.ike_version = c->config->ike_version,
			.search = {
				.order = OLD2NEW,
				.verbose.logger = ike->sa.logger,
				.where = HERE,
			},
		};
		while (next_connection(&hpf)) {
			struct connection *d = hpf.c;
			if (c == d) {
				/* already scored above */
				continue;
			}

			connection_buf b2;
			verbose.level = 2;
			dbg_rhc("checking "PRI_CONNECTION, pri_connection(d, &b2));
			verbose.level++;

			struct score score = {
				.connection = d,
			};
			if (!score_host_connection(ike,
						   proposed_authbys,
						   peer_id, tarzan_id, peer_ca,
						   &score, verbose)) {
				continue;
			}

			/*
			 * D has passed all the tests.
			 *
			 * We'll go with it if the Peer ID was an
			 * exact match (this includes an ID only
			 * match).
			 */
			if (exact_id_match(score)) {
				connection_buf dcb;
				dbg_rhc("returning "PRI_CONNECTION" because exact (peer) ID match",
					pri_connection(d, &dcb));
				return d;
			}

			/*
			 * If it was a non-exact (wildcard) match,
			 * we'll remember it as best_found in case an
			 * exact match doesn't come along.
			 *
			 * ??? the logic involving *_pathlen looks wrong.
			 * ??? which matters more peer_pathlen or v1_requested_ca_pathlen minimization?
			 */
			if (better_score(best, score, ike->sa.logger)) {
				connection_buf cib;
				dbg_rhc("picking new best "PRI_CONNECTION" (wild=%d, peer_pathlen=%d/our=%d)",
					pri_connection(d, &cib),
					score.wildcards, score.peer_pathlen,
					score.v1_requested_ca_pathlen);
				best = score;
			}
		}
	}
	return best.connection;
}

bool refine_host_connection_of_state_on_responder(struct ike_sa *ike,
						  lset_t proposed_authbys,
						  const struct id *peer_id,
						  const struct id *tarzan_id)
{
	struct verbose verbose = { .logger = ike->sa.logger, };
	connection_buf cib;
	dbg_rhc("looking for an %s connection more refined than "PRI_CONNECTION"",
		ike->sa.st_connection->config->ike_info->version_name,
	    pri_connection(ike->sa.st_connection, &cib));
	verbose.level = 1;

	struct connection *r = refine_host_connection_on_responder(ike,
								   proposed_authbys,
								   peer_id, tarzan_id,
								   verbose);
	if (r == NULL) {
		dbg_rhc("returning FALSE because nothing is sufficiently refined");
		return false;
	}

	connection_buf bfb;
	dbg_rhc("returning TRUE as "PRI_CONNECTION" is most refined",
		pri_connection(r, &bfb));

	if (r != ike->sa.st_connection) {
		/*
		 * We are changing ike->sa.st_connection!  Our caller
		 * might be surprised!
		 *
		 * XXX: Code was trying to avoid instantiating the
		 * refined connection; it ran into problems:
		 *
		 * - it made for convoluted code trying to figure out
		 *   the cert/id
		 *
		 * - it resulted in wrong log lines (it was against
		 *   the old connection).
		 *
		 * Should this be moved into above call, it is
		 * identical between IKEv[12]?
		 *
		 * Should the ID be fully updated here?
		 */
		if (is_template(r)) {
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
			pexpect(is_template(r));
			r = rw_responder_id_instantiate(r, ike->sa.st_connection->remote->host.addr,
							peer_id, HERE);
		} else {
			r = connection_addref(r, ike->sa.logger);
		}
		/*
		 * R is an improvement on .st_connection -- replace.
		 */
		connswitch_state_and_log(&ike->sa, r);
		connection_delref(&r, ike->sa.logger);
	}

	connection_buf bcb;
	dbg_rhc("most refined is "PRI_CONNECTION,
		pri_connection(ike->sa.st_connection, &bcb));
	return true;
}

diag_t update_peer_id_certs(struct ike_sa *ike)
{
       struct connection *const c = ike->sa.st_connection; /* no longer changing */

       /* end cert is at the front; move to where? */
       struct certs *certs = ike->sa.st_remote_certs.verified;
       CERTCertificate *end_cert = certs->cert;
       dbg("rhc: comparing certificate: %s", end_cert->subjectName);

       struct id remote_cert_id = empty_id;
       diag_t d = match_peer_id_cert(certs, &c->remote->host.id, &remote_cert_id);

       if (d == NULL) {
	       dbg("X509: CERT and ID matches current connection");
	       if (remote_cert_id.kind != ID_NONE) {
		       replace_connection_that_id(c, &remote_cert_id);
	       }
	       return NULL;
       }

       if (!c->config->require_id_on_certificate) {
	       id_buf idb;
	       ldbg_sa(ike, "X509: CERT '%s' and ID '%s' don't match but require-id-on-certificate=no",
		       end_cert->subjectName, str_id(&c->remote->host.id, &idb));
	       llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
	       pfree_diag(&d);
	       llog_sa(RC_LOG, ike, "X509: connection allows unmatched IKE ID and certificate SAN");
	       return NULL;
       }

       return diag_diag(&d, "X509: authentication failed; ");
       return NULL;
}

diag_t update_peer_id(struct ike_sa *ike, const struct id *peer_id, const struct id *tarzan_id)
{
	if (ike->sa.st_remote_certs.verified != NULL) {
		return update_peer_id_certs(ike);
	}

	struct connection *const c = ike->sa.st_connection; /* no longer changing */

	if (c->remote->host.id.kind == ID_FROMCERT) {
#if 0
		if (peer_id->kind != ID_DER_ASN1_DN) {
			id_buf idb;
			llog_sa(RC_LOG, ike,
				"peer ID '%s' is not a certificate type",
				str_id(peer_id, &idb));
			return false;
		}
#endif
		id_buf idb;
		dbg("rhc: %%fromcert and no certificate payload - continuing with peer ID %s",
		    str_id(peer_id, &idb));
		replace_connection_that_id(c, peer_id);
	} else if (same_id(&c->remote->host.id, peer_id)) {
		id_buf idb;
		dbg("rhc: peer ID matches and no certificate payload - continuing with peer ID %s",
		    str_id(peer_id, &idb));
	} else if (c->remote->host.config->authby.null &&
		   tarzan_id != NULL && tarzan_id->kind == ID_NULL) {
		id_buf peer_idb;
		llog_sa(RC_LOG, ike,
			"Peer ID '%s' expects us to have ID_NULL and connection allows AUTH_NULL - allowing",
			str_id(peer_id, &peer_idb));
		dbg("rhc: setting .st_peer_wants_null");
		ike->sa.st_peer_wants_null = true;
	} else {
		id_buf peer_idb;
		return diag("Peer ID '%s' mismatched on first found connection and no better connection found",
			    str_id(peer_id, &peer_idb));
	}

	return NULL;
}

bool compare_connection_id(const struct connection *c,
			   const struct connection *d,
			   struct connection_id_score *score,
			   struct verbose verbose)
{
	if (c->config->connalias != NULL &&
	    d->config->connalias != NULL &&
	    streq(c->config->connalias, d->config->connalias)) {
		/*
		 * conns created as aliases from the same
		 * source have identical ID/CA.
		 */
		vdbg("connalias %s match, skipping ID check",
		     c->config->connalias);
		return true;
	}

	/* local */
	if (!same_id(&c->local->host.id, &d->local->host.id)) {
		id_buf cb, db;
		vdbg("skipping connection, local ID %s needs to be the same as %s",
		     str_id(&d->local->host.id, &db),
		     str_id(&c->local->host.id, &cb));
		return false;
	}

	/* remote */
	if (!match_id(&c->remote->host.id, &d->remote->host.id,
		      &score->wildcards, verbose)) {
		id_buf cb, db;
		vdbg("skipping connection, remote ID %s needs to match %s",
		     str_id(&d->remote->host.id, &db),
		     str_id(&c->remote->host.id, &cb));
		return false;
	}

	/* remote */
	if (!trusted_ca(ASN1(c->remote->host.config->ca),
			ASN1(d->remote->host.config->ca),
			&score->pathlen, verbose)) {
		vdbg("skipping connection, remote CA 'B' needs to trust CA 'A'");
		return false;
	}

	return true;
}

/*
 * Decode the ID payload.
 *
 * IKEv2 uses this to decode both IDi and IDr.
 *
 * IKEv1 Phase 1 (main_inI3_outR3 and main_inR3) Clears *peer to avoid
 * surprises.
 *
 * Note: what we discover may oblige Pluto to switch connections.  We
 * must be called before SIG or HASH are decoded since we may change
 * the peer's RSA key or ID.
 */

diag_t unpack_id(enum ike_id_type kind, struct id *peer, const struct pbs_in *id_pbs)
{
	struct pbs_in in_pbs = *id_pbs; /* local copy */
	shunk_t name = pbs_in_left(&in_pbs);

	*peer = (struct id) {.kind = kind };	/* clears everything */

	switch (kind) {

	/* ident types mostly match between IKEv1 and IKEv2 */
	case ID_IPV4_ADDR:
		/* failure mode for initaddr is probably inappropriate address length */
		return pbs_in_address(&in_pbs, &peer->ip_addr, &ipv4_info, "peer ID");

	case ID_IPV6_ADDR:
		/* failure mode for initaddr is probably inappropriate address length */
		return pbs_in_address(&in_pbs, &peer->ip_addr, &ipv6_info, "peer ID");

	/* seems odd to continue as ID_FQDN? */
	case ID_USER_FQDN:
#if 0
		if (memchr(name.ptr, '@', name.len) == NULL) {
			llog(RC_LOG, logger,
				    "peer's ID_USER_FQDN contains no @: %.*s",
				    (int) left, id_pbs->cur);
			/* return false; */
		}
#endif
		if (memchr(name.ptr, '\0', name.len) != NULL) {
			esb_buf b;
			return diag("Phase 1 (Parent)ID Payload of type %s contains a NUL",
				    str_enum(&ike_id_type_names, kind, &b));
		}
		/* ??? ought to do some more sanity check, but what? */
		peer->name = name;
		break;

	case ID_FQDN:
		if (memchr(name.ptr, '\0', name.len) != NULL) {
			esb_buf b;
			return diag("Phase 1 (Parent)ID Payload of type %s contains a NUL",
				    str_enum(&ike_id_type_names, kind, &b));
		}
		/* ??? ought to do some more sanity check, but what? */
		peer->name = name;
		break;

	case ID_KEY_ID:
		peer->name = name;
		if (DBGP(DBG_BASE)) {
			DBG_dump_hunk("KEY ID:", peer->name);
		}
		break;

	case ID_DER_ASN1_DN:
		peer->name = name;
		if (DBGP(DBG_BASE)) {
		    DBG_dump_hunk("DER ASN1 DN:", peer->name);
		}
		break;

	case ID_NULL:
		if (name.len != 0) {
			if (DBGP(DBG_BASE)) {
				DBG_dump_hunk("unauthenticated NULL ID:", name);
			}
		}
		break;

	default:
	{
		esb_buf b;
		return diag("Unsupported identity type (%s) in Phase 1 (Parent) ID Payload",
			    str_enum(&ike_id_type_names, kind, &b));
	}
	}

	return NULL;
}
