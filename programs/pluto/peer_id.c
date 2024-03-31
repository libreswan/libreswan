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

/*
 * This is to support certificates with SAN using wildcard, eg SAN
 * contains DNS:*.vpnservice.com where our leftid=*.vpnservice.com
 */
static bool idr_wildmatch(const struct host_end *this, const struct id *idr, struct logger *logger)
{
	/* check if received IDr is a valid SAN of our cert */
	/* cert_VerifySubjectAltName, if called, will [debug]log any errors */
	/* XXX:  calling cert_VerifySubjectAltName with ID_DER_ASN1_DN futile? */
	/* ??? if cert matches we don't actually do any further ID matching, wildcard or not */
	if (this->config->cert.nss_cert != NULL &&
	    (idr->kind == ID_FQDN || idr->kind == ID_DER_ASN1_DN)) {
		diag_t d = cert_verify_subject_alt_name(this->config->cert.nss_cert, idr);
		if (d == NULL) {
			return true;
		}
		llog_diag(RC_LOG_SERIOUS, logger, &d, "%s", "");
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

#define dbg_rhc(FORMAT, ...) dbg("rhc:%*s "FORMAT, indent*2, "", ##__VA_ARGS__)

static struct connection *refine_host_connection_on_responder(int indent,
							      const struct state *st,
							      lset_t proposed_authbys,
							      const struct id *peer_id,
							      const struct id *tarzan_id)
{

	struct connection *c = st->st_connection;

	indent = 1;

	const generalName_t *requested_ca = st->st_v1_requested_ca;

	passert(!LHAS(proposed_authbys, AUTH_NEVER));
	passert(!LHAS(proposed_authbys, AUTH_UNSET));

	/*
	 * Find the PEER's CA, check the per-state DB first.
	 */
	pexpect(st->st_remote_certs.processed);
	asn1_t peer_ca = get_peer_ca(&st->st_remote_certs.pubkey_db, peer_id);

	if (hunk_isempty(peer_ca)) {
		peer_ca = get_peer_ca(&pluto_pubkeys, peer_id);
	}

	/*
	 * The current connection won't do: search for one that will.
	 * First search for one with the same pair of hosts.
	 * If that fails, search for a suitable Road Warrior or Opportunistic
	 * connection (i.e. wildcard peer IP).
	 * We need to match:
	 * - peer_id (slightly complicated by instantiation)
	 * - if PSK auth, the key must not change (we used it to decode message)
	 * - policy-as-used must be acceptable to new connection
	 * - if initiator, also:
	 *   + our ID must not change (we sent it in previous message)
	 *   + our RSA key must not change (we used in in previous message)
	 */
	passert(c != NULL);

	int best_our_pathlen = 0;
	int best_peer_pathlen = 0;
	struct connection *best_found = NULL;
	int best_wildcards = 0;

	/*
	 * PASS 1: Match anything with the exact same SRC->DST. This
	 * list contains instantiated templates and oriented permanent
	 * connections.
	 *
	 * PASS 2: Match matching SRC->%any.  This list contains
	 * oriented template connections (since the remote address is
	 * %any).
	 */

	ip_address local = c->iface->local_address;
	FOR_EACH_THING(remote, endpoint_address(st->st_remote_endpoint), unset_address) {

		indent = 1;
		address_buf lb, rb;
		dbg_rhc("trying connections matching %s->%s",
			str_address(&local, &lb), str_address(&remote, &rb));

		struct connection_filter hpf = {
			.local = &local,
			.remote = &remote,
			.where = HERE,
		};
		while (next_connection(NEW2OLD, &hpf)) {
			struct connection *d = hpf.c;

			connection_buf b1, b2;
			indent = 2;
			dbg_rhc("checking "PRI_CONNECTION" against existing "PRI_CONNECTION"",
				pri_connection(d, &b2), pri_connection(c, &b1));
			indent = 3;

			/*
			 * First all the "easy" skips.
			 */

			/*
			 * An instantiated connection with ID_NULL is
			 * never better.  (it's identity was never
			 * authenticated).
			 *
			 * The exception being the current connection
			 * instance which is allowed to have no
			 * authentication.
			 */
			if (c != d && is_instance(d) && d->remote->host.id.kind == ID_NULL) {
				connection_buf cb;
				dbg_rhc("skipping ID_NULL instance "PRI_CONNECTION"",
					pri_connection(d, &cb));
				continue;
			}

			if (st->st_remote_certs.groundhog && !d->remote->config->host.groundhog) {
				connection_buf cb;
				dbg_rhc("skipping non-groundhog instance "PRI_CONNECTION"",
					pri_connection(d, &cb));
				continue;
			}

			/*
			 * An Opportunistic connection is never
			 * better.
			 *
			 * The exception being the current connection
			 * instance which is allowed to be
			 * opportunistic.
			 */

			if (c != d && is_opportunistic(d)) {
				connection_buf cb;
				dbg_rhc("skipping opportunistic connection "PRI_CONNECTION"",
					pri_connection(d, &cb));
				continue;
			}

			/*
			 * Only consider template and parent instances
			 * sec_label connections.
			 */
			if (is_labeled_child(d)) {
				connection_buf cb;
				dbg_rhc("skipping labeled child "PRI_CONNECTION,
					pri_connection(d, &cb));
				continue;
			}

			/* ignore group connections */
			if (is_group(d)) {
				connection_buf cb;
				dbg_rhc("skipping group template connection "PRI_CONNECTION,
					pri_connection(d, &cb));
				continue;
			}

			/* IKE version has to match */
			if (d->config->ike_version != st->st_ike_version) {
				dbg_rhc("skipping because mismatching IKE version");
				continue;
			}

			/*
			 * XXX: are these two bogus?  C was chosen
			 * when only the address was known so there's
			 * no reason to think that XAUTH_SERVER is
			 * correct.
			 */

			if (d->local->host.config->xauth.server != c->local->host.config->xauth.server) {
				/* Disallow IKEv2 CP or IKEv1 XAUTH mismatch */
				dbg_rhc("skipping because mismatched xauth_server");
				continue;
			}

			if (d->local->host.config->xauth.client != c->local->host.config->xauth.client) {
				/* Disallow IKEv2 CP or IKEv1 XAUTH mismatch */
				dbg_rhc("skipping because mismatched xauth_client");
				continue;
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
					enum_show(&ike_id_type_names, tarzan_id->kind, &tzesb));
				id_buf usb;
				esb_buf usesb;
				dbg_rhc("this connection's local id is %s (%s)",
				    str_id(&d->local->host.id, &usb),
				    enum_show(&ike_id_type_names, d->local->host.id.kind, &usesb));
				/* ??? pexpect(d->spd->spd_next == NULL); */
				if (!idr_wildmatch(&d->local->host, tarzan_id, st->logger)) {
					dbg_rhc("skipping because peer IDr payload does not match our expected ID");
					continue;
				}
			} else {
				dbg_rhc("no IDr payload received from peer");
			}

			/*
			 * The proposed authentication must match the
			 * policy of this connection.
			 */
			switch (st->st_ike_version) {
			case IKEv1:
				if (d->config->aggressive) {
					dbg_rhc("skipping because AGGRESSIVE isn't right");
					continue;	/* differ about aggressive mode */
				}
				if (LHAS(proposed_authbys, AUTH_PSK)) {
					if (!(d->remote->host.config->auth == AUTH_PSK)) {
						/* there needs to be a key */
						dbg_rhc("skipping because no PSK in POLICY");
						continue;
					}
					if (get_connection_psk(d) == NULL) {
						/* there needs to be a key */
						dbg_rhc("skipping because PSK and no secret");
						continue; /* no secret */
					}
				}
				if (LHAS(proposed_authbys, AUTH_RSASIG)) {
					if (!(d->remote->host.config->auth == AUTH_RSASIG)) {
						dbg_rhc("skipping because not RSASIG in POLICY");
						continue;	/* no key */
					}
					if (get_local_private_key(d, &pubkey_type_rsa,
								  st->logger) == NULL) {
						/*
						 * We must at least be able to find
						 * our private key.
						 */
						dbg_rhc("skipping because RSASIG and no private key");
						continue;	/* no key */
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
					continue;
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
						continue; /* no secret */
#else
						dbg_rhc("has no PSK; why?");
					}
#endif
					break;
				case AUTH_RSASIG:
					if (get_local_private_key(d, &pubkey_type_rsa,
								  st->logger) == NULL) {
						dbg_rhc("skipping because RSASIG and no private key");
						continue;	/* no key */
					}
					break;
				case AUTH_ECDSA:
					if (get_local_private_key(d, &pubkey_type_ecdsa,
								  st->logger) == NULL) {
						dbg_rhc("skipping because ECDSA and no private key");
						continue;	/* no key */
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

			int wildcards = 0;
			bool matching_peer_id =
				match_id("rhc:       ",
					 peer_id, &d->remote->host.id, &wildcards);

			/*
			 * Check if peer_id matches, exactly or after
			 * instantiation.
			 *
			 * Check for the match but also check to see
			 * if it's the %fromcert + peer id match
			 * result. - matt
			 */
			if (!matching_peer_id) {
				/* must be checking certs */
				if (d->remote->host.id.kind != ID_FROMCERT) {
					dbg_rhc("skipping because peer_id does not match and that.id.kind is not a cert");
					continue;
				}
			}

			/*
			 * XXX: When there are no certificates at all
			 * (PEER_CA and THAT.CA are NULL; REQUESTED_CA
			 * is NULL), these lookups return TRUE and
			 * *_pathlen==0 - a perfect match.
			 */
			int peer_pathlen;
			bool matching_peer_ca = trusted_ca(peer_ca,
							   ASN1(d->remote->host.config->ca),
							   &peer_pathlen);
			int our_pathlen;
			bool matching_requested_ca = match_requested_ca(requested_ca,
									d->local->host.config->ca,
									&our_pathlen);
			dbg_rhc("matching_peer_ca=%s(%d)/matching_request_ca=%s(%d))",
				bool_str(matching_peer_ca), peer_pathlen,
				bool_str(matching_requested_ca), our_pathlen);
			indent++;

			/*
			 * Both matching_peer_ca and
			 * matching_requested_ca are required.
			 *
			 * XXX: Remember, when there are no
			 * certificates, both are forced to TRUE.
			 */
			if (!matching_peer_ca || !matching_requested_ca) {
				dbg_rhc("skipping because !matching_peer_ca || !matching_requested_ca");
				continue;
			}

			/*
			 * Paul: We need to check all the other
			 * relevant policy bits, like compression,
			 * pfs, etc
			 */

			/*
			 * D has passed all the tests.
			 *
			 * We'll go with it if the Peer ID was an
			 * exact match (this includes an ID only
			 * match).
			 */
			if (matching_peer_id &&
			    wildcards == 0 &&
			    peer_pathlen == 0 &&
			    our_pathlen == 0) {
				connection_buf dcb;
				dbg_rhc("returning "PRI_CONNECTION" because exact peer id match",
					pri_connection(d, &dcb));
				return d;
			}

			/*
			 * If it was a non-exact (wildcard) match,
			 * we'll remember it as best_found in case an
			 * exact match doesn't come along.
			 *
			 * ??? the logic involving *_pathlen looks wrong.
			 * ??? which matters more peer_pathlen or our_pathlen minimization?
			 */
			if (best_found == NULL ||
			    (wildcards < best_wildcards) ||
			    (wildcards == best_wildcards && peer_pathlen < best_peer_pathlen) ||
			    (wildcards == best_wildcards && peer_pathlen == best_peer_pathlen && our_pathlen < best_our_pathlen)) {
				connection_buf cib;
				dbg_rhc("picking new best "PRI_CONNECTION" (wild=%d, peer_pathlen=%d/our=%d)",
					pri_connection(d, &cib),
					wildcards, peer_pathlen,
					our_pathlen);
				best_found = d;
				best_wildcards = wildcards;
				best_peer_pathlen = peer_pathlen;
				best_our_pathlen = our_pathlen;
			}
		}
	}
	return best_found;
}

bool refine_host_connection_of_state_on_responder(struct state *st,
						  lset_t proposed_authbys,
						  const struct id *peer_id,
						  const struct id *tarzan_id)
{
	int indent = 0;
	connection_buf cib;
	dbg_rhc("looking for an %s connection more refined than "PRI_CONNECTION"",
		st->st_connection->config->ike_info->version_name,
	    pri_connection(st->st_connection, &cib));
	indent = 1;

	struct connection *r = refine_host_connection_on_responder(indent, st,
								   proposed_authbys,
								   peer_id, tarzan_id);
	if (r == NULL) {
		dbg_rhc("returning FALSE because nothing is sufficiently refined");
		return false;
	}

	connection_buf bfb;
	dbg_rhc("returning TRUE as "PRI_CONNECTION" is most refined",
		pri_connection(r, &bfb));

	if (r != st->st_connection) {
		/*
		 * We are changing st->st_connection!  Our caller
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
		if (is_template(r) || is_group(r)) {
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
			r = rw_responder_refined_instantiate(r, st->st_connection->remote->host.addr,
							    NULL/*not-yet-known*/,
							    peer_id, HERE);
		} else {
			r = connection_addref(r, st->logger);
		}
		/*
		 * R is an improvement on .st_connection -- replace.
		 */
		connswitch_state_and_log(st, r);
		connection_delref(&r, st->logger);
	}

	connection_buf bcb;
	dbg_rhc("most refined is "PRI_CONNECTION,
		pri_connection(st->st_connection, &bcb));
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
       diag_t d = match_end_cert_id(certs, &c->remote->host.id, &remote_cert_id);

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
	       llog_diag(RC_LOG_SERIOUS, ike->sa.logger, &d, "%s", "");
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
			llog_sa(RC_LOG_SERIOUS, ike,
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
