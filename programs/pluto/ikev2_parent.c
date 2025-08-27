/*
 * IKEv2 parent SA creation routines, for Libreswan
 *
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010-2019 Tuomo Soini <tis@foobar.fi
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012-2018 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017-2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2017-2018 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
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

#include <unistd.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "demux.h"
#include "ikev2_parent.h"
#include "state.h"
#include "keys.h" /* needs state.h */
#include "id.h"
#include "connections.h"
#include "crypt_prf.h"
#include "crypto.h"
#include "x509.h"
#include "pluto_x509.h"
#include "ike_alg.h"
#include "ike_alg_hash.h"
#include "ike_alg_kem.h"
#include "kernel_alg.h"
#include "plutoalg.h"
#include "packet.h"
#include "ikev2.h"
#include "log.h"
#include "ipsec_doi.h"
#include "ikev2_replace.h"
#include "timer.h"
#include "ike_spi.h"
#include "rnd.h"
#include "pending.h"
#include "kernel.h"
#include "nat_traversal.h"
#include "keyhi.h" /* for SECKEY_DestroyPublicKey */
#include "crypt_hash.h"
#include "ikev2_ipseckey.h"
#include "ikev2_ppk.h"
#include "ikev2_redirect.h"
#include "crypt_dh.h"
#include "crypt_prf.h"
#include "ietf_constants.h"
#include "ip_address.h"
#include "send.h"
#include "ikev2_send.h"
#include "pluto_stats.h"
#include "ipsecconf/confread.h"		/* for struct starter_end */
#include "addr_lookup.h"
#include "impair.h"
#include "ikev2_message.h"
#include "ikev2_notification.h"
#include "ikev2_ts.h"
#include "ikev2_msgid.h"
#include "crypt_ke.h"
#include "crypt_symkey.h" /* for release_symkey */
#include "ip_info.h"
#include "iface.h"
#include "ikev2_auth.h"
#include "secrets.h"
#include "cert_decode_helper.h"
#include "addresspool.h"
#include "unpack.h"
#include "ikev2_peer_id.h"
#include "ikev2_cp.h"
#include "ikev2_child.h"
#include "ikev2_child.h"
#include "ikev2_create_child_sa.h"	/* for ikev2_rekey_ike_start() */
#include "rekeyfuzz.h"
#include "ikev2_ike_sa_init.h"		/* for initiate_v2_IKE_SA_INIT_request() */
#include "ikev2_states.h"

bool accept_v2_nonce(struct logger *logger, struct msg_digest *md,
		     chunk_t *dest, const char *name)
{
	/*
	 * note ISAKMP_NEXT_v2Ni == ISAKMP_NEXT_v2Nr
	 * so when we refer to ISAKMP_NEXT_v2Ni, it might be ISAKMP_NEXT_v2Nr
	 */
	struct pbs_in *nonce_pbs = &md->chain[ISAKMP_NEXT_v2Ni]->pbs;
	shunk_t nonce = pbs_in_left(nonce_pbs);

	/*
	 * RFC 7296 Section 2.10:
	 * Nonces used in IKEv2 MUST be randomly chosen, MUST be at least 128
	 * bits in size, and MUST be at least half the key size of the
	 * negotiated pseudorandom function (PRF).  However, the initiator
	 * chooses the nonce before the outcome of the negotiation is known.
	 * Because of that, the nonce has to be long enough for all the PRFs
	 * being proposed.
	 *
	 * We will check for a minimum/maximum here - not meeting that
	 * requirement is a syntax error(?).  Once the PRF is
	 * selected, we verify the nonce is big enough.
	 */

	if (nonce.len < IKEv2_MINIMUM_NONCE_SIZE || nonce.len > IKEv2_MAXIMUM_NONCE_SIZE) {
		llog(RC_LOG, logger, "%s length %zu not between %d and %d",
			    name, nonce.len, IKEv2_MINIMUM_NONCE_SIZE, IKEv2_MAXIMUM_NONCE_SIZE);
		return false;
	}
	replace_chunk(dest, nonce, name);
	return true;
}

bool negotiate_hash_algo_from_notification(const struct pbs_in *payload_pbs,
					   struct ike_sa *ike)
{
	lset_t sighash_policy = ike->sa.st_connection->config->sighash_policy;

	struct pbs_in pbs = *payload_pbs;
	while (pbs_left(&pbs) > 0) {

		uint16_t nh_value;
		passert(sizeof(nh_value) == RFC_7427_HASH_ALGORITHM_IDENTIFIER_SIZE);
		diag_t d = pbs_in_thing(&pbs, nh_value,
					"hash algorithm identifier (network ordered)");
		if (d != NULL) {
			llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
			pfree_diag(&d);
			return false;
		}
		enum ikev2_hash_algorithm h_value = ntohs(nh_value);

		name_buf b;
		const struct hash_desc *hash = ikev2_hash_desc(h_value, &b);
		if (hash == NULL) {
			llog_sa(RC_LOG, ike, "received and ignored unknown hash algorithm %s", b.buf);
			continue;
		}

		lset_t hash_bit = LELEM(h_value);
		if (!(sighash_policy & hash_bit)) {
			ldbg(ike->sa.logger, "digsig: received and ignored unacceptable hash algorithm %s", hash->common.fqn);
			continue;
		}

		ldbg(ike->sa.logger, "digsig: received and accepted hash algorithm %s", hash->common.fqn);
		ike->sa.st_v2_digsig.negotiated_hashes |= hash_bit;
	}
	return true;
}

void llog_v2_ike_sa_established(struct ike_sa *ike, struct child_sa *larval)
{
	LLOG_JAMBUF(RC_LOG, larval->sa.logger, buf) {
		switch (larval->sa.st_sa_role) {
		case SA_INITIATOR: jam_string(buf, "initiator"); break;
		case SA_RESPONDER: jam_string(buf, "responder"); break;
		}
		if (larval->sa.st_v2_rekey_pred != SOS_NOBODY) {
			pexpect(ike->sa.st_serialno == larval->sa.st_v2_rekey_pred);
			jam(buf, " rekeyed IKE SA "PRI_SO"",
			    pri_so(larval->sa.st_v2_rekey_pred));
		} else {
			jam(buf, " established IKE SA");
		}
		jam(buf, " ");
		jam_parent_sa_details(buf, &larval->sa);
	}
}

void v2_ike_sa_established(struct ike_sa *ike, where_t where)
{
	connection_establish_ike(ike, where);
	schedule_v2_nat_keepalive(ike, where);
	pstat_sa_established(&ike->sa);
}

/*
 * Check that the bundled keying material (KE) matches the accepted
 * proposal and if it doesn't record a response and return false.
 */

bool v2_accept_ke_for_proposal(struct ike_sa *ike,
			       struct state *st,
			       struct msg_digest *md,
			       const struct kem_desc *accepted_dh,
			       enum payload_security security)
{
	passert(md->chain[ISAKMP_NEXT_v2KE] != NULL);
	int ke_group = md->chain[ISAKMP_NEXT_v2KE]->payload.v2ke.isak_group;

	if (accepted_dh->ikev2_alg_id != ke_group) {
		name_buf ke_esb;
		llog(RC_LOG, st->logger,
		     "initiator guessed wrong keying material group (%s); responding with INVALID_KE_PAYLOAD requesting %s",
		     str_enum_short(&oakley_group_names, ke_group, &ke_esb),
		     accepted_dh->common.fqn);
		pstats(invalidke_sent_u, ke_group);
		pstats(invalidke_sent_s, accepted_dh->ikev2_alg_id);
		/* convert group to a raw buffer */
		uint16_t gr = htons(accepted_dh->ikev2_alg_id);
		record_v2N_response(st->logger, ike, md,
				    v2N_INVALID_KE_PAYLOAD, THING_AS_SHUNK(gr),
				    security);
		return false;
	}

	/* ike sa init */
	if (!unpack_KE(&st->st_gi, "Gi", accepted_dh,
		       md->chain[ISAKMP_NEXT_v2KE], st->logger)) {
		/* already logged? */
		record_v2N_response(st->logger, ike, md,
				    v2N_INVALID_SYNTAX, empty_shunk,
				    security);
		return false;
	}

	return true;
}

bool id_ipseckey_allowed(struct ike_sa *ike, enum ikev2_auth_method atype)
{
	const struct connection *c = ike->sa.st_connection;
	struct logger *logger = ike->sa.logger;
	struct id id = c->remote->host.id;

	if (!c->remote->host.config->key_from_DNS_on_demand)
		return false;

	if (c->remote->host.config->auth == AUTH_RSASIG &&
	    (id.kind == ID_FQDN || id_is_ipaddr(&id)))
{
		switch (atype) {
		case IKEv2_AUTH_RESERVED:
		case IKEv2_AUTH_DIGITAL_SIGNATURE:
		case IKEv2_AUTH_RSA_DIGITAL_SIGNATURE:
			return true; /* success */
		default:
			break;	/*  failure */
		}
	}

	if (LDBGP(DBG_BASE, logger)) {
		/* eb2 and err2 must have same scope */
		name_buf eb2;
		const char *err1 = "%dnsondemand";
		const char *err2 = "";

		if (atype != IKEv2_AUTH_RESERVED && !(atype == IKEv2_AUTH_RSA_DIGITAL_SIGNATURE ||
							atype == IKEv2_AUTH_DIGITAL_SIGNATURE)) {
			err1 = " initiator IKEv2 Auth Method mismatched ";
			err2 = str_enum_long(&ikev2_auth_method_names, atype, &eb2);
		}

		if (id.kind != ID_FQDN &&
		    id.kind != ID_IPV4_ADDR &&
		    id.kind != ID_IPV6_ADDR) {
			err1 = " mismatched ID type, that ID is not a FQDN, IPV4_ADDR, or IPV6_ADDR id type=";
			err2 = str_enum_short(&ike_id_type_names, id.kind, &eb2);
		}

		id_buf thatid;
		endpoint_buf ra;
		LDBG_log(logger, "%s "PRI_SO" not fetching ipseckey %s%s remote=%s thatid=%s",
			 c->name, pri_so(ike->sa.st_serialno),
			 err1, err2,
			 str_endpoint(&ike->sa.st_remote_endpoint, &ra),
			 str_id(&id, &thatid));
	}
	return false;
}

void ikev2_rekey_expire_predecessor(const struct child_sa *larval, so_serial_t pred)
{
	struct state *rst = state_by_serialno(pred);
	if (rst == NULL) {
		ldbg_sa(larval, "rekeyed "PRI_SO"; the state is already is gone",
			pri_so(pred));
		return;
	}

	/*
	 * Only established states have a lifetime scheduled.
	 */

	const struct state_event *lifetime_event = st_v2_lifetime_event(rst);
	deltatime_t lifetime = deltatime(0);
	if (lifetime_event != NULL) {
		lifetime = monotime_diff(lifetime_event->ev_time, mononow());
	}

	deltatime_buf lb;
	ldbg_sa(larval, "rekeyed "PRI_SO"; expire it remaining life %ss",
		pri_so(pred),
		(lifetime_event == NULL ? "<never>" : str_deltatime(lifetime, &lb)));

	if (deltatime_cmp(lifetime, >, EXPIRE_OLD_SA_DELAY)) {
		/* replace the REPLACE/EXPIRE event */
		if (lifetime_event != NULL) {
			event_delete(lifetime_event->ev_type, rst);
		}
		event_schedule(EVENT_v2_EXPIRE, EXPIRE_OLD_SA_DELAY, rst);
		pexpect(st_v2_lifetime_event(rst)->ev_type == EVENT_v2_EXPIRE);
	}
	/*
	 * else it should be on its way to expire, no need to kick
	 * dead state when it is down
	 */
}

void schedule_v2_replace_event(struct state *st)
{
	/*
	 * Time to rekey/replace/discard; scheduled only once
	 * during a state's lifetime.
	 */
	pexpect(st->st_v2_rekey_event == NULL);
	pexpect(st_v2_lifetime_event(st) == NULL);

	struct connection *c = st->st_connection;

	/*
	 * Determine the SA's lifetime (in seconds).
	 *
	 * Use .st_sa_kind_when_established, because, for an IKE SA, it may not
	 * have been emancipated (so IS_IKE_SA() would still be
	 * false).
	 */
	deltatime_t lifetime;
	switch (st->st_sa_kind_when_established) {
	case IKE_SA: lifetime = c->config->sa_ike_max_lifetime; break;
	case CHILD_SA: lifetime = c->config->sa_ipsec_max_lifetime; break;
	default: bad_case(st->st_sa_kind_when_established);
	}

	enum event_type kind;
	const char *story;
	if (is_opportunistic(c) &&
	    nr_child_leases(st->st_connection->remote) > 0) {
		kind = EVENT_v2_EXPIRE;
		story = "always expire opportunistic SA with lease";
	} else if (!c->config->rekey) {
		kind = EVENT_v2_EXPIRE;
		story = "policy doesn't allow re-key";
	} else if (IS_IKE_SA(st) && st->st_connection->config->reauth) {
		kind = EVENT_v2_REPLACE;
		story = "IKE SA with policy re-authenticate";
	} else {
		deltatime_t marg = fuzz_rekey_margin(st->st_sa_role,
						     c->config->sa_rekey_margin,
						     c->config->sa_rekey_fuzz/*percent*/);

		deltatime_t rekey_delay;
		if (deltatime_cmp(lifetime, >, marg)) {
			rekey_delay = deltatime_sub(lifetime, marg);
		} else {
			rekey_delay = lifetime;
			marg = deltatime(0);
		}
		st->st_replace_margin = marg;

		/* Time to rekey/reauth; scheduled once during a state's lifetime.*/
		deltatime_buf rdb, lb;
		ldbg(st->logger, PRI_SO" will start re-keying in %s seconds (replace in %s seconds)",
		     pri_so(st->st_serialno),
		     str_deltatime(rekey_delay, &rdb),
		     str_deltatime(lifetime, &lb));
		event_schedule(EVENT_v2_REKEY, rekey_delay, st);
		pexpect(st->st_v2_rekey_event->ev_type == EVENT_v2_REKEY);
		story = "attempting re-key";

		kind = EVENT_v2_REPLACE;
	}

	/*
	 * This is the drop-dead event.
	 */
	passert(kind == EVENT_v2_REPLACE || kind == EVENT_v2_EXPIRE);
	deltatime_buf lb;
	ldbg(st->logger, PRI_SO" will %s in %s seconds (%s)",
	     pri_so(st->st_serialno),
	     kind == EVENT_v2_EXPIRE ? "expire" : "be replaced",
	     str_deltatime(lifetime, &lb), story);

	/*
	 * Schedule the lifetime (death) event.  Only happens once
	 * when the state is established.
	 */
	event_schedule(kind, lifetime, st);
	pexpect(st_v2_lifetime_event(st)->ev_type == kind);
}

static stf_status process_v2_request_no_skeyseed_continue(struct state *ike_st,
							  struct msg_digest *unused_md)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_st);
	pexpect(ike->sa.st_sa_role == SA_RESPONDER);
	pexpect(v2_msg_role(unused_md) == NO_MESSAGE);
	pexpect(ike->sa.st_state == &state_v2_IKE_SA_INIT_R);
	ldbg(ike->sa.logger, "%s() for "PRI_SO" %s: calculating g^{xy}, sending R2",
	     __func__, pri_so(ike->sa.st_serialno), ike->sa.st_state->name);

	/* * Since UNUSED_MD is a request. */
	struct v2_incoming_fragments **frags = &ike->sa.st_v2_msgid_windows.responder.incoming_fragments;
	if (!pexpect((*frags) != NULL)) {
		return STF_INTERNAL_ERROR;
	}

	if (ike->sa.st_dh_shared_secret == NULL) {
		/*
		 * Since dh failed, the channel isn't end-to-end
		 * encrypted.  Try to send back a clear text notify
		 * and then abandon the connection.
		 */
		ldbg(ike->sa.logger, "aborting IKE SA: DH failed (EXPECTATION FAILED valid as no transition?)");
		send_v2N_response_from_md((*frags)->md, v2N_INVALID_SYNTAX, NULL,
					  "DH failed");
		return STF_FATAL;
	}

	if (!calc_v2_new_ike_keymat(ike, &ike->sa.st_ike_spis, HERE)) {
		/* already logged */
		return STF_FATAL;
	}

	/*
	 * Try to decrypt the fragments; the result could be no
	 * fragments, and hence, no exchange.
	 */

	struct msg_digest *md;
	if ((*frags)->total == 0) {
		if (!ikev2_decrypt_msg(ike, (*frags)->md)) {
			free_v2_incoming_fragments(frags);
			return STF_SKIP_COMPLETE_STATE_TRANSITION;
		}
		md = md_addref((*frags)->md);
		free_v2_incoming_fragments(frags);
	} else {
		if (!decrypt_v2_incoming_fragments(ike, frags)) {
			/* could free FRAGS */
			return STF_SKIP_COMPLETE_STATE_TRANSITION;
		}
		md = reassemble_v2_incoming_fragments(frags, ike->sa.logger);
	}

	process_protected_v2_message(ike, md);
	md_delref(&md);
	return STF_SKIP_COMPLETE_STATE_TRANSITION;
}

static void llog_v2_request_no_skeyseed(struct ike_sa *ike, const struct msg_digest *md,
					const char *content, ...)
{
	LLOG_JAMBUF(RC_LOG, ike->sa.logger, buf) {
		jam_string(buf, "received ");
		jam_enum_short(buf, &ikev2_exchange_names, md->hdr.isa_xchg);
		jam_string(buf, " containing ");
		{
			va_list ap;
			va_start(ap, content);
			jam_va_list(buf, content, ap);
			va_end(ap);
		}
		jam_string(buf, " from ");
		jam_endpoint_address_protocol_port_sensitive(buf, &md->sender);
		jam_string(buf, ", computing DH in the background");
	}
}

void process_v2_request_no_skeyseed(struct ike_sa *ike, struct msg_digest *md)
{
	if (!PEXPECT(md->logger, v2_msg_role(md) == MESSAGE_REQUEST)) {
		/*
		 * Responder only: on the initiator, SKEYSEED is
		 * computed by the IKE_SA_INIT response processor.
		 */
		return;
	}

	const enum ikev2_exchange ix = md->hdr.isa_xchg;
	if (!PEXPECT(md->logger, (ix == ISAKMP_v2_IKE_INTERMEDIATE ||
				  ix == ISAKMP_v2_IKE_AUTH))) {
		/*
		 * IKE_INTERMEDIATE and IKE_AUTH requests only.
		 */
		return;
	}

	if (!PEXPECT(ike->sa.logger, (ike->sa.st_state == &state_v2_IKE_SA_INIT_R ||
				      ike->sa.st_state == &state_v2_IKE_SESSION_RESUME_R))) {
		/*
		 * Still in IKE_SA_INIT responder state.
		 */
		return;
	}

	/*
	 * Not yet officially started on next message.
	 */
	if (!PEXPECT(ike->sa.logger, (ike->sa.st_v2_msgid_windows.responder.recv == 0 &&
				      ike->sa.st_v2_msgid_windows.responder.sent == 0 &&
				      ike->sa.st_v2_msgid_windows.responder.wip == -1))) {
		return;
	}

	/*
	 * Accumulate (or ignore) the message requests.
	 *
	 * If the message seems reasonable and is consistent with
	 * previous messages, save it.
	 *
	 * However, if there's something suspect such as flip-flopping
	 * between SK and SKF, repeated fragment; wrong or bad total;
	 * ... then let it drop.  End result could be that no messages
	 * accumulate and .st_v2_incomming remains NULL.
	 */

	struct v2_incoming_fragments **frags = &ike->sa.st_v2_msgid_windows.responder.incoming_fragments;
	if ((*frags) != NULL) {
		/*
		 * Already accumulating fragments, keep going?
		 */
		if (md->chain[ISAKMP_NEXT_v2SK] != NULL) {
			ldbg(ike->sa.logger, "received IKE encrypted message");
			if ((*frags)->total == 0) {
				ldbg(ike->sa.logger, "  ignoring message; collecting fragments");
			} else {
				ldbg(ike->sa.logger, "  ignoring message; already collected");
			}
			pexpect((*frags)->md != NULL);
		} else if (md->chain[ISAKMP_NEXT_v2SKF] != NULL) {
			collect_v2_incoming_fragment(ike, md, frags);
		} else {
			llog_pexpect(ike->sa.logger, HERE,
				     "message has neither SK nor SKF payload");
		}
		return;
	}

	/*
	 * First fragment (SKF) or payload (SK), start accumulating it
	 * as fragments and start crypto (for SK there's only one
	 * fragment).
	 */
	if (md->chain[ISAKMP_NEXT_v2SK] != NULL) {
		/* save message */
		*frags = alloc_thing(struct v2_incoming_fragments, "incoming v2_ike_rfrags");
		(*frags)->md = md_addref(md);
		llog_v2_request_no_skeyseed(ike, md, "SK payload");
	} else if (md->chain[ISAKMP_NEXT_v2SKF] != NULL) {
		struct ikev2_skf *skf = &md->chain[ISAKMP_NEXT_v2SKF]->payload.v2skf;
		switch (collect_v2_incoming_fragment(ike, md, frags)) {
		case FRAGMENT_IGNORED:
			ldbg(ike->sa.logger, "no fragments accumulated; skipping SKEYSEED");
			return;
		case FRAGMENTS_MISSING:
		case FRAGMENTS_COMPLETE:
			break;
		}
		llog_v2_request_no_skeyseed(ike, md, "SKF fragment %u (1 of %u)",
					    skf->isaskf_number, (*frags)->total);
	} else {
		llog_pexpect(ike->sa.logger, HERE, "message has neither SK nor SKF payload");
		return;
	}

	if ((*frags) == NULL) {
		llog_pexpect(ike->sa.logger, HERE, "no fragments");
		return;
	}

	/*
	 * Now that the first fragment or payload to arrive, kick of
	 * the SKEYSEED calculation.
	 */
	submit_dh_shared_secret(/*callback*/&ike->sa, /*task*/&ike->sa,
				/*no-md:in-background*/NULL,
				ike->sa.st_gi/*responder needs initiator KE*/,
				process_v2_request_no_skeyseed_continue, HERE);
}

void record_first_v2_packet(struct ike_sa *ike, struct msg_digest *md,
			    where_t where)
{
	/*
	 * Record first packet for later checking of signature.
	 *
	 * XXX:
	 *
	 * Should this code use pbs_in_all() which uses
	 * [.start...roof)?  The original code used:
	 *
	 * 	clonetochunk(st->st_firstpacket_peer, md->message_pbs.start,
	 *		     md->message_pbs(.cur-start),
	 *		     "saved first received packet");
	 *
	 * and pbs_in_to_cursor() both use (.cur-.start).
	 *
	 * Suspect it doesn't matter as the code initializing
	 * .message_pbs forces .roof==.cur - look for the comment
	 * "trim padding (not actually legit)".
	 */
	PEXPECT(ike->sa.logger, md->message_pbs.cur == md->message_pbs.roof);
	replace_chunk(&ike->sa.st_firstpacket_peer,
		      pbs_in_to_cursor(&md->message_pbs),
		      where->func);
}
