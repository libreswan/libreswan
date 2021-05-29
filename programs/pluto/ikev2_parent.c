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
#include "ike_alg_dh.h"
#include "kernel_alg.h"
#include "plutoalg.h"
#include "packet.h"
#include "demux.h"
#include "ikev2.h"
#include "log.h"
#include "ipsec_doi.h"
#include "vendor.h"
#include "timer.h"
#include "ike_spi.h"
#include "rnd.h"
#include "pending.h"
#include "kernel.h"
#include "nat_traversal.h"
#include "keyhi.h" /* for SECKEY_DestroyPublicKey */
#include "vendor.h"
#include "crypt_hash.h"
#include "ikev2_ipseckey.h"
#include "ikev2_ppk.h"
#include "ikev2_redirect.h"
#include "pam_auth.h"
#include "crypt_dh.h"
#include "crypt_prf.h"
#include "ietf_constants.h"
#include "ip_address.h"
#include "host_pair.h"
#include "send.h"
#include "ikev2_send.h"
#include "pluto_stats.h"
#include "ikev2_retry.h"
#include "ipsecconf/confread.h"		/* for struct starter_end */
#include "addr_lookup.h"
#include "impair.h"
#include "ikev2_message.h"
#include "ikev2_notify.h"
#include "ikev2_ts.h"
#include "ikev2_msgid.h"
#include "state_db.h"
#ifdef USE_XFRM_INTERFACE
# include "kernel_xfrm_interface.h"
#endif
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
#include "ikev2_create_child_sa.h"	/* for ikev2_rekey_ike_start() */

bool accept_v2_nonce(struct logger *logger, struct msg_digest *md,
		     chunk_t *dest, const char *name)
{
	/*
	 * note ISAKMP_NEXT_v2Ni == ISAKMP_NEXT_v2Nr
	 * so when we refer to ISAKMP_NEXT_v2Ni, it might be ISAKMP_NEXT_v2Nr
	 */
	pb_stream *nonce_pbs = &md->chain[ISAKMP_NEXT_v2Ni]->pbs;
	shunk_t nonce = pbs_in_left_as_shunk(nonce_pbs);

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
		llog(RC_LOG_SERIOUS, logger, "%s length %zu not between %d and %d",
			    name, nonce.len, IKEv2_MINIMUM_NONCE_SIZE, IKEv2_MAXIMUM_NONCE_SIZE);
		return false;
	}
	replace_chunk(dest, clone_hunk(nonce, name));
	return true;
}

static bool negotiate_hash_algo_from_notification(const struct pbs_in *payload_pbs,
						  struct ike_sa *ike)
{
	lset_t sighash_policy = ike->sa.st_connection->sighash_policy;

	struct pbs_in pbs = *payload_pbs;
	while (pbs_left(&pbs) > 0) {

		uint16_t nh_value;
		passert(sizeof(nh_value) == RFC_7427_HASH_ALGORITHM_IDENTIFIER_SIZE);
		diag_t d = pbs_in_raw(&pbs, &nh_value, sizeof(nh_value),
				      "hash algorithm identifier (network ordered)");
		if (d != NULL) {
			llog_diag(RC_LOG_SERIOUS, ike->sa.st_logger, &d, "%s", "");
			return false;
		}
		uint16_t h_value = ntohs(nh_value);

		switch (h_value) {
		/* We no longer support SHA1 (as per RFC 8247) */
		case IKEv2_HASH_ALGORITHM_SHA2_256:
			if (sighash_policy & POL_SIGHASH_SHA2_256) {
				ike->sa.st_hash_negotiated |= NEGOTIATE_AUTH_HASH_SHA2_256;
				dbg("received HASH_ALGORITHM_SHA2_256 which is allowed by local policy");
			}
			break;
		case IKEv2_HASH_ALGORITHM_SHA2_384:
			if (sighash_policy & POL_SIGHASH_SHA2_384) {
				ike->sa.st_hash_negotiated |= NEGOTIATE_AUTH_HASH_SHA2_384;
				dbg("received HASH_ALGORITHM_SHA2_384 which is allowed by local policy");
			}
			break;
		case IKEv2_HASH_ALGORITHM_SHA2_512:
			if (sighash_policy & POL_SIGHASH_SHA2_512) {
				ike->sa.st_hash_negotiated |= NEGOTIATE_AUTH_HASH_SHA2_512;
				dbg("received HASH_ALGORITHM_SHA2_512 which is allowed by local policy");
			}
			break;
		case IKEv2_HASH_ALGORITHM_SHA1:
			dbg("received and ignored IKEv2_HASH_ALGORITHM_SHA1 - it is no longer allowed as per RFC 8247");
			break;
		case IKEv2_HASH_ALGORITHM_IDENTITY:
			/* ike->sa.st_hash_negotiated |= NEGOTIATE_HASH_ALGORITHM_IDENTITY; */
			dbg("received unsupported HASH_ALGORITHM_IDENTITY - ignored");
			break;
		default:
			log_state(RC_LOG, &ike->sa, "received and ignored unknown hash algorithm %d", h_value);
		}
	}
	return true;
}

void ikev2_ike_sa_established(struct ike_sa *ike,
			      const struct state_v2_microcode *svm,
			      enum state_kind new_state)
{
	struct connection *c = ike->sa.st_connection;
	/*
	 * Taking it (what???) current from current state I2/R1.
	 * The parent has advanced but not the svm???
	 * Ideally this should be timeout of I3/R2 state svm.
	 * How to find that svm???
	 * I wonder what this comment means?  Needs rewording.
	 *
	 * XXX: .timeout_event is tied to a state transition.  Does
	 * that mean it applies to the transition or to the final
	 * state?  It is kind of treated as all three (the third case
	 * is where a transition gets shared between the parent and
	 * child).
	 */
	pexpect(svm->timeout_event == EVENT_SA_REPLACE);

	/*
	 * update the parent state to make sure that it knows we have
	 * authenticated properly.
	 */
	change_state(&ike->sa, new_state);
	c->newest_ike_sa = ike->sa.st_serialno;
	v2_schedule_replace_event(&ike->sa);
	ike->sa.st_viable_parent = TRUE;
	linux_audit_conn(&ike->sa, LAK_PARENT_START);
	pstat_sa_established(&ike->sa);
}

/*
 * Check that the bundled keying material (KE) matches the accepted
 * proposal and if it doesn't record a response and return false.
 */

bool v2_accept_ke_for_proposal(struct ike_sa *ike,
				      struct state *st,
				      struct msg_digest *md,
				      const struct dh_desc *accepted_dh,
				      enum payload_security security)
{
	passert(md->chain[ISAKMP_NEXT_v2KE] != NULL);
	int ke_group = md->chain[ISAKMP_NEXT_v2KE]->payload.v2ke.isak_group;
	if (accepted_dh->common.id[IKEv2_ALG_ID] == ke_group) {
		return true;
	}

	esb_buf ke_esb;
	llog(RC_LOG, st->st_logger,
		    "initiator guessed wrong keying material group (%s); responding with INVALID_KE_PAYLOAD requesting %s",
		    enum_show_short(&oakley_group_names, ke_group, &ke_esb),
		    accepted_dh->common.fqn);
	pstats(invalidke_sent_u, ke_group);
	pstats(invalidke_sent_s, accepted_dh->common.id[IKEv2_ALG_ID]);
	/* convert group to a raw buffer */
	uint16_t gr = htons(accepted_dh->group);
	chunk_t nd = THING_AS_CHUNK(gr);
	record_v2N_response(st->st_logger, ike, md,
			    v2N_INVALID_KE_PAYLOAD, &nd,
			    security);
	return false;
}

bool id_ipseckey_allowed(struct ike_sa *ike, enum ikev2_auth_method atype)
{
	const struct connection *c = ike->sa.st_connection;
	struct id id = c->spd.that.id;

	if (!c->spd.that.key_from_DNS_on_demand)
		return FALSE;

	if (c->spd.that.authby == AUTHBY_RSASIG &&
	    (id.kind == ID_FQDN || id_is_ipaddr(&id)))
{
		switch (atype) {
		case IKEv2_AUTH_RESERVED:
		case IKEv2_AUTH_DIGSIG:
		case IKEv2_AUTH_RSA:
			return TRUE; /* success */
		default:
			break;	/*  failure */
		}
	}

	if (DBGP(DBG_BASE)) {
		/* eb2 and err2 must have same scope */
		esb_buf eb2;
		const char *err1 = "%dnsondemand";
		const char *err2 = "";

		if (atype != IKEv2_AUTH_RESERVED && !(atype == IKEv2_AUTH_RSA ||
							atype == IKEv2_AUTH_DIGSIG)) {
			err1 = " initiator IKEv2 Auth Method mismatched ";
			err2 = enum_name(&ikev2_auth_names, atype);
		}

		if (id.kind != ID_FQDN &&
		    id.kind != ID_IPV4_ADDR &&
		    id.kind != ID_IPV6_ADDR) {
			err1 = " mismatched ID type, that ID is not a FQDN, IPV4_ADDR, or IPV6_ADDR id type=";
			err2 = enum_show(&ike_id_type_names, id.kind, &eb2);
		}

		id_buf thatid;
		endpoint_buf ra;
		DBG_log("%s #%lu not fetching ipseckey %s%s remote=%s thatid=%s",
			c->name, ike->sa.st_serialno,
			err1, err2,
			str_endpoint(&ike->sa.st_remote_endpoint, &ra),
			str_id(&id, &thatid));
	}
	return FALSE;
}

/*
 *
 ***************************************************************
 *****                   PARENT_OUTI1                      *****
 ***************************************************************
 *
 *
 * Initiate an Oakley Main Mode exchange.
 *       HDR, SAi1, KEi, Ni   -->
 *
 * Note: this is not called from demux.c, but from ipsecdoi_initiate().
 *
 */
static ke_and_nonce_cb ikev2_parent_outI1_continue;

void ikev2_out_IKE_SA_INIT_I(struct connection *c,
			     struct state *predecessor,
			     lset_t policy,
			     unsigned long try,
			     const threadtime_t *inception,
			     chunk_t sec_label,
			     bool background, struct logger *logger)
{
	if (drop_new_exchanges()) {
		/* Only drop outgoing opportunistic connections */
		if (c->policy & POLICY_OPPORTUNISTIC) {
			return;
		}
	}

	const struct finite_state *fs = finite_states[STATE_PARENT_I0];
	pexpect(fs->nr_transitions == 1);
	const struct state_v2_microcode *transition = &fs->v2_transitions[0];
	struct ike_sa *ike = new_v2_ike_state(c, transition, SA_INITIATOR,
					      ike_initiator_spi(), zero_ike_spi,
					      policy, try, logger->global_whackfd);
	statetime_t start = statetime_backdate(&ike->sa, inception);

	/* set up new state */
	passert(ike->sa.st_ike_version == IKEv2);
	passert(ike->sa.st_state->kind == STATE_PARENT_I0);
	passert(ike->sa.st_sa_role == SA_INITIATOR);
	ike->sa.st_try = try;

	if (sec_label.len != 0) {
		dbg("%s: received security label from acquire: \"%.*s\"", __FUNCTION__,
				(int)sec_label.len, sec_label.ptr);
		dbg("%s: connection security label: \"%.*s\"", __FUNCTION__,
				(int)c->spd.this.sec_label.len, c->spd.this.sec_label.ptr);
		/*
		 * Should we have a within_range() check here? In theory, the ACQUIRE came
		 * from a policy we gave the kernel, so it _should_ be within our range?
		 */
		ike->sa.st_acquired_sec_label = clone_hunk(sec_label, "st_acquired_sec_label");
	}

	if ((c->iketcp == IKE_TCP_ONLY) || (try > 1 && c->iketcp != IKE_TCP_NO)) {
		dbg("TCP: forcing #%lu remote endpoint port to %d",
		    ike->sa.st_serialno, c->remote_tcpport);
		update_endpoint_port(&ike->sa.st_remote_endpoint, ip_hport(c->remote_tcpport));
		struct iface_endpoint *ret = create_tcp_interface(ike->sa.st_interface->ip_dev,
								  ike->sa.st_remote_endpoint,
								  ike->sa.st_logger);
		if (ret == NULL) {
			/* TCP: already logged? */
			delete_state(&ike->sa);
			return;
		}
		/*
		 * TCP: leaks old st_interface?
		 *
		 * XXX: perhaps; first time through .st_interface
		 * points at the packet interface (ex UDP) which is
		 * shared between states; but once that is replaced by
		 * a per-state interface it could well leak?
		 *
		 * Fix by always refcnting struct iface_endpoint?
		 */
		ike->sa.st_interface = ret;
	}

	if (impair.omit_v2_ike_auth_child) {
		llog_sa(RC_LOG, ike, "IMPAIR: omitting CHILD SA payloads from the IKE_AUTH request");
	} else if (HAS_IPSEC_POLICY(policy)) {
		add_pending(background ? null_fd : logger->global_whackfd, ike, c, policy, 1,
			    predecessor == NULL ? SOS_NOBODY : predecessor->st_serialno,
			    sec_label, true /*part of initiate*/);
	}

	/*
	 * XXX: why limit this log line to whack when opportunistic?
	 * This was, after all, triggered by something that happened
	 * at this end.
	 */
	enum stream log_stream = ((c->policy & POLICY_OPPORTUNISTIC) == LEMPTY) ? ALL_STREAMS : WHACK_STREAM;

	if (predecessor != NULL) {
		/*
		 * XXX: can PREDECESSOR be a child?  Idle speculation
		 * would suggest it can: perhaps it's a state that
		 * hasn't yet emancipated, or the child from a must
		 * remain up connection.
		 */
		dbg("predecessor #%lu: %s SA; %s %s; %s",
		    predecessor->st_serialno,
		    IS_CHILD_SA(predecessor) ? "CHILD" : "IKE",
		    IS_V2_ESTABLISHED(predecessor->st_state) ? "established" : "establishing?",
		    enum_enum_name(&sa_type_names, predecessor->st_ike_version,
				   predecessor->st_establishing_sa),
		    predecessor->st_state->name);
		log_state(log_stream | (RC_NEW_V2_STATE + STATE_PARENT_I1), &ike->sa,
			  "initiating IKEv2 connection to replace #%lu",
			  predecessor->st_serialno);
		if (IS_V2_ESTABLISHED(predecessor->st_state)) {
#if 0
			/*
			 * XXX: TYPO (as in ST should be PREDECESSOR)
			 * or intended be behaviour?  ST is the just
			 * created IKE SA so ...
			 */
			if (IS_CHILD_SA(st))
				ike->sa.st_ipsec_pred = predecessor->st_serialno;
			else
				ike->sa.st_ike_pred = predecessor->st_serialno;
#else
			ike->sa.st_ike_pred = predecessor->st_serialno;
#endif
		}
		update_pending(ike_sa(predecessor, HERE), ike);
	} else {
		log_state(log_stream | (RC_NEW_V2_STATE + STATE_PARENT_I1), &ike->sa,
			  "initiating IKEv2 connection");
	}

	/*
	 * XXX: hack: detach from whack _after_ the above message has
	 * been logged.  Better to do that in the caller?
	 */
	if (background) {
		close_any(&ike->sa.st_logger->object_whackfd);
		close_any(&ike->sa.st_logger->global_whackfd);
	}

	if (IS_LIBUNBOUND && id_ipseckey_allowed(ike, IKEv2_AUTH_RESERVED)) {
		stf_status ret = idr_ipseckey_fetch(ike);
		if (ret != STF_OK) {
			return;
		}
	}

	/*
	 * Initialize ike->sa.st_oakley, including the group number.
	 * Grab the DH group from the first configured proposal and build KE.
	 */
	struct ikev2_proposals *ike_proposals =
		get_v2_ike_proposals(c, "IKE SA initiator selecting KE", ike->sa.st_logger);
	ike->sa.st_oakley.ta_dh = ikev2_proposals_first_dh(ike_proposals, ike->sa.st_logger);
	if (ike->sa.st_oakley.ta_dh == NULL) {
		log_state(RC_LOG, &ike->sa, "proposals do not contain a valid DH");
		delete_state(&ike->sa);
		return;
	}

	/*
	 * Calculate KE and Nonce.
	 */
	submit_ke_and_nonce(&ike->sa, ike->sa.st_oakley.ta_dh,
			    ikev2_parent_outI1_continue,
			    "ikev2_outI1 KE");
	statetime_stop(&start, "%s()", __func__);
}

/*
 * package up the calculated KE value, and emit it as a KE payload.
 * used by IKEv2: parent, child (PFS)
 */
bool emit_v2KE(chunk_t *g, const struct dh_desc *group,
	       pb_stream *outs)
{
	if (impair.ke_payload == IMPAIR_EMIT_OMIT) {
		llog(RC_LOG, outs->outs_logger, "IMPAIR: omitting KE payload");
		return true;
	}

	pb_stream kepbs;

	struct ikev2_ke v2ke = {
		.isak_group = group->common.id[IKEv2_ALG_ID],
	};

	if (!out_struct(&v2ke, &ikev2_ke_desc, outs, &kepbs))
		return FALSE;

	if (impair.ke_payload >= IMPAIR_EMIT_ROOF) {
		uint8_t byte = impair.ke_payload - IMPAIR_EMIT_ROOF;
		llog(RC_LOG, outs->outs_logger,
			    "IMPAIR: sending bogus KE (g^x) == %u value to break DH calculations", byte);
		/* Only used to test sending/receiving bogus g^x */
		diag_t d = pbs_out_repeated_byte(&kepbs, byte, g->len, "ikev2 impair KE (g^x) == 0");
		if (d != NULL) {
			llog_diag(RC_LOG_SERIOUS, outs->outs_logger, &d, "%s", "");
			return false;
		}
	} else if (impair.ke_payload == IMPAIR_EMIT_EMPTY) {
		llog(RC_LOG, outs->outs_logger, "IMPAIR: sending an empty KE value");
		diag_t d = pbs_out_zero(&kepbs, 0, "ikev2 impair KE (g^x) == empty");
		if (d != NULL) {
			llog_diag(RC_LOG_SERIOUS, outs->outs_logger, &d, "%s", "");
			return false;
		}
	} else {
		if (!out_hunk(*g, &kepbs, "ikev2 g^x"))
			return FALSE;
	}

	close_output_pbs(&kepbs);
	return TRUE;
}

stf_status ikev2_parent_outI1_continue(struct state *ike_st,
				       struct msg_digest *unused_md,
				       struct dh_local_secret *local_secret,
				       chunk_t *nonce)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_st);
	pexpect(ike->sa.st_sa_role == SA_INITIATOR);
	pexpect(unused_md == NULL);
	/* I1 is from INVALID KE */
	pexpect(ike->sa.st_state->kind == STATE_PARENT_I0 ||
		ike->sa.st_state->kind == STATE_PARENT_I1);
	dbg("%s() for #%lu %s",
	     __func__, ike->sa.st_serialno, ike->sa.st_state->name);

	unpack_KE_from_helper(&ike->sa, local_secret, &ike->sa.st_gi);
	unpack_nonce(&ike->sa.st_ni, nonce);
	return record_v2_IKE_SA_INIT_request(ike) ? STF_OK : STF_INTERNAL_ERROR;
}

bool record_v2_IKE_SA_INIT_request(struct ike_sa *ike)
{
	struct connection *c = ike->sa.st_connection;

	/* set up reply */
	struct pbs_out reply_stream = open_pbs_out("reply packet",
						   reply_buffer, sizeof(reply_buffer),
						   ike->sa.st_logger);

	if (impair.send_bogus_dcookie) {
		/* add or mangle a dcookie so what we will send is bogus */
		DBG_log("Mangling dcookie because --impair-send-bogus-dcookie is set");
		replace_chunk(&ike->sa.st_dcookie, alloc_chunk(1, "mangled dcookie"));
		messupn(ike->sa.st_dcookie.ptr, 1);
	}

	/* HDR out */

	pb_stream rbody = open_v2_message(&reply_stream, ike, NULL /* request */,
					  ISAKMP_v2_IKE_SA_INIT);
	if (!pbs_ok(&rbody)) {
		return false;
	}

	/*
	 * https://tools.ietf.org/html/rfc5996#section-2.6
	 * reply with the anti DDOS cookie if we received one (remote is under attack)
	 */
	if (ike->sa.st_dcookie.ptr != NULL) {
		/* In v2, for parent, protoid must be 0 and SPI must be empty */
		if (!emit_v2N_hunk(v2N_COOKIE, ike->sa.st_dcookie, &rbody)) {
			return false;
		}
	}

	/* SA out */

	struct ikev2_proposals *ike_proposals =
		get_v2_ike_proposals(c, "IKE SA initiator emitting local proposals", ike->sa.st_logger);
	if (!ikev2_emit_sa_proposals(&rbody, ike_proposals,
				     (chunk_t*)NULL /* IKE - no CHILD SPI */)) {
		return false;
	}

	/*
	 * ??? from here on, this looks a lot like the end of
	 * ikev2_in_IKE_SA_INIT_I_out_IKE_SA_INIT_R_tail.
	 */

	/* send KE */
	if (!emit_v2KE(&ike->sa.st_gi, ike->sa.st_oakley.ta_dh, &rbody))
		return false;

	/* send NONCE */
	{
		pb_stream pb;
		struct ikev2_generic in = {
			.isag_critical = build_ikev2_critical(false, ike->sa.st_logger),
		};

		if (!out_struct(&in, &ikev2_nonce_desc, &rbody, &pb) ||
		    !out_hunk(ike->sa.st_ni, &pb, "IKEv2 nonce"))
			return false;

		close_output_pbs(&pb);
	}

	/* Send fragmentation support notification */
	if (c->policy & POLICY_IKE_FRAG_ALLOW) {
		if (!emit_v2N(v2N_IKEV2_FRAGMENTATION_SUPPORTED, &rbody))
			return false;
	}

	/* Send USE_PPK Notify payload */
	if (LIN(POLICY_PPK_ALLOW, c->policy)) {
		if (!emit_v2N(v2N_USE_PPK, &rbody))
			return false;
	}

	/* Send INTERMEDIATE_EXCHANGE_SUPPORTED Notify payload */
	if (c->policy & POLICY_INTERMEDIATE) {
		if (!emit_v2N(v2N_INTERMEDIATE_EXCHANGE_SUPPORTED, &rbody))
			return STF_INTERNAL_ERROR;
	}

	/* first check if this IKE_SA_INIT came from redirect
	 * instruction.
	 * - if yes, send the v2N_REDIRECTED_FROM
	 *   with the identity of previous gateway
	 * - if not, check if we support redirect mechanism
	 *   and send v2N_REDIRECT_SUPPORTED if we do
	 */
	if (address_is_specified(c->temp_vars.redirect_ip)) {
		if (!emit_redirected_from_notification(&c->temp_vars.old_gw_address, &rbody))
			return false;
	} else if (LIN(POLICY_ACCEPT_REDIRECT_YES, c->policy)) {
		if (!emit_v2N(v2N_REDIRECT_SUPPORTED, &rbody))
			return false;
	}

	/* Send SIGNATURE_HASH_ALGORITHMS Notify payload */
	if (!impair.omit_hash_notify_request) {
		if (((c->policy & POLICY_RSASIG) || (c->policy & POLICY_ECDSA))
			&& (c->sighash_policy != LEMPTY)) {
			if (!emit_v2N_signature_hash_algorithms(c->sighash_policy, &rbody))
				return false;
		}
	} else {
		log_state(RC_LOG, &ike->sa,
			  "Impair: Skipping the Signature hash notify in IKE_SA_INIT Request");
	}

	/* Send NAT-T Notify payloads */
	if (!ikev2_out_nat_v2n(&rbody, &ike->sa, &zero_ike_spi/*responder unknown*/))
		return false;

	/* From here on, only payloads left are Vendor IDs */
	if (c->send_vendorid) {
		if (!emit_v2V(pluto_vendorid, &rbody))
			return false;
	}

	if (c->fake_strongswan) {
		if (!emit_v2V("strongSwan", &rbody))
			return false;
	}

	if (c->policy & POLICY_AUTH_NULL) {
		if (!emit_v2V("Opportunistic IPsec", &rbody))
			return STF_INTERNAL_ERROR;
	}

	close_output_pbs(&rbody);
	close_output_pbs(&reply_stream);

	/* save packet for later signing */
	replace_chunk(&ike->sa.st_firstpacket_me,
		clone_out_pbs_as_chunk(&reply_stream, "saved first packet"));

	/* Transmit */
	record_v2_message(ike, &reply_stream, "IKE_SA_INIT request",
			  MESSAGE_REQUEST);
	return true;
}

/*
 *
 ***************************************************************
 *                       PARENT_INI1                       *****
 ***************************************************************
 *  -
 *
 *
 */

/* no state: none I1 --> R1
 *                <-- HDR, SAi1, KEi, Ni
 * HDR, SAr1, KEr, Nr, [CERTREQ] -->
 */

static ke_and_nonce_cb ikev2_in_IKE_SA_INIT_I_out_IKE_SA_INIT_R_continue;	/* forward decl and type assertion */

stf_status ikev2_in_IKE_SA_INIT_I_out_IKE_SA_INIT_R(struct ike_sa *ike,
						    struct child_sa *child,
						    struct msg_digest *md)
{
	pexpect(child == NULL);
	struct connection *c = ike->sa.st_connection;
	/* set up new state */
	update_ike_endpoints(ike, md);
	passert(ike->sa.st_ike_version == IKEv2);
	passert(ike->sa.st_state->kind == STATE_PARENT_R0);
	passert(ike->sa.st_sa_role == SA_RESPONDER);
	/* set by caller */
	pexpect(md->svm == finite_states[STATE_PARENT_R0]->v2_transitions);
	pexpect(md->svm->state == STATE_PARENT_R0);

	/* Vendor ID processing */
	for (struct payload_digest *v = md->chain[ISAKMP_NEXT_v2V]; v != NULL; v = v->next) {
		handle_vendorid(md, (char *)v->pbs.cur, pbs_left(&v->pbs), TRUE, ike->sa.st_logger);
	}

	/* Get the proposals ready. */
	struct ikev2_proposals *ike_proposals =
		get_v2_ike_proposals(c, "IKE SA responder matching remote proposals", ike->sa.st_logger);

	/*
	 * Select the proposal.
	 */
	stf_status ret = ikev2_process_sa_payload("IKE responder",
						  &md->chain[ISAKMP_NEXT_v2SA]->pbs,
						  /*expect_ike*/ TRUE,
						  /*expect_spi*/ FALSE,
						  /*expect_accepted*/ FALSE,
						  LIN(POLICY_OPPORTUNISTIC, c->policy),
						  &ike->sa.st_accepted_ike_proposal,
						  ike_proposals, ike->sa.st_logger);
	if (ret != STF_OK) {
		pexpect(ike->sa.st_sa_role == SA_RESPONDER);
		pexpect(ret > STF_FAIL);
		record_v2N_response(ike->sa.st_logger, ike, md,
				    ret - STF_FAIL, NULL,
				    UNENCRYPTED_PAYLOAD);
		return STF_FAIL;
	}

	if (DBGP(DBG_BASE)) {
		DBG_log_ikev2_proposal("accepted IKE proposal",
				       ike->sa.st_accepted_ike_proposal);
	}

	/*
	 * Convert what was accepted to internal form and apply some
	 * basic validation.  If this somehow fails (it shouldn't but
	 * ...), drop everything.
	 */
	if (!ikev2_proposal_to_trans_attrs(ike->sa.st_accepted_ike_proposal,
					   &ike->sa.st_oakley, ike->sa.st_logger)) {
		log_state(RC_LOG_SERIOUS, &ike->sa, "IKE responder accepted an unsupported algorithm");
		/* STF_INTERNAL_ERROR doesn't delete ST */
		return STF_FATAL;
	}

	/*
	 * Check the MODP group in the payload matches the accepted
	 * proposal.
	 */
	if (!v2_accept_ke_for_proposal(ike, &ike->sa, md,
				       ike->sa.st_oakley.ta_dh,
				       UNENCRYPTED_PAYLOAD)) {
		/* pexpect(reply-recorded) */
		return STF_FAIL;
	}

	/*
	 * Check and read the KE contents.
	 */
	/* note: v1 notification! */
	if (!unpack_KE(&ike->sa.st_gi, "Gi", ike->sa.st_oakley.ta_dh,
		       md->chain[ISAKMP_NEXT_v2KE], ike->sa.st_logger)) {
		send_v2N_response_from_md(md, v2N_INVALID_SYNTAX, NULL);
		return STF_FATAL;
	}

	/* extract results */
	ike->sa.st_seen_fragmentation_supported = md->pd[PD_v2N_IKEV2_FRAGMENTATION_SUPPORTED] != NULL;
	ike->sa.st_seen_ppk = md->pd[PD_v2N_USE_PPK] != NULL;
	ike->sa.st_seen_intermediate = md->pd[PD_v2N_INTERMEDIATE_EXCHANGE_SUPPORTED] != NULL;
	ike->sa.st_seen_redirect_sup = (md->pd[PD_v2N_REDIRECTED_FROM] != NULL ||
					md->pd[PD_v2N_REDIRECT_SUPPORTED] != NULL);

	/*
	 * Responder: check v2N_NAT_DETECTION_DESTINATION_IP or/and
	 * v2N_NAT_DETECTION_SOURCE_IP.
	 *
	 *   2.23.  NAT Traversal
	 *
	 *   The IKE initiator MUST check the NAT_DETECTION_SOURCE_IP
	 *   or NAT_DETECTION_DESTINATION_IP payloads if present, and
	 *   if they do not match the addresses in the outer packet,
	 *   MUST tunnel all future IKE and ESP packets associated
	 *   with this IKE SA over UDP port 4500.
	 *
	 * Since this is the responder, there's really not much to do.
	 * It is the initiator that will switch to port 4500 (float
	 * away) when necessary.
	 */
	if (v2_nat_detected(ike, md)) {
		dbg("NAT: responder so initiator gets to switch ports");
		/* should this check that a port is available? */
	}

	if (md->pd[PD_v2N_SIGNATURE_HASH_ALGORITHMS] != NULL) {
		if (impair.ignore_hash_notify_response) {
			log_state(RC_LOG, &ike->sa, "IMPAIR: ignoring the hash notify in IKE_SA_INIT request");
		} else if (!negotiate_hash_algo_from_notification(&md->pd[PD_v2N_SIGNATURE_HASH_ALGORITHMS]->pbs, ike)) {
			return STF_FATAL;
		}
		ike->sa.st_seen_hashnotify = true;
	}

	/* calculate the nonce and the KE */
	submit_ke_and_nonce(&ike->sa,
			    ike->sa.st_oakley.ta_dh,
			    ikev2_in_IKE_SA_INIT_I_out_IKE_SA_INIT_R_continue,
			    "ikev2_in_IKE_SA_INIT_I_out_IKE_SA_INIT_R_continue");
	return STF_SUSPEND;
}

static stf_status ikev2_in_IKE_SA_INIT_I_out_IKE_SA_INIT_R_continue(struct state *ike_st,
								    struct msg_digest *md,
								    struct dh_local_secret *local_secret,
								    chunk_t *nonce)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_st);
	pexpect(ike->sa.st_sa_role == SA_RESPONDER);
	pexpect(v2_msg_role(md) == MESSAGE_REQUEST); /* i.e., MD!=NULL */
	pexpect(ike->sa.st_state->kind == STATE_PARENT_R0);
	dbg("%s() for #%lu %s: calculated ke+nonce, sending R1",
	    __func__, ike->sa.st_serialno, ike->sa.st_state->name);

	struct connection *c = ike->sa.st_connection;
	bool send_certreq = FALSE;

	/* note that we don't update the state here yet */

	/*
	 * XXX:
	 *
	 * Should this code use clone_in_pbs_as_chunk() which uses
	 * pbs_room() (.roof-.start)?  The original code:
	 *
	 * 	clonetochunk(ike->sa.st_firstpacket_peer, md->message_pbs.start,
	 *		     pbs_offset(&md->message_pbs),
	 *		     "saved first received packet");
	 *
	 * and clone_out_pbs_as_chunk() both use pbs_offset()
	 * (.cur-.start).
	 *
	 * Suspect it doesn't matter as the code initializing
	 * .message_pbs forces .roof==.cur - look for the comment
	 * "trim padding (not actually legit)".
	 */
	/* record first packet for later checking of signature */
	replace_chunk(&ike->sa.st_firstpacket_peer,
		clone_out_pbs_as_chunk(&md->message_pbs,
			"saved first received packet in inI1outR1_continue_tail"));

	/* make sure HDR is at start of a clean buffer */
	struct pbs_out reply_stream = open_pbs_out("reply packet",
						   reply_buffer, sizeof(reply_buffer),
						   ike->sa.st_logger);

	/* HDR out */
	struct pbs_out rbody = open_v2_message(&reply_stream, ike,
					       md /* response */,
					       ISAKMP_v2_IKE_SA_INIT);
	if (!pbs_ok(&rbody)) {
		return STF_INTERNAL_ERROR;
	}

	/* start of SA out */
	{
		/*
		 * Since this is the initial IKE exchange, the SPI is
		 * emitted as part of the packet header and not as
		 * part of the proposal.  Hence the NULL SPI.
		 */
		passert(ike->sa.st_accepted_ike_proposal != NULL);
		if (!ikev2_emit_sa_proposal(&rbody, ike->sa.st_accepted_ike_proposal, NULL)) {
			dbg("problem emitting accepted proposal");
			return STF_INTERNAL_ERROR;
		}
	}

	/* Ni in */
	if (!accept_v2_nonce(ike->sa.st_logger, md, &ike->sa.st_ni, "Ni")) {
		/*
		 * Presumably not our fault.  Syntax errors kill the
		 * family, hence FATAL.
		 */
		record_v2N_response(ike->sa.st_logger, ike, md,
				    v2N_INVALID_SYNTAX, NULL/*no-data*/,
				    UNENCRYPTED_PAYLOAD);
		return STF_FATAL;
	}

	/* ??? from here on, this looks a lot like the end of ikev2_parent_outI1_common */

	/*
	 * Unpack and send KE
	 *
	 * Pass the crypto helper's oakley group so that it is
	 * consistent with what was unpacked.
	 *
	 * IKEv2 code (arguably, incorrectly) uses st_oakley.ta_dh to
	 * track the most recent KE sent out.  It should instead be
	 * maintaining a list of KEs sent out (so that they can be
	 * reused should the initial responder flip-flop) and only set
	 * st_oakley.ta_dh once the proposal has been accepted.
	 */
	pexpect(ike->sa.st_oakley.ta_dh == dh_local_secret_desc(local_secret));
	unpack_KE_from_helper(&ike->sa, local_secret, &ike->sa.st_gr);
	if (!emit_v2KE(&ike->sa.st_gr, dh_local_secret_desc(local_secret), &rbody)) {
		return STF_INTERNAL_ERROR;
	}

	/* send NONCE */
	unpack_nonce(&ike->sa.st_nr, nonce);
	{
		pb_stream pb;
		struct ikev2_generic in = {
			.isag_critical = build_ikev2_critical(false, ike->sa.st_logger),
		};

		if (!out_struct(&in, &ikev2_nonce_desc, &rbody, &pb) ||
		    !out_hunk(ike->sa.st_nr, &pb, "IKEv2 nonce"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&pb);
	}

	/* decide to send a CERTREQ - for RSASIG or GSSAPI */
	send_certreq = (((c->policy & POLICY_RSASIG) &&
			 !has_preloaded_public_key(&ike->sa)));

	/* Send fragmentation support notification */
	if (c->policy & POLICY_IKE_FRAG_ALLOW) {
		if (!emit_v2N(v2N_IKEV2_FRAGMENTATION_SUPPORTED, &rbody))
			return STF_INTERNAL_ERROR;
	}

	/* Send USE_PPK Notify payload */
	if (ike->sa.st_seen_ppk) {
		if (!emit_v2N(v2N_USE_PPK, &rbody))
			return STF_INTERNAL_ERROR;
	 }

	/* Send INTERMEDIATE_EXCHANGE_SUPPORTED Notify payload */
	if ((c->policy & POLICY_INTERMEDIATE) && ike->sa.st_seen_intermediate) {
		if (!emit_v2N(v2N_INTERMEDIATE_EXCHANGE_SUPPORTED, &rbody))
			return STF_INTERNAL_ERROR;
		ike->sa.st_intermediate_used = true;
	}

	/* Send SIGNATURE_HASH_ALGORITHMS notification only if we received one */
	if (!impair.ignore_hash_notify_request) {
		if (ike->sa.st_seen_hashnotify && ((c->policy & POLICY_RSASIG) || (c->policy & POLICY_ECDSA))
			&& (c->sighash_policy != LEMPTY)) {
			if (!emit_v2N_signature_hash_algorithms(c->sighash_policy, &rbody))
				return STF_INTERNAL_ERROR;
		}
	} else {
		log_state(RC_LOG, &ike->sa, "Impair: Not sending out signature hash notify");
	}

	/* Send NAT-T Notify payloads */
	if (!ikev2_out_nat_v2n(&rbody, &ike->sa, &ike->sa.st_ike_spis.responder)) {
		return STF_INTERNAL_ERROR;
	}

	/* something the other end won't like */

	/* send CERTREQ */
	if (send_certreq) {
		dbg("going to send a certreq");
		ikev2_send_certreq(&ike->sa, md, &rbody);
	}

	if (c->send_vendorid) {
		if (!emit_v2V(pluto_vendorid, &rbody))
			return STF_INTERNAL_ERROR;
	}

	if (c->fake_strongswan) {
		if (!emit_v2V("strongSwan", &rbody))
			return STF_INTERNAL_ERROR;
	}

	if (c->policy & POLICY_AUTH_NULL) {
		if (!emit_v2V("Opportunistic IPsec", &rbody))
			return STF_INTERNAL_ERROR;
	}

	close_output_pbs(&rbody);
	close_output_pbs(&reply_stream);

	record_v2_message(ike, &reply_stream,
			  "reply packet for IKE_SA_INIT request",
			  MESSAGE_RESPONSE);

	/* save packet for later signing */
	replace_chunk(&ike->sa.st_firstpacket_me,
		clone_out_pbs_as_chunk(&reply_stream, "saved first packet"));

	return STF_OK;
}

/*
 *
 ***************************************************************
 *                       PARENT_inR1                       *****
 ***************************************************************
 *  -
 *
 *
 */
/* STATE_PARENT_I1: R1B --> I1B
 *                     <--  HDR, N
 * HDR, N(COOKIE), SAi1, KEi, Ni -->
 */

static stf_status resubmit_ke_and_nonce(struct ike_sa *ike)
{
	submit_ke_and_nonce(&ike->sa, ike->sa.st_oakley.ta_dh,
			    ikev2_parent_outI1_continue,
			    "rekey outI");
	return STF_SUSPEND;
}

stf_status ikev2_in_IKE_SA_INIT_R_v2N_INVALID_KE_PAYLOAD(struct ike_sa *ike,
							 struct child_sa *child,
							 struct msg_digest *md)
{
	struct connection *c = ike->sa.st_connection;

	pexpect(child == NULL);
	if (!pexpect(md->pd[PD_v2N_INVALID_KE_PAYLOAD] != NULL)) {
		return STF_INTERNAL_ERROR;
	}
	struct pbs_in invalid_ke_pbs = md->pd[PD_v2N_INVALID_KE_PAYLOAD]->pbs;

	/* careful of DDOS, only log with debugging on? */
	/* we treat this as a "retransmit" event to rate limit these */
	if (!count_duplicate(&ike->sa, MAXIMUM_INVALID_KE_RETRANS)) {
		dbg("ignoring received INVALID_KE packets - received too many (DoS?)");
		return STF_IGNORE;
	}

	/*
	 * There's at least this notify payload, is there more than
	 * one?
	 */
	if (md->chain[ISAKMP_NEXT_v2N]->next != NULL) {
		dbg("ignoring other notify payloads");
	}

	struct suggested_group sg;
	diag_t d = pbs_in_struct(&invalid_ke_pbs, &suggested_group_desc,
				 &sg, sizeof(sg), NULL);
	if (d != NULL) {
		llog_diag(RC_LOG, ike->sa.st_logger, &d, "%s", "");
		return STF_IGNORE;
	}

	pstats(invalidke_recv_s, sg.sg_group);
	pstats(invalidke_recv_u, ike->sa.st_oakley.ta_dh->group);

	struct ikev2_proposals *ike_proposals =
		get_v2_ike_proposals(c, "IKE SA initiator validating remote's suggested KE", ike->sa.st_logger);
	if (!ikev2_proposals_include_modp(ike_proposals, sg.sg_group)) {
		esb_buf esb;
		log_state(RC_LOG, &ike->sa,
			  "Discarding unauthenticated INVALID_KE_PAYLOAD response to DH %s; suggested DH %s is not acceptable",
			  ike->sa.st_oakley.ta_dh->common.fqn,
			  enum_show_short(&oakley_group_names,
					  sg.sg_group, &esb));
		return STF_IGNORE;
	}

	dbg("Suggested modp group is acceptable");
	/*
	 * Since there must be a group object for every local
	 * proposal, and sg.sg_group matches one of the local proposal
	 * groups, a lookup of sg.sg_group must succeed.
	 */
	const struct dh_desc *new_group = ikev2_get_dh_desc(sg.sg_group);
	passert(new_group != NULL);
	log_state(RC_LOG, &ike->sa,
		  "Received unauthenticated INVALID_KE_PAYLOAD response to DH %s; resending with suggested DH %s",
		  ike->sa.st_oakley.ta_dh->common.fqn,
		  new_group->common.fqn);
	ike->sa.st_oakley.ta_dh = new_group;
	/* wipe our mismatched KE */
	dh_local_secret_delref(&ike->sa.st_dh_local_secret, HERE);
	/*
	 * get a new KE
	 */
	schedule_reinitiate_v2_ike_sa_init(ike, resubmit_ke_and_nonce);
	return STF_OK;
}

/* STATE_PARENT_I1: R1 --> I2
 *                     <--  HDR, SAr1, KEr, Nr, [CERTREQ]
 * HDR, SK {IDi, [CERT,] [CERTREQ,]
 *      [IDr,] AUTH, SAi2,
 *      TSi, TSr}      -->
 */

static dh_shared_secret_cb ikev2_in_IKE_SA_INIT_R_or_IKE_INTERMEDIATE_R_out_IKE_AUTH_I_continue;	/* forward decl and type assertion */
static dh_shared_secret_cb ikev2_in_IKE_SA_INIT_R_or_IKE_INTERMEDIATE_R_out_IKE_INTERMEDIATE_I_continue;	/* forward decl and type assertion */
static ikev2_state_transition_fn ikev2_in_IKE_SA_INIT_R_or_IKE_INTERMEDIATE_R_out_IKE_AUTH_I_or_IKE_INTERMEDIATE_I;	/* forward decl and type assertion */

/*
 * XXX: there's a lot of code duplication between the IKE_AUTH and
 * IKE_INTERMEDIATE paths.
 */

stf_status ikev2_in_IKE_INTERMEDIATE_R_out_IKE_AUTH_I_or_IKE_INTERMEDIATE_I(struct ike_sa *ike,
									    struct child_sa *child,
									    struct msg_digest *md)
{
	/*
	 * The function below always schedules a dh calculation - even
	 * when it's been peformed earlier (there's something in the
	 * intermediate echange about this?).
	 *
	 * So that things don't pexpect, blow away the old shared secret.
	 */
	dbg("HACK: blow away old shared secret as going to re-compute it");
	release_symkey(__func__, "st_dh_shared_secret", &ike->sa.st_dh_shared_secret);
	return ikev2_in_IKE_SA_INIT_R_or_IKE_INTERMEDIATE_R_out_IKE_AUTH_I_or_IKE_INTERMEDIATE_I(ike, child, md);
}

stf_status ikev2_in_IKE_SA_INIT_R_out_IKE_AUTH_I_or_IKE_INTERMEDIATE_I(struct ike_sa *ike,
								       struct child_sa *child,
								       struct msg_digest *md)
{
	return ikev2_in_IKE_SA_INIT_R_or_IKE_INTERMEDIATE_R_out_IKE_AUTH_I_or_IKE_INTERMEDIATE_I(ike, child, md);
}

stf_status ikev2_in_IKE_SA_INIT_R_or_IKE_INTERMEDIATE_R_out_IKE_AUTH_I_or_IKE_INTERMEDIATE_I(struct ike_sa *ike,
											     struct child_sa *unused_child UNUSED,
											     struct msg_digest *md)
{
	struct connection *c = ike->sa.st_connection;

	/* for testing only */
	if (impair.send_no_ikev2_auth) {
		log_state(RC_LOG, &ike->sa,
			  "IMPAIR_SEND_NO_IKEV2_AUTH set - not sending IKE_AUTH packet");
		return STF_IGNORE;
	}

	/*
	 * if this connection has a newer Child SA than this state
	 * this negotiation is not relevant any more.  would this
	 * cover if there are multiple CREATE_CHILD_SA pending on this
	 * IKE negotiation ???
	 *
	 * XXX: this is testing for an IKE SA that's been superseed by
	 * a newer IKE SA (not child).  Suspect this is to handle a
	 * race where the other end brings up the IKE SA first?  For
	 * that case, shouldn't this state have been deleted?
	 *
	 * NOTE: a larger serialno does not mean superseded. crossed
	 * streams could mean the lower serial established later and is
	 * the "newest". Should > be replaced with !=   ?
	 */
	if (c->newest_ipsec_sa > ike->sa.st_serialno) {
		log_state(RC_LOG, &ike->sa,
			  "state superseded by #%lu try=%lu, drop this negotiation",
			  c->newest_ipsec_sa, ike->sa.st_try);
		return STF_FATAL;
	}
	if (md->hdr.isa_xchg != ISAKMP_v2_IKE_INTERMEDIATE) {
		/*
		* XXX: this iteration over the notifies modifies state
		* _before_ the code's committed to creating an SA.  Hack this
		* by resetting any flags that might be set.
		*/
		ike->sa.st_seen_fragmentation_supported = false;
		ike->sa.st_seen_ppk = false;
		ike->sa.st_seen_intermediate = false;

		ike->sa.st_seen_fragmentation_supported = md->pd[PD_v2N_IKEV2_FRAGMENTATION_SUPPORTED] != NULL;
		ike->sa.st_seen_ppk = md->pd[PD_v2N_USE_PPK] != NULL;
		ike->sa.st_seen_intermediate = md->pd[PD_v2N_INTERMEDIATE_EXCHANGE_SUPPORTED] != NULL;
		if (md->pd[PD_v2N_SIGNATURE_HASH_ALGORITHMS] != NULL) {
			if (impair.ignore_hash_notify_request) {
				log_state(RC_LOG, &ike->sa,
					  "IMPAIR: ignoring the Signature hash notify in IKE_SA_INIT response");
			} else if (!negotiate_hash_algo_from_notification(&md->pd[PD_v2N_SIGNATURE_HASH_ALGORITHMS]->pbs, ike)) {
				return STF_FATAL;
			}
			ike->sa.st_seen_hashnotify = true;
		}

		/*
		* the responder sent us back KE, Gr, Nr, and it's our time to calculate
		* the shared key values.
		*/

		dbg("ikev2 parent inR1: calculating g^{xy} in order to send I2");

		/* KE in */
		if (!unpack_KE(&ike->sa.st_gr, "Gr", ike->sa.st_oakley.ta_dh,
			       md->chain[ISAKMP_NEXT_v2KE], ike->sa.st_logger)) {
			/*
			* XXX: Initiator - so this code will not trigger a
			* notify.  Since packet isn't trusted, should it be
			* ignored?
			*/
			return STF_FAIL + v2N_INVALID_SYNTAX;
		}

		/* Ni in */
		if (!accept_v2_nonce(ike->sa.st_logger, md, &ike->sa.st_nr, "Nr")) {
			/*
			* Presumably not our fault.  Syntax errors in a
			* response kill the family (and trigger no further
			* exchange).
			*/
			return STF_FATAL;
		}

		/* We're missing processing a CERTREQ in here */

		/* process and confirm the SA selected */
		{
			/* SA body in and out */
			struct payload_digest *const sa_pd =
				md->chain[ISAKMP_NEXT_v2SA];
			struct ikev2_proposals *ike_proposals =
				get_v2_ike_proposals(c, "IKE SA initiator accepting remote proposal", ike->sa.st_logger);

			stf_status ret = ikev2_process_sa_payload("IKE initiator (accepting)",
								&sa_pd->pbs,
								/*expect_ike*/ TRUE,
								/*expect_spi*/ FALSE,
								/*expect_accepted*/ TRUE,
								LIN(POLICY_OPPORTUNISTIC, c->policy),
								&ike->sa.st_accepted_ike_proposal,
								ike_proposals, ike->sa.st_logger);
			if (ret != STF_OK) {
				dbg("ikev2_parse_parent_sa_body() failed in ikev2_parent_inR1outI2()");
				return ret; /* initiator; no response */
			}

			if (!ikev2_proposal_to_trans_attrs(ike->sa.st_accepted_ike_proposal,
						   &ike->sa.st_oakley, ike->sa.st_logger)) {
				log_state(RC_LOG_SERIOUS, &ike->sa,
					  "IKE initiator proposed an unsupported algorithm");
				free_ikev2_proposal(&ike->sa.st_accepted_ike_proposal);
				passert(ike->sa.st_accepted_ike_proposal == NULL);
				/*
				* Assume caller et.al. will clean up the
				* reset of the mess?
				*/
				return STF_FAIL;
			}
		}
		replace_chunk(&ike->sa.st_firstpacket_peer,
			clone_out_pbs_as_chunk(&md->message_pbs,
				"saved first received packet in inR1outI2"));

	} else {
		dbg("No KE payload in INTERMEDIATE RESPONSE, not calculating keys, going to AUTH by completing state transition");
	}

	/*
	 * Initiator: check v2N_NAT_DETECTION_DESTINATION_IP or/and
	 * v2N_NAT_DETECTION_SOURCE_IP.
	 *
	 *   2.23.  NAT Traversal
	 *
	 *   The IKE initiator MUST check the NAT_DETECTION_SOURCE_IP
	 *   or NAT_DETECTION_DESTINATION_IP payloads if present, and
	 *   if they do not match the addresses in the outer packet,
	 *   MUST tunnel all future IKE and ESP packets associated
	 *   with this IKE SA over UDP port 4500.
	 *
	 * When detected, float to the NAT port as needed (*ikeport
	 * can't float but already supports NAT).  When the ports
	 * can't support NAT, give up.
	 */

	if (v2_nat_detected(ike, md)) {
		pexpect(ike->sa.hidden_variables.st_nat_traversal & NAT_T_DETECTED);
		if (!v2_natify_initiator_endpoints(ike, HERE)) {
			/* already logged */
			return STF_FATAL;
		}
	}

	/*
	 * Initiate the calculation of g^xy.
	 *
	 * Form and pass in the full SPI[ir] that will eventually be
	 * used by this IKE SA.  Only once DH has been computed and
	 * the SA is secure (but not authenticated) should the state's
	 * IKE SPIr be updated.
	 */

	if (!(md->hdr.isa_xchg == ISAKMP_v2_IKE_INTERMEDIATE)){
		pexpect(ike_spi_is_zero(&ike->sa.st_ike_spis.responder));
	}
	ike->sa.st_ike_rekey_spis = (ike_spis_t) {
		.initiator = ike->sa.st_ike_spis.initiator,
		.responder = md->hdr.isa_ike_responder_spi,
	};

	/* If we seen the intermediate AND we are configured to use intermediate */
	/* for now, do only one Intermediate Exchange round and proceed with IKE_AUTH */
	dh_shared_secret_cb (*pcrc_func) = (ike->sa.st_seen_intermediate && (md->pd[PD_v2N_INTERMEDIATE_EXCHANGE_SUPPORTED] != NULL) && !(md->hdr.isa_xchg == ISAKMP_v2_IKE_INTERMEDIATE)) ?
			ikev2_in_IKE_SA_INIT_R_or_IKE_INTERMEDIATE_R_out_IKE_INTERMEDIATE_I_continue :
		ikev2_in_IKE_SA_INIT_R_or_IKE_INTERMEDIATE_R_out_IKE_AUTH_I_continue;

	submit_dh_shared_secret(&ike->sa, ike->sa.st_gr/*initiator needs responder KE*/,
				pcrc_func, HERE);
	return STF_SUSPEND;
}

static stf_status ikev2_in_IKE_SA_INIT_R_or_IKE_INTERMEDIATE_R_out_IKE_INTERMEDIATE_I_continue(struct state *ike_st,
											       struct msg_digest *mdp)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_st);
	pexpect(ike->sa.st_sa_role == SA_INITIATOR);
	pexpect(v2_msg_role(mdp) == MESSAGE_RESPONSE); /* i.e., MD!=NULL */
	dbg("%s() for #%lu %s: g^{xy} calculated, sending INTERMEDIATE",
	    __func__, ike->sa.st_serialno, ike->sa.st_state->name);

	ike->sa.st_intermediate_used = true;

	if (ike->sa.st_dh_shared_secret == NULL) {
		/*
		 * XXX: this is the initiator so returning a
		 * notification is kind of useless.
		 */
		pstat_sa_failed(&ike->sa, REASON_CRYPTO_FAILED);
		return STF_FAIL;
	}

	calc_v2_keymat(&ike->sa, NULL, NULL, /*previous keymat*/
		       &ike->sa.st_ike_rekey_spis);

	/*
	 * All systems are go.
	 *
	 * Since DH succeeded, a secure (but unauthenticated) SA
	 * (channel) is available.  From this point on, should things
	 * go south, the state needs to be abandoned (but it shouldn't
	 * happen).
	 */

	/*
	 * Since systems are go, start updating the state, starting
	 * with SPIr.
	 */
	rehash_state(&ike->sa, &mdp->hdr.isa_ike_responder_spi);

	/* beginning of data going out */

	/* make sure HDR is at start of a clean buffer */
	struct pbs_out reply_stream = open_pbs_out("reply packet",
						   reply_buffer, sizeof(reply_buffer),
						   ike->sa.st_logger);

	/* HDR out */

	struct pbs_out rbody = open_v2_message(&reply_stream, ike,
					       NULL /* request */,
					       ISAKMP_v2_IKE_INTERMEDIATE);
	if (!pbs_ok(&rbody)) {
		return STF_INTERNAL_ERROR;
	}

	/* insert an Encryption payload header (SK) */

	struct v2SK_payload sk = open_v2SK_payload(ike->sa.st_logger, &rbody, ike);
	if (!pbs_ok(&sk.pbs)) {
		return STF_INTERNAL_ERROR;
	}

	/* send NOTIFY payload */
	if (ike->sa.st_seen_intermediate) {
		if (!emit_v2N(v2N_INTERMEDIATE_EXCHANGE_SUPPORTED, &sk.pbs))
			return STF_INTERNAL_ERROR;
	}

	if (!close_v2SK_payload(&sk)) {
		return STF_INTERNAL_ERROR;
	}
	close_output_pbs(&rbody);
	close_output_pbs(&reply_stream);

	stf_status ret = encrypt_v2SK_payload(&sk);

	if (ret != STF_OK) {
		return ret;
	}

	record_v2_message(ike, &reply_stream, "reply packet for intermediate exchange",
				  MESSAGE_REQUEST);
	return STF_OK;
}

bool need_configuration_payload(const struct connection *const pc,
				const lset_t st_nat_traversal)
{
	return (pc->spd.this.modecfg_client &&
		(!pc->spd.this.cat || LHAS(st_nat_traversal, NATED_HOST)));
}

struct crypt_mac v2_hash_id_payload(const char *id_name, struct ike_sa *ike,
					   const char *key_name, PK11SymKey *key)
{
	/*
	 * InitiatorIDPayload = PayloadHeader | RestOfInitIDPayload
	 * RestOfInitIDPayload = IDType | RESERVED | InitIDData
	 * MACedIDForR = prf(SK_pr, RestOfInitIDPayload)
	 */
	struct crypt_prf *id_ctx = crypt_prf_init_symkey(id_name, ike->sa.st_oakley.ta_prf,
							 key_name, key, ike->sa.st_logger);
	/* skip PayloadHeader; hash: IDType | RESERVED */
	crypt_prf_update_bytes(id_ctx, "IDType", &ike->sa.st_v2_id_payload.header.isai_type,
				sizeof(ike->sa.st_v2_id_payload.header.isai_type));
	/* note that res1+res2 is 3 zero bytes */
	crypt_prf_update_byte(id_ctx, "RESERVED 1", ike->sa.st_v2_id_payload.header.isai_res1);
	crypt_prf_update_byte(id_ctx, "RESERVED 2", ike->sa.st_v2_id_payload.header.isai_res2);
	crypt_prf_update_byte(id_ctx, "RESERVED 3", ike->sa.st_v2_id_payload.header.isai_res3);
	/* hash: InitIDData */
	crypt_prf_update_hunk(id_ctx, "InitIDData", ike->sa.st_v2_id_payload.data);
	return crypt_prf_final_mac(&id_ctx, NULL/*no-truncation*/);
}

struct crypt_mac v2_id_hash(struct ike_sa *ike, const char *why,
			    const char *id_name, shunk_t id_payload,
			    const char *key_name, PK11SymKey *key)
{
	const uint8_t *id_start = id_payload.ptr;
	size_t id_size = id_payload.len;
	/* HASH of ID is not done over common header */
	id_start += NSIZEOF_isakmp_generic;
	id_size -= NSIZEOF_isakmp_generic;
	struct crypt_prf *id_ctx = crypt_prf_init_symkey(why, ike->sa.st_oakley.ta_prf,
							 key_name, key, ike->sa.st_logger);
	crypt_prf_update_bytes(id_ctx, id_name, id_start, id_size);
	return crypt_prf_final_mac(&id_ctx, NULL/*no-truncation*/);
}

static stf_status ikev2_in_IKE_SA_INIT_R_or_IKE_INTERMEDIATE_R_out_IKE_AUTH_I_signature_continue(struct ike_sa *ike,
												 struct msg_digest *md,
												 const struct hash_signature *sig);


static stf_status ikev2_in_IKE_SA_INIT_R_or_IKE_INTERMEDIATE_R_out_IKE_AUTH_I_continue(struct state *ike_st,
										       struct msg_digest *md)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_st);
	pexpect(ike->sa.st_sa_role == SA_INITIATOR);
	pexpect(v2_msg_role(md) == MESSAGE_RESPONSE); /* i.e., MD!=NULL */
	dbg("%s() for #%lu %s: g^{xy} calculated, sending IKE_AUTH",
	    __func__, ike->sa.st_serialno, ike->sa.st_state->name);

	struct connection *const pc = ike->sa.st_connection;	/* parent connection */

	if (!(md->hdr.isa_xchg == ISAKMP_v2_IKE_INTERMEDIATE)) {
		if (ike->sa.st_dh_shared_secret == NULL) {
			/*
			* XXX: this is the initiator so returning a
			* notification is kind of useless.
			*/
			pstat_sa_failed(&ike->sa, REASON_CRYPTO_FAILED);
			return STF_FAIL;
		}
		calc_v2_keymat(&ike->sa, NULL, NULL, /*no old keymat*/
			       &ike->sa.st_ike_rekey_spis);
	}

	/*
	 * All systems are go.
	 *
	 * Since DH succeeded, a secure (but unauthenticated) SA
	 * (channel) is available.  From this point on, should things
	 * go south, the state needs to be abandoned (but it shouldn't
	 * happen).
	 */

	/*
	 * Since systems are go, start updating the state, starting
	 * with SPIr.
	 */
	rehash_state(&ike->sa, &md->hdr.isa_ike_responder_spi);

	/*
	 * If we and responder are willing to use a PPK, we need to
	 * generate NO_PPK_AUTH as well as PPK-based AUTH payload.
	 *
	 * Stash the no-ppk keys in st_skey_*_no_ppk, and then
	 * scramble the st_skey_* keys with PPK.
	 */
	if (LIN(POLICY_PPK_ALLOW, pc->policy) && ike->sa.st_seen_ppk) {
		chunk_t *ppk_id;
		chunk_t *ppk = get_connection_ppk(ike->sa.st_connection, &ppk_id);

		if (ppk != NULL) {
			dbg("found PPK and PPK_ID for our connection");

			pexpect(ike->sa.st_sk_d_no_ppk == NULL);
			ike->sa.st_sk_d_no_ppk = reference_symkey(__func__, "sk_d_no_ppk", ike->sa.st_skey_d_nss);

			pexpect(ike->sa.st_sk_pi_no_ppk == NULL);
			ike->sa.st_sk_pi_no_ppk = reference_symkey(__func__, "sk_pi_no_ppk", ike->sa.st_skey_pi_nss);

			pexpect(ike->sa.st_sk_pr_no_ppk == NULL);
			ike->sa.st_sk_pr_no_ppk = reference_symkey(__func__, "sk_pr_no_ppk", ike->sa.st_skey_pr_nss);

			ppk_recalculate(ppk, ike->sa.st_oakley.ta_prf,
					&ike->sa.st_skey_d_nss,
					&ike->sa.st_skey_pi_nss,
					&ike->sa.st_skey_pr_nss,
					ike->sa.st_logger);
			log_state(RC_LOG, &ike->sa,
				  "PPK AUTH calculated as initiator");
		} else {
			if (pc->policy & POLICY_PPK_INSIST) {
				log_state(RC_LOG_SERIOUS, &ike->sa,
					  "connection requires PPK, but we didn't find one");
				return STF_FATAL;
			} else {
				log_state(RC_LOG, &ike->sa,
					  "failed to find PPK and PPK_ID, continuing without PPK");
				/* we should omit sending any PPK Identity, so we pretend we didn't see USE_PPK */
				ike->sa.st_seen_ppk = FALSE;
			}
		}
	}

	/*
	 * Construct the IDi payload and store it in state so that it
	 * can be emitted later.  Then use that to construct the
	 * "MACedIDFor[I]".
	 *
	 * Code assumes that struct ikev2_id's "IDType|RESERVED" is
	 * laid out the same as the packet.
	 */

	{
		shunk_t data;
		ike->sa.st_v2_id_payload.header = build_v2_id_payload(&pc->spd.this, &data,
								      "my IDi", ike->sa.st_logger);
		ike->sa.st_v2_id_payload.data = clone_hunk(data, "my IDi");
	}

	ike->sa.st_v2_id_payload.mac = v2_hash_id_payload("IDi", ike,
							  "st_skey_pi_nss",
							  ike->sa.st_skey_pi_nss);
	if (ike->sa.st_seen_ppk && !LIN(POLICY_PPK_INSIST, pc->policy)) {
		/* ID payload that we've build is the same */
		ike->sa.st_v2_id_payload.mac_no_ppk_auth =
			v2_hash_id_payload("IDi (no-PPK)", ike,
					   "sk_pi_no_pkk",
					   ike->sa.st_sk_pi_no_ppk);
	}

	{
		enum keyword_authby authby = v2_auth_by(ike);
		enum ikev2_auth_method auth_method = v2_auth_method(ike, authby);
		switch (auth_method) {
		case IKEv2_AUTH_RSA:
		{
			const struct hash_desc *hash_algo = &ike_alg_hash_sha1;
			struct crypt_mac hash_to_sign =
				v2_calculate_sighash(ike, &ike->sa.st_v2_id_payload.mac,
						     hash_algo, LOCAL_PERSPECTIVE);
			if (!submit_v2_auth_signature(ike, &hash_to_sign, hash_algo,
						      authby, auth_method,
						      ikev2_in_IKE_SA_INIT_R_or_IKE_INTERMEDIATE_R_out_IKE_AUTH_I_signature_continue)) {
				dbg("submit_v2_auth_signature() died, fatal");
				return STF_FATAL;
			}
			return STF_SUSPEND;
		}
		case IKEv2_AUTH_DIGSIG:
		{
			const struct hash_desc *hash_algo = v2_auth_negotiated_signature_hash(ike);
			if (hash_algo == NULL) {
				return STF_FATAL;
			}
			struct crypt_mac hash_to_sign =
				v2_calculate_sighash(ike, &ike->sa.st_v2_id_payload.mac,
						     hash_algo, LOCAL_PERSPECTIVE);
			if (!submit_v2_auth_signature(ike, &hash_to_sign, hash_algo,
						      authby, auth_method,
						      ikev2_in_IKE_SA_INIT_R_or_IKE_INTERMEDIATE_R_out_IKE_AUTH_I_signature_continue)) {
				dbg("submit_v2_auth_signature() died, fatal");
				return STF_FATAL;
			}
			return STF_SUSPEND;
		}
		case IKEv2_AUTH_PSK:
		case IKEv2_AUTH_NULL:
		{
			struct hash_signature sig = { .len = 0, };
			return ikev2_in_IKE_SA_INIT_R_or_IKE_INTERMEDIATE_R_out_IKE_AUTH_I_signature_continue(ike, md, &sig);
		}
		default:
			log_state(RC_LOG, &ike->sa,
				  "authentication method %s not supported",
				  enum_name(&ikev2_auth_names, auth_method));
			return STF_FATAL;
		}
	}
}

static stf_status ikev2_in_IKE_SA_INIT_R_or_IKE_INTERMEDIATE_R_out_IKE_AUTH_I_signature_continue(struct ike_sa *ike,
												 struct msg_digest *md,
												 const struct hash_signature *auth_sig)
{
	struct connection *const pc = ike->sa.st_connection;	/* parent connection */
	ikev2_log_parentSA(&ike->sa);

	/*
	 * XXX:
	 *
	 * Should this code use clone_in_pbs_as_chunk() which uses
	 * pbs_room() (.roof-.start)?  The original code:
	 *
	 * 	clonetochunk(st->st_firstpacket_peer, md->message_pbs.start,
	 *		     pbs_offset(&md->message_pbs),
	 *		     "saved first received packet");
	 *
	 * and clone_out_pbs_as_chunk() both use pbs_offset()
	 * (.cur-.start).
	 *
	 * Suspect it doesn't matter as the code initializing
	 * .message_pbs forces .roof==.cur - look for the comment
	 * "trim padding (not actually legit)".
	 */
	/* record first packet for later checking of signature */
	if (md->hdr.isa_xchg != ISAKMP_v2_IKE_INTERMEDIATE) {
		replace_chunk(&ike->sa.st_firstpacket_peer,
			clone_out_pbs_as_chunk(&md->message_pbs, "saved first received non-intermediate packet"));
	}
	/* beginning of data going out */

	/* make sure HDR is at start of a clean buffer */
	struct pbs_out reply_stream = open_pbs_out("reply packet",
						   reply_buffer, sizeof(reply_buffer),
						   ike->sa.st_logger);

	/* HDR out */

	struct pbs_out rbody = open_v2_message(&reply_stream, ike,
					       NULL /* request */,
					       ISAKMP_v2_IKE_AUTH);
	if (!pbs_ok(&rbody)) {
		return STF_INTERNAL_ERROR;
	}

	/* insert an Encryption payload header (SK) */

	struct v2SK_payload sk = open_v2SK_payload(ike->sa.st_logger, &rbody, ike);
	if (!pbs_ok(&sk.pbs)) {
		return STF_INTERNAL_ERROR;
	}

	/* actual data */

	/* decide whether to send CERT payload */

	bool send_cert = ikev2_send_cert_decision(ike);
	bool ic =  pc->initial_contact && (ike->sa.st_ike_pred == SOS_NOBODY);
	bool send_idr = ((pc->spd.that.id.kind != ID_NULL && pc->spd.that.id.name.len != 0) ||
				pc->spd.that.id.kind == ID_NULL); /* me tarzan, you jane */

	if (impair.send_no_idr) {
		log_state(RC_LOG, &ike->sa, "IMPAIR: omitting IDr payload");
		send_idr = false;
	}

	dbg("IDr payload will %sbe sent", send_idr ? "" : "NOT ");

	/* send out the IDi payload */

	{
		pb_stream i_id_pbs;
		if (!out_struct(&ike->sa.st_v2_id_payload.header,
				&ikev2_id_i_desc,
				&sk.pbs,
				&i_id_pbs) ||
		    !out_hunk(ike->sa.st_v2_id_payload.data, &i_id_pbs, "my identity"))
			return STF_INTERNAL_ERROR;
		close_output_pbs(&i_id_pbs);
	}

	if (impair.add_unknown_v2_payload_to_sk == ISAKMP_v2_IKE_AUTH) {
		if (!emit_v2UNKNOWN("SK request",
				    impair.add_unknown_v2_payload_to_sk,
				    &sk.pbs)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* send [CERT,] payload RFC 4306 3.6, 1.2) */
	if (send_cert) {
		stf_status certstat = ikev2_send_cert(ike->sa.st_connection, &sk.pbs);
		if (certstat != STF_OK)
			return certstat;

		/* send CERTREQ */
		bool send_certreq = ikev2_send_certreq_INIT_decision(&ike->sa, SA_INITIATOR);
		if (send_certreq) {
			if (DBGP(DBG_BASE)) {
				dn_buf buf;
				DBG_log("Sending [CERTREQ] of %s",
					str_dn(ike->sa.st_connection->spd.that.ca, &buf));
			}
			ikev2_send_certreq(&ike->sa, md, &sk.pbs);
		}
	}

	/* you Tarzan, me Jane support */
	if (send_idr) {
		switch (pc->spd.that.id.kind) {
		case ID_DER_ASN1_DN:
		case ID_FQDN:
		case ID_USER_FQDN:
		case ID_KEY_ID:
		case ID_NULL:
		{
			shunk_t id_b;
			struct ikev2_id r_id = build_v2_id_payload(&pc->spd.that, &id_b,
								   "their IDr",
								   ike->sa.st_logger);
			pb_stream r_id_pbs;
			if (!out_struct(&r_id, &ikev2_id_r_desc, &sk.pbs,
				&r_id_pbs) ||
			    !out_hunk(id_b, &r_id_pbs, "their IDr"))
				return STF_INTERNAL_ERROR;

			close_output_pbs(&r_id_pbs);
			break;
		}
		default:
		{
			esb_buf b;
			dbg("Not sending IDr payload for remote ID type %s",
			    enum_show(&ike_id_type_names, pc->spd.that.id.kind, &b));
			break;
		}
		}
	}

	if (ic) {
		log_state(RC_LOG, &ike->sa, "sending INITIAL_CONTACT");
		if (!emit_v2N(v2N_INITIAL_CONTACT, &sk.pbs))
			return STF_INTERNAL_ERROR;
	} else {
		dbg("not sending INITIAL_CONTACT");
	}

	/* send out the AUTH payload */

	if (!emit_v2_auth(ike, auth_sig, &ike->sa.st_v2_id_payload.mac, &sk.pbs)) {
		return STF_INTERNAL_ERROR;
	}

	/*
	 * Now that the AUTH payload is done(?), create and emit the
	 * child using the first pending connection (or the IKE SA's
	 * connection) if there isn't one.
	 *
	 * Then emit SA2i, TSi and TSr and NOTIFY payloads related to
	 * the IPsec SA.
	 */

	/* Child Connection */
	lset_t unused_policy = pc->policy; /* unused */
	struct fd *child_whackfd = null_fd; /* must-free */
	struct connection *cc = first_pending(ike, &unused_policy, &child_whackfd);
	if (cc == NULL) {
		llog_sa(RC_LOG, ike, "omitting CHILD SA payloads");
	} else {
		/*
		 * XXX: The problem isn't so much that the child state is
		 * created - it provides somewhere to store all the child's
		 * state - but that things switch to the child before the IKE
		 * SA is finished.  Consequently, code is forced to switch
		 * back to the IKE SA.
		 */
		struct child_sa *child = new_v2_child_state(cc, ike, IPSEC_SA,
							    SA_INITIATOR,
							    STATE_V2_IKE_AUTH_CHILD_I0,
							    child_whackfd);
		close_any(&child_whackfd);
		ike->sa.st_v2_larval_initiator_sa = child;

		/* XXX because the early child state ends up with the try counter check, we need to copy it */
		/* XXX: huh?!? */
		child->sa.st_try = ike->sa.st_try;

		if (cc != pc) {
			/* lie */
			connection_buf cib;
			log_state(RC_LOG, &ike->sa,
				  "switching CHILD #%lu to pending connection "PRI_CONNECTION,
				  child->sa.st_serialno, pri_connection(cc, &cib));
		}

		if (need_configuration_payload(pc, ike->sa.hidden_variables.st_nat_traversal)) {
			if (!emit_v2_child_configuration_payload(child, &sk.pbs)) {
				return STF_INTERNAL_ERROR;
			}
		}

		/* code does not support AH+ESP, which not recommended as per RFC 8247 */
		struct ipsec_proto_info *proto_info = ikev2_child_sa_proto_info(child, cc->policy);
		proto_info->our_spi = ikev2_child_sa_spi(&cc->spd, cc->policy, child->sa.st_logger);
		const chunk_t local_spi = THING_AS_CHUNK(proto_info->our_spi);

		/*
		 * A CHILD_SA established during an AUTH exchange does
		 * not propose DH - the IKE SA's SKEYSEED is always
		 * used.
		 */
		struct ikev2_proposals *child_proposals =
			get_v2_ike_auth_child_proposals(cc, "IKE SA initiator emitting ESP/AH proposals",
							child->sa.st_logger);
		if (!ikev2_emit_sa_proposals(&sk.pbs, child_proposals, &local_spi)) {
			return STF_INTERNAL_ERROR;
		}

		child->sa.st_ts_this = ikev2_end_to_ts(&cc->spd.this, child);
		child->sa.st_ts_that = ikev2_end_to_ts(&cc->spd.that, child);

		v2_emit_ts_payloads(child, &sk.pbs, cc);

		if ((cc->policy & POLICY_TUNNEL) == LEMPTY) {
			dbg("Initiator child policy is transport mode, sending v2N_USE_TRANSPORT_MODE");
			/* In v2, for parent, protoid must be 0 and SPI must be empty */
			if (!emit_v2N(v2N_USE_TRANSPORT_MODE, &sk.pbs)) {
				return STF_INTERNAL_ERROR;
			}
		} else {
			dbg("Initiator child policy is tunnel mode, NOT sending v2N_USE_TRANSPORT_MODE");
		}

		/*
		 * Propose IPCOMP based on policy.
		 */
		if (cc->policy & POLICY_COMPRESS) {
			if (!emit_v2N_ipcomp_supported(child, &sk.pbs)) {
				return STF_INTERNAL_ERROR;
			}
		}

		if (cc->send_no_esp_tfc) {
			if (!emit_v2N(v2N_ESP_TFC_PADDING_NOT_SUPPORTED, &sk.pbs)) {
				return STF_INTERNAL_ERROR;
			}
		}

		if (LIN(POLICY_MOBIKE, cc->policy)) {
			ike->sa.st_ike_sent_v2n_mobike_supported = true;
			if (!emit_v2N(v2N_MOBIKE_SUPPORTED, &sk.pbs)) {
				return STF_INTERNAL_ERROR;
			}
		}

		/* send CP payloads */
		if (cc->modecfg_domains != NULL || cc->modecfg_dns != NULL) {
			if (!emit_v2_child_configuration_payload(child, &sk.pbs)) {
				return STF_INTERNAL_ERROR;
			}
		}
	}

	/*
	 * If we and responder are willing to use a PPK, we need to
	 * generate NO_PPK_AUTH as well as PPK-based AUTH payload
	 */
	if (ike->sa.st_seen_ppk) {
		chunk_t *ppk_id;
		get_connection_ppk(ike->sa.st_connection, &ppk_id);
		struct ppk_id_payload ppk_id_p = { .type = 0, };
		create_ppk_id_payload(ppk_id, &ppk_id_p);
		if (DBGP(DBG_BASE)) {
			DBG_log("ppk type: %d", (int) ppk_id_p.type);
			DBG_dump_hunk("ppk_id from payload:", ppk_id_p.ppk_id);
		}

		pb_stream ppks;
		if (!emit_v2Npl(v2N_PPK_IDENTITY, &sk.pbs, &ppks) ||
		    !emit_unified_ppk_id(&ppk_id_p, &ppks)) {
			return STF_INTERNAL_ERROR;
		}
		close_output_pbs(&ppks);

		if (!LIN(POLICY_PPK_INSIST, cc->policy)) {
			if (!ikev2_calc_no_ppk_auth(ike, &ike->sa.st_v2_id_payload.mac_no_ppk_auth,
						    &ike->sa.st_no_ppk_auth)) {
				dbg("ikev2_calc_no_ppk_auth() failed dying");
				return STF_FATAL;
			}

			if (!emit_v2N_hunk(v2N_NO_PPK_AUTH,
					   ike->sa.st_no_ppk_auth, &sk.pbs)) {
				return STF_INTERNAL_ERROR;
			}
		}
	}

	/*
	 * The initiator:
	 *
	 * We sent normal IKEv2_AUTH_RSA but if the policy also allows
	 * AUTH_NULL, we will send a Notify with NULL_AUTH in separate
	 * chunk. This is only done on the initiator in IKE_AUTH, and
	 * not repeated in rekeys.
	 */
	if (v2_auth_by(ike) == AUTHBY_RSASIG && pc->policy & POLICY_AUTH_NULL) {
		/* store in null_auth */
		chunk_t null_auth = NULL_HUNK;
		if (!ikev2_create_psk_auth(AUTHBY_NULL, ike,
					   &ike->sa.st_v2_id_payload.mac,
					   &null_auth)) {
			log_state(RC_LOG_SERIOUS, &ike->sa,
				  "Failed to calculate additional NULL_AUTH");
			return STF_FATAL;
		}
		ike->sa.st_intermediate_used = false;
		if (!emit_v2N_hunk(v2N_NULL_AUTH, null_auth, &sk.pbs)) {
			free_chunk_content(&null_auth);
			return STF_INTERNAL_ERROR;
		}
		free_chunk_content(&null_auth);
	}

	if (!close_v2SK_payload(&sk)) {
		return STF_INTERNAL_ERROR;
	}
	close_output_pbs(&rbody);
	close_output_pbs(&reply_stream);

	/*
	 * For AUTH exchange, store the message in the IKE SA.  The
	 * attempt to create the CHILD SA could have failed.
	 */
	return record_v2SK_message(&reply_stream, &sk,
				   "sending IKE_AUTH request",
				   MESSAGE_REQUEST);
}

void ikev2_rekey_expire_pred(const struct state *st, so_serial_t pred)
{
	struct state *rst = state_with_serialno(pred);
	deltatime_t lifetime = deltatime(0); /* .lt. EXPIRE_OLD_SA_DELAY */

	if (rst != NULL && IS_V2_ESTABLISHED(rst->st_state)) {
		/* on initiator, delete st_ipsec_pred. The responder should not */
		monotime_t now = mononow();
		const struct pluto_event *ev = rst->st_event;

		if (ev != NULL)
			lifetime = monotimediff(ev->ev_time, now);
	}

	deltatime_buf lb;
	log_state(RC_LOG, st, "rekeyed #%lu %s %s remaining life %ss", pred,
		  st->st_state->name,
		  rst == NULL ? "and the state is gone" : "and expire it",
		  str_deltatime(lifetime, &lb));

	/*
	 * ??? added pexpect to avoid NULL dereference.
	 * Why do we test this three times?  Should it not be done once and for all?
	 */
	if (pexpect(rst != NULL) && deltatime_cmp(lifetime, >, EXPIRE_OLD_SA_DELAY)) {
		delete_event(rst);
		event_schedule(EVENT_SA_EXPIRE, EXPIRE_OLD_SA_DELAY, rst);
	}
	/* else it should be on its way to expire no need to kick dead state */
}

/*
 * For opportunistic IPsec, we want to delete idle connections, so we
 * are not gaining an infinite amount of unused IPsec SAs.
 *
 * NOTE: Soon we will accept an idletime= configuration option that
 * replaces this check.
 *
 * Only replace the SA when it's been in use (checking for in-use is a
 * separate operation).
 */

static bool expire_ike_because_child_not_used(struct state *st)
{
	if (!(IS_PARENT_SA_ESTABLISHED(st) ||
	      IS_CHILD_SA_ESTABLISHED(st))) {
		/* for instance, too many retransmits trigger replace */
		return false;
	}

	struct connection *c = st->st_connection;

	if (!(c->policy & POLICY_OPPORTUNISTIC)) {
		/* killing idle IPsec SA's is only for opportunistic SA's */
		return false;
	}

	if (c->spd.that.has_lease) {
		pexpect_fail(st->st_logger, HERE,
			     "#%lu has lease; should not be trying to replace",
			     st->st_serialno);
		return true;
	}

	/* see of (most recent) child is busy */
	struct state *cst;
	struct ike_sa *ike;
	if (IS_IKE_SA(st)) {
		ike = pexpect_ike_sa(st);
		cst = state_with_serialno(c->newest_ipsec_sa);
		if (cst == NULL) {
			pexpect_fail(st->st_logger, HERE,
				     "can't check usage as IKE SA #%lu has no newest child",
				     ike->sa.st_serialno);
			return true;
		}
	} else {
		cst = st;
		ike = ike_sa(st, HERE);
	}

	dbg("#%lu check last used on newest CHILD SA #%lu",
	    ike->sa.st_serialno, cst->st_serialno);

	/* not sure why idleness is set to rekey margin? */
	if (was_eroute_idle(cst, c->sa_rekey_margin)) {
		/* we observed no traffic, let IPSEC SA and IKE SA expire */
		dbg("expiring IKE SA #%lu as CHILD SA #%lu has been idle for more than %jds",
		    ike->sa.st_serialno,
		    ike->sa.st_serialno,
		    deltasecs(c->sa_rekey_margin));
		return true;
	}
	return false;
}

void v2_schedule_replace_event(struct state *st)
{
	struct connection *c = st->st_connection;

	/* unwrapped deltatime_t in seconds */
	intmax_t delay = deltasecs(IS_IKE_SA(st) ? c->sa_ike_life_seconds
				   : c->sa_ipsec_life_seconds);
	st->st_replace_by = monotime_add(mononow(), deltatime(delay));

	/*
	 * Important policy lies buried here.  For example, we favour
	 * the initiator over the responder by making the initiator
	 * start rekeying sooner.  Also, fuzz is only added to the
	 * initiator's margin.
	 */

	enum event_type kind;
	const char *story;
	intmax_t marg;
	if ((c->policy & POLICY_OPPORTUNISTIC) &&
	    st->st_connection->spd.that.has_lease) {
		marg = 0;
		kind = EVENT_SA_EXPIRE;
		story = "always expire opportunistic SA with lease";
	} else if (c->policy & POLICY_DONT_REKEY) {
		marg = 0;
		kind = EVENT_SA_EXPIRE;
		story = "policy doesn't allow re-key";
	} else if (IS_IKE_SA(st) && LIN(POLICY_REAUTH, st->st_connection->policy)) {
		marg = 0;
		kind = EVENT_SA_REPLACE;
		story = "IKE SA with policy re-authenticate";
	} else {
		/* unwrapped deltatime_t in seconds */
		marg = deltasecs(c->sa_rekey_margin);

		switch (st->st_sa_role) {
		case SA_INITIATOR:
			marg += marg *
				c->sa_rekey_fuzz / 100.E0 *
				(rand() / (RAND_MAX + 1.E0));
			break;
		case SA_RESPONDER:
			marg /= 2;
			break;
		default:
			bad_case(st->st_sa_role);
		}

		if (delay > marg) {
			delay -= marg;
			kind = EVENT_SA_REKEY;
			story = "attempting re-key";
		} else {
			marg = 0;
			kind = EVENT_SA_REPLACE;
			story = "margin to small for re-key";
		}
	}

	st->st_replace_margin = deltatime(marg);
	if (marg > 0) {
		passert(kind == EVENT_SA_REKEY);
		dbg("#%lu will start re-keying in %jd seconds with margin of %jd seconds (%s)",
		    st->st_serialno, delay, marg, story);
	} else {
		passert(kind == EVENT_SA_REPLACE || kind == EVENT_SA_EXPIRE);
		dbg("#%lu will %s in %jd seconds (%s)",
		    st->st_serialno,
		    kind == EVENT_SA_EXPIRE ? "expire" : "be replaced",
		    delay, story);
	}

	delete_event(st);
	event_schedule(kind, deltatime(delay), st);
}

void v2_event_sa_rekey(struct state *st)
{
	monotime_t now = mononow();
	const char *satype = IS_IKE_SA(st) ? "IKE" : "CHILD";

	so_serial_t newer_sa = get_newer_sa_from_connection(st);
	if (newer_sa != SOS_NOBODY) {
		/* implies a double re-key? */
		pexpect_fail(st->st_logger, HERE,
			     "not replacing stale %s SA #%lu; as already got a newer #%lu",
			     satype, st->st_serialno, newer_sa);
		event_force(EVENT_SA_EXPIRE, st);
		return;
	}

	if (expire_ike_because_child_not_used(st)) {
		struct ike_sa *ike = ike_sa(st, HERE);
		event_force(EVENT_SA_EXPIRE, &ike->sa);
		return;
	}

	if (monobefore(st->st_replace_by, now)) {
		dbg("#%lu has no time to re-key, will replace",
		    st->st_serialno);
		event_force(EVENT_SA_REPLACE, st);
	}

	dbg("rekeying stale %s SA with logger "PRI_LOGGER, satype, pri_logger(st->st_logger));
	if (IS_IKE_SA(st)) {
		log_state(RC_LOG, st, "initiate rekey of IKEv2 CREATE_CHILD_SA IKE Rekey");
		ikev2_rekey_ike_start(pexpect_ike_sa(st));
	} else {
		/*
		 * XXX: Don't be fooled, ipsecdoi_replace() is magic -
		 * if the old state still exists it morphs things into
		 * a child re-key.
		 */
		ipsecdoi_replace(st, 1);
	}
	/*
	 * Should the rekey go into the weeds this replace will kick
	 * in.
	 *
	 * XXX: should the next event be SA_EXPIRE instead of
	 * SA_REPLACE?  For an IKE SA it breaks ikev2-32-nat-rw-rekey.
	 * For a CHILD SA perhaps - there is a mystery around what
	 * happens to the new child if the old one disappears.
	 */
	dbg("scheduling drop-dead replace event for #%lu", st->st_serialno);
	event_delete(EVENT_v2_LIVENESS, st);
	event_schedule(EVENT_SA_REPLACE, monotimediff(st->st_replace_by, now), st);
}

void v2_event_sa_replace(struct state *st)
{
	const char *satype = IS_IKE_SA(st) ? "IKE" : "CHILD";

	so_serial_t newer_sa = get_newer_sa_from_connection(st);
	if (newer_sa != SOS_NOBODY) {
		/*
		 * For some reason the rekey, above, hasn't completed.
		 * For an IKE SA blow away the entire family
		 * (including the in-progress rekey).  For a CHILD SA
		 * this will delete the old SA but leave the rekey
		 * alone.  Confusing.
		 */
		if (IS_IKE_SA(st)) {
			dbg("replacing entire stale IKE SA #%lu family; rekey #%lu will be deleted",
			    st->st_serialno, newer_sa);
			ipsecdoi_replace(st, 1);
		} else {
			dbg("expiring stale CHILD SA #%lu; newer #%lu will replace?",
			    st->st_serialno, newer_sa);
		}
		/* XXX: are these calls needed? it's about to die */
		event_delete(EVENT_v2_LIVENESS, st);
		event_force(EVENT_SA_EXPIRE, st);
		return;
	}

	if (expire_ike_because_child_not_used(st)) {
		struct ike_sa *ike = ike_sa(st, HERE);
		event_force(EVENT_SA_EXPIRE, &ike->sa);
		return;
	}

	/*
	 * XXX: For a CHILD SA, will this result in a re-key attempt?
	 */
	dbg("replacing stale %s SA", satype);
	ipsecdoi_replace(st, 1);
	event_delete(EVENT_v2_LIVENESS, st);
	event_force(EVENT_SA_EXPIRE, st);
}

/*
 * an ISAKMP SA has been established.
 * Note the serial number, and release any connections with
 * the same peer ID but different peer IP address.
 *
 * Called by IKEv1 and IKEv2 when the IKE SA is established.
 * It checks if the freshly established connection needs is
 * replacing an established version of itself.
 *
 * The use of uniqueIDs is mostly historic and might be removed
 * in a future version. It is ignored for PSK based connections,
 * which only act based on being a "server using PSK".
 *
 * IKEv1 code does not send or process INITIAL_CONTACT
 * IKEv2 codes does so we take it into account.
 */

void IKE_SA_established(const struct ike_sa *ike)
{
	struct connection *c = ike->sa.st_connection;
	bool authnull = (LIN(POLICY_AUTH_NULL, c->policy) || c->spd.that.authby == AUTHBY_NULL);

	if (c->spd.this.xauth_server && LIN(POLICY_PSK, c->policy)) {
		/*
		 * If we are a server and use PSK, all clients use the same group ID
		 * Note that "xauth_server" also refers to IKEv2 CP
		 */
		dbg("We are a server using PSK and clients are using a group ID");
	} else if (!uniqueIDs) {
		dbg("uniqueIDs disabled, not contemplating releasing older self");
	} else {
		/*
		 * for all existing connections: if the same Phase 1 IDs are used,
		 * unorient the (old) connection (if different from current connection)
		 * Only do this for connections with the same name (can be shared ike sa)
		 */
		dbg("FOR_EACH_CONNECTION_... in %s", __func__);
		for (struct connection *d = connections; d != NULL; ) {
			/* might move underneath us */
			struct connection *next = d->ac_next;

			/* if old IKE SA is same as new IKE sa and non-auth isn't overwrting auth */
			if (c != d && c->kind == d->kind && streq(c->name, d->name) &&
			    same_id(&c->spd.this.id, &d->spd.this.id) &&
			    same_id(&c->spd.that.id, &d->spd.that.id))
			{
				bool old_is_nullauth = (LIN(POLICY_AUTH_NULL, d->policy) || d->spd.that.authby == AUTHBY_NULL);
				bool same_remote_ip = sameaddr(&c->spd.that.host_addr, &d->spd.that.host_addr);

				if (same_remote_ip && (!old_is_nullauth && authnull)) {
					log_state(RC_LOG, &ike->sa, "cannot replace old authenticated connection with authnull connection");
				} else if (!same_remote_ip && old_is_nullauth && authnull) {
					log_state(RC_LOG, &ike->sa, "NULL auth ID for different IP's cannot replace each other");
				} else {
					dbg("unorienting old connection with same IDs");
					/*
					 * When replacing an old
					 * existing connection,
					 * suppress sending delete
					 * notify
					 */
					suppress_delete_notify(ike, "ISAKMP", d->newest_ike_sa);
					suppress_delete_notify(ike, "IKE", d->newest_ipsec_sa);
					/*
					 * XXX: Assume this call
					 * doesn't want to log to
					 * whack?  Even though the IKE
					 * SA may have whack attached,
					 * don't transfer it to the
					 * old connection.
					 */
					if (d->kind == CK_INSTANCE) {
						delete_connection(&d, /*relations?*/false);
					} else {
						release_connection(d, /*relations?*/false); /* this deletes the states */
					}
				}
			}
			d = next;
		}

		/*
		 * This only affects IKEv2, since we don't store any
		 * received INITIAL_CONTACT for IKEv1.
		 * We don't do this on IKEv1, because it seems to
		 * confuse various third parties (Windows, Cisco VPN 300,
		 * and juniper
		 * likely because this would be called before the IPsec SA
		 * of QuickMode is installed, so the remote endpoints view
		 * this IKE SA still as the active one?
		 */
		if (ike->sa.st_ike_seen_v2n_initial_contact) {
			if (c->newest_ike_sa != SOS_NOBODY &&
			    c->newest_ike_sa != ike->sa.st_serialno) {
				struct state *old_p1 = state_by_serialno(c->newest_ike_sa);

				dbg("deleting replaced IKE state for %s",
				    old_p1->st_connection->name);
				old_p1->st_dont_send_delete = true;
				event_force(EVENT_SA_EXPIRE, old_p1);
			}

			if (c->newest_ipsec_sa != SOS_NOBODY) {
				struct state *old_p2 = state_by_serialno(c->newest_ipsec_sa);
				struct connection *d = old_p2 == NULL ? NULL : old_p2->st_connection;

				if (c == d && same_id(&c->spd.that.id, &d->spd.that.id)) {
					dbg("Initial Contact received, deleting old state #%lu from connection '%s'",
					    c->newest_ipsec_sa, c->name);
					old_p2->st_dont_send_delete = true;
					event_force(EVENT_SA_EXPIRE, old_p2);
				}
			}
		}
	}

	c->newest_ike_sa = ike->sa.st_serialno;
}
