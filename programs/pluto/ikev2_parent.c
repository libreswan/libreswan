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

bool negotiate_hash_algo_from_notification(const struct pbs_in *payload_pbs,
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
			      const struct v2_state_transition *svm,
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

bool need_v2_configuration_payload(const struct connection *const cc,
				   const lset_t st_nat_traversal)
{
	return (cc->spd.this.modecfg_client &&
		(!cc->spd.this.cat || LHAS(st_nat_traversal, NATED_HOST)));
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

void ikev2_rekey_expire_predecessor(const struct child_sa *larval_sa, so_serial_t pred)
{
	struct state *rst = state_with_serialno(pred);
	if (rst == NULL) {
		llog_sa(RC_LOG, larval_sa,
			"rekeyed #%lu; the state is already is gone", pred);
		return;
	}

	deltatime_t lifetime = deltatime(0); /* .lt. EXPIRE_OLD_SA_DELAY */
	if (IS_IKE_SA_ESTABLISHED(rst) || IS_CHILD_SA_ESTABLISHED(rst)) {
		/* on initiator, delete st_ipsec_pred. The responder should not */
		monotime_t now = mononow();
		const struct state_event *ev = rst->st_event;
		if (ev != NULL)
			lifetime = monotimediff(ev->ev_time, now);
	}

	deltatime_buf lb;
	llog_sa(RC_LOG, larval_sa,
		"rekeyed #%lu %s and expire it remaining life %ss",
		pred, larval_sa->sa.st_state->name,
		str_deltatime(lifetime, &lb));

	if (deltatime_cmp(lifetime, >, EXPIRE_OLD_SA_DELAY)) {
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
	if (!(IS_IKE_SA_ESTABLISHED(st) ||
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

	struct ike_sa *ike = ike_sa(st, HERE);
	if (ike == NULL) {
		/*
		 * An IKE SA must return itself so NULL implies a
		 * child.
		 *
		 * Even it is decided that Child SAs can linger after
		 * the IKE SA has gone they shouldn't be getting
		 * rekeys!
		 */
		pexpect_fail(st->st_logger, HERE,
			     "not replacing Child SA #%lu; as IKE SA #%lu has diasppeared",
			     st->st_serialno, st->st_clonedfrom);
		return;
	}

	const char *satype = IS_IKE_SA(st) ? "IKE" : "Child";

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
		event_force(EVENT_SA_EXPIRE, &ike->sa);
		return;
	}

	deltatime_t replace_in = monotimediff(st->st_replace_by, now);
	if (deltatime_cmp(replace_in, <, deltatime_zero)) {
		dbg("%s SA #%lu has no time to re-key, will replace", satype, st->st_serialno);
		event_force(EVENT_SA_REPLACE, st);
	}

	struct child_sa *larval_sa;
	if (IS_IKE_SA(st)) {
		larval_sa = submit_v2_CREATE_CHILD_SA_rekey_ike(ike);
	} else {
		larval_sa = submit_v2_CREATE_CHILD_SA_rekey_child(ike, pexpect_child_sa(st));
	}

	llog_sa(RC_LOG, larval_sa,
		"initiating rekey to replace %s SA #%lu",
		satype, st->st_serialno);


	/*
	 * Should the rekey go into the weeds this replace will kick
	 * in.
	 *
	 * XXX: should the next event be SA_EXPIRE instead of
	 * SA_REPLACE?  For an IKE SA it breaks ikev2-32-nat-rw-rekey.
	 * For a CHILD SA perhaps - there is a mystery around what
	 * happens to the new child if the old one disappears.
	 */
	dbg("scheduling drop-dead replace event for %s SA #%lu", satype, st->st_serialno);
	event_delete(EVENT_v2_LIVENESS, st);
	event_schedule(EVENT_SA_REPLACE, replace_in, st);
}

void v2_event_sa_replace(struct state *st)
{
	const char *satype = IS_IKE_SA(st) ? "IKE" : "CHILD";

	/*
	 * Is ST obsolete?
	 *
	 * When ST and connection serial numbers match, or whn
	 * connection has no serial number SOS_NOBODY is returned.
	 */
	so_serial_t newer_sa = get_newer_sa_from_connection(st);
	if (newer_sa != SOS_NOBODY) {
		/*
		 * This state is somehow newer then the established
		 * state as identified by the connection.
		 *
		 * Presumably it is a failed rekey (see above?) that
		 * didn't complete.
		 *
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
				old_p1->st_send_delete = DONT_SEND_DELETE;
				event_force(EVENT_SA_EXPIRE, old_p1);
			}

			if (c->newest_ipsec_sa != SOS_NOBODY) {
				struct state *old_p2 = state_by_serialno(c->newest_ipsec_sa);
				struct connection *d = old_p2 == NULL ? NULL : old_p2->st_connection;

				if (c == d && same_id(&c->spd.that.id, &d->spd.that.id)) {
					dbg("Initial Contact received, deleting old state #%lu from connection '%s'",
					    c->newest_ipsec_sa, c->name);
					old_p2->st_send_delete = DONT_SEND_DELETE;
					event_force(EVENT_SA_EXPIRE, old_p2);
				}
			}
		}
	}

	c->newest_ike_sa = ike->sa.st_serialno;
}
