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
#include "rekeyfuzz.h"

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
	lset_t sighash_policy = ike->sa.st_connection->config->sighash_policy;

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
		enum ikev2_hash_algorithm h_value = ntohs(nh_value);

		const struct hash_desc *hash = ikev2_get_hash_desc(h_value);
		if (hash == NULL) {
			llog_sa(RC_LOG, ike, "received and ignored unknown hash algorithm %d", h_value);
			continue;
		}

		lset_t hash_bit = LELEM(h_value);
		if (!(sighash_policy & hash_bit)) {
			dbg("digsig: received and ignored unacceptable hash algorithm %s", hash->common.fqn);
			continue;
		}

		dbg("digsig: received and accepted hash algorithm %s", hash->common.fqn);
		ike->sa.st_v2_digsig.negotiated_hashes |= hash_bit;
	}
	return true;
}

void llog_v2_ike_sa_established(struct ike_sa *ike, struct child_sa *larval)
{
	LLOG_JAMBUF(RC_SUCCESS, larval->sa.st_logger, buf) {
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

void v2_ike_sa_established(struct ike_sa *ike)
{
	struct connection *c = ike->sa.st_connection;
	c->newest_ike_sa = ike->sa.st_serialno;
	ike->sa.st_viable_parent = true;
	linux_audit_conn(&ike->sa, LAK_PARENT_START);
	pstat_sa_established(&ike->sa);
	/* dump new keys */
	if (DBGP(DBG_PRIVATE)) {
		DBG_tcpdump_ike_sa_keys(&ike->sa);
	}
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

	enum_buf ke_esb;
	llog(RC_LOG, st->st_logger,
	     "initiator guessed wrong keying material group (%s); responding with INVALID_KE_PAYLOAD requesting %s",
	     str_enum_short(&oakley_group_names, ke_group, &ke_esb),
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
	struct id id = c->remote->host.id;

	if (!c->remote->config->host.key_from_DNS_on_demand)
		return false;

	if (c->remote->config->host.auth == AUTH_RSASIG &&
	    (id.kind == ID_FQDN || id_is_ipaddr(&id)))
{
		switch (atype) {
		case IKEv2_AUTH_RESERVED:
		case IKEv2_AUTH_DIGSIG:
		case IKEv2_AUTH_RSA:
			return true; /* success */
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
			err2 = str_enum(&ikev2_auth_method_names, atype, &eb2);
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
	return false;
}

/*
 * package up the calculated KE value, and emit it as a KE payload.
 * used by IKEv2: parent, child (PFS)
 */
bool emit_v2KE(chunk_t g, const struct dh_desc *group,
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
		return false;

	if (impair.ke_payload >= IMPAIR_EMIT_ROOF) {
		uint8_t byte = impair.ke_payload - IMPAIR_EMIT_ROOF;
		llog(RC_LOG, outs->outs_logger,
			    "IMPAIR: sending bogus KE (g^x) == %u value to break DH calculations", byte);
		/* Only used to test sending/receiving bogus g^x */
		diag_t d = pbs_out_repeated_byte(&kepbs, byte, g.len, "ikev2 impair KE (g^x) == 0");
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
		if (!out_hunk(g, &kepbs, "ikev2 g^x"))
			return false;
	}

	close_output_pbs(&kepbs);
	return true;
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

void ikev2_rekey_expire_predecessor(const struct child_sa *larval, so_serial_t pred)
{
	struct state *rst = state_by_serialno(pred);
	if (rst == NULL) {
		ldbg(larval->sa.st_logger,
		     "rekeyed #%lu; the state is already is gone", pred);
		return;
	}

	/*
	 * Only established states have a lifetime scheduled.
	 */

	deltatime_t lifetime = deltatime(0);
	if (rst->st_v2_lifetime_event != NULL) {
		lifetime = monotimediff(rst->st_v2_lifetime_event->ev_time, mononow());
	}

	deltatime_buf lb;
	ldbg(larval->sa.st_logger,
	     "rekeyed #%lu; expire it remaining life %ss",
	     pred, (rst->st_v2_lifetime_event == NULL ? "<never>" : str_deltatime(lifetime, &lb)));

	if (deltatime_cmp(lifetime, >, EXPIRE_OLD_SA_DELAY)) {
		/* replace the REPLACE/EXPIRE event */
		delete_state_event(&rst->st_v2_lifetime_event, HERE);
		event_schedule(EVENT_SA_EXPIRE, EXPIRE_OLD_SA_DELAY, rst);
		pexpect(rst->st_v2_lifetime_event->ev_type == EVENT_SA_EXPIRE);
	}
	/*
	 * else it should be on its way to expire, no need to kick
	 * dead state when it is down
	 */
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
		llog_pexpect(st->st_logger, HERE,
			     "#%lu has lease; should not be trying to replace",
			     st->st_serialno);
		return true;
	}

	/* see of (most recent) child is busy */
	struct state *cst;
	struct ike_sa *ike;
	if (IS_IKE_SA(st)) {
		ike = pexpect_ike_sa(st);
		cst = state_by_serialno(c->newest_ipsec_sa);
		if (cst == NULL) {
			llog_pexpect(st->st_logger, HERE,
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

void schedule_v2_replace_event(struct state *st)
{
	/*
	 * Time to rekey/reauth/replace/discard; scheduled only once
	 * during a state's lifetime.
	 */
	pexpect(st->st_v2_refresh_event == NULL);
	pexpect(st->st_v2_lifetime_event == NULL);

	struct connection *c = st->st_connection;

	/*
	 * Determine the SA's lifetime (in seconds).
	 *
	 * Use .st_establishing_sa, because, for an IKE SA, it may not
	 * have been emancipated (so IS_IKE_SA() would still be
	 * false).
	 */
	deltatime_t lifetime;
	switch (st->st_establishing_sa) {
	case IKE_SA: lifetime = c->sa_ike_life_seconds; break;
	case IPSEC_SA: lifetime = c->sa_ipsec_life_seconds; break;
	default: bad_case(st->st_establishing_sa);
	}
	intmax_t delay = deltasecs(lifetime);

	enum event_type kind;
	const char *story;
	if ((c->policy & POLICY_OPPORTUNISTIC) &&
	    st->st_connection->spd.that.has_lease) {
		kind = EVENT_SA_EXPIRE;
		story = "always expire opportunistic SA with lease";
	} else if (c->policy & POLICY_DONT_REKEY) {
		kind = EVENT_SA_EXPIRE;
		story = "policy doesn't allow re-key";
	} else if (IS_IKE_SA(st) && LIN(POLICY_REAUTH, st->st_connection->policy)) {
		kind = EVENT_SA_REPLACE;
		story = "IKE SA with policy re-authenticate";
	} else {
		time_t marg_s = fuzz_margin((st->st_sa_role == SA_INITIATOR),
					    deltasecs(c->sa_rekey_margin),
					    c->sa_rekey_fuzz);

		intmax_t rekey_delay = delay;
		if (delay > marg_s)
			rekey_delay = delay - marg_s;
		else
			marg_s = 0;
		deltatime_t marg = deltatime(marg_s);
		st->st_replace_margin = marg;

		/* Time to rekey/reauth; scheduled once during a state's lifetime.*/
		dbg("#%lu will start re-keying in %jd seconds (replace in %jd seconds)",
		    st->st_serialno, rekey_delay, delay);
		event_schedule(EVENT_v2_REKEY, deltatime(rekey_delay), st);
		pexpect(st->st_v2_refresh_event->ev_type == EVENT_v2_REKEY);
		story = "attempting re-key";

		kind = EVENT_SA_REPLACE;
	}

	/*
	 * This is the drop-dead event.
	 */
	passert(kind == EVENT_SA_REPLACE || kind == EVENT_SA_EXPIRE);
	dbg("#%lu will %s in %jd seconds (%s)",
	    st->st_serialno,
	    kind == EVENT_SA_EXPIRE ? "expire" : "be replaced",
	    delay, story);

	/*
	 * Schedule the lifetime (death) event.  Only happens once
	 * when the state is established.
	 */
	event_schedule(kind, deltatime(delay), st);
	pexpect(st->st_v2_lifetime_event->ev_type == kind);
}

static bool state_is_expired(struct state *st, const char *verb)
{
	struct ike_sa *ike = ike_sa(st, HERE);
	if (ike == NULL) {
		/*
		 * An IKE SA must return itself so NULL implies a
		 * parentless child.
		 *
		 * Even it is decided that Child SAs can linger after
		 * the IKE SA has gone they shouldn't be getting
		 * rekeys!
		 */
		llog_pexpect(st->st_logger, HERE,
			     "not %s Child SA #%lu; as IKE SA #%lu has diasppeared",
			     verb, st->st_serialno, st->st_clonedfrom);
		event_force(EVENT_SA_EXPIRE, st);
		return true;
	}

	if (expire_ike_because_child_not_used(st)) {
		struct ike_sa *ike = ike_sa(st, HERE);
		event_force(EVENT_SA_EXPIRE, &ike->sa);
		return true;
	}

	so_serial_t newer_sa = get_newer_sa_from_connection(st);
	if (newer_sa != SOS_NOBODY) {
		/*
		 * A newer SA implies that this SA has already been
		 * successfully replaced (it's only set when the newer
		 * SA establishes).
		 *
		 * Two ways this can happen:
		 *
		 * + the SA should have been expired at the same time
		 * as the new SA was established; but wasn't
		 *
		 * + this and the peer established the same SA in
		 * parallel, aka crossing the streams; the two SAs are
		 * allowed to linger until one is clearly obsolete;
		 * see github/699
		 *
		 * either way expire the SA now
		 */
		const char *satype = IS_IKE_SA(st) ? "IKE" : "Child";
#if 0
		llog_pexpect(st->st_logger, HERE,
			     "not %s stale %s SA #%lu; as already got a newer #%lu",
			     verb, satype, st->st_serialno, newer_sa);
#else
		log_state(RC_LOG, st,
			  "not %s stale %s SA #%lu; as already got a newer #%lu",
			  verb, satype, st->st_serialno, newer_sa);
#endif
		event_force(EVENT_SA_EXPIRE, st);
		return true;
	}

	return false;
}

void v2_event_sa_rekey(struct state *st)
{
	if (state_is_expired(st, "rekey")) {
		return;
	}

	struct ike_sa *ike = ike_sa(st, HERE);

	struct child_sa *larval_sa;
	if (IS_IKE_SA(st)) {
		larval_sa = submit_v2_CREATE_CHILD_SA_rekey_ike(ike);
	} else {
		larval_sa = submit_v2_CREATE_CHILD_SA_rekey_child(ike, pexpect_child_sa(st));
	}

	const char *satype = IS_IKE_SA(st) ? "IKE" : "Child";
	llog_sa(RC_LOG, larval_sa,
		"initiating rekey to replace %s SA #%lu",
		satype, st->st_serialno);
}

void v2_event_sa_replace(struct state *st)
{
	if (state_is_expired(st, "replace")) {
		return;
	}

	const char *satype = IS_IKE_SA(st) ? "IKE" : "Child";
	dbg("replacing stale %s SA", satype);

	/*
	 * XXX: For a CHILD SA, will this result in a re-key attempt?
	 */
	ipsecdoi_replace(st, 1);
	event_force(EVENT_SA_EXPIRE, st);
}

void v2_event_sa_reauth(struct state *st)
{
	if (state_is_expired(st, "re-authenticating")) {
		return;
	}

	const char *satype = IS_IKE_SA(st) ? "IKE" : "Child";
	dbg("re-authenticating %s SA", satype);

	/*
	 * XXX: For a CHILD SA, will this result in a re-key attempt?
	 */
	ipsecdoi_replace(st, 1);
}

/*
 * An IKE SA has been established.  Check if the freshly established
 * connection is replacing an established version of itself.
 *
 * Note the serial number, and release any connections with the same
 * peer ID but different peer IP address.
 * *
 * The use of uniqueIDs is mostly historic and might be removed
 * in a future version. It is ignored for PSK based connections,
 * which only act based on being a "server using PSK".
 */

void wipe_old_v2_connections(const struct ike_sa *ike)
{
	struct connection *c = ike->sa.st_connection;
	bool new_remote_is_authnull =
		(c->remote->config->host.authby.null ||
		 /*XXX: redundant? */
		 c->remote->config->host.auth == AUTH_NULL);

	if (c->local->config->host.xauth.server &&
	    c->remote->config->host.authby.psk) {
		/*
		 * If we are a server and authenticate all clients
		 * using PSK then all clients use the same group ID
		 * Note that "xauth.server" also refers to IKEv2 CP
		 */
		dbg("%s() skipped, we are a server using PSK and clients are using a group ID", __func__);
		return;
	}

	if (!uniqueIDs) {
		dbg("%s() skipped, uniqueIDs disabled", __func__);
		return;
	}

	dbg("%s() contemplating releasing older self", __func__);

	/*
	 * For all existing connections: if the same Phase 1 IDs are
	 * used, unorient the (old) connection (if different from
	 * current connection).
	 *
	 * Only do this for connections with the same name (can be
	 * shared ike sa).
	 */
	struct connection_filter cf = {
		.name = c->name,
		.kind = c->kind,
		.this_id_eq = &c->local->host.id,
		.that_id_eq = &c->remote->host.id,
		.where = HERE,
	};
	while (next_connection_new2old(&cf)) {
		struct connection *d = cf.c;

		/*
		 * If old IKE SA is same as new IKE sa and non-auth
		 * isn't overwrting auth?
		 */
		if (c == d) {
			continue;
		}

		bool old_remote_is_nullauth = (d->remote->config->host.authby.null ||
					       /* XXX: redundant? */
					       d->remote->config->host.auth == AUTH_NULL);
		if (!old_remote_is_nullauth && new_remote_is_authnull) {
			llog_sa(RC_LOG, ike, "cannot replace old authenticated connection with authnull connection");
			continue;
		}

		if (!address_eq_address(c->remote->host.addr, d->remote->host.addr) &&
		    old_remote_is_nullauth &&
		    new_remote_is_authnull) {
			llog_sa(RC_LOG, ike, "NULL auth ID for different IP's cannot replace each other");
			continue;
		}

		dbg("unorienting old connection with same IDs");
		/*
		 * When replacing an old existing connection, suppress
		 * sending delete notify.
		 */
		suppress_delete_notify(ike, "ISAKMP", d->newest_ike_sa);
		suppress_delete_notify(ike, "IKE", d->newest_ipsec_sa);
		/*
		 * XXX: Assume this call doesn't want to log to whack?
		 * Even though the IKE SA may have whack attached,
		 * don't transfer it to the old connection.
		 */
		if (d->kind == CK_INSTANCE) {
			/* this also deletes the states */
			delete_connection(&d);
		} else {
			/* this only deletes the states */
			release_connection(d);
		}
	}
}
