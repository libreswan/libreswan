/*
 * IPsec DOI and Oakley resolution routines
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002,2010-2017 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2006  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010-2011 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2018 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2014-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017-2018 Antony Antony <antony@phenome.org>
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
 *
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "state.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "packet.h"
#include "keys.h"
#include "demux.h"      /* needs packet.h */
#include "kernel.h"     /* needs connections.h */
#include "log.h"
#include "server.h"
#include "timer.h"
#include "rnd.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "ikev1_quick.h"
#include "whack.h"
#include "fetch.h"
#include "asn1.h"
#include "crypto.h"
#include "secrets.h"
#include "crypt_dh.h"
#include "ike_alg.h"
#include "ike_alg_integ.h"
#include "ike_alg_encrypt.h"
#include "kernel_alg.h"
#include "plutoalg.h"
#include "pluto_crypt.h"
#include "ikev1.h"
#include "ikev1_continuations.h"
#include "ikev2.h"
#include "ikev2_send.h"
#include "ikev1_xauth.h"
#include "ip_info.h"
#include "vendor.h"
#include "nat_traversal.h"
#include "ikev1_dpd.h"
#include "pluto_x509.h"
#include "ip_address.h"
#include "pluto_stats.h"
#include "chunk.h"
#include "pending.h"
#include "iface.h"
#include "ikev2_delete.h"	/* for record_v2_delete(); but call is dying */
#include "unpack.h"

bool ikev1_justship_nonce(chunk_t *n, struct pbs_out *outs,
			  const char *name)
{
	return ikev1_out_generic_chunk(&isakmp_nonce_desc, outs, *n, name);
}

bool ikev1_ship_nonce(chunk_t *n, chunk_t *nonce,
		      struct pbs_out *outs, const char *name)
{
	unpack_nonce(n, nonce);
	return ikev1_justship_nonce(n, outs, name);
}

#ifdef USE_IKEv1
static initiator_function *pick_initiator(struct connection *c,
					  lset_t policy)
{
	if (policy & c->policy & POLICY_IKEV2_ALLOW) {
		return ikev2_parent_outI1;
	} else {
		/* we may try V1; Aggressive or Main Mode? */
		return (policy & POLICY_AGGRESSIVE) ? aggr_outI1 : main_outI1;
	}
}
#endif

void ipsecdoi_initiate(struct fd *whack_sock,
		       struct connection *c,
		       lset_t policy,
		       unsigned long try,
		       so_serial_t replacing,
		       const threadtime_t *inception,
		       struct xfrm_user_sec_ctx_ike *uctx
		       )
{
	/*
	 * If there's already an IKEv1 ISAKMP SA established, use that and
	 * go directly to Quick Mode.  We are even willing to use one
	 * that is still being negotiated, but only if we are the Initiator
	 * (thus we can be sure that the IDs are not going to change;
	 * other issues around intent might matter).
	 * Note: there is no way to initiate with a Road Warrior.
	 */
	struct state *st = find_phase1_state(c,
#ifdef USE_IKEv1
					     ISAKMP_SA_ESTABLISHED_STATES |
					     PHASE1_INITIATOR_STATES |
#endif
					     IKEV2_ISAKMP_INITIATOR_STATES);

	if (st == NULL) {
#ifdef USE_IKEv1
		initiator_function *initiator = pick_initiator(c, policy);
#else
		initiator_function *initiator = ikev2_parent_outI1;
#endif

		if (initiator != NULL) {
			/*
			 * initiator will create a state (and that in
			 * turn will start its timing it), need a way
			 * to stop it.
			 */
			initiator(whack_sock, c, NULL, policy, try, inception, uctx);
		}
	} else if (HAS_IPSEC_POLICY(policy)) {
#ifdef USE_IKEv1
		if (st->st_ike_version == IKEv1) {
			if (!IS_ISAKMP_SA_ESTABLISHED(st->st_state)) {
				/* leave our Phase 2 negotiation pending */
				add_pending(whack_sock, pexpect_ike_sa(st),
				    c, policy, try,
				    replacing, uctx,
				    false/*part of initiate*/);
			} else {
				/* ??? we assume that peer_nexthop_sin isn't important:
				 * we already have it from when we negotiated the ISAKMP SA!
				 * It isn't clear what to do with the error return.
				 */
			quick_outI1(whack_sock, st, c, policy, try,
				    replacing, uctx);
			}
		}
#endif
		if (st->st_ike_version == IKEv2) {
			if (!IS_PARENT_SA_ESTABLISHED(st)) {
				/* leave our Phase 2 negotiation pending */
				add_pending(whack_sock, pexpect_ike_sa(st),
				    c, policy, try,
				    replacing, uctx,
				    false/*part of initiate*/);
			} else {
				struct pending p = {
				.whack_sock = whack_sock, /*on-stack*/
				.ike = pexpect_ike_sa(st),
				.connection = c,
				.try = try,
				.policy = policy,
				.replacing = replacing,
				.uctx = uctx,
				};
				ikev2_initiate_child_sa(&p);
			}
		}
	}
}

/* Replace SA with a fresh one that is similar
 *
 * Shares some logic with ipsecdoi_initiate, but not the same!
 * - we must not reuse the ISAKMP SA if we are trying to replace it!
 * - if trying to replace IPSEC SA, use ipsecdoi_initiate to build
 *   ISAKMP SA if needed.
 * - duplicate whack fd, if live.
 * Does not delete the old state -- someone else will do that.
 */
void ipsecdoi_replace(struct state *st, unsigned long try)
{
	/*
	 * start billing the new state.  The old state also gets
	 * billed for this function call, oops.
	 */
	threadtime_t inception = threadtime_start();

	if (IS_IKE_SA(st)) {
		/* start from policy in connection */

		struct connection *c = st->st_connection;

		lset_t policy = c->policy & ~POLICY_IPSEC_MASK;

		if (IS_PARENT_SA_ESTABLISHED(st))
			log_state(RC_LOG, st, "initiate reauthentication of IKE SA");

#ifdef USE_IKEv1
		initiator_function *initiator = pick_initiator(c, policy);
#else
		initiator_function *initiator = ikev2_parent_outI1;
#endif

		if (initiator != NULL) {
			/*
			 * initiator will create a state (and that in
			 * turn will start its timing it), need a way
			 * to stop it.
			 */
			(void) initiator(st->st_whack_sock,
					 c, st, policy, try, &inception,
				st->sec_ctx);
		}
	} else {
		/*
		 * Start from policy in (ipsec) state, not connection.
		 * This ensures that rekeying doesn't downgrade
		 * security.  I admit that this doesn't capture
		 * everything.
		 */
		lset_t policy = st->st_policy;

		if (st->st_pfs_group != NULL)
			policy |= POLICY_PFS;
		if (st->st_ah.present) {
			policy |= POLICY_AUTHENTICATE;
			if (st->st_ah.attrs.mode ==
			    ENCAPSULATION_MODE_TUNNEL)
				policy |= POLICY_TUNNEL;
		}
		if (st->st_esp.present &&
		    st->st_esp.attrs.transattrs.ta_encrypt != &ike_alg_encrypt_null) {
			policy |= POLICY_ENCRYPT;
			if (st->st_esp.attrs.mode ==
			    ENCAPSULATION_MODE_TUNNEL)
				policy |= POLICY_TUNNEL;
		}
		if (st->st_ipcomp.present) {
			policy |= POLICY_COMPRESS;
			if (st->st_ipcomp.attrs.mode ==
			    ENCAPSULATION_MODE_TUNNEL)
				policy |= POLICY_TUNNEL;
		}

		if (st->st_ike_version == IKEv1)
			passert(HAS_IPSEC_POLICY(policy));

		ipsecdoi_initiate(st->st_whack_sock, st->st_connection,
				  policy, try, st->st_serialno, &inception,
			st->sec_ctx);
	}
}

/*
 * look for the existence of a non-expiring preloaded public key
 */
bool has_preloaded_public_key(const struct state *st)
{
	const struct connection *c = st->st_connection;

	/* do not consider rw connections since
	 * the peer's identity must be known
	 */
	if (c->kind == CK_PERMANENT) {
		/* look for a matching RSA public key */
		for (const struct pubkey_list *p = pluto_pubkeys; p != NULL;
		     p = p->next) {
			const struct pubkey *key = p->key;

			if (key->type == &pubkey_type_rsa &&
			    same_id(&c->spd.that.id, &key->id) &&
			    is_realtime_epoch(key->until_time)) {
				/* found a preloaded public key */
				return TRUE;
			}
		}
	}
	return FALSE;
}

/*
 * Decode the ID payload of Phase 1 (main_inI3_outR3 and main_inR3)
 * Clears *peer to avoid surprises.
 * Note: what we discover may oblige Pluto to switch connections.
 * We must be called before SIG or HASH are decoded since we
 * may change the peer's RSA key or ID.
 */

bool extract_peer_id(enum ike_id_type kind, struct id *peer, const pb_stream *id_pbs)
{
	size_t left = pbs_left(id_pbs);

	*peer = (struct id) {.kind = kind };	/* clears everything */

	switch (kind) {
	/* ident types mostly match between IKEv1 and IKEv2 */
	case ID_IPV4_ADDR:
	case ID_IPV6_ADDR:
		/* failure mode for initaddr is probably inappropriate address length */
	{
		struct pbs_in in_pbs = *id_pbs;
		if (!pbs_in_address(&peer->ip_addr,
				    (peer->kind == ID_IPV4_ADDR ? &ipv4_info :
				     &ipv6_info),
				    &in_pbs, "peer ID")) {
			/* XXX Could send notification back */
			return false;
		}
	}
	break;

	/* seems odd to continue as ID_FQDN? */
	case ID_USER_FQDN:
		if (memchr(id_pbs->cur, '@', left) == NULL) {
			loglog(RC_LOG_SERIOUS,
				"peer's ID_USER_FQDN contains no @: %.*s",
				(int) left,
				id_pbs->cur);
			/* return FALSE; */
		}
	/* FALLTHROUGH */
	case ID_FQDN:
		if (memchr(id_pbs->cur, '\0', left) != NULL) {
			loglog(RC_LOG_SERIOUS,
				"Phase 1 (Parent)ID Payload of type %s contains a NUL",
				enum_show(&ike_idtype_names, kind));
			return FALSE;
		}

		/* ??? ought to do some more sanity check, but what? */

		peer->name = chunk2(id_pbs->cur, left);
		break;

	case ID_KEY_ID:
		peer->name = chunk2(id_pbs->cur, left);
		if (DBGP(DBG_BASE)) {
			DBG_dump_hunk("KEY ID:", peer->name);
		}
		break;

	case ID_DER_ASN1_DN:
		peer->name = chunk2(id_pbs->cur, left);
		if (DBGP(DBG_BASE)) {
		    DBG_dump_hunk("DER ASN1 DN:", peer->name);
		}
		break;

	case ID_NULL:
		if (left != 0) {
			if (DBGP(DBG_BASE)) {
				DBG_dump("unauthenticated NULL ID:", id_pbs->cur, left);
			}
		}
		break;

	default:
		/* XXX Could send notification back */
		loglog(RC_LOG_SERIOUS,
			"Unsupported identity type (%s) in Phase 1 (Parent) ID Payload",
			enum_show(&ike_idtype_names, kind));
		return FALSE;
	}

	return TRUE;
}

void initialize_new_state(struct state *st,
			  struct connection *c,
			  lset_t policy,
			  int try)
{
	update_state_connection(st, c);

	/* reset our choice of interface */
	c->interface = NULL;
	(void)orient(c);
	st->st_interface = c->interface;
	passert(st->st_interface != NULL);
	st->st_remote_endpoint = endpoint3(c->interface->protocol,
					   &c->spd.that.host_addr,
					   ip_hport(c->spd.that.host_port));

	st->st_policy = policy & ~POLICY_IPSEC_MASK;        /* clear bits */
	st->st_try = try;

	for (const struct spd_route *sr = &c->spd;
	     sr != NULL; sr = sr->spd_next) {
		if (sr->this.xauth_client) {
			if (sr->this.xauth_username != NULL) {
				jam_str(st->st_xauth_username, sizeof(st->st_xauth_username), sr->this.xauth_username);
				break;
			}
		}
	}

	binlog_refresh_state(st);
}

void send_delete(struct state *st)
{
	if (impair.send_no_delete) {
		dbg("IMPAIR: impair-send-no-delete set - not sending Delete/Notify");
	} else {
		dbg("#%lu send %s delete notification for %s",
		    st->st_serialno,
		    enum_name(&ike_version_names, st->st_ike_version),
		    st->st_state->name);
		switch (st->st_ike_version) {
#ifdef USE_IKEv1
		case IKEv1:
			send_v1_delete(st);
			break;
#endif
		case IKEv2:
		{
			struct ike_sa *ike = ike_sa(st, HERE);
			record_v2_delete(ike, st);
			send_recorded_v2_message(ike, "delete notification",
						 MESSAGE_REQUEST);
			/*
			 * XXX: The record 'n' send call shouldn't be
			 * needed.  Instead, as part of this
			 * transition (live -> being-deleted) the
			 * standard success_v2_transition() code path
			 * should get to do the right thing.
			 *
			 * XXX: The record 'n' send call leads to an
			 * RFC violation.  The lack of a state
			 * transition means there's nothing set up to
			 * wait for the ack.  And that in turn means
			 * that the next packet will be sent before
			 * this one has had a response.
			 */
			dbg("Message ID: IKE #%lu sender #%lu in %s hacking around record 'n' send",
			    ike->sa.st_serialno, st->st_serialno, __func__);
			v2_msgid_update_sent(ike, &ike->sa, NULL/*new exchange*/, MESSAGE_REQUEST);
			st->st_dont_send_delete = true;
			break;
		}
		default:
			bad_case(st->st_ike_version);
		}
	}
}

void lswlog_child_sa_established(struct jambuf *buf, struct state *st)
{
	struct connection *const c = st->st_connection;
	const char *ini = " {";

	jam_string(buf, c->policy & POLICY_TUNNEL ? " tunnel mode" : " transport mode");

	if (st->st_esp.present) {
		bool nat = (st->hidden_variables.st_nat_traversal & NAT_T_DETECTED) != 0;
		bool tfc = c->sa_tfcpad != 0 && !st->st_seen_no_tfc;
		bool esn = st->st_esp.attrs.transattrs.esn_enabled;
		bool tcp = st->st_interface->protocol == &ip_protocol_tcp;

		if (nat)
			dbg("NAT-T: NAT Traversal detected - their IKE port is '%d'",
			     c->spd.that.host_port);

		dbg("NAT-T: encaps is '%s'",
		     c->encaps == yna_auto ? "auto" : bool_str(c->encaps == yna_yes));

		jam(buf, "%sESP%s%s%s=>0x%08" PRIx32 " <0x%08" PRIx32 "",
			ini,
			tcp ? "inTCP" : nat ? "inUDP" : "",
			esn ? "/ESN" : "",
			tfc ? "/TFC" : "",
			ntohl(st->st_esp.attrs.spi),
			ntohl(st->st_esp.our_spi));
		jam(buf, " xfrm=%s", st->st_esp.attrs.transattrs.ta_encrypt->common.fqn);
		/* log keylen when it is required and/or "interesting" */
		if (!st->st_esp.attrs.transattrs.ta_encrypt->keylen_omitted ||
		    (st->st_esp.attrs.transattrs.enckeylen != 0 &&
		     st->st_esp.attrs.transattrs.enckeylen != st->st_esp.attrs.transattrs.ta_encrypt->keydeflen)) {
			jam(buf, "_%u", st->st_esp.attrs.transattrs.enckeylen);
		}
		jam(buf, "-%s", st->st_esp.attrs.transattrs.ta_integ->common.fqn);

		if ((st->st_ike_version == IKEv2) && st->st_pfs_group != NULL)  {
			jam_string(buf, "-");
			jam_string(buf, st->st_pfs_group->common.fqn);
		}

		ini = " ";
	}

	if (st->st_ah.present) {
		jam(buf, "%sAH%s=>0x%08" PRIx32 " <0x%08" PRIx32 " xfrm=%s",
			ini,
			st->st_ah.attrs.transattrs.esn_enabled ? "/ESN" : "",
			ntohl(st->st_ah.attrs.spi),
			ntohl(st->st_ah.our_spi),
			st->st_ah.attrs.transattrs.ta_integ->common.fqn);

		ini = " ";
	}

	if (st->st_ipcomp.present) {
		jam(buf, "%sIPCOMP=>0x%08" PRIx32 " <0x%08" PRIx32,
			ini,
			ntohl(st->st_ipcomp.attrs.spi),
			ntohl(st->st_ipcomp.our_spi));

		ini = " ";
	}

	jam_string(buf, ini);
	jam_string(buf, "NATOA=");
	/* XXX: can lswlog_ip() be used? */
	ipstr_buf ipb;
	jam_string(buf, isanyaddr(&st->hidden_variables.st_nat_oa) ? "none" :
		ipstr(&st->hidden_variables.st_nat_oa, &ipb));

	jam_string(buf, " NATD=");

	if (isanyaddr(&st->hidden_variables.st_natd)) {
		jam_string(buf, "none");
	} else {
		/* XXX: can lswlog_ip() be used?  need to check st_remoteport */
		char oa[ADDRTOT_BUF + sizeof(":00000")];
		snprintf(oa, sizeof(oa),
			 "%s:%d",
			 sensitive_ipstr(&st->hidden_variables.st_natd, &ipb),
			 endpoint_hport(&st->st_remote_endpoint));
		jam_string(buf, oa);
	}

	jam(buf, (st->st_ike_version == IKEv1 && !st->hidden_variables.st_peer_supports_dpd) ? " DPD=unsupported" :
			dpd_active_locally(st) ? " DPD=active" : " DPD=passive");

	if (st->st_xauth_username[0] != '\0') {
		jam_string(buf, " username=");
		jam_string(buf, st->st_xauth_username);
	}

	jam_string(buf, "}");
}

void lswlog_ike_sa_established(struct jambuf *buf, struct state *st)
{
	passert(st->st_oakley.ta_encrypt != NULL);
	passert(st->st_oakley.ta_prf != NULL);
	passert(st->st_oakley.ta_dh != NULL);

	jam_string(buf, " {auth=");
	if (st->st_ike_version == IKEv2) {
		jam(buf, "IKEv2");
	} else {
		jam_enum_short(buf, &oakley_auth_names, st->st_oakley.auth);
	}

	jam(buf, " cipher=%s", st->st_oakley.ta_encrypt->common.fqn);
	if (st->st_oakley.enckeylen > 0) {
		/* XXX: also check omit key? */
		jam(buf, "_%d", st->st_oakley.enckeylen);
	}

	/*
	 * Note: for IKEv1 and AEAD encrypters,
	 * st->st_oakley.ta_integ is 'none'!
	 */
	jam_string(buf, " integ=");
	if (st->st_ike_version == IKEv2) {
		if (st->st_oakley.ta_integ == &ike_alg_integ_none) {
			jam_string(buf, "n/a");
		} else {
			jam_string(buf, st->st_oakley.ta_integ->common.fqn);
		}
	} else {
		/*
		 * For IKEv1, since the INTEG algorithm is potentially
		 * (always?) NULL.  Display the PRF.  The choice and
		 * behaviour are historic.
		 */
		jam_string(buf, st->st_oakley.ta_prf->common.fqn);
	}

	if (st->st_ike_version == IKEv2) {
		jam(buf, " prf=%s", st->st_oakley.ta_prf->common.fqn);
	}

	jam(buf, " group=%s}", st->st_oakley.ta_dh->common.fqn);
}
