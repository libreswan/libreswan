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
 * Copyright (C) 2014,2017 Andrew Cagney <cagney@gmail.com>
 * Copyright (C) 2017-2018 Antony Antony <antony@phenome.org>
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

#include <libreswan.h>
#include "libreswan/pfkeyv2.h"

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
#include "spdb.h"
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

#include "vendor.h"
#include "nat_traversal.h"
#include "virtual.h"	/* needs connections.h */
#include "ikev1_dpd.h"
#include "pluto_x509.h"
#include "ip_address.h"
#include "pluto_stats.h"
#include "chunk.h"
#include "pending.h"

/*
 * Process KE values.
 */
void unpack_KE_from_helper(struct state *st,
			   struct pluto_crypto_req *r,
			   chunk_t *g)
{
	struct pcr_kenonce *kn = &r->pcr_d.kn;

	/*
	 * Should the crypto helper group and the state group be in
	 * sync?
	 *
	 * Probably not, yet seemingly (IKEv2) code is assuming this.
	 *
	 * For instance, with IKEv2, the initial initiator is setting
	 * st_oakley.group to the draft KE group (and well before
	 * initial responder has had a chance to agree to any thing).
	 * Should the initial responder comes back with INVALID_KE
	 * then st_oakley.group gets changed to match the suggestion
	 * and things restart; should the initial responder come back
	 * with an accepted proposal and KE, then the st_oakley.group
	 * is set based on the accepted proposal (the two are
	 * checked).
	 *
	 * Surely, instead, st_oakley.group should be left alone.  The
	 * the initial initiator would maintain a list of KE values
	 * proposed (INVALID_KE flip-flopping can lead to more than
	 * one) and only set st_oakley.group when the initial
	 * responder comes back with a vald accepted propsal and KE.
	 */
	if (DBGP(DBG_CRYPT)) {
		DBG_log("wire (crypto helper) group %s and state group %s %s",
			kn->group ? kn->group->common.name : "NULL",
			st->st_oakley.ta_dh ? st->st_oakley.ta_dh->common.name : "NULL",
			kn->group == st->st_oakley.ta_dh ? "match" : "differ");
	}

	freeanychunk(*g); /* happens in odd error cases */
	*g = kn->gi;

	transfer_dh_secret_to_state("KE", &kn->secret, st);
}

/* accept_KE
 *
 * Check and accept DH public value (Gi or Gr) from peer's message.
 * According to RFC2409 "The Internet key exchange (IKE)" 5:
 *  The Diffie-Hellman public value passed in a KE payload, in either
 *  a phase 1 or phase 2 exchange, MUST be the length of the negotiated
 *  Diffie-Hellman group enforced, if necessary, by pre-pending the
 *  value with zeros.
 */
notification_t accept_KE(chunk_t *dest, const char *val_name,
			 const struct oakley_group_desc *gr,
			 pb_stream *pbs)
{
	if (pbs_left(pbs) != gr->bytes) {
		loglog(RC_LOG_SERIOUS,
		       "KE has %u byte DH public value; %u required",
		       (unsigned) pbs_left(pbs), (unsigned) gr->bytes);
		/* XXX Could send notification back */
		return INVALID_KEY_INFORMATION;
	}
	free_chunk_contents(dest); /* XXX: ever needed? */
	*dest = clone_in_pbs_left_as_chunk(pbs, val_name);
	DBG_cond_dump_chunk(DBG_CRYPT, "DH public value received:\n", *dest);
	return NOTHING_WRONG;
}

void unpack_nonce(chunk_t *n, const struct pluto_crypto_req *r)
{
	const struct pcr_kenonce *kn = &r->pcr_d.kn;

	freeanychunk(*n);
	*n = kn->n;
}

bool ikev1_justship_nonce(chunk_t *n, pb_stream *outs, uint8_t np,
		    const char *name)
{
	return ikev1_out_generic_chunk(np, &isakmp_nonce_desc, outs, *n, name);
}

bool ikev1_ship_nonce(chunk_t *n, struct pluto_crypto_req *r,
		pb_stream *outs, uint8_t np,
		const char *name)
{
	unpack_nonce(n, r);
	return ikev1_justship_nonce(n, outs, np, name);
}

static initiator_function *pick_initiator(struct connection *c,
					  lset_t policy)
{
	if ((policy & POLICY_IKEV2_PROPOSE) &&
	    (policy & c->policy & POLICY_IKEV2_ALLOW) &&
	    !c->failed_ikev2) {
		/* we may try V2, and we haven't failed */
		return ikev2_parent_outI1;
	} else if (policy & c->policy & POLICY_IKEV1_ALLOW) {
		/* we may try V1; Aggressive or Main Mode? */
		return (policy & POLICY_AGGRESSIVE) ? aggr_outI1 : main_outI1;
	} else {
		libreswan_log("Neither IKEv1 nor IKEv2 allowed: %s%s",
			c->failed_ikev2? "previous V2 failure, " : "",
			bitnamesof(sa_policy_bit_names, policy & c->policy));
		/*
		 * tried IKEv2, if allowed, and failed,
		 * and tried IKEv1, if allowed, and got nowhere.
		 */
		return NULL;
	}
}

void ipsecdoi_initiate(fd_t whack_sock,
		       struct connection *c,
		       lset_t policy,
		       unsigned long try,
		       so_serial_t replacing
#ifdef HAVE_LABELED_IPSEC
		       , struct xfrm_user_sec_ctx_ike *uctx
#endif
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
					     ISAKMP_SA_ESTABLISHED_STATES |
					     PHASE1_INITIATOR_STATES |
					     IKEV2_ISAKMP_INITIATOR_STATES);

	if (st == NULL) {
		initiator_function *initiator = pick_initiator(c, policy);

		if (initiator != NULL) {
			initiator(whack_sock, c, NULL, policy, try
#ifdef HAVE_LABELED_IPSEC
				  , uctx
#endif
				  );
		} else {
			/* fizzle: whack_sock will be unused */
			close_any(&whack_sock);
		}
	} else if (HAS_IPSEC_POLICY(policy)) {
		if (!IS_ISAKMP_SA_ESTABLISHED(st->st_state)) {
			/* leave our Phase 2 negotiation pending */
			add_pending(whack_sock, st, c, policy, try,
				    replacing
#ifdef HAVE_LABELED_IPSEC
				    , uctx
#endif
				    );
		} else if (st->st_ikev2) {
			struct pending p;
			p.whack_sock = whack_sock;
			p.isakmp_sa = st;
			p.connection = c;
			p.try = try;
			p.policy = policy;
			p.replacing = replacing;
#ifdef HAVE_LABELED_IPSEC
			p.uctx = uctx;
#endif
			ikev2_initiate_child_sa(&p);
		} else {
			/* ??? we assume that peer_nexthop_sin isn't important:
			 * we already have it from when we negotiated the ISAKMP SA!
			 * It isn't clear what to do with the error return.
			 */
			quick_outI1(whack_sock, st, c, policy, try,
				    replacing
#ifdef HAVE_LABELED_IPSEC
				    , uctx
#endif
				    );
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
	if (IS_PARENT_SA_ESTABLISHED(st) &&
	    !LIN(POLICY_REAUTH, st->st_connection->policy)) {
		libreswan_log("initiate rekey of IKEv2 CREATE_CHILD_SA IKE Rekey");
		/* ??? why does this not need whack socket fd? */
		ikev2_rekey_ike_start(st);
	} else if (IS_IKE_SA(st)) {
		/* start from policy in connection */

		struct connection *c = st->st_connection;

		lset_t policy = c->policy & ~POLICY_IPSEC_MASK;

		if (IS_PARENT_SA_ESTABLISHED(st))
			libreswan_log("initiate reauthentication of IKE SA");

		initiator_function *initiator = pick_initiator(c, policy);

		if (initiator != NULL) {
			(void) initiator(dup_any(st->st_whack_sock),
				c, st, policy, try
#ifdef HAVE_LABELED_IPSEC
				, st->sec_ctx
#endif
				);
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
			if (st->st_ah.attrs.encapsulation ==
			    ENCAPSULATION_MODE_TUNNEL)
				policy |= POLICY_TUNNEL;
		}
		if (st->st_esp.present &&
		    st->st_esp.attrs.transattrs.ta_encrypt != &ike_alg_encrypt_null) {
			policy |= POLICY_ENCRYPT;
			if (st->st_esp.attrs.encapsulation ==
			    ENCAPSULATION_MODE_TUNNEL)
				policy |= POLICY_TUNNEL;
		}
		if (st->st_ipcomp.present) {
			policy |= POLICY_COMPRESS;
			if (st->st_ipcomp.attrs.encapsulation ==
			    ENCAPSULATION_MODE_TUNNEL)
				policy |= POLICY_TUNNEL;
		}

		if (!st->st_ikev2)
			passert(HAS_IPSEC_POLICY(policy));
		ipsecdoi_initiate(dup_any(st->st_whack_sock), st->st_connection,
			policy, try, st->st_serialno
#ifdef HAVE_LABELED_IPSEC
			, st->sec_ctx
#endif
			);
	}
}

/*
 * look for the existence of a non-expiring preloaded public key
 */
bool has_preloaded_public_key(struct state *st)
{
	struct connection *c = st->st_connection;

	/* do not consider rw connections since
	 * the peer's identity must be known
	 */
	if (c->kind == CK_PERMANENT) {
		struct pubkey_list *p;

		/* look for a matching RSA public key */
		for (p = pluto_pubkeys; p != NULL; p = p->next) {
			struct pubkey *key = p->key;

			if (key->alg == PUBKEY_ALG_RSA &&
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
	memset(peer, 0x00, sizeof(struct id));
	peer->kind = kind;

	switch (kind) {
	/* ident types mostly match between IKEv1 and IKEv2 */
	case ID_IPV4_ADDR:
	case ID_IPV6_ADDR:
		/* failure mode for initaddr is probably inappropriate address length */
	{
		err_t ugh = initaddr(id_pbs->cur, left,
				peer->kind == ID_IPV4_ADDR ? AF_INET : AF_INET6,
				&peer->ip_addr);

		if (ugh != NULL) {
			loglog(RC_LOG_SERIOUS,
				"improper %s identification payload: %s",
				enum_show(&ike_idtype_names, peer->kind),
				ugh);
			/* XXX Could send notification back */
			return FALSE;
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
				enum_show(&ike_idtype_names, peer->kind));
			return FALSE;
		}

		/* ??? ought to do some more sanity check, but what? */

		setchunk(peer->name, id_pbs->cur, left);
		break;

	case ID_KEY_ID:
		setchunk(peer->name, id_pbs->cur, left);
		DBG(DBG_PARSING,
		    DBG_dump_chunk("KEY ID:", peer->name));
		break;

	case ID_DER_ASN1_DN:
		setchunk(peer->name, id_pbs->cur, left);
		DBG(DBG_PARSING,
		    DBG_dump_chunk("DER ASN1 DN:", peer->name));
		break;

	case ID_NULL:
		if (left != 0) {
			setchunk(peer->name, id_pbs->cur, left);
			DBG(DBG_PARSING,
				DBG_dump_chunk("unauthenticated NULL ID:", peer->name));
			peer->name.ptr = NULL;
			peer->name.len = 0;
		}
		peer->kind = ID_NULL;
		break;

	default:
		/* XXX Could send notification back */
		loglog(RC_LOG_SERIOUS,
			"Unsupported identity type (%s) in Phase 1 (Parent) ID Payload",
			enum_show(&ike_idtype_names, peer->kind));
		return FALSE;
	}

	return TRUE;
}

void initialize_new_state(struct state *st,
			  struct connection *c,
			  lset_t policy,
			  int try,
			  fd_t whack_sock)
{
	st->st_connection = c;	/* surely safe: must be a new state */

	set_state_ike_endpoints(st, c);

	set_cur_state(st);                                      /* we must reset before exit */
	st->st_policy = policy & ~POLICY_IPSEC_MASK;        /* clear bits */
	st->st_whack_sock = whack_sock;
	st->st_try = try;

	const struct spd_route *sr;

	for (sr = &c->spd; sr != NULL; sr = sr->spd_next) {
		if (sr->this.xauth_client) {
			if (sr->this.xauth_username != NULL) {
				jam_str(st->st_xauth_username, sizeof(st->st_xauth_username), sr->this.xauth_username);
				break;
			}
		}
	}

	insert_state(st); /* needs cookies, connection */

	set_cur_state(st);
}

void send_delete(struct state *st)
{
	if (IMPAIR(SEND_NO_DELETE)) {
		DBGF(DBG_CONTROL, "IMPAIR: impair-send-no-delete set - not sending Delete/Notify");
	} else {
		DBGF(DBG_CONTROL, "#%lu send %s delete notification for %s",
		     st->st_serialno, st->st_ikev2 ? "IKEv2": "IKEv1",
		     st->st_state_name);
		st->st_ikev2 ? send_v2_delete(st) : send_v1_delete(st);
	}
}

static void pstats_sa(bool nat, bool tfc, bool esn)
{
	if (nat)
		pstats_ipsec_encap_yes++;
	else
		pstats_ipsec_encap_no++;
	if (esn)
		pstats_ipsec_esn++;
	if (tfc)
		pstats_ipsec_tfc++;
}

void lswlog_child_sa_established(struct lswlog *buf, struct state *st)
{
	struct connection *const c = st->st_connection;
	const char *ini = " {";

	lswlogs(buf, c->policy & POLICY_TUNNEL ? " tunnel mode" : " transport mode");

	/* don't count IKEv1 half ipsec sa */
	if (st->st_state == STATE_QUICK_R1) {
		pstats_ipsec_sa++;
	}

	if (st->st_esp.present) {
		bool nat = (st->hidden_variables.st_nat_traversal & NAT_T_DETECTED) != 0;
		bool tfc = c->sa_tfcpad != 0 && !st->st_seen_no_tfc;
		bool esn = st->st_esp.attrs.transattrs.esn_enabled;

		if (nat)
			DBGF(DBG_NATT, "NAT-T: NAT Traversal detected - their IKE port is '%d'",
			     c->spd.that.host_port);

		DBGF(DBG_NATT, "NAT-T: encaps is '%s'",
		     c->encaps == yna_auto ? "auto" : bool_str(c->encaps == yna_yes));

		lswlogf(buf, "%sESP%s%s%s=>0x%08" PRIx32 " <0x%08" PRIx32 "",
			ini,
			nat ? "/NAT" : "",
			esn ? "/ESN" : "",
			tfc ? "/TFC" : "",
			ntohl(st->st_esp.attrs.spi),
			ntohl(st->st_esp.our_spi));
		lswlogf(buf, " xfrm=%s", st->st_esp.attrs.transattrs.ta_encrypt->common.fqn);
		/* log keylen when it is required and/or "interesting" */
		if (!st->st_esp.attrs.transattrs.ta_encrypt->keylen_omitted ||
		    (st->st_esp.attrs.transattrs.enckeylen != 0 &&
		     st->st_esp.attrs.transattrs.enckeylen != st->st_esp.attrs.transattrs.ta_encrypt->keydeflen)) {
			lswlogf(buf, "_%u", st->st_esp.attrs.transattrs.enckeylen);
		}
		lswlogf(buf, "-%s", st->st_esp.attrs.transattrs.ta_integ->common.fqn);

		if (st->st_ikev2 && st->st_pfs_group != NULL)  {
			lswlogs(buf, "-");
			lswlogs(buf, st->st_pfs_group->common.name);
		}

		ini = " ";

		pstats_ipsec_esp++;
		pstatsv(ipsec_encrypt, st->st_ikev2,
			st->st_esp.attrs.transattrs.ta_encrypt->common.id[IKEv1_ESP_ID],
			st->st_esp.attrs.transattrs.ta_encrypt->common.id[IKEv2_ALG_ID]);
		pstatsv(ipsec_integ, st->st_ikev2,
			st->st_esp.attrs.transattrs.ta_integ->common.id[IKEv1_ESP_ID],
			st->st_esp.attrs.transattrs.ta_integ->common.id[IKEv2_ALG_ID]);
		pstats_sa(nat, tfc, esn);
	}

	if (st->st_ah.present) {
		bool esn = st->st_esp.attrs.transattrs.esn_enabled;

		lswlogf(buf, "%sAH%s=>0x%08" PRIx32 " <0x%08" PRIx32 " xfrm=%s",
			ini,
			st->st_ah.attrs.transattrs.esn_enabled ? "/ESN" : "",
			ntohl(st->st_ah.attrs.spi),
			ntohl(st->st_ah.our_spi),
			st->st_ah.attrs.transattrs.ta_integ->common.fqn);

		ini = " ";

		pstats_ipsec_ah++;
		pstatsv(ipsec_integ, st->st_ikev2,
			st->st_ah.attrs.transattrs.ta_integ->common.id[IKEv1_ESP_ID],
			st->st_ah.attrs.transattrs.ta_integ->common.id[IKEv2_ALG_ID]);
		pstats_sa(FALSE, FALSE, esn);
	}

	if (st->st_ipcomp.present) {
		lswlogf(buf, "%sIPCOMP=>0x%08" PRIx32 " <0x%08" PRIx32,
			ini,
			ntohl(st->st_ipcomp.attrs.spi),
			ntohl(st->st_ipcomp.our_spi));

		ini = " ";

		pstats_ipsec_ipcomp++;
	}

	lswlogs(buf, ini);
	lswlogs(buf, "NATOA=");
	/* XXX: can lswlog_ip() be used? */
	ipstr_buf ipb;
	lswlogs(buf, isanyaddr(&st->hidden_variables.st_nat_oa) ? "none" :
		ipstr(&st->hidden_variables.st_nat_oa, &ipb));

	lswlogs(buf, " NATD=");

	if (isanyaddr(&st->hidden_variables.st_natd)) {
		lswlogs(buf, "none");
	} else {
		/* XXX: can lswlog_ip() be used?  need to check st_remoteport */
		char oa[ADDRTOT_BUF + sizeof(":00000")];
		snprintf(oa, sizeof(oa),
			 "%s:%d",
			 sensitive_ipstr(&st->hidden_variables.st_natd, &ipb),
			 st->st_remoteport);
		lswlogs(buf, oa);
	}

	lswlogf(buf, dpd_active_locally(st) ? " DPD=active" : " DPD=passive");

	if (st->st_xauth_username[0] != '\0') {
		lswlogs(buf, " username=");
		lswlogs(buf, st->st_xauth_username);
	}

	lswlogs(buf, "}");
}

void lswlog_ike_sa_established(struct lswlog *buf, struct state *st)
{
	passert(st->st_oakley.ta_encrypt != NULL);
	passert(st->st_oakley.ta_prf != NULL);
	passert(st->st_oakley.ta_dh != NULL);

	lswlogs(buf, " {auth=");
	if (st->st_ikev2) {
		lswlogs(buf, "IKEv2");
	} else {
		lswlog_enum_short(buf, &oakley_auth_names, st->st_oakley.auth);
	}

	lswlogf(buf, " cipher=%s", st->st_oakley.ta_encrypt->common.fqn);
	if (st->st_oakley.enckeylen > 0) {
		/* XXX: also check omit key? */
		lswlogf(buf, "_%d", st->st_oakley.enckeylen);
	}

	/*
	 * Note: for IKEv1 and AEAD encrypters,
	 * st->st_oakley.ta_integ is 'none'!
	 */
	lswlogs(buf, " integ=");
	if (st->st_ikev2) {
		if (st->st_oakley.ta_integ == &ike_alg_integ_none) {
			lswlogs(buf, "n/a");
		} else {
			lswlogs(buf, st->st_oakley.ta_integ->common.fqn);
		}
	} else {
		/*
		 * For IKEv1, since the INTEG algorithm is potentially
		 * (always?) NULL.  Display the PRF.  The choice and
		 * behaviour are historic.
		 */
		lswlogs(buf, st->st_oakley.ta_prf->common.fqn);
	}

	if (st->st_ikev2) {
		lswlogf(buf, " prf=%s", st->st_oakley.ta_prf->common.fqn);
	}

	lswlogf(buf, " group=%s}", st->st_oakley.ta_dh->common.fqn);

	/* keep IKE SA statistics */
	if (st->st_ikev2) {
		pstats_ikev2_sa++;
		pstats(ikev2_encr, st->st_oakley.ta_encrypt->common.id[IKEv2_ALG_ID]);
		if (st->st_oakley.ta_integ != NULL)
			pstats(ikev2_integ, st->st_oakley.ta_integ->common.id[IKEv2_ALG_ID]);
		pstats(ikev2_groups, st->st_oakley.ta_dh->group);
	} else {
		pstats_ikev1_sa++;
		pstats(ikev1_encr, st->st_oakley.ta_encrypt->common.ikev1_oakley_id);
		pstats(ikev1_integ, st->st_oakley.ta_prf->common.id[IKEv1_OAKLEY_ID]);
		pstats(ikev1_groups, st->st_oakley.ta_dh->group);
	}
}
