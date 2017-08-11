/*
 * IKEv2 parent SA creation routines, for Libreswan
 *
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi
 * Copyright (C) 2012-2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012-2017 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013-2016 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2015-2017 Andrew Cagney
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#include <pthread.h>    /* Must be the first include file */
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include <libreswan.h>
#include <errno.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "state.h"
#include "id.h"
#include "connections.h"

#include "crypto.h"
#include "x509.h"
#include "pluto_x509.h"
#include "ike_alg.h"
#include "kernel_alg.h"
#include "plutoalg.h"
#include "pluto_crypt.h"
#include "packet.h"
#include "demux.h"
#include "ikev2.h"
#include "log.h"
#include "spdb.h"          /* for out_sa */
#include "ipsec_doi.h"
#include "vendor.h"
#include "timer.h"
#include "cookie.h"
#include "rnd.h"
#include "pending.h"
#include "kernel.h"
#include "nat_traversal.h"
#include "alg_info.h" /* for ike_info / esp_info */
#include "key.h" /* for SECKEY_DestroyPublicKey */
#include "vendor.h"
#include "ike_alg_sha2.h"
#include "crypt_hash.h"
#include "ikev2_ipseckey.h"
#include "xauth.h"

#include "ietf_constants.h"

#include "hostpair.h"

#include "pluto_stats.h"

static stf_status ikev2_parent_inI2outR2_auth_tail( struct msg_digest *md, bool pam_status);

//static crypto_req_cont_func ikev2_parent_outI1_continue;	/* type assertion */

static void ikev2_get_dcookie(u_char *dcookie, chunk_t st_ni,
			      ip_address *addr, chunk_t spiI);

static stf_status ikev2_parent_outI1_common(struct msg_digest *md,
					    struct state *st);

static int build_ikev2_version(void);

void ikev2_isakamp_established(struct state *st, const struct state_v2_microcode *svm,
		enum state_kind new_state, enum original_role role)
{
	struct connection *c = st->st_connection;
	/*
	 * taking it current from current state I2/R1. The parent has advanced but not the svm???
	 * Ideally this should be timeout of I3/R2 state svm. how to find that svm
	 * ??? I wonder what this comment means?  Needs rewording.
	 */
	enum event_type kind = svm->timeout_event;
	time_t delay;

	/*
	 * update the parent state to make sure that it knows we have
	 * authenticated properly.
	 */
	change_state(st, new_state);

	if (st->st_ike_pred != SOS_NOBODY) {
		for_each_state(ikev2_repl_est_ipsec, &st->st_ike_pred);
	}
	c->newest_isakmp_sa = st->st_serialno;
	delay = ikev2_replace_delay(st, &kind, role);
	delete_event(st);
	event_schedule(kind, delay, st);
}

/*
 * This code assumes that the encrypted part of an IKE message starts
 * with an Initialization Vector (IV) of enc_blocksize of random octets.
 * The IV will subsequently be discarded after decryption.
 * This is true of Cipher Block Chaining mode (CBC).
 */
static bool emit_wire_iv(const struct state *st, pb_stream *pbs)
{
	size_t wire_iv_size = st->st_oakley.encrypter->wire_iv_size;
	unsigned char ivbuf[MAX_CBC_BLOCK_SIZE];

	passert(wire_iv_size <= MAX_CBC_BLOCK_SIZE);
	get_rnd_bytes(ivbuf, wire_iv_size);
	return out_raw(ivbuf, wire_iv_size, pbs, "IV");
}

static stf_status add_st_send_list(struct state *st, struct state *pst)
{
	msgid_t unack = pst->st_msgid_nextuse - pst->st_msgid_lastack - 1;
	stf_status e = STF_OK;
	char  *what;

	if (unack < st->st_connection->ike_window) {
		what  =  "send new exchange now";
	} else  {
		struct initiate_list *n = alloc_thing(struct initiate_list,
				"struct initiate_list");
		struct initiate_list *p;

		e = STF_SUSPEND;
		n->st_serialno = st->st_serialno;

		what = "wait sending, add to send next list";
		delete_event(st);
		event_schedule(EVENT_SA_REPLACE, MAXIMUM_RESPONDER_WAIT, st);

		for (p = pst->send_next_ix; (p != NULL && p->next != NULL);
				p = p->next) {
		}

		if (p == NULL) {
			pst->send_next_ix = n;
		} else {
			p->next = n;
		}
	}
	DBG(DBG_CONTROLMORE, DBG_log("#%lu %s using parent #%lu "
				"unacknowledged %u next message id="
				"%u ike excange window %u", st->st_serialno,
				what, pst->st_serialno, unack,
				pst->st_msgid_nextuse,
				pst->st_connection->ike_window));
	return e;
}

static void ikev2_crypto_continue(struct pluto_crypto_req_cont *cn,
		struct pluto_crypto_req *r);

static stf_status ikev2_rekey_dh_start(struct pluto_crypto_req *r,
		struct msg_digest *md)
{

	struct state *const st = md->st;
	struct state *pst = state_with_serialno(st->st_clonedfrom);
	stf_status e = STF_OK;


	if (md->chain[ISAKMP_NEXT_v2KE] == NULL)
		return STF_OK;

	if (r->pcr_type == pcr_build_ke_and_nonce) {
		enum original_role  role;
		role = IS_CHILD_SA_RESPONDER(st) ? ORIGINAL_RESPONDER :
			ORIGINAL_INITIATOR;
		if (pst == NULL) {
			loglog(RC_LOG_SERIOUS, "#%lu can not find parent state "
					"#%lu to setup DH v2", st->st_serialno,
					st->st_clonedfrom);
			return STF_FAIL;
		}
		passert(st->st_sec_in_use == TRUE); /* child has its own KE */

		/* initiate calculation of g^xy */
		e = start_dh_v2(md, "DHv2 for child sa", role,
				pst->st_skey_d_nss, /* only IKE has SK_d */
				pst->st_oakley.prf, /* for IKE/ESP/AH */
				ikev2_crypto_continue);
	}
	return e;
}

/* redundant type assertion: static crypto_req_cont_func ikev2_crypto_continue; */
static void ikev2_crypto_continue(struct pluto_crypto_req_cont *cn,
		struct pluto_crypto_req *r)
{
	struct msg_digest *md = cn->pcrc_md;
	struct state *const st = md->st;
	struct state *pst;
	stf_status e = STF_OK;
	bool only_shared = FALSE;

	DBG(DBG_CRYPT | DBG_CONTROL,
		DBG_log("ikev2_crypto_continue for #%lu: %s", cn->pcrc_serialno,
			cn->pcrc_name));
	if (cn->pcrc_serialno == SOS_NOBODY) {
		loglog(RC_LOG_SERIOUS,
		       "%s: Request was disconnected from state", __FUNCTION__);
		release_any_md(&cn->pcrc_md);
		return;
	}

	passert(cn->pcrc_serialno == st->st_serialno);	/* transitional */

	passert(cur_state == NULL);
	passert(st != NULL);

	pst = IS_CHILD_SA(st) ? state_with_serialno(st->st_clonedfrom) : st;
	passert(pst != NULL);

	passert(st->st_suspended_md == cn->pcrc_md);
	unset_suspended(st); /* no longer connected or suspended */
	set_cur_state(st);

	st->st_calculating = FALSE;
	DBG(DBG_CONTROLMORE, DBG_log("#%lu %s:%u st->st_calculating = FALSE;", st->st_serialno, __FUNCTION__, __LINE__));

	switch (st->st_state) {

	case STATE_PARENT_I1:
		/* tail function will extract crypto results */
		break;

	case STATE_V2_CREATE_I0:
		unpack_nonce(&st->st_ni, r);
		if (r->pcr_type == pcr_build_ke_and_nonce)
			unpack_KE_from_helper(st, r, &st->st_gi);

		e = add_st_send_list(st, pst);
		if (e == STF_SUSPEND)
			set_suspended(st, md);
		break;

	case STATE_V2_REKEY_IKE_I0:
		unpack_nonce(&st->st_ni, r);
		unpack_KE_from_helper(st, r, &st->st_gi);
		break;

	case STATE_V2_CREATE_I:
		only_shared = TRUE;
		if (!finish_dh_v2(st, r, only_shared))
			e = STF_FAIL + v2N_INVALID_KE_PAYLOAD;
		break;

	case STATE_V2_CREATE_R:
	case STATE_V2_REKEY_CHILD_R:
		only_shared = TRUE;
		/* FALL THROUGH*/
	case STATE_V2_REKEY_IKE_R:
		if (r->pcr_type == pcr_compute_dh_v2) {
			if (!finish_dh_v2(st, r, only_shared))
				e = STF_FAIL + v2N_INVALID_KE_PAYLOAD;
		} else {
			unpack_nonce(&st->st_nr, r);
			if (md->chain[ISAKMP_NEXT_v2KE] != NULL &&
					r->pcr_type == pcr_build_ke_and_nonce){
				unpack_KE_from_helper(st, r, &st->st_gr);
			}
			e = ikev2_rekey_dh_start(r,md); /* STF_SUSPEND | OK */
		}
		break;
	default :
		bad_case(st->st_state);
	}

	if (e == STF_OK) {
		e = md->svm->crypto_end(cn, r);
	}

	passert(cn->pcrc_md != NULL);
	complete_v2_state_transition(&cn->pcrc_md, e);
	release_any_md(&cn->pcrc_md);
	reset_globals();
}

/*
 * We need an md because the crypto continuation mechanism requires one
 * but we don't have one because we are not responding to an
 * incoming packet.
 * Solution: build a fake one.  How much do we need to fake?
 * Note: almost identical code appears at the end of aggr_outI1.
 */
static stf_status ikev2_crypto_start(struct msg_digest *md, struct state *st)
{
	struct msg_digest *fake_md = NULL;
	struct pluto_crypto_req_cont *ke;
	stf_status e = STF_OK;
	char  *what = "";
	enum crypto_importance ci = pcim_stranger_crypto;

	if (md == NULL) {
		fake_md = alloc_md("msg_digest by ikev2_crypto_start()");
		fake_md->st = st;
		fake_md->from_state = STATE_IKEv2_BASE;
		fake_md->msgid_received = v2_INVALID_MSGID;
		md = fake_md;
	}

	switch (st->st_state) {
	case STATE_PARENT_I1:
		fake_md->svm = &ikev2_parent_firststate_microcode;
		what = "ikev2_outI1 KE";
		break;

	case STATE_V2_REKEY_CHILD_I0:
		fake_md->svm = &ikev2_rekey_ike_firststate_microcode;
		ci = pcim_known_crypto;
		what = (st->st_pfs_group == NULL) ? "Child Rekey Initiator nonce ni" :
			"Child Rekey Initiator KE and nonce ni";
		break;

	case STATE_V2_REKEY_IKE_R:
		ci = pcim_known_crypto;
		what = "IKE rekey KE response gir";
		break;

	case STATE_V2_CREATE_R:
		ci = pcim_known_crypto;
		what = md->chain[ISAKMP_NEXT_v2KE] == NULL ?
			"Child Responder nonce nr" :
			"Child Responder KE and nonce nr";
		break;

	case STATE_V2_REKEY_CHILD_R:
		ci = pcim_known_crypto;
		what = md->chain[ISAKMP_NEXT_v2KE] == NULL ?
			"Child Rekey Responder nonce nr" :
			"Child Rekey Responder KE and nonce nr";
		break;

	case STATE_V2_CREATE_I0:
		fake_md->svm = &ikev2_create_child_initiate_microcode;
		ci = pcim_known_crypto;
		what = (st->st_pfs_group == NULL) ? "Child Initiator nonce ni" :
			"Child Initiator KE and nonce ni";
		break;

	case STATE_V2_CREATE_I:
		ci = pcim_known_crypto;
		what = "ikev2 Child SA initiator pfs=yes";
		/* DH will call its own new_pcrc */
		break;

	default:
		bad_case(st->st_state);
		break;
	}

	if (st->st_state != STATE_V2_CREATE_I)
		ke = new_pcrc(ikev2_crypto_continue, what, st, md);

	switch (st->st_state) {

	case STATE_PARENT_I1:
		/* if we received INVALID_KE, msgid was incremented */
		st->st_msgid_lastack = v2_INVALID_MSGID;
		st->st_msgid_lastrecv = v2_INVALID_MSGID;
		st->st_msgid_nextuse = 0;
		st->st_msgid = 0;
		/* fall through */
	case STATE_V2_REKEY_IKE_R:
		e = build_ke_and_nonce(ke, st->st_oakley.group, ci);
		break;

	case STATE_V2_CREATE_R:
	case STATE_V2_REKEY_CHILD_R:
		if (md->chain[ISAKMP_NEXT_v2KE] != NULL) {
			e = build_ke_and_nonce(ke, st->st_oakley.group, ci);
		} else {
			e = build_nonce(ke, ci);
		}
		break;

	case STATE_V2_REKEY_CHILD_I0:
	case STATE_V2_CREATE_I0:
		if (st->st_pfs_group == NULL) {
			e = build_nonce(ke, ci);
		} else {
			e = build_ke_and_nonce(ke, st->st_pfs_group, ci);
		}
		break;

	case STATE_V2_CREATE_I:
		e = start_dh_v2(md, "ikev2 Child SA initiator pfs=yes",
				ORIGINAL_INITIATOR, NULL, st->st_oakley.prf,
				ikev2_crypto_continue);
		break;

	default:
		break;
	}

	reset_globals();
	return e;
}

/*
 * Check the MODP (KE) group matches the accepted proposal.
 *
 * The caller is responsible for freeing any scratch objects.
 */
static stf_status ikev2_match_ke_group_and_proposal(struct msg_digest *md,
						    const struct oakley_group_desc *accepted_dh)
{
	passert(md->chain[ISAKMP_NEXT_v2KE] != NULL);
	int ke_group = md->chain[ISAKMP_NEXT_v2KE]->payload.v2ke.isak_group;
	if (accepted_dh->common.id[IKEv2_ALG_ID] != ke_group) {
		struct esb_buf ke_esb;
		libreswan_log("initiator guessed wrong keying material group (%s); responding with INVALID_KE_PAYLOAD requesting %s",
			      enum_show_shortb(&oakley_group_names,
					       ke_group, &ke_esb),
			      accepted_dh->common.name);
		pstats(invalidke_sent_u, ke_group);
		pstats(invalidke_sent_s, accepted_dh->common.id[IKEv2_ALG_ID]);
		send_v2_notification_invalid_ke(md, accepted_dh);
		pexpect(md->st == NULL);
		return STF_FAIL;
	}

	return STF_OK;
}

/*
 * Called by ikev2_parent_inI2outR2_tail() and ikev2parent_inR2()
 * Do the actual AUTH payload verification
 */
static bool v2_check_auth(enum ikev2_auth_method atype,
		   struct state *st,
		   const enum original_role role,
		   unsigned char idhash_in[MAX_DIGEST_LEN],
		   pb_stream *pbs,
		   const enum keyword_authby that_authby)
{

	switch (atype) {
	case IKEv2_AUTH_RSA:
	{
		if (that_authby != AUTH_RSASIG) {
			libreswan_log("Peer attempted RSA authentication but we want %s",
				enum_name(&ikev2_asym_auth_name, that_authby));
			return FALSE;
		}

		stf_status authstat = ikev2_verify_rsa_sha1(
				st,
				role,
				idhash_in,
				pbs);

		if (authstat != STF_OK) {
			libreswan_log("RSA authentication failed");
			return FALSE;
		}
		return TRUE;
	}

	case IKEv2_AUTH_PSK:
	{
		if (that_authby != AUTH_PSK) {
			libreswan_log("Peer attempted PSK authentication but we want %s",
				enum_name(&ikev2_asym_auth_name, that_authby));
			return FALSE;
		}

               stf_status authstat = ikev2_verify_psk_auth(
                               that_authby, st, idhash_in,
                               pbs);

               if (authstat != STF_OK) {
                       libreswan_log("PSK Authentication failed: AUTH mismatch!");
                       return FALSE;
               }
               return TRUE;
	}

	case IKEv2_AUTH_NULL:
	{
		if (that_authby != AUTH_NULL) {
			libreswan_log("Peer attempted NULL authentication but we want %s",
				enum_name(&ikev2_asym_auth_name, that_authby));
			return FALSE;
		}

		stf_status authstat = ikev2_verify_psk_auth(
				that_authby, st, idhash_in,
				pbs);

		if (authstat != STF_OK) {
			libreswan_log("NULL Authentication failed: AUTH mismatch! (implementation bug?)");
			return FALSE;
		}
		return TRUE;
	}

	default:
	{
		libreswan_log("authentication method: %s not supported",
			      enum_name(&ikev2_auth_names, atype));
		return FALSE;
	}

	}
}

static bool id_ipseckey_allowed(struct state *st, enum ikev2_auth_method atype)
{
	struct id id = st->st_connection->spd.that.id;
	const struct connection *c = st->st_connection;
	const char *err1 = "%dnsondemand";
	const char *err2 = "";
	const char *err21 = "";
	const char *err3 = "ID_FQDN";
	const char *err31 = "";
	char thatid[IDTOA_BUF];
	ipstr_buf ra;

	if (c->spd.that.key_from_DNS_on_demand &&
			c->spd.that.authby == AUTH_RSASIG &&
			(id.kind == ID_FQDN ||
			 id.kind == ID_IPV4_ADDR ||
			 id.kind == ID_IPV6_ADDR)) {
		if (atype == IKEv2_AUTH_RESERVED) {
			return FALSE; /* called from the initiator */
		} else if (atype == IKEv2_AUTH_RSA) {
			return FALSE; /* success */
		}
	}

	idtoa(&id, thatid, sizeof(thatid));

	if (!c->spd.that.key_from_DNS_on_demand)
	{
		err1 = "that end rsasigkey != %dnsondemand";
	}

	if (atype != IKEv2_AUTH_RESERVED && atype != IKEv2_AUTH_RSA) {
		err2 = "initiator IKEv2 Auth Method is not IKEv2_AUTH_RSA, ";
		err3 = enum_name(&ikev2_auth_names, atype);
	}

	if (id.kind != ID_FQDN &&
			id.kind != ID_IPV4_ADDR &&
			id.kind != ID_IPV6_ADDR) {
		err2 = " can only query DNS for IPSECKEY for ID that is a FQDN, IPV4_ADDR, or IPV6_ADDR id type=";
		err21 = enum_show(&ike_idtype_names, id.kind);
	}

	DBG(DBG_CONTROLMORE, DBG_log("%s #%lu not fetching ipseckey "
			"%s %s%s %s%s remote=%s thatid=%s",
			c->name, st->st_serialno,
			err1, err2, err21, err3, err31,
			ipstr(&st->st_remoteaddr, &ra), thatid));
	return TRUE;
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
stf_status ikev2parent_outI1(int whack_sock,
			     struct connection *c,
			     struct state *predecessor,
			     lset_t policy,
			     unsigned long try,
			     enum crypto_importance importance
#ifdef HAVE_LABELED_IPSEC
			     , struct xfrm_user_sec_ctx_ike *uctx
#endif
			     )
{
	struct state *st;

	if (drop_new_exchanges()) {
		/* Only drop outgoing opportunistic connections */
		if (c->policy & POLICY_OPPORTUNISTIC) {
			return STF_IGNORE;
		}
	}

	st = new_state();

	/* set up new state */
	get_cookie(TRUE, st->st_icookie, &c->spd.that.host_addr);
	initialize_new_state(st, c, policy, try, whack_sock, importance);
	st->st_ikev2 = TRUE;
	change_state(st, STATE_PARENT_I1);
	st->st_original_role = ORIGINAL_INITIATOR;
	st->st_msgid_lastack = v2_INVALID_MSGID;
	st->st_msgid_lastrecv = v2_INVALID_MSGID;
	st->st_msgid_nextuse = 0;
	st->st_try = try;

	if (HAS_IPSEC_POLICY(policy)) {
#ifdef HAVE_LABELED_IPSEC
		st->sec_ctx = NULL;
		if (uctx != NULL)
			libreswan_log(
				"Labeled ipsec is not supported with ikev2 yet");
#endif

		add_pending(dup_any(whack_sock), st, c, policy, 1,
			    predecessor == NULL ? SOS_NOBODY : predecessor->st_serialno
#ifdef HAVE_LABELED_IPSEC
			    , st->sec_ctx
#endif
			    );
	}

	if (predecessor != NULL) {
		if ((c->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
			libreswan_log("initiating v2 parent SA to replace #%lu",
				predecessor->st_serialno);
		}
		if (IS_V2_ESTABLISHED( predecessor->st_state)) {
			if (IS_CHILD_SA(st))
				st->st_ipsec_pred = predecessor->st_serialno;
			else
				st->st_ike_pred = predecessor->st_serialno;
		}
		update_pending(predecessor, st);
		whack_log(RC_NEW_STATE + STATE_PARENT_I1,
			  "%s: initiate, replacing #%lu",
			  enum_name(&state_names, st->st_state),
			  predecessor->st_serialno);
	} else {
		if ((c->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
			libreswan_log("initiating v2 parent SA");
		}
		whack_log(RC_NEW_STATE + STATE_PARENT_I1, "%s: initiate",
			  enum_name(&state_names, st->st_state));
	}

	if (IS_LIBUNBOUND && !id_ipseckey_allowed(st, IKEv2_AUTH_RESERVED)) {
		stf_status ret = idr_ipseckey_fetch(st);
		if (ret != STF_OK)
			return ret;
	}

	/*
	 * Initialize st->st_oakley, including the group number.
	 * Grab the DH group from the first configured proposal and build KE.
	 */
	{
		ikev2_proposals_from_alg_info_ike(c->name,
						  "initial initiator (selecting KE)",
						  c->alg_info_ike,
						  &c->ike_proposals);
		passert(c->ike_proposals != NULL);
		st->st_oakley.group = ikev2_proposals_first_modp(c->ike_proposals);
		passert(st->st_oakley.group != NULL); /* known! */

		/*
		 * Calculate KE and Nonce.
		 */
		stf_status e = ikev2_crypto_start(NULL, st);
		reset_globals();
		return e;
	}
}

/*
 * package up the calculated KE value, and emit it as a KE payload.
 * used by IKEv2: parent, child (PFS)
 */
bool justship_v2KE(chunk_t *g, const struct oakley_group_desc *group,
			  pb_stream *outs, u_int8_t np)
{
	struct ikev2_ke v2ke;
	pb_stream kepbs;

	zero(&v2ke);	/* OK: no pointer fields */
	v2ke.isak_np = np;
	v2ke.isak_group = group->common.id[IKEv2_ALG_ID];
	if (!out_struct(&v2ke, &ikev2_ke_desc, outs, &kepbs))
		return FALSE;

	if (DBGP(IMPAIR_SEND_ZERO_GX))	{
		libreswan_log("sending bogus g^x == 0 value to break DH calculations because impair-send-zero-gx was set");
		/* Only used to test sending/receiving bogus g^x */
		if (!out_zero(g->len, &kepbs, "ikev2 impair g^x == 0"))
			return FALSE;
	} else {
		if (!out_chunk(*g, &kepbs, "ikev2 g^x"))
			return FALSE;
	}

	close_output_pbs(&kepbs);
	return TRUE;
}

stf_status ikev2_parent_outI1_tail(struct pluto_crypto_req_cont *ke,
					  struct pluto_crypto_req *r)
{
	struct msg_digest *md = ke->pcrc_md;
	struct state *const st = md->st;

	DBG(DBG_CONTROL,
		DBG_log("ikev2_parent_outI1_tail for #%lu",
			ke->pcrc_serialno));

	passert(ke->pcrc_serialno == st->st_serialno);	/* transitional */

	unpack_KE_from_helper(st, r, &st->st_gi);
	unpack_nonce(&st->st_ni, r);
	return ikev2_parent_outI1_common(md, st);
}

static stf_status ikev2_parent_outI1_common(struct msg_digest *md,
					    struct state *st)
{
	struct connection *c = st->st_connection;
	int vids = 0;

	/* set up reply */
	init_out_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		 "reply packet");

	/* remember how many VID's we are going to send */
	if (c->policy & POLICY_AUTH_NULL)
		vids++;
	if (c->send_vendorid)
		vids++;
	if (c->fake_strongswan)
		vids++;

	if (DBGP(IMPAIR_SEND_BOGUS_DCOOKIE)) {
		/* add or mangle a dcookie so what we will send is bogus */
		DBG_log("Mangling dcookie because --impair-send-bogus-dcookie is set");
		freeanychunk(st->st_dcookie);
		st->st_dcookie.ptr = alloc_bytes(1, "mangled dcookie");
		st->st_dcookie.len = 1;
		messupn(st->st_dcookie.ptr, 1);
	}

	/* HDR out */
	{
		struct isakmp_hdr hdr;

		zero(&hdr);	/* OK: no pointer fields */
		/* Impair function will raise major/minor by 1 for testing */
		hdr.isa_version = build_ikev2_version();

		hdr.isa_np = st->st_dcookie.ptr != NULL ?
			ISAKMP_NEXT_v2N : ISAKMP_NEXT_v2SA;
		hdr.isa_xchg = ISAKMP_v2_SA_INIT;
		hdr.isa_msgid = v2_INITIAL_MSGID;
		memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
		/* R-cookie left as zero */

		/* add original initiator flag - version flag could be set */
		hdr.isa_flags = ISAKMP_FLAGS_v2_IKE_I;
		if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
			hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
		}

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_stream,
				&md->rbody)) {
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}
	/*
	 * http://tools.ietf.org/html/rfc5996#section-2.6
	 * reply with the anti DDOS cookie if we received one (remote is under attack)
	 */
	if (st->st_dcookie.ptr != NULL) {
		/* In v2, for parent, protoid must be 0 and SPI must be empty */
		if (!ship_v2N(ISAKMP_NEXT_v2SA,
			 DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG) ?
			   (ISAKMP_PAYLOAD_NONCRITICAL |
			    ISAKMP_PAYLOAD_LIBRESWAN_BOGUS) :
			   ISAKMP_PAYLOAD_NONCRITICAL,
			 PROTO_v2_RESERVED,
			 &empty_chunk,
			 v2N_COOKIE, &st->st_dcookie, &md->rbody))
			return STF_INTERNAL_ERROR;
	}
	/* SA out */
	{
		u_char *sa_start = md->rbody.cur;

		if (!DBGP(IMPAIR_SEND_IKEv2_KE)) {
			ikev2_proposals_from_alg_info_ike(c->name, "initial initiator",
							  c->alg_info_ike,
							  &c->ike_proposals);
			passert(c->ike_proposals != NULL);
			/*
			 * Since this is an initial IKE exchange, the
			 * SPI is emitted as is part of the packet
			 * header and not the proposal.  Hence the
			 * NULL SPIs.
			 */
			bool ret = ikev2_emit_sa_proposals(&md->rbody,
							   c->ike_proposals,
							   (chunk_t*)NULL,
							   ISAKMP_NEXT_v2KE);
			if (!ret) {
				libreswan_log("outsa fail");
				reset_cur_state();
				return STF_INTERNAL_ERROR;
			}
		} else {
			libreswan_log("SKIPPED sending KE payload because impair-send-ikev2-ke was set");
		}
		/* save initiator SA for later HASH */
		if (st->st_p1isa.ptr == NULL) {
			/* no leak! (MUST be first time) */
			clonetochunk(st->st_p1isa, sa_start,
				     md->rbody.cur - sa_start,
				     "SA in ikev2_parent_outI1_common");
		}
	}

	/* ??? from here on, this looks a lot like the end of ikev2_parent_inI1outR1_tail */

	/* send KE */
	if (!justship_v2KE(&st->st_gi, st->st_oakley.group,
			   &md->rbody, ISAKMP_NEXT_v2Ni))
		return STF_INTERNAL_ERROR;

	/* send NONCE */
	{
		int np = ISAKMP_NEXT_v2N;
		struct ikev2_generic in;
		pb_stream pb;

		zero(&in);	/* OK: no pointer fields */
		in.isag_np = np;
		in.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;
		if (DBGP(IMPAIR_SEND_BOGUS_PAYLOAD_FLAG)) {
			libreswan_log(
				" setting bogus ISAKMP_PAYLOAD_LIBRESWAN_BOGUS flag in ISAKMP payload");
			in.isag_critical |= ISAKMP_PAYLOAD_LIBRESWAN_BOGUS;
		}

		if (!out_struct(&in, &ikev2_nonce_desc, &md->rbody, &pb) ||
		    !out_chunk(st->st_ni, &pb, "IKEv2 nonce"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&pb);
	}

	/* Send fragmentation support notification */
	if (c->policy & POLICY_IKE_FRAG_ALLOW) {
		int np = ISAKMP_NEXT_v2N;

		if (!ship_v2N(np, ISAKMP_PAYLOAD_NONCRITICAL,
			      PROTO_v2_RESERVED, &empty_chunk,
			      v2N_IKEV2_FRAGMENTATION_SUPPORTED, &empty_chunk,
			      &md->rbody))
			return STF_INTERNAL_ERROR;
	}

	/* Send NAT-T Notify payloads */
	{
		int np = (vids != 0) ? ISAKMP_NEXT_v2V : ISAKMP_NEXT_v2NONE;
		struct ikev2_generic in;

		zero(&in);	/* OK: no pointer fields */
		in.isag_np = np;
		in.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;
		if (!ikev2_out_nat_v2n(np, &md->rbody, md))
			return STF_INTERNAL_ERROR;
	}

	/* From here on, only payloads left are Vendor IDs */
	if (c->send_vendorid) {
		vids--;
		int np = (vids != 0) ? ISAKMP_NEXT_v2V : ISAKMP_NEXT_v2NONE;

		if (!ikev2_out_generic_raw(np, &ikev2_vendor_id_desc, &md->rbody,
				     pluto_vendorid, strlen(pluto_vendorid),
				     "VID_LIBRESWANSELF"))
			return STF_INTERNAL_ERROR;
	}

	if (c->fake_strongswan) {
		vids--;
		int np = (vids != 0) ? ISAKMP_NEXT_v2V : ISAKMP_NEXT_v2NONE;

		if (!ikev2_out_generic_raw(np, &ikev2_vendor_id_desc, &md->rbody,
				     "strongSwan", strlen("strongSwan"),
				     "VID_STRONGSWAN"))
			return STF_INTERNAL_ERROR;
	}

	if (c->policy & POLICY_AUTH_NULL) {
		vids--;
		int np = (vids != 0) ? ISAKMP_NEXT_v2V : ISAKMP_NEXT_v2NONE;

		if (!ikev2_out_generic_raw(np, &ikev2_vendor_id_desc, &md->rbody,
				     "Opportunistic IPsec", strlen("Opportunistic IPsec"),
				     "VID_OPPORTUNISTIC"))
			return STF_INTERNAL_ERROR;
	}

	passert(vids == 0); /* Ensure we built a valid chain */

	if (!close_message(&md->rbody, st))
		return STF_INTERNAL_ERROR;

	close_output_pbs(&reply_stream);

	/* save packet for later signing */
	freeanychunk(st->st_firstpacket_me);
	clonetochunk(st->st_firstpacket_me, reply_stream.start,
		     pbs_offset(&reply_stream), "saved first packet");

	/* Transmit */
	record_outbound_ike_msg(st, &reply_stream, "reply packet for ikev2_parent_outI1_common");

	reset_cur_state();
	return STF_OK;
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

static crypto_req_cont_func ikev2_parent_inI1outR1_continue;	/* type assertion */

static stf_status ikev2_parent_inI1outR1_tail(
	struct pluto_crypto_req_cont *ke,
	struct pluto_crypto_req *r);

stf_status ikev2parent_inI1outR1(struct msg_digest *md)
{
	pexpect(md->st == NULL);	/* ??? where would a state come from? Duplicate packet? */

	bool seen_dcookie = FALSE;
	bool seen_ntfy_frag = FALSE;
	bool require_dcookie = require_ddos_cookies();
	struct payload_digest *ntfy;

	if (drop_new_exchanges()) {
		/* only log for debug to prevent disk filling up */
		DBG(DBG_CONTROL,DBG_log("pluto is overloaded with half-open IKE SAs - dropping IKE_INIT request"));
		return STF_IGNORE;
	}

	/* Process NOTIFY payloads, including checking for a DCOOKIE */
	for (ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
		switch (ntfy->payload.v2n.isan_type) {
		case v2N_COOKIE:
			DBG(DBG_CONTROLMORE, DBG_log("Received a NOTIFY payload of type COOKIE - we will verify the COOKIE"));
			seen_dcookie = TRUE;
			break;
		case v2N_ESP_TFC_PADDING_NOT_SUPPORTED:
		case v2N_USE_TRANSPORT_MODE:
			DBG(DBG_CONTROLMORE, DBG_log("Received unauthenticated %s notify in wrong exchange - ignored",
				enum_name(&ikev2_notify_names,
					ntfy->payload.v2n.isan_type)));
			break;
		case v2N_NAT_DETECTION_DESTINATION_IP:
		case v2N_NAT_DETECTION_SOURCE_IP:
			/* handled further below */
			break;
		case v2N_IKEV2_FRAGMENTATION_SUPPORTED:
			seen_ntfy_frag = TRUE;
			break;
		default:
			DBG(DBG_CONTROLMORE, DBG_log("Received unauthenticated %s notify - ignored",
				enum_name(&ikev2_notify_names,
					ntfy->payload.v2n.isan_type)));
		}
	}

	/*
	 * The RFC states we should ignore unexpected cookies. We purposefully
	 * violate the RFC and validate the cookie anyway. This prevents an
	 * attacker from being able to inject a lot of data used later to HMAC
	 */
	if (seen_dcookie || require_dcookie) {
		u_char dcookie[SHA2_256_DIGEST_SIZE];
		chunk_t dc, ni, spiI;

		setchunk(spiI, md->hdr.isa_icookie, COOKIE_SIZE);
		setchunk(ni, md->chain[ISAKMP_NEXT_v2Ni]->pbs.cur,
			md->chain[ISAKMP_NEXT_v2Ni]->payload.v2gen.isag_length);
		/*
		 * RFC 5996 Section 2.10
		 * Nonces used in IKEv2 MUST be randomly chosen, MUST be at
		 * least 128 bits in size, and MUST be at least half the key
		 * size of the negotiated pseudorandom function (PRF).
		 * (We can check for minimum 128bit length)
		 */

		/*
		 * XXX: Note that we check the nonce size in accept_v2_nonce() so this
		 * check is extra. I guess since we need to extract the nonce to calculate
		 * the cookie, it is cheap to check here and reject.
		 */

		if (ni.len < IKEv2_MINIMUM_NONCE_SIZE || IKEv2_MAXIMUM_NONCE_SIZE < ni.len) {
			/*
			 * If this were a DDOS, we cannot afford to log.
			 * We do log if we are debugging.
			 */
			DBG(DBG_CONTROL, DBG_log("Dropping message with insufficient length Nonce"));
			return STF_IGNORE;
		}

		ikev2_get_dcookie(dcookie, ni, &md->sender, spiI);
		dc.ptr = dcookie;
		dc.len = SHA2_256_DIGEST_SIZE;

		if (seen_dcookie) {
			const pb_stream *dc_pbs;
			chunk_t idc;

			DBG(DBG_CONTROLMORE,
			    DBG_log("received a DOS cookie in I1 verify it"));
			/* we received dcookie we send earlier verify it */
			if (md->chain[ISAKMP_NEXT_v2N]->payload.v2n.isan_spisize != 0) {
				DBG(DBG_CONTROLMORE, DBG_log(
					"DOS cookie contains non-zero length SPI - message discarded"
				));
				return STF_IGNORE;
			}

			dc_pbs = &md->chain[ISAKMP_NEXT_v2N]->pbs;
			idc.ptr = dc_pbs->cur;
			idc.len = pbs_left(dc_pbs);
			DBG(DBG_CONTROLMORE,
			    DBG_dump_chunk("received dcookie", idc);
			    DBG_dump("dcookie computed", dcookie,
				     SHA2_256_DIGEST_SIZE));

			if (idc.len != SHA2_256_DIGEST_SIZE ||
				!memeq(idc.ptr, dcookie, SHA2_256_DIGEST_SIZE)) {
				DBG(DBG_CONTROLMORE, DBG_log(
					"mismatch in DOS v2N_COOKIE: dropping message (possible attack)"
				));
				return STF_IGNORE;
			}
			DBG(DBG_CONTROLMORE, DBG_log(
				"dcookie received matched computed one"));
		} else {
			/* we are under DOS attack and I1 contains no COOKIE */
			DBG(DBG_CONTROLMORE,
			    DBG_log("busy mode on. received I1 without a valid dcookie");
			    DBG_log("send a dcookie and forget this state"));
			send_v2_notification_from_md(md, v2N_COOKIE, &dc);
			return STF_FAIL;
		}
	} else {
		DBG(DBG_CONTROLMORE,
		    DBG_log("anti-DDoS cookies not required (and no cookie received)"));
	}

	/* authentication policy alternatives in order of decreasing preference */
	static const lset_t policies[] = { POLICY_RSASIG, POLICY_PSK, POLICY_AUTH_NULL };

	lset_t policy;
	struct connection *c;
	stf_status e;
	unsigned int i;

	/* XXX in the near future, this loop should find type=passthrough and return STF_DROP */
	for (i=0; i < elemsof(policies); i++){
		policy = policies[i] | POLICY_IKEV2_ALLOW;
		e = ikev2_find_host_connection(&c, &md->iface->ip_addr,
				md->iface->port, &md->sender, md->sender_port,
				policy);
		if (e == STF_OK)
			break;
	}

	if (e != STF_OK) {
		ipstr_buf b;

		/* we might want to change this to a debug log message only */
		loglog(RC_LOG_SERIOUS, "initial parent SA message received on %s:%u but no suitable connection found with IKEv2 policy",
			ipstr(&md->iface->ip_addr, &b),
			ntohs(portof(&md->iface->ip_addr)));
		return e;
	}

	passert(c != NULL);	/* (e != STF_OK) == (c == NULL) */

	DBG(DBG_CONTROL, {
			char ci[CONN_INST_BUF];
		DBG_log("found connection: %s%s with policy %s",
			c->name, fmt_conn_instance(c, ci),
			bitnamesof(sa_policy_bit_names, policy));});

	/*
	 * Did we overlook a type=passthrough foodgroup?
	 */
	{
		struct connection *tmp = find_host_pair_connections(
			&md->iface->ip_addr, md->iface->port,
			(ip_address *)NULL, md->sender_port);

		for (; tmp != NULL; tmp = tmp->hp_next) {
			if ((tmp->policy & POLICY_SHUNT_MASK) != LEMPTY) {
				if (tmp->kind == CK_INSTANCE) {
					if (addrinsubnet(&md->sender, &tmp->spd.that.client)) {
						DBG(DBG_OPPO, DBG_log("passthrough conn %s also matches - check which has longer prefix match", tmp->name));

						if (c->spd.that.client.maskbits  < tmp->spd.that.client.maskbits) {
							DBG(DBG_OPPO, DBG_log("passthrough conn was a better match (%d bits versus conn %d bits) - suppressing NO_PROPSAL_CHOSEN reply",
								tmp->spd.that.client.maskbits,
								c->spd.that.client.maskbits));
							return STF_DROP;
						}
					}
				}
			}
		}
	}

	/* check if we would drop the packet based on VID before we create a state */
	if (md->chain[ISAKMP_NEXT_v2V] != NULL) {
		struct payload_digest *p = md->chain[ISAKMP_NEXT_v2V];

		DBG(DBG_CONTROLMORE, DBG_log("received at least one VID"));
                while (p != NULL) {
                        if (vid_is_oppo((char *)p->pbs.cur, pbs_left(&p->pbs))) {
				DBG(DBG_CONTROLMORE, DBG_log("received VID_OPPORTUNISTIC"));
				if (pluto_drop_oppo_null) {
					DBG(DBG_OPPO, DBG_log("Dropped IKE request for Opportunistic IPsec by global policy"));
					return STF_DROP; /* no state to delete */
				} else {
					DBG(DBG_OPPO, DBG_log("Processing IKE request for Opportunistic IPsec"));
				}
				break;
			}
                        p = p->next;
                }
	} else {
		DBG(DBG_OPPO, DBG_log("no Vendor ID's received - skipped check for VID_OPPORTUNISTIC"));
	}

	/* Vendor ID processing */
	{
		if (md->chain[ISAKMP_NEXT_v2V] != NULL) {
			struct payload_digest *v = md->chain[ISAKMP_NEXT_v2V];

			DBG(DBG_CONTROL, DBG_log("Processing VIDs"));
			while (v != NULL) {
				handle_vendorid(md, (char *)v->pbs.cur,
					pbs_left(&v->pbs), TRUE);
				v = v->next;
			}
		} else {
			DBG(DBG_CONTROL, DBG_log("no VIDs received"));
		}
	}

	/* Get the proposals ready.  */
	ikev2_proposals_from_alg_info_ike(c->name, "initial responder",
					  c->alg_info_ike,
					  &c->ike_proposals);
	passert(c->ike_proposals != NULL);

	/*
	 * Select the proposal.
	 */
	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_v2SA];
	struct ikev2_proposal *accepted_ike_proposal = NULL;
	stf_status ret = ikev2_process_sa_payload("IKE responder",
						  &sa_pd->pbs,
						  /*expect_ike*/ TRUE,
						  /*expect_spi*/ FALSE,
						  /*expect_accepted*/ FALSE,
						  c->policy & POLICY_OPPORTUNISTIC,
						  &accepted_ike_proposal,
						  c->ike_proposals);
	if (ret != STF_OK) {
		passert(accepted_ike_proposal == NULL);
		return ret;
	}
	passert(accepted_ike_proposal != NULL);
	DBG(DBG_CONTROL, DBG_log_ikev2_proposal("accepted IKE proposal", accepted_ike_proposal));

	/*
	 * Early return must free: accepted_ike_proposal
	 */

	/*
	 * Convert what was accepted to internal form and apply some
	 * basic validation.  If this somehow fails (it shouldn't but
	 * ...), drop everything.
	 */
	struct trans_attrs accepted_oakley;
	if (!ikev2_proposal_to_trans_attrs(accepted_ike_proposal, &accepted_oakley)) {
		loglog(RC_LOG_SERIOUS, "IKE responder accepted an unsupported algorithm");
		/* free early return items */
		free_ikev2_proposal(&accepted_ike_proposal);
		return STF_IGNORE;
	}

	/*
	 * Early return must free: accepted_ike_proposal
	 */

	/*
	 * Check the MODP group in the payload matches the accepted proposal.
	 */
	ret = ikev2_match_ke_group_and_proposal(md, accepted_oakley.group);
	if (ret != STF_OK) {
		free_ikev2_proposal(&accepted_ike_proposal);
		return ret;
	}

	/*
	 * Check and read the KE contents.
	 */
	chunk_t accepted_gi = empty_chunk;
	{
		/* note: v1 notification! */
		if (accept_KE(&accepted_gi, "Gi",
			      accepted_oakley.group,
			      &md->chain[ISAKMP_NEXT_v2KE]->pbs)
		    != NOTHING_WRONG) {
			/*
			 * A KE with the incorrect number of bytes is
			 * a syntax error and not a wrong modp group.
			 */
			freeanychunk(accepted_gi);
			free_ikev2_proposal(&accepted_ike_proposal);
			/* lower-layer will generate a notify.  */
			return STF_FAIL + v2N_INVALID_SYNTAX;
		}
	}

	/*
	 * Early return must free: accepted_ike_proposal, accepted_gi.
	 */

	/*
	 * We've committed to creating a state and, presumably,
	 * dedicating real resources to the connection.
	 */
	struct state *st = md->st;
	if (st == NULL) {
		st = new_state();
		/* set up new state */
		memcpy(st->st_icookie, md->hdr.isa_icookie, COOKIE_SIZE);
		/* initialize_new_state expects valid icookie/rcookie values, so create it now */
		get_cookie(FALSE, st->st_rcookie, &md->sender);
		initialize_new_state(st, c, policy, 0, NULL_FD,
				     pcim_stranger_crypto);
		update_ike_endpoints(st, md);
		st->st_ikev2 = TRUE;
		change_state(st, STATE_PARENT_R1);
		st->st_original_role = ORIGINAL_RESPONDER;
		st->st_msgid_lastack = v2_INVALID_MSGID;
		st->st_msgid_nextuse = 0;

		/* save the proposal information */
		st->st_oakley = accepted_oakley;
		st->st_accepted_ike_proposal = accepted_ike_proposal;
		st->st_gi = accepted_gi;

		md->st = st;
		md->from_state = STATE_IKEv2_BASE;

		if (seen_ntfy_frag)
			st->st_seen_fragvid = TRUE;
	} else {
		loglog(RC_LOG_SERIOUS, "Incoming non-duplicate packet already has state?");
		pexpect(st == NULL); /* fire an expect so test cases see it clearly */
		/* ??? should st->st_connection be changed to c? */
	}

	/*
	 * check v2N_NAT_DETECTION_DESTINATION_IP or/and
	 * v2N_NAT_DETECTION_SOURCE_IP
	 */
	if (md->chain[ISAKMP_NEXT_v2N] != NULL) {
		ikev2_natd_lookup(md, zero_cookie);
	}

	/* calculate the nonce and the KE */
	{
		struct pluto_crypto_req_cont *ke = new_pcrc(
			ikev2_parent_inI1outR1_continue, "ikev2_inI1outR1 KE",
			st, md);
		stf_status e;

		e = build_ke_and_nonce(ke, st->st_oakley.group,
			pcim_stranger_crypto);

		reset_globals();

		return e;
	}
}

/* redundant type assertion: static crypto_req_cont_func ikev2_parent_inI1outR1_continue; */

static void ikev2_parent_inI1outR1_continue(struct pluto_crypto_req_cont *ke,
					    struct pluto_crypto_req *r)
{
	struct msg_digest *md = ke->pcrc_md;
	struct state *const st = md->st;
	stf_status e;

	DBG(DBG_CONTROL,
		DBG_log("ikev2_parent_inI1outR1_continue for #%lu: calculated ke+nonce, sending R1",
			ke->pcrc_serialno));

	if (ke->pcrc_serialno == SOS_NOBODY) {
		loglog(RC_LOG_SERIOUS,
		       "%s: Request was disconnected from state",
		       __FUNCTION__);
		release_any_md(&ke->pcrc_md);
		return;
	}

	passert(ke->pcrc_serialno == st->st_serialno);	/* transitional */

	passert(cur_state == NULL);
	passert(st != NULL);

	passert(st->st_suspended_md == ke->pcrc_md);
	unset_suspended(st); /* no longer connected or suspended */

	set_cur_state(st);

	DBG(DBG_CONTROLMORE, DBG_log("#%lu %s:%u st->st_calculating = FALSE;", st->st_serialno, __FUNCTION__, __LINE__));
	st->st_calculating = FALSE;

	e = ikev2_parent_inI1outR1_tail(ke, r);

	passert(ke->pcrc_md != NULL);
	complete_v2_state_transition(&ke->pcrc_md, e);
	release_any_md(&ke->pcrc_md);
	reset_globals();
}

/*
 * ikev2_parent_inI1outR1_tail: do what's left after all the crypto
 *
 * Called from:
 *	ikev2parent_inI1outR1: if KE and Nonce were already calculated
 *	ikev2_parent_inI1outR1_continue: if they needed to be calculated
 */
static stf_status ikev2_parent_inI1outR1_tail(
	struct pluto_crypto_req_cont *ke,
	struct pluto_crypto_req *r)
{
	struct msg_digest *md = ke->pcrc_md;
	struct state *const st = md->st;
	struct connection *c = st->st_connection;
	bool send_certreq = FALSE;
	int vids = 0;

	passert(ke->pcrc_serialno == st->st_serialno);	/* transitional */

	/* note that we don't update the state here yet */

	/* record first packet for later checking of signature */
	clonetochunk(st->st_firstpacket_him, md->message_pbs.start,
		     pbs_offset(&md->message_pbs),
		     "saved first received packet");

	/* make sure HDR is at start of a clean buffer */
	init_out_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		 "reply packet");

	/* remember how many VID's we are going to send */
	if (c->policy & POLICY_AUTH_NULL)
		vids++;
	if (c->send_vendorid)
		vids++;
	if (c->fake_strongswan)
		vids++;

	/* HDR out */
	{
		struct isakmp_hdr hdr = md->hdr;

		memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
		hdr.isa_np = ISAKMP_NEXT_v2SA;
		hdr.isa_version = build_ikev2_version();

		/* set msg responder flag - clear other flags */
		hdr.isa_flags = ISAKMP_FLAGS_v2_MSG_R;
		if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
			hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
		}

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_stream,
				&md->rbody))
			return STF_INTERNAL_ERROR;
	}

	/* start of SA out */
	{
		enum next_payload_types_ikev2 next_payload_type;
		if (!DBGP(IMPAIR_SEND_IKEv2_KE)) {
			/* normal case */
			next_payload_type = ISAKMP_NEXT_v2KE;
		} else {
			/* We are faking not sending a KE, we'll just call it a Notify */
			next_payload_type = ISAKMP_NEXT_v2N;
		}

		/*
		 * Since this is the initial IKE exchange, the SPI is
		 * emitted as part of the packet header and not as
		 * part of the proposal.  Hence the NULL SPI.
		 */
		passert(st->st_accepted_ike_proposal != NULL);
		if (!ikev2_emit_sa_proposal(&md->rbody, st->st_accepted_ike_proposal,
					    NULL, next_payload_type)) {
			DBG(DBG_CONTROL, DBG_log("problem emitting accepted proposal"));
			return STF_INTERNAL_ERROR;
		}
	}

	/* Ni in */
	RETURN_STF_FAILURE(accept_v2_nonce(md, &st->st_ni, "Ni"));

	/* ??? from here on, this looks a lot like the end of ikev2_parent_outI1_common */

	/*
	 * Unpack and send KE
	 *
	 * Pass the crypto helper's oakley group so that it is
	 * consistent with what was unpacked.
	 *
	 * IKEv2 code (arguably, incorrectly) uses st_oakley.group to
	 * track the most recent KE sent out.  It should instead be
	 * maintaing a list of KEs sent out (so that they can be
	 * reused should the initial responder flip-flop) and only set
	 * st_oakley.group once the proposal has been accepted.
	 */
	pexpect(st->st_oakley.group == r->pcr_d.kn.group);
	unpack_KE_from_helper(st, r, &st->st_gr);
	if (!justship_v2KE(&st->st_gr,
			   r->pcr_d.kn.group,
			   &md->rbody, ISAKMP_NEXT_v2Nr)) {
		return STF_INTERNAL_ERROR;
	}

	/* send NONCE */
	unpack_nonce(&st->st_nr, r);
	{
		int np = ISAKMP_NEXT_v2N;
		struct ikev2_generic in;
		pb_stream pb;

		zero(&in);	/* OK: no pointers */
		in.isag_np = np;
		in.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;
		if (DBGP(IMPAIR_SEND_BOGUS_PAYLOAD_FLAG)) {
			libreswan_log(
				" setting bogus ISAKMP_PAYLOAD_LIBRESWAN_BOGUS flag in ISAKMP payload");
			in.isag_critical |= ISAKMP_PAYLOAD_LIBRESWAN_BOGUS;
		}

		if (!out_struct(&in, &ikev2_nonce_desc, &md->rbody, &pb) ||
		    !out_chunk(st->st_nr, &pb, "IKEv2 nonce"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&pb);
	}

	/* decide to send a CERTREQ - for RSASIG or GSSAPI */
	send_certreq = (((c->policy & POLICY_RSASIG) &&
		!has_preloaded_public_key(st))
		);

	/* Send fragmentation support notification */
	if (c->policy & POLICY_IKE_FRAG_ALLOW) {
		int np = ISAKMP_NEXT_v2N;

		if (!ship_v2N(np, ISAKMP_PAYLOAD_NONCRITICAL,
			      PROTO_v2_RESERVED, &empty_chunk,
			      v2N_IKEV2_FRAGMENTATION_SUPPORTED, &empty_chunk,
			      &md->rbody))
			return STF_INTERNAL_ERROR;
	}

	/* Send NAT-T Notify payloads */
	{
		struct ikev2_generic in;
		int np = send_certreq ? ISAKMP_NEXT_v2CERTREQ :
			(vids != 0) ? ISAKMP_NEXT_v2V : ISAKMP_NEXT_v2NONE;

		zero(&in);	/* OK: no pointers */
		in.isag_np = np;
		in.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;
		if (!ikev2_out_nat_v2n(np, &md->rbody, md))
			return STF_INTERNAL_ERROR;
	}

	/* send CERTREQ  */
	if (send_certreq) {
		int np = (vids != 0) ? ISAKMP_NEXT_v2V : ISAKMP_NEXT_v2NONE;
		DBG(DBG_CONTROL, DBG_log("going to send a certreq"));
		ikev2_send_certreq(st, md, ORIGINAL_RESPONDER, np, &md->rbody);
	}

	/* From here on, only payloads left are Vendor IDs */
	if (c->send_vendorid) {
		vids--;
		int np = (vids != 0) ? ISAKMP_NEXT_v2V : ISAKMP_NEXT_v2NONE;

		if (!ikev2_out_generic_raw(np, &ikev2_vendor_id_desc, &md->rbody,
				     pluto_vendorid, strlen(pluto_vendorid),
				     "VID_LIBRESWANSELF"))
			return STF_INTERNAL_ERROR;
	}

	if (c->fake_strongswan) {
		vids--;
		int np = (vids != 0) ? ISAKMP_NEXT_v2V : ISAKMP_NEXT_v2NONE;

		if (!ikev2_out_generic_raw(np, &ikev2_vendor_id_desc, &md->rbody,
				     "strongSwan", strlen("strongSwan"),
				     "VID_STRONGSWAN"))
			return STF_INTERNAL_ERROR;
	}

	if (c->policy & POLICY_AUTH_NULL) {
		vids--;
		int np = (vids != 0) ? ISAKMP_NEXT_v2V : ISAKMP_NEXT_v2NONE;

		if (!ikev2_out_generic_raw(np, &ikev2_vendor_id_desc, &md->rbody,
				     "Opportunistic IPsec", strlen("Opportunistic IPsec"),
				     "VID_OPPORTUNISTIC"))
			return STF_INTERNAL_ERROR;
	}

	passert(vids == 0); /* Ensure we built a valid chain */

	if (!close_message(&md->rbody, st))
		return STF_INTERNAL_ERROR;

	close_output_pbs(&reply_stream);

	record_outbound_ike_msg(st, &reply_stream,
		"reply packet for ikev2_parent_inI1outR1_tail");

	/* save packet for later signing */
	freeanychunk(st->st_firstpacket_me);
	clonetochunk(st->st_firstpacket_me, reply_stream.start,
		     pbs_offset(&reply_stream), "saved first packet");

	/* note: retransmission is driven by initiator, not us */

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
 *                     <--  HDR, N(COOKIE)
 * HDR, N(COOKIE), SAi1, KEi, Ni -->
 */
stf_status ikev2parent_inR1BoutI1B(struct msg_digest *md)
{
	struct state *st = md->st;
	struct connection *c = st->st_connection;
	struct payload_digest *ntfy;

	for (ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
		if (ntfy->payload.v2n.isan_spisize != 0) {
			DBG(DBG_CONTROLMORE, DBG_log(
				"Notify payload for IKE must have zero length SPI - message dropped"
			));
			return STF_IGNORE;
		}

		if ((ntfy->payload.v2n.isan_type < v2N_ERROR_ROOF) &&
		    (ntfy->payload.v2n.isan_type > v2N_NOTHING_WRONG)) {
			pstats(ikev2_recv_notifies_e, ntfy->payload.v2n.isan_type);
		}

		switch (ntfy->payload.v2n.isan_type) {
		case v2N_COOKIE:
		{
			/*
			 * Responder replied with N(COOKIE) for DOS avoidance.
			 * See rfc5996bis-04 2.6.
			 * Responder SPI ought to have been 0 (but might not be).
			 * Our state should not advance.  Instead
			 * we should send our I1 packet with the same cookie.
			 */

			/*
			 * RFC-7296 Section 2.6:
			 * The data associated with this notification MUST be
			 * between 1 and 64 octets in length (inclusive)
			 */
			if (ntfy->payload.v2n.isan_length > IKEv2_MAX_COOKIE_SIZE) {
				DBG(DBG_CONTROL, DBG_log("v2N_COOKIE notify payload too big - packet dropped"));
				return STF_IGNORE; /* avoid DDOS / reflection attacks */
			}

			if (ntfy->next != NULL) {
				DBG(DBG_CONTROL, DBG_log("ignoring Notify payloads after v2N_COOKIE"));
			}

			clonetochunk(st->st_dcookie,
				ntfy->pbs.cur, pbs_left(&ntfy->pbs),
				"saved received dcookie");

			DBG(DBG_CONTROLMORE,
			    DBG_dump_chunk("dcookie received (instead of an R1):",
					   st->st_dcookie);
			    DBG_log("next STATE_PARENT_I1 resend I1 with the dcookie"));

			if (DBGP(DBG_OPPO) || (st->st_connection->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
				libreswan_log("Received anti-DDOS COOKIE, resending I1 with cookie payload");
			}

			md->svm = &ikev2_parent_firststate_microcode;

			change_state(st, STATE_PARENT_I1);
			/* AA_2016 why do we need to mess with st_msgid_nextuse
			 * now ?
			st->st_msgid_lastack = v2_INVALID_MSGID;
			md->msgid_received = v2_INVALID_MSGID;
			st->st_msgid_nextuse = 0;
			*/

			return ikev2_parent_outI1_common(md, st);
		}
		case v2N_INVALID_KE_PAYLOAD:
		{
			/* careful of DDOS, only log with debugging on */
			struct suggested_group sg;

			/* we treat this as a "retransmit" event to rate limit these */
			if (st->st_retransmit >= MAXIMUM_INVALID_KE_RETRANS) {
				DBG(DBG_CONTROLMORE, DBG_log("ignoring received INVALID_KE packets - received too many (DoS?)"));
				return STF_IGNORE;
			}
			st->st_retransmit++;

			if (ntfy->next != NULL) {
				DBG(DBG_CONTROL, DBG_log("ignoring Notify payloads after v2N_INVALID_KE_PAYLOAD"));
			}

			if (!in_struct(&sg, &suggested_group_desc,
				&ntfy->pbs, NULL))
					return STF_IGNORE;

			pstats(invalidke_recv_s, sg.sg_group);
			pstats(invalidke_recv_u, st->st_oakley.group->group);

			ikev2_proposals_from_alg_info_ike(c->name,
							  "initial initiator (validating suggested KE)",
							  c->alg_info_ike,
							  &c->ike_proposals);
			passert(c->ike_proposals != NULL);
			if (ikev2_proposals_include_modp(c->ike_proposals, sg.sg_group)) {
				DBG(DBG_CONTROLMORE, DBG_log("Suggested modp group is acceptable"));
				/*
				 * Since there must be a group object
				 * for every local proposal, and
				 * sg.sg_group matches one of the
				 * local proposal groups, a lookup of
				 * sg.sg_group must succeed.
				 */
				const struct oakley_group_desc *new_group = ikev2_get_dh_desc(sg.sg_group);
				passert(new_group);
				DBG(DBG_CONTROLMORE, {
					DBG_log("Received unauthenticated INVALID_KE rejected our group %s suggesting group %s; resending with updated modp group",
						st->st_oakley.group->common.name,
						new_group->common.name);
				});
				st->st_oakley.group = new_group;
				/* wipe our mismatched KE */
				clear_dh_from_state(st);
				/* wipe out any saved RCOOKIE */
				DBG(DBG_CONTROLMORE, DBG_log("zeroing any RCOOKIE from unauthenticated INVALID_KE packet"));
				rehash_state(st, NULL, zero_cookie);
				/* get a new KE */
				return ikev2_crypto_start(NULL, st);
			} else {
				DBG(DBG_CONTROLMORE, {
					struct esb_buf esb;
					DBG_log("Ignoring received unauthenticated INVALID_KE with unacceptable DH group suggestion %s",
						enum_show_shortb(&oakley_group_names,
								 sg.sg_group, &esb));
				});
				return STF_IGNORE;
			}
		}

		case v2N_NO_PROPOSAL_CHOSEN:
		default:
			/*
			 * ??? At least NO_PROPOSAL_CHOSEN
			 * is legal and should keep us in this state.
			 *
			 * Note initial child SA might have failed but an incoming
			 * CREATE_CHILD_SA for another range might succeed, so do not
			 * delete childless parent state.
			 *
			 * The responder SPI ought to have been 0 (but might not be).
			 * See rfc5996bis-04 2.6.
			 */
			if (DBGP(DBG_OPPO) || (st->st_connection->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
				libreswan_log("%s: received unauthenticated %s - ignored",
					enum_name(&state_names, st->st_state),
					enum_name(&ikev2_notify_names,
						ntfy->payload.v2n.isan_type));
			}
		}
	}
	return STF_IGNORE;
}

/* STATE_PARENT_I1: R1 --> I2
 *                     <--  HDR, SAr1, KEr, Nr, [CERTREQ]
 * HDR, SK {IDi, [CERT,] [CERTREQ,]
 *      [IDr,] AUTH, SAi2,
 *      TSi, TSr}      -->
 */

static crypto_req_cont_func ikev2_parent_inR1outI2_continue;	/* type assertion */

static stf_status ikev2_parent_inR1outI2_tail(
	struct pluto_crypto_req_cont *dh,
	struct pluto_crypto_req *r);

stf_status ikev2parent_inR1outI2(struct msg_digest *md)
{
	struct state *st = md->st;
	struct connection *c = st->st_connection;
	struct payload_digest *ntfy;

	/* for testing only */
	if (DBGP(IMPAIR_SEND_NO_IKEV2_AUTH)) {
		libreswan_log(
			"IMPAIR_SEND_NO_IKEV2_AUTH set - not sending IKE_AUTH packet");
		return STF_IGNORE;
	}

	if (need_this_intiator(st)) {
		return STF_DROP;
	}

	for (ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {

		if ((ntfy->payload.v2n.isan_type < v2N_ERROR_ROOF) &&
		    (ntfy->payload.v2n.isan_type > v2N_NOTHING_WRONG)) {
			pstats(ikev2_recv_notifies_e, ntfy->payload.v2n.isan_type);
		}

		switch (ntfy->payload.v2n.isan_type) {
		case v2N_COOKIE:
		case v2N_INVALID_KE_PAYLOAD:
		case v2N_NO_PROPOSAL_CHOSEN:
			DBG(DBG_CONTROL, DBG_log("%s cannot appear with other payloads",
				enum_name(&ikev2_notify_names,
						ntfy->payload.v2n.isan_type)));
			return STF_FAIL + v2N_INVALID_SYNTAX;

		case v2N_USE_TRANSPORT_MODE:
		case v2N_ESP_TFC_PADDING_NOT_SUPPORTED:
			DBG(DBG_CONTROL, DBG_log("%s: received %s which is not valid for IKE_INIT - ignoring it",
				enum_name(&state_names, st->st_state),
				enum_name(&ikev2_notify_names,
					ntfy->payload.v2n.isan_type)));
			break;

		case v2N_NAT_DETECTION_SOURCE_IP:
		case v2N_NAT_DETECTION_DESTINATION_IP:
			/* we do handle these further down */
			break;
		case v2N_IKEV2_FRAGMENTATION_SUPPORTED:
			st->st_seen_fragvid = TRUE;
                        break;
		default:
			DBG(DBG_CONTROL, DBG_log("%s: received %s but ignoring it",
				enum_name(&state_names, st->st_state),
				enum_name(&ikev2_notify_names,
					ntfy->payload.v2n.isan_type)));
		}
	}

	/*
	 * the responder sent us back KE, Gr, Nr, and it's our time to calculate
	 * the shared key values.
	 */

	DBG(DBG_CONTROLMORE,
	    DBG_log("ikev2 parent inR1: calculating g^{xy} in order to send I2"));

	/* KE in */
	RETURN_STF_FAILURE(accept_KE(&st->st_gr, "Gr", st->st_oakley.group,
				     &md->chain[ISAKMP_NEXT_v2KE]->pbs));

	/* Ni in */
	RETURN_STF_FAILURE(accept_v2_nonce(md, &st->st_nr, "Ni"));

	/* We're missing processing a CERTREQ in here */

	/* process and confirm the SA selected */
	{
		/* SA body in and out */
		struct payload_digest *const sa_pd =
			md->chain[ISAKMP_NEXT_v2SA];
		ikev2_proposals_from_alg_info_ike(c->name, "initial initiator (accepting)",
						  c->alg_info_ike,
						  &c->ike_proposals);
		passert(c->ike_proposals != NULL);

		stf_status ret = ikev2_process_sa_payload("IKE initiator (accepting)",
							  &sa_pd->pbs,
							  /*expect_ike*/ TRUE,
							  /*expect_spi*/ FALSE,
							  /*expect_accepted*/ TRUE,
							  c->policy & POLICY_OPPORTUNISTIC,
							  &st->st_accepted_ike_proposal,
							  c->ike_proposals);
		if (ret != STF_OK) {
			DBG(DBG_CONTROLMORE, DBG_log("ikev2_parse_parent_sa_body() failed in ikev2parent_inR1outI2()"));
			return ret;
		}
		passert(st->st_accepted_ike_proposal != NULL);

		if (!ikev2_proposal_to_trans_attrs(st->st_accepted_ike_proposal,
						   &st->st_oakley)) {
			loglog(RC_LOG_SERIOUS, "IKE initiator proposed an unsupported algorithm");
			free_ikev2_proposal(&st->st_accepted_ike_proposal);
			passert(st->st_accepted_ike_proposal == NULL);
			/*
			 * Assume caller et.al. will clean up the
			 * reset of the mess?
			 */
			return STF_FAIL;
		}
	}

	/* update state */
	ikev2_update_msgid_counters(md);

	/* check v2N_NAT_DETECTION_DESTINATION_IP or/and
	 * v2N_NAT_DETECTION_SOURCE_IP
	 */
	if (md->chain[ISAKMP_NEXT_v2N] != NULL) {
		ikev2_natd_lookup(md, st->st_rcookie);
	}

	/* initiate calculation of g^xy */
	return start_dh_v2(md, "ikev2_inR1outI2 KE", ORIGINAL_INITIATOR, NULL,
		NULL, ikev2_parent_inR1outI2_continue);
}

/* redundant type assertion: static crypto_req_cont_func ikev2_parent_inR1outI2_continue; */

static void ikev2_parent_inR1outI2_continue(struct pluto_crypto_req_cont *dh,
					    struct pluto_crypto_req *r)
{
	struct msg_digest *md = dh->pcrc_md;
	struct state *const st = md->st;
	stf_status e;

	DBG(DBG_CONTROL,
		DBG_log("ikev2_parent_inR1outI2_continue for #%lu: calculating g^{xy}, sending I2",
			dh->pcrc_serialno));

	if (dh->pcrc_serialno == SOS_NOBODY) {
		loglog(RC_LOG_SERIOUS,
		       "%s: Request was disconnected from state",
		       __FUNCTION__);
		release_any_md(&dh->pcrc_md);
		return;
	}

	passert(dh->pcrc_serialno == st->st_serialno);	/* transitional */

	passert(cur_state == NULL);
	passert(st != NULL);

	passert(st->st_suspended_md == dh->pcrc_md);
	unset_suspended(st); /* no longer connected or suspended */

	set_cur_state(st);

	DBG(DBG_CONTROLMORE, DBG_log("#%lu %s:%u st->st_calculating = FALSE;", st->st_serialno, __FUNCTION__, __LINE__));
	st->st_calculating = FALSE;

	e = ikev2_parent_inR1outI2_tail(dh, r);

	passert(dh->pcrc_md != NULL);
	complete_v2_state_transition(&dh->pcrc_md, e);
	release_any_md(&dh->pcrc_md);
	reset_globals();
}

/*
 * Form the encryption IV (a.k.a. starting variable) from the salt
 * (a.k.a. nonce) wire-iv and a counter set to 1.
 *
 * note: no iv is longer than MAX_CBC_BLOCK_SIZE
 */
static void construct_enc_iv(const char *name,
			     u_char enc_iv[],
			     u_char *wire_iv, chunk_t salt,
			     const struct encrypt_desc *encrypter)
{
	DBG(DBG_CRYPT, DBG_log("construct_enc_iv: %s: salt-size=%zd wire-IV-size=%zd block-size %zd",
			       name, encrypter->salt_size, encrypter->wire_iv_size,
			       encrypter->enc_blocksize));
	passert(salt.len == encrypter->salt_size);
	passert(encrypter->enc_blocksize <= MAX_CBC_BLOCK_SIZE);
	passert(encrypter->enc_blocksize >= encrypter->salt_size + encrypter->wire_iv_size);
	size_t counter_size = encrypter->enc_blocksize - encrypter->salt_size - encrypter->wire_iv_size;
	DBG(DBG_CRYPT, DBG_log("construct_enc_iv: %s: computed counter-size=%zd",
			       name, counter_size));

	memcpy(enc_iv, salt.ptr, salt.len);
	memcpy(enc_iv + salt.len, wire_iv, encrypter->wire_iv_size);
	if (counter_size > 0) {
		memset(enc_iv + encrypter->enc_blocksize - counter_size, 0,
		       counter_size - 1);
		enc_iv[encrypter->enc_blocksize - 1] = 1;
	}
	DBG(DBG_CRYPT, DBG_dump(name, enc_iv, encrypter->enc_blocksize));
}

/*
 * Append optional "padding" and reguired "padding-length" byte.
 *
 * Some encryption modes, namely CBC, require things to be padded to
 * the encryption block-size.  While others, such as CTR, do not.
 * Either way a "padding-length" byte is always appended.
 *
 * This code starts by appending a 0 pad-octet, and each subsequent
 * octet is one larger.  Thus the last octet always contains one less
 * than the number of octets added i.e., the padding-length.
 *
 * Adding to the confusion, ESP requires a minimum of 4-byte alignment
 * and IKE is free to use the ESP code for padding - we don't.
 */
static bool ikev2_padup_pre_encrypt(struct state *st,
				    pb_stream *e_pbs_cipher) MUST_USE_RESULT;
static bool ikev2_padup_pre_encrypt(struct state *st,
				    pb_stream *e_pbs_cipher)
{
	struct state *pst = st;

	if (IS_CHILD_SA(st))
		pst = state_with_serialno(st->st_clonedfrom);

	/* pads things up to message size boundary */
	{
		size_t blocksize = pst->st_oakley.encrypter->enc_blocksize;
		char b[MAX_CBC_BLOCK_SIZE];
		unsigned int i;
		size_t padding;

		if (pst->st_oakley.encrypter->pad_to_blocksize) {
			passert(blocksize <= MAX_CBC_BLOCK_SIZE);
			padding = pad_up(pbs_offset(e_pbs_cipher), blocksize);
			if (padding == 0) {
				padding = blocksize;
			}
			DBG(DBG_CRYPT,
			    DBG_log("ikev2_padup_pre_encrypt: adding %zd bytes of padding (last is padding-length)",
				    padding));
		} else {
			padding = 1;
			DBG(DBG_CRYPT,
			    DBG_log("ikev2_padup_pre_encrypt: adding %zd byte padding-length", padding));
		}

		for (i = 0; i < padding; i++)
			b[i] = i;
		if (!out_raw(b, padding, e_pbs_cipher, "padding and length"))
			return FALSE;
	}
	return TRUE;
}

static unsigned char *ikev2_authloc(struct state *st,
				    pb_stream *e_pbs)
{
	unsigned char *b12;
	struct state *pst = st;

	if (IS_CHILD_SA(st)) {
		pst = state_with_serialno(st->st_clonedfrom);
		if (pst == NULL)
			return NULL;
	}

	b12 = e_pbs->cur;
	size_t integ_size = (ike_alg_enc_requires_integ(pst->st_oakley.encrypter)
			    ? pst->st_oakley.integ->integ_output_size
			    : pst->st_oakley.encrypter->aead_tag_size);
	if (integ_size == 0) {
		DBG(DBG_CRYPT, DBG_log("ikev2_authloc: HMAC/KEY size is zero"));
		return NULL;
	}

	if (!out_zero(integ_size, e_pbs, "length of truncated HMAC/KEY")) {
		return NULL;
	}

	return b12;
}

static stf_status ikev2_encrypt_msg(struct state *st,
				    unsigned char *auth_start,
				    unsigned char *wire_iv_start,
				    unsigned char *enc_start,
				    unsigned char *integ_start,
				    pb_stream *e_pbs_cipher)
{
	struct state *pst = st;

	/*
	 * If this is a child (esp/ah) then set PST to the parent so
	 * the parent's crypto-suite is used.
	 */
	if (IS_CHILD_SA(st))
		pst = state_with_serialno(st->st_clonedfrom);

	chunk_t salt;
	PK11SymKey *cipherkey;
	PK11SymKey *authkey;
	if (pst->st_original_role == ORIGINAL_INITIATOR) {
		cipherkey = pst->st_skey_ei_nss;
		authkey = pst->st_skey_ai_nss;
		salt = pst->st_skey_initiator_salt;
	} else {
		cipherkey = pst->st_skey_er_nss;
		authkey = pst->st_skey_ar_nss;
		salt = pst->st_skey_responder_salt;
	}

	/* size of plain or cipher text.  */
	size_t enc_size = e_pbs_cipher->cur - enc_start;

	/* encrypt and authenticate the block */
	if (ike_alg_enc_requires_integ(pst->st_oakley.encrypter)) {
		/* note: no iv is longer than MAX_CBC_BLOCK_SIZE */
		unsigned char enc_iv[MAX_CBC_BLOCK_SIZE];
		construct_enc_iv("encryption IV/starting-variable", enc_iv,
				 wire_iv_start, salt,
				 pst->st_oakley.encrypter);

		DBG(DBG_CRYPT,
		    DBG_dump("data before encryption:", enc_start, enc_size));

		/* now, encrypt */
		pst->st_oakley.encrypter->encrypt_ops
			->do_crypt(pst->st_oakley.encrypter,
				   enc_start, enc_size,
				   cipherkey,
				   enc_iv, TRUE);

		DBG(DBG_CRYPT,
		    DBG_dump("data after encryption:", enc_start, enc_size));
		/* note: saved_iv's updated value is discarded */

		/* okay, authenticate from beginning of IV */
		struct hmac_ctx ctx;
		hmac_init(&ctx, pst->st_oakley.integ->prf, authkey);
		hmac_update(&ctx, auth_start, integ_start - auth_start);
		hmac_final(integ_start, &ctx);

		DBG(DBG_PARSING, {
			    DBG_dump("data being hmac:", auth_start,
				     integ_start - auth_start);
			    DBG_dump("out calculated auth:", integ_start,
				     pst->st_oakley.integ->integ_output_size);
		    });
	} else {
		size_t wire_iv_size = pst->st_oakley.encrypter->wire_iv_size;
		size_t integ_size = pst->st_oakley.encrypter->aead_tag_size;
		/*
		 * Additional Authenticated Data - AAD - size.
		 * RFC5282 says: The Initialization Vector and Ciphertext
		 * fields [...] MUST NOT be included in the associated
		 * data.
		 */
		unsigned char *aad_start = auth_start;
		size_t aad_size = enc_start - aad_start - wire_iv_size;

		DBG(DBG_CRYPT,
		    DBG_dump_chunk("Salt before authenticated encryption:", salt);
		    DBG_dump("IV before authenticated encryption:",
			     wire_iv_start, wire_iv_size);
		    DBG_dump("AAD before authenticated encryption:",
			     aad_start, aad_size);
		    DBG_dump("data before authenticated encryption:",
			     enc_start, enc_size);
		    DBG_dump("integ before authenticated encryption:",
			     integ_start, integ_size));
		if (!pst->st_oakley.encrypter->encrypt_ops
		    ->do_aead(pst->st_oakley.encrypter,
			      salt.ptr, salt.len,
			      wire_iv_start, wire_iv_size,
			      aad_start, aad_size,
			      enc_start, enc_size, integ_size,
			      cipherkey, TRUE)) {
			return STF_FAIL;
		}
		DBG(DBG_CRYPT,
		    DBG_dump("data after authenticated encryption:",
			     enc_start, enc_size);
		    DBG_dump("integ after authenticated encryption:",
			     integ_start, integ_size));
	}

	return STF_OK;
}

/*
 * ikev2_decrypt_msg: decode the v2E payload.
 * The result is stored in-place.
 * Calls ikev2_process_payloads to decode the payloads within.
 *
 * This code assumes that the encrypted part of an IKE message starts
 * with an Initialization Vector (IV) of WIRE_IV_SIZE random octets.
 * We will discard the IV after decryption.
 *
 * The (optional) salt, wire-iv, and (optional) 1 are combined to form
 * the actual starting-variable (a.k.a. IV).
 */

static stf_status ikev2_verify_and_decrypt_sk_payload(struct msg_digest *md,
						      chunk_t *chunk,
						      unsigned int iv)
{
	/* caller should be passing in the original (parent) state. */
	struct state *st = md->st;
	struct state *pst = IS_CHILD_SA(st) ?
		state_with_serialno(st->st_clonedfrom) : st;

	if (st != NULL && !st->hidden_variables.st_skeyid_calculated)
	{
		DBG(DBG_CRYPT | DBG_CONTROL, {
				ipstr_buf b;
				DBG_log("received encrypted packet from %s:%u  but no exponents for state #%lu to decrypt it",
					ipstr(&md->sender, &b),
					(unsigned)md->sender_port,
					st->st_serialno);
				});
		return STF_FAIL;
	}

	u_char *wire_iv_start = chunk->ptr + iv;
	size_t wire_iv_size = pst->st_oakley.encrypter->wire_iv_size;
	size_t integ_size = (ike_alg_enc_requires_integ(pst->st_oakley.encrypter)
			     ? pst->st_oakley.integ->integ_output_size
			     : pst->st_oakley.encrypter->aead_tag_size);

	/*
	 * check to see if length is plausible:
	 * - wire-IV
	 * - encoded data (possibly empty)
	 * - at least one padding-length byte
	 * - truncated integrity digest / tag
	 */
	u_char *payload_end = chunk->ptr + chunk->len;
	if (payload_end < (wire_iv_start + wire_iv_size + 1 + integ_size)) {
		libreswan_log("encrypted payload impossibly short (%tu)",
			      payload_end - wire_iv_start);
		return STF_FAIL;
	}

	u_char *auth_start = chunk->ptr;
	u_char *enc_start = wire_iv_start + wire_iv_size;
	u_char *integ_start = payload_end - integ_size;
	size_t enc_size = integ_start - enc_start;

	/*
	 * Check that the payload is block-size aligned.
	 *
	 * Per rfc7296 "the recipient MUST accept any length that
	 * results in proper alignment".
	 *
	 * Do this before the payload's integrity has been verified as
	 * block-alignment requirements aren't exactly secret
	 * (originally this was being done between integrity and
	 * decrypt).
	 */
	size_t enc_blocksize = pst->st_oakley.encrypter->enc_blocksize;
	bool pad_to_blocksize = pst->st_oakley.encrypter->pad_to_blocksize;
	if (pad_to_blocksize) {
		if (enc_size % enc_blocksize != 0) {
			libreswan_log("discarding invalid packet: %zu octet payload length is not a multiple of encryption block-size (%zu)",
				      enc_size, enc_blocksize);
			return STF_FAIL;
		}
	}

	chunk_t salt;
	PK11SymKey *cipherkey;
	PK11SymKey *authkey;
	if (md->original_role == ORIGINAL_INITIATOR) {
		cipherkey = pst->st_skey_er_nss;
		authkey = pst->st_skey_ar_nss;
		salt = pst->st_skey_responder_salt;
	} else {
		cipherkey = pst->st_skey_ei_nss;
		authkey = pst->st_skey_ai_nss;
		salt = pst->st_skey_initiator_salt;
	}

	/* authenticate and decrypt the block. */
	if (ike_alg_enc_requires_integ(st->st_oakley.encrypter)) {
		/*
		 * check authenticator.  The last INTEG_SIZE bytes are
		 * the truncated digest.
		 */
		unsigned char td[MAX_DIGEST_LEN];
		struct hmac_ctx ctx;

		hmac_init(&ctx, pst->st_oakley.integ->prf, authkey);
		hmac_update(&ctx, auth_start, integ_start - auth_start);
		hmac_final(td, &ctx);

		DBG(DBG_PARSING, {
			DBG_dump("data for hmac:",
				auth_start, integ_start - auth_start);
			DBG_dump("calculated auth:",
				 td, integ_size);
			DBG_dump("  provided auth:",
				 integ_start, integ_size);
		    });

		if (!memeq(td, integ_start, integ_size)) {
			libreswan_log("failed to match authenticator");
			return STF_FAIL;
		}

		DBG(DBG_PARSING, DBG_log("authenticator matched"));

		/* decrypt */

		/* note: no iv is longer than MAX_CBC_BLOCK_SIZE */
		unsigned char enc_iv[MAX_CBC_BLOCK_SIZE];
		construct_enc_iv("decryption IV/starting-variable", enc_iv,
				 wire_iv_start, salt,
				 pst->st_oakley.encrypter);

		DBG(DBG_CRYPT,
		    DBG_dump("payload before decryption:", enc_start, enc_size));
		pst->st_oakley.encrypter->encrypt_ops
			->do_crypt(pst->st_oakley.encrypter,
				   enc_start, enc_size,
				   cipherkey,
				   enc_iv, FALSE);
		DBG(DBG_CRYPT,
		    DBG_dump("payload after decryption:", enc_start, enc_size));

	  } else {
		/*
		 * Additional Authenticated Data - AAD - size.
		 * RFC5282 says: The Initialization Vector and Ciphertext
		 * fields [...] MUST NOT be included in the associated
		 * data.
		 */
		unsigned char *aad_start = auth_start;
		size_t aad_size = enc_start - auth_start - wire_iv_size;

		DBG(DBG_CRYPT,
		    DBG_dump_chunk("Salt before authenticated decryption:", salt);
		    DBG_dump("IV before authenticated decryption:",
			     wire_iv_start, wire_iv_size);
		    DBG_dump("AAD before authenticated decryption:",
			     aad_start, aad_size);
		    DBG_dump("data before authenticated decryption:",
			     enc_start, enc_size);
		    DBG_dump("integ before authenticated decryption:",
			     integ_start, integ_size));
		if (!pst->st_oakley.encrypter->encrypt_ops
		    ->do_aead(pst->st_oakley.encrypter,
			      salt.ptr, salt.len,
			      wire_iv_start, wire_iv_size,
			      aad_start, aad_size,
			      enc_start, enc_size, integ_size,
			      cipherkey, FALSE)) {
			return STF_FAIL; /* sub-code? */
		}
		DBG(DBG_CRYPT,
		    DBG_dump("data after authenticated decryption:",
			     enc_start, enc_size + integ_size));
	}

	/*
	 * Check the padding.
	 *
	 * Per rfc7296 "The sender SHOULD set the Pad Length to the
	 * minimum value that makes the combination of the payloads,
	 * the Padding, and the Pad Length a multiple of the block
	 * size, but the recipient MUST accept any length that results
	 * in proper alignment."
	 *
	 * Notice the "should".  RACOON, for instance, sends extra
	 * blocks of padding that contain random bytes.
	 */
	u_int8_t padlen = enc_start[enc_size - 1] + 1;
	if (padlen > enc_size) {
		libreswan_log("discarding invalid packet: padding-length %u (octet 0x%02x) is larger than %zu octet payload length",
			      padlen, padlen - 1, enc_size);
		return STF_FAIL;
	}
	if (pad_to_blocksize) {
		if (padlen > enc_blocksize) {
			/* probably racoon */
			DBG(DBG_CRYPT,
			    DBG_log("payload contains %zu blocks of extra padding (padding-length: %d (octet 0x%2x), encryption block-size: %zu)",
				    (padlen - 1) / enc_blocksize,
				    padlen, padlen - 1, enc_blocksize));
		}
	} else {
		if (padlen > 1) {
			DBG(DBG_CRYPT,
			    DBG_log("payload contains %u octets of extra padding (padding-length: %u (octet 0x%2x))",
				    padlen - 1, padlen, padlen - 1));
		}
	}

	/*
	 * Don't check the contents of the pad octets; racoon, for
	 * instance, sets them to random values.
	 */
	DBG(DBG_CRYPT, DBG_log("stripping %u octets as pad", padlen));
	setchunk(*chunk, enc_start, enc_size - padlen);

	return STF_OK;
}

static stf_status ikev2_reassemble_fragments(struct msg_digest *md,
					     chunk_t *chunk)
{
	struct ikev2_frag *frag;
	stf_status status;
	unsigned int size;
	unsigned int offset;
	struct state *st = md->st;

	size = 0;
	for (frag = st->ikev2_frags; frag; frag = frag->next) {
		setchunk(frag->plain, frag->cipher.ptr, frag->cipher.len);

		status = ikev2_verify_and_decrypt_sk_payload(
			md, &frag->plain, frag->iv);
		if (status != STF_OK) {
			release_fragments(st);
			return status;
		}

		size += frag->plain.len;
	}

	/* We have all the fragments */
	md->raw_packet.ptr = alloc_bytes(size, "IKE fragments buffer");

	/* Reassemble fragments in buffer */
	frag = st->ikev2_frags;
	md->chain[ISAKMP_NEXT_v2SKF]->payload.v2skf.isaskf_np = frag->np;
	offset = 0;
	do {
		struct ikev2_frag *old = frag;

		passert(offset + frag->plain.len <= size);
		memcpy(md->raw_packet.ptr + offset, frag->plain.ptr,
		       frag->plain.len);
		offset += frag->plain.len;
		frag = frag->next;

		freeanychunk(old->cipher);
		pfree(old);
	} while (frag != NULL);

	st->ikev2_frags = NULL;

	setchunk(*chunk, md->raw_packet.ptr, size);

	return STF_OK;
}

static stf_status ikev2_verify_enc_payloads(struct msg_digest *md,
					    struct ikev2_payloads_summary summary,
					    const struct state_v2_microcode *svm)
{
	const struct state_v2_microcode *s = svm == NULL ? md->svm : svm;

	/*
	 * XXX: hack until expected_encrypted_paylods is added to
	 * struct state_v2_microcode or replacement.
	 */
	struct ikev2_expected_payloads expected_encrypted_payloads = {
		.required = s->req_enc_payloads,
		.optional = s->opt_enc_payloads,
	};
	struct ikev2_payload_errors errors = ikev2_verify_payloads(summary,
								   &expected_encrypted_payloads);
	if (errors.status != STF_OK) {
		ikev2_log_payload_errors(errors, md->st);
		return errors.status;
	}

	DBG(DBG_CONTROLMORE, DBG_log("#%lu match encrypted payloads to svm %s",
				md->st->st_serialno, svm->story));

	return STF_OK;
}

struct ikev2_payloads_summary ikev2_decrypt_msg(struct msg_digest *md, bool verify_pl)
{
	stf_status status;
	chunk_t chunk;

	if (md->chain[ISAKMP_NEXT_v2SKF] != NULL) {
		status = ikev2_reassemble_fragments(md, &chunk);
		/* note: if status is SFT_OK, chunk is set */
	} else {
		pb_stream *e_pbs = &md->chain[ISAKMP_NEXT_v2SK]->pbs;

		setchunk(chunk, md->packet_pbs.start,
			 e_pbs->roof - md->packet_pbs.start);

		status = ikev2_verify_and_decrypt_sk_payload(
			md, &chunk, e_pbs->cur - md->packet_pbs.start);
	}

	if (status != STF_OK) {
		return (struct ikev2_payloads_summary) {
			.status = status,
		};
	}

	/* CLANG 3.5 mis-diagnoses that chunk is undefined */
	init_pbs(&md->clr_pbs, chunk.ptr, chunk.len, "cleartext");

	DBG(DBG_CONTROLMORE, DBG_log("#%lu ikev2 %s decrypt %s",
				md->st->st_serialno,
				enum_name(&ikev2_exchange_names,
					md->hdr.isa_xchg),
				status == STF_OK ? "success" : "failed"));

	 enum next_payload_types_ikev2 np = md->chain[ISAKMP_NEXT_v2SK] ?
		md->chain[ISAKMP_NEXT_v2SK]->payload.generic.isag_np :
		md->chain[ISAKMP_NEXT_v2SKF]->payload.v2skf.isaskf_np;

	struct ikev2_payloads_summary summary = ikev2_decode_payloads(md, &md->clr_pbs, np);
	if (summary.status != STF_OK) {
		return summary;
	}

	if (verify_pl) {
		summary.status = ikev2_verify_enc_payloads(md, summary, md->svm);
		if (summary.status == STF_OK) {
			struct state *pst = IS_CHILD_SA(md->st) ?
				state_with_serialno(md->st->st_clonedfrom) : md->st;
			/* going to switch to child st. before that update parent */
			if (!LHAS(pst->hidden_variables.st_nat_traversal, NATED_HOST))
				update_ike_endpoints(pst, md);
		}
	}
	return summary;
}

static stf_status ikev2_ship_cp_attr_ip4(u_int16_t type, ip_address *ip4,
		const char *story, pb_stream *outpbs)
{
	struct ikev2_cp_attribute attr;
	pb_stream a_pbs;

	attr.type = type;
	attr.len = ip4 == NULL ? 0 : 4;	/* ??? is this redundant */

	if (!out_struct(&attr, &ikev2_cp_attribute_desc, outpbs,
				&a_pbs))
		return STF_INTERNAL_ERROR;

	if (attr.len > 0) {
		const unsigned char *byte_ptr;
		addrbytesptr_read(ip4, &byte_ptr);
		if (!out_raw(byte_ptr, attr.len, &a_pbs, story))
			return STF_INTERNAL_ERROR;
	}

	close_output_pbs(&a_pbs);
	return STF_OK;
}

stf_status ikev2_send_cp(struct connection *c, enum next_payload_types_ikev2 np,
				  pb_stream *outpbs)
{
	struct ikev2_cp cp;
	pb_stream cp_pbs;
	bool cfg_reply = c->spd.that.has_lease;

	DBG(DBG_CONTROLMORE, DBG_log("Send Configuration Payload %s ",
				cfg_reply ? "reply" : "request"));
	zero(&cp);	/* OK: no pointer fields */
	cp.isacp_critical = ISAKMP_PAYLOAD_NONCRITICAL;
	cp.isacp_np = np;
	cp.isacp_type = cfg_reply ? IKEv2_CP_CFG_REPLY : IKEv2_CP_CFG_REQUEST;

	if (!out_struct(&cp, &ikev2_cp_desc, outpbs, &cp_pbs))
		return STF_INTERNAL_ERROR;

	ikev2_ship_cp_attr_ip4(IKEv2_INTERNAL_IP4_ADDRESS,
			cfg_reply ? &c->spd.that.client.addr : NULL,
			"IPV4 Address", &cp_pbs);

	if (cfg_reply) {
		if (!isanyaddr(&c->modecfg_dns1)) {
			ikev2_ship_cp_attr_ip4(IKEv2_INTERNAL_IP4_DNS, &c->modecfg_dns1,
					"DNS 1", &cp_pbs);
		}
		if (!isanyaddr(&c->modecfg_dns2)) {
			ikev2_ship_cp_attr_ip4(IKEv2_INTERNAL_IP4_DNS, &c->modecfg_dns2,
					"DNS 2", &cp_pbs);
		}
	} else {
		ikev2_ship_cp_attr_ip4(IKEv2_INTERNAL_IP4_DNS, NULL, "DNS", &cp_pbs);
	}

	close_output_pbs(&cp_pbs);

	return STF_OK;
}

static stf_status ikev2_send_auth(struct connection *c,
				  struct state *st,
				  enum original_role role,
				  enum next_payload_types_ikev2 np,
				  unsigned char *idhash_out,
				  pb_stream *outpbs)
{
	struct ikev2_a a;
	pb_stream a_pbs;
	struct state *pst = IS_CHILD_SA(st) ?
		state_with_serialno(st->st_clonedfrom) : st;
	enum keyword_authby authby = c->spd.this.authby;

	if (authby == AUTH_UNSET) {
		/* asymmetric policy unset, pick up from symmetric policy */
		if (c->policy & POLICY_PSK) {
			authby = AUTH_PSK;
		} else if (c->policy & POLICY_RSASIG) {
			authby = AUTH_RSASIG;
		} else if (c->policy & POLICY_AUTH_NULL) {
			authby = AUTH_NULL;
		}
	}

	/* ??? isn't c redundant? */
	pexpect(c == st->st_connection)

	a.isaa_critical = ISAKMP_PAYLOAD_NONCRITICAL;
	if (DBGP(IMPAIR_SEND_BOGUS_PAYLOAD_FLAG)) {
		libreswan_log(
			" setting bogus ISAKMP_PAYLOAD_LIBRESWAN_BOGUS flag in ISAKMP payload");
		a.isaa_critical |= ISAKMP_PAYLOAD_LIBRESWAN_BOGUS;
	}

	a.isaa_np = np;

	switch (authby) {
	case AUTH_RSASIG:
		a.isaa_type = IKEv2_AUTH_RSA;
		break;
	case AUTH_PSK:
		a.isaa_type = IKEv2_AUTH_PSK;
		break;
	case AUTH_NULL:
		a.isaa_type = IKEv2_AUTH_NULL;
		break;
	case AUTH_NEVER:
	default:
		bad_case(authby);
	}

	if (!out_struct(&a, &ikev2_a_desc, outpbs, &a_pbs))
		return STF_INTERNAL_ERROR;

	switch (a.isaa_type) {
	case IKEv2_AUTH_RSA:
		if (!ikev2_calculate_rsa_sha1(pst, role, idhash_out, &a_pbs)) {
				loglog(RC_LOG_SERIOUS, "Failed to find our RSA key");
			return STF_FATAL;
		}
		break;

	case IKEv2_AUTH_PSK:
	case IKEv2_AUTH_NULL:
		if (!ikev2_create_psk_auth(authby, pst, idhash_out, &a_pbs)) {
				loglog(RC_LOG_SERIOUS, "Failed to find our PreShared Key");
			return STF_FATAL;
		}
		break;
	}

	close_output_pbs(&a_pbs);
	return STF_OK;
}

/*
 * fragment contents:
 * - sometimes:	NON_ESP_MARKER (RFC3948) (NON_ESP_MARKER_SIZE) (4)
 * - always:	isakmp header (NSIZEOF_isakmp_hdr) (28)
 * - always:	ikev2_skf header (NSIZEOF_ikev2_skf) (8)
 * - variable:	IV (no IV is longer than SHA2_512_DIGEST_SIZE) (64 or less)
 * - variable:	fragment's data
 * - variable:	padding (no padding is longer than MAX_CBC_BLOCK_SIZE) (16 or less)
 */
static stf_status ikev2_record_fragment(struct msg_digest *md,
				      struct isakmp_hdr *hdr,
				      struct ikev2_generic *oe,
				      struct ikev2_frag **fragp,
				      chunk_t *payload,	/* read-only */
				      unsigned int count, unsigned int total,
				      const char *desc)
{
	struct state *st = IS_CHILD_SA(md->st) ?
		state_with_serialno(md->st->st_clonedfrom) : md->st;
	struct ikev2_skf e;
	unsigned char *encstart;
	pb_stream e_pbs, e_pbs_cipher;
	unsigned char *iv;
	unsigned char *authstart;
	pb_stream frag_stream;
	unsigned char frag_buffer[PMAX(MIN_MAX_UDP_DATA_v4, MIN_MAX_UDP_DATA_v6)];

	/* make sure HDR is at start of a clean buffer */
	init_out_pbs(&frag_stream, frag_buffer, sizeof(frag_buffer),
		 "reply frag packet");

	/* beginning of data going out */
	authstart = frag_stream.cur;

	/* HDR out */
	{
		hdr->isa_np = ISAKMP_NEXT_v2SKF;

		if (!out_struct(hdr, &isakmp_hdr_desc, &frag_stream,
				&md->rbody))
			return STF_INTERNAL_ERROR;
	}

	/* insert an Encryption payload header */
	e.isaskf_np = count == 1 ? oe->isag_np : 0;
	e.isaskf_critical = oe->isag_critical;
	e.isaskf_number = count;
	e.isaskf_total = total;

	if (!out_struct(&e, &ikev2_skf_desc, &md->rbody, &e_pbs))
		return STF_INTERNAL_ERROR;

	/* insert IV */
	iv = e_pbs.cur;
	if (!emit_wire_iv(st, &e_pbs))
		return STF_INTERNAL_ERROR;

	/* note where cleartext starts */
	init_pbs(&e_pbs_cipher, e_pbs.cur, e_pbs.roof - e_pbs.cur,
		 "cleartext");
	e_pbs_cipher.container = &e_pbs;
	e_pbs_cipher.desc = NULL;
	e_pbs_cipher.cur = e_pbs.cur;
	encstart = e_pbs_cipher.cur;

	if (!out_raw(payload->ptr, payload->len, &e_pbs_cipher,
		     "cleartext fragment"))
		return STF_INTERNAL_ERROR;

	/*
	 * need to extend the packet so that we will know how big it is
	 * since the length is under the integrity check
	 */
	if (!ikev2_padup_pre_encrypt(st, &e_pbs_cipher))
		return STF_INTERNAL_ERROR;

	close_output_pbs(&e_pbs_cipher);

	{
		unsigned char *authloc = ikev2_authloc(st, &e_pbs);
		int ret;

		if (authloc == NULL)
			return STF_INTERNAL_ERROR;

		close_output_pbs(&e_pbs);
		close_output_pbs(&md->rbody);
		close_output_pbs(&frag_stream);

		ret = ikev2_encrypt_msg(st, authstart,
					iv, encstart, authloc,
					&e_pbs_cipher);
		if (ret != STF_OK)
			return ret;
	}

	*fragp = alloc_thing(struct ikev2_frag, "ikev2_frag");
	(*fragp)->next = NULL;
	clonetochunk((*fragp)->cipher, frag_stream.start,
		     pbs_offset(&frag_stream), desc);

	return STF_OK;
}

static stf_status ikev2_record_fragments(struct msg_digest *md,
				       struct isakmp_hdr *hdr,
				       struct ikev2_generic *e,
				       chunk_t *payload, /* read-only */
				       const char *desc)
{
	struct state *const st = IS_CHILD_SA(md->st) ?
		state_with_serialno(md->st->st_clonedfrom) : md->st;
	unsigned int len;

	release_fragments(st);
	freeanychunk(st->st_tpacket);

	len = (st->st_connection->addr_family == AF_INET) ?
	      ISAKMP_V2_FRAG_MAXLEN_IPv4 : ISAKMP_V2_FRAG_MAXLEN_IPv6;

	if (st->st_interface != NULL && st->st_interface->ike_float)
		len -= NON_ESP_MARKER_SIZE;

	len -= NSIZEOF_isakmp_hdr + NSIZEOF_ikev2_skf;

	len -= ike_alg_enc_requires_integ(st->st_oakley.encrypter) ?
	       st->st_oakley.integ->integ_output_size :
	       st->st_oakley.encrypter->aead_tag_size;

	if (st->st_oakley.encrypter->pad_to_blocksize)
		len &= ~(st->st_oakley.encrypter->enc_blocksize - 1);

	len -= 2;	/* ??? what's this? */

	passert(payload->len != 0);

	unsigned int nfrags = (payload->len + len - 1) / len;

	if (nfrags > MAX_IKE_FRAGMENTS) {
		loglog(RC_LOG_SERIOUS, "Fragmenting this %zu byte message into %u byte chunks leads to too many frags",
		       payload->len, len);
		return STF_INTERNAL_ERROR;
	}

	unsigned int count = 0;
	unsigned int offset = 0;
	struct ikev2_frag **fragp;
	int ret = STF_INTERNAL_ERROR;

	for (fragp = &st->st_tfrags; ; fragp = &(*fragp)->next) {
		chunk_t cipher;

		passert(*fragp == NULL);
		setchunk(cipher, payload->ptr + offset,
			PMIN(payload->len - offset, len));
		offset += cipher.len;
		count++;
		ret = ikev2_record_fragment(md, hdr, e, fragp, &cipher,
					  count, nfrags, desc);

		if (ret != STF_OK || offset == payload->len)
			break;
	}

	return ret;
}

static int ikev2_np_cp_or_sa(struct connection *const pc, int np, const lset_t
	   st_nat_traversal)
{
	int rnp = np;

	if (pc->spd.this.modecfg_client) {
		if (pc->spd.this.cat) {
			if (LHAS(st_nat_traversal, NATED_HOST)) {
				rnp = ISAKMP_NEXT_v2CP;
			}
		} else {
			rnp = ISAKMP_NEXT_v2CP;
		}
	}
	return rnp;
}

static stf_status ikev2_parent_inR1outI2_tail(
	struct pluto_crypto_req_cont *dh,
	struct pluto_crypto_req *r)
{
	struct msg_digest *const md = dh->pcrc_md;
	struct state *const pst = md->st;	/* parent's state object */
	struct connection *const pc = pst->st_connection;	/* parent connection */
	int send_cp_r = 0;

	if (!finish_dh_v2(pst, r, FALSE))
		return STF_FAIL + v2N_INVALID_KE_PAYLOAD;

	ikev2_log_parentSA(pst);

	/* XXX This is too early and many failures could lead to not needing a child state */
	struct state *cst = duplicate_state(pst, IPSEC_SA);	/* child state */

	/* XXX because the early child state ends up with the try counter check, we need to copy it */
	cst->st_try = pst->st_try;

	cst->st_msgid = htonl(pst->st_msgid_nextuse); /* PAUL: note ordering */
	insert_state(cst);
	md->st = cst;

	/* parent had crypto failed, replace it with rekey! */
	/* ??? seems wrong: not conditional at all */
	delete_event(pst);
	{
		enum event_type x = md->svm->timeout_event;
		time_t delay = ikev2_replace_delay(pst, &x, ORIGINAL_INITIATOR);

		event_schedule(x, delay, pst);
	}

	/* need to force parent state to I2 */
	change_state(pst, STATE_PARENT_I2);

	/* record first packet for later checking of signature */
	clonetochunk(pst->st_firstpacket_him, md->message_pbs.start,
		     pbs_offset(&md->message_pbs),
		     "saved first received packet");

	/* beginning of data going out */

	unsigned char *const authstart = reply_stream.cur;

	/* make sure HDR is at start of a clean buffer */
	init_out_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		 "reply packet");

	/* HDR out */

	struct isakmp_hdr hdr;

	/* XXX it should pick the cookies from the parent state! */
	memcpy(hdr.isa_icookie, cst->st_icookie, COOKIE_SIZE);
	memcpy(hdr.isa_rcookie, cst->st_rcookie, COOKIE_SIZE);
	hdr.isa_np = ISAKMP_NEXT_v2SK;
	hdr.isa_version = build_ikev2_version();
	hdr.isa_xchg = ISAKMP_v2_AUTH;
	/* XXX same here, use parent */
	hdr.isa_msgid = cst->st_msgid;

	/* set original initiator; all other flags clear */
	hdr.isa_flags = ISAKMP_FLAGS_v2_IKE_I;
	if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
		hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
	}

	if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_stream,
			&md->rbody))
		return STF_INTERNAL_ERROR;

	/* insert an Encryption payload header */

	struct ikev2_generic e = {ISAKMP_NEXT_v2IDi, ISAKMP_PAYLOAD_NONCRITICAL, 0};

	if (DBGP(IMPAIR_SEND_BOGUS_PAYLOAD_FLAG)) {
		libreswan_log(
			" setting bogus ISAKMP_PAYLOAD_LIBRESWAN_BOGUS flag in ISAKMP payload");
		e.isag_critical |= ISAKMP_PAYLOAD_LIBRESWAN_BOGUS;
	}

	pb_stream e_pbs;

	if (!out_struct(&e, &ikev2_sk_desc, &md->rbody, &e_pbs))
		return STF_INTERNAL_ERROR;

	/* insert IV */

	unsigned char *const iv = e_pbs.cur;

	if (!emit_wire_iv(cst, &e_pbs))
		return STF_INTERNAL_ERROR;

	/* note where cleartext starts */

	pb_stream e_pbs_cipher;	/* ??? it might be possible to eliminate this */

	init_pbs(&e_pbs_cipher, e_pbs.cur, e_pbs.roof - e_pbs.cur,
		 "cleartext");
	e_pbs_cipher.container = &e_pbs;

	unsigned char *const encstart = e_pbs_cipher.cur;

	/* decide whether to send CERT payload */

	/* it should use parent not child state */
	bool send_cert = ikev2_send_cert_decision(cst);
	bool ic =  pc->initial_contact && (pst->st_ike_pred == SOS_NOBODY);

	/* send out the IDi payload */

	unsigned char idhash[MAX_DIGEST_LEN];

	{
		struct ikev2_id r_id;
		pb_stream r_id_pbs;
		chunk_t id_b;
		struct hmac_ctx id_ctx;

		hmac_init(&id_ctx, pst->st_oakley.prf, pst->st_skey_pi_nss);
		build_id_payload((struct isakmp_ipsec_id *)&r_id, &id_b,
				 &pc->spd.this);
		r_id.isai_critical = ISAKMP_PAYLOAD_NONCRITICAL;
		if (DBGP(IMPAIR_SEND_BOGUS_PAYLOAD_FLAG)) {
			libreswan_log(
				" setting bogus ISAKMP_PAYLOAD_LIBRESWAN_BOGUS flag in ISAKMP payload");
			r_id.isai_critical |= ISAKMP_PAYLOAD_LIBRESWAN_BOGUS;
		}

		r_id.isai_np = send_cert ?
			ISAKMP_NEXT_v2CERT : ic ? ISAKMP_NEXT_v2N :
			ISAKMP_NEXT_v2AUTH;

		/* HASH of ID is not done over common header */
		unsigned char *const id_start =
			e_pbs_cipher.cur + NSIZEOF_isakmp_generic;

		if (!out_struct(&r_id,
				&ikev2_id_desc,
				&e_pbs_cipher,
				&r_id_pbs) ||
		    !out_chunk(id_b, &r_id_pbs, "my identity"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&r_id_pbs);

		/* calculate hash of IDi for AUTH below */

		const size_t id_len = e_pbs_cipher.cur - id_start;

		DBG(DBG_CRYPT, DBG_dump("idhash calc I2", id_start, id_len));
		hmac_update(&id_ctx, id_start, id_len);
		hmac_final(idhash, &id_ctx);
	}

	/* send [CERT,] payload RFC 4306 3.6, 1.2) */
	if (send_cert) {
		enum next_payload_types_ikev2 np = ic ?
			ISAKMP_NEXT_v2N : ISAKMP_NEXT_v2AUTH;

		stf_status certstat = ikev2_send_cert(cst, md,
						      ORIGINAL_INITIATOR,
						      np, &e_pbs_cipher);

		if (certstat != STF_OK)
			return certstat;
	}

	if (ic) {
		libreswan_log("sending INITIAL_CONTACT");
		if (!ship_v2N(ISAKMP_NEXT_v2AUTH, ISAKMP_PAYLOAD_NONCRITICAL,
					PROTO_v2_RESERVED,
					&empty_chunk,
					v2N_INITIAL_CONTACT,
					&empty_chunk,
					&e_pbs_cipher))
			return STF_INTERNAL_ERROR;
	} else {
		DBG(DBG_CONTROL, DBG_log("not sending INITIAL_CONTACT"));
	}

	/* send out the AUTH payload */
	{
		int np = send_cp_r = ikev2_np_cp_or_sa(pc, ISAKMP_NEXT_v2SA,
				pst->hidden_variables.st_nat_traversal);

		stf_status authstat = ikev2_send_auth(pc, cst, ORIGINAL_INITIATOR, np,
				idhash, &e_pbs_cipher);

		if (authstat != STF_OK)
			return authstat;
	}

	if (send_cp_r == ISAKMP_NEXT_v2CP) {
		stf_status cpstat = ikev2_send_cp(pc, ISAKMP_NEXT_v2SA,
				&e_pbs_cipher);

		if (cpstat != STF_OK)
			return cpstat;
	}

	/*
	 * Switch to first pending child request for this host pair.
	 * ??? Why so late in this game?
	 *
	 * Then emit SA2i, TSi and TSr and
	 * (v2N_USE_TRANSPORT_MODE notification in transport mode)
	 * for it.
	 */

	/* so far child's connection is same as parent's */
	passert(pc == cst->st_connection);

	{
		lset_t policy = pc->policy;
		bool send_use_transport;

		/* child connection */
		struct connection *cc = first_pending(pst, &policy, &cst->st_whack_sock);

		if (cc == NULL) {
			cc = pc;
			DBG(DBG_CONTROL, DBG_log("no pending CHILD SAs found for %s Reauthentication so use the original policy",
				cc->name));
		}

		if (cc != cst->st_connection){
			char cib[CONN_INST_BUF];
			DBG_log("Switching Child connection for #%lu to \"%s\"%s"
					" from \"%s\"%s",
					cst->st_serialno, cc->name,
					fmt_conn_instance(cc, cib),
					pc->name, fmt_conn_instance(pc, cib));

		}
		/* ??? this seems very late to change the connection */
		cst->st_connection = cc;	/* safe: from duplicate_state */

		send_use_transport = (cc->policy & POLICY_TUNNEL) == LEMPTY;

		/* ??? this code won't support AH + ESP */
		struct ipsec_proto_info *proto_info
			= ikev2_esp_or_ah_proto_info(cst, cc->policy);
		proto_info->our_spi = ikev2_esp_or_ah_spi(&cc->spd, cc->policy);
		chunk_t local_spi;
		setchunk(local_spi, (uint8_t*)&proto_info->our_spi,
			 sizeof(proto_info->our_spi));

		free_ikev2_proposals(&cc->esp_or_ah_proposals);
		ikev2_proposals_from_alg_info_esp(cc->name, "initiator",
						  cc->alg_info_esp,
						  cc->policy, NULL, /* pfs=no */
						  &cc->esp_or_ah_proposals);
		passert(cc->esp_or_ah_proposals != NULL);

		ikev2_emit_sa_proposals(&e_pbs_cipher, cc->esp_or_ah_proposals,
					&local_spi, ISAKMP_NEXT_v2TSi);

		cst->st_ts_this = ikev2_end_to_ts(&cc->spd.this);
		cst->st_ts_that = ikev2_end_to_ts(&cc->spd.that);

		ikev2_calc_emit_ts(md, &e_pbs_cipher, ORIGINAL_INITIATOR, cc,
			(send_use_transport || cc->send_no_esp_tfc) ?
				ISAKMP_NEXT_v2N : ISAKMP_NEXT_v2NONE);

		if ((cc->policy & POLICY_TUNNEL) == LEMPTY) {
			DBG(DBG_CONTROL, DBG_log("Initiator child policy is transport mode, sending v2N_USE_TRANSPORT_MODE"));
			/* In v2, for parent, protoid must be 0 and SPI must be empty */
			if (!ship_v2N(cc->send_no_esp_tfc ? ISAKMP_NEXT_v2N : ISAKMP_NEXT_v2NONE,
						ISAKMP_PAYLOAD_NONCRITICAL,
						PROTO_v2_RESERVED,
						&empty_chunk,
						v2N_USE_TRANSPORT_MODE, &empty_chunk,
						&e_pbs_cipher))
				return STF_INTERNAL_ERROR;
		}

		if (cc->send_no_esp_tfc) {
			if (!ship_v2N(ISAKMP_NEXT_v2NONE,
					ISAKMP_PAYLOAD_NONCRITICAL,
					PROTO_v2_RESERVED,
					&empty_chunk,
					v2N_ESP_TFC_PADDING_NOT_SUPPORTED, &empty_chunk,
					&e_pbs_cipher))
				return STF_INTERNAL_ERROR;
		}
	}

	const unsigned int len = pbs_offset(&e_pbs_cipher);

	/*
	 * need to extend the packet so that we will know how big it is
	 * since the length is under the integrity check
	 */
	if (!ikev2_padup_pre_encrypt(cst, &e_pbs_cipher))
		return STF_INTERNAL_ERROR;

	close_output_pbs(&e_pbs_cipher);

	unsigned char *const authloc = ikev2_authloc(cst, &e_pbs);

	if (authloc == NULL)
		return STF_INTERNAL_ERROR;

	close_output_pbs(&e_pbs);
	close_output_pbs(&md->rbody);
	close_output_pbs(&reply_stream);

	if (should_fragment_ike_msg(cst, pbs_offset(&reply_stream), TRUE)) {
		chunk_t payload;

		setchunk(payload, e_pbs_cipher.start, len);
		return ikev2_record_fragments(md, &hdr, &e, &payload,
					   "reply fragment for ikev2_parent_outR1_I2");
	} else {
		stf_status ret = ikev2_encrypt_msg(pst, authstart,
					iv, encstart, authloc,
					&e_pbs_cipher);

		if (ret == STF_OK)
			record_outbound_ike_msg(pst, &reply_stream,
				"reply packet for ikev2_parent_inR1outI2_tail");
		return ret;
	}
}

#ifdef XAUTH_HAVE_PAM

static void ikev2_pam_continue(struct state *st, const char *name UNUSED,
			       bool success)
{
	struct msg_digest *md = st->st_suspended_md;

	unset_suspended(md->st);

	stf_status stf;
	if (success) {
		/*
		 * This is a hardcoded continue, convert this to micro
		 * state.
		 */
		stf = ikev2_parent_inI2outR2_auth_tail(md, success);
	} else {
		stf = STF_FAIL + v2N_AUTHENTICATION_FAILED;
	}

	complete_v2_state_transition(&md, stf);
	release_any_md(&md);
	reset_globals();
}

/*
 * In the middle of IKEv2 AUTH exchange, the AUTH payload is verified succsfully.
 * Now invoke the PAM helper to authorize connection (based on name only, not password)
 * When pam helper is done state will be woken up and continue.
 *
 * This routine "suspends" MD/ST; once PAM finishes it will be
 * unsuspended.
 */

static stf_status ikev2_start_pam_authorize(struct msg_digest *md)
{
	struct state *st = md->st;
	set_suspended(md->st, md);

	char thatid[IDTOA_BUF];
	idtoa(&st->st_connection->spd.that.id, thatid, sizeof(thatid));
	libreswan_log("IKEv2: [XAUTH]PAM method requested to authorize '%s'",
		      thatid);
	xauth_start_pam_thread(&st->st_xauth_thread,
			       thatid, "password",
			       st->st_connection->name,
			       &st->st_remoteaddr,
			       st->st_serialno,
			       st->st_connection->instance_serial,
			       "IKEv2",
			       ikev2_pam_continue);
	return STF_SUSPEND;
}

#endif /* XAUTH_HAVE_PAM */

/*
 *
 ***************************************************************
 *                       PARENT_inI2                       *****
 ***************************************************************
 *  -
 *
 *
 */

/* STATE_PARENT_R1: I2 --> R2
 *                  <-- HDR, SK {IDi, [CERT,] [CERTREQ,]
 *                             [IDr,] AUTH, SAi2,
 *                             TSi, TSr}
 * HDR, SK {IDr, [CERT,] AUTH,
 *      SAr2, TSi, TSr} -->
 *
 * [Parent SA established]
 */

static crypto_req_cont_func ikev2_parent_inI2outR2_continue;

static stf_status ikev2_parent_inI2outR2_tail(
	struct pluto_crypto_req_cont *dh,
	struct pluto_crypto_req *r);

stf_status ikev2parent_inI2outR2(struct msg_digest *md)
{
	struct state *st = md->st;

	/* for testing only */
	if (DBGP(IMPAIR_SEND_NO_IKEV2_AUTH)) {
		libreswan_log(
			"IMPAIR_SEND_NO_IKEV2_AUTH set - not sending IKE_AUTH packet");
		return STF_IGNORE;
	}

	nat_traversal_change_port_lookup(md, st);

	/*
	 * the initiator sent us an encrypted payload. We need to calculate
	 * our g^xy, and skeyseed values, and then decrypt the payload.
	 */

	DBG(DBG_CONTROLMORE,
	    DBG_log("ikev2 parent inI2outR2: calculating g^{xy} in order to decrypt I2"));

	/* initiate calculation of g^xy */
	return start_dh_v2(md, "ikev2_inI2outR2 KE", ORIGINAL_RESPONDER, NULL,
			NULL, ikev2_parent_inI2outR2_continue);
}

static void ikev2_parent_inI2outR2_continue(struct pluto_crypto_req_cont *dh,
					    struct pluto_crypto_req *r)
{
	struct msg_digest *md = dh->pcrc_md;
	struct state *const st = md->st;
	stf_status e;

	DBG(DBG_CONTROL,
		DBG_log("ikev2_parent_inI2outR2_continue for #%lu: calculating g^{xy}, sending R2",
			dh->pcrc_serialno));

	if (dh->pcrc_serialno == SOS_NOBODY) {
		loglog(RC_LOG_SERIOUS,
		       "%s: Request was disconnected from state",
		       __FUNCTION__);
		release_any_md(&dh->pcrc_md);
		return;
	}

	passert(dh->pcrc_serialno == st->st_serialno);	/* transitional */

	passert(cur_state == NULL);
	passert(st != NULL);

	passert(st->st_suspended_md == dh->pcrc_md);
	unset_suspended(st); /* no longer connected or suspended */

	set_cur_state(st);

	DBG(DBG_CONTROLMORE, DBG_log("#%lu %s:%u st->st_calculating = FALSE;", st->st_serialno, __FUNCTION__, __LINE__));
	st->st_calculating = FALSE;

	e = ikev2_parent_inI2outR2_tail(dh, r);

	if (e > STF_FAIL) {
		/* we do not send a notify because we are the initiator that could be responding to an error notification */
		int v2_notify_num = e - STF_FAIL;

		DBG_log("ikev2_parent_inI2outR2_tail returned STF_FAIL with %s",
			enum_name(&ikev2_notify_names, v2_notify_num));
	} else if (e != STF_OK) {
		DBG_log("ikev2_parent_inI2outR2_tail returned %s",
			enum_name(&stfstatus_name, e));
	}

	/*
	 * if failed OE, delete state completly, no create_child_sa
	 * allowed so childless parent makes no sense. That is also
	 * the reason why we send v2N_AUTHENTICATION_FAILED, even
	 * though authenticated succeeded. It shows the remote end
	 * we have deleted the SA from our end.
	 */
	if (e >= STF_FAIL &&
	    (st->st_connection->policy & POLICY_OPPORTUNISTIC)) {
		DBG(DBG_OPPO,
			DBG_log("Deleting opportunistic Parent with no Child SA"));
		e = STF_FATAL;
		SEND_V2_NOTIFICATION(v2N_AUTHENTICATION_FAILED);
	}

	passert(dh->pcrc_md != NULL);
	complete_v2_state_transition(&dh->pcrc_md, e);
	release_any_md(&dh->pcrc_md);
	reset_globals();
}

static stf_status ikev2_parent_inI2outR2_tail(
	struct pluto_crypto_req_cont *dh,
	struct pluto_crypto_req *r)
{
	struct msg_digest *md = dh->pcrc_md;
	struct state *const st = md->st;
	stf_status ret = STF_OK;
	enum ikev2_auth_method atype;

	/* extract calculated values from r */
	if (!finish_dh_v2(st, r, FALSE))
		return STF_FAIL + v2N_INVALID_KE_PAYLOAD;

	ikev2_log_parentSA(st);

	/* decrypt things. */
	{
		struct ikev2_payloads_summary ps = ikev2_decrypt_msg(md, TRUE);

		if (ps.status != STF_OK)
			return ps.status;
	}

	/* this call might update connection in md->st */
	if (!ikev2_decode_peer_id_and_certs(md))
		return STF_FAIL + v2N_AUTHENTICATION_FAILED;

	atype = md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2a.isaa_type;
	if (IS_LIBUNBOUND && !id_ipseckey_allowed(st, atype)) {
		ret = idi_ipseckey_fetch(md);
		if (ret != STF_OK)
			return ret;
	}

	if (ret == STF_OK) {
		ret = ikev2_parent_inI2outR2_id_tail(md);
	}

	return ret;
}

stf_status ikev2_parent_inI2outR2_id_tail(struct msg_digest *md)
{
	struct state *const st = md->st;
	unsigned char idhash_in[MAX_DIGEST_LEN];

	/* calculate hash of IDi for AUTH below */
	{
		struct hmac_ctx id_ctx;
		const pb_stream *id_pbs = &md->chain[ISAKMP_NEXT_v2IDi]->pbs;
		unsigned char *idstart = id_pbs->start + NSIZEOF_isakmp_generic;
		unsigned int idlen = pbs_room(id_pbs) - NSIZEOF_isakmp_generic;

		hmac_init(&id_ctx, st->st_oakley.prf, st->st_skey_pi_nss);
		DBG(DBG_CRYPT, DBG_dump("idhash verify I2", idstart, idlen));
		hmac_update(&id_ctx, idstart, idlen);
		hmac_final(idhash_in, &id_ctx);
	}

	/* process CERTREQ payload */
	if (md->chain[ISAKMP_NEXT_v2CERTREQ] != NULL) {
		DBG(DBG_CONTROLMORE,
		    DBG_log("received CERTREQ payload; going to decode it"));
		ikev2_decode_cr(md);
	}

	/* process AUTH payload */

	enum keyword_authby that_authby = st->st_connection->spd.that.authby;

	passert(that_authby != AUTH_NEVER && that_authby != AUTH_UNSET);

	if (!v2_check_auth(md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2a.isaa_type,
		st, ORIGINAL_RESPONDER, idhash_in, &md->chain[ISAKMP_NEXT_v2AUTH]->pbs,
		st->st_connection->spd.that.authby))
	{
		/* TODO: This should really be an encrypted message! */
		SEND_V2_NOTIFICATION(v2N_AUTHENTICATION_FAILED);
		return STF_FATAL;
	}

	/* AUTH succeeded */

#ifdef XAUTH_HAVE_PAM
	if (st->st_connection->policy & POLICY_IKEV2_PAM_AUTHORIZE)
		return ikev2_start_pam_authorize(md);
#endif
	return ikev2_parent_inI2outR2_auth_tail(md, TRUE);
}

static stf_status ikev2_parent_inI2outR2_auth_tail(struct msg_digest *md,
		bool pam_status)
{
	struct state *const st = md->st;
	struct connection *const c = st->st_connection;
	unsigned char idhash_out[MAX_DIGEST_LEN];
	unsigned char *authstart;
	unsigned int np;

	if (!pam_status) {
		/*
		 * TBD: send this notification encrypted because the
		 * AUTH payload succeed
		 */
		SEND_V2_NOTIFICATION(v2N_AUTHENTICATION_FAILED);
		return STF_FATAL;
	}

	{
		struct payload_digest *ntfy;

		for (ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
			switch (ntfy->payload.v2n.isan_type) {
			case v2N_NAT_DETECTION_SOURCE_IP:
			case v2N_NAT_DETECTION_DESTINATION_IP:
			case v2N_IKEV2_FRAGMENTATION_SUPPORTED:
			case v2N_COOKIE:
				DBG(DBG_CONTROL, DBG_log("received %s which is not valid for current exchange",
					enum_name(&ikev2_notify_names,
						ntfy->payload.v2n.isan_type)));
				break;
			case v2N_USE_TRANSPORT_MODE:
				DBG(DBG_CONTROL, DBG_log("received USE_TRANSPORT_MODE"));
				st->st_seen_use_transport = TRUE;
				break;
			case v2N_ESP_TFC_PADDING_NOT_SUPPORTED:
				DBG(DBG_CONTROL, DBG_log("received ESP_TFC_PADDING_NOT_SUPPORTED"));
				st->st_seen_no_tfc = TRUE;
				break;
			default:
				DBG(DBG_CONTROL, DBG_log("received %s but ignoring it",
					enum_name(&ikev2_notify_names,
						ntfy->payload.v2n.isan_type)));
			}
		}
	}

	/* good. now create child state */
	/* note: as we will switch to child state, we force the parent to the
	 * new state now
	 */

	ikev2_isakamp_established(st, md->svm, STATE_PARENT_R2,
			md->original_role);

#ifdef USE_LINUX_AUDIT
	linux_audit_conn(st, LAK_PARENT_START);
#endif

	authstart = reply_stream.cur;
	/* send response */
	{
		unsigned char *encstart;
		unsigned char *iv;
		unsigned char *authloc;
		struct ikev2_generic e;
		pb_stream e_pbs, e_pbs_cipher;
		bool send_cert = FALSE;
		unsigned int len;
		struct isakmp_hdr hdr;

		/* make sure HDR is at start of a clean buffer */
		init_out_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
			 "reply packet");

		/* HDR out */
		{
			hdr = md->hdr; /* grab cookies */

			hdr.isa_version = build_ikev2_version();
			hdr.isa_np = ISAKMP_NEXT_v2SK;
			hdr.isa_xchg = ISAKMP_v2_AUTH;
			memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
			memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);

			/* set msg responder flag - clear others */
			hdr.isa_flags = ISAKMP_FLAGS_v2_MSG_R;
			if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
				hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
			}

			if (!out_struct(&hdr, &isakmp_hdr_desc,
					&reply_stream, &md->rbody))
				return STF_INTERNAL_ERROR;
		}

		/* insert an Encryption payload header */
		e.isag_np = ISAKMP_NEXT_v2IDr;
		e.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;

		if (!out_struct(&e, &ikev2_sk_desc, &md->rbody, &e_pbs))
			return STF_INTERNAL_ERROR;

		/* insert IV */
		iv = e_pbs.cur;
		if (!emit_wire_iv(st, &e_pbs))
			return STF_INTERNAL_ERROR;

		/* note where cleartext starts */
		init_pbs(&e_pbs_cipher, e_pbs.cur, e_pbs.roof - e_pbs.cur,
			 "cleartext");
		e_pbs_cipher.container = &e_pbs;
		e_pbs_cipher.desc = NULL;
		e_pbs_cipher.cur = e_pbs.cur;
		encstart = e_pbs_cipher.cur;

		/* decide to send CERT payload before we generate IDr */
		send_cert = ikev2_send_cert_decision(st);

		/* send out the IDr payload */
		{
			struct ikev2_id r_id;
			pb_stream r_id_pbs;
			chunk_t id_b;
			struct hmac_ctx id_ctx;
			unsigned char *id_start;
			unsigned int id_len;

			hmac_init(&id_ctx, st->st_oakley.prf, st->st_skey_pr_nss);
			build_id_payload((struct isakmp_ipsec_id *)&r_id,
					 &id_b,
					 &c->spd.this);
			r_id.isai_critical = ISAKMP_PAYLOAD_NONCRITICAL;
			r_id.isai_np = send_cert ?
				ISAKMP_NEXT_v2CERT : ISAKMP_NEXT_v2AUTH;

			id_start = e_pbs_cipher.cur + NSIZEOF_isakmp_generic;

			if (!out_struct(&r_id, &ikev2_id_desc, &e_pbs_cipher,
					&r_id_pbs) ||
			    !out_chunk(id_b, &r_id_pbs, "my identity"))
				return STF_INTERNAL_ERROR;

			close_output_pbs(&r_id_pbs);

			/* calculate hash of IDi for AUTH below */
			id_len = e_pbs_cipher.cur - id_start;
			DBG(DBG_CRYPT,
			    DBG_dump("idhash calc R2", id_start, id_len));
			hmac_update(&id_ctx, id_start, id_len);
			hmac_final(idhash_out, &id_ctx);
		}

		DBG(DBG_CONTROLMORE,
		    DBG_log("assembled IDr payload"));

		/*
		 * send CERT payload RFC 4306 3.6, 1.2:([CERT,] )
		 * upon which our received I2 CERTREQ is ignored,
		 * but ultimately should go into the CERT decision
		 */
		if (send_cert) {
			stf_status certstat = ikev2_send_cert(st, md,
							      ORIGINAL_RESPONDER,
							      ISAKMP_NEXT_v2AUTH,
							      &e_pbs_cipher);

			if (certstat != STF_OK)
				return certstat;
		}

		/* authentication good, see if there is a child SA being proposed */
		if (md->chain[ISAKMP_NEXT_v2SA] == NULL ||
		    md->chain[ISAKMP_NEXT_v2TSi] == NULL ||
		    md->chain[ISAKMP_NEXT_v2TSr] == NULL) {
			/* initiator didn't propose anything. Weird. Try unpending our end. */
			/* UNPEND XXX */
			if ((c->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
				libreswan_log("No CHILD SA proposals received.");
			} else {
				DBG(DBG_CONTROLMORE, DBG_log("No CHILD SA proposals received"));
			}
			np = ISAKMP_NEXT_v2NONE;
		} else {
			DBG(DBG_CONTROLMORE, DBG_log("CHILD SA proposals received"));
			np = (c->pool != NULL && md->chain[ISAKMP_NEXT_v2CP] != NULL) ?
				ISAKMP_NEXT_v2CP : ISAKMP_NEXT_v2SA;
		}

		DBG(DBG_CONTROLMORE,
		    DBG_log("going to assemble AUTH payload"));

		/* now send AUTH payload */
		{
			stf_status authstat = ikev2_send_auth(c, st,
							      ORIGINAL_RESPONDER, np,
							      idhash_out,
							      &e_pbs_cipher);

			if (authstat != STF_OK)
				return authstat;
		}

		if (np == ISAKMP_NEXT_v2SA || np == ISAKMP_NEXT_v2CP) {
			/* must have enough to build an CHILD_SA */
			stf_status ret = ikev2_child_sa_respond(md, ORIGINAL_RESPONDER,
						     &e_pbs_cipher,
						     ISAKMP_v2_AUTH);

			/* note: st: parent; md->st: child */

			if (ret > STF_FAIL) {
				int v2_notify_num = ret - STF_FAIL;

				DBG(DBG_CONTROL,
				    DBG_log("ikev2_child_sa_respond returned STF_FAIL with %s",
					    enum_name(&ikev2_notify_names,
						      v2_notify_num)));
				np = ISAKMP_NEXT_v2NONE; /* use some day if we built a complete packet */
				return ret; /* we should continue building a valid reply packet */
			} else if (ret != STF_OK) {
				DBG(DBG_CONTROL,
				    DBG_log("ikev2_child_sa_respond returned %s",
					enum_name(&stfstatus_name, ret)));
				np = ISAKMP_NEXT_v2NONE; /* use some day if we built a complete packet */
				return ret; /* we should continue building a valid reply packet */
			}
		}

		/*
		 * note:
		 * st: parent state
		 * cst: child, if any, else parent
		 * There is probably no good reason to use st from here on.
		 */
		struct state *const cst = md->st;	/* may actually be parent if no child */

		len = pbs_offset(&e_pbs_cipher);

		if (!ikev2_padup_pre_encrypt(cst, &e_pbs_cipher))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&e_pbs_cipher);

		authloc = ikev2_authloc(cst, &e_pbs);

		if (authloc == NULL)
			return STF_INTERNAL_ERROR;

		close_output_pbs(&e_pbs);
		close_output_pbs(&md->rbody);
		close_output_pbs(&reply_stream);

		if (should_fragment_ike_msg(cst, pbs_offset(&reply_stream),
						TRUE)) {
			chunk_t payload;

			setchunk(payload, e_pbs_cipher.start, len);
			return ikev2_record_fragments(md, &hdr, &e, &payload,
						   "reply fragment for ikev2_parent_inI2outR2_tail");
		} else {
			stf_status ret = ikev2_encrypt_msg(st, authstart,
						iv, encstart, authloc,
						&e_pbs_cipher);

			if (ret == STF_OK) {
				record_outbound_ike_msg(st, &reply_stream,
					"reply packet for ikev2_parent_inI2outR2_auth_tail");
				st->st_msgid_lastreplied = md->msgid_received;
			}

			return ret;
		}
	}

	/* if the child failed, delete its state here - we sent the packet */
	/* PAUL */
	/* ??? what does that mean?  We cannot even reach here. */
}

static void ikev2_child_set_pfs(struct state *st)
{
	struct connection *c = st->st_connection;

	st->st_pfs_group = ike_alg_pfsgroup(c, c->policy);
	if (st->st_pfs_group == NULL &&
			(c->policy & POLICY_PFS) != LEMPTY) {
		struct state *pst = state_with_serialno(st->st_clonedfrom);

		st->st_pfs_group = pst->st_oakley.group;
		DBG(DBG_CONTROL, DBG_log("#%lu no phase2 MODP group specified "
					"on this connection %s use seletected "
					"IKE MODP group %s from #%lu",
					st->st_serialno,
					c->name,
					st->st_pfs_group->common.name,
					pst->st_serialno));
	}
}

stf_status ikev2_process_child_sa_pl(struct msg_digest *md,
		bool expect_accepted)
{
	struct state *st = md->st;
	struct connection *c = st->st_connection;
	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_v2SA];
	enum isakmp_xchg_types isa_xchg = md->hdr.isa_xchg;
	struct ipsec_proto_info *proto_info = ikev2_esp_or_ah_proto_info(st,
			c->policy);
	stf_status ret;
	char *what;

	if (isa_xchg == ISAKMP_v2_CREATE_CHILD_SA) {
		if (st->st_state == STATE_V2_CREATE_I) {
			what = "ESP/AH initiator Child";
		} else {
			ikev2_child_set_pfs(st);
			what = "ESP/AH responder Child";
		}
	} else {
		what = "ESP/AH responder AUTH Child";
	}
	if (!expect_accepted) {
		/* preparing to initiate or parse a request flush old ones */
		free_ikev2_proposals(&c->esp_or_ah_proposals);
	}

	ikev2_proposals_from_alg_info_esp(c->name, what,
			c->alg_info_esp,
			c->policy,
			st->st_pfs_group,
			&c->esp_or_ah_proposals);

	passert(c->esp_or_ah_proposals != NULL);

	ret = ikev2_process_sa_payload(what,
			&sa_pd->pbs,
			/*expect_ike*/ FALSE,
			/*expect_spi*/ TRUE,
			expect_accepted,
			c->policy & POLICY_OPPORTUNISTIC,
			&st->st_accepted_esp_or_ah_proposal,
			c->esp_or_ah_proposals);

	if (ret != STF_OK)
		return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;

	passert(st->st_accepted_esp_or_ah_proposal != NULL);

	if (isa_xchg == ISAKMP_v2_CREATE_CHILD_SA && st->st_pfs_group != NULL) {
		struct trans_attrs accepted_oakley;

		if (!ikev2_proposal_to_trans_attrs(st->st_accepted_esp_or_ah_proposal,
					&accepted_oakley)) {
			loglog(RC_LOG_SERIOUS, "%s responder accepted an unsupported algorithm", what);
			ret = STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
		}

		/* ESP/AH use use IKE negotiated PRF */
		accepted_oakley.prf = st->st_oakley.prf;
		st->st_oakley = accepted_oakley;

		if (!ikev2_proposal_to_trans_attrs(st->st_accepted_esp_or_ah_proposal,
					&accepted_oakley)) {
			loglog(RC_LOG_SERIOUS, "%s responder accepted an unsupported algorithm", what);
			ret = STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
		}
	}

	DBG(DBG_CONTROL, DBG_log_ikev2_proposal(what, st->st_accepted_esp_or_ah_proposal));
	if (!ikev2_proposal_to_proto_info(st->st_accepted_esp_or_ah_proposal, proto_info)) {
		loglog(RC_LOG_SERIOUS, "%s proposed/accepted a proposal we don't actually support!", what);
		ret =  STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
	}

	if (ret != STF_OK) {
		/*
		 * leave it on st for reporting or clean?
		 * it will get freed with st object
		 * free_ikev2_proposal(&st->st_accepted_esp_or_ah_proposal);
		 */
	}
	return ret;
}

static stf_status ikev2_process_ts_and_rest(struct msg_digest *md)
{
	int cp_r;
	struct state *st = md->st;
	struct connection *c = st->st_connection;

	cp_r = ikev2_np_cp_or_sa(c, 0, st->hidden_variables.st_nat_traversal);
	/* are we expecting a v2CP (RESP) ?  */
	if (cp_r == ISAKMP_NEXT_v2CP) {
		if (md->chain[ISAKMP_NEXT_v2CP] == NULL) {
			/* not really anything to here... but it would be worth unpending again */
			libreswan_log("missing v2CP reply, not attempting to setup child SA");
			/* Delete previous retransmission event. */
			delete_event(st);
			/*
			 * ??? this isn't really a failure, is it?
			 * If none of those payloads appeared, isn't this is a
			 * legitimate negotiation of a parent?
			 */
			return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
		}
		if (!ikev2_parse_cp_r_body(md->chain[ISAKMP_NEXT_v2CP], st))
		{
			return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
		}
	}

	/* check TS payloads */
	{
		int bestfit_n, bestfit_p, bestfit_pr;
		int best_tsi_i, best_tsr_i;
		bestfit_n = -1;
		bestfit_p = -1;
		bestfit_pr = -1;

		/* Check TSi/TSr http://tools.ietf.org/html/rfc5996#section-2.9 */
		DBG(DBG_CONTROLMORE,
		    DBG_log(" check narrowing - we are responding to I2"));

		struct payload_digest *const tsi_pd = md->chain[ISAKMP_NEXT_v2TSi];
		struct payload_digest *const tsr_pd = md->chain[ISAKMP_NEXT_v2TSr];
		struct traffic_selector tsi[16], tsr[16];
#if 0
		bool instantiate = FALSE;
		ip_subnet tsi_subnet, tsr_subnet;
		const char *oops;
#endif
		const int tsi_n = ikev2_parse_ts(tsi_pd, tsi, elemsof(tsi));
		const int tsr_n = ikev2_parse_ts(tsr_pd, tsr, elemsof(tsr));

		if (tsi_n < 0 || tsr_n < 0)
			return STF_FAIL + v2N_TS_UNACCEPTABLE;

		DBG(DBG_CONTROLMORE, DBG_log("Checking TSi(%d)/TSr(%d) selectors, looking for exact match",
			tsi_n, tsr_n));

		{
			const struct spd_route *sra = &c->spd;
			int bfit_n = ikev2_evaluate_connection_fit(c, sra,
								   ORIGINAL_INITIATOR,
								   tsi, tsr,
								   tsi_n,
								   tsr_n);
			if (bfit_n > bestfit_n) {
				DBG(DBG_CONTROLMORE,
				    DBG_log("prefix fitness found a better match c %s",
					    c->name));
				int bfit_p = ikev2_evaluate_connection_port_fit(
						c, sra, ORIGINAL_INITIATOR,
						tsi, tsr,
						tsi_n, tsr_n,
						&best_tsi_i, &best_tsr_i);

				if (bfit_p > bestfit_p) {
					DBG(DBG_CONTROLMORE,
					    DBG_log("port fitness found better match c %s, tsi[%d],tsr[%d]",
						    c->name, best_tsi_i, best_tsr_i));
					int bfit_pr = ikev2_evaluate_connection_protocol_fit(
							c, sra, ORIGINAL_INITIATOR, tsi,
							tsr, tsi_n, tsr_n,
							&best_tsi_i,
							&best_tsr_i);
					if (bfit_pr > bestfit_pr) {
						DBG(DBG_CONTROLMORE,
						    DBG_log("protocol fitness found better match c %s, tsi[%d],tsr[%d]",
							    c->name, best_tsi_i,
							    best_tsr_i));
						bestfit_p = bfit_p;
						bestfit_n = bfit_n;
					} else {
						DBG(DBG_CONTROLMORE,
						    DBG_log("protocol fitness rejected c %s",
							    c->name));
					}
				} else {
					DBG(DBG_CONTROLMORE,
							DBG_log("port fitness rejected c %s c->name",
								c->name));
				}
			} else {
				DBG(DBG_CONTROLMORE,
				    DBG_log("prefix fitness rejected c %s c->name",
					    c->name));
			}
		}

		if (bestfit_n > 0 && bestfit_p > 0) {
			DBG(DBG_CONTROLMORE,
			    DBG_log("found an acceptable TSi/TSr Traffic Selector"));
			memcpy(&st->st_ts_this, &tsi[best_tsi_i],
			       sizeof(struct traffic_selector));
			memcpy(&st->st_ts_that, &tsr[best_tsr_i],
			       sizeof(struct traffic_selector));
			ikev2_print_ts(&st->st_ts_this);
			ikev2_print_ts(&st->st_ts_that);

			ip_subnet tmp_subnet_i;
			ip_subnet tmp_subnet_r;
			rangetosubnet(&st->st_ts_this.net.start,
				      &st->st_ts_this.net.end, &tmp_subnet_i);
			rangetosubnet(&st->st_ts_that.net.start,
				      &st->st_ts_that.net.end, &tmp_subnet_r);

			c->spd.this.client = tmp_subnet_i;
			c->spd.this.port = st->st_ts_this.startport;
			c->spd.this.protocol = st->st_ts_this.ipprotoid;
			setportof(htons(c->spd.this.port),
				  &c->spd.this.host_addr);
			setportof(htons(c->spd.this.port),
				  &c->spd.this.client.addr);

			c->spd.this.has_client =
				!(subnetishost(&c->spd.this.client) &&
				addrinsubnet(&c->spd.this.host_addr,
					  &c->spd.this.client));

			c->spd.that.client = tmp_subnet_r;
			c->spd.that.port = st->st_ts_that.startport;
			c->spd.that.protocol = st->st_ts_that.ipprotoid;
			setportof(htons(c->spd.that.port),
				  &c->spd.that.host_addr);
			setportof(htons(c->spd.that.port),
				  &c->spd.that.client.addr);

			c->spd.that.has_client =
				!(subnetishost(&c->spd.that.client) &&
				addrinsubnet(&c->spd.that.host_addr,
					  &c->spd.that.client));
		} else {
			DBG(DBG_CONTROLMORE,
			    DBG_log("reject responder TSi/TSr Traffic Selector"));
			/* prevents parent from going to I3 */
			return STF_FAIL + v2N_TS_UNACCEPTABLE;
		}
	} /* end of TS check block */

	/* examin and accpept SA ESP/AH proposals */
	if (md->hdr.isa_xchg != ISAKMP_v2_CREATE_CHILD_SA)
		RETURN_STF_FAILURE_STATUS(ikev2_process_child_sa_pl(md, TRUE));

	/* examine each notification payload */
	{
		struct payload_digest *p;

		for (p = md->chain[ISAKMP_NEXT_v2N]; p != NULL; p = p->next) {
			/* RFC 5996 */
			/* Types in the range 0 - 16383 are intended for reporting errors.  An
			 * implementation receiving a Notify payload with one of these types
			 * that it does not recognize in a response MUST assume that the
			 * corresponding request has failed entirely.  Unrecognized error types
			 * in a request and status types in a request or response MUST be
			 * ignored, and they should be logged.
			 */
			if (enum_name(&ikev2_notify_names,
				      p->payload.v2n.isan_type) == NULL) {
				if (p->payload.v2n.isan_type <
				    v2N_INITIAL_CONTACT)
					return STF_FAIL +
					       p->payload.v2n.isan_type;
			}

			if (p->payload.v2n.isan_type ==
			    v2N_USE_TRANSPORT_MODE) {
				if (st->st_connection->policy & POLICY_TUNNEL) {
					/* This means we did not send v2N_USE_TRANSPORT, however responder is sending it in now (inR2), seems incorrect */
					DBG(DBG_CONTROLMORE,
					    DBG_log("Initiator policy is tunnel, responder sends v2N_USE_TRANSPORT_MODE notification in inR2, ignoring it"));
				} else {
					DBG(DBG_CONTROLMORE,
					    DBG_log("Initiator policy is transport, responder sends v2N_USE_TRANSPORT_MODE, setting CHILD SA to transport mode"));
					if (st->st_esp.present) {
						st->st_esp.attrs.encapsulation
							= ENCAPSULATION_MODE_TRANSPORT;
					}
					if (st->st_ah.present) {
						st->st_ah.attrs.encapsulation
							= ENCAPSULATION_MODE_TRANSPORT;
					}
				}
			}
		} /* for */
	} /* notification block */

	ikev2_derive_child_keys(st, md->original_role);

	/* now install child SAs */
	if (!install_ipsec_sa(st, TRUE))
		return STF_FATAL;

	set_newest_ipsec_sa("inR2", st);

	/*
	 * Delete previous retransmission event.
	 */
	delete_event(st);

	return STF_OK;
}

/*
 *
 ***************************************************************
 *                       PARENT_inR2    (I3 state)         *****
 ***************************************************************
 *  - there are no cryptographic continuations, but be certain
 *    that there will have to be DNS continuations, but they
 *    just aren't implemented yet.
 *
 */

/* STATE_PARENT_I2: R2 --> I3
 *                     <--  HDR, SK {IDr, [CERT,] AUTH,
 *                               SAr2, TSi, TSr}
 * [Parent SA established]
 *
 * For error handling in this function, please read:
 * https://tools.ietf.org/html/rfc7296#section-2.21.2
 */

stf_status ikev2parent_inR2(struct msg_digest *md)
{
	struct state *st = md->st;
	unsigned char idhash_in[MAX_DIGEST_LEN];
	struct payload_digest *ntfy;
	struct state *pst = st;
	bool got_transport = FALSE;

	if (IS_CHILD_SA(st))
		pst = state_with_serialno(st->st_clonedfrom);

	/* Process NOTIFY payloads before AUTH so we can log any error notifies */
	for (ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
		switch (ntfy->payload.v2n.isan_type) {
		case v2N_COOKIE:
			DBG(DBG_CONTROLMORE, DBG_log("Ignoring bogus COOKIE notify in IKE_AUTH rpely"));
			break;
		case v2N_ESP_TFC_PADDING_NOT_SUPPORTED:
			DBG(DBG_CONTROLMORE, DBG_log("Received ESP_TFC_PADDING_NOT_SUPPORTED - disabling TFC"));
			st->st_seen_no_tfc = TRUE; /* Technically, this should be only on the child sa */
			break;
		case v2N_USE_TRANSPORT_MODE:
			got_transport = TRUE;
			break;
		default:
			DBG(DBG_CONTROLMORE, DBG_log("Received %s notify - ignored",
				enum_name(&ikev2_notify_names,
					ntfy->payload.v2n.isan_type)));
		}
	}

	/* XXX this call might change connection in md->st! */
	if (!ikev2_decode_peer_id_and_certs(md))
		return STF_FAIL + v2N_AUTHENTICATION_FAILED;

	struct connection *c = st->st_connection;
	enum keyword_authby that_authby = c->spd.that.authby;

	passert(that_authby != AUTH_NEVER && that_authby != AUTH_UNSET);

	{
		struct hmac_ctx id_ctx;
		const pb_stream *id_pbs = &md->chain[ISAKMP_NEXT_v2IDr]->pbs;
		unsigned char *idstart = id_pbs->start + NSIZEOF_isakmp_generic;
		unsigned int idlen = pbs_room(id_pbs) - NSIZEOF_isakmp_generic;

		hmac_init(&id_ctx, pst->st_oakley.prf, pst->st_skey_pr_nss);

		/* calculate hash of IDr for AUTH below */
		DBG(DBG_CRYPT, DBG_dump("idhash auth R2", idstart, idlen));
		hmac_update(&id_ctx, idstart, idlen);
		hmac_final(idhash_in, &id_ctx);
	}

	/* process AUTH payload */

	if (!v2_check_auth(md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2a.isaa_type,
		pst, ORIGINAL_INITIATOR, idhash_in, &md->chain[ISAKMP_NEXT_v2AUTH]->pbs,
		that_authby))
	{
		/*
		 * We cannot send a response as we are processing IKE_AUTH reply
		 * the RFC states we should pretend IKE_AUTH was okay, and then
		 * send an INFORMATIONAL DELETE IKE SA but we have not implemented
		 * that yet.
		 */
		return STF_FATAL;
	}

	/* AUTH succeeded */

	/*
	 * update the parent state to make sure that it knows we have
	 * authenticated properly.
	 */
	ikev2_isakamp_established(pst, md->svm, STATE_PARENT_I3, md->original_role);

#ifdef USE_LINUX_AUDIT
	linux_audit_conn(st, LAK_PARENT_START);
#endif

	/* AUTH is ok, we can trust the notify payloads */
	if (!got_transport && ((st->st_connection->policy & POLICY_TUNNEL) == LEMPTY)) {
		libreswan_log("local policy requires Transport Mode but peer requires required Tunnel Mode");
		return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN; /* applies only to Child SA */
	}
	if (got_transport && ((st->st_connection->policy & POLICY_TUNNEL) != LEMPTY)) {
		libreswan_log("local policy requires Tunnel Mode but peer requires required Transport Mode");
		return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN; /* applies only to Child SA */
	}

	/* See if there is a child SA available */
	if (md->chain[ISAKMP_NEXT_v2SA] == NULL ||
	    md->chain[ISAKMP_NEXT_v2TSi] == NULL ||
	    md->chain[ISAKMP_NEXT_v2TSr] == NULL) {
		/* not really anything to here... but it would be worth unpending again */
		libreswan_log("missing v2SA, v2TSi or v2TSr: not attempting to setup child SA");
		/*
		 * Delete previous retransmission event.
		 */
		delete_event(st);
		/*
		 * ??? this isn't really a failure, is it?
		 * If none of those payloads appeared, isn't this is a
		 * legitimate negotiation of a parent?
		 * Paul: this notify is never sent because w
		 */
		return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
	}

	return(ikev2_process_ts_and_rest(md));
}

/*
 * Cookie = <VersionIDofSecret> | Hash(Ni | IPi | SPIi | <secret>)
 * where <secret> is a randomly generated secret known only to us
 *
 * Our implementation does not use <VersionIDofSecret> which means
 * once a day and while under DOS attack, we could fail a few cookies
 * until the peer restarts from scratch.
 */
static void ikev2_get_dcookie(u_char *dcookie, chunk_t ni,
			      ip_address *addr, chunk_t spiI)
{
	size_t addr_length;
	unsigned char addr_buff[
		sizeof(union { struct in_addr A;
			       struct in6_addr B;
		       })];

	addr_length = addrbytesof(addr, addr_buff, sizeof(addr_buff));

	struct crypt_hash *ctx = crypt_hash_init(&ike_alg_hash_sha2_256,
						 "dcookie", DBG_CRYPT);
	crypt_hash_digest_chunk(ctx, "ni", ni);
	crypt_hash_digest_bytes(ctx, "addr", addr_buff, addr_length);
	crypt_hash_digest_chunk(ctx, "spiI", spiI);
	crypt_hash_digest_bytes(ctx, "sod", ikev2_secret_of_the_day,
				SHA2_256_DIGEST_SIZE);
	crypt_hash_final_bytes(&ctx, dcookie, SHA2_256_DIGEST_SIZE);
	DBG(DBG_PRIVATE,
	    DBG_log("ikev2 secret_of_the_day used %s, length %d",
		    ikev2_secret_of_the_day,
		    SHA2_256_DIGEST_SIZE));

	DBG(DBG_CRYPT,
	    DBG_dump("computed dcookie: HASH(Ni | IPi | SPIi | <secret>)",
		     dcookie, SHA2_256_DIGEST_SIZE));
}

/*
 *
 ***************************************************************
 *                       NOTIFICATION_OUT Complete packet  *****
 ***************************************************************
 *
 */

void send_v2_notification(struct state *p1st,
			  v2_notification_t ntype,
			  struct state *encst,
			  u_char *icookie,
			  u_char *rcookie,
			  chunk_t *n_data)
{
	/*
	 * buffer in which to marshal our notification.
	 * We don't use reply_buffer/reply_stream because they might be in use.
	 */
	u_char buffer[1024];	/* ??? large enough for any notification? */
	pb_stream rbody;

	/*
	 * TBD check which of these comments below is still true :)
	 *
	 * TBD accept HDR FLAGS as arg. default ISAKMP_FLAGS_v2_MSG_R
	 * ^--- Is this notify in response to request packet? If so yes.
	 *
	 * TBD if we are the original initiator we must set the
	 *     ISAKMP_FLAGS_v2_IKE_I flag. This is currently not done!
	 *
	 * TBD when there is a child SA use that SPI in the notify paylod.
	 * TBD support encrypted notifications payloads.
	 * TBD accept Critical bit as an argument. default is set.
	 * TBD accept exchange type as an arg, default is ISAKMP_v2_SA_INIT
	 * do we need to send a notify with empty data?
	 * do we need to support more Protocol ID? more than PROTO_ISAKMP
	 */

	{
		ipstr_buf b;

		libreswan_log("sending %sencrypted notification %s to %s:%u",
			encst ? "" : "un",
			enum_name(&ikev2_notify_names, ntype),
			ipstr(&p1st->st_remoteaddr, &b),
			p1st->st_remoteport);
	}

	init_out_pbs(&reply_stream, buffer, sizeof(buffer), "notification msg");

	/* HDR out */
	{
		struct isakmp_hdr hdr;

		zero(&hdr);	/* OK: no pointer fields */
		hdr.isa_version = build_ikev2_version();
		if (rcookie != NULL) /* some responses are with zero rSPI */
			memcpy(hdr.isa_rcookie, rcookie, COOKIE_SIZE);
		memcpy(hdr.isa_icookie, icookie, COOKIE_SIZE);

		/* incomplete */
		switch (p1st->st_state) {
		case STATE_PARENT_R2:
			hdr.isa_xchg = ISAKMP_v2_AUTH;
			break;
		default:
			/* default to old behaviour of hardcoding ISAKMP_v2_SA_INIT */
			hdr.isa_xchg = ISAKMP_v2_SA_INIT;
			break;
		}
		if (p1st->st_reply_xchg != 0)
			hdr.isa_xchg = p1st->st_reply_xchg; /* use received exchange type */

		hdr.isa_np = ISAKMP_NEXT_v2N;
		/* XXX unconditionally clearing original initiator flag is wrong */

		/* add msg responder flag */
		hdr.isa_flags = ISAKMP_FLAGS_v2_MSG_R;
		if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
			hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
		}

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_stream, &rbody)) {
			libreswan_log(
				"error initializing hdr for notify message");
			return;
		}
	}

	/* build and add v2N payload to the packet */
	/* In v2, for parent, protoid must be 0 and SPI must be empty */
	if (!ship_v2N(ISAKMP_NEXT_v2NONE,
		 DBGP(IMPAIR_SEND_BOGUS_PAYLOAD_FLAG) ?
		   (ISAKMP_PAYLOAD_NONCRITICAL | ISAKMP_PAYLOAD_LIBRESWAN_BOGUS) :
		   ISAKMP_PAYLOAD_NONCRITICAL,
		 PROTO_v2_RESERVED,
		 &empty_chunk,
		 ntype, n_data, &rbody))
		return;	/* ??? NO WAY TO SIGNAL INTERNAL ERROR */

	if (!close_message(&rbody, p1st))
		return; /* ??? NO WAY TO SIGNAL INTERNAL ERROR */

	close_output_pbs(&reply_stream);

	/*
	 * The notification is piggybacked on the existing parent state.
	 * This notification is fire-and-forget (not a proper exchange,
	 * one with retrying).  So we need not preserve the packet we
	 * are sending.
	 */
	send_ike_msg_without_recording(p1st, &reply_stream, "v2 notify");

	if (ntype < v2N_ERROR_ROOF)
		pstats(ikev2_sent_notifies_e, ntype);
}

/* add notify payload to the rbody */
bool ship_v2N(enum next_payload_types_ikev2 np,
	u_int8_t critical,
	u_int8_t protoid,
	const chunk_t *spi,
	v2_notification_t type,
	const chunk_t *n_data,
	pb_stream *rbody)
{
	struct ikev2_notify n;
	pb_stream n_pbs;

	/* See RFC 5996 section 3.10 "Notify Payload" */
	passert(protoid == PROTO_v2_RESERVED || protoid == PROTO_v2_AH || protoid == PROTO_v2_ESP);
	passert((protoid == PROTO_v2_RESERVED) == (spi->len == 0));

	DBG(DBG_CONTROLMORE, DBG_log("Adding a v2N Payload"));

	zero(&n);

	n.isan_np = np;
	n.isan_critical = critical;
	if (DBGP(IMPAIR_SEND_BOGUS_PAYLOAD_FLAG)) {
		libreswan_log(
			" setting bogus ISAKMP_PAYLOAD_LIBRESWAN_BOGUS flag in ISAKMP payload");
		n.isan_critical |= ISAKMP_PAYLOAD_LIBRESWAN_BOGUS;
	}

	n.isan_protoid = protoid;
	n.isan_spisize = spi->len;
	n.isan_type = type;

	if (!out_struct(&n, &ikev2_notify_desc, rbody, &n_pbs)) {
		libreswan_log(
			"error initializing notify payload for notify message");
		return FALSE;
	}

	if (spi->len > 0) {
		if (!out_chunk(*spi, &n_pbs, "SPI ")) {
			libreswan_log("error writing SPI to notify payload");
			return FALSE;
		}
	}
	if (n_data != NULL) {
		if (!out_chunk(*n_data, &n_pbs, "Notify data")) {
			libreswan_log(
				"error writing notify payload for notify message");
			return FALSE;
		}
	}

	close_output_pbs(&n_pbs);
	return TRUE;
}

static struct state *find_state_to_rekey(struct payload_digest *p,
		struct state *pst)
{
	struct state *st;
	ipsec_spi_t spi;
	struct ikev2_notify ntfy = p->payload.v2n;

	if (ntfy.isan_protoid == PROTO_IPSEC_ESP ||
			ntfy.isan_protoid == PROTO_IPSEC_AH) {
		DBG(DBG_CONTROLMORE, DBG_log("CREATE_CHILD_SA IPsec SA rekey "
					"Protocol %s",
					enum_show(&ikev2_protocol_names,
						ntfy.isan_protoid)));

	} else {
		libreswan_log("CREATE_CHILD_SA IPsec SA rekey invalid Protocol ID %s",
				enum_show(&ikev2_protocol_names,
					ntfy.isan_protoid));
		return NULL;
	}
	if (ntfy.isan_spisize != sizeof(ipsec_spi_t)) {
		libreswan_log("CREATE_CHILD_SA IPsec SA rekey invalid spi "
				"size %u", ntfy.isan_spisize);
		return NULL;
	}

	if (!in_raw(&spi, sizeof(spi), &p->pbs, "SPI"))
		return NULL;      /* cannot happen */

	DBG(DBG_CONTROLMORE, DBG_log("CREATE_CHILD_S to rekey IPsec SA(0x%08"
				PRIx32 ") Protocol %s", ntohl((uint32_t) spi),
				enum_show(&ikev2_protocol_names,
					ntfy.isan_protoid)));

	st = find_state_ikev2_child_to_delete(pst->st_icookie, pst->st_rcookie,
			ntfy.isan_protoid, spi);
	if (st == NULL) {
		libreswan_log("CREATE_CHILD_SA no such IPsec SA to rekey SA(0x%08"
				PRIx32 ") Protocol %s", ntohl((uint32_t) spi),
				enum_show(&ikev2_protocol_names,
					ntfy.isan_protoid));
	}

	return st;
}

static stf_status ikev2_rekey_child(const struct msg_digest *md)
{
        struct state *st = md->st;  /* new child state */
        struct state *rst = NULL; /* old child state being rekeyed */
        struct payload_digest *ntfy;
        struct state *pst = state_with_serialno(st->st_clonedfrom);
        stf_status ret = STF_OK; /* no v2N_REKEY_SA return OK */

        for (ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
		char cib[CONN_INST_BUF];

                switch (ntfy->payload.v2n.isan_type) {

		case v2N_REKEY_SA:
			DBG(DBG_CONTROL, DBG_log("received v2N_REKEY_SA "));
			if (rst != NULL) {
				/* will tollarate multiple */
				loglog(RC_LOG_SERIOUS, "duplicate v2N_REKEY_SA in excahnge");
			}

			/*
			 * incase of a failure the response is
			 * a v2N_CHILD_SA_NOT_FOUND with  with SPI and type
			 * {AH|ESP} in the notify  do we support that yet?
			 * RFC 7296 3.10 return STF_FAIL + v2N_CHILD_SA_NOT_FOUND;
			 */
			change_state(st, STATE_V2_REKEY_CHILD_R);
			rst = find_state_to_rekey(ntfy, pst);
			if (rst == NULL) {
				libreswan_log("no valid IPsec SA SPI to rekey");
				ret = STF_FAIL + v2N_CHILD_SA_NOT_FOUND;
			} else {

				st->st_ipsec_pred = rst->st_serialno;

				DBG(DBG_CONTROLMORE, DBG_log("#%lu rekey request for \"%s\"%s #%lu TSi TSr",
							st->st_serialno,
							rst->st_connection->name,
							fmt_conn_instance(rst->st_connection, cib),
							rst->st_serialno));
				ikev2_print_ts(&rst->st_ts_this);
				ikev2_print_ts(&rst->st_ts_that);

				ret = STF_OK;
			}

			break;
		default:
			/*
			 * there is another pass of notify payloads after this
			 * that will handle all other but REKEY
			 */
			break;
		}
	}

	return ret;
}

static stf_status ikev2_rekey_child_copy_ts(const struct msg_digest *md)
{
	struct state *st = md->st;  /* new child state */
	struct state *rst; /* old child state being rekeyed */
	stf_status ret = STF_OK; /* if no v2N_REKEY_SA return OK */
	struct spd_route *spd;

	if (st->st_ipsec_pred == SOS_NOBODY) {
		/* this is not rekey quietly return */
		return ret;
	}

	rst = state_with_serialno(st->st_ipsec_pred);

	if (rst == NULL) {
		/* add SPI and type {AH|ESP} in the notify, RFC 7296 3.10 */
		return STF_FAIL + v2N_CHILD_SA_NOT_FOUND;
	}

	/*
	 * RFC 7296 #2.9.2 the exact or the superset.
	 * exact is a should. Here libreswan only allow the exact.
	 * Inherit the TSi TSr from old state, IPsec SA.
	 */

	DBG(DBG_CONTROLMORE, {
			char cib[CONN_INST_BUF];

			DBG_log("#%lu inherit spd, TSi TSr, from "
					"\"%s\"%s #%lu", st->st_serialno,
					rst->st_connection->name,
					fmt_conn_instance(rst->st_connection, cib),
					rst->st_serialno); });


	spd = &rst->st_connection->spd;
	st->st_ts_this = ikev2_end_to_ts(&spd->this);
	st->st_ts_that = ikev2_end_to_ts(&spd->that);
	ikev2_print_ts(&st->st_ts_this);
	ikev2_print_ts(&st->st_ts_that);

	return ret;
}


/* once done use the same function in ikev2_parent_inR1outI2_tail too */
static stf_status ikev2_child_add_ipsec_payloads(struct msg_digest *md,
                                  pb_stream *outpbs,
				  enum isakmp_xchg_types isa_xchg)
{
	bool send_use_transport;
	/* child connection */
	struct state *cst = md->st;
	struct connection *cc = cst->st_connection;
	enum next_payload_types_ikev2 np = isa_xchg ==
		ISAKMP_v2_CREATE_CHILD_SA ? ISAKMP_NEXT_v2Ni :
		ISAKMP_NEXT_v2TSi;

	send_use_transport = (cc->policy & POLICY_TUNNEL) == LEMPTY;

	/* ??? this code won't support AH + ESP */
	struct ipsec_proto_info *proto_info
		= ikev2_esp_or_ah_proto_info(cst, cc->policy);
	proto_info->our_spi = ikev2_esp_or_ah_spi(&cc->spd, cc->policy);
	chunk_t local_spi;
	setchunk(local_spi, (uint8_t*)&proto_info->our_spi,
			sizeof(proto_info->our_spi));

	ikev2_proposals_from_alg_info_esp(cc->name, "initiator",
			cc->alg_info_esp,
			cc->policy, cst->st_pfs_group,
			&cc->esp_or_ah_proposals);
	passert(cc->esp_or_ah_proposals != NULL);

	ikev2_emit_sa_proposals(outpbs, cc->esp_or_ah_proposals,
			&local_spi, np);

	if (isa_xchg == ISAKMP_v2_CREATE_CHILD_SA) {
		/* send NONCE */
		struct ikev2_generic in;
		pb_stream pb_nr;

		zero(&in);      /* OK: no pointer fields */
		in.isag_np =  (cst->st_pfs_group != NULL) ? ISAKMP_NEXT_v2KE :
			ISAKMP_NEXT_v2TSi;
		in.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;
		if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
			libreswan_log(" setting bogus ISAKMP_PAYLOAD_LIBRESWAN_BOGUS flag in ISAKMP payload");
			in.isag_critical |= ISAKMP_PAYLOAD_LIBRESWAN_BOGUS;
		}
		if (!out_struct(&in, &ikev2_nonce_desc, outpbs, &pb_nr) ||
				!out_chunk(cst->st_ni, &pb_nr, "IKEv2 nonce"))
			return STF_INTERNAL_ERROR;
		close_output_pbs(&pb_nr);

		if (in.isag_np == ISAKMP_NEXT_v2KE)  {
			if (!justship_v2KE(&cst->st_gi,
						cst->st_pfs_group, outpbs,
						ISAKMP_NEXT_v2TSi))
				return STF_INTERNAL_ERROR;
		}
	}

	cst->st_ts_this = ikev2_end_to_ts(&cc->spd.this);
	cst->st_ts_that = ikev2_end_to_ts(&cc->spd.that);

	ikev2_calc_emit_ts(md, outpbs, ORIGINAL_INITIATOR, cc,
			(send_use_transport || cc->send_no_esp_tfc) ?
			ISAKMP_NEXT_v2N : ISAKMP_NEXT_v2NONE);

	if ((cc->policy & POLICY_TUNNEL) == LEMPTY) {
		DBG(DBG_CONTROL, DBG_log("Initiator child policy is transport mode, sending v2N_USE_TRANSPORT_MODE"));
		/* In v2, for parent, protoid must be 0 and SPI must be empty */
		if (!ship_v2N(cc->send_no_esp_tfc ? ISAKMP_NEXT_v2N : ISAKMP_NEXT_v2NONE,
					ISAKMP_PAYLOAD_NONCRITICAL,
					PROTO_v2_RESERVED,
					&empty_chunk,
					v2N_USE_TRANSPORT_MODE, &empty_chunk,
					outpbs))
			return STF_INTERNAL_ERROR;
	}

	if (cc->send_no_esp_tfc) {
		if (!ship_v2N(ISAKMP_NEXT_v2NONE,
					ISAKMP_PAYLOAD_NONCRITICAL,
					PROTO_v2_RESERVED,
					&empty_chunk,
					v2N_ESP_TFC_PADDING_NOT_SUPPORTED, &empty_chunk,
					outpbs))
			return STF_INTERNAL_ERROR;
	}
	return STF_OK;
}

static stf_status ikev2_child_add_ike_payloads(struct msg_digest *md,
                                  pb_stream *outpbs)
{
	struct state *st = md->st;
	struct connection *c = st->st_connection;
	chunk_t local_spi;
	chunk_t local_nonce;
	chunk_t *local_g;

	if (is_msg_request(md)) {
		local_g = &st->st_gr;
		setchunk(local_spi, st->st_rcookie,
				sizeof(st->st_rcookie));
		local_nonce = st->st_nr;

		/* send selected v2 IKE SA */
		if (!ikev2_emit_sa_proposal(outpbs, st->st_accepted_ike_proposal,
					&local_spi, ISAKMP_NEXT_v2Ni)) {
			DBG(DBG_CONTROL, DBG_log("problem emitting accepted ike proposal in CREATE_CHILD_SA"));
			return STF_INTERNAL_ERROR;
		}
	} else {
		local_g = &st->st_gi;
		setchunk(local_spi, st->st_icookie,
				sizeof(st->st_icookie));
		local_nonce = st->st_ni;

		free_ikev2_proposals(&c->ike_proposals);
		ikev2_proposals_from_alg_info_ike(c->name,
				"ike rekey initiating child",
				c->alg_info_ike,
				&c->ike_proposals);

		/* send v2 IKE SAs*/
		if (!ikev2_emit_sa_proposals(outpbs,
					st->st_connection->ike_proposals,
					&local_spi,
					ISAKMP_NEXT_v2Ni))  {
			libreswan_log("outsa fail");
			DBG(DBG_CONTROL, DBG_log("problem emitting connection ike proposals in CREATE_CHILD_SA"));
			return STF_INTERNAL_ERROR;
		}
	}

	/* send NONCE */
	{
		struct ikev2_generic in;
		pb_stream nr_pbs;

		zero(&in);      /* OK: no pointer fields */
		in.isag_np = ISAKMP_NEXT_v2KE;
		if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
			libreswan_log(" setting bogus ISAKMP_PAYLOAD_LIBRESWAN_BOGUS flag in ISAKMP payload");
			in.isag_critical |= ISAKMP_PAYLOAD_LIBRESWAN_BOGUS;
		}
		if (!out_struct(&in, &ikev2_nonce_desc, outpbs, &nr_pbs) ||
				!out_chunk(local_nonce, &nr_pbs, "IKEv2 nonce"))
			return STF_INTERNAL_ERROR;
		close_output_pbs(&nr_pbs);

	}
	if (!justship_v2KE(local_g, st->st_oakley.group, outpbs,
			   ISAKMP_NEXT_v2NONE))
		return STF_INTERNAL_ERROR;

	return STF_OK;
}

static notification_t accept_child_sa_KE(struct msg_digest *md,
		struct state *st, struct trans_attrs accepted_oakley)
{
	if (md->chain[ISAKMP_NEXT_v2KE] != NULL) {
		chunk_t accepted_g = empty_chunk;
		{
			if (accept_KE(&accepted_g, "Gi", accepted_oakley.group,
					&md->chain[ISAKMP_NEXT_v2KE]->pbs)
					!= NOTHING_WRONG) {
				/*
				 * A KE with the incorrect number of bytes is
				 * a syntax error and not a wrong modp group.
				 */
				freeanychunk(accepted_g);
				return v2N_INVALID_KE_PAYLOAD;
			}
		}
		if (is_msg_request(md))
			st->st_gi = accepted_g;
		else
			st->st_gr = accepted_g;
	}

	return NOTHING_WRONG;
}

static notification_t process_ike_rekey_sa_pl(struct msg_digest *md, struct state *pst,
		struct state *st)
{
	struct connection *c = st->st_connection;
	struct ikev2_proposal *accepted_ike_proposal = NULL;
	struct trans_attrs accepted_oakley;
	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_v2SA];

	/* Get the proposals ready.  */
	ikev2_proposals_from_alg_info_ike(c->name, "CREATE_CHILD_SA IKE rekey responder",
						c->alg_info_ike,
						&c->ike_proposals);
	passert(c->ike_proposals != NULL);
	stf_status ret = ikev2_process_sa_payload("IKE Rekey responder child",
			&sa_pd->pbs,
			/*expect_ike*/ TRUE,
			/*expect_spi*/ TRUE,
			/*expect_accepted*/ FALSE,
			c->policy & POLICY_OPPORTUNISTIC,
			&accepted_ike_proposal,
			c->ike_proposals);
	if (ret != STF_OK) {
		passert(accepted_ike_proposal == NULL);
		return ret;
	}
	if (accepted_ike_proposal == NULL) {
		return ret;
	}
	DBG(DBG_CONTROL, DBG_log_ikev2_proposal("accepted IKE proposal",
				accepted_ike_proposal));
	/*
	 * Early return must free: accepted_ike_proposal
	 */
	if (!ikev2_proposal_to_trans_attrs(accepted_ike_proposal,
			&accepted_oakley)) {
		loglog(RC_LOG_SERIOUS, "IKE responder accepted an unsupported algorithm");
		/* free early return items */
		free_ikev2_proposal(&accepted_ike_proposal);
		md->st = pst;
		return STF_IGNORE;
	}

	ret = ikev2_match_ke_group_and_proposal(md, accepted_oakley.group);
	if (ret != STF_OK) {
		free_ikev2_proposal(&accepted_ike_proposal);
		md->st = pst;
		return ret;
	}

	/*
	 * Check and read the KE contents.
	 */

	/* KE in with new accepted_oakley for IKE */
	notification_t res = accept_child_sa_KE(md, st, accepted_oakley);
	if (res != NOTHING_WRONG) {
		free_ikev2_proposal(&accepted_ike_proposal);
		return STF_FAIL + res;
	}

	/* save the proposal information */
	st->st_oakley = accepted_oakley;
	st->st_accepted_ike_proposal = accepted_ike_proposal;

	ikev2_copy_cookie_from_sa(st, accepted_ike_proposal);
	get_cookie(TRUE, st->st_rcookie, &md->sender);
	insert_state(st); /* needed for delete - we are duplicating early */

	return STF_OK;
}


/* ikev2 initiator received a create Child SA Response */
stf_status ikev2_child_inR(struct msg_digest *md)
{
	struct state *st = md->st;
	stf_status e;

	RETURN_STF_FAILURE(accept_v2_nonce(md, &st->st_nr, "Nr"));

	RETURN_STF_FAILURE_STATUS(ikev2_process_child_sa_pl(md, TRUE));

	if (st->st_pfs_group == NULL) {
		e = ikev2_process_ts_and_rest(md);
		return e;
	}

	RETURN_STF_FAILURE(accept_child_sa_KE(md, st, st->st_oakley));

	e = ikev2_crypto_start(md, st);

	return e;
}

/* processing a new Child SA (RFC 7296 1.3.1 or 1.3.3) request */
stf_status ikev2_child_inIoutR(struct msg_digest *md)
{
	struct state *st = md->st; /* child state */
	struct state *pst = state_with_serialno(st->st_clonedfrom);

	passert(pst != NULL);

	freeanychunk(st->st_ni); /* this is from the parent. */
	freeanychunk(st->st_nr); /* this is from the parent. */

	/* Ni in */
	RETURN_STF_FAILURE(accept_v2_nonce(md, &st->st_ni, "Ni"));

	RETURN_STF_FAILURE_STATUS(ikev2_process_child_sa_pl(md, FALSE));

	/* KE in with old(pst) and matching accepted_oakley from proposals */
	RETURN_STF_FAILURE(accept_child_sa_KE(md, st, st->st_oakley));

	/* check N_REKEY_SA in the negotation */
	RETURN_STF_FAILURE_STATUS(ikev2_rekey_child(md));

	if (st->st_ipsec_pred == SOS_NOBODY) {
		RETURN_STF_FAILURE_STATUS(ikev2_resp_accept_child_ts(md, &st,
					ORIGINAL_RESPONDER,
					ISAKMP_v2_CREATE_CHILD_SA));
	}

	stf_status e = ikev2_crypto_start(md, st);
	return e;
}

/* processsing a new Rekey IKE SA (RFC 7296 1.3.2) request */
stf_status ikev2_child_ike_inIoutR(struct msg_digest *md)
{
	struct state *st = md->st; /* child state */
	struct state *pst = state_with_serialno(st->st_clonedfrom);

	passert(pst != NULL);

	/* child's role could be different from original ike role, of pst; */
	st->st_original_role = ORIGINAL_RESPONDER;

	freeanychunk(st->st_ni); /* this is from the parent. */
	freeanychunk(st->st_nr); /* this is from the parent. */

	/* Ni in */
	RETURN_STF_FAILURE(accept_v2_nonce(md, &st->st_ni, "Ni"));

	RETURN_STF_FAILURE_STATUS(process_ike_rekey_sa_pl(md, pst,st));

	return ikev2_crypto_start(md, st);
}

static stf_status ikev2_child_out_tail(struct msg_digest *md)
{
	struct state *st = md->st;
	struct state *pst = state_with_serialno(st->st_clonedfrom);
	unsigned char *authstart;
	unsigned char *encstart;
	unsigned char *iv;
	struct ikev2_generic e;
	pb_stream e_pbs, e_pbs_cipher;
	stf_status ret;

	passert(pst != NULL);

	/* ??? this is kind of odd: regular control flow only selecting DBG  output */
	if (DBGP(DBG_PRIVATE) && DBGP(DBG_CRYPT))
		ikev2_log_parentSA(st);

	init_out_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer), "reply packet");
	authstart = reply_stream.cur;

	/* HDR out Start assembling respone message */
	{
		struct isakmp_hdr hdr;

		zero(&hdr);	/* OK: no pointer fields */
		hdr.isa_version = build_ikev2_version();
		memcpy(hdr.isa_rcookie, pst->st_rcookie, COOKIE_SIZE);
		memcpy(hdr.isa_icookie, pst->st_icookie, COOKIE_SIZE);
		hdr.isa_xchg = ISAKMP_v2_CREATE_CHILD_SA;
		hdr.isa_np = ISAKMP_NEXT_v2SK;
		if (IS_CHILD_SA_RESPONDER(st)) {
			hdr.isa_msgid = htonl(md->msgid_received);
			hdr.isa_flags = ISAKMP_FLAGS_v2_MSG_R; /* response on */
		} else {
			hdr.isa_msgid = htonl(pst->st_msgid_nextuse);
			/* store it to match response */
			st->st_msgid = htonl(pst->st_msgid_nextuse);
		}

		if (pst->st_original_role == ORIGINAL_INITIATOR) {
			hdr.isa_flags |= ISAKMP_FLAGS_v2_IKE_I;
		}

		if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG))
			hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;

		if (!IS_CHILD_SA_RESPONDER(st)) {
			md->hdr = hdr; /* fill it with fake header ??? */
		}
		if (!out_struct(&hdr, &isakmp_hdr_desc,
				&reply_stream, &md->rbody))
			return STF_FATAL;
	}

	/* insert an Encryption payload header */
	e.isag_np = ISAKMP_NEXT_v2SA;
	e.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;
	if (!out_struct(&e, &ikev2_sk_desc, &md->rbody, &e_pbs))
		return STF_INTERNAL_ERROR;

	/* IV */
	iv = e_pbs.cur;
	if (!emit_wire_iv(pst, &e_pbs))
		return STF_INTERNAL_ERROR;

	/* note where cleartext starts */
	init_pbs(&e_pbs_cipher, e_pbs.cur, e_pbs.roof - e_pbs.cur,
			"cleartext CREATE_CHILD_SA reply");

	e_pbs_cipher.container = &e_pbs;
	e_pbs_cipher.desc = NULL;
	e_pbs_cipher.cur = e_pbs.cur;
	encstart = e_pbs_cipher.cur;

	if (st->st_state == STATE_V2_REKEY_IKE_R) {
		ret = ikev2_child_add_ike_payloads(md, &e_pbs_cipher);
	} else if (st->st_state == STATE_V2_CREATE_I0) {
		free_ikev2_proposals(&st->st_connection->esp_or_ah_proposals);
		ret = ikev2_child_add_ipsec_payloads(md, &e_pbs_cipher,
				ISAKMP_v2_CREATE_CHILD_SA);
	} else  {
		RETURN_STF_FAILURE_STATUS(ikev2_rekey_child_copy_ts(md));
		ret = ikev2_child_sa_respond(md, ORIGINAL_RESPONDER,
				&e_pbs_cipher, ISAKMP_v2_CREATE_CHILD_SA);
	}

	/* note: pst: parent; md->st: child */

	if (ret > STF_FAIL) {
		int v2_notify_num = ret - STF_FAIL;

		DBG_log("ikev2_child_sa_respond returned STF_FAIL with %s",
				enum_name(&ikev2_notify_names, v2_notify_num));
		return ret; /* abort building the response message */
	} else if (ret != STF_OK) {
		DBG_log("ikev2_child_sa_respond returned %s",
				enum_name(&stfstatus_name, ret));
		return ret; /* abort building the response message */
	}

	if (!ikev2_padup_pre_encrypt(pst, &e_pbs_cipher))
		return STF_INTERNAL_ERROR;

	close_output_pbs(&e_pbs_cipher);

	{
		unsigned char *authloc = ikev2_authloc(pst, &e_pbs);

		if (authloc == NULL)
			return STF_INTERNAL_ERROR;

		close_output_pbs(&e_pbs);
		close_output_pbs(&md->rbody);
		close_output_pbs(&reply_stream);
		ret = ikev2_encrypt_msg(pst, authstart, iv, encstart,
					authloc, &e_pbs_cipher);

		if (ret != STF_OK)
			return ret;
	}

	/*
	 * CREATE_CHILD_SA request and response are small 300 - 750 bytes.
	 * should we support fragmenting? may be one day.
	 */
	record_outbound_ike_msg(pst, &reply_stream,
				"packet from ikev2_child_out_cont");

	pst->st_msgid_lastreplied = md->msgid_received;

	if (st->st_state == STATE_V2_CREATE_R ||
			st->st_state == STATE_V2_REKEY_CHILD_R) {
		log_ipsec_sa_established("negotiated new IPsec SA", st);
	}

	return STF_OK;
}

stf_status ikev2_child_inR_tail(struct pluto_crypto_req_cont *qke,
					struct pluto_crypto_req *r UNUSED)
{
	struct msg_digest *md = qke->pcrc_md;
	stf_status e = ikev2_process_ts_and_rest(md);

	return e;
}
stf_status ikev2_child_out_cont(struct pluto_crypto_req_cont *qke,
					struct pluto_crypto_req *r UNUSED)
{
	struct msg_digest *md = qke->pcrc_md;
	stf_status e = ikev2_child_out_tail(md);
	return e;
}

void ikev2_child_send_next( struct state *st)
{
	struct msg_digest *md = st->st_suspended_md;
	stf_status e;
	set_cur_state(st);
	unset_suspended(st);
	e = ikev2_child_out_tail(md);
	complete_v2_state_transition(&md, e);
	release_any_md(&md);
	reset_globals();
	return;
}

static void delete_or_replace_state(struct state *st) {
	struct connection *c = st->st_connection;

	if (st->st_event == NULL) { /* this could be an assert/except? */
		loglog(RC_LOG_SERIOUS, "received Delete SA payload: delete IPSEC State #%lu. st_event == NULL",
				st->st_serialno);
		delete_state(st);
		return;
	}

	if (st->st_event->ev_type == EVENT_SA_EXPIRE) {
		/* this state  was going to  EXPIRE just let it now*/
		delete_event(st);
		event_schedule(EVENT_SA_EXPIRE, 0, st);
		loglog(RC_LOG_SERIOUS, "received Delete SA payload: expire IPSEC State #%lu now",
				st->st_serialno);
		return;
	}

	if ((c->newest_ipsec_sa == st->st_serialno && (c->policy & POLICY_UP))
		&& ((st->st_event->ev_type == EVENT_SA_REPLACE) ||
		    (st->st_event->ev_type == EVENT_v2_SA_REPLACE_IF_USED))) {
		/*
		 * Last IPsec SA for a permanent  connection that we have initiated.
		 * Replace it now.  Useful if the other peer is rebooting.
		 */
		loglog(RC_LOG_SERIOUS, "received Delete SA payload: replace IPSEC State #%lu now",
				st->st_serialno);
		delete_event(st);
		st->st_margin = deltatime(0);
		event_schedule(EVENT_SA_REPLACE, 0, st);
	} else {
		loglog(RC_LOG_SERIOUS, "received Delete SA payload: delete IPSEC State #%lu now",
				st->st_serialno);
		delete_state(st);
	}
}

/*
 *
 ***************************************************************
 *                       INFORMATIONAL                     *****
 ***************************************************************
 *  -
 *
 *
 */

/* RFC 5996 1.4 "The INFORMATIONAL Exchange"
 *
 * HDR, SK {[N,] [D,] [CP,] ...}  -->
 *   <--  HDR, SK {[N,] [D,] [CP], ...}
 */

stf_status process_encrypted_informational_ikev2(struct msg_digest *md)
{
	struct state *st = md->st;
	struct payload_digest *p;

	/* Are we responding (as opposed to processing a response)? */
	const bool responding = (md->hdr.isa_flags & ISAKMP_FLAGS_v2_MSG_R) == 0;

	/*
	 * get parent
	 *
	 * ??? shouldn't st always be the parent?
	 */
	pexpect(!IS_CHILD_SA(st));	/* ??? why would st be a child? */

	if (IS_CHILD_SA(st)) {
		/* we picked incomplete child, change to parent */
		so_serial_t c_serialno = st->st_serialno;

		st = state_with_serialno(st->st_clonedfrom);
		if (st == NULL)
			return STF_INTERNAL_ERROR;

		md->st = st;
		set_cur_state(st);
		DBG(DBG_CONTROLMORE,
		    DBG_log("Informational exchange matched Child SA #%lu - switched to its Parent SA #%lu",
			c_serialno, st->st_serialno));
	}

	if (!LHAS(st->hidden_variables.st_nat_traversal, NATED_HOST))
		update_ike_endpoints(st, md);

	/*
	 * We only process Delete Payloads. The rest are
	 * ignored.
	 *
	 * RFC 7296 1.4.1 "Deleting an SA with INFORMATIONAL Exchanges"
	 */

	/*
	 * Pass 1 over Delete Payloads:
	 *
	 * - Count number of IPsec SA Delete Payloads
	 * - notice any IKE SA Delete Payload
	 * - sanity checking
	 */
	int ndp = 0;	/* number Delete payloads for IPsec protocols */
	bool del_ike = FALSE;	/* any IKE SA Deletions? */

	for (p = md->chain[ISAKMP_NEXT_v2D]; p != NULL; p = p->next) {
		struct ikev2_delete *v2del = &p->payload.v2delete;

		switch (v2del->isad_protoid) {
		case PROTO_ISAKMP:
			if (!responding) {
				libreswan_log("Response to Delete improperly includes IKE SA");
				return STF_FAIL + v2N_INVALID_SYNTAX;
			}

			if (del_ike) {
				libreswan_log("Error: INFORMATIONAL Exchange with more than one Delete Payload for the IKE SA");
				return STF_FAIL + v2N_INVALID_SYNTAX;
			}

			if (v2del->isad_nrspi != 0 || v2del->isad_spisize != 0) {
				libreswan_log("IKE SA Delete has non-zero SPI size or number of SPIs");
				return STF_FAIL + v2N_INVALID_SYNTAX;
			}

			del_ike = TRUE;
			break;

		case PROTO_IPSEC_AH:
		case PROTO_IPSEC_ESP:
			if (v2del->isad_spisize != sizeof(ipsec_spi_t)) {
				libreswan_log("IPsec Delete Notification has invalid SPI size %u",
					v2del->isad_spisize);
				return STF_FAIL + v2N_INVALID_SYNTAX;
			}

			if (v2del->isad_nrspi * v2del->isad_spisize != pbs_left(&p->pbs)) {
				libreswan_log("IPsec Delete Notification payload size is %zu but %u is required",
					pbs_left(&p->pbs),
					v2del->isad_nrspi * v2del->isad_spisize);
				return STF_FAIL + v2N_INVALID_SYNTAX;
			}

			ndp++;
			break;

		default:
			libreswan_log("Ignored bogus delete protoid '%d'", v2del->isad_protoid);
		}
	}

	if (del_ike && ndp != 0)
		libreswan_log("Odd: INFORMATIONAL Exchange deletes IKE SA and yet also deletes some IPsec SA");

	/*
	 * response packet preparation
	 *
	 * We respond to the Informational with an Informational.
	 *
	 * There can be at most one Delete Payload for an IKE SA.
	 * It means that this very SA is to be deleted.
	 *
	 * For each non-IKE Delete Payload we receive,
	 * we respond with a corresponding Delete Payload.
	 * Note that that means we will have an empty response
	 * if no Delete Payloads came in or if the only
	 * Delete Payload is for an IKE SA.
	 */

	/* variables for generating response (if we are responding) */

	pb_stream e_pbs, e_pbs_cipher;
	unsigned char *iv = NULL;	/* initialized to silence GCC */
	unsigned char *encstart = NULL;	/* initialized to silence GCC */
	unsigned char *authstart = reply_stream.cur;

	if (responding) {
		/* make sure HDR is at start of a clean buffer */
		init_out_pbs(&reply_stream, reply_buffer,
			 sizeof(reply_buffer),
			 "information exchange reply packet");

		DBG(DBG_CONTROLMORE | DBG_DPD,
		    DBG_log("updating st_last_liveness, no pending_liveness"));

		st->st_last_liveness = mononow();
		st->st_pend_liveness = FALSE;

		/* HDR out */
		{
			struct isakmp_hdr hdr;

			zero(&hdr);	/* OK: no pointer fields */
			hdr.isa_version = build_ikev2_version();
			memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
			memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
			hdr.isa_xchg = ISAKMP_v2_INFORMATIONAL;
			hdr.isa_np = ISAKMP_NEXT_v2SK;
			hdr.isa_msgid = htonl(md->msgid_received);

			hdr.isa_flags = ISAKMP_FLAGS_v2_MSG_R;
			if (md->original_role == ORIGINAL_INITIATOR)
				hdr.isa_flags |= ISAKMP_FLAGS_v2_IKE_I;
			if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG))
				hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;

			if (!out_struct(&hdr, &isakmp_hdr_desc,
					&reply_stream, &md->rbody))
				return STF_INTERNAL_ERROR;
		}

		/* insert an Encryption payload header */
		{
			struct ikev2_generic e;

			e.isag_np = (del_ike || ndp == 0) ?
				ISAKMP_NEXT_v2NONE : ISAKMP_NEXT_v2D;

			e.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;

			if (!out_struct(&e, &ikev2_sk_desc, &md->rbody, &e_pbs))
				return STF_INTERNAL_ERROR;
		}

		/* insert IV */
		iv = e_pbs.cur;
		if (!emit_wire_iv(st, &e_pbs))
			return STF_INTERNAL_ERROR;

		/* note where cleartext starts in output */
		init_pbs(&e_pbs_cipher, e_pbs.cur,
			 e_pbs.roof - e_pbs.cur, "cleartext");
		e_pbs_cipher.container = &e_pbs;
		e_pbs_cipher.desc = NULL;
		e_pbs_cipher.cur = e_pbs.cur;
		encstart = e_pbs_cipher.cur;
	}

	/*
	 * Do the actual deletion.
	 * If responding, build the body of the response.
	 */

	if (!responding &&
	    st->st_state == STATE_IKESA_DEL) {
		/*
		 * this must be a response to our IKE SA delete request
		 * Even if there are are other Delete Payloads,
		 * they cannot matter: we delete the family.
		 */
		delete_my_family(st, TRUE);
		md->st = st = NULL;
	} else if (!responding &&
		   md->chain[ISAKMP_NEXT_v2D] == NULL) {
		/* A liveness update response */
		/* ??? why wouldn't any INFORMATIONAL count, even one that
		 * is actually deleting SAs?
		 */
		DBG(DBG_CONTROLMORE,
		    DBG_log("Received an INFORMATIONAL response; updating liveness, no longer pending."));
		st->st_last_liveness = mononow();
		st->st_pend_liveness = FALSE;
	} else if (del_ike) {
		/*
		 * If we are deleting the Parent SA, the Child SAs will be torn down as well,
		 * so no point processing the other Delete SA payloads.
		 * We won't catch nonsense in those payloads.
		 *
		 * But wait: we cannot delete the IKE SA until after we've sent
		 * the response packet.  To be continued...
		 */
		passert(responding);
	} else {
		/*
		 * Pass 2 over the Delete Payloads:
		 * Actual IPsec SA deletion.
		 * If responding, build response Delete Payloads.
		 * If there is no payload, this loop is a no-op.
		 */
		int pli = 0;	/* payload index */

		for (p = md->chain[ISAKMP_NEXT_v2D]; p != NULL;
		     p = p->next) {
			struct ikev2_delete *v2del =
				&p->payload.v2delete;

			switch (v2del->isad_protoid) {
			case PROTO_ISAKMP:
				PASSERT_FAIL("%s", "unexpected IKE delete");

			case PROTO_IPSEC_AH: /* Child SAs */
			case PROTO_IPSEC_ESP: /* Child SAs */
			{
				/* stuff for responding */
				ipsec_spi_t spi_buf[128];
				u_int16_t j = 0;	/* number of SPIs in spi_buf */
				u_int16_t i;

				for (i = 0; i < v2del->isad_nrspi; i++) {
					ipsec_spi_t spi;

					if (!in_raw(&spi, sizeof(spi), &p->pbs, "SPI"))
						return STF_INTERNAL_ERROR;	/* cannot happen */

					DBG(DBG_CONTROLMORE, DBG_log(
						    "delete %s SA(0x%08" PRIx32 ")",
						    enum_show(&ikev2_protocol_names,
							    v2del->isad_protoid),
						    ntohl((uint32_t)
							  spi)));

					struct state *dst =
						find_state_ikev2_child_to_delete(
							st->st_icookie,
							st->st_rcookie,
							v2del->isad_protoid,
							spi);

					passert(dst != st);	/* st is an IKE SA */
					if (dst == NULL) {
						libreswan_log(
						    "received delete request for %s SA(0x%08" PRIx32 ") but corresponding state not found",
							    enum_show(&ikev2_protocol_names, v2del->isad_protoid),
								ntohl((uint32_t)spi));
					} else {
						DBG(DBG_CONTROLMORE,
							DBG_log("our side SPI that needs to be deleted: %s SA(0x%08" PRIx32 ")",
								enum_show(&ikev2_protocol_names,
									v2del->isad_protoid),
								ntohl((uint32_t)spi)));
						/* we just recieved a delete, don't send anther delete */
						dst->st_ikev2_no_del = TRUE;
						passert(dst != st);	/* st is a parent */
						if (!del_ike && responding) {
							struct ipsec_proto_info *pr =
								v2del->isad_protoid == PROTO_IPSEC_AH ?
									&dst->st_ah :
									&dst->st_esp;

							if (j < elemsof(spi_buf)) {
								spi_buf[j] = pr->our_spi;
								j++;
							} else {
								libreswan_log("too many SPIs in Delete Notification payload; ignoring 0x%08" PRIx32,
									ntohl(spi));
							}
						}
						delete_or_replace_state(dst);
						/* note: md->st != dst */
					}
				} /* for each spi */

				if (!del_ike && responding) {
					/* build output Delete Payload */
					struct ikev2_delete v2del_tmp;

					zero(&v2del_tmp);	/* OK: no pointer fields */

					passert(pli < ndp);
					pli++;
					v2del_tmp.isad_np = (pli == ndp) ?
						ISAKMP_NEXT_v2NONE : ISAKMP_NEXT_v2D;

					v2del_tmp.isad_protoid =
						v2del->isad_protoid;
					v2del_tmp.isad_spisize =
						v2del->isad_spisize;
					v2del_tmp.isad_nrspi = j;

					/* Emit delete payload header out */
					pb_stream del_pbs;	/* output stream */

					if (!out_struct(&v2del_tmp,
							&ikev2_delete_desc,
							&e_pbs_cipher,
							&del_pbs))
						return STF_INTERNAL_ERROR;

					/* Emit values of SPI to be sent to the peer */
					if (!out_raw(spi_buf,
							j * sizeof(spi_buf[0]),
							&del_pbs,
							"local SPIs"))
						return STF_INTERNAL_ERROR;

					close_output_pbs(&del_pbs);
				}
			}
			break;

			default:
				/* ignore unrecognized protocol */
				break;
			}
		}  /* for each Delete Payload */
	}

	if (responding) {
		/*
		 * We've now build up the content (if any) of the Response:
		 *
		 * - empty, if there were no Delete Payloads.  Treat as a check
		 *   for liveness.  Correct response is this empty Response.
		 *
		 * - if an ISAKMP SA is mentioned in input message,
		 *   we are sending an empty Response, as per standard.
		 *
		 * - for IPsec SA mentioned, we are sending its mate.
		 *
		 * Close up the packet and send it.
		 */

		if (!ikev2_padup_pre_encrypt(st, &e_pbs_cipher))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&e_pbs_cipher);

		{
			unsigned char *authloc = ikev2_authloc(st, &e_pbs);

			passert(authloc != NULL);

			close_output_pbs(&e_pbs);
			close_output_pbs(&md->rbody);
			close_output_pbs(&reply_stream);

			stf_status ret =
				ikev2_encrypt_msg(st, authstart,
						iv, encstart, authloc,
						&e_pbs_cipher);
			if (ret != STF_OK)
				return ret;
		}

		record_and_send_ike_msg(st, &reply_stream,
			"reply packet for process_encrypted_informational_ikev2");
		st->st_msgid_lastreplied = md->msgid_received;

		/* Now we can delete the IKE SA if we want to */
		if (del_ike) {
			delete_my_family(st, TRUE);
			md->st = st = NULL;
		}
	}

	/* count as DPD/liveness only if there was no Delete (or MOBIKE Notify) */
	if (!del_ike && ndp == 0) {
		if (responding)
			pstats_ike_dpd_replied++;
		else
			pstats_ike_dpd_recv++;
	}

	ikev2_update_msgid_counters(md);
	return STF_OK;
}

stf_status ikev2_send_informational(struct state *st)
{
	struct state *pst = st;

	if (IS_CHILD_SA(st)) {
		pst = state_with_serialno(st->st_clonedfrom);
		if (pst == NULL) {
			DBG(DBG_CONTROL,
			    DBG_log("IKE SA does not exist for this child SA - should not happen"));
			DBG(DBG_CONTROL,
			    DBG_log("INFORMATIONAL exchange cannot be sent"));
			return STF_IGNORE;
		}
	}

	{
		/* buffer in which to marshal our informational message.
		 * We don't use reply_buffer/reply_stream because they might be in use.
		 */
		u_char buffer[1024];	/* ??? large enough for any informational? */
		unsigned char *authstart;
		unsigned char *encstart;
		unsigned char *iv;

		struct ikev2_generic e;
		pb_stream e_pbs, e_pbs_cipher;
		pb_stream rbody;
		pb_stream reply_stream;

		init_out_pbs(&reply_stream, buffer, sizeof(buffer),
			 "informational exchange request packet");
		authstart = reply_stream.cur;

		/* HDR out */
		{
			struct isakmp_hdr hdr;

			zero(&hdr);	/* OK: no pointer fields */
			hdr.isa_version = build_ikev2_version();
			memcpy(hdr.isa_rcookie, pst->st_rcookie, COOKIE_SIZE);
			memcpy(hdr.isa_icookie, pst->st_icookie, COOKIE_SIZE);
			hdr.isa_xchg = ISAKMP_v2_INFORMATIONAL;
			hdr.isa_np = ISAKMP_NEXT_v2SK;
			hdr.isa_msgid = htonl(pst->st_msgid_nextuse);

			/* encryption role based on original state not md state */
			if (pst->st_original_role == ORIGINAL_INITIATOR)
				hdr.isa_flags = ISAKMP_FLAGS_v2_IKE_I;

			/* not setting message responder flag */

			if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG))
				hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;

			if (!out_struct(&hdr, &isakmp_hdr_desc,
					&reply_stream, &rbody))
				return STF_FATAL;
		}

		/* insert an Encryption payload header */
		e.isag_np = ISAKMP_NEXT_v2NONE;
		e.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;
		if (!out_struct(&e, &ikev2_sk_desc, &rbody, &e_pbs))
			return STF_FATAL;

		/* IV */
		iv = e_pbs.cur;
		if (!emit_wire_iv(st, &e_pbs))
			return STF_INTERNAL_ERROR;

		/* note where cleartext starts */
		init_pbs(&e_pbs_cipher, e_pbs.cur, e_pbs.roof - e_pbs.cur,
			 "cleartext");
		e_pbs_cipher.container = &e_pbs;
		e_pbs_cipher.desc = NULL;
		e_pbs_cipher.cur = e_pbs.cur;
		encstart = e_pbs_cipher.cur;

		/* This is an empty informational exchange (A.K.A liveness check) */

		if (!ikev2_padup_pre_encrypt(st, &e_pbs_cipher))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&e_pbs_cipher);

		{
			stf_status ret;
			unsigned char *authloc = ikev2_authloc(pst, &e_pbs);

			passert(authloc != NULL);

			close_output_pbs(&e_pbs);
			close_output_pbs(&rbody);
			close_output_pbs(&reply_stream);

			ret = ikev2_encrypt_msg(st, authstart,
						iv, encstart, authloc,
						&e_pbs_cipher);
			if (ret != STF_OK)
				return STF_FATAL;
		}
		/* cannot use ikev2_update_msgid_counters - no md here */
		/* But we know we are the initiator for thie exchange */
		pst->st_msgid_nextuse += 1;

		pst->st_pend_liveness = TRUE; /* we should only do this when dpd/liveness is active? */
		record_and_send_ike_msg(st, &reply_stream,
			"packet for ikev2_send_informational");
	}

	pstats_ike_dpd_sent++;

	return STF_OK;
}

/*
 * ikev2_delete_out: initiate an Informational Exchange announcing a deletion.
 *
 * CURRENTLY SUPPRESSED:
 * If we fail to send the deletion, we just go ahead with deleting the state.
 * The code in delete_state would break if we actually did this.
 *
 * Deleting an IKE SA is a bigger deal than deleting an IPsec SA.
 */

static bool ikev2_delete_out_guts(struct state *const st, struct state *const pst)
{
	unsigned char *authstart;
	pb_stream e_pbs, e_pbs_cipher;
	pb_stream rbody;
	struct ikev2_generic e;
	unsigned char *iv;
	unsigned char *encstart;

	/* make sure HDR is at start of a clean buffer */
	init_out_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		 "information exchange request packet");
	/* beginning of data going out */
	authstart = reply_stream.cur;

	/* HDR out */
	{
		struct isakmp_hdr hdr;

		zero(&hdr);	/* OK: no pointer fields */
		hdr.isa_version = build_ikev2_version();
		memcpy(hdr.isa_rcookie, pst->st_rcookie, COOKIE_SIZE);
		memcpy(hdr.isa_icookie, pst->st_icookie, COOKIE_SIZE);
		hdr.isa_xchg = ISAKMP_v2_INFORMATIONAL;
		hdr.isa_np = ISAKMP_NEXT_v2SK;
		hdr.isa_msgid = htonl(pst->st_msgid_nextuse);

		/* set Initiator flag if we are the IKE Original Initiator */
		if (pst->st_original_role == ORIGINAL_INITIATOR) {
			hdr.isa_flags |= ISAKMP_FLAGS_v2_IKE_I;
		}

		/* we are sending a request, so ISAKMP_FLAGS_v2_MSG_R is unset */

		if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
			hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
		}

		if (!out_struct(&hdr, &isakmp_hdr_desc,
				&reply_stream, &rbody)) {
			libreswan_log(
				"error initializing hdr for informational message");
			return FALSE;
		}
	}

	/* insert an Encryption payload header */
	e.isag_np = ISAKMP_NEXT_v2D;
	e.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;

	if (!out_struct(&e, &ikev2_sk_desc, &rbody, &e_pbs))
		return FALSE;

	/* insert IV */
	iv = e_pbs.cur;
	if (!emit_wire_iv(st, &e_pbs))
		return FALSE;

	/* note where cleartext starts */
	init_pbs(&e_pbs_cipher, e_pbs.cur, e_pbs.roof - e_pbs.cur,
		 "cleartext");
	e_pbs_cipher.container = &e_pbs;
	e_pbs_cipher.desc = NULL;
	e_pbs_cipher.cur = e_pbs.cur;
	encstart = e_pbs_cipher.cur;

	{
		pb_stream del_pbs;
		struct ikev2_delete v2del_tmp;
		/*
		 * u_int16_t i, j=0;
		 * u_char *spi;
		 * char spi_buf[1024];
		 */

		zero(&v2del_tmp);	/* OK: no pointer fields */
		v2del_tmp.isad_np = ISAKMP_NEXT_v2NONE;

		if (IS_CHILD_SA(st)) {
			v2del_tmp.isad_protoid = PROTO_IPSEC_ESP;
			v2del_tmp.isad_spisize = sizeof(ipsec_spi_t);
			v2del_tmp.isad_nrspi = 1;
		} else {
			v2del_tmp.isad_protoid = PROTO_ISAKMP;
			v2del_tmp.isad_spisize = 0;
			v2del_tmp.isad_nrspi = 0;
		}

		/* Emit delete payload header out */
		if (!out_struct(&v2del_tmp, &ikev2_delete_desc,
				&e_pbs_cipher, &del_pbs))
			return FALSE;

		/* Emit values of spi to be sent to the peer */
		if (IS_CHILD_SA(st)) {
			if (!out_raw((u_char *)&st->st_esp.our_spi,
				     sizeof(ipsec_spi_t), &del_pbs,
				     "local spis"))
				return FALSE;
		}

		close_output_pbs(&del_pbs);
	}

	if (!ikev2_padup_pre_encrypt(st, &e_pbs_cipher)) {
		libreswan_log("error padding before encryption in delete payload");
		return FALSE;
	}

	close_output_pbs(&e_pbs_cipher);

	{
		stf_status ret;
		unsigned char *authloc = ikev2_authloc(st, &e_pbs);

		passert(authloc != NULL);

		close_output_pbs(&e_pbs);
		close_output_pbs(&rbody);
		close_output_pbs(&reply_stream);

		ret = ikev2_encrypt_msg(st, authstart,
					iv, encstart, authloc,
					&e_pbs_cipher);
		if (ret != STF_OK)
			return FALSE;
	}

	record_and_send_ike_msg(st, &reply_stream,
		     "packet for ikev2_delete_out_guts");

	/* increase message ID for next delete message */
	/* ikev2_update_msgid_counters need an md */

	pst->st_msgid_nextuse++;
        st->st_msgid =  htonl(pst->st_msgid_nextuse);

	return TRUE;
}

bool ikev2_delete_out(struct state *st)
{
	bool res;

	if (IS_CHILD_SA(st)) {
		/* child SA */
		struct state *pst = state_with_serialno(st->st_clonedfrom);

		pexpect(pst != NULL);
		if (pst == NULL) {
			/* ??? surely this can only happen if there is a bug in our code */
			DBG(DBG_CONTROL,
			    DBG_log("IKE SA does not exist for the child SA that we are deleting"));
			DBG(DBG_CONTROL,
			    DBG_log("INFORMATIONAL exchange cannot be sent, deleting state"));
			res = FALSE;
		} else {
			res = ikev2_delete_out_guts(st, pst);
		}
	} else {
		/* Parent SA */
		res = ikev2_delete_out_guts(st, st);
	}

	return res;
}

/*
 * Determine the IKE version we will use for the IKE packet
 * Normally, this is "2.0", but in the future we might need to
 * change that. Version used is the minimum 2.x version both
 * sides support. So if we support 2.1, and they support 2.0,
 * we should sent 2.0 (not implemented until we hit 2.1 ourselves)
 * We also have some impair functions that modify the major/minor
 * version on purpose - for testing
 *
 * rcv_version: the received IKE version, 0 if we don't know
 *
 * top 4 bits are major version, lower 4 bits are minor version
 */
static int build_ikev2_version(void)
{
	/* TODO: if bumping, we should also set the Version flag in the ISAKMP header */
	return ((IKEv2_MAJOR_VERSION + (DBGP(IMPAIR_MAJOR_VERSION_BUMP) ? 1 : 0))
			<< ISA_MAJ_SHIFT) |
	       (IKEv2_MINOR_VERSION + (DBGP(IMPAIR_MINOR_VERSION_BUMP) ? 1 : 0));
}

void ikev2_add_ipsec_child(int whack_sock, struct state *isakmp_sa,
                       struct connection *c, lset_t policy,
                       unsigned long try, so_serial_t replacing
#ifdef HAVE_LABELED_IPSEC
                       , struct xfrm_user_sec_ctx_ike *uctx
#endif
                       )
{
	struct state *st;
	char replacestr[32];
	const char *pfsgroupname = "no-pfs";

	if (find_pending_phas2(isakmp_sa->st_serialno,
				c, IPSECSA_PENDING_STATES)) {
		return;
	}

	passert(c != NULL);

	st = duplicate_state(isakmp_sa, IPSEC_SA);
	st->st_whack_sock = whack_sock;
	st->st_connection = c;	/* safe: from duplicate_state */
	passert(c != NULL);

	set_cur_state(st); /* we must reset before exit */
	st->st_policy = policy;
	st->st_try = try;

	freeanychunk(st->st_ni); /* this is from the parent. */
	freeanychunk(st->st_nr); /* this is from the parent. */

#ifdef HAVE_LABELED_IPSEC
	st->sec_ctx = NULL;
	if (uctx != NULL) {
		st->sec_ctx = clone_thing(*uctx, "sec ctx structure");
		DBG(DBG_CONTROL,
		    DBG_log("pending phase 2 with security context \"%s\"",
			    st->sec_ctx->sec_ctx_value));
	}
#endif
	st->st_state = STATE_UNDEFINED; /* change_state ignores from == to */
	change_state(st, STATE_V2_CREATE_I0);

	insert_state(st); /* needs cookies, connection, and msgid */

	replacestr[0] = '\0';
	if (replacing != SOS_NOBODY)
		snprintf(replacestr, sizeof(replacestr), " to replace #%lu",
				replacing);

	passert(st->st_connection != NULL);

	st->st_pfs_group = NULL;
	if ((policy & POLICY_PFS) != LEMPTY) {
		ikev2_child_set_pfs(st);
		pfsgroupname = st->st_pfs_group->common.name;
	}

	DBG(DBG_CONTROLMORE, DBG_log("#%lu schedule event to initiate IPsec SA "
				"%s%s using IKE#%lu pfs=%s",
				st->st_serialno,
				prettypolicy(policy),
				replacestr,
				isakmp_sa->st_serialno,
				pfsgroupname));
	delete_event(st);
	event_schedule(EVENT_v2_INITIATE_CHILD, 0, st);
	reset_globals();
	return;
}

void ikev2_child_outI(struct state *st)
{
	ikev2_crypto_start(NULL, st);
	return;
}

/*
 * if this connection has a newer Child SA than this state
 * this negotitation is not relevent any more.
 * would this cover if there are multiple CREATE_CHILD_SA pending on
 * this IKE negotiation ???
 */
bool need_this_intiator(struct state *st)
{
	struct connection *c = st->st_connection;

	if (st->st_state !=  STATE_PARENT_I1)
		return FALSE; /* ignore STATE_V2_CREATE_I ??? */

	if (c->newest_ipsec_sa > st->st_serialno) {
		libreswan_log( "suppressing retransmit because superseded by "
				"#%lu try=%lu. Drop this negotitation",
				c->newest_ipsec_sa, st->st_try);
		return TRUE;
	}
	return FALSE;
}
