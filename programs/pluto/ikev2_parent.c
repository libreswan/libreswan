/*
 * IKEv2 parent SA creation routines
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi
 * Copyright (C) 2012 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Antony Antony <antony@phenome.org>
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

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <gmp.h>

#include <libreswan.h>
#include <libreswan/ipsec_policy.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "state.h"
#include "id.h"
#include "connections.h"

#include "crypto.h" /* requires sha1.h and md5.h */
#include "x509.h"
#include "x509more.h"
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
#include "ike_continuations.h"
#include "cookie.h"
#include "rnd.h"
#include "pending.h"
#include "kernel.h"

#define SEND_NOTIFICATION_AA(t, d) \
	if (st) \
		send_v2_notification_from_state(st, st->st_state, t, d); \
	else \
		send_v2_notification_from_md(md, t, d);

#define SEND_NOTIFICATION(t) \
	if (st) \
		send_v2_notification_from_state(st, st->st_state, t, NULL); \
	else \
		send_v2_notification_from_md(md, t, NULL);

static void ikev2_parent_outI1_continue(struct pluto_crypto_req_cont *pcrc,
					struct pluto_crypto_req *r,
					err_t ugh);

static stf_status ikev2_parent_outI1_tail(struct pluto_crypto_req_cont *pcrc,
					  struct pluto_crypto_req *r);

static bool ikev2_get_dcookie(u_char *dcookie, chunk_t st_ni,
			      ip_address *addr, u_int8_t *spiI);

static stf_status ikev2_parent_outI1_common(struct msg_digest *md,
					    struct state *st);

static int build_ike_version();

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
			     , struct xfrm_user_sec_ctx_ike * uctx
#endif
			     )
{
	struct state *st = new_state();
	struct db_sa *sadb;
	int groupnum;
	int policy_index = POLICY_ISAKMP(policy,
					 c->spd.this.xauth_server,
					 c->spd.this.xauth_client);

	/* set up new state */
	get_cookie(TRUE, st->st_icookie, COOKIE_SIZE, &c->spd.that.host_addr);
	initialize_new_state(st, c, policy, try, whack_sock, importance);
	st->st_ikev2 = TRUE;
	change_state(st, STATE_PARENT_I1);
	st->st_msgid_lastack = INVALID_MSGID;
	st->st_msgid_nextuse = 0;
	st->st_try   = try;

	if (HAS_IPSEC_POLICY(policy)) {
#ifdef HAVE_LABELED_IPSEC
		st->sec_ctx = NULL;
		if ( uctx != NULL)
			libreswan_log(
				"Labeled ipsec is not supported with ikev2 yet");


#endif

		add_pending(dup_any(
				    whack_sock), st, c, policy, 1,
			    predecessor == NULL ? SOS_NOBODY : predecessor->st_serialno
#ifdef HAVE_LABELED_IPSEC
			    , st->sec_ctx
#endif
			    );
	}

	if (predecessor == NULL)
		libreswan_log("initiating v2 parent SA");
	else
		libreswan_log("initiating v2 parent SA to replace #%lu",
			      predecessor->st_serialno);

	if (predecessor != NULL) {
		update_pending(predecessor, st);
		whack_log(RC_NEW_STATE + STATE_PARENT_I1,
			  "%s: initiate, replacing #%lu",
			  enum_name(&state_names, st->st_state),
			  predecessor->st_serialno);
	} else {
		whack_log(RC_NEW_STATE + STATE_PARENT_I1,
			  "%s: initiate",
			  enum_name(&state_names, st->st_state));
	}

	/*
	 * now, we need to initialize st->st_oakley, specifically, the group
	 * number needs to be initialized.
	 */
	groupnum = 0;

	st->st_sadb = &oakley_sadb[policy_index];
	sadb = oakley_alg_makedb(st->st_connection->alg_info_ike,
				 st->st_sadb, 0);
	if (sadb != NULL)
		st->st_sadb = sadb;
	sadb = st->st_sadb = sa_v2_convert(st->st_sadb);
	{
		unsigned int pc_cnt;

		/* look at all the proposals */
		if (st->st_sadb->prop_disj != NULL) {
			for (pc_cnt = 0;
			     pc_cnt < st->st_sadb->prop_disj_cnt && groupnum ==
			     0;
			     pc_cnt++) {
				struct db_v2_prop *vp =
					&st->st_sadb->prop_disj[pc_cnt];
				unsigned int pr_cnt;

				/* look at all the proposals */
				if (vp->props != NULL) {
					for (pr_cnt = 0;
					     pr_cnt < vp->prop_cnt &&
					     groupnum == 0;
					     pr_cnt++) {
						unsigned int ts_cnt;
						struct db_v2_prop_conj *vpc =
							&vp->props[pr_cnt];

						for (ts_cnt = 0;
						     ts_cnt < vpc->trans_cnt &&
						     groupnum == 0; ts_cnt++) {
							struct db_v2_trans *tr
								=
									&vpc->
									trans[
										ts_cnt
									];
							if (tr != NULL &&
							    tr->transform_type
							    ==
							    IKEv2_TRANS_TYPE_DH)
							{
								groupnum =
									tr->
									transid;
							}
						}
					}
				}
			}
		}
	}
	if (groupnum == 0)
		groupnum = OAKLEY_GROUP_MODP2048;
	st->st_oakley.group = lookup_group(groupnum);
	st->st_oakley.groupnum = groupnum;

	/* now. we need to go calculate the nonce, and the KE */
	{
		struct ke_continuation *ke = alloc_thing(
			struct ke_continuation,
			"ikev2_outI1 KE");
		stf_status e;

		ke->md = alloc_md();
		ke->md->from_state = STATE_IKEv2_BASE;
		ke->md->svm = ikev2_parent_firststate();
		ke->md->st = st;
		set_suspended(st, ke->md);

		if (!st->st_sec_in_use) {
			pcrc_init(&ke->ke_pcrc);
			ke->ke_pcrc.pcrc_func = ikev2_parent_outI1_continue;
			e = build_ke(&ke->ke_pcrc, st, st->st_oakley.group,
				     importance);
			if ( (e != STF_SUSPEND &&
			      e != STF_INLINE) || (e == STF_TOOMUCHCRYPTO)) {
				loglog(RC_CRYPTOFAILED,
				       "system too busy - Enabling dcookies [TODO]");
				delete_state(st);
			}
		} else {
			e =
				ikev2_parent_outI1_tail(
					(struct pluto_crypto_req_cont *)ke,
					NULL);
		}

		reset_globals();

		return e;
	}
}

static void ikev2_parent_outI1_continue(struct pluto_crypto_req_cont *pcrc,
					struct pluto_crypto_req *r,
					err_t ugh)
{
	struct ke_continuation *ke = (struct ke_continuation *)pcrc;
	struct msg_digest *md = ke->md;
	struct state *const st = md->st;
	stf_status e;

	DBG(DBG_CONTROLMORE,
	    DBG_log("ikev2 parent outI1: calculated ke+nonce, sending I1"));

	if (st == NULL) {
		loglog(RC_LOG_SERIOUS,
		       "%s: Request was disconnected from state",
		       __FUNCTION__);
		if (ke->md)
			release_md(ke->md);
		return;
	}

	/* XXX should check out ugh */
	passert(ugh == NULL);
	passert(cur_state == NULL);
	passert(st != NULL);

	passert(st->st_suspended_md == ke->md);
	set_suspended(st, NULL); /* no longer connected or suspended */

	set_cur_state(st);

	st->st_calculating = FALSE;

	e = ikev2_parent_outI1_tail(pcrc, r);

	if (ke->md != NULL) {
		complete_v2_state_transition(&ke->md, e);
		if (ke->md)
			release_md(ke->md);
	}
	reset_cur_state();
	reset_globals();
}

/*
 * unpack the calculate KE value, store it in state.
 * used by IKEv2: parent, child (PFS)
 */
static int unpack_v2KE(struct state *st,
		       struct pluto_crypto_req *r,
		       chunk_t *g)
{
	struct pcr_kenonce *kn = &r->pcr_d.kn;

	unpack_KE(st, r, g);
	return kn->oakley_group;
}

/*
 * package up the calculate KE value, and emit it as a KE payload.
 * used by IKEv2: parent, child (PFS)
 */
static bool justship_v2KE(struct state *st UNUSED,
			  chunk_t *g, unsigned int oakley_group,
			  pb_stream *outs, u_int8_t np)
{
	struct ikev2_ke v2ke;
	pb_stream kepbs;

	memset(&v2ke, 0, sizeof(v2ke));
	v2ke.isak_np      = np;
	v2ke.isak_group   = oakley_group;
	if (!out_struct(&v2ke, &ikev2_ke_desc, outs, &kepbs))
		return FALSE;

	if (!out_chunk(*g, &kepbs, "ikev2 g^x"))
		return FALSE;

	close_output_pbs(&kepbs);
	return TRUE;
}

static bool ship_v2KE(struct state *st,
		      struct pluto_crypto_req *r,
		      chunk_t *g,
		      pb_stream *outs, u_int8_t np)
{
	int oakley_group = unpack_v2KE(st, r, g);

	return justship_v2KE(st, g, oakley_group, outs, np);
}

static stf_status ikev2_parent_outI1_tail(struct pluto_crypto_req_cont *pcrc,
					  struct pluto_crypto_req *r)
{
	struct ke_continuation *ke = (struct ke_continuation *)pcrc;
	struct msg_digest *md = ke->md;
	struct state *const st = md->st;

	unpack_v2KE(st, r, &st->st_gi);
	unpack_nonce(&st->st_ni, r);
	return ikev2_parent_outI1_common(md, st);
}

static stf_status ikev2_parent_outI1_common(struct msg_digest *md,
					    struct state *st)
{
	struct connection *c = st->st_connection;
	int numvidtosend = 0;

	/* set up reply */
	init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		 "reply packet");

	/* HDR out */
	{
		struct isakmp_hdr hdr;

		zero(&hdr);                             /* default to 0 */
		/* Impair function will raise major/minor by 1 for testing */
		hdr.isa_version = build_ike_version();
		if (st->st_dcookie.ptr)
			hdr.isa_np   = ISAKMP_NEXT_v2N;
		else
			hdr.isa_np   = ISAKMP_NEXT_v2SA;
		hdr.isa_xchg = ISAKMP_v2_SA_INIT;
		hdr.isa_flags = ISAKMP_FLAGS_I;
		memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
		/* R-cookie, are left zero */

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_stream,
				&md->rbody)) {
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}
	/* send an anti DOS cookie, 4306 2.6, if we have received one from the
	 * responder
	 */

	if (st->st_dcookie.ptr) {
		chunk_t child_spi;
		memset(&child_spi, 0, sizeof(child_spi));
		ship_v2N(ISAKMP_NEXT_v2SA, DBGP(
				 IMPAIR_SEND_BOGUS_ISAKMP_FLAG) ?
			 (ISAKMP_PAYLOAD_NONCRITICAL |
			  ISAKMP_PAYLOAD_LIBRESWAN_BOGUS) :
			 ISAKMP_PAYLOAD_NONCRITICAL, PROTO_ISAKMP,
			 &child_spi,
			 v2N_COOKIE, &st->st_dcookie, &md->rbody);
	}
	/* SA out */
	{
		u_char *sa_start = md->rbody.cur;

		if (st->st_sadb->prop_disj_cnt == 0 || st->st_sadb->prop_disj)
			st->st_sadb = sa_v2_convert(st->st_sadb);

		if (!ikev2_out_sa(&md->rbody,
				  PROTO_ISAKMP,
				  st->st_sadb,
				  st, TRUE, /* parentSA */
				  ISAKMP_NEXT_v2KE)) {
			libreswan_log("outsa fail");
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
		/* save initiator SA for later HASH */
		if (st->st_p1isa.ptr == NULL) { /* no leak!  (MUST be first time) */
			clonetochunk(st->st_p1isa, sa_start,
				     md->rbody.cur - sa_start,
				     "sa in main_outI1");
		}
	}

	/* send KE */
	if (!justship_v2KE(st, &st->st_gi, st->st_oakley.groupnum,  &md->rbody,
			   ISAKMP_NEXT_v2Ni))
		return STF_INTERNAL_ERROR;

	/*
	 * Check which Vendor ID's we need to send - there will be more soon
	 * In IKEv2, DPD and NAT-T are no longer vendorid's
	 */
	if (c->send_vendorid) {
		numvidtosend++;  /* if we need to send Libreswan VID */
	}

	/* send NONCE */
	{
		int np = numvidtosend > 0 ? ISAKMP_NEXT_v2V : ISAKMP_NEXT_v2NONE;
		struct ikev2_generic in;
		pb_stream pb;

		memset(&in, 0, sizeof(in));
		in.isag_np = np;
		in.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;
		if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
			libreswan_log(
				" setting bogus ISAKMP_PAYLOAD_LIBRESWAN_BOGUS flag in ISAKMP payload");
			in.isag_critical |= ISAKMP_PAYLOAD_LIBRESWAN_BOGUS;
		}

		if (!out_struct(&in, &ikev2_nonce_desc, &md->rbody, &pb) ||
		    !out_raw(st->st_ni.ptr, st->st_ni.len, &pb, "IKEv2 nonce"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&pb);
	}

	/* Send Vendor VID if needed */
	if (c->send_vendorid) {
		const char *myvid = ipsec_version_vendorid();
		int np = --numvidtosend >
			 0 ? ISAKMP_NEXT_v2V : ISAKMP_NEXT_v2NONE;

		if (!out_generic_raw(np, &isakmp_vendor_id_desc, &md->rbody,
				     myvid, strlen(myvid),
				     "Vendor ID"))
			return STF_INTERNAL_ERROR;

		/* ensure our VID chain was valid */
		passert(numvidtosend == 0);
	}

	close_message(&md->rbody, st);
	close_output_pbs(&reply_stream);

	freeanychunk(st->st_tpacket);
	clonetochunk(st->st_tpacket, reply_stream.start,
		     pbs_offset(&reply_stream),
		     "reply packet for ikev2_parent_outI1_tail");

	/* save packet for later signing */
	freeanychunk(st->st_firstpacket_me);
	clonetochunk(st->st_firstpacket_me, reply_stream.start,
		     pbs_offset(&reply_stream), "saved first packet");

	/* Transmit */
	send_ike_msg(st, __FUNCTION__);

	delete_event(st);
	event_schedule(EVENT_v2_RETRANSMIT, EVENT_RETRANSMIT_DELAY_0, st);

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
static void ikev2_parent_inI1outR1_continue(struct pluto_crypto_req_cont *pcrc,
					    struct pluto_crypto_req *r,
					    err_t ugh);

static stf_status ikev2_parent_inI1outR1_tail(
	struct pluto_crypto_req_cont *pcrc,
	struct pluto_crypto_req *r);

stf_status ikev2parent_inI1outR1(struct msg_digest *md)
{
	struct state *st = md->st;
	lset_t policy = POLICY_IKEV2_ALLOW;
	struct connection *c = find_host_connection(&md->iface->ip_addr,
						    md->iface->port,
						    &md->sender,
						    md->sender_port,
						    POLICY_IKEV2_ALLOW);

	/* retrieve st->st_gi */

#if 0
	if (c == NULL) {
		/*
		 * make up a policy from the thing that was proposed, and see
		 * if we can find a connection with that policy.
		 */

		pb_stream pre_sa_pbs = sa_pd->pbs;
		policy = preparse_isakmp_sa_body(&pre_sa_pbs);
		c = find_host_connection(&md->iface->ip_addr, pluto_port,
					 (ip_address*)NULL, md->sender_port,
					 policy);

	}
#endif

	if (c == NULL) {

		/* See if a wildcarded connection can be found.
		 * We cannot pick the right connection, so we're making a guess.
		 * All Road Warrior connections are fair game:
		 * we pick the first we come across (if any).
		 * If we don't find any, we pick the first opportunistic
		 * with the smallest subnet that includes the peer.
		 * There is, of course, no necessary relationship between
		 * an Initiator's address and that of its client,
		 * but Food Groups kind of assumes one.
		 */
		{
			struct connection *d;
			d = find_host_connection(&md->iface->ip_addr,
						 pluto_port,
						 (ip_address*)NULL,
						 md->sender_port, policy);

			for (; d != NULL; d = d->hp_next) {
				if (d->kind == CK_GROUP) {
					/* ignore */
				} else {
					if (d->kind == CK_TEMPLATE &&
					    !(d->policy & POLICY_OPPO)) {
						/* must be Road Warrior: we have a winner */
						c = d;
						break;
					}

					/* Opportunistic or Shunt: pick tightest match */
					if (addrinsubnet(&md->sender,
							 &d->spd.that.client)
					    &&
					    (c == NULL ||
					     !subnetinsubnet(&c->spd.that.
							     client,
							     &d->spd.that.
							     client)))
						c = d;
				}
			}
		}
		if (c == NULL) {
			loglog(RC_LOG_SERIOUS, "initial parent SA message received on %s:%u"
			       " but no connection has been authorized%s%s",
			       ip_str(
				       &md->iface->ip_addr),
			       ntohs(portof(&md->iface->ip_addr)),
			       (policy != LEMPTY) ? " with policy=" : "",
			       (policy !=
				LEMPTY) ? bitnamesof(sa_policy_bit_names,
						     policy) : "");
			return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
		}
		if (c->kind != CK_TEMPLATE) {
			loglog(RC_LOG_SERIOUS, "initial parent SA message received on %s:%u"
			       " but \"%s\" forbids connection",
			       ip_str(
				       &md->iface->ip_addr), pluto_port,
			       c->name);
			return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
		}
		c = rw_instantiate(c, &md->sender, NULL, NULL);

	} else {
		/* we found a non-wildcard conn. double check if it needs instantiation anyway (eg vnet=) */
		/* vnet=/vhost= should have set CK_TEMPLATE on connection loading */
		if ((c->kind == CK_TEMPLATE) && c->spd.that.virt) {
			DBG(DBG_CONTROL,
			    DBG_log(
				    "local endpoint has virt (vnet/vhost) set without wildcards - needs instantiation"));
			c = rw_instantiate(c, &md->sender, NULL, NULL);
		} else if ((c->kind == CK_TEMPLATE) &&
			   (c->policy & POLICY_IKEV2_ALLOW_NARROWING)) {
			DBG(DBG_CONTROL,
			    DBG_log(
				    "local endpoint has narrowing=yes - needs instantiation"));
			c = rw_instantiate(c, &md->sender, NULL, NULL);
		}
	}

	DBG_log("found connection: %s\n", c ? c->name : "<none>");

	if (!st) {
		st = new_state();
		/* set up new state */
		memcpy(st->st_icookie, md->hdr.isa_icookie, COOKIE_SIZE);
		/* initialize_new_state expects valid icookie/rcookie values, so create it now */
		get_cookie(FALSE, st->st_rcookie, COOKIE_SIZE, &md->sender);
		initialize_new_state(st, c, policy, 0, NULL_FD,
				     pcim_stranger_crypto);
		st->st_ikev2 = TRUE;
		change_state(st, STATE_PARENT_R1);
		st->st_msgid_lastack = INVALID_MSGID;
		st->st_msgid_nextuse = 0;

		md->st = st;
		md->from_state = STATE_IKEv2_BASE;
	}

	/* check,as a responder, are we under dos attack or not
	 * if yes go to 6 message exchange mode. it is a config option for now.
	 * TBD set force_busy dynamically
	 * Paul: Can we check for STF_TOOMUCHCRYPTO ?
	 */
	if (force_busy == TRUE) {
		u_char dcookie[SHA1_DIGEST_SIZE];
		chunk_t dc;
		ikev2_get_dcookie( dcookie, st->st_ni, &md->sender,
				   st->st_icookie);
		dc.ptr = dcookie;
		dc.len = SHA1_DIGEST_SIZE;

		/* check if I1 packet contian KE and a v2N payload with type COOKIE */
		if ( md->chain[ISAKMP_NEXT_v2KE] &&
		     md->chain[ISAKMP_NEXT_v2N] &&
		     (md->chain[ISAKMP_NEXT_v2N]->payload.v2n.isan_type ==
		      v2N_COOKIE)) {
			u_int8_t spisize;
			const pb_stream *dc_pbs;
			chunk_t blob;
			DBG(DBG_CONTROLMORE,
			    DBG_log("received a DOS cookie in I1 verify it"));
			/* we received dcookie we send earlier verify it */
			spisize =
				md->chain[ISAKMP_NEXT_v2N]->payload.v2n.
				isan_spisize;
			dc_pbs = &md->chain[ISAKMP_NEXT_v2N]->pbs;
			blob.ptr = dc_pbs->cur + spisize;
			blob.len = pbs_left(dc_pbs) - spisize;
			DBG(DBG_CONTROLMORE,
			    DBG_dump_chunk("dcookie received in I1 Packet",
					   blob);
			    DBG_dump("dcookie computed", dcookie,
				     SHA1_DIGEST_SIZE));

			if (memcmp(blob.ptr, dcookie, SHA1_DIGEST_SIZE) != 0) {
				libreswan_log(
					"mismatch in DOS v2N_COOKIE,send a new one");
				SEND_NOTIFICATION_AA(v2N_COOKIE, &dc);
				return STF_FAIL + v2N_INVALID_IKE_SPI;
			}
			DBG(DBG_CONTROLMORE,
			    DBG_log("dcookie received match with computed one"));
		} else {
			/* we are under DOS attack I1 contains no DOS COOKIE */
			DBG(DBG_CONTROLMORE,
			    DBG_log(
				    "busy mode on. receieved I1 without a valid dcookie");
			    DBG_log("send a dcookie and forget this state"));
			SEND_NOTIFICATION_AA(v2N_COOKIE, &dc);
			return STF_FAIL;
		}
	} else {
		DBG(DBG_CONTROLMORE,
		    DBG_log("will not send/process a dcookie"));

	}

	/*
	 * We have to agree to the DH group before we actually know who
	 * we are talking to.   If we support the group, we use it.
	 *
	 * It is really too hard here to go through all the possible policies
	 * that might permit this group.  If we think we are being DOS'ed
	 * then we should demand a cookie.
	 */
	{
		struct ikev2_ke *ke;
		char fromname[ADDRTOT_BUF];
		addrtot(&md->sender, 0, fromname, ADDRTOT_BUF);

		if (!md->chain[ISAKMP_NEXT_v2KE]) {
			/* is this a notify? If so, log it */
			if(md->chain[ISAKMP_NEXT_v2N]) {
				libreswan_log("Received Notify(%d): %s",
					md->chain[ISAKMP_NEXT_v2N]->payload.v2n.isan_type,
					enum_name(&ikev2_notify_names,
						md->chain[ISAKMP_NEXT_v2N]->payload.v2n.isan_type));
			}
			libreswan_log(
				"rejecting I1 from %s:%u, no KE payload present",
				fromname, md->sender_port);
			return STF_FAIL + v2N_INVALID_KE_PAYLOAD;
		}
		ke = &md->chain[ISAKMP_NEXT_v2KE]->payload.v2ke;

		st->st_oakley.group = lookup_group(ke->isak_group);
		if (st->st_oakley.group == NULL) {
			libreswan_log(
				"rejecting I1 from %s:%u, invalid DH group=%u",
				fromname, md->sender_port,
				ke->isak_group);
			return STF_FAIL + v2N_INVALID_KE_PAYLOAD;
		}
	}

	/* now. we need to go calculate the nonce, and the KE */
	{
		struct ke_continuation *ke = alloc_thing(
			struct ke_continuation,
			"ikev2_inI1outR1 KE");
		stf_status e;

		ke->md = md;
		set_suspended(st, ke->md);

		if (!st->st_sec_in_use) {
			pcrc_init(&ke->ke_pcrc);
			ke->ke_pcrc.pcrc_func =
				ikev2_parent_inI1outR1_continue;
			e = build_ke(&ke->ke_pcrc, st, st->st_oakley.group,
				     pcim_stranger_crypto);
			if (e != STF_SUSPEND && e != STF_INLINE) {
				loglog(RC_CRYPTOFAILED, "system too busy");
				delete_state(st);
			}
		} else {
			e =
				ikev2_parent_inI1outR1_tail((struct
							     pluto_crypto_req_cont
							     *)ke,
							    NULL);
		}

		reset_globals();

		return e;
	}
}

static void ikev2_parent_inI1outR1_continue(struct pluto_crypto_req_cont *pcrc,
					    struct pluto_crypto_req *r,
					    err_t ugh)
{
	struct ke_continuation *ke = (struct ke_continuation *)pcrc;
	struct msg_digest *md = ke->md;
	struct state *const st = md->st;
	stf_status e;

	DBG(DBG_CONTROLMORE,
	    DBG_log("ikev2 parent inI1outR1: calculated ke+nonce, sending R1"));

	if (st == NULL) {
		loglog(RC_LOG_SERIOUS,
		       "%s: Request was disconnected from state",
		       __FUNCTION__);
		if (ke->md)
			release_md(ke->md);
		return;
	}

	/* XXX should check out ugh */
	passert(ugh == NULL);
	passert(cur_state == NULL);
	passert(st != NULL);

	passert(st->st_suspended_md == ke->md);
	set_suspended(st, NULL); /* no longer connected or suspended */

	set_cur_state(st);

	st->st_calculating = FALSE;

	e = ikev2_parent_inI1outR1_tail(pcrc, r);

	if (ke->md != NULL) {
		complete_v2_state_transition(&ke->md, e);
		if (ke->md)
			release_md(ke->md);
	}
	reset_globals();
}

static stf_status ikev2_parent_inI1outR1_tail(
	struct pluto_crypto_req_cont *pcrc,
	struct pluto_crypto_req *r)
{
	struct ke_continuation *ke = (struct ke_continuation *)pcrc;
	struct msg_digest *md = ke->md;
	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_v2SA];
	struct state *const st = md->st;
	struct connection *c = st->st_connection;
	pb_stream *keyex_pbs;
	int numvidtosend = 0;

	if (c->send_vendorid) {
		numvidtosend++; /* we send Libreswan VID */
	}
	/* note that we don't update the state here yet */

	/* record first packet for later checking of signature */
	clonetochunk(st->st_firstpacket_him, md->message_pbs.start,
		     pbs_offset(
			     &md->message_pbs), "saved first received packet");

	/* make sure HDR is at start of a clean buffer */
	zero(reply_buffer);
	init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		 "reply packet");

	/* HDR out */
	{
		struct isakmp_hdr r_hdr = md->hdr;

		memcpy(r_hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
		r_hdr.isa_np = ISAKMP_NEXT_v2SA;
		/* major will be same, but their minor might be higher */
		r_hdr.isa_version = build_ike_version();
		r_hdr.isa_flags &= ~ISAKMP_FLAGS_I;
		r_hdr.isa_flags |=  ISAKMP_FLAGS_R;
		/* PAUL shouldn't we set r_hdr.isa_msgid = [htonl](st->st_msgid);  here? */
		if (!out_struct(&r_hdr, &isakmp_hdr_desc, &reply_stream,
				&md->rbody))
			return STF_INTERNAL_ERROR;
	}

	/* start of SA out */
	{
		struct isakmp_sa r_sa = sa_pd->payload.sa;
		v2_notification_t rn;
		pb_stream r_sa_pbs;

		r_sa.isasa_np = ISAKMP_NEXT_v2KE; /* XXX */
		if (!out_struct(&r_sa, &ikev2_sa_desc, &md->rbody, &r_sa_pbs))
			return STF_INTERNAL_ERROR;

		/* SA body in and out */
		rn = ikev2_parse_parent_sa_body(&sa_pd->pbs,
						&sa_pd->payload.v2sa,
						&r_sa_pbs, st, FALSE);

		if (rn != v2N_NOTHING_WRONG)
			return STF_FAIL + rn;
	}

	{
		v2_notification_t rn;
		chunk_t dc;
		keyex_pbs = &md->chain[ISAKMP_NEXT_v2KE]->pbs;
		/* KE in */
		rn =
			accept_KE(&st->st_gi, "Gi", st->st_oakley.group,
				  keyex_pbs);
		if (rn != v2N_NOTHING_WRONG) {
			u_int16_t group_number = htons(
				st->st_oakley.group->group);
			dc.ptr = (unsigned char *)&group_number;
			dc.len = 2;
			SEND_NOTIFICATION_AA(v2N_INVALID_KE_PAYLOAD, &dc);
			delete_state(st);
			return STF_FAIL + rn;
		}
	}

	/* Ni in */
	RETURN_STF_FAILURE(accept_v2_nonce(md, &st->st_ni, "Ni"));

	/* send KE */
	if (!ship_v2KE(st, r, &st->st_gr, &md->rbody, ISAKMP_NEXT_v2Nr))
		return STF_INTERNAL_ERROR;

	/* send NONCE */
	unpack_nonce(&st->st_nr, r);
	{
		int np = numvidtosend > 0 ? ISAKMP_NEXT_v2V : ISAKMP_NEXT_v2NONE;
		struct ikev2_generic in;
		pb_stream pb;

		memset(&in, 0, sizeof(in));
		in.isag_np = np;
		in.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;
		if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
			libreswan_log(
				" setting bogus ISAKMP_PAYLOAD_LIBRESWAN_BOGUS flag in ISAKMP payload");
			in.isag_critical |= ISAKMP_PAYLOAD_LIBRESWAN_BOGUS;
		}

		if (!out_struct(&in, &ikev2_nonce_desc, &md->rbody, &pb) ||
		    !out_raw(st->st_nr.ptr, st->st_nr.len, &pb, "IKEv2 nonce"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&pb);
	}

	/* Send VendrID if needed VID */
	if (c->send_vendorid) {
		const char *myvid = ipsec_version_vendorid();
		int np = --numvidtosend >
			 0 ? ISAKMP_NEXT_v2V : ISAKMP_NEXT_v2NONE;

		if (!out_generic_raw(np, &isakmp_vendor_id_desc, &md->rbody,
				     myvid, strlen(myvid),
				     "Vendor ID"))
			return STF_INTERNAL_ERROR;
	}

	close_message(&md->rbody, st);
	close_output_pbs(&reply_stream);

	/* keep it for a retransmit if necessary */
	freeanychunk(st->st_tpacket);
	clonetochunk(st->st_tpacket, reply_stream.start,
		     pbs_offset(&reply_stream),
		     "reply packet for ikev2_parent_inI1outR1_tail");

	/* save packet for later signing */
	freeanychunk(st->st_firstpacket_me);
	clonetochunk(st->st_firstpacket_me, reply_stream.start,
		     pbs_offset(&reply_stream), "saved first packet");

	/* note: retransimission is driven by initiator */

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
static void ikev2_parent_inR1outI2_continue(struct pluto_crypto_req_cont *pcrc,
					    struct pluto_crypto_req *r,
					    err_t ugh);

static stf_status ikev2_parent_inR1outI2_tail(
	struct pluto_crypto_req_cont *pcrc,
	struct pluto_crypto_req *r);

stf_status ikev2parent_inR1outI2(struct msg_digest *md)
{
	struct state *st = md->st;
	/* struct connection *c = st->st_connection; */
	pb_stream *keyex_pbs;

	/* check if the responder replied with v2N with DOS COOKIE */
	if ( md->chain[ISAKMP_NEXT_v2N] &&
	     md->chain[ISAKMP_NEXT_v2N]->payload.v2n.isan_type ==
	     v2N_COOKIE) {
		u_int8_t spisize;
		const pb_stream *dc_pbs;
		DBG(DBG_CONTROLMORE,
		    DBG_log(
			    "inR1OutI2 received a DOS v2N_COOKIE from the responder");
		    DBG_log("resend the I1 with a cookie payload"));
		spisize = md->chain[ISAKMP_NEXT_v2N]->payload.v2n.isan_spisize;
		dc_pbs = &md->chain[ISAKMP_NEXT_v2N]->pbs;
		clonetochunk(st->st_dcookie,  (dc_pbs->cur + spisize),
			     (pbs_left(
				      dc_pbs) - spisize),
			     "saved received dcookie");

		DBG(DBG_CONTROLMORE,
		    DBG_dump_chunk("dcookie received (instead of a R1):",
				   st->st_dcookie);
		    DBG_log("next STATE_PARENT_I1 resend I1 with the dcookie"));

		md->svm = ikev2_parent_firststate();

		change_state(st, STATE_PARENT_I1);
		st->st_msgid_lastack = INVALID_MSGID;
		md->msgid_received = INVALID_MSGID; /* AAA hack  */
		st->st_msgid_nextuse = 0;

		return ikev2_parent_outI1_common(md, st);
	}

	/*
	 * If we did not get a KE payload, we cannot continue. There * should be
	 * a Notify telling us why. We inform the user, but continue to try this
	 * connection via regular retransmit intervals.
	 */
	if ( md->chain[ISAKMP_NEXT_v2N]  &&
	     (md->chain[ISAKMP_NEXT_v2KE] == NULL)) {
		const char *from_state_name = enum_name(&state_names,
							st->st_state);
		const u_int16_t isan_type =
			md->chain[ISAKMP_NEXT_v2N]->payload.v2n.isan_type;
		libreswan_log("%s: received %s",
			      from_state_name,
			      enum_name(&ikev2_notify_names, isan_type));
		return STF_FAIL + isan_type;
	} else if ( md->chain[ISAKMP_NEXT_v2N]) {
		DBG(DBG_CONTROL, DBG_log("received a notify.."));
	}

	/*
	 * the responder sent us back KE, Gr, Nr, and it's our time to calculate
	 * the shared key values.
	 */

	DBG(DBG_CONTROLMORE,
	    DBG_log(
		    "ikev2 parent inR1: calculating g^{xy} in order to send I2"));

	/* KE in */
	keyex_pbs = &md->chain[ISAKMP_NEXT_v2KE]->pbs;
	RETURN_STF_FAILURE(accept_KE(&st->st_gr, "Gr", st->st_oakley.group,
				     keyex_pbs));

	/* Ni in */
	RETURN_STF_FAILURE(accept_v2_nonce(md, &st->st_nr, "Ni"));

	if (md->chain[ISAKMP_NEXT_v2SA] == NULL) {
		libreswan_log("No responder SA proposal found");
		return v2N_INVALID_SYNTAX;
	}

	/* process and confirm the SA selected */
	{
		struct payload_digest *const sa_pd =
			md->chain[ISAKMP_NEXT_v2SA];
		v2_notification_t rn;

		/* SA body in and out */
		rn = ikev2_parse_parent_sa_body(&sa_pd->pbs,
						&sa_pd->payload.v2sa,
						NULL, st, FALSE);

		if (rn != v2N_NOTHING_WRONG)
			return STF_FAIL + rn;
	}

	/* update state */
	ikev2_update_counters(md);

	/* now. we need to go calculate the g^xy */
	{
		struct dh_continuation *dh = alloc_thing(
			struct dh_continuation,
			"ikev2_inR1outI2 KE");
		stf_status e;

		dh->md = md;
		set_suspended(st, dh->md);

		pcrc_init(&dh->dh_pcrc);
		dh->dh_pcrc.pcrc_func = ikev2_parent_inR1outI2_continue;
		e = start_dh_v2(&dh->dh_pcrc, st, st->st_import, INITIATOR,
				st->st_oakley.groupnum);
		if (e != STF_SUSPEND && e != STF_INLINE) {
			loglog(RC_CRYPTOFAILED, "system too busy");
			delete_state(st);
		}

		reset_globals();

		return e;
	}
}

static void ikev2_parent_inR1outI2_continue(struct pluto_crypto_req_cont *pcrc,
					    struct pluto_crypto_req *r,
					    err_t ugh)
{
	struct dh_continuation *dh = (struct dh_continuation *)pcrc;
	struct msg_digest *md = dh->md;
	struct state *const st = md->st;
	stf_status e;

	DBG(DBG_CONTROLMORE,
	    DBG_log("ikev2 parent inR1outI2: calculating g^{xy}, sending I2"));

	if (st == NULL) {
		loglog(RC_LOG_SERIOUS,
		       "%s: Request was disconnected from state",
		       __FUNCTION__);
		if (dh->md)
			release_md(dh->md);
		return;
	}

	/* XXX should check out ugh */
	passert(ugh == NULL);
	passert(cur_state == NULL);
	passert(st != NULL);

	passert(st->st_suspended_md == dh->md);
	set_suspended(st, NULL); /* no longer connected or suspended */

	set_cur_state(st);

	st->st_calculating = FALSE;

	e = ikev2_parent_inR1outI2_tail(pcrc, r);

	if (dh->md != NULL) {
		complete_v2_state_transition(&dh->md, e);
		if (dh->md)
			release_md(dh->md);
	}
	reset_globals();
}

static void ikev2_padup_pre_encrypt(struct msg_digest *md,
				    pb_stream *e_pbs_cipher)
{
	struct state *st = md->st;
	struct state *pst = st;

	if (st->st_clonedfrom != 0)
		pst = state_with_serialno(st->st_clonedfrom);

	/* pads things up to message size boundary */
	{
		size_t blocksize = pst->st_oakley.encrypter->enc_blocksize;
		char  *b = alloca(blocksize);
		unsigned int i;
		size_t padding =  pad_up(pbs_offset(e_pbs_cipher), blocksize);
		if (padding == 0)
			padding = blocksize;

		for (i = 0; i < padding; i++)
			b[i] = i;
		out_raw(b, padding, e_pbs_cipher, "padding and length");
	}
}

static unsigned char *ikev2_authloc(struct msg_digest *md,
				    pb_stream *e_pbs)
{
	unsigned char *b12;
	struct state *st = md->st;
	struct state *pst = st;

	if (st->st_clonedfrom != 0) {
		pst = state_with_serialno(st->st_clonedfrom);
		if ( pst == NULL)
			return NULL;
	}

	b12 = e_pbs->cur;
	if (!out_zero(pst->st_oakley.integ_hasher->hash_integ_len, e_pbs,
		      "length of truncated HMAC"))
		return NULL;

	return b12;
}

static stf_status ikev2_encrypt_msg(struct msg_digest *md,
				    enum phase1_role init,
				    unsigned char *authstart,
				    unsigned char *iv,
				    unsigned char *encstart,
				    unsigned char *authloc,
				    pb_stream *e_pbs UNUSED,
				    pb_stream *e_pbs_cipher)
{
	struct state *st = md->st;
	struct state *pst = st;
	chunk_t *cipherkey, *authkey;

	if (st->st_clonedfrom != 0)
		pst = state_with_serialno(st->st_clonedfrom);

	if (init == INITIATOR) {
		cipherkey = &pst->st_skey_ei;
		authkey   = &pst->st_skey_ai;
	} else {
		cipherkey = &pst->st_skey_er;
		authkey   = &pst->st_skey_ar;
	}

	/* encrypt the block */
	{
		size_t blocksize = pst->st_oakley.encrypter->enc_blocksize;
		unsigned char *savediv = alloca(blocksize);
		unsigned int cipherlen = e_pbs_cipher->cur - encstart;

		DBG(DBG_CRYPT,
		    DBG_dump("data before encryption:", encstart, cipherlen));

		memcpy(savediv, iv, blocksize);

		/* now, encrypt */
		(st->st_oakley.encrypter->do_crypt)(encstart,
						    cipherlen,
						    cipherkey->ptr,
						    cipherkey->len,
						    savediv, TRUE);

		DBG(DBG_CRYPT,
		    DBG_dump("data after encryption:", encstart, cipherlen));
	}

	/* okay, authenticate from beginning of IV */
	{
		struct hmac_ctx ctx;
		DBG(DBG_PARSING, DBG_log("Inside authloc"));
		DBG(DBG_CRYPT,
		    DBG_dump("authkey value: ", authkey->ptr, authkey->len));
		hmac_init_chunk(&ctx, pst->st_oakley.integ_hasher, *authkey);
		DBG(DBG_PARSING, DBG_log("Inside authloc after init"));
		hmac_update(&ctx, authstart, authloc - authstart);
		DBG(DBG_PARSING, DBG_log("Inside authloc after update"));
		hmac_final(authloc, &ctx);
		DBG(DBG_PARSING, DBG_log("Inside authloc after final"));

		DBG(DBG_PARSING, {
			    DBG_dump("data being hmac:", authstart, authloc -
				     authstart);
			    DBG_dump("out calculated auth:", authloc,
				     pst->st_oakley.integ_hasher->
				     hash_integ_len);
		    });
	}

	return STF_OK;
}

static
stf_status ikev2_decrypt_msg(struct msg_digest *md,
			     enum phase1_role init)
{
	struct state *st = md->st;
	unsigned char *encend;
	pb_stream     *e_pbs;
	unsigned int np;
	unsigned char *iv;
	chunk_t       *cipherkey, *authkey;
	unsigned char *authstart;
	struct state *pst = st;

	if (st->st_clonedfrom != 0)
		pst = state_with_serialno(st->st_clonedfrom);

	if (init == INITIATOR) {
		cipherkey = &pst->st_skey_er;
		authkey   = &pst->st_skey_ar;
	} else {
		cipherkey = &pst->st_skey_ei;
		authkey   = &pst->st_skey_ai;
	}

	e_pbs = &md->chain[ISAKMP_NEXT_v2E]->pbs;
	np    = md->chain[ISAKMP_NEXT_v2E]->payload.generic.isag_np;

	authstart = md->packet_pbs.start;
	iv     = e_pbs->cur;
	encend = e_pbs->roof - pst->st_oakley.integ_hasher->hash_integ_len;

	/* start by checking authenticator */
	{
		unsigned char  *b12 = alloca(
			pst->st_oakley.integ_hasher->hash_digest_len);
		struct hmac_ctx ctx;

		hmac_init_chunk(&ctx, pst->st_oakley.integ_hasher, *authkey);
		hmac_update(&ctx, authstart, encend - authstart);
		hmac_final(b12, &ctx);

		DBG(DBG_PARSING, {
			    DBG_dump("data being hmac:", authstart, encend -
				     authstart);
			    DBG_dump("R2 calculated auth:", b12,
				     pst->st_oakley.integ_hasher->
				     hash_integ_len);
			    DBG_dump("R2  provided  auth:", encend,
				     pst->st_oakley.integ_hasher->
				     hash_integ_len);
		    });

		/* compare first 96 bits == 12 bytes */
		/* It is not always 96 bytes, it depends upon which integ algo is used*/
		if (memcmp(b12, encend,
			   pst->st_oakley.integ_hasher->hash_integ_len) != 0) {
			libreswan_log("R2 failed to match authenticator");
			return STF_FAIL;
		}
	}

	DBG(DBG_PARSING, DBG_log("authenticator matched"));

	/* decrypt */
	{
		size_t blocksize = pst->st_oakley.encrypter->enc_blocksize;
		unsigned char *encstart  = iv + blocksize;
		unsigned int enclen    = encend - encstart;
		unsigned int padlen;

		DBG(DBG_CRYPT,
		    DBG_dump("data before decryption:", encstart, enclen));

		/* now, decrypt */
		(pst->st_oakley.encrypter->do_crypt)(encstart,
						     enclen,
						     cipherkey->ptr,
						     cipherkey->len,
						     iv, FALSE);

		padlen = encstart[enclen - 1];
		encend = encend - padlen + 1;

		if (encend < encstart) {
			libreswan_log("invalid pad length: %u", padlen);
			return STF_FAIL;
		}

		DBG(DBG_CRYPT, {
			    DBG_dump("decrypted payload:", encstart, enclen);
			    DBG_log("striping %u bytes as pad", padlen + 1);
		    });

		init_pbs(&md->clr_pbs, encstart, enclen - (padlen + 1),
			 "cleartext");
	}

	{
		stf_status ret;
		ret =
			ikev2_process_payloads(md, &md->clr_pbs, st->st_state,
					       np);
		if (ret != STF_OK)
			return ret;
	}

	return STF_OK;
}

static stf_status ikev2_send_auth(struct connection *c,
				  struct state *st,
				  enum phase1_role role,
				  unsigned int np,
				  unsigned char *idhash_out,
				  pb_stream *outpbs)
{
	struct ikev2_a a;
	pb_stream a_pbs;
	struct state *pst = st;

	if (st->st_clonedfrom != 0)
		pst = state_with_serialno(st->st_clonedfrom);

	a.isaa_critical = ISAKMP_PAYLOAD_NONCRITICAL;
	if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
		libreswan_log(
			" setting bogus ISAKMP_PAYLOAD_LIBRESWAN_BOGUS flag in ISAKMP payload");
		a.isaa_critical |= ISAKMP_PAYLOAD_LIBRESWAN_BOGUS;
	}

	a.isaa_np = np;

	if (c->policy & POLICY_RSASIG) {
		a.isaa_type = v2_AUTH_RSA;
	} else if (c->policy & POLICY_PSK) {
		a.isaa_type = v2_AUTH_SHARED;
	} else {
		/* what else is there?... DSS not implemented. */
		return STF_FAIL;
	}

	if (!out_struct(&a,
			&ikev2_a_desc,
			outpbs,
			&a_pbs))
		return STF_INTERNAL_ERROR;

	if (c->policy & POLICY_RSASIG) {
		if (!ikev2_calculate_rsa_sha1(pst, role, idhash_out, &a_pbs))
			return STF_FATAL + v2N_AUTHENTICATION_FAILED;

	} else if (c->policy & POLICY_PSK) {
		if (!ikev2_calculate_psk_auth(pst, role, idhash_out, &a_pbs))
			return STF_FAIL + v2N_AUTHENTICATION_FAILED;
	}

	close_output_pbs(&a_pbs);
	return STF_OK;
}

static stf_status ikev2_parent_inR1outI2_tail(
	struct pluto_crypto_req_cont *pcrc,
	struct pluto_crypto_req *r)
{
	struct dh_continuation *dh = (struct dh_continuation *)pcrc;
	struct msg_digest *md = dh->md;
	struct state *st      = md->st;
	struct connection *c  = st->st_connection;
	struct ikev2_generic e;
	unsigned char *encstart;
	pb_stream e_pbs, e_pbs_cipher;
	unsigned char *iv;
	int ivsize;
	stf_status ret;
	unsigned char *idhash;
	unsigned char *authstart;
	struct state *pst = st;
	bool send_cert = FALSE;

	finish_dh_v2(st, r);

	if (DBGP(DBG_PRIVATE) && DBGP(DBG_CRYPT))
		ikev2_log_parentSA(st);

	pst = st;
	st = duplicate_state(pst);
	st->st_msgid = htonl(pst->st_msgid_nextuse); /* PAUL: note ordering */
	insert_state(st);
	md->st = st;
	md->pst = pst;

	/* parent had crypto failed, replace it with rekey! */
	delete_event(pst);
	event_schedule(EVENT_SA_REPLACE, c->sa_ike_life_seconds, pst);

	/* need to force parent state to I2 */
	change_state(pst, STATE_PARENT_I2);

	/* record first packet for later checking of signature */
	clonetochunk(pst->st_firstpacket_him, md->message_pbs.start,
		     pbs_offset(
			     &md->message_pbs), "saved first received packet");

	/* beginning of data going out */
	authstart = reply_stream.cur;

	/* make sure HDR is at start of a clean buffer */
	zero(reply_buffer);
	init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		 "reply packet");

	/* HDR out */
	{
		struct isakmp_hdr r_hdr = md->hdr;

		r_hdr.isa_np    = ISAKMP_NEXT_v2E;
		r_hdr.isa_xchg  = ISAKMP_v2_AUTH;
		r_hdr.isa_flags = ISAKMP_FLAGS_I;
		r_hdr.isa_msgid = st->st_msgid;
		memcpy(r_hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
		memcpy(r_hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
		if (!out_struct(&r_hdr, &isakmp_hdr_desc, &reply_stream,
				&md->rbody))
			return STF_INTERNAL_ERROR;
	}

	/* insert an Encryption payload header */
	e.isag_np = ISAKMP_NEXT_v2IDi;
	e.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;
	if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
		libreswan_log(
			" setting bogus ISAKMP_PAYLOAD_LIBRESWAN_BOGUS flag in ISAKMP payload");
		e.isag_critical |= ISAKMP_PAYLOAD_LIBRESWAN_BOGUS;
	}

	if (!out_struct(&e, &ikev2_e_desc, &md->rbody, &e_pbs))
		return STF_INTERNAL_ERROR;

	/* insert IV */
	iv     = e_pbs.cur;
	ivsize = st->st_oakley.encrypter->iv_size;
	if (!out_zero(ivsize, &e_pbs, "iv"))
		return STF_INTERNAL_ERROR;

	get_rnd_bytes(iv, ivsize);

	/* note where cleartext starts */
	init_pbs(&e_pbs_cipher, e_pbs.cur, e_pbs.roof - e_pbs.cur,
		 "cleartext");
	e_pbs_cipher.container = &e_pbs;
	e_pbs_cipher.desc = NULL;
	e_pbs_cipher.cur = e_pbs.cur;
	encstart = e_pbs_cipher.cur;

	/* send out the IDi payload */
	{
		struct ikev2_id r_id;
		pb_stream r_id_pbs;
		chunk_t id_b;
		struct hmac_ctx id_ctx;
		unsigned char *id_start;
		unsigned int id_len;

		hmac_init_chunk(&id_ctx, pst->st_oakley.prf_hasher,
				pst->st_skey_pi);
		build_id_payload((struct isakmp_ipsec_id *)&r_id, &id_b,
				 &c->spd.this);
		r_id.isai_critical = ISAKMP_PAYLOAD_NONCRITICAL;
		if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
			libreswan_log(
				" setting bogus ISAKMP_PAYLOAD_LIBRESWAN_BOGUS flag in ISAKMP payload");
			r_id.isai_critical |= ISAKMP_PAYLOAD_LIBRESWAN_BOGUS;
		}

		{       /* decide to send CERT payload */
			send_cert = doi_send_ikev2_cert_thinking(st);

			if (send_cert)
				r_id.isai_np = ISAKMP_NEXT_v2CERT;
			else
				r_id.isai_np = ISAKMP_NEXT_v2AUTH;
		}

		id_start = e_pbs_cipher.cur;
		if (!out_struct(&r_id,
				&ikev2_id_desc,
				&e_pbs_cipher,
				&r_id_pbs) ||
		    !out_chunk(id_b, &r_id_pbs, "my identity"))
			return STF_INTERNAL_ERROR;

		/* HASH of ID is not done over common header */
		id_start += 4;

		close_output_pbs(&r_id_pbs);

		/* calculate hash of IDi for AUTH below */
		id_len = e_pbs_cipher.cur - id_start;
		DBG(DBG_CRYPT, DBG_dump_chunk("idhash calc pi",
					      pst->st_skey_pi));
		DBG(DBG_CRYPT, DBG_dump("idhash calc I2", id_start, id_len));
		hmac_update(&id_ctx, id_start, id_len);
		idhash = alloca(pst->st_oakley.prf_hasher->hash_digest_len);
		hmac_final(idhash, &id_ctx);
	}

	/* send [CERT,] payload RFC 4306 3.6, 1.2) */
	{

		if (send_cert) {
			stf_status certstat = ikev2_send_cert( st, md,
							       INITIATOR,
							       ISAKMP_NEXT_v2AUTH,
							       &e_pbs_cipher);
			if (certstat != STF_OK)
				return certstat;
		}
	}

	/* send out the AUTH payload */
	{
		lset_t policy;
		struct connection *c0 = first_pending(pst, &policy,
						      &st->st_whack_sock);
		unsigned int np = (c0 ? ISAKMP_NEXT_v2SA : ISAKMP_NEXT_v2NONE);
		DBG(DBG_CONTROL,
		    DBG_log(" payload after AUTH will be %s",
			    (c0) ? "ISAKMP_NEXT_v2SA" :
			    "ISAKMP_NEXT_v2NONE/NOTIFY"));

		stf_status authstat = ikev2_send_auth(c, st,
						      INITIATOR,
						      np,
						      idhash, &e_pbs_cipher);
		if (authstat != STF_OK)
			return authstat;

		/*
		 * now, find an eligible child SA from the pending list, and emit
		 * SA2i, TSi and TSr and (v2N_USE_TRANSPORT_MODE notification in transport mode) for it .
		 */
		if (c0) {
			chunk_t child_spi, notify_data;
			st->st_connection = c0;

			ikev2_emit_ipsec_sa(md, &e_pbs_cipher,
					    ISAKMP_NEXT_v2TSi, c0, policy);

			st->st_ts_this = ikev2_end_to_ts(&c0->spd.this);
			st->st_ts_that = ikev2_end_to_ts(&c0->spd.that);

			ikev2_calc_emit_ts(md, &e_pbs_cipher, INITIATOR, c0,
					   policy);

			if ( !(st->st_connection->policy & POLICY_TUNNEL) ) {
				DBG_log(
					"Initiator child policy is transport mode, sending v2N_USE_TRANSPORT_MODE");
				memset(&child_spi, 0, sizeof(child_spi));
				memset(&notify_data, 0, sizeof(notify_data));
				ship_v2N(ISAKMP_NEXT_v2NONE,
					 ISAKMP_PAYLOAD_NONCRITICAL, 0,
					 &child_spi,
					 v2N_USE_TRANSPORT_MODE, &notify_data,
					 &e_pbs_cipher);
			}
		} else {
			libreswan_log(
				"no pending SAs found, PARENT SA keyed only");
		}
	}

	/*
	 * need to extend the packet so that we will know how big it is
	 * since the length is under the integrity check
	 */
	ikev2_padup_pre_encrypt(md, &e_pbs_cipher);
	close_output_pbs(&e_pbs_cipher);

	{
		unsigned char *authloc = ikev2_authloc(md, &e_pbs);

		if (authloc == NULL)
			return STF_INTERNAL_ERROR;

		close_output_pbs(&e_pbs);
		close_output_pbs(&md->rbody);
		close_output_pbs(&reply_stream);

		ret = ikev2_encrypt_msg(md, INITIATOR,
					authstart,
					iv, encstart, authloc,
					&e_pbs, &e_pbs_cipher);
		if (ret != STF_OK)
			return ret;
	}

	/* keep it for a retransmit if necessary, but on initiator
	 * we never do that, but send_ike_msg() uses it.
	 */
	freeanychunk(pst->st_tpacket);
	clonetochunk(pst->st_tpacket, reply_stream.start,
		     pbs_offset(&reply_stream),
		     "reply packet for ikev2_parent_outI1");

	/*
	 * Delete previous retransmission event.
	 */
	delete_event(st);
	event_schedule(EVENT_v2_RETRANSMIT, EVENT_RETRANSMIT_DELAY_0, st);

	return STF_OK;

}

/*
 *
 ***************************************************************
 *                       PARENT_inI2                       *****
 ***************************************************************
 *  -
 *
 *
 */
static void ikev2_parent_inI2outR2_continue(struct pluto_crypto_req_cont *pcrc,
					    struct pluto_crypto_req *r,
					    err_t ugh);

static stf_status ikev2_parent_inI2outR2_tail(
	struct pluto_crypto_req_cont *pcrc,
	struct pluto_crypto_req *r);

stf_status ikev2parent_inI2outR2(struct msg_digest *md)
{
	struct state *st = md->st;

	/* struct connection *c = st->st_connection; */

	/*
	 * the initiator sent us an encrypted payload. We need to calculate
	 * our g^xy, and skeyseed values, and then decrypt the payload.
	 */

	DBG(DBG_CONTROLMORE,
	    DBG_log(
		    "ikev2 parent inI2outR2: calculating g^{xy} in order to decrypt I2"));

	/* verify that there is in fact an encrypted payload */
	if (!md->chain[ISAKMP_NEXT_v2E]) {
		libreswan_log("R2 state should receive an encrypted payload");
		reset_globals(); /* XXX suspicious - why was this deemed neccessary? */
		return STF_FATAL;
	}

	/* now. we need to go calculate the g^xy */
	{
		struct dh_continuation *dh = alloc_thing(
			struct dh_continuation,
			"ikev2_inI2outR2 KE");
		stf_status e;

		dh->md = md;
		set_suspended(st, dh->md);

		pcrc_init(&dh->dh_pcrc);
		dh->dh_pcrc.pcrc_func = ikev2_parent_inI2outR2_continue;
		e = start_dh_v2(&dh->dh_pcrc, st, st->st_import, RESPONDER,
				st->st_oakley.groupnum);
		if (e != STF_SUSPEND && e != STF_INLINE) {
			loglog(RC_CRYPTOFAILED, "system too busy");
			delete_state(st);
		}

		reset_globals();

		return e;
	}
}

static void ikev2_parent_inI2outR2_continue(struct pluto_crypto_req_cont *pcrc,
					    struct pluto_crypto_req *r,
					    err_t ugh)
{
	struct dh_continuation *dh = (struct dh_continuation *)pcrc;
	struct msg_digest *md = dh->md;
	struct state *const st = md->st;
	stf_status e;

	DBG(DBG_CONTROLMORE,
	    DBG_log("ikev2 parent inI2outR2: calculating g^{xy}, sending R2"));

	if (st == NULL) {
		loglog(RC_LOG_SERIOUS,
		       "%s: Request was disconnected from state",
		       __FUNCTION__);
		if (dh->md)
			release_md(dh->md);
		return;
	}

	/* XXX should check out ugh */
	passert(ugh == NULL);
	passert(cur_state == NULL);
	passert(st != NULL);

	passert(st->st_suspended_md == dh->md);
	set_suspended(st, NULL); /* no longer connected or suspended */

	set_cur_state(st);

	st->st_calculating = FALSE;

	e = ikev2_parent_inI2outR2_tail(pcrc, r);
	if ( e > STF_FAIL) {
		/* we do not send a notify because we are the initiator that could be responding to an error notification */
		int v2_notify_num = e - STF_FAIL;
		DBG_log(
			"ikev2_parent_inI2outR2_tail returned STF_FAIL with %s",
			enum_name(&ikev2_notify_names, v2_notify_num));
	} else if ( e != STF_OK) {
		DBG_log("ikev2_parent_inI2outR2_tail returned %s",
			enum_name(&stfstatus_name, e));
	}

	if (dh->md != NULL) {
		complete_v2_state_transition(&dh->md, e);
		if (dh->md)
			release_md(dh->md);
	}
	reset_globals();
}

static stf_status ikev2_parent_inI2outR2_tail(
	struct pluto_crypto_req_cont *pcrc,
	struct pluto_crypto_req *r)
{
	struct dh_continuation *dh = (struct dh_continuation *)pcrc;
	struct msg_digest *md  = dh->md;
	struct state *const st = md->st;
	struct connection *c   = st->st_connection;
	unsigned char *idhash_in, *idhash_out;
	unsigned char *authstart;
	unsigned int np;
	int v2_notify_num = 0;

	/* extract calculated values from r */
	finish_dh_v2(st, r);

	if (DBGP(DBG_PRIVATE) && DBGP(DBG_CRYPT))
		ikev2_log_parentSA(st);

	/* decrypt things. */
	{
		stf_status ret;
		ret = ikev2_decrypt_msg(md, RESPONDER);
		if (ret != STF_OK)
			return ret;
	}

	/*Once the message has been decrypted, then only we can check for auth payload*/
	/*check the presense of auth payload now so that it does not crash in rehash_state if auth payload has not been received*/
	if (!md->chain[ISAKMP_NEXT_v2AUTH]) {
		libreswan_log("no authentication payload found");
		return STF_FAIL;
	}

	if (!ikev2_decode_peer_id(md, RESPONDER))
		return STF_FAIL + v2N_AUTHENTICATION_FAILED;

	{
		struct hmac_ctx id_ctx;
		const pb_stream *id_pbs = &md->chain[ISAKMP_NEXT_v2IDi]->pbs;
		unsigned char *idstart = id_pbs->start + 4;
		unsigned int idlen  = pbs_room(id_pbs) - 4;

		hmac_init_chunk(&id_ctx, st->st_oakley.prf_hasher,
				st->st_skey_pi);

		/* calculate hash of IDi for AUTH below */
		DBG(DBG_CRYPT,
		    DBG_dump_chunk("idhash verify pi", st->st_skey_pi));
		DBG(DBG_CRYPT, DBG_dump("idhash verify I2", idstart, idlen));
		hmac_update(&id_ctx, idstart, idlen);
		idhash_in = alloca(st->st_oakley.prf_hasher->hash_digest_len);
		hmac_final(idhash_in, &id_ctx);
	}

	/* process CERT payload */
	{
		if (md->chain[ISAKMP_NEXT_v2CERT]) {
			/* should we check if we should accept a cert payload ?
			 *  has_preloaded_public_key(st)
			 */
			DBG(DBG_CONTROLMORE,
			    DBG_log(
				    "has a v2_CERT payload going to process it "));
			ikev2_decode_cert(md);
		}
	}

	/* process CERTREQ payload */
	if (md->chain[ISAKMP_NEXT_v2CERTREQ]) {
		DBG(DBG_CONTROLMORE,
		    DBG_log("has a v2CERTREQ payload going to decode it"));
		ikev2_decode_cr(md, &st->st_connection->requested_ca);
	}

	/* process AUTH payload now */
	/* now check signature from RSA key */
	switch (md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2a.isaa_type) {
	case v2_AUTH_RSA:
	{
		stf_status authstat = ikev2_verify_rsa_sha1(st,
							    RESPONDER,
							    idhash_in,
							    NULL,       /* keys from DNS */
							    NULL,       /* gateways from DNS */
							    &md->chain[
								    ISAKMP_NEXT_v2AUTH]->pbs);
		if (authstat != STF_OK) {
			libreswan_log("RSA authentication failed");
			SEND_NOTIFICATION(v2N_AUTHENTICATION_FAILED);
			return STF_FATAL;
		}
		break;
	}
	case v2_AUTH_SHARED:
	{
		stf_status authstat = ikev2_verify_psk_auth(st,
							    RESPONDER,
							    idhash_in,
							    &md->chain[
								    ISAKMP_NEXT_v2AUTH]->pbs);
		if (authstat != STF_OK) {
			libreswan_log(
				"PSK authentication failed AUTH mismatch!");
			SEND_NOTIFICATION(v2N_AUTHENTICATION_FAILED);
			return STF_FATAL;
		}
		break;
	}
	default:
		libreswan_log("authentication method: %s not supported",
			      enum_name(&ikev2_auth_names,
					md->chain[ISAKMP_NEXT_v2AUTH]->payload.
					v2a.isaa_type));
		return STF_FATAL;
	}

	/* Is there a notify about an error ? */
	if (md->chain[ISAKMP_NEXT_v2N] != NULL) {
		DBG(DBG_CONTROL,
		    DBG_log(
			    " notify payload detected, should be processed...."));
	}

	/* good. now create child state */
	/* note: as we will switch to child state, we force the parent to the
	 * new state now */
	change_state(st, STATE_PARENT_R2);
	c->newest_isakmp_sa = st->st_serialno;

	delete_event(st);
	event_schedule(EVENT_SA_REPLACE, c->sa_ike_life_seconds, st);

	authstart = reply_stream.cur;
	/* send response */
	{
		unsigned char *encstart;
		unsigned char *iv;
		unsigned int ivsize;
		struct ikev2_generic e;
		pb_stream e_pbs, e_pbs_cipher;
		stf_status ret;
		bool send_cert = FALSE;

		/* make sure HDR is at start of a clean buffer */
		zero(reply_buffer);
		init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
			 "reply packet");

		/* HDR out */
		{
			struct isakmp_hdr r_hdr = md->hdr;

			r_hdr.isa_np    = ISAKMP_NEXT_v2E;
			r_hdr.isa_xchg  = ISAKMP_v2_AUTH;
			r_hdr.isa_flags = ISAKMP_FLAGS_R;
			memcpy(r_hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
			memcpy(r_hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
			if (!out_struct(&r_hdr, &isakmp_hdr_desc,
					&reply_stream, &md->rbody))
				return STF_INTERNAL_ERROR;
		}

		/* insert an Encryption payload header */
		e.isag_np = ISAKMP_NEXT_v2IDr;
		e.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;

		if (!out_struct(&e, &ikev2_e_desc, &md->rbody, &e_pbs))
			return STF_INTERNAL_ERROR;

		/* insert IV */
		iv     = e_pbs.cur;
		ivsize = st->st_oakley.encrypter->iv_size;
		if (!out_zero(ivsize, &e_pbs, "iv"))
			return STF_INTERNAL_ERROR;

		get_rnd_bytes(iv, ivsize);

		/* note where cleartext starts */
		init_pbs(&e_pbs_cipher, e_pbs.cur, e_pbs.roof - e_pbs.cur,
			 "cleartext");
		e_pbs_cipher.container = &e_pbs;
		e_pbs_cipher.desc = NULL;
		e_pbs_cipher.cur = e_pbs.cur;
		encstart = e_pbs_cipher.cur;

		/* decide to send CERT payload before we generate IDr */
		send_cert = doi_send_ikev2_cert_thinking(st);

		/* send out the IDr payload */
		{
			struct ikev2_id r_id;
			pb_stream r_id_pbs;
			chunk_t id_b;
			struct hmac_ctx id_ctx;
			unsigned char *id_start;
			unsigned int id_len;

			hmac_init_chunk(&id_ctx, st->st_oakley.prf_hasher,
					st->st_skey_pr);
			build_id_payload((struct isakmp_ipsec_id *)&r_id,
					 &id_b,
					 &c->spd.this);
			r_id.isai_critical = ISAKMP_PAYLOAD_NONCRITICAL;

			if (send_cert)
				r_id.isai_np = ISAKMP_NEXT_v2CERT;
			else
				r_id.isai_np = ISAKMP_NEXT_v2AUTH;

			id_start = e_pbs_cipher.cur;

			if (!out_struct(&r_id,
					&ikev2_id_desc,
					&e_pbs_cipher,
					&r_id_pbs) ||
			    !out_chunk(id_b, &r_id_pbs, "my identity"))
				return STF_INTERNAL_ERROR;

			close_output_pbs(&r_id_pbs);

			id_start += 4;

			/* calculate hash of IDi for AUTH below */
			id_len = e_pbs_cipher.cur - id_start;
			DBG(DBG_CRYPT,
			    DBG_dump_chunk("idhash calc pr", st->st_skey_pr));
			DBG(DBG_CRYPT,
			    DBG_dump("idhash calc R2", id_start, id_len));
			hmac_update(&id_ctx, id_start, id_len);
			idhash_out = alloca(
				st->st_oakley.prf_hasher->hash_digest_len);
			hmac_final(idhash_out, &id_ctx);
		}

		DBG(DBG_CONTROLMORE,
		    DBG_log("assembled IDr payload -- CERT next"));

		/* send CERT payload RFC 4306 3.6, 1.2:([CERT,] ) */
		if (send_cert) {
			stf_status certstat = ikev2_send_cert(st, md,
							      RESPONDER,
							      ISAKMP_NEXT_v2AUTH,
							      &e_pbs_cipher);
			if (certstat != STF_OK)
				return certstat;
		}

		/* authentication good, see if there is a child SA being proposed */
		if (md->chain[ISAKMP_NEXT_v2SA] == NULL ||
		    md->chain[ISAKMP_NEXT_v2TSi] == NULL ||
		    md->chain[ISAKMP_NEXT_v2TSr] == NULL) {

			/* initiator didn't propose anything. Weird. Try unpending out end. */
			/* UNPEND XXX */
			libreswan_log("No CHILD SA proposals received.");
			np = ISAKMP_NEXT_v2NONE;
		} else {
			DBG_log("CHILD SA proposals received");
			libreswan_log(
				"PAUL: this is where we have to check the TSi/TSr");
			np = ISAKMP_NEXT_v2SA;
		}

		DBG(DBG_CONTROLMORE,
		    DBG_log("going to assemble AUTH payload"));

		/* now send AUTH payload */
		{
			stf_status authstat = ikev2_send_auth(c, st,
							      RESPONDER, np,
							      idhash_out,
							      &e_pbs_cipher);
			if (authstat != STF_OK)
				return authstat;
		}

		if (np == ISAKMP_NEXT_v2SA) {
			/* must have enough to build an CHILD_SA */
			ret = ikev2_child_sa_respond(md, RESPONDER,
						     &e_pbs_cipher);
			if (ret > STF_FAIL) {
				v2_notify_num = ret - STF_FAIL;
				DBG(DBG_CONTROL,
				    DBG_log(
					    "ikev2_child_sa_respond returned STF_FAIL with %s",
					    enum_name(&ikev2_notify_names,
						      v2_notify_num)));
				np = ISAKMP_NEXT_v2NONE;
			} else if (ret != STF_OK) {
				DBG_log("ikev2_child_sa_respond returned %s", enum_name(
						&stfstatus_name,
						ret));
				np = ISAKMP_NEXT_v2NONE;
			}
		}

		ikev2_padup_pre_encrypt(md, &e_pbs_cipher);
		close_output_pbs(&e_pbs_cipher);

		{
			unsigned char *authloc = ikev2_authloc(md, &e_pbs);

			if (authloc == NULL)
				return STF_INTERNAL_ERROR;

			close_output_pbs(&e_pbs);

			close_output_pbs(&md->rbody);
			close_output_pbs(&reply_stream);

			ret = ikev2_encrypt_msg(md, RESPONDER,
						authstart,
						iv, encstart, authloc,
						&e_pbs, &e_pbs_cipher);
			if (ret != STF_OK)
				return ret;
		}
	}

	/* keep it for a retransmit if necessary */
	freeanychunk(st->st_tpacket);
	clonetochunk(st->st_tpacket, reply_stream.start,
		     pbs_offset(&reply_stream),
		     "reply packet for ikev2_parent_inI2outR2_tail");

	/* note: retransimission is driven by initiator */

	/* if the child failed, delete its state here - we sent the packet */
	/* PAUL */
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
stf_status ikev2parent_inR2(struct msg_digest *md)
{
	struct state *st = md->st;
	struct connection *c = st->st_connection;
	unsigned char *idhash_in;
	struct state *pst = st;

	if (st->st_clonedfrom != 0)
		pst = state_with_serialno(st->st_clonedfrom);

	/*
	 * the initiator sent us an encrypted payload. We need to calculate
	 * our g^xy, and skeyseed values, and then decrypt the payload.
	 */

	DBG(DBG_CONTROLMORE,
	    DBG_log(
		    "ikev2 parent inR2: calculating g^{xy} in order to decrypt I2"));

	/* verify that there is in fact an encrypted payload */
	if (!md->chain[ISAKMP_NEXT_v2E]) {
		libreswan_log("R2 state should receive an encrypted payload");
		return STF_FATAL;
	}

	/* decrypt things. */
	{
		stf_status ret;
		ret = ikev2_decrypt_msg(md, INITIATOR);
		if (ret != STF_OK)
			return ret;
	}

	if (!ikev2_decode_peer_id(md, INITIATOR))
		return STF_FAIL + v2N_AUTHENTICATION_FAILED;

	{
		struct hmac_ctx id_ctx;
		const pb_stream *id_pbs = &md->chain[ISAKMP_NEXT_v2IDr]->pbs;
		unsigned char *idstart = id_pbs->start + 4;
		unsigned int idlen  = pbs_room(id_pbs) - 4;

		hmac_init_chunk(&id_ctx, pst->st_oakley.prf_hasher,
				pst->st_skey_pr);

		/* calculate hash of IDr for AUTH below */
		DBG(DBG_CRYPT,
		    DBG_dump_chunk("idhash verify pr", pst->st_skey_pr));
		DBG(DBG_CRYPT, DBG_dump("idhash auth R2", idstart, idlen));
		hmac_update(&id_ctx, idstart, idlen);
		idhash_in = alloca(pst->st_oakley.prf_hasher->hash_digest_len);
		hmac_final(idhash_in, &id_ctx);
	}

	if (md->chain[ISAKMP_NEXT_v2CERT]) {
		/* should we check if we should accept a cert payload ?
		 *  has_preloaded_public_key(st)
		 */
		/* in v1 code it is  decode_cert(struct msg_digest *md) */
		DBG(DBG_CONTROLMORE,
		    DBG_log("has a v2_CERT payload going to decode it"));
		ikev2_decode_cert(md);
	}

	/* process AUTH payload */
	if (!md->chain[ISAKMP_NEXT_v2AUTH]) {
		libreswan_log("no authentication payload found");
		return STF_FAIL;
	}

	/* now check signature from RSA key */
	switch (md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2a.isaa_type) {
	case v2_AUTH_RSA:
	{
		stf_status authstat = ikev2_verify_rsa_sha1(pst,
							    INITIATOR,
							    idhash_in,
							    NULL,       /* keys from DNS */
							    NULL,       /* gateways from DNS */
							    &md->chain[
								    ISAKMP_NEXT_v2AUTH]->pbs);
		if (authstat != STF_OK) {
			libreswan_log("authentication failed");
			SEND_NOTIFICATION(v2N_AUTHENTICATION_FAILED);
			return STF_FAIL;
		}
		break;
	}
	case v2_AUTH_SHARED:
	{
		stf_status authstat = ikev2_verify_psk_auth(pst,
							    INITIATOR,
							    idhash_in,
							    &md->chain[
								    ISAKMP_NEXT_v2AUTH]->pbs);
		if (authstat != STF_OK) {
			libreswan_log("PSK authentication failed");
			SEND_NOTIFICATION(v2N_AUTHENTICATION_FAILED);
			return STF_FAIL;
		}
		break;
	}

	default:
		libreswan_log("authentication method: %s not supported",
			      enum_name(&ikev2_auth_names,
					md->chain[ISAKMP_NEXT_v2AUTH]->payload.
					v2a.isaa_type));
		return STF_FAIL;
	}

	/*
	 * update the parent state to make sure that it knows we have
	 * authenticated properly.
	 */
	change_state(pst, STATE_PARENT_I3);
	c->newest_isakmp_sa = pst->st_serialno;

	/* authentication good, see if there is a child SA available */
	if (md->chain[ISAKMP_NEXT_v2SA] == NULL ||
	    md->chain[ISAKMP_NEXT_v2TSi] == NULL ||
	    md->chain[ISAKMP_NEXT_v2TSr] == NULL) {
		/* not really anything to here... but it would be worth unpending again */
		DBG(DBG_CONTROLMORE,
		    DBG_log(
			    "no v2SA, v2TSi or v2TSr received, not attempting to setup child SA"));
		DBG(DBG_CONTROLMORE,
		    DBG_log("  Should we check for some notify?"));
		/*
		 * Delete previous retransmission event.
		 */
		delete_event(st);
		return STF_OK;
	}

	{
		int bestfit_n, bestfit_p, bestfit_pr;
		unsigned int best_tsi_i,  best_tsr_i;
		bestfit_n = -1;
		bestfit_p = -1;
		bestfit_pr = -1;

		/* Check TSi/TSr http://tools.ietf.org/html/rfc5996#section-2.9 */
		DBG(DBG_CONTROLMORE,
		    DBG_log(" check narrowing - we are responding to I2"));

		struct payload_digest *const tsi_pd =
			md->chain[ISAKMP_NEXT_v2TSi];
		struct payload_digest *const tsr_pd =
			md->chain[ISAKMP_NEXT_v2TSr];
		struct traffic_selector tsi[16], tsr[16];
#if 0
		bool instantiate = FALSE;
		ip_subnet tsi_subnet, tsr_subnet;
		const char *oops;
#endif

		unsigned int tsi_n, tsr_n;
		tsi_n = ikev2_parse_ts(tsi_pd, tsi, 16);
		tsr_n = ikev2_parse_ts(tsr_pd, tsr, 16);

		DBG_log(
			"Checking TSi(%d)/TSr(%d) selectors, looking for exact match", tsi_n,
			tsr_n);
		{
			struct spd_route *sra;
			sra = &c->spd;
			int bfit_n = ikev2_evaluate_connection_fit(c, sra,
								   INITIATOR,
								   tsi, tsr,
								   tsi_n,
								   tsr_n);
			if (bfit_n > bestfit_n) {
				DBG(DBG_CONTROLMORE,
				    DBG_log(
					    "bfit_n=ikev2_evaluate_connection_fit found better fit c %s",
					    c->name));
				int bfit_p =
					ikev2_evaluate_connection_port_fit(c,
									   sra,
									   INITIATOR,
									   tsi, tsr,
									   tsi_n, tsr_n, &best_tsi_i,
									   &best_tsr_i);
				if (bfit_p > bestfit_p) {
					DBG(DBG_CONTROLMORE,
					    DBG_log(
						    "ikev2_evaluate_connection_port_fit found better fit c %s, tsi[%d],tsr[%d]",
						    c->name,
						    best_tsi_i, best_tsr_i));
					int bfit_pr =
						ikev2_evaluate_connection_protocol_fit(
							c, sra, INITIATOR, tsi,
							tsr,
							tsi_n, tsr_n,
							&best_tsi_i,
							&best_tsr_i);
					if (bfit_pr > bestfit_pr ) {
						DBG(DBG_CONTROLMORE,
						    DBG_log(
							    "ikev2_evaluate_connection_protocol_fit found better fit c %s, tsi[%d],tsr[%d]",
							    c
							    ->name, best_tsi_i,
							    best_tsr_i));
						bestfit_p = bfit_p;
						bestfit_n = bfit_n;
					} else {
						DBG(DBG_CONTROLMORE,
						    DBG_log(
							    "protocol range fit c %s c->name was rejected by protocol matching",
							    c
							    ->name));
					}
				}
			} else {
				DBG(DBG_CONTROLMORE,
				    DBG_log(
					    "prefix range fit c %s c->name was rejected by port matching",
					    c->name));
			}
		}

		if ( ( bestfit_n > 0 )  && (bestfit_p > 0)) {
			DBG(DBG_CONTROLMORE,
			    DBG_log(
				    (
					    "found an acceptable TSi/TSr Traffic Selector")));
			memcpy(&st->st_ts_this, &tsi[best_tsi_i],
			       sizeof(struct traffic_selector));
			memcpy(&st->st_ts_that, &tsr[best_tsr_i],
			       sizeof(struct traffic_selector));
			ikev2_print_ts(&st->st_ts_this);
			ikev2_print_ts(&st->st_ts_that);

			ip_subnet tmp_subnet_i;
			ip_subnet tmp_subnet_r;
			rangetosubnet(&st->st_ts_this.low,
				      &st->st_ts_this.high, &tmp_subnet_i);
			rangetosubnet(&st->st_ts_that.low,
				      &st->st_ts_that.high, &tmp_subnet_r);

			c->spd.this.client = tmp_subnet_i;
			c->spd.this.port  = st->st_ts_this.startport;
			c->spd.this.protocol  = st->st_ts_this.ipprotoid;
			setportof(htons(
					  c->spd.this.port),
				  &c->spd.this.host_addr);
			setportof(htons(
					  c->spd.this.port),
				  &c->spd.this.client.addr);

			if ( subnetishost(&c->spd.this.client) &&
			     addrinsubnet(&c->spd.this.host_addr,
					  &c->spd.this.client))
				c->spd.this.has_client = FALSE;
			else
				c->spd.this.has_client = TRUE;

			c->spd.that.client = tmp_subnet_r;
			c->spd.that.port = st->st_ts_that.startport;
			c->spd.that.protocol = st->st_ts_that.ipprotoid;
			setportof(htons(
					  c->spd.that.port),
				  &c->spd.that.host_addr);
			setportof(htons(
					  c->spd.that.port),
				  &c->spd.that.client.addr);

			if ( subnetishost(&c->spd.that.client) &&
			     addrinsubnet(&c->spd.that.host_addr,
					  &c->spd.that.client))
				c->spd.that.has_client = FALSE;
			else
				c->spd.that.has_client = TRUE;
			/* AAAA */
		} else {
			DBG(DBG_CONTROLMORE,
			    DBG_log((
					    "reject responder TSi/TSr Traffic Selector")));
			/* prevents parent from going to I3 */
			return STF_FAIL + v2N_TS_UNACCEPTABLE;
		}
	} /* end of TS check block */

	{
		v2_notification_t rn;
		struct payload_digest *const sa_pd =
			md->chain[ISAKMP_NEXT_v2SA];

		rn = ikev2_parse_child_sa_body(&sa_pd->pbs,
					       &sa_pd->payload.v2sa,
					       NULL, st, FALSE);

		if (rn != v2N_NOTHING_WRONG)
			return STF_FAIL + rn;
	}

	{
		struct payload_digest *p;

		for (p = md->chain[ISAKMP_NEXT_v2N]; p != NULL; p = p->next) {
			/* RFC 5996 */
			/*Types in the range 0 - 16383 are intended for reporting errors.  An
			 * implementation receiving a Notify payload with one of these types
			 * that it does not recognize in a response MUST assume that the
			 * corresponding request has failed entirely.  Unrecognized error types
			 * in a request and status types in a request or response MUST be
			 * ignored, and they should be logged.*/

			if (enum_name(&ikev2_notify_names,
				      p->payload.v2n.isan_type) == NULL) {
				if (p->payload.v2n.isan_type <
				    v2N_INITIAL_CONTACT)
					return STF_FAIL +
					       p->payload.v2n.isan_type;
			}

			if ( p->payload.v2n.isan_type ==
			     v2N_USE_TRANSPORT_MODE ) {
				if ( st->st_connection->policy &
				     POLICY_TUNNEL) {
					/*This means we did not send v2N_USE_TRANSPORT, however responder is sending it in now (inR2), seems incorrect*/
					DBG(DBG_CONTROLMORE,
					    DBG_log(
						    "Initiator policy is tunnel, responder sends v2N_USE_TRANSPORT_MODE notification in inR2, ignoring it"));
				} else {
					DBG(DBG_CONTROLMORE,
					    DBG_log(
						    "Initiator policy is transport, responder sends v2N_USE_TRANSPORT_MODE, setting CHILD SA to transport mode"));
					if (st->st_esp.present == TRUE) {
						/*libreswan supports only "esp" with ikev2 it seems, look at ikev2_parse_child_sa_body handling*/
						st->st_esp.attrs.encapsulation
							=
								ENCAPSULATION_MODE_TRANSPORT;
					}
				}
			}
		}       /* for */

	}               /* notification block */

	ikev2_derive_child_keys(st, md->role);

	c->newest_ipsec_sa = st->st_serialno;

	/* now install child SAs */
	if (!install_ipsec_sa(st, TRUE))
		return STF_FATAL;

	/*
	 * Delete previous retransmission event.
	 */
	delete_event(st);

	return STF_OK;
}

/*
 * Cookie = <VersionIDofSecret> | Hash(Ni | IPi | SPIi | <secret>)
 * where <secret> is a randomly generated secret known only to the
 * in LSW implementation <VersionIDofSecret> is not used.
 */
static bool ikev2_get_dcookie(u_char *dcookie,  chunk_t st_ni,
			      ip_address *addr, u_int8_t *spiI)
{
	size_t addr_length;
	SHA1_CTX ctx_sha1;
	unsigned char addr_buff[
		sizeof(union { struct in_addr A;
			       struct in6_addr B;
		       })];

	addr_length = addrbytesof(addr, addr_buff, sizeof(addr_buff));
	SHA1Init(&ctx_sha1);
	SHA1Update(&ctx_sha1, st_ni.ptr, st_ni.len);
	SHA1Update(&ctx_sha1, addr_buff, addr_length);
	SHA1Update(&ctx_sha1, spiI, sizeof(*spiI));
	SHA1Update(&ctx_sha1, ikev2_secret_of_the_day,
		   SHA1_DIGEST_SIZE);
	SHA1Final(dcookie, &ctx_sha1);
	DBG(DBG_PRIVATE,
	    DBG_log("ikev2 secret_of_the_day used %s, length %d",
		    ikev2_secret_of_the_day,
		    SHA1_DIGEST_SIZE);
	    );

	DBG(DBG_CRYPT,
	    DBG_dump("computed dcookie: HASH(Ni | IPi | SPIi | <secret>)",
		     dcookie, SHA1_DIGEST_SIZE));
#if 0
	ikev2_secrets_recycle++;
	if (ikev2_secrets_recycle >= 32768) {
		/* handed out too many cookies, cycle secrets */
		ikev2_secrets_recycle = 0;
		/* can we call init_secrets() without adding an EVENT? */
		init_secrets();
	}
#endif
	return TRUE;
}

/*
 *
 ***************************************************************
 *                       NOTIFICATION_OUT Complete packet  *****
 ***************************************************************
 *
 */

void send_v2_notification(struct state *p1st, u_int16_t type,
			  struct state *encst,
			  u_char *icookie,
			  u_char *rcookie,
			  chunk_t *n_data)
{
	u_char buffer[1024];
	pb_stream reply;
	pb_stream rbody;
	chunk_t child_spi, notify_data;

	/* this function is not generic enough yet just enough for 6msg
	 * TBD accept HDR FLAGS as arg. default ISAKMP_FLAGS_R
	 * TBD when there is a child SA use that SPI in the notify paylod.
	 * TBD support encrypted notifications payloads.
	 * TBD accept Critical bit as an argument. default is set.
	 * TBD accept exchange type as an arg, default is ISAKMP_v2_SA_INIT
	 * do we need to send a notify with empty data?
	 * do we need to support more Protocol ID? more than PROTO_ISAKMP
	 */

	libreswan_log("sending %s notification %s to %s:%u",
		      encst ? "encrypted " : "",
		      enum_name(&ikev2_notify_names, type),
		      ip_str(&p1st->st_remoteaddr),
		      p1st->st_remoteport);
#if 0
/* Empty notification data section should be fine? */
	if (n_data == NULL) {
		DBG(DBG_CONTROLMORE,
		    DBG_log("don't send packet when notification data empty"));
		return;
	}
#endif

	memset(buffer, 0, sizeof(buffer));
	init_pbs(&reply, buffer, sizeof(buffer), "notification msg");

	/* HDR out */
	{
		struct isakmp_hdr n_hdr;
		zero(&n_hdr);                           /* default to 0 */  /* AAA should we copy from MD? */
		/* Impair function will raise major/minor by 1 for testing */
		n_hdr.isa_version = build_ike_version();
		memcpy(n_hdr.isa_rcookie, rcookie, COOKIE_SIZE);
		memcpy(n_hdr.isa_icookie, icookie, COOKIE_SIZE);
		n_hdr.isa_xchg = ISAKMP_v2_SA_INIT;
		n_hdr.isa_np = ISAKMP_NEXT_v2N;
		n_hdr.isa_flags &= ~ISAKMP_FLAGS_I;
		n_hdr.isa_flags  |=  ISAKMP_FLAGS_R;
#warning check msgid code here
		/* PAUL: shouldn't we set n_hdr.isa_msgid = [htonl](p1st->st_msgid); */
		if (!out_struct(&n_hdr, &isakmp_hdr_desc, &reply, &rbody)) {
			libreswan_log(
				"error initializing hdr for notify message");
			return;
		}

	}
	child_spi.ptr = NULL;
	child_spi.len = 0;

	/* build and add v2N payload to the packet */
	memset(&child_spi, 0, sizeof(child_spi));
	memset(&notify_data, 0, sizeof(notify_data));
	ship_v2N(ISAKMP_NEXT_v2NONE, DBGP(
			 IMPAIR_SEND_BOGUS_ISAKMP_FLAG) ?
		 (ISAKMP_PAYLOAD_NONCRITICAL | ISAKMP_PAYLOAD_LIBRESWAN_BOGUS) :
		 ISAKMP_PAYLOAD_NONCRITICAL, PROTO_ISAKMP,
		 &child_spi,
		 type, n_data, &rbody);

	close_message(&rbody, p1st);
	close_output_pbs(&reply);

	clonetochunk(p1st->st_tpacket, reply.start, pbs_offset(&reply),
		     "notification packet");

	send_ike_msg(p1st, __FUNCTION__);
}
/* add notify payload to the rbody */
bool ship_v2N(unsigned int np, u_int8_t critical,
	      u_int8_t protoid, chunk_t *spi,
	      u_int16_t type, chunk_t *n_data, pb_stream *rbody)
{
	struct ikev2_notify n;
	pb_stream n_pbs;

	DBG(DBG_CONTROLMORE,
	    DBG_log("Adding a v2N Payload"));
	n.isan_np =  np;
	n.isan_critical = critical;
	if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
		libreswan_log(
			" setting bogus ISAKMP_PAYLOAD_LIBRESWAN_BOGUS flag in ISAKMP payload");
		n.isan_critical |= ISAKMP_PAYLOAD_LIBRESWAN_BOGUS;
	}

	n.isan_protoid =  protoid;
	n.isan_spisize = spi->len;
	n.isan_type = type;

	if (!out_struct(&n, &ikev2_notify_desc, rbody, &n_pbs)) {
		libreswan_log(
			"error initializing notify payload for notify message");
		return FALSE;
	}

	if (spi->len > 0) {
		if (!out_raw(spi->ptr, spi->len, &n_pbs, "SPI ")) {
			libreswan_log("error writing SPI to notify payload");
			return FALSE;
		}
	}
	if (n_data != NULL) {
		if (!out_raw(n_data->ptr, n_data->len, &n_pbs,
			     "Notify data")) {
			libreswan_log(
				"error writing notify payload for notify message");
			return FALSE;
		}
	}

	close_output_pbs(&n_pbs);
	return TRUE;
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
stf_status process_informational_ikev2(struct msg_digest *md)
{
	/* verify that there is in fact an encrypted payload */
	if (!md->chain[ISAKMP_NEXT_v2E]) {
		libreswan_log(
			"Ignoring informational exchange outside encrypted payload (rfc5996 section 1.4)");
		return STF_IGNORE;
	}

	/* decrypt things. */
	{
		stf_status ret;

		if (md->hdr.isa_flags & ISAKMP_FLAGS_I) {
			DBG(DBG_CONTROLMORE,
			    DBG_log(
				    "received informational exchange request from INITIATOR"));
			ret = ikev2_decrypt_msg(md, RESPONDER);
		} else {
			DBG(DBG_CONTROLMORE,
			    DBG_log(
				    "received informational exchange request from RESPONDER"));
			ret = ikev2_decrypt_msg(md, INITIATOR);
		}

		if (ret != STF_OK)
			return ret;
	}

	{
		struct payload_digest *p;
		struct ikev2_delete *v2del = NULL;
		stf_status ret;
		struct state *const st = md->st;

		/* Only send response if it is request*/
		if (!(md->hdr.isa_flags & ISAKMP_FLAGS_R)) {
			unsigned char *authstart;
			pb_stream e_pbs, e_pbs_cipher;
			struct ikev2_generic e;
			unsigned char *iv;
			int ivsize;
			unsigned char *encstart;

			/* beginning of data going out */
			authstart = reply_stream.cur;

			/* make sure HDR is at start of a clean buffer */
			zero(reply_buffer);
			init_pbs(&reply_stream, reply_buffer,
				 sizeof(reply_buffer),
				 "information exchange reply packet");

			DBG(DBG_CONTROLMORE | DBG_DPD,
			    DBG_log("Received an INFORMATIONAL request, "
				    "updating liveness, no longer pending"));
			st->st_last_liveness = now();
			st->st_pend_liveness = FALSE;

			/* HDR out */
			{
				struct isakmp_hdr r_hdr;
				zero(&r_hdr); /* default to 0 */  /* AAA should we copy from MD? */
				r_hdr.isa_version = build_ike_version();
				memcpy(r_hdr.isa_rcookie, st->st_rcookie,
				       COOKIE_SIZE);
				memcpy(r_hdr.isa_icookie, st->st_icookie,
				       COOKIE_SIZE);
				r_hdr.isa_xchg = ISAKMP_v2_INFORMATIONAL;
				r_hdr.isa_np = ISAKMP_NEXT_v2E;
				r_hdr.isa_msgid = htonl(md->msgid_received);

				/*set initiator bit if we are initiator*/
				if (md->role == INITIATOR)
					r_hdr.isa_flags |= ISAKMP_FLAGS_I;

				r_hdr.isa_flags  |=  ISAKMP_FLAGS_R;

				if (!out_struct(&r_hdr, &isakmp_hdr_desc,
						&reply_stream, &md->rbody)) {
					libreswan_log(
						"error initializing hdr for informational message");
					return STF_INTERNAL_ERROR;
				}

			} /*HDR Done*/

			/* insert an Encryption payload header */
			if (md->chain[ISAKMP_NEXT_v2D]) {
				bool ikesa_flag = FALSE;
				/* Search if there is a IKE SA delete payload*/
				for (p = md->chain[ISAKMP_NEXT_v2D]; p != NULL;
				     p = p->next) {
					if (p->payload.v2delete.isad_protoid ==
					    PROTO_ISAKMP) {
						e.isag_np = ISAKMP_NEXT_v2NONE;
						ikesa_flag = TRUE;
						break;
					}
				}
				/* if there is no IKE SA DELETE PAYLOAD*/
				/* That means, there are AH OR ESP*/
				if (!ikesa_flag)
					e.isag_np = ISAKMP_NEXT_v2D;

			} else {
				e.isag_np = ISAKMP_NEXT_v2NONE;
			}

			e.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;

			if (!out_struct(&e, &ikev2_e_desc, &md->rbody, &e_pbs))
				return STF_INTERNAL_ERROR;

			/* insert IV */
			iv     = e_pbs.cur;
			ivsize = st->st_oakley.encrypter->iv_size;
			if (!out_zero(ivsize, &e_pbs, "iv"))
				return STF_INTERNAL_ERROR;

			get_rnd_bytes(iv, ivsize);

			/* note where cleartext starts */
			init_pbs(&e_pbs_cipher, e_pbs.cur,
				 e_pbs.roof - e_pbs.cur, "cleartext");
			e_pbs_cipher.container = &e_pbs;
			e_pbs_cipher.desc = NULL;
			e_pbs_cipher.cur = e_pbs.cur;
			encstart = e_pbs_cipher.cur;

			if (md->chain[ISAKMP_NEXT_v2D]) {

				for (p = md->chain[ISAKMP_NEXT_v2D]; p != NULL;
				     p = p->next) {
					v2del = &p->payload.v2delete;

					switch (v2del->isad_protoid) {
					case PROTO_ISAKMP:
						/* My understanding is that delete payload for IKE SA
						 *  should be the only payload in the informational exchange
						 */
						break;

					case PROTO_IPSEC_AH:
					case PROTO_IPSEC_ESP:
					{
						char spi_buf[1024];
						pb_stream del_pbs;
						struct ikev2_delete v2del_tmp;
						u_int16_t i, j = 0;
						u_char *spi;

						for (i = 0;
						     i < v2del->isad_nrspi;
						     i++ ) {
							spi = p->pbs.cur +
							      (i *
							       v2del->
							       isad_spisize);
							DBG(DBG_CONTROLMORE, DBG_log(
								    "received delete request for %s SA(0x%08lx)",
								    enum_show(
									    &
									    protocol_names,
									    v2del
									    ->
									    isad_protoid),
								    (
									    unsigned
									    long)
								    ntohl((
										  unsigned
										  long)
									  *(
										  ipsec_spi_t
										  *)
									  spi)));

							struct state *dst =
								find_state_ikev2_child_to_delete(
									st->st_icookie,
									st->st_rcookie,
									v2del->isad_protoid,
									*(
										ipsec_spi_t
										*)spi);

							if (dst != NULL) {
								struct
								ipsec_proto_info
								*pr =
									v2del->
									isad_protoid
									==
									PROTO_IPSEC_AH
									?
									&dst
									->st_ah
									:
									&dst
									->
									st_esp;
								DBG(
									DBG_CONTROLMORE,
									DBG_log(
										"our side spi that needs to be sent: %s SA(0x%08lx)",
										enum_show(
											&
											protocol_names,
											v2del
											->
											isad_protoid),
										(
											unsigned
											long)
										ntohl(
											pr
											->
											our_spi)));

								memcpy(
									spi_buf +
									(j *
									 v2del
									 ->
									 isad_spisize),
									(u_char
									 *)&pr->our_spi,
									v2del->isad_spisize);
								j++;
							} else {
								DBG(
									DBG_CONTROLMORE,
									DBG_log(
										"received delete request for %s SA(0x%08lx) but local state is not found",
										enum_show(
											&
											protocol_names,
											v2del
											->
											isad_protoid),
										(
											unsigned
											long)
										ntohl((
											      unsigned
											      long)
										      *(
											      ipsec_spi_t
											      *)
										      spi)));
							}
						}

						if ( !j ) {
							DBG(DBG_CONTROLMORE, DBG_log(
								    "This delete payload does not contain a single spi that has any local state, ignoring"));
							return STF_IGNORE;
						} else {
							DBG(DBG_CONTROLMORE, DBG_log(
								    "No. of SPIs to be sent %d",
								    j);
							    DBG_dump(
								    " Emit SPIs",
								    spi_buf,
								    j *
								    v2del->
								    isad_spisize));
						}

						zero(&v2del_tmp);

						if (p->next != NULL)
							v2del_tmp.isad_np =
								ISAKMP_NEXT_v2D;


						else
							v2del_tmp.isad_np =
								ISAKMP_NEXT_v2NONE;


						v2del_tmp.isad_protoid =
							v2del->isad_protoid;
						v2del_tmp.isad_spisize =
							v2del->isad_spisize;
						v2del_tmp.isad_nrspi = j;

						/* Emit delete payload header out*/
						if (!out_struct(&v2del_tmp,
								&
								ikev2_delete_desc,
								&e_pbs_cipher,
								&del_pbs)) {
							libreswan_log(
								"error initializing hdr for delete payload");
							return
								STF_INTERNAL_ERROR;
						}

						/* Emit values of spi to be sent to the peer*/
						if (!out_raw(spi_buf, j *
							     v2del->
							     isad_spisize,
							     &del_pbs,
							     "local spis")) {
							libreswan_log(
								"error sending spi values in delete payload");
							return
								STF_INTERNAL_ERROR;
						}

						close_output_pbs(&del_pbs);

					}
					break;
					default:
						/*Unrecongnized protocol */
						return STF_IGNORE;
					}

					/* this will break from for loop*/
					if (v2del->isad_protoid ==
					    PROTO_ISAKMP)
						break;

				}
			}

			/*If there are no payloads or in other words empty payload in request
			 * that means it is check for liveliness, so send an empty payload message
			 * this will end up sending an empty payload
			 */

			ikev2_padup_pre_encrypt(md, &e_pbs_cipher);
			close_output_pbs(&e_pbs_cipher);

			{
				unsigned char *authloc = ikev2_authloc(md,
								       &e_pbs);
				if (authloc == NULL)
					return STF_INTERNAL_ERROR;

				close_output_pbs(&e_pbs);
				close_output_pbs(&md->rbody);
				close_output_pbs(&reply_stream);

				ret = ikev2_encrypt_msg(md, md->role,
							authstart,
							iv, encstart, authloc,
							&e_pbs, &e_pbs_cipher);
				if (ret != STF_OK)
					return ret;
			}


			/* keep it for a retransmit if necessary */
			freeanychunk(st->st_tpacket);
			clonetochunk(st->st_tpacket, reply_stream.start, pbs_offset(
					     &reply_stream),
				     "reply packet for informational exchange");

			send_ike_msg(st, __FUNCTION__);
		}

		/* Now carry out the actualy task, we can not carry the actual task since
		 * we need to send informational responde using existig SAs
		 */

		{
			if (md->chain[ISAKMP_NEXT_v2D] && st->st_state !=
			    STATE_IKESA_DEL) {

				for (p = md->chain[ISAKMP_NEXT_v2D]; p != NULL;
				     p = p->next) {
					v2del = &p->payload.v2delete;

					switch (v2del->isad_protoid) {
					case PROTO_ISAKMP:
					{
						/* My understanding is that delete payload for IKE SA
						 *  should be the only payload in the informational
						 * Now delete the IKE SA state and all its child states
						 */
						struct state *current_st = st;
						struct state *next_st = NULL;
						struct state *first_st = NULL;

						/* Find the first state in the hash chain*/
						while (current_st !=
						       (struct state *) NULL) {
							first_st = current_st;
							current_st =
								first_st->
								st_hashchain_prev;
						}

						current_st = first_st;
						while (current_st !=
						       (struct state *) NULL) {
							next_st =
								current_st->
								st_hashchain_next;
							if (current_st->
							    st_clonedfrom !=
							    0 ) {
								change_state(
									current_st,
									STATE_CHILDSA_DEL);
							} else {
								change_state(
									current_st,
									STATE_IKESA_DEL);
							}
							delete_state(current_st);
							current_st = next_st;
						}
					}
					break;

					case PROTO_IPSEC_AH:
					case PROTO_IPSEC_ESP:
					{
						/* pb_stream del_pbs; */
						struct ikev2_delete;
						u_int16_t i;
						u_char *spi;

						for (i = 0;
						     i < v2del->isad_nrspi;
						     i++ ) {
							spi = p->pbs.cur +
							      (i *
							       v2del->
							       isad_spisize);
							DBG(DBG_CONTROLMORE, DBG_log(
								    "Now doing actual deletion for request: %s SA(0x%08lx)",
								    enum_show(
									    &
									    protocol_names,
									    v2del
									    ->
									    isad_protoid),
								    (
									    unsigned
									    long)
								    ntohl((
										  unsigned
										  long)
									  *(
										  ipsec_spi_t
										  *)
									  spi)));

							struct state *dst =
								find_state_ikev2_child_to_delete(
									st->st_icookie,
									st->st_rcookie,
									v2del->isad_protoid,
									*(
										ipsec_spi_t
										*)spi);

							if (dst != NULL) {
								struct
								ipsec_proto_info
								*pr =
									v2del->
									isad_protoid
									==
									PROTO_IPSEC_AH
									?
									&dst
									->st_ah
									:
									&dst
									->
									st_esp;
								DBG(
									DBG_CONTROLMORE,
									DBG_log(
										"our side spi that needs to be deleted: %s SA(0x%08lx)",
										enum_show(
											&
											protocol_names,
											v2del
											->
											isad_protoid),
										(
											unsigned
											long)
										ntohl(
											pr
											->
											our_spi)));

								/* now delete the state*/
								change_state(
									dst,
									STATE_CHILDSA_DEL);
								delete_state(
									dst);
							} else {
								DBG(
									DBG_CONTROLMORE,
									DBG_log(
										"received delete request for %s SA(0x%08lx) but local state is not found",
										enum_show(
											&
											protocol_names,
											v2del
											->
											isad_protoid),
										(
											unsigned
											long)
										ntohl((
											      unsigned
											      long)
										      *(
											      ipsec_spi_t
											      *)
										      spi)));
							}
						}
					}
					break;

					default:
						/*Unrecongnized protocol */
						return STF_IGNORE;
					}

					/* this will break from for loop*/
					if (v2del->isad_protoid ==
					    PROTO_ISAKMP)
						break;

				}       /* for */

			}               /* if*/
			else {
				/* empty response to our IKESA delete request*/
				if ((md->hdr.isa_flags & ISAKMP_FLAGS_R) &&
				    st->st_state == STATE_IKESA_DEL) {
					/* My understanding is that delete payload for IKE SA
					 *  should be the only payload in the informational
					 * Now delete the IKE SA state and all its child states
					 */
					struct state *current_st = st;
					struct state *next_st = NULL;
					struct state *first_st = NULL;

					/* Find the first state in the hash chain*/
					while (current_st !=
					       (struct state *) NULL) {
						first_st = current_st;
						current_st =
							first_st->
							st_hashchain_prev;
					}

					current_st = first_st;
					while (current_st !=
					       (struct state *) NULL) {
						next_st =
							current_st->
							st_hashchain_next;
						if (current_st->st_clonedfrom
						    !=
						    0 ) {
							change_state(
								current_st,
								STATE_CHILDSA_DEL);
						} else {
							change_state(
								current_st,
								STATE_IKESA_DEL);
						}
						delete_state(current_st);
						current_st = next_st;
					}
					/* empty response to our empty INFORMATIONAL
					 * We don't send anything back */
				} else if ((md->hdr.isa_flags &
					    ISAKMP_FLAGS_R) &&
					   st->st_state != STATE_IKESA_DEL) {
					DBG(DBG_CONTROLMORE,
					    DBG_log(
						    "Received an INFORMATIONAL response, "
						    "updating liveness, no longer pending."));
					st->st_last_liveness = now();
					st->st_pend_liveness = FALSE;
					st->st_msgid_lastrecv =
						md->msgid_received;
				}
			}
		}

	}

	return STF_OK;
}

stf_status ikev2_send_informational(struct state *st)
{
	struct state *pst = NULL;

	if (st->st_clonedfrom != SOS_NOBODY) {
		pst = state_with_serialno(st->st_clonedfrom);
		if (!pst) {
			DBG(DBG_CONTROL,
			    DBG_log(
				    "IKE SA does not exist for this child SA - should not happen"));
			DBG(DBG_CONTROL,
			    DBG_log("INFORMATIONAL exchange can not be sent"));
			return STF_IGNORE;
		}
	} else {
		pst = st;
	}

	{
		unsigned char *authstart;
		unsigned char *encstart;
		unsigned char *iv;
		int ivsize;
		struct msg_digest md;
		struct ikev2_generic e;
		enum phase1_role role;
		pb_stream e_pbs, e_pbs_cipher;
		pb_stream rbody;
		pb_stream request;
		u_char buffer[1024];

		md.st = st;
		md.pst = pst;
		memset(buffer, 0, sizeof(buffer));
		init_pbs(&request, buffer, sizeof(buffer),
			 "informational exchange request packet");
		authstart = request.cur;

		/* HDR out */
		{
			struct isakmp_hdr r_hdr;
			zero(&r_hdr);
			r_hdr.isa_version = build_ike_version();
			memcpy(r_hdr.isa_rcookie, pst->st_rcookie,
			       COOKIE_SIZE);
			memcpy(r_hdr.isa_icookie, pst->st_icookie,
			       COOKIE_SIZE);
			r_hdr.isa_xchg = ISAKMP_v2_INFORMATIONAL;
			r_hdr.isa_np = ISAKMP_NEXT_v2E;

			if (pst->st_state == STATE_PARENT_I2 ||
			    pst->st_state == STATE_PARENT_I3) {
				r_hdr.isa_flags |= ISAKMP_FLAGS_I;
				role = INITIATOR;
				r_hdr.isa_msgid = htonl(pst->st_msgid_nextuse);
			} else {
				role = RESPONDER;
				r_hdr.isa_msgid = htonl(
					pst->st_msgid_lastrecv + 1);
			}

			if (!out_struct(&r_hdr, &isakmp_hdr_desc,
					&request, &rbody)) {
				libreswan_log(
					"error initializing hdr for informational message");
				return STF_FATAL;
			}
		} /* HDR done*/

		/* insert an Encryption payload header */
		e.isag_np = ISAKMP_NEXT_v2NONE;
		e.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;
		if (!out_struct(&e, &ikev2_e_desc, &rbody, &e_pbs))
			return STF_FATAL;

		/* IV */
		iv = e_pbs.cur;
		ivsize = pst->st_oakley.encrypter->iv_size;
		if (!out_zero(ivsize, &e_pbs, "iv"))
			return STF_FATAL;

		get_rnd_bytes(iv, ivsize);

		/* note where cleartext starts */
		init_pbs(&e_pbs_cipher, e_pbs.cur, e_pbs.roof - e_pbs.cur,
			 "cleartext");
		e_pbs_cipher.container = &e_pbs;
		e_pbs_cipher.desc = NULL;
		e_pbs_cipher.cur = e_pbs.cur;
		encstart = e_pbs_cipher.cur;

		/* This is an empty informational exchange (A.K.A liveness check) */
		ikev2_padup_pre_encrypt(&md, &e_pbs_cipher);
		close_output_pbs(&e_pbs_cipher);

		{
			stf_status ret;
			unsigned char *authloc = ikev2_authloc(&md, &e_pbs);

			if (!authloc)
				return STF_FATAL;

			close_output_pbs(&e_pbs);
			close_output_pbs(&rbody);
			close_output_pbs(&request);

			ret = ikev2_encrypt_msg(&md, role,
						authstart,
						iv, encstart, authloc,
						&e_pbs, &e_pbs_cipher);
			if (ret != STF_OK)
				return STF_FATAL;
		}
		/* keep it for a retransmit if necessary */
		freeanychunk(pst->st_tpacket);
		clonetochunk(pst->st_tpacket, request.start,
			     pbs_offset(&request),
			     "reply packet for informational exchange");
		pst->st_pend_liveness = TRUE; /* we should only do this when dpd/liveness is active? */
		send_ike_msg(pst, __FUNCTION__);
		ikev2_update_counters(&md);

	}

	return STF_OK;
}
/*
 *
 ***************************************************************
 *                       DELETE_OUT                        *****
 ***************************************************************
 *
 */
void ikev2_delete_out(struct state *st)
{
	struct state *pst = NULL;

	if (st->st_clonedfrom != 0) {
		/*child SA*/
		pst = state_with_serialno(st->st_clonedfrom);

		if (!pst) {
			DBG(DBG_CONTROL,
			    DBG_log("IKE SA does not exist for this child SA"));
			DBG(DBG_CONTROL,
			    DBG_log(
				    "INFORMATIONAL exchange can not be sent, deleting state"));
			goto end;
		}
	} else {
		/* Parent SA*/
		pst = st;

	}

	{
		unsigned char *authstart;
		pb_stream e_pbs, e_pbs_cipher;
		pb_stream rbody;
		struct ikev2_generic e;
		unsigned char *iv;
		int ivsize;
		unsigned char *encstart;
		struct msg_digest md;
		enum phase1_role role;

		md.st = st;
		md.pst = pst;
		/* beginning of data going out */
		authstart = reply_stream.cur;

		/* make sure HDR is at start of a clean buffer */
		zero(reply_buffer);
		init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
			 "information exchange request packet");

		/* HDR out */
		{
			struct isakmp_hdr r_hdr;
			zero(&r_hdr); /* default to 0 */  /* AAA should we copy from MD? */
			r_hdr.isa_version = build_ike_version();
			memcpy(r_hdr.isa_rcookie, pst->st_rcookie,
			       COOKIE_SIZE);
			memcpy(r_hdr.isa_icookie, pst->st_icookie,
			       COOKIE_SIZE);
			r_hdr.isa_xchg = ISAKMP_v2_INFORMATIONAL;
			r_hdr.isa_np = ISAKMP_NEXT_v2E;
			r_hdr.isa_msgid = htonl(pst->st_msgid_nextuse);

			/*set initiator bit if we are initiator*/
			if (pst->st_state == STATE_PARENT_I2 ||
			    pst->st_state == STATE_PARENT_I3) {
				r_hdr.isa_flags |= ISAKMP_FLAGS_I;
				role = INITIATOR;
			} else {
				role = RESPONDER;
			}

			/* r_hdr.isa_flags  |=  ISAKMP_FLAGS_R; */

			if (!out_struct(&r_hdr, &isakmp_hdr_desc,
					&reply_stream, &rbody)) {
				libreswan_log(
					"error initializing hdr for informational message");
				goto end;
			}

		} /*HDR Done*/

		/* insert an Encryption payload header */
		e.isag_np = ISAKMP_NEXT_v2D;
		e.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;

		if (!out_struct(&e, &ikev2_e_desc, &rbody, &e_pbs))
			goto end;

		/* insert IV */
		iv     = e_pbs.cur;
		ivsize = pst->st_oakley.encrypter->iv_size;
		if (!out_zero(ivsize, &e_pbs, "iv"))
			goto end;
		get_rnd_bytes(iv, ivsize);

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

			zero(&v2del_tmp);
			v2del_tmp.isad_np = ISAKMP_NEXT_v2NONE;

			if (st->st_clonedfrom != 0 ) {
				v2del_tmp.isad_protoid = PROTO_IPSEC_ESP;
				v2del_tmp.isad_spisize = sizeof(ipsec_spi_t);
				v2del_tmp.isad_nrspi = 1;
			} else {
				v2del_tmp.isad_protoid = PROTO_ISAKMP;
				v2del_tmp.isad_spisize = 0;
				v2del_tmp.isad_nrspi = 0;
			}

			/* Emit delete payload header out*/
			if (!out_struct(&v2del_tmp, &ikev2_delete_desc,
					&e_pbs_cipher, &del_pbs)) {
				libreswan_log(
					"error initializing hdr for delete payload");
				goto end;
			}

			/* Emit values of spi to be sent to the peer*/
			if (st->st_clonedfrom != 0) {
				if (!out_raw( (u_char *)&st->st_esp.our_spi,
					      sizeof(ipsec_spi_t), &del_pbs,
					      "local spis")) {
					libreswan_log(
						"error sending spi values in delete payload");
					goto end;
				}
			}

			close_output_pbs(&del_pbs);

		}

		ikev2_padup_pre_encrypt(&md, &e_pbs_cipher);
		close_output_pbs(&e_pbs_cipher);

		{
			stf_status ret;
			unsigned char *authloc = ikev2_authloc(&md, &e_pbs);
			if (authloc == NULL)
				goto end;
			close_output_pbs(&e_pbs);
			close_output_pbs(&rbody);
			close_output_pbs(&reply_stream);

			ret = ikev2_encrypt_msg(&md, role,
						authstart,
						iv, encstart, authloc,
						&e_pbs, &e_pbs_cipher);
			if (ret != STF_OK)
				goto end;
		}

		/* keep it for a retransmit if necessary */
		freeanychunk(pst->st_tpacket);
		clonetochunk(pst->st_tpacket, reply_stream.start,
			     pbs_offset(&reply_stream),
			     "request packet for informational exchange");

		send_ike_msg(pst, __FUNCTION__);

		/* update state */
		ikev2_update_counters(&md);

	}

	/* If everything is fine, and we sent packet, goto real_end*/
	goto real_end;

end:
	/* If some error occurs above that prevents us sending a request packet*/
	/* delete the states right now*/

	if (st->st_clonedfrom != SOS_NOBODY) {
		change_state(st, STATE_CHILDSA_DEL);
		delete_state(st);
	} else {

		struct state *current_st = pst;
		struct state *next_st = NULL;
		struct state *first_st = NULL;

		/* Find the first state in the hash chain*/
		while (current_st != (struct state *) NULL) {
			first_st = current_st;
			current_st = first_st->st_hashchain_prev;
		}

		current_st = first_st;
		while (current_st != (struct state *) NULL) {
			next_st = current_st->st_hashchain_next;
			if (current_st->st_clonedfrom != 0 )
				change_state(current_st, STATE_CHILDSA_DEL);
			else
				change_state(current_st, STATE_IKESA_DEL);
			delete_state(current_st);
			current_st = next_st;
		}
	}

real_end:;
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
static int build_ike_version()
{
return ((IKEv2_MAJOR_VERSION + (DBGP(IMPAIR_MAJOR_VERSION_BUMP) ? 1 : 0))
	<< ISA_MAJ_SHIFT) | (IKEv2_MINOR_VERSION +
	(DBGP(IMPAIR_MINOR_VERSION_BUMP) ? 1 : 0));
}
