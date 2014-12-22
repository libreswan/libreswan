/*
 * IKEv2 parent SA creation routines
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012,2014 Antony Antony <antony@phenome.org>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
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
#include "cookie.h"
#include "rnd.h"
#include "pending.h"
#include "kernel.h"
#include "nat_traversal.h"

/* Note: same definition appears in programs/pluto/ikev2.c */
#define SEND_V2_NOTIFICATION(t) { \
		if (st != NULL) \
			send_v2_notification_from_state(st, t, NULL); \
		else \
			send_v2_notification_from_md(md, t, NULL); \
	}

static crypto_req_cont_func ikev2_parent_outI1_continue;	/* type assertion */

static stf_status ikev2_parent_outI1_tail(struct pluto_crypto_req_cont *ke,
					  struct pluto_crypto_req *r);

static bool ikev2_get_dcookie(u_char *dcookie, chunk_t st_ni,
			      ip_address *addr, chunk_t spiI);

static stf_status ikev2_parent_outI1_common(struct msg_digest *md,
					    struct state *st);

static int build_ikev2_version();

static crypto_req_cont_func ikev2_child_inIoutR_continue;	/* type assertion */

static stf_status ikev2_child_inIoutR_tail(struct pluto_crypto_req_cont *qke,
					   struct pluto_crypto_req *r);

/*
 * This code assumes that the encrypted part of an IKE message starts
 * with an Initialization Vector (IV) of enc_blocksize of random octets.
 * The IV will subsequently be discarded after decryption.
 * This is true of Cipher Block Chaining mode (CBC).
 */
static bool emit_iv(const struct state *st, pb_stream *pbs)
{
	size_t ivsize = st->st_oakley.encrypter->ivsize;
	unsigned char ivbuf[MAX_CBC_BLOCK_SIZE];

	passert(ivsize <= MAX_CBC_BLOCK_SIZE);
	get_rnd_bytes(ivbuf, ivsize);
	return out_raw(ivbuf, ivsize, pbs, "IV");
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
			     , const struct xfrm_user_sec_ctx_ike *uctx
#endif
			     )
{
	struct state *st = new_state();

	/* set up new state */
	get_cookie(TRUE, st->st_icookie, COOKIE_SIZE, &c->spd.that.host_addr);
	initialize_new_state(st, c, policy, try, whack_sock, importance);
	st->st_ikev2 = TRUE;
	change_state(st, STATE_PARENT_I1);
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
		libreswan_log("initiating v2 parent SA to replace #%lu",
				predecessor->st_serialno);
		update_pending(predecessor, st);
		whack_log(RC_NEW_STATE + STATE_PARENT_I1,
			  "%s: initiate, replacing #%lu",
			  enum_name(&state_names, st->st_state),
			  predecessor->st_serialno);
	} else {
		libreswan_log("initiating v2 parent SA");
		whack_log(RC_NEW_STATE + STATE_PARENT_I1, "%s: initiate",
			  enum_name(&state_names, st->st_state));
	}

	/*
	 * now, we need to initialize st->st_oakley, specifically, the group
	 * number needs to be initialized.
	 */
	{
		oakley_group_t groupnum = OAKLEY_GROUP_invalid;
		struct db_sa *sadb;
		unsigned int pc_cnt;

		/* inscrutable dance of the sadbs */
		sadb = &oakley_sadb[sadb_index(policy, c)];
		{
			struct db_sa *sadb_plus =
				oakley_alg_makedb(st->st_connection->alg_info_ike,
					 sadb, FALSE);

			if (sadb_plus != NULL)
				sadb = sadb_plus;
		}
		sadb = sa_v2_convert(sadb);
		free_sa(st->st_sadb);
		st->st_sadb = sadb;

		/* look at all the proposals for the first group specified */

		for (pc_cnt = 0;
		     pc_cnt < sadb->prop_disj_cnt &&
		     groupnum == 0;
		     pc_cnt++)
		{
			/* look at all the proposals in this disjunction */
			struct db_v2_prop *vp = &sadb->prop_disj[pc_cnt];
			unsigned int pr_cnt;

			for (pr_cnt = 0;
			     pr_cnt < vp->prop_cnt && groupnum == OAKLEY_GROUP_invalid;
			     pr_cnt++)
			{
				struct db_v2_prop_conj *vpc = &vp->props[pr_cnt];
				unsigned int ts_cnt;

				for (ts_cnt = 0;
				     ts_cnt < vpc->trans_cnt && groupnum == OAKLEY_GROUP_invalid;
				     ts_cnt++)
				{
					struct db_v2_trans *tr =
						&vpc->trans[ts_cnt];

					/* ??? why would tr be NULL? */
					if (tr != NULL &&
					    tr->transform_type
					    == IKEv2_TRANS_TYPE_DH)
					{
						groupnum = tr->transid;
					}
				}
			}
		}
		if (groupnum == OAKLEY_GROUP_invalid)
			groupnum = OAKLEY_GROUP_MODP2048;
		st->st_oakley.group = lookup_group(groupnum);	/* NULL if unknown */
		st->st_oakley.groupnum = groupnum;
	}

	/*
	 * Calculate KE and Nonce.
	 *
	 * We need an md because the crypto continuation mechanism requires one
	 * but we don't have one because we are not responding to an
	 * incoming packet.
	 * Solution: build a fake one.  How much do we need to fake?
	 * Note: almost identical code appears at the end of aggr_outI1.
	 */
	{
		struct msg_digest *fake_md = alloc_md();
		struct pluto_crypto_req_cont *ke;
		stf_status e;

		fake_md->from_state = STATE_IKEv2_BASE;
		fake_md->svm = &ikev2_parent_firststate_microcode;
		fake_md->st = st;

		ke = new_pcrc(ikev2_parent_outI1_continue, "ikev2_outI1 KE",
			st, fake_md);
		e = build_ke_and_nonce(ke, st->st_oakley.group, importance);

		/*
		 * ??? what exactly do we expect for e?
		 * ??? Who frees ke? md?
		 */

		reset_globals();
		return e;
	}
}

/* redundant type assertion: static crypto_req_cont_func ikev2_parent_outI1_continue; */

static void ikev2_parent_outI1_continue(struct pluto_crypto_req_cont *ke,
					struct pluto_crypto_req *r)
{
	struct msg_digest *md = ke->pcrc_md;
	struct state *const st = md->st;
	stf_status e;

	DBG(DBG_CONTROL,
		DBG_log("ikev2_parent_outI1_continue for #%lu: calculated ke+nonce, sending I1",
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

	e = ikev2_parent_outI1_tail(ke, r);

	passert(ke->pcrc_md != NULL);
	/* ??? not legitimate: we were not provoked by a packet */
	complete_v2_state_transition(&ke->pcrc_md, e);
	release_any_md(&ke->pcrc_md);
	reset_globals();
}

/*
 * unpack the calculated KE value, store it in state.
 * used by IKEv2: parent, child (PFS)
 */
static enum ike_trans_type_dh unpack_v2KE_from_helper(struct state *st,
		       const struct pluto_crypto_req *r,
		       chunk_t *g)
{
	const struct pcr_kenonce *kn = &r->pcr_d.kn;

	unpack_KE_from_helper(st, r, g);
	/*
	 * clang 3.4: warning: Access to field 'oakley_group' results in a dereference of a null pointer (loaded from variable 'kn')
	 * This should not be accurate.
	 */
	return kn->oakley_group;
}

/*
 * package up the calculated KE value, and emit it as a KE payload.
 * used by IKEv2: parent, child (PFS)
 */
static bool justship_v2KE(struct state *st UNUSED,
			  chunk_t *g,
			  enum ike_trans_type_dh oakley_group,
			  pb_stream *outs,
			  u_int8_t np)
{
	struct ikev2_ke v2ke;
	pb_stream kepbs;

	zero(&v2ke);
	v2ke.isak_np = np;
	v2ke.isak_group = oakley_group;
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
	enum ike_trans_type_dh oakley_group = unpack_v2KE_from_helper(st, r, g);

	return justship_v2KE(st, g, oakley_group, outs, np);
}

static stf_status ikev2_parent_outI1_tail(struct pluto_crypto_req_cont *ke,
					  struct pluto_crypto_req *r)
{
	struct msg_digest *md = ke->pcrc_md;
	struct state *const st = md->st;

	DBG(DBG_CONTROL,
		DBG_log("ikev2_parent_outI1_tail for #%lu",
			ke->pcrc_serialno));

	passert(ke->pcrc_serialno == st->st_serialno);	/* transitional */

	unpack_v2KE_from_helper(st, r, &st->st_gi);
	unpack_nonce(&st->st_ni, r);
	return ikev2_parent_outI1_common(md, st);
}

static stf_status ikev2_parent_outI1_common(struct msg_digest *md,
					    struct state *st)
{
	struct connection *c = st->st_connection;

	/* set up reply */
	init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		 "reply packet");

	/* HDR out */
	{
		struct isakmp_hdr hdr;

		zero(&hdr);
		/* Impair function will raise major/minor by 1 for testing */
		hdr.isa_version = build_ikev2_version();

		hdr.isa_np = st->st_dcookie.ptr != NULL?
			ISAKMP_NEXT_v2N : ISAKMP_NEXT_v2SA;
		hdr.isa_xchg = ISAKMP_v2_SA_INIT;
		/* add original initiator flag - version flag could be set */
		hdr.isa_flags |= ISAKMP_FLAGS_v2_IKE_I;
		hdr.isa_msgid = v2_INITIAL_MSGID;
		memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
		/* R-cookie, are left zero */

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


		if (st->st_sadb->prop_disj_cnt == 0 || st->st_sadb->prop_disj)
			st->st_sadb = sa_v2_convert(st->st_sadb);

		if (!DBGP(IMPAIR_SEND_IKEv2_KE)) {
			if (!ikev2_out_sa(&md->rbody, PROTO_v2_ISAKMP, st->st_sadb, st,
				  TRUE, /* parentSA */
				  ISAKMP_NEXT_v2KE)) {
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
	if (!justship_v2KE(st, &st->st_gi, st->st_oakley.groupnum, &md->rbody,
			   ISAKMP_NEXT_v2Ni))
		return STF_INTERNAL_ERROR;

	/* send NONCE */
	{
		int np = ISAKMP_NEXT_v2N;
		struct ikev2_generic in;
		pb_stream pb;

		zero(&in);
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

	/* Send NAT-T Notify payloads */
	{
		int np = c->send_vendorid ? ISAKMP_NEXT_v2V : ISAKMP_NEXT_v2NONE;
		struct ikev2_generic in;

		zero(&in);
		in.isag_np = np;
		in.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;
		if (!ikev2_out_nat_v2n(np, &md->rbody, md))
			return STF_INTERNAL_ERROR;
	}

	/* Send VendorID VID if needed.  Only one. */
	if (c->send_vendorid) {
		if (!out_generic_raw(ISAKMP_NEXT_v2NONE, &isakmp_vendor_id_desc, &md->rbody,
				     pluto_vendorid, strlen(pluto_vendorid),
				     "Vendor ID"))
			return STF_INTERNAL_ERROR;
	}

	if (!close_message(&md->rbody, st))
		return STF_INTERNAL_ERROR;

	close_output_pbs(&reply_stream);

	/* keep it for a retransmit if necessary */
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
	/* Check: as a responder, are we under DoS attack or not?
	 * If yes go to 6 message exchange mode. It is a config option for now.
	 * TBD set force_busy dynamically.
	 * Paul: Can we check for STF_TOOMUCHCRYPTO?
	 */
        if (force_busy) {
                u_char dcookie[SHA1_DIGEST_SIZE];
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
		if (ni.len < BYTES_FOR_BITS(128)) {
			/*
			 * If this were a DDOS, we cannot afford to log.
			 * We do log if we are debugging.
			 */
			DBG(DBG_CONTROL, DBG_log("Dropping message with insufficient length Nonce"));
			return STF_IGNORE;
		}

                ikev2_get_dcookie(dcookie, ni, &md->sender, spiI);
                dc.ptr = dcookie;
                dc.len = SHA1_DIGEST_SIZE;

		/* check a v2N payload with type COOKIE */
		if (md->chain[ISAKMP_NEXT_v2N] != NULL &&
			md->chain[ISAKMP_NEXT_v2N]->payload.v2n.isan_type == v2N_COOKIE) {
			const pb_stream *dc_pbs;
			chunk_t idc;

			DBG(DBG_CONTROLMORE,
			    DBG_log("received a DOS cookie in I1 verify it"));
			/* we received dcookie we send earlier verify it */
			if (md->chain[ISAKMP_NEXT_v2N]->payload.v2n.isan_spisize != 0) {
				DBG(DBG_CONTROLMORE, DBG_log(
					"DOS cookie contains non-zero length SPI - message dropped"
				));
				return STF_IGNORE;
			}

			dc_pbs = &md->chain[ISAKMP_NEXT_v2N]->pbs;
			idc.ptr = dc_pbs->cur;
			idc.len = pbs_left(dc_pbs);
			DBG(DBG_CONTROLMORE,
			    DBG_dump_chunk("received dcookie", idc);
			    DBG_dump("dcookie computed", dcookie,
				     SHA1_DIGEST_SIZE));

			if (idc.len != SHA1_DIGEST_SIZE ||
				!memeq(idc.ptr, dcookie, SHA1_DIGEST_SIZE)) {
				DBG(DBG_CONTROLMORE, DBG_log(
					"mismatch in DOS v2N_COOKIE: dropping message (possible DoS attack)"
				));
				return STF_IGNORE;
			}
			DBG(DBG_CONTROLMORE, DBG_log(
				"dcookie received matched computed one"));
		} else {
			/* we are under DOS attack I1 contains no DOS COOKIE */
			DBG(DBG_CONTROLMORE,
			    DBG_log("busy mode on. received I1 without a valid dcookie");
			    DBG_log("send a dcookie and forget this state"));
			send_v2_notification_from_md(md, v2N_COOKIE, &dc);
			return STF_FAIL;
		}
	} else {
		DBG(DBG_CONTROLMORE,
		    DBG_log("will not send/process a dcookie"));
	}

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
			struct connection *d = find_host_connection(&md->iface->ip_addr,
						 pluto_port,
						 (ip_address*)NULL,
						 md->sender_port, policy);

			for (; d != NULL; d = d->hp_next) {
				if (d->kind == CK_GROUP) {
					/* ignore */
				} else {
					if (d->kind == CK_TEMPLATE &&
					    !(d->policy & POLICY_OPPORTUNISTIC)) {
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
			ipstr_buf b;

			loglog(RC_LOG_SERIOUS, "initial parent SA message received on %s:%u"
			       " but no connection has been authorized%s%s",
			       ipstr(&md->iface->ip_addr, &b),
			       ntohs(portof(&md->iface->ip_addr)),
			       (policy != LEMPTY) ? " with policy=" : "",
			       (policy !=LEMPTY) ?
			         bitnamesof(sa_policy_bit_names, policy) : "");
			return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
		}
		if (c->kind != CK_TEMPLATE) {
			ipstr_buf b;

			loglog(RC_LOG_SERIOUS, "initial parent SA message received on %s:%u"
			       " but \"%s\" forbids connection",
			       ipstr(&md->iface->ip_addr, &b), pluto_port, c->name);
			return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
		}
		c = rw_instantiate(c, &md->sender, NULL, NULL);
	} else {
		/* We found a non-wildcard connection.
		 * Double check whether it needs instantiation anyway (eg. vnet=)
		 */
		/* vnet=/vhost= should have set CK_TEMPLATE on connection loading */
		if ((c->kind == CK_TEMPLATE) && c->spd.that.virt) {
			DBG(DBG_CONTROL,
			    DBG_log("local endpoint has virt (vnet/vhost) set without wildcards - needs instantiation"));
			c = rw_instantiate(c, &md->sender, NULL, NULL);
		} else if ((c->kind == CK_TEMPLATE) &&
			   (c->policy & POLICY_IKEV2_ALLOW_NARROWING)) {
			DBG(DBG_CONTROL,
			    DBG_log("local endpoint has narrowing=yes - needs instantiation"));
			c = rw_instantiate(c, &md->sender, NULL, NULL);
		}
	}

	DBG(DBG_CONTROL, DBG_log("found connection: %s", c ? c->name : "<none>"));

	pexpect(st == NULL);	/* ??? where would a state come from? Duplicate packet? */

	if (st == NULL) {
		st = new_state();
		/* set up new state */
		memcpy(st->st_icookie, md->hdr.isa_icookie, COOKIE_SIZE);
		/* initialize_new_state expects valid icookie/rcookie values, so create it now */
		get_cookie(FALSE, st->st_rcookie, COOKIE_SIZE, &md->sender);
		initialize_new_state(st, c, policy, 0, NULL_FD,
				     pcim_stranger_crypto);
		st->st_ikev2 = TRUE;
		change_state(st, STATE_PARENT_R1);
		st->st_msgid_lastack = v2_INVALID_MSGID;
		st->st_msgid_nextuse = 0;

		md->st = st;
		md->from_state = STATE_IKEv2_BASE;
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
		struct ikev2_ke *ke = &md->chain[ISAKMP_NEXT_v2KE]->payload.v2ke;

		st->st_oakley.group = lookup_group(ke->isak_group);
		if (st->st_oakley.group == NULL) {
			ipstr_buf b;

			libreswan_log(
				"rejecting I1 from %s:%u, invalid DH group=%u",
				ipstr(&md->sender, &b), md->sender_port,
				ke->isak_group);
			return STF_FAIL + v2N_INVALID_KE_PAYLOAD;
		}
	}

	/*
	 * check v2N_NAT_DETECTION_DESTINATION_IP or/and
	 * v2N_NAT_DETECTION_SOURCE_IP
	 */
	if (md->chain[ISAKMP_NEXT_v2N] != NULL)
		ikev2_natd_lookup(md, zero_cookie);

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
	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_v2SA];
	struct state *const st = md->st;
	struct connection *c = st->st_connection;
	bool send_certreq = FALSE;

	passert(ke->pcrc_serialno == st->st_serialno);	/* transitional */

	/* note that we don't update the state here yet */

	/* record first packet for later checking of signature */
	clonetochunk(st->st_firstpacket_him, md->message_pbs.start,
		     pbs_offset(&md->message_pbs),
		     "saved first received packet");

	/* make sure HDR is at start of a clean buffer */
	zero(&reply_buffer);
	init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		 "reply packet");

	/* HDR out */
	{
		struct isakmp_hdr hdr = md->hdr;

		memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
		hdr.isa_np = ISAKMP_NEXT_v2SA;
		/* set msg responder flag - clear other flags */
		hdr.isa_flags = ISAKMP_FLAGS_v2_MSG_R;
		hdr.isa_version = build_ikev2_version();

		if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
			hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
		}

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_stream,
				&md->rbody))
			return STF_INTERNAL_ERROR;
	}

	/* start of SA out */
	{
		struct ikev2_sa r_sa;
		stf_status ret;
		pb_stream r_sa_pbs;

		zero(&r_sa);

		if (!DBGP(IMPAIR_SEND_IKEv2_KE)) {
			/* normal case */
			r_sa.isasa_np = ISAKMP_NEXT_v2KE;
		} else {
			/* We are faking not sending a KE, we'll just call it a Notify */
			r_sa.isasa_np = ISAKMP_NEXT_v2N;
		}

		if (!out_struct(&r_sa, &ikev2_sa_desc, &md->rbody, &r_sa_pbs))
			return STF_INTERNAL_ERROR;

		/* SA body in and out */
		ret = ikev2_parse_parent_sa_body(&sa_pd->pbs,
						&r_sa_pbs, st, FALSE);

		if (ret != STF_OK) {
			DBG(DBG_CONTROLMORE,DBG_log("ikev2_parse_parent_sa_body() failed in ikev2_parent_inI1outR1_tail()"));
			return ret;
		}
	}

	/* KE in */
	{
		/* note: v1 notification! */
		notification_t rn = accept_KE(&st->st_gi, "Gi", st->st_oakley.group,
			       &md->chain[ISAKMP_NEXT_v2KE]->pbs);

		switch (rn) {
		case NOTHING_WRONG:
			break;
		case INVALID_KEY_INFORMATION:
		{
			/*
			 * RFC 5996 1.3 says that we should return
			 * our desired group number when rejecting sender's.
			 */
			u_int16_t group_number = htons(
				st->st_oakley.group->group);
			chunk_t dc = { (unsigned char *)&group_number,
				sizeof(group_number) };

			send_v2_notification_from_state(st,
				v2N_INVALID_KE_PAYLOAD, &dc);
			delete_state(st);
			md->st = NULL;
			return STF_FAIL;	/* don't send second notification */
		}
		default:
			/* hope v1 and v2 notifications correspond! */
			return STF_FAIL + rn;
		}
	}

	/* Ni in */
	RETURN_STF_FAILURE(accept_v2_nonce(md, &st->st_ni, "Ni"));

	/* ??? from here on, this looks a lot like the end of ikev2_parent_outI1_common */

	/* send KE */
	if (!ship_v2KE(st, r, &st->st_gr, &md->rbody, ISAKMP_NEXT_v2Nr))
		return STF_INTERNAL_ERROR;

	/* send NONCE */
	unpack_nonce(&st->st_nr, r);
	{
		int np = ISAKMP_NEXT_v2N;
		struct ikev2_generic in;
		pb_stream pb;

		zero(&in);
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
	{
		 /* decide to send a CERTREQ */
		send_certreq = (c->policy & POLICY_RSASIG) &&
			!has_preloaded_public_key(st);
	}

	/* Send NAT-T Notify payloads */
	{
		struct ikev2_generic in;
		int np = send_certreq ? ISAKMP_NEXT_v2CERTREQ :
			c->send_vendorid ? ISAKMP_NEXT_v2V : ISAKMP_NEXT_v2NONE;

		zero(&in);
		in.isag_np = np;
		in.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;
		if (!ikev2_out_nat_v2n(np, &md->rbody, md))
			return STF_INTERNAL_ERROR;
	}

	/* send CERTREQ  */
	if(send_certreq) {
		int np = c->send_vendorid ? ISAKMP_NEXT_v2V : ISAKMP_NEXT_v2NONE;
		DBG(DBG_CONTROL, DBG_log("going to send a certreq"));
		ikev2_send_certreq(st, md, O_RESPONDER, np, &md->rbody);
	}

	/* Send VendorID VID if needed.  Only one. */
	if (c->send_vendorid) {
		if (!out_generic_raw(ISAKMP_NEXT_v2NONE, &isakmp_vendor_id_desc, &md->rbody,
				     pluto_vendorid, strlen(pluto_vendorid),
				     "Vendor ID"))
			return STF_INTERNAL_ERROR;
	}

	if (!close_message(&md->rbody, st))
		return STF_INTERNAL_ERROR;

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
 *                     <--  HDR, N
 * HDR, N, SAi1, KEi, Ni -->
 */
stf_status ikev2parent_inR1BoutI1B(struct msg_digest *md)
{
	struct state *st = md->st;
	/* struct connection *c = st->st_connection; */
	struct payload_digest *ntfy;

	for (ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
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
			u_int8_t spisize;
			const pb_stream *dc_pbs;

			if (ntfy != md->chain[ISAKMP_NEXT_v2N] || ntfy->next != NULL) {
				libreswan_log("v2N_COOKIE must be only notification in packet");
				return STF_FAIL + v2N_INVALID_SYNTAX;
			}
			libreswan_log("Received anti-DDOS COOKIE -resending I1 with cookie payload");
			spisize = ntfy->payload.v2n.isan_spisize;
			dc_pbs = &ntfy->pbs;
			clonetochunk(st->st_dcookie,
				dc_pbs->cur + spisize,
				pbs_left(dc_pbs) - spisize,
				"saved received dcookie");

			DBG(DBG_CONTROLMORE,
			    DBG_dump_chunk("dcookie received (instead of a R1):",
					   st->st_dcookie);
			    DBG_log("next STATE_PARENT_I1 resend I1 with the dcookie"));

			md->svm = &ikev2_parent_firststate_microcode;

			change_state(st, STATE_PARENT_I1);
			st->st_msgid_lastack = v2_INVALID_MSGID;
			md->msgid_received = v2_INVALID_MSGID;
			st->st_msgid_nextuse = 0;

			return ikev2_parent_outI1_common(md, st);
		}
		case v2N_INVALID_KE_PAYLOAD:
		case v2N_NO_PROPOSAL_CHOSEN:
		default:
			/*
			 * ??? At least INVALID_KE_PAYLOAD and NO_PROPOSAL_CHOSEN
			 * are legal and should keep us in this state.
			 * The responder SPI ought to have been 0 (but might not be).
			 * See rfc5996bis-04 2.6.
			 */
			libreswan_log("%s: received unauthenticated %s - ignored",
				enum_name(&state_names, st->st_state),
				enum_name(&ikev2_notify_names,
					ntfy->payload.v2n.isan_type));
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
	/* struct connection *c = st->st_connection; */
	struct payload_digest *ntfy;

	for (ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
		switch (ntfy->payload.v2n.isan_type) {
		case v2N_COOKIE:
		case v2N_INVALID_KE_PAYLOAD:
		case v2N_NO_PROPOSAL_CHOSEN:
			libreswan_log("%s cannot appear with other payloads",
				enum_name(&ikev2_notify_names,
						ntfy->payload.v2n.isan_type));
			return STF_FAIL + v2N_INVALID_SYNTAX;

		case v2N_USE_TRANSPORT_MODE:
		case v2N_NAT_DETECTION_SOURCE_IP:
		case v2N_NAT_DETECTION_DESTINATION_IP:
			/* we do handle these further down */
			break;
		default:
			libreswan_log("%s: received %s but ignoring it",
				enum_name(&state_names, st->st_state),
				enum_name(&ikev2_notify_names,
					ntfy->payload.v2n.isan_type));
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
		stf_status ret = ikev2_parse_parent_sa_body(&sa_pd->pbs,
						NULL, st, TRUE);

		if (ret != STF_OK) {
			DBG(DBG_CONTROLMORE,DBG_log("ikev2_parse_parent_sa_body() failed in ikev2parent_inR1outI2()"));
			return ret;
		}
	}

	/* update state */
	ikev2_update_msgid_counters(md);

	/* check v2N_NAT_DETECTION_DESTINATION_IP or/and
	 * v2N_NAT_DETECTION_SOURCE_IP
	 */
	if(md->chain[ISAKMP_NEXT_v2N] != NULL)
		ikev2_natd_lookup(md, st->st_rcookie);

	/* initiate calculation of g^xy */
	return start_dh_v2(md, "ikev2_inR1outI2 KE", O_INITIATOR,
		ikev2_parent_inR1outI2_continue);
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
 * Pad message for CBC-mode encryption. Should not be called for CTR or CCM/GCM
 * Octets are added to make the message a multiple of the cipher block size.
 * At least one octet is added and at most blocksize are added.
 * The first is 0, and each subsequent octet is one larger.
 * Thus the last octet contains one less than the number of octets added.
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
		size_t padding = pad_up(pbs_offset(e_pbs_cipher), blocksize);

		if (padding == 0)
			padding = blocksize;

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
	if (!out_zero(pst->st_oakley.integ_hasher->hash_integ_len, e_pbs,
		      "length of truncated HMAC"))
		return NULL;

	return b12;
}

static stf_status ikev2_encrypt_msg(struct state *st,
				    enum phase1_role role,
				    unsigned char *authstart,
				    unsigned char *iv,
				    unsigned char *encstart,
				    unsigned char *authloc,
				    pb_stream *e_pbs UNUSED,
				    pb_stream *e_pbs_cipher)
{
	struct state *pst = st;
	PK11SymKey *cipherkey, *authkey;

	if (IS_CHILD_SA(st))
		pst = state_with_serialno(st->st_clonedfrom);

	if (role == O_INITIATOR) {
		cipherkey = pst->st_skey_ei_nss;
		authkey = pst->st_skey_ai_nss;
	} else {
		cipherkey = pst->st_skey_er_nss;
		authkey = pst->st_skey_ar_nss;
	}

	/* encrypt the block */
	{
		size_t ivsize = pst->st_oakley.encrypter->ivsize;
		/* note: no iv is longer than MAX_CBC_BLOCK_SIZE */
		unsigned char savediv[MAX_CBC_BLOCK_SIZE];
		unsigned int cipherlen = e_pbs_cipher->cur - encstart;

		passert(ivsize <= MAX_CBC_BLOCK_SIZE);
		DBG(DBG_CRYPT,
		    DBG_dump("data before encryption:", encstart, cipherlen));

		memcpy(savediv, iv, ivsize);

		/* now, encrypt */
		(st->st_oakley.encrypter->do_crypt)(encstart,
						    cipherlen,
						    cipherkey,
						    savediv, TRUE);

		DBG(DBG_CRYPT,
		    DBG_dump("data after encryption:", encstart, cipherlen));
		/* note: saved_iv's updated value is discarded */
	}

	/* okay, authenticate from beginning of IV */
	{
		struct hmac_ctx ctx;
		DBG(DBG_PARSING, DBG_log("Inside authloc"));
		DBG(DBG_CRYPT,
		    DBG_log("authkey pointer: %p", authkey));
		hmac_init(&ctx, pst->st_oakley.integ_hasher, authkey);
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

/*
 * ikev2_decrypt_msg: decode the v2E payload.
 * The result is stored in-place.
 * Calls ikev2_process_payloads to decode the payloads within.
 *
 * This code assumes that the encrypted part of an IKE message starts
 * with an Initialization Vector (IV) of ivsize of random octets.
 * We will discard the IV after decryption.
 * This is true of Cipher Block Chaining mode (CBC).
 */
static
stf_status ikev2_decrypt_msg(struct msg_digest *md,
			     enum phase1_role role)
{
	struct state *st = md->st;
	struct state *pst = IS_CHILD_SA(st) ?
		state_with_serialno(st->st_clonedfrom) : st;
	pb_stream *e_pbs = &md->chain[ISAKMP_NEXT_v2E]->pbs;
	unsigned char *authstart = md->packet_pbs.start;
	unsigned char *iv = e_pbs->cur;	/* start of IV, right after header */
	size_t integ_len = pst->st_oakley.integ_hasher->hash_integ_len;
	size_t enc_blocksize = pst->st_oakley.encrypter->enc_blocksize;
	size_t ivsize = pst->st_oakley.encrypter->ivsize;
	unsigned char *roof= e_pbs->roof;
	PK11SymKey *cipherkey, *authkey;

	if (st != NULL && !st->hidden_variables.st_skeyid_calculated)
	{
		DBG(DBG_CRYPT | DBG_CONTROL, {
				ipstr_buf b;
				DBG_log("received encrypted packet from %s:%u "
						" but no exponents for state #%lu"
						" to decrypt it",
						ipstr(&md->sender, &b),
						(unsigned)md->sender_port,
						st->st_serialno);
				});
		return STF_FAIL;
	}
	/*
	 * check to see if length is plausible.  Need room for:
	 * - IV (at start)
	 * - at least one byte for padding (just before integrity digest)
	 * - truncated integrity digest (at end)
	 */
	if (roof - iv < (ptrdiff_t)(ivsize + 1 + integ_len)) {
		libreswan_log("encrypted payload impossibly short (%td)",
			roof - iv);
		return STF_FAIL;
	}

	roof -= integ_len;	/* strip truncated digest */

	if (role == O_INITIATOR) {
		cipherkey = pst->st_skey_er_nss;
		authkey = pst->st_skey_ar_nss;
	} else {
		cipherkey = pst->st_skey_ei_nss;
		authkey = pst->st_skey_ai_nss;
	}

	/*
	 * check authenticator
	 * The last [integ_len] bytes are the truncated digest.
	 */
	{
		unsigned char td[MAX_DIGEST_LEN];
		struct hmac_ctx ctx;

		hmac_init(&ctx, pst->st_oakley.integ_hasher, authkey);
		hmac_update(&ctx, authstart, roof - authstart);
		hmac_final(td, &ctx);

		DBG(DBG_PARSING, {
			DBG_dump("data for hmac:",
				authstart, roof - authstart);
			DBG_dump("calculated auth:",
				td,
				pst->st_oakley.integ_hasher-> hash_integ_len);
			DBG_dump("  provided auth:",
				roof,
				pst->st_oakley.integ_hasher->hash_integ_len);
		    });

		if (!memeq(td, roof, integ_len)) {
			libreswan_log("failed to match authenticator");
			return STF_FAIL;
		}
	}

	DBG(DBG_PARSING, DBG_log("authenticator matched"));

	/* decrypt */
	{
		/*
		 * The first [ivsize] octet chunk is the IV.
		 * The encrypted data follows.
		 * The last byte of encrypted data is one less than
		 * the number of padding octets.
		 */
		unsigned char *encstart = iv + ivsize;
		size_t enclen = roof - encstart;
		unsigned char padlen;

		DBG(DBG_CRYPT,
		    DBG_dump("data before decryption:", encstart, enclen));

		if (enclen % enc_blocksize != 0) {
			libreswan_log("cyphertext length (%zu) not a multiple of blocksize (%zu)",
				enclen, enc_blocksize);
			return STF_FAIL;
		}

		/* now, decrypt */
		(pst->st_oakley.encrypter->do_crypt)(encstart,
						     enclen,
						     cipherkey,
						     iv, FALSE);

		padlen = encstart[enclen - 1] + 1;

		if (padlen > enc_blocksize || padlen > enclen) {
			libreswan_log("invalid last pad octet: 0x%2x", padlen - 1);
			return STF_FAIL;
		}

		/* don't bother to check any other pad octets */

		DBG(DBG_CRYPT, {
			    DBG_dump("decrypted payload:", encstart, enclen);
			    DBG_log("striping %u bytes as pad", padlen);
		    });

		init_pbs(&md->clr_pbs, encstart, enclen - padlen, "cleartext");
	}

	return ikev2_process_payloads(md, &md->clr_pbs,
		md->chain[ISAKMP_NEXT_v2E]->payload.generic.isag_np,
		TRUE);
}

static stf_status ikev2_ship_cp_attr_ip4( u_int16_t type, ip_address *ip4,
		const char *story, pb_stream *outpbs )
{
	struct ikev2_cp_attribute attr;
	unsigned char *byte_ptr;
	pb_stream a_pbs;
	attr.type = type;
	attr.len = ip4 == NULL ? 0 : 4;

	if (!out_struct(&attr, &ikev2_cp_attribute_desc, outpbs,
				&a_pbs))
		return STF_INTERNAL_ERROR;

	if (attr.len > 0) {
		addrbytesptr(ip4, &byte_ptr);
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
	zero(&cp);
	cp.isacp_critical = ISAKMP_PAYLOAD_NONCRITICAL;
	cp.isacp_np = np;
	cp.isacp_type = cfg_reply ? IKEv2_CP_CFG_REPLY : IKEv2_CP_CFG_REQUEST;

	if (!out_struct(&cp, &ikev2_cp_desc, outpbs, &cp_pbs))
		return STF_INTERNAL_ERROR;

	ikev2_ship_cp_attr_ip4(IKEv2_INTERNAL_IP4_ADDRESS,
			cfg_reply ? &c->spd.that.client.addr : NULL,
			"IPV4 Address", &cp_pbs);

	if(cfg_reply) {
		if(!isanyaddr(&c->modecfg_dns1)) {
			ikev2_ship_cp_attr_ip4(IKEv2_INTERNAL_IP4_DNS, &c->modecfg_dns1,
					"DNS 1", &cp_pbs);
		}
		if(!isanyaddr(&c->modecfg_dns2)) {
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
				  enum phase1_role role,
				  enum next_payload_types_ikev2 np,
				  unsigned char *idhash_out,
				  pb_stream *outpbs)
{
	struct ikev2_a a;
	pb_stream a_pbs;
	struct state *pst = st;

	if (IS_CHILD_SA(st))
		pst = state_with_serialno(st->st_clonedfrom);

	a.isaa_critical = ISAKMP_PAYLOAD_NONCRITICAL;
	if (DBGP(IMPAIR_SEND_BOGUS_PAYLOAD_FLAG)) {
		libreswan_log(
			" setting bogus ISAKMP_PAYLOAD_LIBRESWAN_BOGUS flag in ISAKMP payload");
		a.isaa_critical |= ISAKMP_PAYLOAD_LIBRESWAN_BOGUS;
	}

	a.isaa_np = np;

	if (c->policy & POLICY_RSASIG) {
		a.isaa_type = IKEv2_AUTH_RSA;
	} else if (c->policy & POLICY_PSK) {
		a.isaa_type = IKEv2_AUTH_PSK;
	} else {
		/* what else is there?... DSS not implemented. */
		loglog(RC_LOG_SERIOUS, "Unknown or not implemented IKEv2 AUTH policy");
		return STF_FATAL;
	}

	if (!out_struct(&a,
			&ikev2_a_desc,
			outpbs,
			&a_pbs))
		return STF_INTERNAL_ERROR;

	if (c->policy & POLICY_RSASIG) {
		if (!ikev2_calculate_rsa_sha1(pst, role, idhash_out, &a_pbs)) {
				loglog(RC_LOG_SERIOUS, "Failed to find our RSA key");
			return STF_FATAL;
		}
	} else if (c->policy & POLICY_PSK) {
		if (!ikev2_calculate_psk_auth(pst, role, idhash_out, &a_pbs)) {
				loglog(RC_LOG_SERIOUS, "Failed to find our PreShared Key");
			return STF_FATAL;
		}
	}

	close_output_pbs(&a_pbs);
	return STF_OK;
}

static stf_status ikev2_parent_inR1outI2_tail(
	struct pluto_crypto_req_cont *dh,
	struct pluto_crypto_req *r)
{
	struct msg_digest *md = dh->pcrc_md;
	struct state *st = md->st;
	struct connection *c = st->st_connection;
	struct ikev2_generic e;
	unsigned char *encstart;
	pb_stream e_pbs, e_pbs_cipher;
	unsigned char *iv;
	stf_status ret;
	unsigned char idhash[MAX_DIGEST_LEN];
	unsigned char *authstart;
	struct state *pst = st;
	bool send_cert = FALSE;

	finish_dh_v2(st, r);

	/* ??? this is kind of odd: regular control flow only selecting DBG output */
	if (DBGP(DBG_PRIVATE) && DBGP(DBG_CRYPT))
		ikev2_log_parentSA(st);

	st = duplicate_state(pst);
	st->st_msgid = htonl(pst->st_msgid_nextuse); /* PAUL: note ordering */
	insert_state(st);
	md->st = st;

	/* parent had crypto failed, replace it with rekey! */
	/* ??? seems wrong: not conditional at all */
	delete_event(pst);
	{
		/* why not from svm->timeout_event ??? */
		enum event_type x = EVENT_SA_REPLACE;
		time_t delay = ikev2_replace_delay(pst, &x, O_INITIATOR);

		event_schedule(x, delay, pst);
	}

	/* need to force parent state to I2 */
	change_state(pst, STATE_PARENT_I2);

	/* record first packet for later checking of signature */
	clonetochunk(pst->st_firstpacket_him, md->message_pbs.start,
		     pbs_offset(
			     &md->message_pbs), "saved first received packet");

	/* beginning of data going out */
	authstart = reply_stream.cur;

	/* make sure HDR is at start of a clean buffer */
	zero(&reply_buffer);
	init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		 "reply packet");

	/* HDR out */
	{
		struct isakmp_hdr hdr = md->hdr;

		/* clear all flags, set original initiator */
		hdr.isa_flags = ISAKMP_FLAGS_v2_IKE_I;
		hdr.isa_version = build_ikev2_version();
		hdr.isa_np = ISAKMP_NEXT_v2E;
		hdr.isa_xchg = ISAKMP_v2_AUTH;
		hdr.isa_msgid = st->st_msgid;
		memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
		memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);

		if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
			hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
		}

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_stream,
				&md->rbody))
			return STF_INTERNAL_ERROR;
	}

	/* insert an Encryption payload header */
	e.isag_np = ISAKMP_NEXT_v2IDi;
	e.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;
	if (DBGP(IMPAIR_SEND_BOGUS_PAYLOAD_FLAG)) {
		libreswan_log(
			" setting bogus ISAKMP_PAYLOAD_LIBRESWAN_BOGUS flag in ISAKMP payload");
		e.isag_critical |= ISAKMP_PAYLOAD_LIBRESWAN_BOGUS;
	}

	if (!out_struct(&e, &ikev2_e_desc, &md->rbody, &e_pbs))
		return STF_INTERNAL_ERROR;

	/* insert IV */
	iv = e_pbs.cur;
	if (!emit_iv(st, &e_pbs))
		return STF_INTERNAL_ERROR;

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

		hmac_init(&id_ctx, pst->st_oakley.prf_hasher,
				pst->st_skey_pi_nss);
		build_id_payload((struct isakmp_ipsec_id *)&r_id, &id_b,
				 &c->spd.this);
		r_id.isai_critical = ISAKMP_PAYLOAD_NONCRITICAL;
		if (DBGP(IMPAIR_SEND_BOGUS_PAYLOAD_FLAG)) {
			libreswan_log(
				" setting bogus ISAKMP_PAYLOAD_LIBRESWAN_BOGUS flag in ISAKMP payload");
			r_id.isai_critical |= ISAKMP_PAYLOAD_LIBRESWAN_BOGUS;
		}

		/* decide to send CERT payload */
		{
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
		DBG(DBG_CRYPT, DBG_dump("idhash calc I2", id_start, id_len));
		hmac_update(&id_ctx, id_start, id_len);
		hmac_final(idhash, &id_ctx);
	}

	/* send [CERT,] payload RFC 4306 3.6, 1.2) */
	{
		if (send_cert) {
			stf_status certstat = ikev2_send_cert(st, md,
							      O_INITIATOR,
							      ISAKMP_NEXT_v2AUTH,
							      &e_pbs_cipher);
			if (certstat != STF_OK)
				return certstat;
		}
	}

	/* send out the AUTH payload */
	{
		int np = c->spd.this.modecfg_client ?
				ISAKMP_NEXT_v2CP : ISAKMP_NEXT_v2SA;

		stf_status authstat = ikev2_send_auth(c, st, O_INITIATOR, np,
				idhash, &e_pbs_cipher);

		if (authstat != STF_OK)
			return authstat;
	}

	if (c->spd.this.modecfg_client){
		stf_status cpstat = ikev2_send_cp(c, ISAKMP_NEXT_v2SA,
				&e_pbs_cipher);

		if (cpstat != STF_OK)
			return cpstat;
	}

	{
		/*
		 * emit SA2i, TSi and TSr and
		 * (v2N_USE_TRANSPORT_MODE notification in transport mode)
		 * for it.
		 */
		lset_t policy;

		passert(c == st->st_connection);
		c = first_pending(pst, &policy, &st->st_whack_sock);

		if (c == NULL) {
			c = st->st_connection;
			DBG_log("no pending CHILD SAs found for %s: Reauthentication so use the original policy",
				c->name);
			policy = c->policy;
		}
		st->st_connection = c;

		ikev2_emit_ipsec_sa(md, &e_pbs_cipher,
				ISAKMP_NEXT_v2TSi, c, policy);

		st->st_ts_this = ikev2_end_to_ts(&c->spd.this);
		st->st_ts_that = ikev2_end_to_ts(&c->spd.that);

		ikev2_calc_emit_ts(md, &e_pbs_cipher, O_INITIATOR, c, policy);

		if ((c->policy & POLICY_TUNNEL) == LEMPTY) {
			DBG_log("Initiator child policy is transport mode, sending v2N_USE_TRANSPORT_MODE");
			/* In v2, for parent, protoid must be 0 and SPI must be empty */
			if (!ship_v2N(ISAKMP_NEXT_v2NONE,
						ISAKMP_PAYLOAD_NONCRITICAL,
						PROTO_v2_RESERVED,
						&empty_chunk,
						v2N_USE_TRANSPORT_MODE, &empty_chunk,
						&e_pbs_cipher))
				return STF_INTERNAL_ERROR;
		}
	}

	/*
	 * TODO WARNING: padding must not be done for CTR mode
	 *
	 * need to extend the packet so that we will know how big it is
	 * since the length is under the integrity check
	 */
	if (!ikev2_padup_pre_encrypt(st, &e_pbs_cipher))
		return STF_INTERNAL_ERROR;

	close_output_pbs(&e_pbs_cipher);

	{
		unsigned char *authloc = ikev2_authloc(st, &e_pbs);

		if (authloc == NULL)
			return STF_INTERNAL_ERROR;

		close_output_pbs(&e_pbs);
		close_output_pbs(&md->rbody);
		close_output_pbs(&reply_stream);

		ret = ikev2_encrypt_msg(st, O_INITIATOR,
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

	nat_traversal_change_port_lookup(md, st);

	/*
	 * the initiator sent us an encrypted payload. We need to calculate
	 * our g^xy, and skeyseed values, and then decrypt the payload.
	 */

	DBG(DBG_CONTROLMORE,
	    DBG_log("ikev2 parent inI2outR2: calculating g^{xy} in order to decrypt I2"));

	/* initiate calculation of g^xy */
	return start_dh_v2(md, "ikev2_inI2outR2 KE", O_RESPONDER,
		ikev2_parent_inI2outR2_continue);
}

/* redundant type assertion: static crypto_req_cont_func ikev2_parent_inI2outR2_continue; */

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
	struct connection *c = st->st_connection;
	unsigned char idhash_in[MAX_DIGEST_LEN], idhash_out[MAX_DIGEST_LEN];
	unsigned char *authstart;
	unsigned int np;
	int v2_notify_num = 0;

	/* extract calculated values from r */
	finish_dh_v2(st, r);

	/* ??? this is kind of odd: regular control flow only selecting DBG output */
	if (DBGP(DBG_PRIVATE) && DBGP(DBG_CRYPT))
		ikev2_log_parentSA(st);

	/* decrypt things. */
	{
		stf_status ret = ikev2_decrypt_msg(md, O_RESPONDER);

		if (ret != STF_OK)
			return ret;
	}

	if (!ikev2_decode_peer_id(md, O_RESPONDER))
		return STF_FAIL + v2N_AUTHENTICATION_FAILED;

	{
		struct hmac_ctx id_ctx;
		const pb_stream *id_pbs = &md->chain[ISAKMP_NEXT_v2IDi]->pbs;
		unsigned char *idstart = id_pbs->start + NSIZEOF_isakmp_generic;
		unsigned int idlen = pbs_room(id_pbs) - NSIZEOF_isakmp_generic;

		hmac_init(&id_ctx, st->st_oakley.prf_hasher,
				st->st_skey_pi_nss);

		/* calculate hash of IDi for AUTH below */
		DBG(DBG_CRYPT, DBG_dump("idhash verify I2", idstart, idlen));
		hmac_update(&id_ctx, idstart, idlen);
		hmac_final(idhash_in, &id_ctx);
	}

	/* process CERT payload */
	{
		if (md->chain[ISAKMP_NEXT_v2CERT] != NULL) {
			/*
			 * should we check if we should accept a cert payload ?
			 *  has_preloaded_public_key(st)
			 */
			DBG(DBG_CONTROLMORE,
			    DBG_log("has a v2_CERT payload going to process it "));
			ikev2_decode_cert(md);
		}
	}

	/* process CERTREQ payload */
	if (md->chain[ISAKMP_NEXT_v2CERTREQ] != NULL) {
		DBG(DBG_CONTROLMORE,
		    DBG_log("has a v2CERTREQ payload; going to decode it"));
		ikev2_decode_cr(md, &st->st_connection->requested_ca);
	}

	/* process AUTH payload now */
	/* now check signature from RSA key */
	switch (md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2a.isaa_type) {
	case IKEv2_AUTH_RSA:
	{
		stf_status authstat = ikev2_verify_rsa_sha1(
				st,
				O_RESPONDER,
				idhash_in,
				NULL,	/* keys from DNS */
				NULL,	/* gateways from DNS */
				&md->chain[ISAKMP_NEXT_v2AUTH]->pbs);

		if (authstat != STF_OK) {
			libreswan_log("RSA authentication failed");
			/*
			 * ??? this could be
			 * return STF_FAIL + v2N_AUTHENTICATION_FAILED
			 * but that would be ignored by the logic in
			 * complete_v2_state_transition()
			 * that says "only send a notify is this packet was a question, not if it was an answer"
			 */
			SEND_V2_NOTIFICATION(v2N_AUTHENTICATION_FAILED);
			return STF_FATAL;
		}
		break;
	}
	case IKEv2_AUTH_PSK:
	{
		stf_status authstat = ikev2_verify_psk_auth(
				st,
				O_RESPONDER,
				idhash_in,
				&md->chain[ISAKMP_NEXT_v2AUTH]->pbs);

		if (authstat != STF_OK) {
			libreswan_log(
				"PSK authentication failed AUTH mismatch!");
			/*
			 * ??? this could be
			 * return STF_FAIL + v2N_AUTHENTICATION_FAILED
			 * but that would be ignored by the logic in
			 * complete_v2_state_transition()
			 * that says "only send a notify is this packet was a question, not if it was an answer"
			 */
			SEND_V2_NOTIFICATION(v2N_AUTHENTICATION_FAILED);
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
		    DBG_log(" notify payload detected, should be processed...."));
	}

	/* good. now create child state */
	/* note: as we will switch to child state, we force the parent to the
	 * new state now
	 */
	change_state(st, STATE_PARENT_R2);
	c->newest_isakmp_sa = st->st_serialno;

#ifdef USE_LINUX_AUDIT
	linux_audit_conn(st, LAK_PARENT_START);
#endif

	delete_event(st);
	{
		enum event_type x = EVENT_SA_REPLACE;
		time_t delay = ikev2_replace_delay(st, &x, O_RESPONDER);

		event_schedule(x, delay, st);
	}

	authstart = reply_stream.cur;
	/* send response */
	{
		unsigned char *encstart;
		unsigned char *iv;
		struct ikev2_generic e;
		pb_stream e_pbs, e_pbs_cipher;
		stf_status ret;
		bool send_cert = FALSE;

		/* make sure HDR is at start of a clean buffer */
		zero(&reply_buffer);
		init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
			 "reply packet");

		/* HDR out */
		{
			struct isakmp_hdr hdr = md->hdr; /* grab cookies */

			/* set msg responder flag - clear others */
			hdr.isa_flags = ISAKMP_FLAGS_v2_MSG_R;
			hdr.isa_version = build_ikev2_version();
			hdr.isa_np = ISAKMP_NEXT_v2E;
			hdr.isa_xchg = ISAKMP_v2_AUTH;
			memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
			memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);

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

		if (!out_struct(&e, &ikev2_e_desc, &md->rbody, &e_pbs))
			return STF_INTERNAL_ERROR;

		/* insert IV */
		iv = e_pbs.cur;
		if (!emit_iv(st, &e_pbs))
			return STF_INTERNAL_ERROR;

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

			hmac_init(&id_ctx, st->st_oakley.prf_hasher,
					st->st_skey_pr_nss);
			build_id_payload((struct isakmp_ipsec_id *)&r_id,
					 &id_b,
					 &c->spd.this);
			r_id.isai_critical = ISAKMP_PAYLOAD_NONCRITICAL;

			if (send_cert)
				r_id.isai_np = ISAKMP_NEXT_v2CERT;
			else
				r_id.isai_np = ISAKMP_NEXT_v2AUTH;

			id_start = e_pbs_cipher.cur;

			if (!out_struct(&r_id, &ikev2_id_desc, &e_pbs_cipher,
					&r_id_pbs) ||
			    !out_chunk(id_b, &r_id_pbs, "my identity"))
				return STF_INTERNAL_ERROR;

			close_output_pbs(&r_id_pbs);

			id_start += 4;

			/* calculate hash of IDi for AUTH below */
			id_len = e_pbs_cipher.cur - id_start;
			DBG(DBG_CRYPT,
			    DBG_dump("idhash calc R2", id_start, id_len));
			hmac_update(&id_ctx, id_start, id_len);
			hmac_final(idhash_out, &id_ctx);
		}

		DBG(DBG_CONTROLMORE,
		    DBG_log("assembled IDr payload -- CERT next"));

		/*
		 * send CERT payload RFC 4306 3.6, 1.2:([CERT,] )
		 * upon which our received I2 CERTREQ is ignored,
		 * but ultimately should go into the CERT decision
		 */
		if (send_cert) {
			stf_status certstat = ikev2_send_cert(st, md,
							      O_RESPONDER,
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
			libreswan_log("No CHILD SA proposals received.");
			np = ISAKMP_NEXT_v2NONE;
		} else {
			DBG_log("CHILD SA proposals received");
			np = (c->pool != NULL && md->chain[ISAKMP_NEXT_v2CP] != NULL) ?
				ISAKMP_NEXT_v2CP :ISAKMP_NEXT_v2SA;
		}

		DBG(DBG_CONTROLMORE,
		    DBG_log("going to assemble AUTH payload"));

		/* now send AUTH payload */
		{
			stf_status authstat = ikev2_send_auth(c, st,
							      O_RESPONDER, np,
							      idhash_out,
							      &e_pbs_cipher);

			if (authstat != STF_OK)
				return authstat;
		}

		if (np == ISAKMP_NEXT_v2SA || np == ISAKMP_NEXT_v2CP) {
			/* must have enough to build an CHILD_SA */
			ret = ikev2_child_sa_respond(md, O_RESPONDER,
						     &e_pbs_cipher,
						     ISAKMP_v2_AUTH);
			if (ret > STF_FAIL) {
				v2_notify_num = ret - STF_FAIL;
				DBG(DBG_CONTROL,
				    DBG_log("ikev2_child_sa_respond returned STF_FAIL with %s",
					    enum_name(&ikev2_notify_names,
						      v2_notify_num)));
				np = ISAKMP_NEXT_v2NONE; /* use some day if we built a complete packet */
				return ret; /* we should continue building a valid reply packet */
			} else if (ret != STF_OK) {
				DBG_log("ikev2_child_sa_respond returned %s",
					enum_name(&stfstatus_name, ret));
				np = ISAKMP_NEXT_v2NONE; /* use some day if we built a complete packet */
				return ret; /* we should continue building a valid reply packet */
			}
		}

		if (!ikev2_padup_pre_encrypt(st, &e_pbs_cipher))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&e_pbs_cipher);

		{
			unsigned char *authloc = ikev2_authloc(st, &e_pbs);

			if (authloc == NULL)
				return STF_INTERNAL_ERROR;

			close_output_pbs(&e_pbs);

			close_output_pbs(&md->rbody);
			close_output_pbs(&reply_stream);

			ret = ikev2_encrypt_msg(st, O_RESPONDER,
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

	/* note: retransmission is driven by initiator */

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

/* STATE_PARENT_I2: R2 --> I3
 *                     <--  HDR, SK {IDr, [CERT,] AUTH,
 *                               SAr2, TSi, TSr}
 * [Parent SA established]
 */

stf_status ikev2parent_inR2(struct msg_digest *md)
{
	struct state *st = md->st;
	struct connection *c = st->st_connection;
	unsigned char idhash_in[MAX_DIGEST_LEN];
	struct state *pst = st;

	if (IS_CHILD_SA(st))
		pst = state_with_serialno(st->st_clonedfrom);

	/*
	 * the initiator sent us an encrypted payload. We need to calculate
	 * our g^xy, and skeyseed values, and then decrypt the payload.
	 */

	DBG(DBG_CONTROLMORE,
	    DBG_log("ikev2 parent inR2: calculating g^{xy} in order to decrypt I2"));

	/* decrypt things. */
	{
		stf_status ret = ikev2_decrypt_msg(md, O_INITIATOR);

		if (ret != STF_OK)
			return ret;
	}

	if (!ikev2_decode_peer_id(md, O_INITIATOR))
		return STF_FAIL + v2N_AUTHENTICATION_FAILED;

	{
		struct hmac_ctx id_ctx;
		const pb_stream *id_pbs = &md->chain[ISAKMP_NEXT_v2IDr]->pbs;
		unsigned char *idstart = id_pbs->start + NSIZEOF_isakmp_generic;
		unsigned int idlen = pbs_room(id_pbs) - NSIZEOF_isakmp_generic;

		hmac_init(&id_ctx, pst->st_oakley.prf_hasher,
				pst->st_skey_pr_nss);

		/* calculate hash of IDr for AUTH below */
		DBG(DBG_CRYPT, DBG_dump("idhash auth R2", idstart, idlen));
		hmac_update(&id_ctx, idstart, idlen);
		hmac_final(idhash_in, &id_ctx);
	}

	if (md->chain[ISAKMP_NEXT_v2CERT] != NULL) {
		/*
		 * should we check if we should accept a cert payload ?
		 *  has_preloaded_public_key(st)
		 */
		DBG(DBG_CONTROLMORE,
		    DBG_log("has a v2_CERT payload; going to decode it"));
		ikev2_decode_cert(md);
	}

	/* process AUTH payload */

	switch (md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2a.isaa_type) {
	case IKEv2_AUTH_RSA:
	{
		stf_status authstat = ikev2_verify_rsa_sha1(
				pst,
				O_INITIATOR,
				idhash_in,
				NULL,	/* keys from DNS */
				NULL,	/* gateways from DNS */
				&md->chain[ISAKMP_NEXT_v2AUTH]->pbs);

		if (authstat != STF_OK) {
			libreswan_log("RSA authentication failed");
			/*
			 * ??? this could be
			 * return STF_FAIL + v2N_AUTHENTICATION_FAILED
			 * but that would be ignored by the logic in
			 * complete_v2_state_transition()
			 * that says "only send a notify is this packet was a question, not if it was an answer"
			 */
			SEND_V2_NOTIFICATION(v2N_AUTHENTICATION_FAILED);
			return STF_FAIL;
		}
		break;
	}
	case IKEv2_AUTH_PSK:
	{
		stf_status authstat = ikev2_verify_psk_auth(
				pst,
				O_INITIATOR,
				idhash_in,
				&md->chain[ISAKMP_NEXT_v2AUTH]->pbs);

		if (authstat != STF_OK) {
			libreswan_log("PSK authentication failed");
			/*
			 * ??? this could be
			 * return STF_FAIL + v2N_AUTHENTICATION_FAILED
			 * but that would be ignored by the logic in
			 * complete_v2_state_transition()
			 * that says "only send a notify is this packet was a question, not if it was an answer"
			 */
			SEND_V2_NOTIFICATION(v2N_AUTHENTICATION_FAILED);
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

	/* authentication good */

#ifdef USE_LINUX_AUDIT
	linux_audit_conn(st, LAK_PARENT_START);
#endif

	/* TODO: see if there are any notifications */

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
		 */
		return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
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
		const int tsi_n = ikev2_parse_ts(tsi_pd, tsi, elemsof(tsi));
		const int tsr_n = ikev2_parse_ts(tsr_pd, tsr, elemsof(tsr));

		if (tsi_n < 0 || tsr_n < 0)
			return STF_FAIL + v2N_TS_UNACCEPTABLE;

		DBG(DBG_CONTROLMORE, DBG_log("Checking TSi(%d)/TSr(%d) selectors, looking for exact match",
			tsi_n, tsr_n));

		{
			struct spd_route *sra;
			sra = &c->spd;
			int bfit_n = ikev2_evaluate_connection_fit(c, sra,
								   O_INITIATOR,
								   tsi, tsr,
								   tsi_n,
								   tsr_n);
			if (bfit_n > bestfit_n) {
				DBG(DBG_CONTROLMORE,
				    DBG_log("prefix fitness found a better match c %s",
					    c->name));
				int bfit_p = ikev2_evaluate_connection_port_fit(
						c, sra, O_INITIATOR,
						tsi, tsr,
						tsi_n, tsr_n,
						&best_tsi_i, &best_tsr_i);

				if (bfit_p > bestfit_p) {
					DBG(DBG_CONTROLMORE,
					    DBG_log("port fitness found better match c %s, tsi[%d],tsr[%d]",
						    c->name, best_tsi_i, best_tsr_i));
					int bfit_pr = ikev2_evaluate_connection_protocol_fit(
							c, sra, O_INITIATOR, tsi,
							tsr, tsi_n, tsr_n,
							&best_tsi_i,
							&best_tsr_i);
					if (bfit_pr > bestfit_pr ) {
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
			rangetosubnet(&st->st_ts_this.low,
				      &st->st_ts_this.high, &tmp_subnet_i);
			rangetosubnet(&st->st_ts_that.low,
				      &st->st_ts_that.high, &tmp_subnet_r);

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

	{
		struct payload_digest *const sa_pd =
			md->chain[ISAKMP_NEXT_v2SA];
		stf_status ret = ikev2_parse_child_sa_body(&sa_pd->pbs,
					       NULL, st, TRUE);

		if (ret != STF_OK)
			return ret;
	}

	/* are we expecting a v2CP (RESP) ?  */
	if(c->spd.this.modecfg_client) {
		if (md->chain[ISAKMP_NEXT_v2CP] == NULL){
			/* not really anything to here... but it would be worth unpending again */
			libreswan_log("missing v2CP reply, not attempting to setup child SA");
			/*  Delete previous retransmission event.  */
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
			    v2N_USE_TRANSPORT_MODE ) {
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
static bool ikev2_get_dcookie(u_char *dcookie, chunk_t ni,
			      ip_address *addr, chunk_t spiI)
{
	size_t addr_length;
	SHA1_CTX ctx_sha1;
	unsigned char addr_buff[
		sizeof(union { struct in_addr A;
			       struct in6_addr B;
		       })];

	addr_length = addrbytesof(addr, addr_buff, sizeof(addr_buff));
	SHA1Init(&ctx_sha1);
	SHA1Update(&ctx_sha1, ni.ptr, ni.len);
	SHA1Update(&ctx_sha1, addr_buff, addr_length);
	SHA1Update(&ctx_sha1, spiI.ptr, spiI.len);
	SHA1Update(&ctx_sha1, ikev2_secret_of_the_day,
		   SHA1_DIGEST_SIZE);
	SHA1Final(dcookie, &ctx_sha1);
	DBG(DBG_PRIVATE,
	    DBG_log("ikev2 secret_of_the_day used %s, length %d",
		    ikev2_secret_of_the_day,
		    SHA1_DIGEST_SIZE));

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

void send_v2_notification(struct state *p1st,
			  v2_notification_t type,
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
			enum_name(&ikev2_notify_names, type),
			ipstr(&p1st->st_remoteaddr, &b),
			p1st->st_remoteport);
	}

	zero(&buffer);
	init_pbs(&reply_stream, buffer, sizeof(buffer), "notification msg");

	/* HDR out */
	{
		struct isakmp_hdr hdr;

		zero(&hdr);
		hdr.isa_version = build_ikev2_version();
		memcpy(hdr.isa_rcookie, rcookie, COOKIE_SIZE);
		memcpy(hdr.isa_icookie, icookie, COOKIE_SIZE);
		hdr.isa_xchg = ISAKMP_v2_SA_INIT;
		hdr.isa_np = ISAKMP_NEXT_v2N;
		/* XXX unconditionally clearing original initiator flag is wrong */
		hdr.isa_flags &= ~ISAKMP_FLAGS_v2_IKE_I;
		/* add msg responder flag */
		hdr.isa_flags |= ISAKMP_FLAGS_v2_MSG_R;
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
		 type, n_data, &rbody))
		return;	/* ??? NO WAY TO SIGNAL INTERNAL ERROR */

	if (!close_message(&rbody, p1st))
		return; /* ??? NO WAY TO SIGNAL INTERNAL ERROR */

	close_output_pbs(&reply_stream);

	clonetochunk(p1st->st_tpacket, reply_stream.start, pbs_offset(&reply_stream),
		     "notification packet");

	send_ike_msg(p1st, __FUNCTION__);
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

	DBG(DBG_CONTROLMORE,
	    DBG_log("Adding a v2N Payload"));
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

stf_status ikev2_child_inIoutR(struct msg_digest *md)
{
	struct state *pst = md->st;
	struct state *st; /* child state */

	if (IS_CHILD_SA(pst))
		pst = state_with_serialno(pst->st_clonedfrom);

	DBG(DBG_CONTROLMORE,
		DBG_log("ikev2 decrypt CREATE_CHILD_SA request"));

	/* decrypt message */
	{
		stf_status ret = ikev2_decrypt_msg(md, O_RESPONDER);

		if (ret != STF_OK)
			return ret;
	}

	st = duplicate_state(pst);	/* create child state */
	set_cur_state(st);	/* (caller will reset) */
	md->st = st;		/* feed back new state. ??? better way to do */
	insert_state(st); /* needed for delete - we are duplicating early */

	if (md->chain[ISAKMP_NEXT_v2KE] != NULL) {
		/* in CREATE_CHILD_SA exchange we don't support new KE */
		ipstr_buf b;

		libreswan_log( "rejecting create child SA from %s:%u -- new KE in DH is not supported",
				ipstr(&md->sender, &b), md->sender_port);
		return STF_FAIL + v2N_INVALID_KE_PAYLOAD;
	}

	freeanychunk(st->st_ni); /* this is from the parent. */
	freeanychunk(st->st_nr); /* this is from the parent. */

	RETURN_STF_FAILURE(accept_v2_nonce(md, &st->st_ni, "Ni"));

	/* calculate new nonce and the KE */
	{
		struct pluto_crypto_req_cont *qke = new_pcrc(
			ikev2_child_inIoutR_continue, "IKEv2 CHILD KE AND NONCE",
			st, md);
		stf_status e;
		enum crypto_importance ci;

		ci = pcim_ongoing_crypto;
		if (ci < st->st_import)
			ci = st->st_import;
		/*
		 * ??? I'm not sure of the logic of this bit.
		 * For one thing, no KE, despite mentions above.
		 */

		if (!st->st_sec_in_use) {
			DBG(DBG_CONTROLMORE, DBG_log("Generate new nonce for CREATE_CHILD_SA exchange."));
			e = build_nonce(qke, ci);
		} else {
			e = ikev2_child_inIoutR_tail(qke, NULL);
			/* ??? who frees qke? */
		}
		reset_globals();
		return e;
	}
}

/* redundant type assertion: static crypto_req_cont_func ikev2_child_inIoutR_continue; */

static void ikev2_child_inIoutR_continue(struct pluto_crypto_req_cont *qke,
		struct pluto_crypto_req *r)
{
	struct msg_digest *md = qke->pcrc_md;
	struct state *const st = md->st;
	stf_status e;

	DBG(DBG_CRYPT | DBG_CONTROL,
			DBG_log("ikev2_child_inIoutR_continue for #%lu: calculated ke+nonce"
				" sending CREATE_CHILD_SA respone", qke->pcrc_serialno));
	if (qke->pcrc_serialno == SOS_NOBODY) {
		loglog(RC_LOG_SERIOUS,
		       "%s: Request was disconnected from state", __FUNCTION__);
		release_any_md(&qke->pcrc_md);
		return;
	}

	passert(qke->pcrc_serialno == st->st_serialno);	/* transitional */

	passert(cur_state == NULL);
	passert(st != NULL);

	passert(st->st_suspended_md == qke->pcrc_md);
	unset_suspended(st); /* no longer connected or suspended */

	set_cur_state(st);

	DBG(DBG_CONTROLMORE, DBG_log("#%lu %s:%u st->st_calculating = FALSE;", st->st_serialno, __FUNCTION__, __LINE__));
	st->st_calculating = FALSE;

	e = ikev2_child_inIoutR_tail(qke, r);

	passert(qke->pcrc_md != NULL);
	complete_v2_state_transition(&qke->pcrc_md, e);
	release_any_md(&qke->pcrc_md);
	reset_globals();
}

static stf_status ikev2_child_inIoutR_tail(struct pluto_crypto_req_cont *qke,
				        struct pluto_crypto_req *r)
{
	struct msg_digest *md = qke->pcrc_md;
	struct state *st = md->st;
        struct state *pst = st;
	unsigned char *authstart;
	unsigned char *encstart;
	unsigned char *iv;
	struct ikev2_generic e;
	pb_stream e_pbs, e_pbs_cipher;
	stf_status ret;

	zero(&reply_buffer);
	init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer), "reply packet");
	authstart = reply_stream.cur;

	/* HDR out */
	{
		struct isakmp_hdr hdr;

		zero(&hdr);
		hdr.isa_version = build_ikev2_version();
		/* add message responder flag */
		hdr.isa_flags |= ISAKMP_FLAGS_v2_MSG_R;
		memcpy(hdr.isa_rcookie, pst->st_rcookie, COOKIE_SIZE);
		memcpy(hdr.isa_icookie, pst->st_icookie, COOKIE_SIZE);
		hdr.isa_xchg = ISAKMP_v2_CREATE_CHILD_SA;
		hdr.isa_np = ISAKMP_NEXT_v2E;
		hdr.isa_msgid = htonl(md->msgid_received);

		/* encryption role based on original originator */
		if (IS_V2_INITIATOR(pst->st_state)) {
			md->role = O_INITIATOR;
			/* add original initiator flag */
			hdr.isa_flags |= ISAKMP_FLAGS_v2_IKE_I;
		} else {
			md->role = O_RESPONDER;
			/* not adding original initiator flag */
		}

		if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
			hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
		}

		if (!out_struct(&hdr, &isakmp_hdr_desc,
				&reply_stream, &md->rbody)) {
			libreswan_log("error initializing hdr for CREATE_CHILD_SA message");
			return STF_FATAL;
		}
	} /* HDR done */

	/* insert an Encryption payload header */
	e.isag_np = ISAKMP_NEXT_v2SA;
	e.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;
	if (!out_struct(&e, &ikev2_e_desc, &md->rbody, &e_pbs))
		return STF_INTERNAL_ERROR;

	/* IV */
	iv = e_pbs.cur;
	if (!emit_iv(st, &e_pbs))
		return STF_INTERNAL_ERROR;

	/* note where cleartext starts */
	init_pbs(&e_pbs_cipher, e_pbs.cur, e_pbs.roof - e_pbs.cur,
			"cleartext CREATE_CHILD_SA reply");

	e_pbs_cipher.container = &e_pbs;
	e_pbs_cipher.desc = NULL;
	e_pbs_cipher.cur = e_pbs.cur;
	encstart = e_pbs_cipher.cur;

	unpack_nonce(&st->st_nr, r);

	ret = ikev2_child_sa_respond(md, O_RESPONDER, &e_pbs_cipher,
			ISAKMP_v2_CREATE_CHILD_SA);

	if (ret > STF_FAIL) {
		int v2_notify_num = ret - STF_FAIL;

		DBG_log("ikev2_child_sa_respond returned STF_FAIL with %s",
				enum_name(&ikev2_notify_names, v2_notify_num));
	} else if (ret != STF_OK) {
		DBG_log("ikev2_child_sa_respond returned %s",
				enum_name(&stfstatus_name, ret));
	}
	if (!ikev2_padup_pre_encrypt(st, &e_pbs_cipher))
		return STF_INTERNAL_ERROR;

	close_output_pbs(&e_pbs_cipher);

	{
		unsigned char *authloc = ikev2_authloc(st, &e_pbs);

		if (authloc == NULL)
			return STF_INTERNAL_ERROR;

		close_output_pbs(&e_pbs);
		close_output_pbs(&md->rbody);
		close_output_pbs(&reply_stream);
		ret = ikev2_encrypt_msg(st, O_RESPONDER, authstart, iv, encstart,
				authloc, &e_pbs, &e_pbs_cipher);

		if (ret != STF_OK)
			return ret;
	}

	freeanychunk(pst->st_tpacket);
	clonetochunk(pst->st_tpacket, reply_stream.start, pbs_offset(&reply_stream), "reply packet for CREATE_CHILD_SA exchange");

	send_ike_msg(pst, __FUNCTION__);

	return STF_OK;
}

stf_status process_encrypted_informational_ikev2(struct msg_digest *md)
{
	struct state *st = md->st;
	enum phase1_role prole;	/* parent SA's role */

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

	/* Since an informational exchange can be started by the original responder,
	 * things such as encryption, decryption should be done based on the original
	 * role and not the md->role
	 */
	if (IS_V2_INITIATOR(st->st_state)) {
		prole = O_INITIATOR;
		DBG(DBG_CONTROLMORE,
		    DBG_log("received informational exchange request from the original responder"));
	} else {
		prole = O_RESPONDER;
		DBG(DBG_CONTROLMORE,
		    DBG_log("received informational exchange request from the original initiator"));
	}

	/* decrypt message */
	{
		stf_status ret = ikev2_decrypt_msg(md, prole);

		if (ret != STF_OK)
			return ret;
	}

	/*
	 * Generate response message,
	 * but only if we are the Responder in this exchange.
	 * (If we're the Initiator, we've already had our turn.)
	 */
	if ((md->hdr.isa_flags & ISAKMP_FLAGS_v2_MSG_R) == 0) {
		pb_stream e_pbs, e_pbs_cipher;
		struct ikev2_generic e;
		unsigned char *iv;
		unsigned char *encstart;
		unsigned char *authstart = reply_stream.cur;
		struct payload_digest *p;

		/* make sure HDR is at start of a clean buffer */
		zero(&reply_buffer);
		init_pbs(&reply_stream, reply_buffer,
			 sizeof(reply_buffer),
			 "information exchange reply packet");

		DBG(DBG_CONTROLMORE | DBG_DPD,
		    DBG_log("updating st_last_liveness, no pending_liveness"));

		st->st_last_liveness = mononow();
		st->st_pend_liveness = FALSE;

		/* HDR out */
		{
			struct isakmp_hdr hdr;

			zero(&hdr); /* default to 0 */
			hdr.isa_version = build_ikev2_version();
			memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
			memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
			hdr.isa_xchg = ISAKMP_v2_INFORMATIONAL;
			hdr.isa_np = ISAKMP_NEXT_v2E;
			hdr.isa_msgid = htonl(md->msgid_received);
			hdr.isa_flags |= ISAKMP_FLAGS_v2_MSG_R;
			if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
				hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
			}

			if (!out_struct(&hdr, &isakmp_hdr_desc,
					&reply_stream, &md->rbody)) {
				libreswan_log(
					"error initializing hdr for informational message");
				return STF_INTERNAL_ERROR;
			}

		} /* HDR Done */


		/* insert an Encryption payload header */

		/*
		 * We only process Delete Payloads. The rest are
		 * ignored.
		 *
		 * If no delete payloads were received, the Next
		 * Payload type to send will be NONE.
		 *
		 * IKE SA Delete cannot be combined with anything
		 * else (including IPsec SA Delete) and its confirmation
		 * is an empty message so Next Payload type would be
		 * NONE.
		 *
		 * There can be any number of IPsec SA Delete payloads
		 * and the next payload type will be v2D or NONE.
		 *
		 * The next code chunk looks at the delete payload(s)
		 * to see if message is deleting an IKE SA or and IPsec SA
		 * or neither.
		 */
		e.isag_np = ISAKMP_NEXT_v2NONE;
		if (md->chain[ISAKMP_NEXT_v2D] != NULL) {
			/* IKE SA delete payloads are always by themselves */
			struct ikev2_delete *v2del =
				&md->chain[ISAKMP_NEXT_v2D]->payload.v2delete;

			if (v2del->isad_protoid == PROTO_ISAKMP) {
				if (md->chain[ISAKMP_NEXT_v2D]->next != NULL) {
					libreswan_log(
						"IKE SA Delete must be the only payload");
					return STF_FAIL + v2N_INVALID_SYNTAX;
				}
				if (v2del->isad_nrspi != 0 ||
					v2del->isad_spisize != 0) {
					libreswan_log("IKE SA Delete has non-zero SPI size or number of SPIs");
					return STF_FAIL + v2N_INVALID_SYNTAX;
				}
			} else {
				e.isag_np = ISAKMP_NEXT_v2D;
			}
		}

		e.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;

		if (!out_struct(&e, &ikev2_e_desc, &md->rbody, &e_pbs))
			return STF_INTERNAL_ERROR;

		/* insert IV */
		iv = e_pbs.cur;
		if (!emit_iv(st, &e_pbs))
			return STF_INTERNAL_ERROR;

		/* note where cleartext starts in output */
		init_pbs(&e_pbs_cipher, e_pbs.cur,
			 e_pbs.roof - e_pbs.cur, "cleartext");
		e_pbs_cipher.container = &e_pbs;
		e_pbs_cipher.desc = NULL;
		e_pbs_cipher.cur = e_pbs.cur;
		encstart = e_pbs_cipher.cur;

		/*
		 * Pass 1: scan incoming Delete Payloads,
		 * generating the contents of the Response packet
		 */
		for (p = md->chain[ISAKMP_NEXT_v2D]; p != NULL; p = p->next) {
			/* Gather all the IPsec SPIs corresponding to SPIs in this message */
			struct ikev2_delete *v2del = &p->payload.v2delete;

			switch (v2del->isad_protoid) {
			case PROTO_ISAKMP:
				/*
				 * There can be only one Delete Payload
				 * if it is ISAKMP
				 */
				passert(p == md->chain[ISAKMP_NEXT_v2D]);
				break;

			case PROTO_IPSEC_AH:
			case PROTO_IPSEC_ESP:
			{
				ipsec_spi_t spi_buf[128];
				u_int16_t j = 0;	/* number of SPIs in spi_buf */
				u_int8_t *spi_start = p->pbs.cur;	/* save for next pass */
				pb_stream del_pbs;	/* output stream */
				struct ikev2_delete v2del_tmp;
				u_int16_t i;

				if (v2del->isad_spisize != sizeof(ipsec_spi_t)){
					libreswan_log("IPsec Delete Notification has invalid SPI size %u",
						v2del->isad_spisize);
					return STF_FAIL + v2N_INVALID_SYNTAX;
				}

				if (v2del->isad_nrspi * v2del->isad_spisize != pbs_left(&p->pbs)) {
					libreswan_log("IPsec Delete Notification payload size is %tu but %u is required",
						pbs_left(&p->pbs),
						v2del->isad_nrspi * v2del->isad_spisize);
					return STF_FAIL + v2N_INVALID_SYNTAX;
				}

				for (i = 0; i < v2del->isad_nrspi; i++)
				{
					ipsec_spi_t spi;

					if (!in_raw(&spi, sizeof(spi), &p->pbs, "SPI"))
						return STF_INTERNAL_ERROR;

					DBG(DBG_CONTROLMORE,
						DBG_log("received delete request for %s SA(0x%08" PRIx32 ")",
							enum_show(&protocol_names,
								v2del->isad_protoid),
							ntohl(spi)));

					struct state *dst =
						find_state_ikev2_child_to_delete(
							st->st_icookie,
							st->st_rcookie,
							v2del->isad_protoid,
							spi);

					if (dst != NULL) {
						struct ipsec_proto_info *pr =
							v2del->isad_protoid == PROTO_IPSEC_AH ?
								&dst->st_ah :
								&dst->st_esp;

						DBG(DBG_CONTROLMORE,
							DBG_log("our side SPI that needs to be sent: %s SA(0x%08" PRIx32 ")",
								enum_show(&protocol_names,
									v2del->isad_protoid),
								ntohl(pr->our_spi)));
						if (j < elemsof(spi_buf)) {
							spi_buf[j] = pr->our_spi;
							j++;
						} else {
							libreswan_log("too many SPIs in Delete Notification payload; ignoring 0x%08" PRIx32,
								ntohl(spi));
						}
					} else {
						/* ??? should this diagnostic go to the real log? */
						DBG(DBG_CONTROLMORE,
							DBG_log("received delete request for %s SA(0x%08" PRIx32 ") but local state is not found",
								enum_show(&protocol_names,
									v2del->isad_protoid),
								ntohl(spi)));
					}
				}

				p->pbs.cur = spi_start;	/* restore for next pass */

				if (j == 0) {
					DBG(DBG_CONTROLMORE, DBG_log(
						    "This IPsec delete payload does not contain a single SPI that has any local state; ignoring"));
					return STF_IGNORE;
				} else {
					DBG(DBG_CONTROLMORE, {
						DBG_log(
							"Number of SPIs to be sent %d",
							j);
						DBG_dump(" Emit SPIs",
							spi_buf,
							j * sizeof(spi_buf[0]));
					});
				}

				/* build output Delete Payload */
				zero(&v2del_tmp);

				v2del_tmp.isad_np = p->next == NULL ?
					ISAKMP_NEXT_v2NONE : ISAKMP_NEXT_v2D;

				v2del_tmp.isad_protoid =
					v2del->isad_protoid;
				v2del_tmp.isad_spisize =
					v2del->isad_spisize;
				v2del_tmp.isad_nrspi = j;

				/* Emit delete payload header out */
				if (!out_struct(&v2del_tmp,
						&ikev2_delete_desc,
						&e_pbs_cipher,
						&del_pbs))
				{
					libreswan_log(
						"error initializing hdr for delete payload");
					return STF_INTERNAL_ERROR;
				}

				/* Emit values of SPI to be sent to the peer */
				if (!out_raw(spi_buf,
						j * sizeof(spi_buf[0]),
						&del_pbs,
						"local SPIs"))
				{
					libreswan_log(
						"error sending SPI values in delete payload");
					return STF_INTERNAL_ERROR;
				}

				close_output_pbs(&del_pbs);
			}
			break;

			default:
				bad_case(v2del->isad_protoid);
			}
		}

		/*
		 * We've now build up the content (if any) of the Response:
		 *
		 * - empty, if there were no Delete Payloads.  Treat as a check
		 *   for liveness.  Correct response is this empty Response.
		 *
		 * - if a (solitary) ISAKMP SA is mentioned in input message,
		 *   we are sending that back.
		 *
		 * - if IPsec SAs were mentioned, we are sending that back too.
		 *
		 * Now's the time to close up the packet.
		 */

		if (!ikev2_padup_pre_encrypt(st, &e_pbs_cipher))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&e_pbs_cipher);

		{
			stf_status ret;
			unsigned char *authloc = ikev2_authloc(st,
							       &e_pbs);
			if (authloc == NULL)
				return STF_INTERNAL_ERROR;

			close_output_pbs(&e_pbs);
			close_output_pbs(&md->rbody);
			close_output_pbs(&reply_stream);

			ret = ikev2_encrypt_msg(st, prole,
						authstart,
						iv, encstart, authloc,
						&e_pbs, &e_pbs_cipher);
			if (ret != STF_OK)
				return ret;
		}


		/* keep it for a retransmit if necessary */
		freeanychunk(st->st_tpacket);
		clonetochunk(st->st_tpacket, reply_stream.start,
			     pbs_offset(&reply_stream),
			     "reply packet for informational exchange");

		send_ike_msg(st, __FUNCTION__);
	}

	/* end of Responder-only code */

	/*
	 * Pass over the Notification Payloads.
	 *
	 * This is the first pass if we are the Initiator,
	 * Looking at the Responder's response.
	 *
	 * This is the second pass if we are the Responder.
	 *
	 * In either case, we carry out the actual deletion task.
	 * ??? Unless st->st_state == STATE_IKESA_DEL.
	 */

	if ((md->hdr.isa_flags & ISAKMP_FLAGS_v2_MSG_R) &&
	    st->st_state == STATE_IKESA_DEL) {
		/*
		 * this must be a response to our IKE SA delete request
		 * Even if there are are other Delete Payloads,
		 * the cannot matter: we delete the family.
		 */
		delete_my_family(st, TRUE);
		md->st = st = NULL;
	} else if ((md->hdr.isa_flags & ISAKMP_FLAGS_v2_MSG_R) &&
		   md->chain[ISAKMP_NEXT_v2D] == NULL) {
		/* A liveness update response */
		DBG(DBG_CONTROLMORE,
		    DBG_log("Received an INFORMATIONAL response; updating liveness, no longer pending."));
		st->st_last_liveness = mononow();
		st->st_pend_liveness = FALSE;
		ikev2_update_msgid_counters(md);
	} else {
		/*
		 * IPsec SA deletion
		 * Unless there are no payloads, in which case this is a no-op.
		 */
		struct payload_digest *p;

		for (p = md->chain[ISAKMP_NEXT_v2D]; p != NULL;
		     p = p->next) {
			struct ikev2_delete *v2del =
				&p->payload.v2delete;

			switch (v2del->isad_protoid) {
			case PROTO_ISAKMP: /* Parent SA */
				/* ??? I don't think that this should happen */
				delete_my_family(st, TRUE);
				md->st = st = NULL;
				break;

			case PROTO_IPSEC_AH: /* Child SAs */
			case PROTO_IPSEC_ESP: /* Child SAs */
			{
				u_int16_t i;

				if (v2del->isad_spisize != sizeof(ipsec_spi_t)) {
					libreswan_log("IPsec Delete SPI size should be 4 but is %u",
						v2del->isad_spisize);
					return STF_FAIL + v2N_INVALID_SYNTAX;
				}

				if (v2del->isad_nrspi * sizeof(ipsec_spi_t) != pbs_left(&p->pbs)) {
					libreswan_log("IPsec Delete SPI payload wrong size (expected %u; got %u)",
						(unsigned) (v2del->isad_nrspi * sizeof(ipsec_spi_t)),
						(unsigned) pbs_left(&p->pbs));
					return STF_FAIL + v2N_INVALID_SYNTAX;
				}

				for (i = 0; i < v2del->isad_nrspi; i++ ) {
					ipsec_spi_t spi;

					if (!in_raw(&spi, sizeof(spi), &p->pbs, "SPI"))
						return STF_INTERNAL_ERROR;	/* cannot happen */

					DBG(DBG_CONTROLMORE, DBG_log(
						    "delete %s SA(0x%08" PRIx32 ")",
						    enum_show(&protocol_names,
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
					if (dst != NULL) {
						DBG(DBG_CONTROLMORE,
							DBG_log("our side SPI that needs to be deleted: %s SA(0x%08" PRIx32 ")",
								enum_show(&protocol_names,
									v2del->isad_protoid),
								ntohl((uint32_t)spi)));

						passert(dst != st);	/* st is a parent */
						/* now delete the state */
						change_state(dst,
							STATE_CHILDSA_DEL);
						delete_state(dst);
						/* note: md->st != dst */
					} else {
						libreswan_log(
						    "received delete request for %s SA(0x%08" PRIx32 ") but corresponding state not found",
							    enum_show(&protocol_names, v2del->isad_protoid),
								ntohl((uint32_t)spi));
					}
				}
			}
			break;

			default:
				/* Unrecognized protocol */
				/* ??? diagnostic?  Failure? */
				return STF_IGNORE;
			}

			/*
			 * If we just deleted the Parent SA, the Child SAs are being torn down as well,
			 * so no point checking the other delete SA payloads here
			 */
			if (v2del->isad_protoid == PROTO_ISAKMP)
				break;

		}  /* for */
	}

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

		/* encryption role based on role in INIT, not role in this exchange */
		enum phase1_role role = IS_V2_INITIATOR(pst->st_state) ?
			O_INITIATOR : O_RESPONDER;

		struct ikev2_generic e;
		pb_stream e_pbs, e_pbs_cipher;
		pb_stream rbody;
		pb_stream reply_stream;

		zero(&buffer);
		init_pbs(&reply_stream, buffer, sizeof(buffer),
			 "informational exchange request packet");
		authstart = reply_stream.cur;

		/* HDR out */
		{
			struct isakmp_hdr hdr;
			zero(&hdr);
			hdr.isa_version = build_ikev2_version();
			memcpy(hdr.isa_rcookie, pst->st_rcookie, COOKIE_SIZE);
			memcpy(hdr.isa_icookie, pst->st_icookie, COOKIE_SIZE);
			hdr.isa_xchg = ISAKMP_v2_INFORMATIONAL;
			hdr.isa_np = ISAKMP_NEXT_v2E;
			hdr.isa_msgid = htonl(pst->st_msgid_nextuse);

			/* encryption role based on original state not md state */
			if (IS_V2_INITIATOR(pst->st_state)) {
				hdr.isa_flags |= ISAKMP_FLAGS_v2_IKE_I;
			} else {
				/* not setting original initiator flag */
			}
			/* not setting message responder flag */

			if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
				hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
			}

			if (!out_struct(&hdr, &isakmp_hdr_desc,
					&reply_stream, &rbody)) {
				libreswan_log(
					"error initializing hdr for informational message");
				return STF_FATAL;
			}
		}

		/* insert an Encryption payload header */
		e.isag_np = ISAKMP_NEXT_v2NONE;
		e.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;
		if (!out_struct(&e, &ikev2_e_desc, &rbody, &e_pbs))
			return STF_FATAL;

		/* IV */
		iv = e_pbs.cur;
		if (!emit_iv(st, &e_pbs))
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
			unsigned char *authloc = ikev2_authloc(st, &e_pbs);

			if (authloc == NULL)
				return STF_FATAL;

			close_output_pbs(&e_pbs);
			close_output_pbs(&rbody);
			close_output_pbs(&reply_stream);

			ret = ikev2_encrypt_msg(st, role,
						authstart,
						iv, encstart, authloc,
						&e_pbs, &e_pbs_cipher);
			if (ret != STF_OK)
				return STF_FATAL;
		}

		/* keep it for a retransmit if necessary */
		freeanychunk(pst->st_tpacket);
		clonetochunk(pst->st_tpacket, reply_stream.start,
			     pbs_offset(&reply_stream),
			     "reply packet for informational exchange");
		pst->st_pend_liveness = TRUE; /* we should only do this when dpd/liveness is active? */
		send_ike_msg(pst, __FUNCTION__);
	}

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
	enum phase1_role role;

	/* make sure HDR is at start of a clean buffer */
	zero(&reply_buffer);
	init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		 "information exchange request packet");
	/* beginning of data going out */
	authstart = reply_stream.cur;

	/* HDR out */
	{
		struct isakmp_hdr hdr;
		zero(&hdr);
		hdr.isa_version = build_ikev2_version();
		memcpy(hdr.isa_rcookie, pst->st_rcookie, COOKIE_SIZE);
		memcpy(hdr.isa_icookie, pst->st_icookie, COOKIE_SIZE);
		hdr.isa_xchg = ISAKMP_v2_INFORMATIONAL;
		hdr.isa_np = ISAKMP_NEXT_v2E;
		hdr.isa_msgid = htonl(pst->st_msgid_nextuse);

		/* set Initiator flag if we are the IKE Original Initiator */
		/*
		 * ??? is this isa_flag setting correct?
		 * Should it not reflect *this* exchange?
		 */
		if (pst->st_state == STATE_PARENT_I2 ||
		    pst->st_state == STATE_PARENT_I3) {
			role = O_INITIATOR;
			hdr.isa_flags |= ISAKMP_FLAGS_v2_IKE_I;
		} else {
			role = O_RESPONDER;
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

	if (!out_struct(&e, &ikev2_e_desc, &rbody, &e_pbs))
		return FALSE;

	/* insert IV */
	iv = e_pbs.cur;
	if (!emit_iv(st, &e_pbs))
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

		zero(&v2del_tmp);
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
				&e_pbs_cipher, &del_pbs)) {
			libreswan_log(
				"error initializing hdr for delete payload");
			return FALSE;
		}

		/* Emit values of spi to be sent to the peer */
		if (IS_CHILD_SA(st)) {
			if (!out_raw((u_char *)&st->st_esp.our_spi,
				     sizeof(ipsec_spi_t), &del_pbs,
				     "local spis")) {
				libreswan_log(
					"error sending spi values in delete payload");
				return FALSE;
			}
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

		if (authloc == NULL)
			return FALSE;

		close_output_pbs(&e_pbs);
		close_output_pbs(&rbody);
		close_output_pbs(&reply_stream);

		ret = ikev2_encrypt_msg(st, role,
					authstart,
					iv, encstart, authloc,
					&e_pbs, &e_pbs_cipher);
		if (ret != STF_OK)
			return FALSE;
	}

	/* keep it for a retransmit if necessary */
	freeanychunk(pst->st_tpacket);
	clonetochunk(pst->st_tpacket, reply_stream.start,
		     pbs_offset(&reply_stream),
		     "request packet for informational exchange");

	send_ike_msg(pst, __FUNCTION__);

	/*
	 * delete messages may not be acknowledged.
	 * increase message ID for next delete message
	 */
	pst->st_msgid_nextuse++;

	/*
	 * We should update state to relect msgid's:
	 *   ikev2_update_msgid_counters(&md);
	 * But we have no idea!
	 * This was a fake exchange.
	 */
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
#if 0	/* ??? deleting is done by delete_state (caller's caller), unconditionally; we must not */
		if (!res) {
			/* prepare to delete ourself */
			change_state(st, STATE_CHILDSA_DEL);
			delete_state(st);
			if (md->st == st)
				md->st = st = NULL;	/* but we don't have an md! */
		}
#endif
	} else {
		/* Parent SA */
		res = ikev2_delete_out_guts(st, st);
#if 0	/* ??? deleting is done by delete_state (caller's caller), unconditionally; we must not */
		if (!res) {
			/* delete our children and
			 * then prepare to delete ourself.
			 * Our children will be on the same hash chain
			 * because we share IKE SPIs.
			 */
			delete_my_family(st, TRUE);
			md->st = st = NULL;	/* but we don't have an md! */
		}
#endif
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
static int build_ikev2_version()
{
/* TODO: if bumping, we should also set the Version flag in the ISAKMP haeder */
return ((IKEv2_MAJOR_VERSION + (DBGP(IMPAIR_MAJOR_VERSION_BUMP) ? 1 : 0))
	<< ISA_MAJ_SHIFT) | (IKEv2_MINOR_VERSION +
	(DBGP(IMPAIR_MINOR_VERSION_BUMP) ? 1 : 0));
}
