/*
 * IKEv2 parent SA creation routines, for Libreswan
 *
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi
 * Copyright (C) 2012-2015 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012,2014 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2015-2016 Andrew Cagney <andrew.cagney@gmail.com>
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

#include "crypto.h" /* requires sha1.h and md5.h */
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
#include "pam_conv.h"
#include "alg_info.h" /* for ALG_INFO_IKE_FOREACH */
#include "key.h" /* for SECKEY_DestroyPublicKey */
#include "vendor.h"

#include "ietf_constants.h"

#include "hostpair.h"

extern bool pluto_drop_oppo_null;

#ifdef XAUTH_HAVE_PAM
struct ikev2_pam_helper {
	struct pam_thread_arg pam;	/* writable inside thread */
	bool pam_status;		/* set inside the thread */
	pthread_t tid;                  /* set before thread */
	bool in_use;                    /* set before and inside thread */
	struct timeval start_time;      /* set before thread */
	struct timeval done_time;       /* set inside thread */
	struct ikev2_pam_helper *next;  /* set outside thread */
	int master_fd;                  /* master's fd (-1 if none) */
	int helper_fd;                  /* helper's fd */
	struct event *evm;              /* callback event on master_fd. */
};

static struct ikev2_pam_helper *pluto_v2_pam_helpers = NULL;
#endif

static stf_status ikev2_parent_inI2outR2_auth_tail( struct msg_digest *md, bool pam_status);

static crypto_req_cont_func ikev2_parent_outI1_continue;	/* type assertion */

static stf_status ikev2_parent_outI1_tail(struct pluto_crypto_req_cont *ke,
					  struct pluto_crypto_req *r);

static void ikev2_get_dcookie(u_char *dcookie, chunk_t st_ni,
			      ip_address *addr, chunk_t spiI);

static stf_status ikev2_parent_outI1_common(struct msg_digest *md,
					    struct state *st);

static int build_ikev2_version(void);

static crypto_req_cont_func ikev2_child_inIoutR_continue;	/* type assertion */

static stf_status ikev2_child_inIoutR_tail(struct pluto_crypto_req_cont *qke,
					   struct pluto_crypto_req *r);

static void ikev2_isakamp_established(struct state *st, const struct state_v2_microcode *svm,
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

/*
 * We need an md because the crypto continuation mechanism requires one
 * but we don't have one because we are not responding to an
 * incoming packet.
 * Solution: build a fake one.  How much do we need to fake?
 * Note: almost identical code appears at the end of aggr_outI1.
 */
static stf_status crypto_helper_build_ke(struct state *st)
{
	struct msg_digest *fake_md = alloc_md();
	struct pluto_crypto_req_cont *ke;
	stf_status e;

	fake_md->from_state = STATE_IKEv2_BASE;
	fake_md->svm = &ikev2_parent_firststate_microcode;
	fake_md->st = st;

	ke = new_pcrc(ikev2_parent_outI1_continue, "ikev2_outI1 KE",
		st, fake_md);
	e = build_ke_and_nonce(ke, st->st_oakley.group, pcim_stranger_crypto);

	/*
	 * ??? what exactly do we expect for e?
	 * ??? Who frees ke? md?
	 */

	return e;
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
		st->st_oakley.groupnum = st->st_oakley.group->group; /* circular */

		/*
		 * Calculate KE and Nonce.
		 */
		stf_status e = crypto_helper_build_ke(st);
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

	zero(&v2ke);	/* OK: no pointer fields */
	v2ke.isak_np = np;
	v2ke.isak_group = oakley_group;
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
	if (!justship_v2KE(st, &st->st_gi, st->st_oakley.groupnum, &md->rbody,
			   ISAKMP_NEXT_v2Ni))
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

	DBG(DBG_CONTROL,
		DBG_log("found connection: %s with policy %s",
			c->name, bitnamesof(sa_policy_bit_names, policy)));

	/*
	 * Did we overlook a type=passthrough foodgroup?
	 */
	{
		struct connection *tmp = find_host_pair_connections(
			&md->iface->ip_addr, md->iface->port,
			(ip_address *)NULL, md->sender_port);

		for (; tmp != NULL; tmp = tmp->hp_next) {
			if ((tmp->policy & POLICY_ID_AUTH_MASK) == LEMPTY) {
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
	 * basic validation.  ACCEPTED_OAKLEY does not contain
	 * allocated data.
	 */
	struct trans_attrs accepted_oakley = ikev2_proposal_to_trans_attrs(accepted_ike_proposal);
	if (accepted_oakley.group == NULL) {
		loglog(RC_LOG_SERIOUS, "discarding accepted proposal with no DH");
		/* free early return items */
		free_ikev2_proposal(&accepted_ike_proposal);
		return STF_IGNORE;
	}

	/*
	 * Early return must free: accepted_ike_proposal
	 */

	/*
	 * Check the MODP group matches the accepted proposal.
	 */
	{
		passert(md->chain[ISAKMP_NEXT_v2KE] != NULL);
		int ke_group = md->chain[ISAKMP_NEXT_v2KE]->payload.v2ke.isak_group;
		if (accepted_oakley.group->group != ke_group) {
			struct esb_buf ke_name;
			struct esb_buf proposal_name;
			libreswan_log("initiator guessed wrong keying material group (%s); responding with INVALID_KE_PAYLOAD requesting %s",
				      strip_prefix(enum_showb(&oakley_group_names,
							      ke_group, &ke_name),
						   "OAKLEY_GROUP_"),
				      strip_prefix(enum_showb(&oakley_group_names,
							      accepted_oakley.group->group,
							      &proposal_name),
						   "OAKLEY_GROUP_"));
			send_v2_notification_invalid_ke(md, accepted_oakley.group);
			pexpect(md->st == NULL);
			/* free early return items */
			free_ikev2_proposal(&accepted_ike_proposal);
			return STF_FAIL;
		}
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

	/* send KE */
	if (!ship_v2KE(st, r, &st->st_gr, &md->rbody, ISAKMP_NEXT_v2Nr))
		return STF_INTERNAL_ERROR;

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
#ifdef USE_GSSAPI
	 || (c->policy & POLICY_GSSAPI)
#endif
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
			const pb_stream *dc_pbs;

			/*
			 * RFC-7296 Sesction 2.6:
			 * The data associated with this notification MUST be
			 * between 1 and 64 octets in length (inclusive)
			 */
			if (ntfy->payload.v2n.isan_length > IKEv2_MAX_COOKIE_SIZE) {
				DBG(DBG_CONTROL, DBG_log("v2N_COOKIE notify payload too big - packet dropped"));
				return STF_IGNORE; /* avoid DDOS / reflection attacks */
			}

			if (ntfy != md->chain[ISAKMP_NEXT_v2N] || ntfy->next != NULL) {
				DBG(DBG_CONTROL, DBG_log("non-v2N_COOKIE notify payload(s) ignored "));
			}
			dc_pbs = &ntfy->pbs;
			clonetochunk(st->st_dcookie,
				dc_pbs->cur,
				pbs_left(dc_pbs),
				"saved received dcookie");

			DBG(DBG_CONTROLMORE,
			    DBG_dump_chunk("dcookie received (instead of a R1):",
					   st->st_dcookie);
			    DBG_log("next STATE_PARENT_I1 resend I1 with the dcookie"));

			if (DBGP(DBG_OPPO) || (st->st_connection->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
				libreswan_log("Received anti-DDOS COOKIE, resending I1 with cookie payload");
			}

			md->svm = &ikev2_parent_firststate_microcode;

			change_state(st, STATE_PARENT_I1);
			st->st_msgid_lastack = v2_INVALID_MSGID;
			md->msgid_received = v2_INVALID_MSGID;
			st->st_msgid_nextuse = 0;

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

			if (!in_struct(&sg, &suggested_group_desc,
				&ntfy->pbs, NULL))
					return STF_IGNORE;

			ikev2_proposals_from_alg_info_ike(c->name,
							  "initial initiator (validating suggested KE)",
							  c->alg_info_ike,
							  &c->ike_proposals);
			passert(c->ike_proposals != NULL);
			if (ikev2_proposals_include_modp(c->ike_proposals, sg.sg_group)) {

				DBG(DBG_CONTROLMORE, DBG_log("Suggested modp group is acceptable"));
				st->st_oakley.groupnum = sg.sg_group;
				st->st_oakley.group = lookup_group(sg.sg_group);
				DBG(DBG_CONTROLMORE, DBG_log("Received unauthenticated INVALID_KE with suggested group %s; resending with updated modp group",
					strip_prefix(enum_show(&oakley_group_names,
						sg.sg_group), "OAKLEY_GROUP_")));
				/* wipe our mismatched KE */
				clear_dh_from_state(st);
				/* wipe out any saved RCOOKIE */
				DBG(DBG_CONTROLMORE, DBG_log("zeroing any RCOOKIE from unauthenticated INVALID_KE packet"));
				rehash_state(st, zero_cookie);
				/* get a new KE */
				return crypto_helper_build_ke(st);
			} else {
				DBG(DBG_CONTROLMORE, DBG_log("Ignoring received unauthenticated INVALID_KE with unacceptable DH group suggestion %s",
					strip_prefix(enum_show(&oakley_group_names,
						sg.sg_group), "OAKLEY_GROUP_")));
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

	for (ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
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
		if (ret == STF_OK) {
			passert(st->st_accepted_ike_proposal != NULL);
			st->st_oakley = ikev2_proposal_to_trans_attrs(st->st_accepted_ike_proposal);
		}

		if (ret != STF_OK) {
			DBG(DBG_CONTROLMORE, DBG_log("ikev2_parse_parent_sa_body() failed in ikev2parent_inR1outI2()"));
			return ret;
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
	return start_dh_v2(md, "ikev2_inR1outI2 KE", ORIGINAL_INITIATOR,
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
			    ? pst->st_oakley.integ_hasher->hash_integ_len
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

	if (IS_CHILD_SA(st))
		pst = state_with_serialno(st->st_clonedfrom);

	chunk_t salt;
	PK11SymKey *cipherkey;
	PK11SymKey *authkey;
	if (st->st_original_role == ORIGINAL_INITIATOR) {
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
	if (ike_alg_enc_requires_integ(st->st_oakley.encrypter)) {
		/* note: no iv is longer than MAX_CBC_BLOCK_SIZE */
		unsigned char enc_iv[MAX_CBC_BLOCK_SIZE];
		construct_enc_iv("encryption IV/starting-variable", enc_iv,
				 wire_iv_start, salt,
				 pst->st_oakley.encrypter);

		DBG(DBG_CRYPT,
		    DBG_dump("data before encryption:", enc_start, enc_size));

		/* now, encrypt */
		(st->st_oakley.encrypter->do_crypt)(enc_start, enc_size,
						    cipherkey,
						    enc_iv, TRUE);

		DBG(DBG_CRYPT,
		    DBG_dump("data after encryption:", enc_start, enc_size));
		/* note: saved_iv's updated value is discarded */

		/* okay, authenticate from beginning of IV */
		struct hmac_ctx ctx;
		DBG(DBG_PARSING, DBG_log("Inside authloc"));
		DBG(DBG_CRYPT,
		    DBG_log("authkey pointer: %p", authkey));
		hmac_init(&ctx, pst->st_oakley.integ_hasher, authkey);
		DBG(DBG_PARSING, DBG_log("Inside authloc after init"));
		hmac_update(&ctx, auth_start, integ_start - auth_start);
		DBG(DBG_PARSING, DBG_log("Inside authloc after update"));
		hmac_final(integ_start, &ctx);
		DBG(DBG_PARSING, DBG_log("Inside authloc after final"));

		DBG(DBG_PARSING, {
			    DBG_dump("data being hmac:", auth_start,
				     integ_start - auth_start);
			    DBG_dump("out calculated auth:", integ_start,
				     pst->st_oakley.integ_hasher->
					hash_integ_len);
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
		if (!st->st_oakley.encrypter->
			do_aead_crypt_auth(salt.ptr, salt.len,
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
			     ? pst->st_oakley.integ_hasher->hash_integ_len
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

		hmac_init(&ctx, pst->st_oakley.integ_hasher, authkey);
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
		construct_enc_iv("decription IV/starting-variable", enc_iv,
				 wire_iv_start, salt,
				 pst->st_oakley.encrypter);

		DBG(DBG_CRYPT,
		    DBG_dump("payload before decryption:", enc_start, enc_size));
		(pst->st_oakley.encrypter->do_crypt)(enc_start, enc_size,
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
		if (!st->st_oakley.encrypter->
			do_aead_crypt_auth(salt.ptr, salt.len,
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
	struct state *st = md->st;
	struct ikev2_frag *frag;
	stf_status status;
	unsigned int size;
	unsigned int offset;

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

static
stf_status ikev2_decrypt_msg(struct msg_digest *md)
{
	stf_status status;
	chunk_t chunk;

	if (md->chain[ISAKMP_NEXT_v2SKF]) {
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
		return status;
	}

	/* CLANG 3.5 mis-diagnoses that chunk is undefined */
	init_pbs(&md->clr_pbs, chunk.ptr, chunk.len, "cleartext");

	unsigned np = md->chain[ISAKMP_NEXT_v2SK] ?
		      md->chain[ISAKMP_NEXT_v2SK]->payload.generic.isag_np :
		      md->chain[ISAKMP_NEXT_v2SKF]->payload.v2skf.isaskf_np;
	struct ikev2_payloads_summary summary = ikev2_decode_payloads(md, &md->clr_pbs, np);
	if (summary.status != STF_OK) {
		return status;
	}
	struct ikev2_payload_errors errors = ikev2_verify_payloads(summary, md->svm, TRUE);
	if (errors.status != STF_OK) {
		ikev2_log_payload_errors(errors, md->st);
		return errors.status;
	}
	return STF_OK;
}

static stf_status ikev2_ship_cp_attr_ip4(u_int16_t type, ip_address *ip4,
		const char *story, pb_stream *outpbs)
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
	lset_t authpolicy = c->policy & POLICY_ID_AUTH_MASK;

	/* ??? isn't c redundant? */
	pexpect(c == st->st_connection)

	/*
	 * ??? it isn't obvious that a connection's auth policy
	 * would allow only one auth method.
	 * Since this code assumes so, let's check.
	 */
	pexpect(LSINGLETON(authpolicy));

	/* ??? authpolicy often different from (st->st_policy & POLICY_ID_AUTH_MASK) */

	a.isaa_critical = ISAKMP_PAYLOAD_NONCRITICAL;
	if (DBGP(IMPAIR_SEND_BOGUS_PAYLOAD_FLAG)) {
		libreswan_log(
			" setting bogus ISAKMP_PAYLOAD_LIBRESWAN_BOGUS flag in ISAKMP payload");
		a.isaa_critical |= ISAKMP_PAYLOAD_LIBRESWAN_BOGUS;
	}

	a.isaa_np = np;

	if (authpolicy & POLICY_RSASIG) {
		a.isaa_type = IKEv2_AUTH_RSA;
	} else if (authpolicy & POLICY_PSK) {
		a.isaa_type = IKEv2_AUTH_PSK;
	} else if (authpolicy & POLICY_AUTH_NULL) {
		a.isaa_type = IKEv2_AUTH_NULL;
	} else {
		/* what else is there?... DSS not implemented. */
		loglog(RC_LOG_SERIOUS, "Unknown or not implemented IKEv2 AUTH policy");
		return STF_FATAL;
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
		if (!ikev2_calculate_psk_auth(pst, role, idhash_out, &a_pbs)) {
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
	struct state *st = md->st;
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
	struct state *const st = md->st;
	unsigned int len;

	len = (st->st_connection->addr_family == AF_INET) ?
	      ISAKMP_V2_FRAG_MAXLEN_IPv4 : ISAKMP_V2_FRAG_MAXLEN_IPv6;

	if (st->st_interface != NULL && st->st_interface->ike_float)
		len -= NON_ESP_MARKER_SIZE;

	len -= NSIZEOF_isakmp_hdr + NSIZEOF_ikev2_skf;

	len -= ike_alg_enc_requires_integ(st->st_oakley.encrypter) ?
	       st->st_oakley.integ_hasher->hash_integ_len :
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
			if (st_nat_traversal & NAT_T_DETECTED) {
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

	if (!finish_dh_v2(pst, r))
		return STF_FAIL + v2N_INVALID_KE_PAYLOAD;

	/* ??? this is kind of odd: regular control flow only selecting DBG output */
	if (DBGP(DBG_PRIVATE) && DBGP(DBG_CRYPT))
		ikev2_log_parentSA(pst);

	/* XXX This is to early and many failures could lead to not needing a child state */
	struct state *cst = duplicate_state(pst);	/* child state */

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
	/* set original initiator; all other flags clear */
	hdr.isa_flags = ISAKMP_FLAGS_v2_IKE_I;
	/* XXX same here, use parent */
	hdr.isa_msgid = cst->st_msgid;

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

	/* send out the IDi payload */

	unsigned char idhash[MAX_DIGEST_LEN];

	{
		struct ikev2_id r_id;
		pb_stream r_id_pbs;
		chunk_t id_b;
		struct hmac_ctx id_ctx;

		hmac_init(&id_ctx, pst->st_oakley.prf_hasher,
				pst->st_skey_pi_nss);
		build_id_payload((struct isakmp_ipsec_id *)&r_id, &id_b,
				 &pc->spd.this);
		r_id.isai_critical = ISAKMP_PAYLOAD_NONCRITICAL;
		if (DBGP(IMPAIR_SEND_BOGUS_PAYLOAD_FLAG)) {
			libreswan_log(
				" setting bogus ISAKMP_PAYLOAD_LIBRESWAN_BOGUS flag in ISAKMP payload");
			r_id.isai_critical |= ISAKMP_PAYLOAD_LIBRESWAN_BOGUS;
		}


		r_id.isai_np = send_cert ?
			ISAKMP_NEXT_v2CERT : ISAKMP_NEXT_v2AUTH;

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
		stf_status certstat = ikev2_send_cert(cst, md,
						      ORIGINAL_INITIATOR,
						      ISAKMP_NEXT_v2AUTH,
						      &e_pbs_cipher);

		if (certstat != STF_OK)
			return certstat;
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

		ikev2_proposals_from_alg_info_esp(cc->name, "initiator",
						  cc->alg_info_esp,
						  cc->policy,
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
		stf_status ret = ikev2_encrypt_msg(cst, authstart,
					iv, encstart, authloc,
					&e_pbs_cipher);

		if (ret == STF_OK)
			record_outbound_ike_msg(cst, &reply_stream,
				"reply packet for ikev2_parent_inR1outI2_tail");
		return ret;
	}
}

#ifdef XAUTH_HAVE_PAM
/* IN AN AUTHENTICAL THREAD */
static void *ikev2_pam_autherize_thread (void *x)
{
	struct ikev2_pam_helper *p = (struct ikev2_pam_helper *) x;
	struct timeval done_delta;
	FILE *in = fdopen(p->helper_fd, "rb");
	FILE *out = fdopen(p->helper_fd, "wb");
	size_t sz;

	/* threads will go quietly if the master cancel it */
	pthread_setcanceltype  (PTHREAD_CANCEL_ASYNCHRONOUS,  NULL);
	pthread_setcancelstate (PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	p->pam_status = do_pam_authentication(&p->pam);
	gettimeofday(&p->done_time, NULL);
	timersub(&p->done_time, &p->start_time, &done_delta);

	DBG(DBG_CONTROL, DBG_log("#%lu %s[%lu] IKEv2 PAM helper thread finished work. status %s elapsed time %lu.%06lu '%s'",
				p->pam.st_serialno, p->pam.c_name,
				p->pam.c_instance_serial,
				p->pam_status ? "SUCCESS" : "FAIL",
				(unsigned long)done_delta.tv_sec,
				(unsigned long)(done_delta.tv_usec * 1000000),
				p->pam.name));
	p->in_use = FALSE;
	sz = fwrite(p, sizeof(char), sizeof(p), out);
	fflush(out);

	if (sz != sizeof(p)) {
		if (ferror(out) != 0) {
			/* ??? is strerror(ferror(out)) correct? */
			char errbuf[1024];       /* ??? how big is big enough? */

			strerror_r(errno, errbuf, sizeof(errbuf));
			loglog(RC_LOG_SERIOUS,
					"IKEv2 PAM helper failed to write answer: %s", errbuf);
		} else {
			/* short write -- fatal */
			loglog(RC_LOG_SERIOUS,
					"IKEv2 PAM helper error: write truncated: %zu instead of %zu",
					sz, sizeof(p));
		}
	}

	fclose(in);
	fclose(out);

	return NULL;
}

static void free_pam_thread_entry(struct ikev2_pam_helper **pp)
{
	struct ikev2_pam_helper *p = *pp;

	*pp = p->next;
	pfreeany(p->pam.name);
	pfreeany(p->pam.password);
	pfreeany(p->pam.c_name);
	pfreeany(p->pam.ra);
	pthread_cancel(p->tid);
	event_free(p->evm);
	if (p->master_fd != NULL_FD)
		close(p->master_fd);
	if (p->helper_fd != NULL_FD)
		close(p->helper_fd);
	pfree(p);
}

static void ikev2_pam_continue(struct ikev2_pam_helper *p)
{
	stf_status stf;
	struct msg_digest *md;
	struct ikev2_pam_helper *x;
	struct timeval served_time;
	struct timeval served_delta;
	struct timeval done_delta;
	struct state *st = state_with_serialno(p->pam.st_serialno);

	gettimeofday(&served_time, NULL);
	timersub(&served_time, &p->start_time, &served_delta);
	timersub(&p->done_time, &p->start_time, &done_delta);

	if (st == NULL) {
		DBG(DBG_CONTROL, DBG_log("IKEv2 PAM helper thread calls state #%lu, %s[%lu]. The state is gone. elapsed time %lu.%06lu",
					p->pam.st_serialno, p->pam.c_name,
					p->pam.c_instance_serial,
					(unsigned long)served_delta.tv_sec,
					(unsigned long)(served_delta.tv_usec * 1000000)));
		return;
	}
	if (read(p->master_fd, (void *)&x, sizeof(p)) == -1) {
		libreswan_log("IKEv2 PAM helper read failed %d: %s",
			errno, strerror(errno));
	}

	DBG(DBG_CONTROL, DBG_log("#%lu %s[%lu] IKEv2 PAM helper thread can continue. PAM status %s. elapsed time %lu.%06lu PAM auth time %lu.%06lu U='%s'",
				p->pam.st_serialno, p->pam.c_name,
				p->pam.c_instance_serial,
				p->pam_status ? "SUCCESS" : "FAIL",
				(unsigned long)served_delta.tv_sec,
				(unsigned long)(served_delta.tv_usec * 1000000),
				(unsigned long)done_delta.tv_sec,
				(unsigned long)(done_delta.tv_usec * 1000000),
				p->pam.name));


	md = st->st_suspended_md;
	unset_suspended(md->st);
	st->has_pam_thread = FALSE;

	if (p->pam_status) {
		/* This is a hardcoded continue, convert this to micro state. */
		stf = ikev2_parent_inI2outR2_auth_tail(md, p->pam_status);
	} else {
		stf = STF_FAIL + v2N_AUTHENTICATION_FAILED;
	}

	ikev2_free_auth_pam(p->pam.st_serialno);

	complete_v2_state_transition(&md, stf);
	release_any_md(&md);
	reset_globals();
}

static event_callback_routine ikev2_pam_continue_cb;
static void ikev2_pam_continue_cb(evutil_socket_t fd UNUSED, const short event UNUSED, void *arg)
{
	ikev2_pam_continue((struct ikev2_pam_helper *)arg);
}

/*
 * In the middle of IKEv2 AUTH exchange, the AUTH payload is verified succsfully.
 * Now invoke the PAM helper to authorize connection (based on name only, not password)
 * When pam helper is done state will be woken up and continue.
 */

static stf_status ikev2_start_pam_authorize(struct msg_digest *md)
{
	struct ikev2_pam_helper *p = alloc_thing(struct ikev2_pam_helper, "v2 pam helper");
	struct state *st = md->st;
	int thread_status;
	int fds[2];
	pthread_attr_t pattr;
	ipstr_buf ra;
	char thatid[IDTOA_BUF];

	p->master_fd = NULL_FD;
	set_suspended(md->st, md);
	messup(p);
	p->in_use = TRUE;
	gettimeofday(&p->start_time, NULL);

	if (socketpair(PF_UNIX, SOCK_STREAM, 0, fds) != 0) {
		loglog(RC_LOG_SERIOUS, "could not create socketpair for ikev2 pam authorize: %s",
				strerror(errno));
		return STF_INTERNAL_ERROR;
	}
	p->master_fd = fds[0];
	p->helper_fd = fds[1];

	idtoa(&st->st_connection->spd.that.id, thatid, sizeof(thatid));
	p->pam.name = clone_str(thatid, "pam name thatid");

	/* ??? if password is always "password" (seems odd) then why is a copy needed? */
	p->pam.password = clone_str("password", "password");
	p->pam.c_name = clone_str(st->st_connection->name, "connection name, ikev2 pam");
	p->pam.ra = clone_str(ipstr(&st->st_remoteaddr, &ra), "st remote address");
	p->pam.c_instance_serial = st->st_connection->instance_serial;
	p->pam.st_serialno = st->st_serialno;
	p->pam.atype = "IKEv2";

	p->next = pluto_v2_pam_helpers;
	pluto_v2_pam_helpers = p;

	DBG(DBG_CONTROL, DBG_log("#%lu, %s[%lu] start IKEv2 PAM helper thread U='%s' P='%s'",
				p->pam.st_serialno, p->pam.c_name,
				p->pam.c_instance_serial, p->pam.name,
				p->pam.password));

	pthread_attr_init(&pattr);
	pthread_attr_setdetachstate(&pattr, PTHREAD_CREATE_DETACHED);
	thread_status = pthread_create(&p->tid, NULL,
			ikev2_pam_autherize_thread, (void *)p);
	if (thread_status != 0) {
		loglog(RC_LOG_SERIOUS,
			"#%lu  %s[%lu] failed to start IKEv2 PAMhelper thread error = %d '%s'",
			p->pam.st_serialno, p->pam.c_name,
			p->pam.c_instance_serial,
			thread_status, p->pam.name);
		close(fds[1]);
		close(fds[0]);
		p->master_fd = NULL_FD;
		return STF_INTERNAL_ERROR;
	}

	DBG(DBG_CONTROLMORE, DBG_log("#%lu %s[%lu] started IKEv2 PAM helper thread '%s'",
				p->pam.st_serialno, p->pam.c_name,
				p->pam.c_instance_serial, p->pam.name));
	st->has_pam_thread = TRUE;
	pthread_attr_destroy(&pattr);

	DBG(DBG_CONTROL, DBG_log("setup IKEv2 PAM authorize helper callback for master fd %d", p->master_fd));
	p->evm = pluto_event_new(p->master_fd, EV_READ, ikev2_pam_continue_cb, p, NULL);

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
	return start_dh_v2(md, "ikev2_inI2outR2 KE", ORIGINAL_RESPONDER,
		ikev2_parent_inI2outR2_continue);
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
	unsigned char idhash_in[MAX_DIGEST_LEN];

	/* extract calculated values from r */
	if (!finish_dh_v2(st, r))
		return STF_FAIL + v2N_INVALID_KE_PAYLOAD;

	/* ??? this is kind of odd: regular control flow only selecting DBG output */
	if (DBGP(DBG_PRIVATE) && DBGP(DBG_CRYPT))
		ikev2_log_parentSA(st);

	/* decrypt things. */
	{
		stf_status ret = ikev2_decrypt_msg(md);

		if (ret != STF_OK)
			return ret;
	}

	if (!ikev2_decode_peer_id_and_certs(md))
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

	/* process CERTREQ payload */
	if (md->chain[ISAKMP_NEXT_v2CERTREQ] != NULL) {
		DBG(DBG_CONTROLMORE,
		    DBG_log("received CERTREQ payload; going to decode it"));
		ikev2_decode_cr(md);
	}

	/* process AUTH payload now */
	/* now check signature from RSA key */
	switch (md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2a.isaa_type) {
	case IKEv2_AUTH_RSA:
	{
		stf_status authstat = ikev2_verify_rsa_sha1(
				st,
				ORIGINAL_RESPONDER,
				idhash_in,
#ifdef USE_KEYRR
				NULL,	/* keys from DNS */
#endif
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
	case IKEv2_AUTH_NULL:
	{
		stf_status authstat = ikev2_verify_psk_auth(
				st,
				ORIGINAL_RESPONDER,
				idhash_in,
				&md->chain[ISAKMP_NEXT_v2AUTH]->pbs);

		if (authstat != STF_OK) {
			libreswan_log(
				"Authentication failed AUTH mismatch!");
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

			/* set msg responder flag - clear others */
			hdr.isa_flags = ISAKMP_FLAGS_v2_MSG_R;
			hdr.isa_version = build_ikev2_version();
			hdr.isa_np = ISAKMP_NEXT_v2SK;
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

			hmac_init(&id_ctx, st->st_oakley.prf_hasher,
					st->st_skey_pr_nss);
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
		 * There is probablly no good reason to use st from here on.
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
			stf_status ret = ikev2_encrypt_msg(cst, authstart,
						iv, encstart, authloc,
						&e_pbs_cipher);

			if (ret == STF_OK)
				record_outbound_ike_msg(cst, &reply_stream,
					"reply packet for ikev2_parent_inI2outR2_auth_tail");

			return ret;
		}
	}


	/* if the child failed, delete its state here - we sent the packet */
	/* PAUL */
	/* ??? what does that mean?  We cannot even reach here. */
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
	struct connection *c = st->st_connection;
	unsigned char idhash_in[MAX_DIGEST_LEN];
	struct payload_digest *ntfy;
	struct state *pst = st;
	bool got_transport = FALSE;
	int cp_r;

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
		stf_status ret = ikev2_decrypt_msg(md);

		if (ret != STF_OK)
			return ret;
	}

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

	if (!ikev2_decode_peer_id_and_certs(md))
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

	/* process AUTH payload */

	switch (md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2a.isaa_type) {
	case IKEv2_AUTH_RSA:
	{
		stf_status authstat = ikev2_verify_rsa_sha1(
				pst,
				ORIGINAL_INITIATOR,
				idhash_in,
#ifdef USE_KEYRR
				NULL,	/* keys from DNS */
#endif
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
	case IKEv2_AUTH_NULL:
	{
		stf_status authstat = ikev2_verify_psk_auth(
				pst,
				ORIGINAL_INITIATOR,
				idhash_in,
				&md->chain[ISAKMP_NEXT_v2AUTH]->pbs);

		if (authstat != STF_OK) {
			libreswan_log("Authentication failed");
			/*
			 * cannot use STF_FAIL + v2N_AUTHENTICATION_FAILED because IKE_AUTH
			 * reply cannot receive an IKE_AUTH reply.
			 * 
			 * The RFC states:
			 * "If the error occurs on the initiator, the notification MAY be
			 *  returned in a separate INFORMATIONAL exchange, usually with no other
			 *  payloads.  This is an exception for the general rule of not starting
			 *  new exchanges based on errors in responses."
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
		SEND_V2_NOTIFICATION(v2N_AUTHENTICATION_FAILED); /* see above comment */
		return STF_FAIL;
	}

	/* authentication good */

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
		/* ??? this code won't support AH + ESP */
		struct ipsec_proto_info *proto_info
			= ikev2_esp_or_ah_proto_info(st, c->policy);

		ikev2_proposals_from_alg_info_esp(c->name, "responder",
						  c->alg_info_esp, c->policy,
						  &c->esp_or_ah_proposals);
		passert(c->esp_or_ah_proposals != NULL);

		stf_status ret = ikev2_process_sa_payload("ESP/AH responder",
							  &sa_pd->pbs,
							  /*expect_ike*/ FALSE,
							  /*expect_spi*/ TRUE,
							  /*expect_accepted*/ TRUE,
							  c->policy & POLICY_OPPORTUNISTIC,
							  &st->st_accepted_esp_or_ah_proposal,
							  c->esp_or_ah_proposals);

		if (ret == STF_OK) {
			passert(st->st_accepted_esp_or_ah_proposal != NULL);
			DBG(DBG_CONTROL, DBG_log_ikev2_proposal("ESP/AH", st->st_accepted_esp_or_ah_proposal));
			if (!ikev2_proposal_to_proto_info(st->st_accepted_esp_or_ah_proposal, proto_info)) {
				DBG(DBG_CONTROL, DBG_log("proposed/accepted a proposal we don't actually support!"));
				ret =  STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
			}
		}

		if (ret != STF_OK)
			return ret;
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

	c->newest_ipsec_sa = st->st_serialno;
	log_newest_sa_change("inR2", st);

	/*
	 * Delete previous retransmission event.
	 */
	delete_event(st);

	return STF_OK;
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
	sha256_context ctx_sha256;
	unsigned char addr_buff[
		sizeof(union { struct in_addr A;
			       struct in6_addr B;
		       })];

	addr_length = addrbytesof(addr, addr_buff, sizeof(addr_buff));
	sha256_init(&ctx_sha256);
	sha256_write(&ctx_sha256, ni.ptr, ni.len);
	sha256_write(&ctx_sha256, addr_buff, addr_length);
	sha256_write(&ctx_sha256, spiI.ptr, spiI.len);
	sha256_write(&ctx_sha256, ikev2_secret_of_the_day,
		   SHA2_256_DIGEST_SIZE);
	sha256_final(dcookie, &ctx_sha256);
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

	/*
	 * The notification is piggybacked on the existing parent state.
	 * This notification is fire-and-forget (not a proper exchange,
	 * one with retrying).  So we need not preserve the packet we
	 * are sending.
	 */
	send_ike_msg_without_recording(p1st, &reply_stream, "v2 notify");
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
		stf_status ret = ikev2_decrypt_msg(md);

		if (ret != STF_OK)
			return ret;
	}

	if (!LHAS(pst->hidden_variables.st_nat_traversal, NATED_HOST))
		update_ike_endpoints(pst, md);

	if (md->chain[ISAKMP_NEXT_v2KE] != NULL) {
		/* in CREATE_CHILD_SA exchange we don't support new KE */
		ipstr_buf b;

		libreswan_log("rejecting create child SA from %s:%u -- new KE in DH for PFS is not yet supported",
				ipstr(&md->sender, &b), md->sender_port);
		return STF_FAIL + v2N_INVALID_KE_PAYLOAD;
	}

	st = duplicate_state(pst);	/* create child state */
	set_cur_state(st);	/* (caller will reset) */
	md->st = st;		/* feed back new state. ??? better way to do */
	insert_state(st); /* needed for delete - we are duplicating early */
	/* XXX we should call change_state() ? arent we in STATE_UNDEFINED now? */

	freeanychunk(st->st_ni); /* this is from the parent. */
	freeanychunk(st->st_nr); /* this is from the parent. */

	RETURN_STF_FAILURE(accept_v2_nonce(md, &st->st_ni, "Ni"));

	/* calculate new nonce. a new KE is not supported yet */
	{
		struct pluto_crypto_req_cont *qke = new_pcrc(
			ikev2_child_inIoutR_continue, "IKEv2 CHILD NONCE",
			st, md);
		stf_status e;
		enum crypto_importance ci;

		ci = pcim_ongoing_crypto;
		if (ci < st->st_import)
			ci = st->st_import;

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
		DBG_log("ikev2_child_inIoutR_continue for #%lu: calculated ke+nonce; sending CREATE_CHILD_SA response",
			qke->pcrc_serialno));
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

	init_out_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer), "reply packet");
	authstart = reply_stream.cur;

	/* HDR out */
	{
		struct isakmp_hdr hdr;

		zero(&hdr);	/* OK: no pointer fields */
		hdr.isa_version = build_ikev2_version();
		/* add message responder flag */
		hdr.isa_flags |= ISAKMP_FLAGS_v2_MSG_R;
		memcpy(hdr.isa_rcookie, pst->st_rcookie, COOKIE_SIZE);
		memcpy(hdr.isa_icookie, pst->st_icookie, COOKIE_SIZE);
		hdr.isa_xchg = ISAKMP_v2_CREATE_CHILD_SA;
		hdr.isa_np = ISAKMP_NEXT_v2SK;
		hdr.isa_msgid = htonl(md->msgid_received);

		/* encryption role based on original originator */
		if (md->original_role == ORIGINAL_INITIATOR) {
			/* add original initiator flag */
			hdr.isa_flags |= ISAKMP_FLAGS_v2_IKE_I;
		} else {
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
	if (!out_struct(&e, &ikev2_sk_desc, &md->rbody, &e_pbs))
		return STF_INTERNAL_ERROR;

	/* IV */
	iv = e_pbs.cur;
	if (!emit_wire_iv(st, &e_pbs))
		return STF_INTERNAL_ERROR;

	/* note where cleartext starts */
	init_pbs(&e_pbs_cipher, e_pbs.cur, e_pbs.roof - e_pbs.cur,
			"cleartext CREATE_CHILD_SA reply");

	e_pbs_cipher.container = &e_pbs;
	e_pbs_cipher.desc = NULL;
	e_pbs_cipher.cur = e_pbs.cur;
	encstart = e_pbs_cipher.cur;

	unpack_nonce(&st->st_nr, r);

	ret = ikev2_child_sa_respond(md, ORIGINAL_RESPONDER, &e_pbs_cipher,
			ISAKMP_v2_CREATE_CHILD_SA);

	/* note: st: parent; md->st: child */
	struct state *const cst = md->st;

	if (ret > STF_FAIL) {
		int v2_notify_num = ret - STF_FAIL;

		DBG_log("ikev2_child_sa_respond returned STF_FAIL with %s",
				enum_name(&ikev2_notify_names, v2_notify_num));
	} else if (ret != STF_OK) {
		DBG_log("ikev2_child_sa_respond returned %s",
				enum_name(&stfstatus_name, ret));
	}
	if (!ikev2_padup_pre_encrypt(cst, &e_pbs_cipher))
		return STF_INTERNAL_ERROR;

	close_output_pbs(&e_pbs_cipher);

	{
		unsigned char *authloc = ikev2_authloc(cst, &e_pbs);

		if (authloc == NULL)
			return STF_INTERNAL_ERROR;

		close_output_pbs(&e_pbs);
		close_output_pbs(&md->rbody);
		close_output_pbs(&reply_stream);
		ret = ikev2_encrypt_msg(cst, authstart, iv, encstart,
					authloc, &e_pbs_cipher);

		if (ret != STF_OK)
			return ret;
	}

	record_outbound_ike_msg(cst, &reply_stream, "reply packet for ikev2_child_inIoutR_tail");

	return STF_OK;
}

stf_status process_encrypted_informational_ikev2(struct msg_digest *md)
{
	struct state *st = md->st;

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

	/* decrypt message */
	{
		stf_status ret = ikev2_decrypt_msg(md);

		if (ret != STF_OK)
			return ret;
	}

	if (!LHAS(st->hidden_variables.st_nat_traversal, NATED_HOST))
		update_ike_endpoints(st, md);

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
			hdr.isa_flags |= ISAKMP_FLAGS_v2_MSG_R;
			if (md->original_role == ORIGINAL_INITIATOR) {
				hdr.isa_flags |= ISAKMP_FLAGS_v2_IKE_I;
			}
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

		if (!out_struct(&e, &ikev2_sk_desc, &md->rbody, &e_pbs))
			return STF_INTERNAL_ERROR;

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
				u_int16_t i;

				if (v2del->isad_spisize != sizeof(ipsec_spi_t)){
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

				for (i = 0; i < v2del->isad_nrspi; i++)
				{
					ipsec_spi_t spi;

					if (!in_raw(&spi, sizeof(spi), &p->pbs, "SPI"))
						return STF_INTERNAL_ERROR;

					DBG(DBG_CONTROLMORE,
						DBG_log("received delete request for %s SA(0x%08" PRIx32 ")",
							enum_show(&ikev2_protocol_names,
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
								enum_show(&ikev2_protocol_names,
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
								enum_show(&ikev2_protocol_names,
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
				struct ikev2_delete v2del_tmp;

				zero(&v2del_tmp);	/* OK: no pointer fields */

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

			ret = ikev2_encrypt_msg(st, authstart,
						iv, encstart, authloc,
						&e_pbs_cipher);
			if (ret != STF_OK)
				return ret;
		}


		record_and_send_ike_msg(st, &reply_stream,
			"reply packet for process_encrypted_informational_ikev2");
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
					if (dst != NULL) {
						DBG(DBG_CONTROLMORE,
							DBG_log("our side SPI that needs to be deleted: %s SA(0x%08" PRIx32 ")",
								enum_show(&ikev2_protocol_names,
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
							    enum_show(&ikev2_protocol_names, v2del->isad_protoid),
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
			if (pst->st_original_role == ORIGINAL_INITIATOR) {
				hdr.isa_flags |= ISAKMP_FLAGS_v2_IKE_I;
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
			unsigned char *authloc = ikev2_authloc(st, &e_pbs);

			if (authloc == NULL)
				return STF_FATAL;

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
		pst->st_msgid_lastack += 1;
		pst->st_msgid_nextuse += 1;

		pst->st_pend_liveness = TRUE; /* we should only do this when dpd/liveness is active? */
		record_and_send_ike_msg(pst, &reply_stream,
			"packet for ikev2_send_informational");
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

		ret = ikev2_encrypt_msg(st, authstart,
					iv, encstart, authloc,
					&e_pbs_cipher);
		if (ret != STF_OK)
			return FALSE;
	}

	record_and_send_ike_msg(pst, &reply_stream,
		     "packet for ikev2_delete_out_guts");

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

#ifdef XAUTH_HAVE_PAM
void ikev2_free_auth_pam(so_serial_t st_serialno)
{
	struct ikev2_pam_helper **pp;
	struct ikev2_pam_helper *p;

	/* search for finished pam threads */
	for (pp = &pluto_v2_pam_helpers; (p = *pp) != NULL; pp = &p->next) {
		if (p->pam.st_serialno == st_serialno) {
			DBG(DBG_CONTROL,
				DBG_log("Deleting IKEv2 PAM helper thread for #%lu, %s[%lu] status %s '%s'",
					p->pam.st_serialno, p->pam.c_name,
					p->pam.c_instance_serial,
					p->pam_status ? "SUCCESS" : "FAIL",
					p->pam.name));
			free_pam_thread_entry(pp);
			return;
		}
	}
}
#endif
