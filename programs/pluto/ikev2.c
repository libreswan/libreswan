/* demultiplex incoming IKE messages
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2010  D. Hugh Redelmeier.
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 Simon Deziel <simon@xelerance.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2011-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <pwouters@redhat.com>
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
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
#include "cookie.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#ifdef XAUTH_HAVE_PAM
#include <security/pam_appl.h>
#endif
#include "connections.h"        /* needs id.h */
#include "cookie.h"
#include "state.h"
#include "packet.h"
#include "md5.h"
#include "sha1.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "ike_alg.h"
#include "log.h"
#include "demux.h"      /* needs packet.h */
#include "ikev2.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "timer.h"
#include "whack.h"      /* requires connections.h */
#include "server.h"
#ifdef XAUTH
#include "xauth.h"
#endif
#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif
#include "vendor.h"
#include "dpd.h"
#include "udpfromto.h"
#include "tpm/tpm.h"

#define SEND_NOTIFICATION(t) { \
		if (st) \
			send_v2_notification_from_state(st, from_state, t, \
							NULL); \
		else \
			send_v2_notification_from_md(md, t, NULL); }

struct state_v2_microcode {
	enum state_kind state, next_state;
	enum isakmp_xchg_types recv_type;
	lset_t flags;
	lset_t req_payloads;    /* required payloads (allows just one) */
	lset_t opt_payloads;    /* optional payloads (any mumber) */
	enum event_type timeout_event;
	state_transition_fn *processor;
};

enum smf2_flags {
	SMF2_INITIATOR = LELEM(1),
	SMF2_RESPONDER = 0,

	SMF2_STATENEEDED=LELEM(2),
	SMF2_NEWSTATE  = 0,

	SMF2_REPLY     = LELEM(3),
};

/*
 * IKEv2 has slightly different states than IKEv1.
 *
 * IKEv2 puts all the responsability for retransmission on the end that
 * wants to do something, usually, that the initiator. (But, not always
 * the original initiator, of the responder decides it needs to rekey first)
 *
 * Each exchange has a bit that indicates if it's a Initiator message,
 * or if it's a response.  The responder never retransmits it's messages
 * except because the initiator has retransmitted.
 *
 * The message ID is *NOT* used in the cryptographic state at all, but instead
 * serves the role of a sequence number.  This makes the state machine far
 * simpler, and there really are no exceptions.
 *
 * The upper level state machine is therefore much simpler.
 * The lower level takes care of retransmissions, and the upper layer state
 * machine just has to worry about whether it needs to go into cookie mode,
 * etc.
 *
 * Like IKEv1, IKEv2 can have multiple child SAs.  Like IKEv1, each one of
 * the child SAs ("Phase 2") will get their own state. Unlike IKEv1,
 * an implementation may negotiate multiple CHILD_SAs at the same time
 * using different MessageIDs.  This is enabled by an option (a notify)
 * that the responder sends to the initiator.  The initiator may only
 * do concurrent negotiations if it sees the notify.
 *
 * XXX This implementation does not support concurrency, but it shouldn't be
 *     that hard to do.  The most difficult part will be to map the message IDs
 *     to the right state. Some CHILD_SAs may take multiple round trips,
 *     and each one will have to be mapped to the same state.
 *
 * The IKEv2 state values are chosen from the same state space as IKEv1.
 *
 */

/* it is not clear how the flags will be used yet, if at all */

static const struct state_v2_microcode state_microcode_table[] = {
	{ .state      = STATE_UNDEFINED,
	  .next_state = STATE_PARENT_I1,
	  .flags      = SMF2_INITIATOR,
	  .processor  = NULL, },

	{ .state      = STATE_PARENT_I1,
	  .next_state = STATE_PARENT_I2,
	  .flags = SMF2_INITIATOR | SMF2_STATENEEDED | SMF2_REPLY,
	  .processor  = ikev2parent_inR1outI2,
	  .recv_type  = ISAKMP_v2_SA_INIT, },

	{ .state      = STATE_PARENT_I2,
	  .next_state = STATE_PARENT_I3,
	  .flags = SMF2_INITIATOR | SMF2_STATENEEDED,
	  .processor  = ikev2parent_inR2,
	  .recv_type  = ISAKMP_v2_AUTH,
	  .timeout_event = EVENT_SA_REPLACE, },

	{ .state      = STATE_UNDEFINED,
	  .next_state = STATE_PARENT_R1,
	  .flags = SMF2_RESPONDER | SMF2_NEWSTATE | SMF2_REPLY,
	  .processor  = ikev2parent_inI1outR1,
	  .recv_type  = ISAKMP_v2_SA_INIT, },

	{ .state      = STATE_PARENT_R1,
	  .next_state = STATE_PARENT_R2,
	  .flags = SMF2_RESPONDER | SMF2_STATENEEDED | SMF2_REPLY,
	  .processor  = ikev2parent_inI2outR2,
	  .recv_type  = ISAKMP_v2_AUTH,
	  .timeout_event = EVENT_SA_REPLACE, },

	/* Informational Exchange*/
	{ .state      = STATE_PARENT_I2,
	  .next_state = STATE_PARENT_I2,
	  .flags      = SMF2_STATENEEDED,
	  .processor  = process_informational_ikev2,
	  .recv_type  = ISAKMP_v2_INFORMATIONAL, },

	/* Informational Exchange*/
	{ .state      = STATE_PARENT_R1,
	  .next_state = STATE_PARENT_R1,
	  .flags      = SMF2_STATENEEDED,
	  .processor  = process_informational_ikev2,
	  .recv_type  = ISAKMP_v2_INFORMATIONAL, },

	/* Informational Exchange*/
	{ .state      = STATE_PARENT_I3,
	  .next_state = STATE_PARENT_I3,
	  .flags      = SMF2_STATENEEDED,
	  .processor  = process_informational_ikev2,
	  .recv_type  = ISAKMP_v2_INFORMATIONAL, },

	/* Informational Exchange*/
	{ .state      = STATE_PARENT_R2,
	  .next_state = STATE_PARENT_R2,
	  .flags      = SMF2_STATENEEDED,
	  .processor  = process_informational_ikev2,
	  .recv_type  = ISAKMP_v2_INFORMATIONAL, },

	/* Informational Exchange*/
	{ .state      = STATE_IKESA_DEL,
	  .next_state = STATE_IKESA_DEL,
	  .flags      = SMF2_STATENEEDED,
	  .processor  = process_informational_ikev2,
	  .recv_type  = ISAKMP_v2_INFORMATIONAL, },

	/* last entry */
	{ .state      = STATE_IKEv2_ROOF }
};

const struct state_v2_microcode *ikev2_parent_firststate()
{
	return &state_microcode_table[0];
}

/*
 * split up an incoming message into payloads
 */
stf_status ikev2_process_payloads(struct msg_digest *md,
				  pb_stream    *in_pbs,
				  unsigned int from_state,
				  unsigned int np)
{
	struct payload_digest *pd = md->digest_roof;
	struct state *st = md->st;

	/* lset_t needed = smc->req_payloads; */

	/* zero out the digest descriptors -- might nuke [v2E] digest! */

	while (np != ISAKMP_NEXT_NONE) {
		struct_desc *sd = np <
				  ISAKMP_NEXT_ROOF ? payload_descs[np] : NULL;
		int thisp = np;
		bool unknown_payload = FALSE;

		DBG(DBG_CONTROL,
		    DBG_log("Now lets proceed with payload (%s)",
			    enum_show(&payload_names, thisp)));
		memset(pd, 0, sizeof(*pd));

		if (pd == &md->digest[PAYLIMIT]) {
			loglog(RC_LOG_SERIOUS,
			       "more than %d payloads in message; ignored",
			       PAYLIMIT);
			SEND_NOTIFICATION(PAYLOAD_MALFORMED);
			return STF_FAIL;
		}

		if (sd == NULL) {
			unknown_payload = TRUE;
			sd = &ikev2_generic_desc;
		}

		/* why to process an unknown payload*/
		/* critical bit in RFC 4306/5996 is just 1 bit not a byte*/
		/* As per RFC other 7 bits are RESERVED and should be ignored*/
		if (unknown_payload) {
			if (pd->payload.v2gen.isag_critical &
			    ISAKMP_PAYLOAD_CRITICAL) {
				/* it was critical */
				loglog(RC_LOG_SERIOUS,
				       "critical payload (%s) was not understood. Message dropped.",
				       enum_show(&payload_names, thisp));
				return STF_FATAL;
			}
			loglog(RC_COMMENT, "non-critical payload ignored because it contains an unknown or"
			       " unexpected payload type (%s) at the outermost level",
			       enum_show(&payload_names, thisp));
		}

		if (!in_struct(&pd->payload, sd, in_pbs, &pd->pbs)) {
			loglog(RC_LOG_SERIOUS, "malformed payload in packet");
			SEND_NOTIFICATION(PAYLOAD_MALFORMED);
			return STF_FAIL;
		}

		DBG(DBG_PARSING,
		    DBG_log("processing payload: %s (len=%u)\n",
			    enum_show(&payload_names, thisp),
			    pd->payload.generic.isag_length));

		/* place this payload at the end of the chain for this type */
		{
			struct payload_digest **p;

			for (p = &md->chain[thisp]; *p != NULL;
			     p = &(*p)->next)
				;
			*p = pd;
			pd->next = NULL;
		}

		np = pd->payload.generic.isag_np;

		/* do payload-type specific things that need to be here. */
		switch (thisp) {
		case ISAKMP_NEXT_v2E:
			np = ISAKMP_NEXT_NONE;
			break;
		default: /* nothing special */
			break;
		}

		pd++;
	}

	DBG(DBG_CONTROL,
	    DBG_log("Finished and now at the end of ikev2_process_payload"));
	md->digest_roof = pd;
	return STF_OK;
}

/*
 * process an input packet, possibly generating a reply.
 *
 * If all goes well, this routine eventually calls a state-specific
 * transition function.
 */
void process_v2_packet(struct msg_digest **mdp)
{
	struct msg_digest *md = *mdp;
	struct state *st = NULL;
	enum state_kind from_state = STATE_UNDEFINED; /* state we started in */
	const struct state_v2_microcode *svm;
	enum isakmp_xchg_types ix;

	/* Look for an state which matches the various things we know */
	/*
	 * 1) exchange type received?
	 * 2) is it initiator or not?
	 *
	 */

	md->msgid_received = ntohl(md->hdr.isa_msgid);

	if (md->hdr.isa_flags & ISAKMP_FLAGS_I) {
		/* then I am the responder */

		md->role = RESPONDER;

		DBG(DBG_CONTROL, DBG_log("I am IKE SA Responder"));

		st = find_state_ikev2_parent(md->hdr.isa_icookie,
					     md->hdr.isa_rcookie);

		if (st == NULL) {
			/* first time for this cookie, it's a new state! */
			st = find_state_ikev2_parent_init(md->hdr.isa_icookie);
		}

		if (st) {
			if (st->st_msgid_lastrecv >  md->msgid_received) {
				/* this is an OLD retransmit. we can't do anything */
				libreswan_log(
					"received too old retransmit: %u < %u",
					md->msgid_received,
					st->st_msgid_lastrecv);
				return;
			}
			if (st->st_msgid_lastrecv == md->msgid_received) {
				/* this is a recent retransmit. */
				send_ike_msg(st, "ikev2-responder-retransmit");
				return;
			}
			/* update lastrecv later on */
		}

	} else {
		/* then I am the initiator, and this is a reply */

		md->role = INITIATOR;

		DBG(DBG_CONTROL, DBG_log("I am IKE SA Initiator"));

		if (md->msgid_received == MAINMODE_MSGID) {
			st = find_state_ikev2_parent(md->hdr.isa_icookie,
						     md->hdr.isa_rcookie);
			if (st == NULL) {
				st = find_state_ikev2_parent(
					md->hdr.isa_icookie, zero_cookie);
				if (st) {
					/* responder inserted its cookie, record it */
					unhash_state(st);
					memcpy(st->st_rcookie,
					       md->hdr.isa_rcookie,
					       COOKIE_SIZE);
					insert_state(st);
				}
			}
		} else {
			st = find_state_ikev2_child(md->hdr.isa_icookie,
						    md->hdr.isa_rcookie,
						    md->hdr.isa_msgid); /* PAUL: really? not md->msgid_received */

			if (st) {
				/* found this child state, so we'll use it */
				/* note we update the st->st_msgid_lastack *AFTER* decryption*/
			} else {
				/*
				 * didn't find something with the msgid, so maybe it's
				 * not valid?
				 */
				st = find_state_ikev2_parent(
					md->hdr.isa_icookie,
					md->hdr.isa_rcookie);
			}
		}

		if (st) {
			/*
			 * then there is something wrong with the msgid, so
			 * maybe they retransmitted for some reason.
			 * Check if it's an old packet being returned, and
			 * if so, drop it.
			 * NOTE: in_struct() changed the byte order.
			 */
			if (st->st_msgid_lastack != INVALID_MSGID &&
			    md->msgid_received <= st->st_msgid_lastack) {
				/* it's fine, it's just a retransmit */
				DBG(DBG_CONTROL,
				    DBG_log(
					    "responding peer retransmitted msgid %u",
					    md->msgid_received));
				return;
			}
#if 0
			libreswan_log("last msgid ack is %u, received: %u",
				      st->st_msgid_lastack,
				      md->msgid_received);
			return;

#endif
		}
	}

	ix = md->hdr.isa_xchg;
	if (st) {

		from_state = st->st_state;
		DBG(DBG_CONTROL,
		    DBG_log("state found and its state is (%s)",
			    enum_show(&state_names, from_state)));
	}

	for (svm = state_microcode_table; svm->state != STATE_IKEv2_ROOF;
	     svm++) {
		if (svm->flags & SMF2_STATENEEDED)
			if (st == NULL)
				continue;
		if ((svm->flags & SMF2_STATENEEDED) == 0)
			if (st != NULL)
				continue;
		if (svm->state != from_state)
			continue;
		if (svm->recv_type != ix)
			continue;

		/* I1 receiving NO_PROPOSAL ened up picking the wrong STATE_UNDEFINED state
		   Since the wrong state is a responder, we just add a check for initiator,
		   so we hit STATE_IKEv2_ROOF
		 */
		/*
		   if ( ((svm->flags&SMF2_INITIATOR) != 0) != ((md->hdr.isa_flags & ISAKMP_FLAGS_R) != 0) )
		       continue;
		 */

		/* must be the right state */
		break;
	}

	if (svm->state == STATE_IKEv2_ROOF) {
		DBG(DBG_CONTROL, DBG_log("ended up with STATE_IKEv2_ROOF"));

		/* no useful state */
		if (md->hdr.isa_flags & ISAKMP_FLAGS_I) {
			/* must be an initiator message, so we are the responder */

			/* XXX need to be more specific */
			SEND_NOTIFICATION(INVALID_MESSAGE_ID);
		}
		return;
	}

	{
		stf_status stf;
		stf = ikev2_process_payloads(md, &md->message_pbs,
					     from_state, md->hdr.isa_np);
		DBG(DBG_CONTROL,
		    DBG_log("Finished processing ikev2_process_payloads"));

		if (stf != STF_OK) {
			complete_v2_state_transition(mdp, stf);
			return;
		}
	}

	DBG(DBG_CONTROL,
	    DBG_log("Now lets proceed with state specific processing"));
	DBG(DBG_PARSING, {
		    if (pbs_left(&md->message_pbs) != 0)
			    DBG_log("removing %d bytes of padding",
				    (int) pbs_left(&md->message_pbs));
	    });

	md->message_pbs.roof = md->message_pbs.cur;

#if 0
	/* check that all mandatory payloads appeared */
	if (needed != 0) {
		loglog(RC_LOG_SERIOUS, "message for %s is missing payloads %s",
		       enum_show(&state_names, from_state),
		       bitnamesof(payload_name, needed));
		SEND_NOTIFICATION(PAYLOAD_MALFORMED);
		return;
	}
#endif

	md->svm = svm;
	md->from_state = from_state;
	md->st  = st;

	{
		stf_status stf;
		stf = (svm->processor)(md);
		complete_v2_state_transition(mdp, stf);
	}
}

bool ikev2_decode_peer_id(struct msg_digest *md, enum phase1_role init)
{
	/* struct state *const st = md->st; */
	unsigned int hisID = (init == INITIATOR) ?
			     ISAKMP_NEXT_v2IDr : ISAKMP_NEXT_v2IDi;
	/* unsigned int myID  = initiator ? ISAKMP_NEXT_v2IDi: ISAKMP_NEXT_v2IDr;
	 * struct payload_digest *const id_me  = md->chain[myID];
	 */
	struct payload_digest *const id_him = md->chain[hisID];
	const pb_stream * id_pbs;
	struct ikev2_id * id;
	struct id peer;

	if (!id_him) {
		libreswan_log("IKEv2 mode no peer ID (hisID)");
		return FALSE;
	}

	id_pbs = &id_him->pbs;
	id = &id_him->payload.v2id;
	peer.kind = id->isai_type;

	if (!extract_peer_id(&peer, id_pbs)) {
		libreswan_log("IKEv2 mode peer ID extraction failed");
		return FALSE;
	}

	{
		char buf[IDTOA_BUF];

		idtoa(&peer, buf, sizeof(buf));
		libreswan_log("IKEv2 mode peer ID is %s: '%s'",
			      enum_show(&ident_names, id->isai_type), buf);
	}

	return TRUE;
}

/*
 * this logs to the main log (including peerlog!) the authentication
 * and encryption keys for an IKEv2 SA.  This is done in a format that
 * is compatible with tcpdump 4.0's -E option.
 *
 * The peerlog will be perfect, the syslog will require that a cut
 * command is used to remove the initial text.
 *
 */
void ikev2_log_parentSA(struct state *st)
{
	const char *authalgo;
	char authkeybuf[256];
	char encalgo[128];
	char enckeybuf[256];

	if (st->st_oakley.integ_hasher == NULL ||
	    st->st_oakley.encrypter == NULL)
		return;

	authalgo = st->st_oakley.integ_hasher->common.officname;

	if (st->st_oakley.enckeylen != 0) {
		/* 3des will use '3des', while aes becomes 'aes128' */
		snprintf(encalgo, sizeof(encalgo), "%s%u",
			 st->st_oakley.encrypter->common.officname,
			 st->st_oakley.enckeylen);
	} else {
		strncpy(encalgo, st->st_oakley.encrypter->common.officname,
			sizeof(encalgo));
	}

	if (DBGP(DBG_CRYPT)) {
		datatot(st->st_skey_ei.ptr, st->st_skey_ei.len, 'x', enckeybuf,
			256);
		datatot(st->st_skey_ai.ptr, st->st_skey_ai.len, 'x',
			authkeybuf, 256);
		DBG_log(
			"ikev2 I 0x%02x%02x%02x%02x%02x%02x%02x%02x 0x%02x%02x%02x%02x%02x%02x%02x%02x %s:%s %s:%s",
			st->st_icookie[0], st->st_icookie[1],
			st->st_icookie[2], st->st_icookie[3],
			st->st_icookie[4], st->st_icookie[5],
			st->st_icookie[6], st->st_icookie[7],
			st->st_rcookie[0], st->st_rcookie[1],
			st->st_rcookie[2], st->st_rcookie[3],
			st->st_rcookie[4], st->st_rcookie[5],
			st->st_rcookie[6], st->st_rcookie[7],
			authalgo,
			authkeybuf,
			encalgo,
			enckeybuf);

		datatot(st->st_skey_er.ptr, st->st_skey_er.len, 'x', enckeybuf,
			256);
		datatot(st->st_skey_ar.ptr, st->st_skey_ar.len, 'x',
			authkeybuf, 256);
		DBG_log(
			"ikev2 R 0x%02x%02x%02x%02x%02x%02x%02x%02x 0x%02x%02x%02x%02x%02x%02x%02x%02x %s:%s %s:%s",
			st->st_icookie[0], st->st_icookie[1],
			st->st_icookie[2], st->st_icookie[3],
			st->st_icookie[4], st->st_icookie[5],
			st->st_icookie[6], st->st_icookie[7],
			st->st_rcookie[0], st->st_rcookie[1],
			st->st_rcookie[2], st->st_rcookie[3],
			st->st_rcookie[4], st->st_rcookie[5],
			st->st_rcookie[6], st->st_rcookie[7],
			authalgo,
			authkeybuf,
			encalgo,
			enckeybuf);
	}
}

void send_v2_notification_from_state(struct state *st, enum state_kind state,
				     u_int16_t type, chunk_t *data)
{
	passert(st);

	if (state == STATE_UNDEFINED)
		state = st->st_state;

	send_v2_notification(st, type, NULL, st->st_icookie, st->st_rcookie,
			     data);
}

void send_v2_notification_from_md(struct msg_digest *md UNUSED, u_int16_t type,
				  chunk_t *data)
{
	struct state st;
	struct connection cnx;

	/**
	 * Create a dummy state to be able to use send_ike_msg in
	 * send_notification
	 *
	 * we need to set:
	 *   st_connection->that.host_addr
	 *   st_connection->that.host_port
	 *   st_connection->interface
	 */
	passert(md);

	memset(&st, 0, sizeof(st));
	memset(&cnx, 0, sizeof(cnx));
	st.st_connection = &cnx;
	st.st_remoteaddr = md->sender;
	st.st_remoteport = md->sender_port;
	st.st_localaddr  = md->iface->ip_addr;
	st.st_localport  = md->iface->port;
	cnx.interface = md->iface;
	st.st_interface = md->iface;

	send_v2_notification(&st, type, NULL,
			     md->hdr.isa_icookie, md->hdr.isa_rcookie, data);
}

void ikev2_update_counters(struct msg_digest *md)
{
	struct state *pst = md->pst;
	struct state *st = md->st;

	if (pst == NULL) {
		if (st->st_clonedfrom != 0)
			pst = state_with_serialno(st->st_clonedfrom);
		if (pst == NULL)
			pst = st;
	}

	switch (md->role) {
	case INITIATOR:
		/* update lastuse values */
		pst->st_msgid_lastack = md->msgid_received;
		pst->st_msgid_nextuse = pst->st_msgid_lastack + 1;
		break;

	case RESPONDER:
		pst->st_msgid_lastrecv = md->msgid_received;
		break;
	}
}

static void success_v2_state_transition(struct msg_digest **mdp)
{
	struct msg_digest *md = *mdp;
	const struct state_v2_microcode *svm = md->svm;
	enum state_kind from_state = md->from_state;
	struct state *st = md->st;
	enum rc_type w;

	if (from_state != svm->next_state) {
		libreswan_log("transition from state %s to state %s",
			      enum_name(&state_names, from_state),
			  enum_name(&state_names, svm->next_state));
	}
	change_state(st, svm->next_state);
	w = RC_NEW_STATE + st->st_state;

	ikev2_update_counters(md);

	/* tell whack and log of progress, if we are actually advancing */
	if (from_state != svm->next_state) {
		const char *story = enum_name(&state_stories, st->st_state);
		char sadetails[512];

		passert(st->st_state >= STATE_IKEv2_BASE);
		passert(st->st_state <  STATE_IKEv2_ROOF);

		sadetails[0] = '\0';

		/* document IPsec SA details for admin's pleasure */
		if (IS_CHILD_SA_ESTABLISHED(st)) {
			char usubl[128], usubh[128];
			char tsubl[128], tsubh[128];

			addrtot(&st->st_ts_this.low,  0, usubl, sizeof(usubl));
			addrtot(&st->st_ts_this.high, 0, usubh, sizeof(usubh));
			addrtot(&st->st_ts_that.low,  0, tsubl, sizeof(tsubl));
			addrtot(&st->st_ts_that.high, 0, tsubh, sizeof(tsubh));

			/* but if this is the parent st, this information is not set! you need to check the child sa! */
			libreswan_log(
				"negotiated tunnel [%s,%s:%d-%d %d] -> [%s,%s:%d-%d %d]",
				usubl, usubh, st->st_ts_this.startport, st->st_ts_this.endport, st->st_ts_this.ipprotoid,
				tsubl, tsubh, st->st_ts_that.startport, st->st_ts_that.endport,
				st->st_ts_that.ipprotoid);

			fmt_ipsec_sa_established(st,  sadetails,
						 sizeof(sadetails));
		} else if (IS_PARENT_SA_ESTABLISHED(st->st_state)) {
			fmt_isakmp_sa_established(st, sadetails,
						  sizeof(sadetails));
		}

		if (IS_CHILD_SA_ESTABLISHED(st)) {
			/* log our success */
			w = RC_SUCCESS;
		}

		/* tell whack and logs our progress */
		loglog(w,
		       "%s: %s%s",
		       enum_name(&state_names, st->st_state),
		       story,
		       sadetails);
	}

	/* if requested, send the new reply packet */
	if (svm->flags & SMF2_REPLY) {

		/* free previously transmitted packet */
		freeanychunk(st->st_tpacket);
#ifdef NAT_TRAVERSAL
		if (nat_traversal_enabled) {
			/* adjust our destination port if necessary */
			nat_traversal_change_port_lookup(md, st);
		}
#endif
		DBG(DBG_CONTROL, {
			    char buf[ADDRTOT_BUF];
			    DBG_log(
				    "sending reply packet to %s:%u (from port %u)",
				    (addrtot(&st->st_remoteaddr,
					     0, buf, sizeof(buf)), buf),
				    st->st_remoteport,
				    st->st_interface->port);
		    });

		close_output_pbs(&reply_stream); /* good form, but actually a no-op */

		clonetochunk(st->st_tpacket, reply_stream.start,
			     pbs_offset(&reply_stream), "reply packet");

		/* actually send the packet
		 * Note: this is a great place to implement "impairments"
		 * for testing purposes.  Suppress or duplicate the
		 * send_ike_msg call depending on st->st_state.
		 */

		TCLCALLOUT("avoidEmitting", st, st->st_connection, md);
		send_ike_msg(st, enum_name(&state_names, from_state));
	}

	TCLCALLOUT("adjustTimers", st, st->st_connection, md);

	if (w == RC_SUCCESS) {
		struct state *pst;

		DBG_log("releasing whack for #%lu (sock=%d)",
			st->st_serialno, st->st_whack_sock);
		release_whack(st);

		/* XXX should call unpend again on parent SA */
		if (st->st_clonedfrom != 0) {
			pst = state_with_serialno(st->st_clonedfrom); /* with failed child sa, we end up here with an orphan?? */
			DBG_log("releasing whack and unpending for #%lu (sock=%d)",
				pst->st_serialno, pst->st_whack_sock);
			unpend(pst);
			release_whack(pst);
		}
	}

	/* Schedule for whatever timeout is specified */
	{
		time_t delay;
		enum event_type kind = svm->timeout_event;
		struct connection *c = st->st_connection;

		switch (kind) {
		case EVENT_SA_REPLACE: /* SA replacement event */
			if (IS_PARENT_SA(st)) {
				/* Note: we will defer to the "negotiated" (dictated)
				 * lifetime if we are POLICY_DONT_REKEY.
				 * This allows the other side to dictate
				 * a time we would not otherwise accept
				 * but it prevents us from having to initiate
				 * rekeying.  The negative consequences seem
				 * minor.
				 */
				delay = c->sa_ike_life_seconds;
			} else {
				/* Delay is what the user said, no negotiation.
				 */
				delay = c->sa_ipsec_life_seconds;
			}

			/* By default, we plan to rekey.
			 *
			 * If there isn't enough time to rekey, plan to
			 * expire.
			 *
			 * If we are --dontrekey, a lot more rules apply.
			 * If we are the Initiator, use REPLACE_IF_USED.
			 * If we are the Responder, and the dictated time
			 * was unacceptable (too large), plan to REPLACE
			 * (the only way to ratchet down the time).
			 * If we are the Responder, and the dictated time
			 * is acceptable, plan to EXPIRE.
			 *
			 * Important policy lies buried here.
			 * For example, we favour the initiator over the
			 * responder by making the initiator start rekeying
			 * sooner.  Also, fuzz is only added to the
			 * initiator's margin.
			 *
			 * Note: for ISAKMP SA, we let the negotiated
			 * time stand (implemented by earlier logic).
			 */
			if (kind != EVENT_SA_EXPIRE) {
				unsigned long marg = c->sa_rekey_margin;

				if (svm->flags & SMF2_INITIATOR) {
					marg += marg *
						c->sa_rekey_fuzz / 100.E0 *
						(rand() / (RAND_MAX + 1.E0));
				} else {
					marg /= 2;
				}

				if ((unsigned long)delay > marg) {
					delay -= marg;
					st->st_margin = marg;
				} else {
					kind = EVENT_SA_EXPIRE;
				}
			}
			delete_event(st);
			event_schedule(kind, delay, st);
			break;

		case EVENT_NULL:
			/* XXX: Is there really no case where we want to set no timer? */
			/* dos_cookie is one 'valid' event, but it is used more? */
			break;

		case EVENT_REINIT_SECRET: /* Refresh cookie secret */
		default:
			bad_case(kind);
		}
		/* start liveness checks if set, making sure we only schedule once when moving 
		 * from I2->I3 or R1->R2 */
		if ((c->dpd_action == DPD_ACTION_CLEAR || c->dpd_action == DPD_ACTION_RESTART
		     || c->dpd_action == DPD_ACTION_RESTART_BY_PEER) && IS_V2_ESTABLISHED(st->st_state)
							             && st->st_state != from_state) {

			DBG_log("dpd_action set, indicating that we want to use liveness checks");
			st->hidden_variables.st_liveness = TRUE;
			event_schedule(EVENT_v2_LIVENESS,
					c->dpd_delay >= MIN_LIVENESS ? c->dpd_delay : MIN_LIVENESS,
					st);
		}

	}


#ifdef TPM
tpm_ignore:
	return;

tpm_stolen:
	*mdp = NULL;
	return;

#endif

}

void complete_v2_state_transition(struct msg_digest **mdp,
				  stf_status result)
{
	struct msg_digest *md = *mdp;
	/* const struct state_v2_microcode *svm=md->svm; */
	struct state *st;
	enum state_kind from_state = STATE_UNDEFINED;
	const char *from_state_name;

	cur_state = st = md->st; /* might have changed */

	/* passert(st);   apparently on STF_TOOMUCH_CRYPTO we have no state? Needs fixing */
	/*
	 * XXX/SML:  There is no need to abort here in all cases if state is
	 * null, so moved this precondition to where it's needed.  Some previous
	 * logic appears to have been tooled to handle null state, and state might
	 * be null legitimately in certain failure cases (STF_FAIL + xxx).
	 *
	 * One condition for null state is when a new connection request packet
	 * arrives and there is no suitable matching configuration.  For example,
	 * ikev2parent_inI1outR1() will return (STF_FAIL + NO_PROPOSAL_CHOSEN) but
	 * no state in this case.  While other failures may be better caught before
	 * this function is called, we should be graceful here.  And for this
	 * particular case, and similar failure cases, we want SEND_NOTIFICATION
	 * (below) to let the peer know why we've rejected the request.
	 */
	if (st) {
		from_state_name = enum_name(&state_names, st->st_state);
		from_state   = st->st_state;
	} else {
		from_state_name = "no-state";
	}

	md->result = result;
	TCLCALLOUT("v2AdjustFailure", st, (st ? st->st_connection : NULL), md);
	result = md->result;

	/* advance the state */
	DBG(DBG_CONTROL,
	    DBG_log("complete v2 state transition with %s",
		    enum_name(&stfstatus_name,
			      (result > STF_FAIL) ? STF_FAIL : result)));

	switch (result) {
	case STF_IGNORE:
		break;

	case STF_INLINE:     /* this is second time through complete
		              * state transition, so the MD has already
		              * been freed.
		                0				  */
		*mdp = NULL;
		break;

	case STF_SUSPEND:
		/* update the previous packet history */
		/* IKEv2 XXX */ /* update_retransmit_history(st, md); */

		/* the stf didn't complete its job: don't relase md */
		*mdp = NULL;
		break;

	case STF_OK:
		/* advance the state */
		passert(st);
		success_v2_state_transition(mdp);
		break;

	case STF_INTERNAL_ERROR:
		lsw_abort();
		break;

	case STF_TOOMUCHCRYPTO:
		/* well, this should never happen during a whack, since
		 * a whack will always force crypto.
		 */
		passert(st);
		set_suspended(st, NULL);
		pexpect(st->st_calculating == FALSE);
		libreswan_log("message in state %s ignored due to "
			      "cryptographic overload",
			      from_state_name);
		break;

	case STF_FATAL:
		/* update the previous packet history */
		/* update_retransmit_history(st, md); */

		passert(st);
		whack_log(RC_FATAL,
			  "encountered fatal error in state %s",
			  from_state_name);
		delete_event(st);
		{
			struct state *pst;
			release_whack(st);
			if (st->st_clonedfrom != 0) {
				pst = state_with_serialno(st->st_clonedfrom);
				release_whack(pst);
			}
		}
		release_pending_whacks(st, "fatal error");
		delete_state(st);
		break;

	default: /* a shortcut to STF_FAIL, setting md->note */
		passert(result > STF_FAIL);
		md->note = result - STF_FAIL;
		result = STF_FAIL;
	/* FALL THROUGH ... */

	case STF_FAIL:

		whack_log(RC_NOTIFICATION + md->note,
			  "%s: %s",
			  from_state_name,
			  enum_name(&ipsec_notification_names, md->note));

		if (md->note > 0) {
			/* only send a notify is this packet was a question, not if it was an answer */
			if (!(md->hdr.isa_flags & ISAKMP_FLAGS_R))
				SEND_NOTIFICATION(md->note);
		}

		DBG(DBG_CONTROL,
		    DBG_log("state transition function for %s failed: %s",
			    from_state_name,
			    (md->note) ? enum_name(&ipsec_notification_names,
						   md->note) :
			    "<no reason given>" ));
	}
#ifdef TPM
tpm_ignore:
	return;

tpm_stolen:
	*mdp = NULL;
	return;

#endif
}

v2_notification_t accept_v2_nonce(struct msg_digest *md, chunk_t *dest,
				  const char *name)
{
	return accept_nonce(md, dest, name, ISAKMP_NEXT_v2Ni);
}
