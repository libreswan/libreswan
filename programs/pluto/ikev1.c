/* State machine for IKEv1
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2010,2013-2016 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2008-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2011 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2008 Hiren Joshi <joshihirenn@gmail.com>
 * Copyright (C) 2009 Anthony Tong <atong@TrustedCS.com>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
 * Copyright (C) 2019-2019 Andrew Cagney <cagney@gnu.org>
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

/* Ordering Constraints on Payloads
 *
 * rfc2409: The Internet Key Exchange (IKE)
 *
 * 5 Exchanges:
 *   "The SA payload MUST precede all other payloads in a phase 1 exchange."
 *
 *   "Except where otherwise noted, there are no requirements for ISAKMP
 *    payloads in any message to be in any particular order."
 *
 * 5.3 Phase 1 Authenticated With a Revised Mode of Public Key Encryption:
 *
 *   "If the HASH payload is sent it MUST be the first payload of the
 *    second message exchange and MUST be followed by the encrypted
 *    nonce. If the HASH payload is not sent, the first payload of the
 *    second message exchange MUST be the encrypted nonce."
 *
 *   "Save the requirements on the location of the optional HASH payload
 *    and the mandatory nonce payload there are no further payload
 *    requirements. All payloads-- in whatever order-- following the
 *    encrypted nonce MUST be encrypted with Ke_i or Ke_r depending on the
 *    direction."
 *
 * 5.5 Phase 2 - Quick Mode
 *
 *   "In Quick Mode, a HASH payload MUST immediately follow the ISAKMP
 *    header and a SA payload MUST immediately follow the HASH."
 *   [NOTE: there may be more than one SA payload, so this is not
 *    totally reasonable.  Probably all SAs should be so constrained.]
 *
 *   "If ISAKMP is acting as a client negotiator on behalf of another
 *    party, the identities of the parties MUST be passed as IDci and
 *    then IDcr."
 *
 *   "With the exception of the HASH, SA, and the optional ID payloads,
 *    there are no payload ordering restrictions on Quick Mode."
 */

/* Unfolding of Identity -- a central mystery
 *
 * This concerns Phase 1 identities, those of the IKE hosts.
 * These are the only ones that are authenticated.  Phase 2
 * identities are for IPsec SAs.
 *
 * There are three case of interest:
 *
 * (1) We initiate, based on a whack command specifying a Connection.
 *     We know the identity of the peer from the Connection.
 *
 * (2) (to be implemented) we initiate based on a flow from our client
 *     to some IP address.
 *     We immediately know one of the peer's client IP addresses from
 *     the flow.  We must use this to figure out the peer's IP address
 *     and Id.  To be solved.
 *
 * (3) We respond to an IKE negotiation.
 *     We immediately know the peer's IP address.
 *     We get an ID Payload in Main I2.
 *
 *     Unfortunately, this is too late for a number of things:
 *     - the ISAKMP SA proposals have already been made (Main I1)
 *       AND one accepted (Main R1)
 *     - the SA includes a specification of the type of ID
 *       authentication so this is negotiated without being told the ID.
 *     - with Preshared Key authentication, Main I2 is encrypted
 *       using the key, so it cannot be decoded to reveal the ID
 *       without knowing (or guessing) which key to use.
 *
 *     There are three reasonable choices here for the responder:
 *     + assume that the initiator is making wise offers since it
 *       knows the IDs involved.  We can balk later (but not gracefully)
 *       when we find the actual initiator ID
 *     + attempt to infer identity by IP address.  Again, we can balk
 *       when the true identity is revealed.  Actually, it is enough
 *       to infer properties of the identity (eg. SA properties and
 *       PSK, if needed).
 *     + make all properties universal so discrimination based on
 *       identity isn't required.  For example, always accept the same
 *       kinds of encryption.  Accept Public Key Id authentication
 *       since the Initiator presumably has our public key and thinks
 *       we must have / can find peers.  This approach is weakest
 *       for preshared key since the actual key must be known to
 *       decrypt the Initiator's ID Payload.
 *     These choices can be blended.  For example, a class of Identities
 *     can be inferred, sufficient to select a preshared key but not
 *     sufficient to infer a unique identity.
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


#include "sysdep.h"
#include "constants.h"

#include "defs.h"
#include "ike_spi.h"
#include "id.h"
#include "x509.h"
#include "pluto_x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "ikev1_msgid.h"
#include "packet.h"
#include "crypto.h"
#include "ike_alg.h"
#include "log.h"
#include "demux.h"      /* needs packet.h */
#include "ikev1.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "ikev1_quick.h"
#include "timer.h"
#include "whack.h"      /* requires connections.h */
#include "server.h"
#include "send.h"
#include "ikev1_send.h"
#include "ikev1_xauth.h"
#include "retransmit.h"
#include "nat_traversal.h"
#include "ikev1_nat.h"
#include "ikev1_vendorid.h"
#include "ikev1_dpd.h"
#include "ip_address.h"
#include "ikev1_hash.h"
#include "crypt_cipher.h"
#include "ikev1_states.h"
#include "initiate.h"
#include "iface.h"
#include "ip_selector.h"
#include "unpack.h"
#include "pending.h"
#include "rekeyfuzz.h"
#include "updown.h"
#include "ikev1_delete.h"
#include "terminate.h"

#ifdef HAVE_NM
#include "kernel.h"
#endif

#include "pluto_stats.h"

static bool v1_state_busy(const struct state *st);
static bool verbose_v1_state_busy(const struct state *st);

void jam_v1_transition(struct jambuf *buf, const struct state_v1_microcode *transition)
{
	if (transition == NULL) {
		jam(buf, "NULL");
	} else {
		jam(buf, "%s->%s",
		    finite_states[transition->state]->short_name,
		    finite_states[transition->next_state]->short_name);
	}
}

stf_status unexpected(struct state *st, struct msg_digest *md UNUSED)
{
	log_state(RC_LOG, st, "unexpected message received in state %s",
		  st->st_state->name);
	return STF_IGNORE;
}

/*
 * RFC 2408 Section 4.6
 *
 *  #   Initiator  Direction Responder  NOTE
 * (1)  HDR*; N/D     =>                Error Notification or Deletion
 */
stf_status informational(struct state *st, struct msg_digest *md)
{
	/*
	 * XXX: Danger: ST is deleted midway through this function.
	 */
	pexpect(st == md->v1_st);
	st = md->v1_st;    /* may be NULL */

	struct payload_digest *const n_pld = md->chain[ISAKMP_NEXT_N];

	/* If the Notification Payload is not null... */
	if (n_pld != NULL) {
		struct pbs_in *const n_pbs = &n_pld->pbs;
		struct isakmp_notification *const n =
			&n_pld->payload.notification;

		/* Switch on Notification Type (enum) */
		/* note that we _can_ get notification payloads unencrypted
		 * once we are at least in R3/I4.
		 * and that the handler is expected to treat them suspiciously.
		 */
		enum_buf eb;
		dbg("processing informational %s (%d)",
		    str_enum_short(&v1_notification_names, n->isan_type, &eb),
		    n->isan_type);

		pstats(ikev1_recv_notifies_e, n->isan_type);

		switch (n->isan_type) {
		/*
		 * We answer DPD probes even if they claimed not to support
		 * Dead Peer Detection.
		 * We would have to send some kind of reply anyway to prevent
		 * a retransmit, so rather then send an error, we might as
		 * well just send a DPD reply
		 */
		case v1N_R_U_THERE:
			if (st == NULL) {
				llog(RC_LOG, md->logger,
				     "received bogus R_U_THERE informational message");
				return STF_IGNORE;
			}
			return dpd_inI_outR(st, n, n_pbs);

		case v1N_R_U_THERE_ACK:
			if (st == NULL) {
				llog(RC_LOG, md->logger,
				     "received bogus R_U_THERE_ACK informational message");
				return STF_IGNORE;
			}
			return dpd_inR(st, n, n_pbs);

		case v1N_PAYLOAD_MALFORMED:
			if (st != NULL) {
				st->hidden_variables.st_malformed_received++;

				log_state(RC_LOG, st, "received %u malformed payload notifies",
					  st->hidden_variables.st_malformed_received);

				if (st->hidden_variables.st_malformed_sent >
				    MAXIMUM_MALFORMED_NOTIFY / 2 &&
				    ((st->hidden_variables.st_malformed_sent +
				      st->hidden_variables.
				      st_malformed_received) >
				     MAXIMUM_MALFORMED_NOTIFY)) {
					log_state(RC_LOG, st, "too many malformed payloads (we sent %u and received %u",
						  st->hidden_variables.st_malformed_sent,
						  st->hidden_variables.st_malformed_received);
					connection_delete_v1_state(&st, HERE);
					md->v1_st = st = NULL;
				}
			}

			return STF_IGNORE;

		default:
		{
			struct logger *logger = st != NULL ? st->logger :
							     md->logger;
			enum_buf eb;
			llog(RC_LOG, logger,
			     "received and ignored notification payload: %s",
			     str_enum_short(&v1_notification_names, n->isan_type, &eb));
			return STF_IGNORE;
		}
		}
	} else {
		/* warn if we didn't find any Delete or Notify payload in packet */
		if (md->chain[ISAKMP_NEXT_D] == NULL) {
			const struct logger *logger = (st != NULL ? st->logger :
						 md->logger);
			llog(RC_LOG, logger,
				    "received and ignored empty informational notification payload");
		}
		return STF_IGNORE;
	}
}

/*
 * create output HDR as replica of input HDR - IKEv1 only; return the body
 */
void ikev1_init_pbs_out_from_md_hdr(struct msg_digest *md, bool enc,
				    struct pbs_out *output_stream, uint8_t *output_buffer,
				    size_t sizeof_output_buffer,
				    struct pbs_out *rbody,
				    struct logger *logger)
{
	struct isakmp_hdr hdr = md->hdr; /* mostly same as incoming header */

	/* make sure we start with a clean buffer */
	*output_stream = open_pbs_out("reply packet", output_buffer, sizeof_output_buffer, logger);

	hdr.isa_flags = 0; /* zero all flags */
	if (enc)
		hdr.isa_flags |= ISAKMP_FLAGS_v1_ENCRYPTION;

	if (impair.send_bogus_isakmp_flag) {
		hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
	}

	/* there is only one IKEv1 version, and no new one will ever come - no need to set version */
	hdr.isa_np = 0;
	/* surely must have room and be well-formed */
	passert(out_struct(&hdr, &isakmp_hdr_desc, output_stream, rbody));
}

/*
 * Recognise and, if necesssary, respond to an IKEv1 duplicate.
 *
 * Use .st_state, which is the true current state, and not MD
 * .FROM_STATE (which is derived from some convoluted magic) when
 * determining if the duplicate should or should not get a response.
 */
static bool ikev1_duplicate(struct state *st, struct msg_digest *md)
{
	passert(st != NULL);
	if (hunk_eq(st->st_v1_rpacket, pbs_in_all(&md->packet_pbs))) {
		/*
		 * Exact Duplicate.  Drop or retransmit?
		 *
		 * Only re-transmit when the last state transition
		 * (triggered by this packet the first time) included
		 * a reply.
		 *
		 * XXX: is SMF_RETRANSMIT_ON_DUPLICATE useful or
		 * correct?
		 */
		bool replied = (st->st_v1_last_transition != NULL &&
				(st->st_v1_last_transition->flags & SMF_REPLY));
		bool retransmit_on_duplicate =
			(st->st_state->v1.flags & SMF_RETRANSMIT_ON_DUPLICATE);
		if (replied && retransmit_on_duplicate) {
			/*
			 * Transitions with EVENT_v1_DISCARD should
			 * always respond to re-transmits (why?); else
			 * cap.
			 */
			if (st->st_v1_last_transition->timeout_event == EVENT_v1_DISCARD ||
			    count_duplicate(st, MAXIMUM_v1_ACCEPTED_DUPLICATES)) {
				log_state(RC_LOG, st,
					  "retransmitting in response to duplicate packet; already %s",
					  st->st_state->name);
				resend_recorded_v1_ike_msg(st, "retransmit in response to duplicate");
			} else {
				log_state(RC_LOG, st,
					  "discarding duplicate packet -- exhausted retransmission; already %s",
					  st->st_state->name);
			}
		} else {
			dbg("#%lu discarding duplicate packet; already %s; replied=%s retransmit_on_duplicate=%s",
			    st->st_serialno, st->st_state->name,
			    bool_str(replied), bool_str(retransmit_on_duplicate));
		}
		return true;
	}
	return false;
}

/* process an input packet, possibly generating a reply.
 *
 * If all goes well, this routine eventually calls a state-specific
 * transition function.
 *
 * This routine will not md_delref(mdp).  It is expected that its
 * caller will do this.  In fact, it will zap *mdp to NULL if it thinks
 * **mdp should not be freed.  So the caller should be prepared for
 * *mdp being set to NULL.
 */
void process_v1_packet(struct msg_digest *md)
{
	bool new_iv_set = false;
	struct state *st = NULL;
	enum state_kind from_state = STATE_UNDEFINED;   /* state we started in */

	/*
	 * For the initial responses, don't leak the responder's SPI.
	 * Hence the use of send_v1_notification_from_md().
	 *
	 * AGGR mode is a mess in that the R0->R1 transition happens
	 * well before the transition succeeds.
	 */
#define SEND_NOTIFICATION(t)						\
	{								\
		pstats(ikev1_sent_notifies_e, t);			\
		if (st != NULL &&					\
		    st->st_state->kind != STATE_AGGR_R0 &&		\
		    st->st_state->kind != STATE_AGGR_R1 &&		\
		    st->st_state->kind != STATE_MAIN_R0)		\
			send_v1_notification_from_state(st, from_state, t); \
		else							\
			send_v1_notification_from_md(md, t);		\
	}

#define LOGGER (st != NULL ? st->logger : md->logger)

#define LOG_PACKET(RC, ...) llog(RC, LOGGER, __VA_ARGS__)
#define LOG_PACKET_JAMBUF(RC_FLAGS, BUF) LLOG_JAMBUF(RC_FLAGS, LOGGER, BUF)

	switch (md->hdr.isa_xchg) {
	case ISAKMP_XCHG_AGGR:
	case ISAKMP_XCHG_IDPROT: /* part of a Main Mode exchange */
		if (md->hdr.isa_msgid != v1_MAINMODE_MSGID) {
			LOG_PACKET(RC_LOG, "Message ID was 0x%08" PRIx32 " but should be zero in phase 1",
				   md->hdr.isa_msgid);
			SEND_NOTIFICATION(v1N_INVALID_MESSAGE_ID);
			return;
		}

		if (ike_spi_is_zero(&md->hdr.isa_ike_initiator_spi)) {
			LOG_PACKET(RC_LOG, "Initiator Cookie must not be zero in phase 1 message");
			SEND_NOTIFICATION(v1N_INVALID_COOKIE);
			return;
		}

		if (ike_spi_is_zero(&md->hdr.isa_ike_responder_spi)) {
			/*
			 * initial message from initiator
			 */
			if (md->hdr.isa_flags & ISAKMP_FLAGS_v1_ENCRYPTION) {
				LOG_PACKET(RC_LOG, "initial phase 1 message is invalid: its Encrypted Flag is on");
				SEND_NOTIFICATION(v1N_INVALID_FLAGS);
				return;
			}

			/*
			 * If there is already an existing state with
			 * this ICOOKIE, assume it is some sort of
			 * re-transmit.
			 */
			st = find_state_ikev1_init(&md->hdr.isa_ike_initiator_spi,
						   md->hdr.isa_msgid);
			if (st != NULL) {
				if (!ikev1_duplicate(st, md)) {
					/*
					 * Not a duplicate for the
					 * current state; assume that
					 * this a really old
					 * re-transmit for an earlier
					 * state that should be
					 * discarded.
					 */
					log_state(RC_LOG, st, "discarding initial packet; already %s",
						  st->st_state->name);
				}
				return;
			}
			passert(st == NULL); /* new state needed */
			/* don't build a state until the message looks tasty */
			from_state = (md->hdr.isa_xchg == ISAKMP_XCHG_IDPROT ?
				      STATE_MAIN_R0 : STATE_AGGR_R0);
		} else {
			/*
			 * Possibly not an initial message.  Possibly
			 * from initiator.  Possibly from responder.
			 *
			 * Possibly.  Which is probably hopeless.
			 */

			st = find_state_ikev1(&md->hdr.isa_ike_spis,
					      md->hdr.isa_msgid);

			if (st == NULL) {
				/*
				 * Perhaps this is a first message
				 * from the responder and contains a
				 * responder cookie that we've not yet
				 * seen.
				 *
				 * Perhaps this is a random message
				 * with a bogus non-zero responder IKE
				 * SPI.
				 */
				st = find_state_ikev1_init(&md->hdr.isa_ike_initiator_spi,
							   md->hdr.isa_msgid);

				if (st == NULL) {
					llog(RC_LOG, md->logger,
					     "phase 1 message is part of an unknown exchange");
					/* XXX Could send notification back */
					return;
				}
				if (st->st_state->kind == STATE_AGGR_R0) {
					/*
					 * The only way for this to
					 * happen is for the attacker
					 * to guess the responder's
					 * IKE SPI that hasn't been
					 * sent over the wire?
					 *
					 * Well that or played 1/2^32
					 * odds.
					 */
					llog_pexpect(md->logger, HERE,
						     "phase 1 message matching AGGR_R0 state");
					return;
				}
			}
			from_state = st->st_state->kind;
		}
		break;

	case ISAKMP_XCHG_INFO:  /* an informational exchange */
		st = find_v1_info_state(&md->hdr.isa_ike_spis,
					v1_MAINMODE_MSGID);

		if (st == NULL) {
			/*
			 * might be an informational response to our
			 * first message, in which case, we don't know
			 * the rcookie yet.
			 */
			st = find_state_ikev1_init(&md->hdr.isa_ike_initiator_spi,
						   v1_MAINMODE_MSGID);
		}

		if (md->hdr.isa_flags & ISAKMP_FLAGS_v1_ENCRYPTION) {
			bool quiet = (st == NULL);

			if (st == NULL) {
				if (DBGP(DBG_BASE)) {
					DBG_log("Informational Exchange is for an unknown (expired?) SA with MSGID:0x%08" PRIx32,
						md->hdr.isa_msgid);
					DBG_dump_thing("- unknown SA's md->hdr.isa_ike_initiator_spi.bytes:",
						       md->hdr.isa_ike_initiator_spi);
					DBG_dump_thing("- unknown SA's md->hdr.isa_ike_responder_spi.bytes:",
						       md->hdr.isa_ike_responder_spi);
				}

				/* XXX Could send notification back */
				return;
			}

			if (!IS_V1_ISAKMP_ENCRYPTED(st->st_state->kind)) {
				if (!quiet) {
					log_state(RC_LOG, st,
						  "encrypted Informational Exchange message is invalid because no key is known");
				}
				/* XXX Could send notification back */
				return;
			}

			if (md->hdr.isa_msgid == v1_MAINMODE_MSGID) {
				if (!quiet) {
					log_state(RC_LOG, st,
						  "Informational Exchange message is invalid because it has a Message ID of 0");
				}
				/* XXX Could send notification back */
				return;
			}

			if (!unique_msgid(st, md->hdr.isa_msgid)) {
				if (!quiet) {
					log_state(RC_LOG, st,
						  "Informational Exchange message is invalid because it has a previously used Message ID (0x%08" PRIx32 " )",
						  md->hdr.isa_msgid);
				}
				/* XXX Could send notification back */
				return;
			}
			st->st_v1_msgid.reserved = false;

			init_phase2_iv(st, &md->hdr.isa_msgid);
			new_iv_set = true;

			from_state = STATE_INFO_PROTECTED;
		} else {
			if (st != NULL &&
			    IS_V1_ISAKMP_AUTHENTICATED(st->st_state)) {
				log_state(RC_LOG, st,
					  "Informational Exchange message must be encrypted");
				/* XXX Could send notification back */
				return;
			}
			from_state = STATE_INFO;
		}
		break;

	case ISAKMP_XCHG_QUICK: /* part of a Quick Mode exchange */

		if (ike_spi_is_zero(&md->hdr.isa_ike_initiator_spi)) {
			dbg("Quick Mode message is invalid because it has an Initiator Cookie of 0");
			SEND_NOTIFICATION(v1N_INVALID_COOKIE);
			return;
		}

		if (ike_spi_is_zero(&md->hdr.isa_ike_responder_spi)) {
			dbg("Quick Mode message is invalid because it has a Responder Cookie of 0");
			SEND_NOTIFICATION(v1N_INVALID_COOKIE);
			return;
		}

		if (md->hdr.isa_msgid == v1_MAINMODE_MSGID) {
			dbg("Quick Mode message is invalid because it has a Message ID of 0");
			SEND_NOTIFICATION(v1N_INVALID_MESSAGE_ID);
			return;
		}

		st = find_state_ikev1(&md->hdr.isa_ike_spis,
				      md->hdr.isa_msgid);

		if (st == NULL) {
			/* No appropriate Quick Mode state.
			 * See if we have a Main Mode state.
			 * ??? what if this is a duplicate of another message?
			 */
			st = find_state_ikev1(&md->hdr.isa_ike_spis,
					      v1_MAINMODE_MSGID);

			if (st == NULL) {
				dbg("Quick Mode message is for a non-existent (expired?) ISAKMP SA");
				/* XXX Could send notification back */
				return;
			}

			if (st->st_oakley.doing_xauth) {
				dbg("Cannot do Quick Mode until XAUTH done.");
				return;
			}

			/* Have we just given an IP address to peer? */
			if (st->st_state->kind == STATE_MODE_CFG_R2) {
				/* ISAKMP is up... */
				change_v1_state(st, STATE_MAIN_R3);
			}

#ifdef SOFTREMOTE_CLIENT_WORKAROUND
			/* See: http://popoludnica.pl/?id=10100110 */
			if (st->st_state->kind == STATE_MODE_CFG_R1) {
				log_state(RC_LOG, st,
					  "SoftRemote workaround: Cannot do Quick Mode until MODECFG done.");
				return;
			}
#endif


			if (!IS_V1_ISAKMP_SA_ESTABLISHED(st)) {
				log_state(RC_LOG, st,
					  "Quick Mode message is unacceptable because it is for an incomplete ISAKMP SA");
				SEND_NOTIFICATION(v1N_PAYLOAD_MALFORMED /* XXX ? */);
				return;
			}

			if (!unique_msgid(st, md->hdr.isa_msgid)) {
				log_state(RC_LOG, st,
					  "Quick Mode I1 message is unacceptable because it uses a previously used Message ID 0x%08" PRIx32 " (perhaps this is a duplicated packet)",
					  md->hdr.isa_msgid);
				SEND_NOTIFICATION(v1N_INVALID_MESSAGE_ID);
				return;
			}
			st->st_v1_msgid.reserved = false;

			/* Quick Mode Initial IV */
			init_phase2_iv(st, &md->hdr.isa_msgid);
			new_iv_set = true;

			from_state = STATE_QUICK_R0;
		} else {
			if (st->st_oakley.doing_xauth) {
				log_state(RC_LOG, st, "Cannot do Quick Mode until XAUTH done.");
				return;
			}
			from_state = st->st_state->kind;
		}

		break;

	case ISAKMP_XCHG_MODE_CFG:
		if (ike_spi_is_zero(&md->hdr.isa_ike_initiator_spi)) {
			dbg("Mode Config message is invalid because it has an Initiator Cookie of 0");
			/* XXX Could send notification back */
			return;
		}

		if (ike_spi_is_zero(&md->hdr.isa_ike_responder_spi)) {
			dbg("Mode Config message is invalid because it has a Responder Cookie of 0");
			/* XXX Could send notification back */
			return;
		}

		if (md->hdr.isa_msgid == 0) {
			dbg("Mode Config message is invalid because it has a Message ID of 0");
			/* XXX Could send notification back */
			return;
		}

		st = find_v1_info_state(&md->hdr.isa_ike_spis, md->hdr.isa_msgid);

		if (st == NULL) {
			/* No appropriate Mode Config state.
			 * See if we have a Main Mode state.
			 * ??? what if this is a duplicate of another message?
			 */
			dbg("No appropriate Mode Config state yet. See if we have a Main Mode state");

			st = find_v1_info_state(&md->hdr.isa_ike_spis, 0);

			if (st == NULL) {
				dbg("Mode Config message is for a non-existent (expired?) ISAKMP SA");
				/* XXX Could send notification back */
				/* ??? ought to log something (not just DBG)? */
				return;
			}


			const struct spd_end *this = st->st_connection->spd->local;
			esb_buf b;
			dbg(" processing received isakmp_xchg_type %s; this is a%s%s%s%s",
			    str_enum(&ikev1_exchange_names, md->hdr.isa_xchg, &b),
			    this->host->config->xauth.server ? " xauthserver" : "",
			    this->host->config->xauth.client ? " xauthclient" : "",
			    this->host->config->modecfg.server ? " modecfgserver" : "",
			    this->host->config->modecfg.client ? " modecfgclient" : "");

			if (!IS_V1_ISAKMP_SA_ESTABLISHED(st)) {
				dbg("Mode Config message is unacceptable because it is for an incomplete ISAKMP SA (state=%s)",
				    st->st_state->name);
				/* XXX Could send notification back */
				return;
			}
			dbg(" call init_phase2_iv");
			init_phase2_iv(st, &md->hdr.isa_msgid);
			new_iv_set = true;

			/*
			 * okay, now we have to figure out if we are receiving a bogus
			 * new message in an outstanding XAUTH server conversation
			 * (i.e. a reply to our challenge)
			 * (this occurs with some broken other implementations).
			 *
			 * or if receiving for the first time, an XAUTH challenge.
			 *
			 * or if we are getting a MODECFG request.
			 *
			 * we distinguish these states because we cannot both be an
			 * XAUTH server and client, and our policy tells us which
			 * one we are.
			 *
			 * to complicate further, it is normal to start a new msgid
			 * when going from one state to another, or when restarting
			 * the challenge.
			 *
			 */

			if (this->host->config->xauth.server &&
			    st->st_state->kind == STATE_XAUTH_R1 &&
			    st->quirks.xauth_ack_msgid) {
				from_state = STATE_XAUTH_R1;
				dbg(" set from_state to %s state is STATE_XAUTH_R1 and quirks.xauth_ack_msgid is TRUE",
				    st->st_state->name);
			} else if (this->host->config->xauth.client &&
				   IS_V1_PHASE1(st->st_state->kind)) {
				from_state = STATE_XAUTH_I0;
				dbg(" set from_state to %s this is xauthclient and IS_PHASE1() is TRUE",
				    st->st_state->name);
			} else if (this->host->config->xauth.client &&
				   st->st_state->kind == STATE_XAUTH_I1) {
				/*
				 * in this case, we got a new MODECFG message after I0, maybe
				 * because it wants to start over again.
				 */
				from_state = STATE_XAUTH_I0;
				dbg(" set from_state to %s this is xauthclient and state == STATE_XAUTH_I1",
				    st->st_state->name);
			} else if (this->host->config->modecfg.server &&
				   IS_V1_PHASE1(st->st_state->kind)) {
				from_state = STATE_MODE_CFG_R0;
				dbg(" set from_state to %s this is modecfgserver and IS_PHASE1() is TRUE",
				    st->st_state->name);
			} else if (this->host->config->modecfg.client &&
				   IS_V1_PHASE1(st->st_state->kind)) {
				from_state = STATE_MODE_CFG_R1;
				dbg(" set from_state to %s this is modecfgclient and IS_PHASE1() is TRUE",
				    st->st_state->name);
			} else {
				esb_buf b;
				dbg("received isakmp_xchg_type %s; this is a%s%s%s%s in state %s. Reply with UNSUPPORTED_EXCHANGE_TYPE",
				    str_enum(&ikev1_exchange_names, md->hdr.isa_xchg, &b),
				    st->st_connection ->local->host.config->xauth.server ? " xauthserver" : "",
				    st->st_connection->local->host.config->xauth.client ? " xauthclient" : "",
				    st->st_connection->local->host.config->modecfg.server ? " modecfgserver" : "",
				    st->st_connection->local->host.config->modecfg.client ? " modecfgclient" : "",
				    st->st_state->name);
				return;
			}
		} else {
			if (st->st_connection->local->host.config->xauth.server &&
			    IS_V1_PHASE1(st->st_state->kind)) {
				/* Switch from Phase1 to Mode Config */
				dbg("We were in phase 1, with no state, so we went to XAUTH_R0");
				change_v1_state(st, STATE_XAUTH_R0);
			}

			/* otherwise, this is fine, we continue in the state we are in */
			from_state = st->st_state->kind;
		}

		break;

	case ISAKMP_XCHG_NONE:
	case ISAKMP_XCHG_BASE:
	case ISAKMP_XCHG_AO:
	case ISAKMP_XCHG_NGRP:
	default:
	{
		esb_buf b;
		dbg("unsupported exchange type %s in message",
		    str_enum(&ikev1_exchange_names, md->hdr.isa_xchg, &b));
		SEND_NOTIFICATION(v1N_UNSUPPORTED_EXCHANGE_TYPE);
		return;
	}
	}

	/* We have found a from_state, and perhaps a state object.
	 * If we need to build a new state object,
	 * we wait until the packet has been sanity checked.
	 */

	/* We don't support the Commit Flag.  It is such a bad feature.
	 * It isn't protected -- neither encrypted nor authenticated.
	 * A man in the middle turns it on, leading to DoS.
	 * We just ignore it, with a warning.
	 */
	if (md->hdr.isa_flags & ISAKMP_FLAGS_v1_COMMIT)
		dbg("IKE message has the Commit Flag set but Pluto doesn't implement this feature due to security concerns; ignoring flag");

	/* Handle IKE fragmentation payloads */
	if (md->hdr.isa_np == ISAKMP_NEXT_IKE_FRAGMENTATION) {
		struct isakmp_ikefrag fraghdr;
		int last_frag_index = 0;  /* index of the last fragment */
		struct pbs_in frag_pbs;

		if (st == NULL) {
			dbg("received IKE fragment, but have no state. Ignoring packet.");
			return;
		}

		if (!st->st_connection->config->ike_frag.allow) {
			dbg("discarding IKE fragment packet - fragmentation not allowed by local policy (ike_frag=no)");
			return;
		}

		diag_t d = pbs_in_struct(&md->message_pbs, &isakmp_ikefrag_desc,
					 &fraghdr, sizeof(fraghdr), &frag_pbs);
		if (d != NULL) {
			llog(RC_LOG, LOGGER, "%s", str_diag(d));
			pfree_diag(&d);
			SEND_NOTIFICATION(v1N_PAYLOAD_MALFORMED);
			return;
		}
		/*
		 * XXX: how could .len!=.isafrag_length?  Reading the
		 * header sets .len to the header length?
		 */
		if (pbs_in_all(&frag_pbs).len != fraghdr.isafrag_length ||
		    fraghdr.isafrag_np != ISAKMP_NEXT_NONE ||
		    fraghdr.isafrag_number == 0 ||
		    fraghdr.isafrag_number > 16) {
			SEND_NOTIFICATION(v1N_PAYLOAD_MALFORMED);
			return;
		}

		dbg("received IKE fragment id '%d', number '%u'%s",
		    fraghdr.isafrag_id,
		    fraghdr.isafrag_number,
		    (fraghdr.isafrag_flags == 1) ? "(last)" : "");

		struct v1_ike_rfrag *ike_frag = alloc_thing(struct v1_ike_rfrag, "ike_frag");
		ike_frag->md = md_addref(md);
		ike_frag->index = fraghdr.isafrag_number;
		ike_frag->last = (fraghdr.isafrag_flags & 1);
		ike_frag->data = pbs_in_left(&frag_pbs);

		/* Add the fragment to the state */
		struct v1_ike_rfrag **i = &st->st_v1_rfrags;
		for (;;) {
			if (ike_frag != NULL) {
				/* Still looking for a place to insert ike_frag */
				if (*i == NULL ||
				    (*i)->index > ike_frag->index) {
					ike_frag->next = *i;
					*i = ike_frag;
					ike_frag = NULL;
				} else if ((*i)->index == ike_frag->index) {
					/* Replace fragment with same index */
					struct v1_ike_rfrag *old = *i;

					ike_frag->next = old->next;
					*i = ike_frag;
					pexpect(old->md != NULL);
					md_delref(&old->md);
					pfree(old);
					ike_frag = NULL;
				}
			}

			if (*i == NULL)
				break;

			if ((*i)->last)
				last_frag_index = (*i)->index;

			i = &(*i)->next;
		}

		/* We have the last fragment, reassemble if complete */
		if (last_frag_index != 0) {
			size_t size = 0;
			int prev_index = 0;

			for (struct v1_ike_rfrag *frag = st->st_v1_rfrags; frag; frag = frag->next) {
				size += frag->data.len;
				if (frag->index != ++prev_index) {
					break; /* fragment list incomplete */
				} else if (frag->index == last_frag_index) {
					struct msg_digest *whole_md = alloc_md(frag->md->iface,
									       &frag->md->sender,
									       NULL/*packet*/, size,
									       HERE);

					/*
					 * Reassemble fragments in
					 * buffer.
					 *
					 * Header is taken directly
					 * from first fragment.
					 *
					 * XXX: DANGER! this code is
					 * re-using FRAG.
					 */
					frag = st->st_v1_rfrags;
					uint8_t *buffer = whole_md->packet_pbs.start;
					size_t offset = 0;
					while (frag != NULL && frag->index <= last_frag_index) {
						passert(offset + frag->data.len <= size);
						memcpy(buffer + offset, frag->data.ptr, frag->data.len);
						offset += frag->data.len;
						frag = frag->next;
					}

					/*
					 * process_md() calls
					 * process_v1_packet(), but
					 * only after first
					 * initializing .hdr and
					 * .message_pbs.
					 */
					process_md(whole_md);
					md_delref(&whole_md);
					free_v1_message_queues(st);
					/* optimize: if receiving fragments, immediately respond with fragments too */
					st->st_v1_seen_fragments = true;
					dbg(" updated IKE fragment state to respond using fragments without waiting for re-transmits");
					break;
				}
			}
		}

		return;
	}

	/*
	 * Set smc to describe this state's properties.
	 *
	 * Look up the appropriate microcode based on state and
	 * possibly Oakley Auth type.
	 */
	passert(STATE_IKEv1_FLOOR <= from_state && from_state < STATE_IKEv1_ROOF);
	const struct finite_state *fs = finite_states[from_state];
	passert(fs != NULL);
	const struct state_v1_microcode *smc = fs->v1.transitions;
	passert(smc != NULL);

	/*
	 * Find the state's the state transitions that has matching
	 * authentication.
	 *
	 * For states where this makes no sense (eg, quick states
	 * creating a CHILD_SA), .flags|=SMF_ALL_AUTH so the first
	 * (only) one always matches.
	 *
	 * XXX: The code assumes that when there is always a match (if
	 * there isn't the passert() triggers.  If needed, bogus
	 * transitions that log/drop the packet are added to the
	 * table?  Would simply dropping the packets be easier.
	 */
	if (st != NULL) {
		oakley_auth_t baseauth =
			xauth_calcbaseauth(st->st_oakley.auth);

		while (!LHAS(smc->flags, baseauth)) {
			smc++;
			passert(smc->state == from_state);
		}
	}

	/*
	 * XXX: do this earlier? */
	if (verbose_v1_state_busy(st))
		return;

	/*
	 * Detect and handle duplicated packets.  This won't work for
	 * the initial packet of an exchange because we won't have a
	 * state object to remember it.  If we are in a non-receiving
	 * state (terminal), and the preceding state did transmit,
	 * then the duplicate may indicate that that transmission
	 * wasn't received -- retransmit it.  Otherwise, just discard
	 * it.  ??? Notification packets are like exchanges -- I hope
	 * that they are idempotent!
	 *
	 * XXX: do this earlier?
	 */
	if (st != NULL && ikev1_duplicate(st, md)) {
		return;
	}

	/* save values for use in resumption of processing below.
	 * (may be suspended due to crypto operation not yet complete)
	 */
	md->v1_st = st;
	md->smc = smc;
	md->new_iv_set = new_iv_set;

	/*
	 * look for encrypt packets. We cannot handle them if we have not
	 * yet calculated the skeyids. We will just store the packet in
	 * the suspended state, since the calculation is likely underway.
	 *
	 * note that this differs from above, because skeyid is calculated
	 * in between states. (or will be, once DH is async)
	 *
	 */
	if ((md->hdr.isa_flags & ISAKMP_FLAGS_v1_ENCRYPTION) &&
	    st != NULL &&
	    !st->hidden_variables.st_skeyid_calculated) {
		PEXPECT(st->logger, st->st_v1_offloaded_task_in_background);
		endpoint_buf b;
		dbg("received encrypted packet from %s but exponentiation still in progress",
		    str_endpoint(&md->sender, &b));

		/*
		 * If there was a previous packet, let it go, and go
		 * with most recent one.
		 *
		 * XXX: since the presence of .st_v1_background_md
		 * flags the state as busy, this shouldn't happen!?!
		 */
		PEXPECT(st->logger, st->st_v1_background_md == NULL);
		if (st->st_v1_background_md != NULL) {
			dbg("suspend: releasing suspended operation for "PRI_SO" MD@%p before completion "PRI_WHERE,
			    st->st_serialno, st->st_v1_background_md,
			    pri_where(HERE));
			md_delref(&st->st_v1_background_md);
		}
		st->st_v1_background_md = md_addref(md);
		return;
	}

	process_packet_tail(md);
	/* our caller will md_delref(mdp); */
}

/*
 * This routine will not md_delref(mdp).  It is expected that its
 * caller will do this.  In fact, it will zap *mdp to NULL if it thinks
 * **mdp should not be freed.  So the caller should be prepared for
 * *mdp being set to NULL.
 */
void process_packet_tail(struct msg_digest *md)
{
	struct state *st = md->v1_st;
	const struct state_v1_microcode *smc = md->smc;
	enum state_kind from_state = smc->state;
	bool new_iv_set = md->new_iv_set;

	if (md->hdr.isa_flags & ISAKMP_FLAGS_v1_ENCRYPTION) {

		endpoint_buf b;
		dbg("received encrypted packet from %s", str_endpoint(&md->sender, &b));

		if (st == NULL) {
			LOG_PACKET(RC_LOG,
				   "discarding encrypted message for an unknown ISAKMP SA");
			return;
		}
		if (st->st_skeyid_e_nss == NULL) {
			LOG_PACKET(RC_LOG,
				   "discarding encrypted message because we haven't yet negotiated keying material");
			return;
		}

		/* Mark as encrypted */
		md->encrypted = true;

		/* do the specified decryption
		 *
		 * IV is from st->st_iv or (if new_iv_set) st->st_new_iv.
		 * The new IV is placed in st->st_new_iv
		 *
		 * See RFC 2409 "IKE" Appendix B
		 *
		 * XXX The IV should only be updated really if the packet
		 * is successfully processed.
		 * We should keep this value, check for a success return
		 * value from the parsing routines and then replace.
		 *
		 * Each post phase 1 exchange generates IVs from
		 * the last phase 1 block, not the last block sent.
		 */
		const struct encrypt_desc *e = st->st_oakley.ta_encrypt;

		if (pbs_left(&md->message_pbs) % e->enc_blocksize != 0) {
			LOG_PACKET(RC_LOG, "malformed message: not a multiple of encryption blocksize");
			return;
		}

		/* XXX Detect weak keys */

		/*
		 * Grab a copy of raw packet (for duplicate packet
		 * detection).
		 */
		md->raw_packet = clone_pbs_in_all(&md->packet_pbs, "raw packet");

		/* Decrypt everything after header */
		if (!new_iv_set) {
			if (st->st_v1_iv.len == 0) {
				init_phase2_iv(st, &md->hdr.isa_msgid);
			} else {
				/* use old IV */
				restore_new_iv(st, st->st_v1_iv);
			}
		}

		passert(st->st_v1_new_iv.len >= e->enc_blocksize);
		st->st_v1_new_iv.len = e->enc_blocksize;   /* truncate */

		if (DBGP(DBG_CRYPT)) {
			DBG_log("decrypting %u bytes using algorithm %s",
				(unsigned) pbs_left(&md->message_pbs),
				st->st_oakley.ta_encrypt->common.fqn);
			DBG_dump_hunk("IV before:", st->st_v1_new_iv);
		}
		size_t cipher_start = (md->message_pbs.cur - md->message_pbs.start);
		chunk_t cipher_text = chunk2(md->message_pbs.start + cipher_start,
					    pbs_left(&md->message_pbs));
		cipher_normal(e, DECRYPT, USE_IKEv1_IV, cipher_text,
			      &st->st_v1_new_iv,
			      st->st_enc_key_nss, st->logger);
		if (DBGP(DBG_CRYPT)) {
			DBG_dump_hunk("IV after:", st->st_v1_new_iv);
			DBG_log("decrypted payload (starts at offset %td):",
				md->message_pbs.cur - md->message_pbs.roof);
			DBG_dump(NULL, md->message_pbs.start,
				 md->message_pbs.roof - md->message_pbs.start);
		}
	} else {
		/* packet was not encrypted -- should it have been? */

		if (smc->flags & SMF_INPUT_ENCRYPTED) {
			LOG_PACKET(RC_LOG,
				   "packet rejected: should have been encrypted");
			SEND_NOTIFICATION(v1N_INVALID_FLAGS);
			return;
		}
	}

	/* Digest the message.
	 * Padding must be removed to make hashing work.
	 * Padding comes from encryption (so this code must be after decryption).
	 * Padding rules are described before the definition of
	 * struct isakmp_hdr in packet.h.
	 */
	{
		enum next_payload_types_ikev1 np = md->hdr.isa_np;
		lset_t needed = smc->req_payloads;
		const char *excuse =
			LIN(SMF_PSK_AUTH | SMF_FIRST_ENCRYPTED_INPUT,
			    smc->flags) ?
			"probable authentication failure (mismatch of preshared secrets?): "
			:
			"";

		while (np != ISAKMP_NEXT_NONE) {
			struct_desc *sd = v1_payload_desc(np);

			if (md->digest_roof >= elemsof(md->digest)) {
				LOG_PACKET(RC_LOG,
					   "more than %zu payloads in message; ignored",
					   elemsof(md->digest));
				if (!md->encrypted) {
					SEND_NOTIFICATION(v1N_PAYLOAD_MALFORMED);
				}
				return;
			}
			struct payload_digest *const pd = md->digest + md->digest_roof;

			/*
			 * Only do this in main mode. In aggressive
			 * mode, there is no negotiation of NAT-T
			 * method. Get it right.
			 */
			if (st != NULL &&
			    st->st_connection != NULL &&
			    !st->st_connection->config->aggressive) {
				switch (np) {
				case ISAKMP_NEXT_NATD_RFC:
				case ISAKMP_NEXT_NATOA_RFC:
					if ((st->hidden_variables.st_nat_traversal & NAT_T_WITH_RFC_VALUES) == LEMPTY) {
						/*
						 * don't accept NAT-D/NAT-OA reloc directly in message,
						 * unless we're using NAT-T RFC
						 */
						lset_buf lb;
						dbg("st_nat_traversal was: %s",
						    str_lset(&natt_method_names,
							     st->hidden_variables.st_nat_traversal,
							     &lb));
						sd = NULL;
					}
					break;
				default:
					break;
				}
			}

			if (sd == NULL) {
				/* payload type is out of range or requires special handling */
				switch (np) {
				case ISAKMP_NEXT_ID:
					/* ??? two kinds of ID payloads */
					sd = (IS_V1_PHASE1(from_state) ||
					      IS_V1_PHASE15(from_state)) ?
						&isakmp_identification_desc :
						&isakmp_ipsec_identification_desc;
					break;

				case ISAKMP_NEXT_NATD_DRAFTS: /* out of range */
					/*
					 * ISAKMP_NEXT_NATD_DRAFTS was a private use type before RFC-3947.
					 * Since it has the same format as ISAKMP_NEXT_NATD_RFC,
					 * just rewrite np and sd, and carry on.
					 */
					np = ISAKMP_NEXT_NATD_RFC;
					sd = &isakmp_nat_d_drafts;
					break;

				case ISAKMP_NEXT_NATOA_DRAFTS: /* out of range */
					/* NAT-OA was a private use type before RFC-3947 -- same format */
					np = ISAKMP_NEXT_NATOA_RFC;
					sd = &isakmp_nat_oa_drafts;
					break;

				case ISAKMP_NEXT_SAK: /* or ISAKMP_NEXT_NATD_BADDRAFTS */
					/*
					 * Official standards say that this is ISAKMP_NEXT_SAK,
					 * a part of Group DOI, something we don't implement.
					 * Old non-updated Cisco gear abused this number in ancient NAT drafts.
					 * We ignore (rather than reject) this in support of people
					 * with crufty Cisco machines.
					 */
					LOG_PACKET(RC_LOG,
						   "%smessage with unsupported payload ISAKMP_NEXT_SAK (or ISAKMP_NEXT_NATD_BADDRAFTS) ignored",
						   excuse);
					/*
					 * Hack to discard payload, whatever it was.
					 * Since we are skipping the rest of the loop
					 * body we must do some things ourself:
					 * - demarshall the payload
					 * - grab the next payload number (np)
					 * - don't keep payload (don't increment pd)
					 * - skip rest of loop body
					 */
					diag_t d = pbs_in_struct(&md->message_pbs, &isakmp_ignore_desc,
								 &pd->payload, sizeof(pd->payload), &pd->pbs);
					if (d != NULL) {
						llog(RC_LOG, LOGGER, "%s", str_diag(d));
						pfree_diag(&d);
						LOG_PACKET(RC_LOG,
							   "%smalformed payload in packet",
							   excuse);
						if (!md->encrypted) {
							SEND_NOTIFICATION(v1N_PAYLOAD_MALFORMED);
						}
						return;
					}
					np = pd->payload.generic.isag_np;
					/* NOTE: we do not increment pd! */
					continue;  /* skip rest of the loop */

				default:
				{
					esb_buf b;
					LOG_PACKET(RC_LOG,
						   "%smessage ignored because it contains an unknown or unexpected payload type (%s) at the outermost level",
						   excuse,
						   str_enum(&ikev1_payload_names, np, &b));
					if (!md->encrypted) {
						SEND_NOTIFICATION(v1N_INVALID_PAYLOAD_TYPE);
					}
					return;
				}
				}
				passert(sd != NULL);
			}

			passert(np < LELEM_ROOF);

			{
				lset_t s = LELEM(np);

				if (LDISJOINT(s,
					      needed | smc->opt_payloads |
					      LELEM(ISAKMP_NEXT_VID) |
					      LELEM(ISAKMP_NEXT_N) |
					      LELEM(ISAKMP_NEXT_D) |
					      LELEM(ISAKMP_NEXT_CR) |
					      LELEM(ISAKMP_NEXT_CERT))) {
					esb_buf b;
					LOG_PACKET(RC_LOG,
						   "%smessage ignored because it contains a payload type (%s) unexpected by state %s",
						   excuse,
						   str_enum(&ikev1_payload_names, np, &b),
						   finite_states[smc->state]->name);
					if (!md->encrypted) {
						SEND_NOTIFICATION(v1N_INVALID_PAYLOAD_TYPE);
					}
					return;
				}

				esb_buf b;
				dbg("got payload 0x"PRI_LSET" (%s) needed: 0x"PRI_LSET" opt: 0x"PRI_LSET,
				    s, str_enum(&ikev1_payload_names, np, &b),
				    needed, smc->opt_payloads);
				needed &= ~s;
			}

			/*
			 * Read in the payload recording what type it
			 * should be
			 */
			pd->payload_type = np;
			diag_t d = pbs_in_struct(&md->message_pbs, sd,
						 &pd->payload, sizeof(pd->payload),
						 &pd->pbs);
			if (d != NULL) {
				llog(RC_LOG, LOGGER, "%s", str_diag(d));
				pfree_diag(&d);
				LOG_PACKET(RC_LOG,
					   "%smalformed payload in packet",
					   excuse);
				if (!md->encrypted) {
					SEND_NOTIFICATION(v1N_PAYLOAD_MALFORMED);
				}
				return;
			}

			/* do payload-type specific debugging */
			switch (np) {
			case ISAKMP_NEXT_ID:
			case ISAKMP_NEXT_NATOA_RFC:
				/* dump ID section */
				if (DBGP(DBG_BASE)) {
					DBG_dump("     obj: ", pd->pbs.cur,
						 pbs_left(&pd->pbs));
				}
				break;
			default:
				break;
			}


			/*
			 * Place payload at the end of the chain for this type.
			 * This code appears in ikev1.c and ikev2.c.
			 */
			{
				/* np is a proper subscript for chain[] */
				passert(np < elemsof(md->chain));
				struct payload_digest **p = &md->chain[np];

				while (*p != NULL)
					p = &(*p)->next;
				*p = pd;
				pd->next = NULL;
			}

			np = pd->payload.generic.isag_np;
			md->digest_roof++;

			/* since we've digested one payload happily, it is probably
			 * the case that any decryption worked.  So we will not suggest
			 * encryption failure as an excuse for subsequent payload
			 * problems.
			 */
			excuse = "";
		}

		if (DBGP(DBG_BASE) &&
		    pbs_left(&md->message_pbs) != 0) {
			DBG_log("removing %d bytes of padding",
				(int) pbs_left(&md->message_pbs));
		}

		md->message_pbs.roof = md->message_pbs.cur;

		/* check that all mandatory payloads appeared */

		if (needed != 0) {
			LOG_PACKET_JAMBUF(RC_LOG, buf) {
				jam(buf, "message for %s is missing payloads ",
				    finite_states[from_state]->name);
				jam_lset_short(buf, &ikev1_payload_names, "+", needed);
			}
			if (!md->encrypted) {
				SEND_NOTIFICATION(v1N_PAYLOAD_MALFORMED);
			}
			return;
		}
	}

	if (!check_v1_HASH(smc->hash_type, smc->message, st, md)) {
		/*SEND_NOTIFICATION(INVALID_HASH_INFORMATION);*/
		return;
	}

	/* more sanity checking: enforce most ordering constraints */

	if (IS_V1_PHASE1(from_state) || IS_V1_PHASE15(from_state)) {
		/* rfc2409: The Internet Key Exchange (IKE), 5 Exchanges:
		 * "The SA payload MUST precede all other payloads in a phase 1 exchange."
		 */
		if (md->chain[ISAKMP_NEXT_SA] != NULL &&
		    md->hdr.isa_np != ISAKMP_NEXT_SA) {
			LOG_PACKET(RC_LOG,
				   "malformed Phase 1 message: does not start with an SA payload");
			if (!md->encrypted) {
				SEND_NOTIFICATION(v1N_PAYLOAD_MALFORMED);
			}
			return;
		}
	} else if (IS_V1_QUICK(from_state)) {
		/* rfc2409: The Internet Key Exchange (IKE), 5.5 Phase 2 - Quick Mode
		 *
		 * "In Quick Mode, a HASH payload MUST immediately follow the ISAKMP
		 *  header and a SA payload MUST immediately follow the HASH."
		 * [NOTE: there may be more than one SA payload, so this is not
		 *  totally reasonable.  Probably all SAs should be so constrained.]
		 *
		 * "If ISAKMP is acting as a client negotiator on behalf of another
		 *  party, the identities of the parties MUST be passed as IDci and
		 *  then IDcr."
		 *
		 * "With the exception of the HASH, SA, and the optional ID payloads,
		 *  there are no payload ordering restrictions on Quick Mode."
		 */

		if (md->hdr.isa_np != ISAKMP_NEXT_HASH) {
			LOG_PACKET(RC_LOG,
				   "malformed Quick Mode message: does not start with a HASH payload");
			if (!md->encrypted) {
				SEND_NOTIFICATION(v1N_PAYLOAD_MALFORMED);
			}
			return;
		}

		{
			struct payload_digest *p;
			int i;

			p = md->chain[ISAKMP_NEXT_SA];
			i = 1;
			while (p != NULL) {
				if (p != &md->digest[i]) {
					LOG_PACKET(RC_LOG,
						   "malformed Quick Mode message: SA payload is in wrong position");
					if (!md->encrypted) {
						SEND_NOTIFICATION(v1N_PAYLOAD_MALFORMED);
					}
					return;
				}
				p = p->next;
				i++;
			}
		}

		/* rfc2409: The Internet Key Exchange (IKE), 5.5 Phase 2 - Quick Mode:
		 * "If ISAKMP is acting as a client negotiator on behalf of another
		 *  party, the identities of the parties MUST be passed as IDci and
		 *  then IDcr."
		 */
		{
			struct payload_digest *id = md->chain[ISAKMP_NEXT_ID];

			if (id != NULL) {
				if (id->next == NULL ||
				    id->next->next != NULL) {
					LOG_PACKET(RC_LOG,
						   "malformed Quick Mode message: if any ID payload is present, there must be exactly two");
					SEND_NOTIFICATION(v1N_PAYLOAD_MALFORMED);
					return;
				}
				if (id + 1 != id->next) {
					LOG_PACKET(RC_LOG,
						   "malformed Quick Mode message: the ID payloads are not adjacent");
					SEND_NOTIFICATION(v1N_PAYLOAD_MALFORMED);
					return;
				}
			}
		}
	}

	/*
	 * Ignore payloads that we don't handle:
	 */
	/* XXX Handle Notifications */
	for (struct payload_digest *p = md->chain[ISAKMP_NEXT_N];
	     p != NULL; p = p->next) {

		enum_buf nname;
		str_enum_short(&v1_notification_names,
			       p->payload.notification.isan_type,
			       &nname);
		switch (p->payload.notification.isan_type) {
		case v1N_R_U_THERE:
		case v1N_R_U_THERE_ACK:
		case v1N_PAYLOAD_MALFORMED:
		case v1N_INVALID_MESSAGE_ID:
		case v1N_IPSEC_RESPONDER_LIFETIME:
			if (md->hdr.isa_xchg == ISAKMP_XCHG_INFO) {
				/* these are handled later on in informational() */
				if (DBGP(DBG_BASE)) {
					shunk_t header = pbs_in_to_cursor(&p->pbs);
					DBG_dump_hunk(p->pbs.name, header);
				}
				continue;
			}
		}

		if (st == NULL) {
			dbg("ignoring informational payload %s, no corresponding state",
			    nname.buf);
		} else {
			if (impair.copy_v1_notify_response_SPIs_to_retransmission) {
				ldbg(st->logger, "IMPAIR: copying notify response SPIs to recorded message and then resending it");
				/* skip non-ESP marker if needed */
				size_t skip = (st->st_iface_endpoint->esp_encapsulation_enabled ? NON_ESP_MARKER_SIZE : 0);
				size_t spis = sizeof(md->hdr.isa_ike_spis);
				PASSERT(st->logger, st->st_v1_tpacket.len >= skip + spis);
				memcpy(st->st_v1_tpacket.ptr + skip, &md->hdr.isa_ike_spis, spis);
#if 0
				uint8_t *flags = (uint8_t*)st->st_v1_tpacket.ptr + skip + spis + 3;
				*flags |= ISAKMP_FLAGS_v1_ENCRYPTION;
#endif
				sleep(2);
				resend_recorded_v1_ike_msg(st, "IMPAIR: retransmitting mangled packet");
			}
			LOG_PACKET(RC_LOG,
				   "ignoring informational payload %s, msgid=%08" PRIx32 ", length=%d",
				   nname.buf, st->st_v1_msgid.id,
				   p->payload.notification.isan_length);
		}
		if (DBGP(DBG_BASE)) {
			shunk_t header = pbs_in_to_cursor(&p->pbs);
			DBG_dump_hunk(p->pbs.name, header);
		}
	}

	pexpect(st == md->v1_st); /* could be NULL */

	for (struct payload_digest *p = md->chain[ISAKMP_NEXT_D];
	     p != NULL; p = p->next) {
		if (!accept_delete(&st, md, p)) {
			ldbg(md->logger, "bailing with bad delete message");
			return;
		}
		if (st == NULL) {
			ldbg(md->logger, "bailing due to self-inflicted delete");
			return;
		}
	}

	pexpect(st == md->v1_st); /* could be NULL */

	for (struct payload_digest *p = md->chain[ISAKMP_NEXT_VID];
	     p != NULL; p = p->next) {
		handle_v1_vendorid(md, pbs_in_left(&p->pbs),
				   (st != NULL ? st->logger : md->logger));
	}

	pexpect(st == md->v1_st); /* could be NULL */

	/*
	 * XXX: Danger.
	 *
	 * ++ the .informational() processor deletes ST; and then
	 * tries to tunnel this loss back through MD.ST.
	 *
	 * ++ the .aggressive() processor replaces .V1_ST with the IKE
	 * SA?
	 */
	statetime_t start = statetime_start(st);
	stf_status e = smc->processor(st, md);
	complete_v1_state_transition(md->v1_st, md, e);
	statetime_stop(&start, "%s()", __func__);
	/* our caller will md_delref(mdp); */
}

/*
 * replace previous receive packet with latest, to update
 * our notion of a retransmitted packet. This is important
 * to do, even for failing transitions, and suspended transitions
 * because the sender may well retransmit their request.
 * We had better be idempotent since we can be called
 * multiple times in handling a packet due to crypto helper logic.
 */
static void remember_received_packet(struct state *st, struct msg_digest *md)
{
	if (md->encrypted) {
		/* if encrypted, duplication already done */
		if (md->raw_packet.ptr != NULL) {
			pfreeany(st->st_v1_rpacket.ptr);
			st->st_v1_rpacket = md->raw_packet;
			md->raw_packet = EMPTY_CHUNK;
		}
	} else {
		/* this may be a repeat, but it will work */
		replace_chunk(&st->st_v1_rpacket,
			      pbs_in_all(&md->packet_pbs),
			      "raw packet");
	}
}

static void jam_v1_ipsec_details(struct jambuf *buf, struct state *st)
{
	struct connection *const c = st->st_connection;
	jam_enum(buf, &encap_mode_story, c->config->child_sa.encap_mode);
	jam_string(buf, " mode ");
	jam_child_sa_details(buf, st);
}

static void jam_v1_isakmp_details(struct jambuf *buf, struct state *st)
{
	jam_parent_sa_details(buf, st);
}

/* complete job started by the state-specific state transition function
 *
 * This routine will not md_delref(mdp).  It is expected that its
 * caller will do this.  In fact, it will zap *mdp to NULL if it thinks
 * **mdp should not be freed.  So the caller should be prepared for
 * *mdp being set to NULL.
 *
 * md is used to:
 * - find st
 * - find from_state (st might be gone)
 * - find note for STF_FAIL_v1N (might not be part of result (STF_FAIL_v1N+note))
 * - find note for STF_INTERNAL_ERROR
 * - record md->event_already_set
 * - remember_received_packet(st, md);
 * - nat_traversal_change_port_lookup(md, st);
 * - smc for smc->next_state
 * - smc for smc->flags & SMF_REPLY to trigger a reply
 * - smc for smc->timeout_event
 * - smc for !(smc->flags & SMF_INITIATOR) for Contivity mode
 * - smc for smc->flags & SMF_RELEASE_PENDING_P2 to trigger unpend call
 * - smc for smc->flags & SMF_INITIATOR to adjust retransmission
 * - fragvid, dpd, nortel
 */
void complete_v1_state_transition(struct state *st, struct msg_digest *md, stf_status result)
{
	/* handle oddball/meta results now */

	/*
	 * statistics; all STF_FAIL_v1N+v1N are lumped together
	 */
	pstat(stf_status, result);

	/* DANGER: MD might be NULL; ST might be NULL */
	enum_buf neb;
	enum_buf rb;
	dbg("complete v1 state transition with %s",
	    (result > STF_FAIL_v1N ? str_enum_short(&v1_notification_names, result - STF_FAIL_v1N, &neb) :
	     str_enum(&stf_status_names, result, &rb)));

	switch (result) {
	case STF_SUSPEND:
		/*
		 * If this transition was triggered by an incoming
		 * packet, save it.
		 *
		 * XXX: some initiator code creates a fake MD (there
		 * isn't a real one); save that as well.
		 *
		 * XXX: is this still true?
		 */
		passert(md != NULL);
		pexpect(md->v1_st == st);
		/*
		 * XXX: Clearing retransmits here is wrong (it is a
		 * slight improvement on submit_task()).
		 *
		 * Retransmits should only be cleared after the
		 * integrity of the packet has been proven and here
		 * that is likely not the case.  For instance, the
		 * exchange is suspended while the DH needed to prove
		 * integrity is computed.
		 *
		 * A better location might be in STF_v1N, assuming the
		 * packet's integrity was verified.
		 */
		clear_retransmits(st);
		/*
		 * Code off-loading work should have scheduled a
		 * timeout.
		 */
		switch (st->st_ike_version) {
		case IKEv1:
			PEXPECT(st->logger, (st->st_event != NULL &&
					     (st->st_event->ev_type == EVENT_v1_CRYPTO_TIMEOUT ||
					      st->st_event->ev_type == EVENT_v1_PAM_TIMEOUT)));
			break;
		case IKEv2:
			PEXPECT(st->logger, (st->st_v2_timeout_initiator_event != NULL ||
					     st->st_v2_timeout_responder_event != NULL ||
					     st->st_v2_timeout_response_event != NULL));
			break;
		}
		return;
	case STF_IGNORE:
		/* DANGER: MD might be NULL; ST might be NULL */
		return;
	case STF_SKIP_COMPLETE_STATE_TRANSITION:
		/* DANGER: MD might be NULL; ST might be NULL */
		return;
	default:
		break;
	}

	passert(md != NULL);
	pexpect(md->v1_st == st);

	/* safe to refer to *md */

	enum state_kind from_state = md->smc->state;
	st = md->v1_st;

	passert(st != NULL);
	pexpect(!v1_state_busy(st));

	if (result > STF_OK) {
		linux_audit_conn(md->v1_st, IS_V1_ISAKMP_SA_ESTABLISHED(md->v1_st) ? LAK_CHILD_FAIL : LAK_PARENT_FAIL);
	}

	switch (result) {
	case STF_OK:
	{
		/* advance the state */
		const struct state_v1_microcode *smc = md->smc;

		dbg("doing_xauth:%s, t_xauth_client_done:%s",
		    bool_str(st->st_oakley.doing_xauth),
		    bool_str(st->hidden_variables.st_xauth_client_done));

		/* accept info from VID because we accept this message */

		/*
		 * Most of below VIDs only appear Main/Aggr mode, not Quick mode,
		 * so why are we checking them for each state transition?
		 */

		if (md->fragvid) {
			dbg("peer supports fragmentation");
			st->st_v1_seen_fragmentation_supported = true;
		}

		if (md->dpd) {
			dbg("peer supports DPD");
			st->hidden_variables.st_peer_supports_dpd = true;
			if (dpd_active_locally(st->st_connection)) {
				dbg("DPD is configured locally");
			}
		}

		if (!st->st_v1_msgid.reserved &&
		    IS_CHILD_SA(st) &&
		    st->st_v1_msgid.id != v1_MAINMODE_MSGID) {
			struct state *p1st = state_by_serialno(st->st_clonedfrom);

			if (p1st != NULL) {
				/* do message ID reservation */
				reserve_msgid(p1st, st->st_v1_msgid.id);
			}

			st->st_v1_msgid.reserved = true;
		}

		dbg("IKEv1: transition from state %s to state %s",
		    finite_states[from_state]->name,
		    finite_states[smc->next_state]->name);

		change_v1_state(st, smc->next_state);

		/*
		 * XAUTH negotiation without ModeCFG cannot follow the regular
		 * state machine change as it cannot be determined if the CFG
		 * payload is "XAUTH OK, no ModeCFG" or "XAUTH OK, expect
		 * ModeCFG". To the smc, these two cases look identical. So we
		 * have an ad hoc state change here for the case where
		 * we have XAUTH but not ModeCFG. We move it to the established
		 * state, so the regular state machine picks up the Quick Mode.
		 */
		if (st->st_connection->local->host.config->xauth.client &&
		    st->hidden_variables.st_xauth_client_done &&
		    !st->st_connection->local->host.config->modecfg.client &&
		    st->st_state->kind == STATE_XAUTH_I1) {
			bool aggrmode = st->st_connection->config->aggressive;

			log_state(RC_LOG, st, "XAUTH completed; ModeCFG skipped as per configuration");
			change_v1_state(st, aggrmode ? STATE_AGGR_I2 : STATE_MAIN_I4);
			st->st_v1_msgid.phase15 = v1_MAINMODE_MSGID;
		}

		/* Schedule for whatever timeout is specified */

		/*
		 * Delete previous retransmission event.
		 * New event will be scheduled below.
		 */
		delete_event(st);
		clear_retransmits(st);

		/* Delete IKE fragments */
		free_v1_message_queues(st);

		/* scrub the previous packet exchange */
		free_chunk_content(&st->st_v1_rpacket);
		free_chunk_content(&st->st_v1_tpacket);

		/* in aggressive mode, there will be no reply packet in transition
		 * from STATE_AGGR_R1 to STATE_AGGR_R2
		 */
		if (nat_traversal_enabled &&
		    st->st_connection->config->ikev1_natt != NATT_NONE) {
			/* adjust our destination port if necessary */
			nat_traversal_change_port_lookup(md, st);
			v1_maybe_natify_initiator_endpoints(st, HERE);
		}

		/*
		 * Save both the received packet, and this
		 * state-transition.
		 *
		 * Only when the (last) state transition was a "reply"
		 * should a duplicate packet trigger a retransmit
		 * (else they get discarded).
		 *
		 * XXX: .st_state .fs_flags & SMF_REPLY can't
		 * be used because it contains flags for the new state
		 * not the old-to-new state transition.
		 */
		remember_received_packet(st, md);
		st->st_v1_last_transition = md->smc;

		/* if requested, send the new reply packet */
		if (smc->flags & SMF_REPLY) {
			close_output_pbs(&reply_stream); /* good form, but actually a no-op */

			if (st->st_state->kind == STATE_MAIN_R2 &&
			    impair.send_no_main_r2) {
				/* record-only so we properly emulate packet drop */
				record_outbound_v1_ike_msg(st, &reply_stream, smc->message);
				log_state(RC_LOG, st, "IMPAIR: Skipped sending STATE_MAIN_R2 response packet");
			} else {
				record_and_send_v1_ike_msg(st, &reply_stream, smc->message);
			}
		}

		/* Schedule for whatever timeout is specified */

		enum event_type event_type = smc->timeout_event;
		struct connection *c = st->st_connection;

		/* fixup in case of state machine jump for xauth without modecfg */
		if (c->local->host.config->xauth.client &&
		    st->hidden_variables.st_xauth_client_done &&
		    !c->local->host.config->modecfg.client &&
		    (st->st_state->kind == STATE_MAIN_I4 || st->st_state->kind == STATE_AGGR_I2)) {
			dbg("fixup XAUTH without ModeCFG event from EVENT_RETRANSMIT to EVENT_v1_REPLACE");
			event_type = EVENT_v1_REPLACE;
		}

		switch (event_type) {
		case EVENT_v1_RETRANSMIT: /* Retransmit packet */
			start_retransmits(st);
			break;

		case EVENT_v1_REPLACE: /* SA replacement event */
		{
			deltatime_t event_delay;
			bool agreed_time = false;
			if (IS_V1_PHASE1(st->st_state->kind) ||
			    IS_V1_PHASE15(st->st_state->kind)) {
				/*
				 * ISAKMP:
				 *
				 * Note: we will defer to the
				 * "negotiated" (dictated) lifetime if
				 * we are POLICY_DONT_REKEY.  This
				 * allows the other side to dictate a
				 * time we would not otherwise accept
				 * but it prevents us from having to
				 * initiate rekeying.  The negative
				 * consequences seem minor.
				 */
				event_delay = c->config->sa_ike_max_lifetime;
				if (!c->config->rekey ||
				    deltatime_cmp(event_delay, >=, st->st_oakley.life_seconds)) {
					agreed_time = true;
					event_delay = st->st_oakley.life_seconds;
				}
			} else {
				/*
				 * IPsec:
				 *
				 * Delay is min of up to four things:
				 * each can limit the lifetime.
				 */
				event_delay = c->config->sa_ipsec_max_lifetime;

#define clamp_delay(trans)						\
				{					\
					if (st->trans.protocol != NULL &&	\
					    deltatime_cmp(event_delay, >=, st->trans.v1_lifetime)) { \
						agreed_time = true;	\
						event_delay = st->trans.v1_lifetime; \
					}				\
				}
				clamp_delay(st_ah);
				clamp_delay(st_esp);
				clamp_delay(st_ipcomp);
#undef clamp_delay
			}

			/*
			 * By default, we plan to rekey via the
			 * replace event.
			 *
			 * If there isn't enough time to rekey, plan
			 * to expire.
			 *
			 * If we are --dontrekey, a lot more rules
			 * apply:
			 *
			 * If we are the Initiator, use REPLACE.
			 *
			 * If we are the Responder, and the dictated
			 * time was unacceptable (too large), plan to
			 * REPLACE (the only way to ratchet down the
			 * time).  If we are the Responder, and the
			 * dictated time is acceptable, plan to
			 * EXPIRE.
			 *
			 * Note: for ISAKMP SA, we let the negotiated
			 * time stand (implemented by earlier logic).
			 */
			if (agreed_time && !c->config->rekey &&
			    (smc->flags & SMF_INITIATOR) == LEMPTY) {
				/* per above, don't re-key responder */
				event_type = EVENT_v1_EXPIRE;
			} else {
				deltatime_t marg = fuzz_rekey_margin(st->st_sa_role,
								     c->config->sa_rekey_margin,
								     c->config->sa_rekey_fuzz/*percent*/);
				if (deltatime_cmp(event_delay, >, marg)) {
					st->st_replace_margin = marg;
				} else {
					marg = deltatime(0);
				}
				event_delay = deltatime_sub(event_delay, marg);
			}
			event_schedule(event_type, event_delay, st);
			break;
		}
		case EVENT_v1_DISCARD:
			event_schedule(EVENT_v1_DISCARD, c->config->retransmit_timeout, st);
			break;

		default:
			bad_case(event_type);
		}

		/* tell whack and log of progress */
		{
			enum rc_type w;
			void (*jam_details)(struct jambuf *buf, struct state *st);

			if (IS_IPSEC_SA_ESTABLISHED(st)) {
				pstat_sa_established(st);
				jam_details = jam_v1_ipsec_details;
				w = RC_SUCCESS; /* log our success */
			} else if (IS_V1_ISAKMP_SA_ESTABLISHED(st)) {
				pstat_sa_established(st);
				jam_details = jam_v1_isakmp_details;
				w = RC_SUCCESS; /* log our success */
			} else {
				jam_details = NULL;
				w = RC_LOG;
			}

			passert(st->st_state->kind < STATE_IKEv1_ROOF);

			/* tell whack and logs our progress */
			LLOG_JAMBUF(w, st->logger, buf) {
				jam(buf, "%s", st->st_state->story);
				/* document SA details for admin's pleasure */
				if (jam_details != NULL) {
					jam(buf, " ");
					jam_details(buf, st);
				}
			}
		}

		/*
		 * make sure that a DPD event gets created for a new phase 1
		 * SA.
		 * Why do we need a DPD event on an IKE SA???
		 */
		if (IS_V1_ISAKMP_SA_ESTABLISHED(st)) {
			if (dpd_init(st) != STF_OK) {
				log_state(RC_LOG, st,
					  "DPD initialization failed - continuing without DPD");
			}
		}

		/* Special case for XAUTH server */
		if (st->st_connection->local->host.config->xauth.server) {
			if (st->st_oakley.doing_xauth &&
			    IS_V1_ISAKMP_SA_ESTABLISHED(st)) {
				dbg("XAUTH: Sending XAUTH Login/Password Request");
				event_schedule(EVENT_v1_SEND_XAUTH,
					       deltatime_ms(EVENT_v1_SEND_XAUTH_DELAY_MS),
					       st);
				break;
			}
		}

		/*
		 * for XAUTH client, we are also done, because we need to
		 * stay in this state, and let the server query us
		 */
		if (!IS_V1_QUICK(st->st_state->kind) &&
		    st->st_connection->local->host.config->xauth.client &&
		    !st->hidden_variables.st_xauth_client_done) {
			dbg("XAUTH client is not yet authenticated");
			break;
		}

		/*
		 * when talking to some vendors, we need to initiate a mode
		 * cfg request to get challenged, but there is also an
		 * override in the form of a policy bit.
		 */
		dbg("modecfg pull: %s policy:%s %s",
		    (st->quirks.modecfg_pull_mode ?
		     "quirk-poll" : "noquirk"),
		    (st->st_connection->config->modecfg.pull ? "pull" : "push"),
		    (st->st_connection->local->host.config->modecfg.client ?
		     "modecfg-client" : "not-client"));

		if (st->st_connection->local->host.config->modecfg.client &&
		    IS_V1_ISAKMP_SA_ESTABLISHED(st) &&
		    (st->quirks.modecfg_pull_mode ||
		     st->st_connection->config->modecfg.pull) &&
		    !st->hidden_variables.st_modecfg_started) {
			dbg("modecfg client is starting due to %s",
			    st->quirks.modecfg_pull_mode ? "quirk" :
			    "policy");
			modecfg_send_request(st);
			break;
		}

		/* Should we set the peer's IP address regardless? */
		if (st->st_connection->local->host.config->modecfg.server &&
		    IS_V1_ISAKMP_SA_ESTABLISHED(st) &&
		    !st->hidden_variables.st_modecfg_vars_set &&
		    !st->st_connection->config->modecfg.pull) {
			change_v1_state(st, STATE_MODE_CFG_R1);
			log_state(RC_LOG, st, "Sending MODE CONFIG set");
			/*
			 * ??? we ignore the result of modecfg.
			 * But surely, if it fails, we ought to terminate this exchange.
			 * What do the RFCs say?
			 */
			modecfg_start_set(st);
			break;
		}

		/* wait for modecfg_set */
		if (st->st_connection->local->host.config->modecfg.client &&
		    IS_V1_ISAKMP_SA_ESTABLISHED(st) &&
		    !st->hidden_variables.st_modecfg_vars_set) {
			dbg("waiting for modecfg set from server");
			break;
		}

		dbg("phase 1 is done, looking for phase 2 to unpend");

		if (smc->flags & SMF_RELEASE_PENDING_P2) {
			/* Initiate any Quick Mode negotiations that
			 * were waiting to piggyback on this Keying Channel.
			 *
			 * ??? there is a potential race condition
			 * if we are the responder: the initial Phase 2
			 * message might outrun the final Phase 1 message.
			 *
			 * so, instead of actually sending the traffic now,
			 * we schedule an event to do so.
			 *
			 * but, in fact, quick_mode will enqueue a cryptographic operation
			 * anyway, which will get done "later" anyway, so maybe it is just fine
			 * as it is.
			 *
			 */
			unpend(pexpect_ike_sa(st), NULL);
		}

		if (IS_V1_ISAKMP_SA_ESTABLISHED(st) ||
		    IS_IPSEC_SA_ESTABLISHED(st))
			release_whack(st->logger, HERE);

		if (IS_V1_QUICK(st->st_state->kind))
			break;

		break;
	}

	case STF_INTERNAL_ERROR:
		/* update the previous packet history */
		remember_received_packet(st, md);
		llog_pexpect(st->logger, HERE,
			     "state transition function for %s had internal error",
			     st->st_state->name);
		release_pending_whacks(st, "internal error");
		/* expire will eventually delete state? */
		break;

	case STF_FATAL:
	{
		passert(st != NULL);
		/* update the previous packet history */
		remember_received_packet(st, md);
		log_state(RC_FATAL, st, "encountered fatal error in state %s",
			  st->st_state->name);
#ifdef HAVE_NM
		if (st->st_connection->config->remote_peer_cisco &&
		    st->st_connection->config->nm_configured) {
			if (!do_updown(UPDOWN_DISCONNECT_NM,
				       st->st_connection,
				       st->st_connection->spd,
				       pexpect_child_sa(st),
				       st->logger))
				dbg("sending disconnect to NM failed, you may need to do it manually");
		}
#endif
		struct ike_sa *isakmp =
			established_isakmp_sa_for_state(st, /*viable-parent*/false);
		llog_n_maybe_send_v1_delete(isakmp, st, HERE);
		connection_delete_v1_state(&st, HERE);
		md->v1_st = st = NULL;
		break;
	}

	case STF_FAIL_v1N:
	default:
	{
		passert(result >= STF_FAIL_v1N);
		md->v1_note = result - STF_FAIL_v1N;
		/* As it is, we act as if this message never happened:
		 * whatever retrying was in place, remains in place.
		 */
		/*
		 * Try to convert the notification into a non-NULL
		 * string.  For NOTHING_WRONG, be vague (at the time
		 * of writing the enum_names didn't contain
		 * NOTHING_WRONG, and even if it did "nothing wrong"
		 * wouldn't exactly help here :-).
		 */
		enum_buf notify_name;
		if (md->v1_note == v1N_NOTHING_WRONG) {
			notify_name.buf = "failed";
		} else {
			str_enum_short(&v1_notification_names, md->v1_note, &notify_name);
		}

		/*
		 * ??? why no call of remember_received_packet?
		 * Perhaps because the message hasn't been authenticated?
		 * But then then any duplicate would lose too, I would think.
		 */

		if (md->v1_note != v1N_NOTHING_WRONG) {
			/* this will log */
			SEND_NOTIFICATION(md->v1_note);
		} else {
			log_state(RC_LOG, st, "state transition failed: %s", notify_name.buf);
		}

		dbg("state transition function for %s failed: %s",
		    st->st_state->name, notify_name.buf);

#ifdef HAVE_NM
		if (st->st_connection->config->remote_peer_cisco &&
		    st->st_connection->config->nm_configured) {
			if (!do_updown(UPDOWN_DISCONNECT_NM,
				       st->st_connection,
				       st->st_connection->spd,
				       pexpect_child_sa(st),
				       st->logger))
				dbg("sending disconnect to NM failed, you may need to do it manually");
		}
#endif
		if (IS_V1_QUICK(st->st_state->kind)) {
			ldbg(st->logger, "quick delete");
			connection_delete_v1_state(&st, HERE);
			/* wipe out dangling pointer to st */
			md->v1_st = NULL;
		} else if  (st->st_state->kind == STATE_AGGR_R0 ||
			    st->st_state->kind == STATE_MAIN_R0) {
			/*
			 *
			 * Wipe out the incomplete larval state.
			 *
			 * ARGH! In <=v4.10, the aggr code flipped the
			 * larval state to R1 right at the start of
			 * the transition and not the end, so using
			 * state to figure things out is close to
			 * useless.
			 *
			 * Deleting the state means that pluto has no
			 * way to detect and ignore amplification
			 * attacks.
			 */
			struct ike_sa *ike = pexpect_ike_sa(st);
			ldbg_sa(ike, "r0 delete");
			connection_delete_ike(&ike, HERE);
			/* wipe out dangling pointer to st */
			md->v1_st = NULL;
		}

		break;
	}
	}
}

void doi_log_cert_thinking(uint16_t auth,
			   enum ike_cert_type certtype,
			   enum certpolicy policy,
			   bool gotcertrequest,
			   bool send_cert,
			   bool send_chain)
{
	if (DBGP(DBG_BASE)) {
		DBG_log("thinking about whether to send my certificate:");

		esb_buf oan;
		esb_buf ictn;
		DBG_log("  I have RSA key: %s cert.type: %s ",
			str_enum(&oakley_auth_names, auth, &oan),
			str_enum(&ike_cert_type_names, certtype, &ictn));

		esb_buf cptn;
		DBG_log("  sendcert: %s and I did%s get a certificate request ",
			str_enum(&certpolicy_type_names, policy, &cptn),
			gotcertrequest ? "" : " not");

		DBG_log("  so %ssend cert.", send_cert ? "" : "do not ");

		if (!send_cert) {
			if (auth == OAKLEY_PRESHARED_KEY) {
				DBG_log("I did not send a certificate because digital signatures are not being used. (PSK)");
			} else if (certtype == CERT_NONE) {
				DBG_log("I did not send a certificate because I do not have one.");
			} else if (policy == CERT_SENDIFASKED) {
				DBG_log("I did not send my certificate because I was not asked to.");
			} else {
				DBG_log("INVALID AUTH SETTING: %d", auth);
			}
		}
		if (send_chain)
			DBG_log("Sending one or more authcerts");
	}
}

/*
 * an ISAKMP SA has been established.
 * Note the serial number, and release any connections with
 * the same peer ID but different peer IP address.
 *
 * Called by IKEv1 when the ISAKMP SA is established.  It checks if
 * the freshly established connection needs is replacing an
 * established version of itself.
 *
 * The use of uniqueIDs is mostly historic and might be removed
 * in a future version. It is ignored for PSK based connections,
 * which only act based on being a "server using PSK".
 *
 * IKEv1 code does not send or process INITIAL_CONTACT.
 */

void ISAKMP_SA_established(struct ike_sa *ike)
{
	wipe_old_connections(ike);
	connection_establish_ike(ike, HERE);
}

/*
 * Return the established ISAKMP SA that can send messages (such as
 * Delete or DPD) for the established state.
 */

struct ike_sa *established_isakmp_sa_for_state(struct state *st,
					       bool viable_parent)
{
	PASSERT(st->logger, !st->st_on_delete.skip_send_delete);
	PASSERT(st->logger, st->st_ike_version == IKEv1);

	if (IS_V1_ISAKMP_SA_ESTABLISHED(st)) {
		pdbg(st->logger,
		     "send? yes, IKEv1 ISAKMP SA in state %s is established",
		     st->st_state->short_name);
		return pexpect_ike_sa(st);
	}

	if (IS_V1_ISAKMP_SA(st)) {
		pdbg(st->logger,
		     "send? no, IKEv1 ISAKMP SA in state %s is NOT established",
		     st->st_state->short_name);
		return NULL;
	}

	PEXPECT(st->logger, IS_CHILD_SA(st));

	if (!IS_IPSEC_SA_ESTABLISHED(st)) {
		/*
		 * PW: But this is valid for IKEv1, where it would
		 * need to start a new IKE SA to send the delete
		 * notification ???
		 */
		pdbg(st->logger,
		     "send? no, IKEv1 IPsec SA in state %s is not established",
		     st->st_state->name);
		return NULL;
	}

	struct ike_sa *isakmp = find_ike_sa_by_connection(st->st_connection,
							  V1_ISAKMP_SA_ESTABLISHED_STATES,
							  viable_parent);
	if (isakmp == NULL) {
		pdbg(st->logger,
		     "send? no, IKEv1 IPsec SA in state %s is established but has no established ISAKMP SA",
		     st->st_state->short_name);
		return NULL;
	}

	pdbg(st->logger,
	     "send? yes, IKEv1 IPsec SA in state %s is established and has the established ISAKMP SA "PRI_SO,
	     st->st_state->short_name,
	     pri_so(isakmp->sa.st_serialno));
	return isakmp;
}

/*
 * if the state is too busy to process a packet, say so
 */

bool v1_state_busy(const struct state *st)
{
	passert(st != NULL);

	if (st->st_v1_background_md != NULL) {
		dbg("#%lu is busy; has background MD %p",
		    st->st_serialno, st->st_v1_background_md);
		return true;
	}

	if (st->ipseckey_dnsr != NULL) {
		dbg("#%lu is busy; has IPSECKEY DNS %p",
		    st->st_serialno, st->ipseckey_dnsr);
		return true;
	}

	/*
	 * If IKEv1 is doing something in the background then the
	 * state isn't busy.
	 */
	if (st->st_v1_offloaded_task_in_background) {
		pexpect(st->st_offloaded_task != NULL);
		dbg("#%lu is idle; has background offloaded task",
		    st->st_serialno);
		return false;
	}
	/*
	 * If this state is busy calculating.
	 */
	if (st->st_offloaded_task != NULL) {
		dbg("#%lu is busy; has an offloaded task",
		    st->st_serialno);
		return true;
	}
	dbg("#%lu is idle", st->st_serialno);
	return false;
}

bool verbose_v1_state_busy(const struct state *st)
{
	if (st == NULL) {
		dbg("#null state always idle");
		return false;
	}
	if (!v1_state_busy(st)) {
		dbg("#%lu idle", st->st_serialno);
		return false;
	}

	/* not whack */
	/* XXX: why not whack? */
	/* XXX: can this and below be merged; is there always an offloaded task? */
	log_state(LOG_STREAM/*not-whack*/, st,
		  "discarding packet received during asynchronous work (DNS or crypto) in %s",
		  st->st_state->name);
	return true;
}

/*
 * Reply messages are built in this nasty evil global buffer.
 *
 * Only one packet can be built at a time.  That should be ok as
 * packets are only built on the main thread and code and a packet is
 * created using a single operation.
 *
 * In the good old days code would partially construct a packet,
 * wonder off to do crypto and process other packets, and then assume
 * things could be picked up where they were left off.  Code to make
 * that work (saving restoring the buffer, re-initializing the buffer
 * in strange places, ....) has all been removed.
 *
 * Something else that should go is global access to REPLY_STREAM.
 * Instead all code should use open_reply_stream() and a reference
 * with only local scope.  This should reduce the odds of code
 * meddling in reply_stream on the sly.
 *
 * Another possibility is to move the buffer onto the stack.  However,
 * the PBS is 64K and that isn't so good for small machines.  Then
 * again the send.[hc] and demux[hc] code both allocate 64K stack
 * buffers already.  Oops.
 */

struct pbs_out reply_stream;
