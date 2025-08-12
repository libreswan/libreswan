/* demultiplex incoming IKE messages
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2010,2013-2017 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 Simon Deziel <simon@xelerance.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2011-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2015-2019 Andrew Cagney
 * Copyright (C) 2016-2018 Antony Antony <appu@phenome.org>
 * Copyright (C) 2017 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
 * Copyright (C) 2021 Paul Wouters <paul.wouters@aiven.io>
 * Copyright (C) 2020 Nupur Agrawal <nupur202000@gmail.com>
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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "sysdep.h"
#include "constants.h"

#include "defs.h"
#include "id.h"
#include "x509.h"
#include "pluto_x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "packet.h"
#include "crypto.h"
#include "crypt_symkey.h"
#include "ike_alg.h"
#include "log.h"
#include "demux.h"      /* needs packet.h */
#include "ikev2.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "timer.h"
#include "whack.h"      /* requires connections.h */
#include "server.h"
#include "nat_traversal.h"
#include "ip_address.h"
#include "ikev2_send.h"
#include "state_db.h"		/* for reash_state_cookies_in_db() */
#include "ietf_constants.h"
#include "ikev2_cookie.h"
#include "plutoalg.h" /* for default_ike_groups */
#include "ikev2_message.h"	/* for ikev2_decrypt_msg() */
#include "pluto_stats.h"
#include "ikev2_msgid.h"
#include "ikev2_redirect.h"
#include "ikev2_states.h"
#include "ip_endpoint.h"
#include "kernel.h"
#include "iface.h"
#include "ikev2_notification.h"
#include "unpack.h"
#include "pending.h"		/* for release_pending_whacks() */
#include "ikev2_host_pair.h"
#include "ikev2_unsecured.h"
#include "ikev2_ike_sa_init.h"
#include "ikev2_informational.h"
#include "ikev2_create_child_sa.h"
#include "ikev2_ike_intermediate.h"
#include "ikev2_ike_auth.h"
#include "ikev2_delete.h"		/* for record_v2_delete() */
#include "ikev2_child.h"		/* for jam_v2_child_sa_details() */
#include "ikev2_eap.h"
#include "terminate.h"
#include "ikev2_parent.h"

static callback_cb reinitiate_v2_ike_sa_init;	/* type assertion */

static void process_packet_with_secured_ike_sa(struct msg_digest *mdp, struct ike_sa *ike);

/*
 * IKEv2 has slightly different states than IKEv1.
 *
 * IKEv2 puts all the responsibility for retransmission on the end that
 * wants to do something, usually, that the initiator. (But, not always
 * the original initiator, of the responder decides it needs to rekey first)
 *
 * Each exchange has a bit that indicates if it is an Initiator message,
 * or if it is a response.  The Responder never retransmits its messages
 * except in response to an Initiator retransmission.
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

void ldbg_success_ikev2(struct ike_sa *ike, const struct msg_digest *md)
{
	LDBGP_JAMBUF(DBG_BASE, ike->sa.logger, buf) {
		jam_logger_prefix(buf, ike->sa.logger);
		jam_string(buf, ike->sa.st_v2_transition->story);
		jam_string(buf, ":");
		/* */
		jam_string(buf, " ");
		jam_enum_long(buf, &message_role_names, v2_msg_role(md));
		/* IKE role, not message role */
		switch (ike->sa.st_sa_role) {
		case SA_INITIATOR: jam_string(buf, " responder"); break;
		case SA_RESPONDER: jam_string(buf, " initiator"); break;
		}
		jam_string(buf, ":");
		jam_string(buf, ike->sa.st_state->story);
	}
}

/* sent EXCHANGE request to <address> */
void llog_success_ikev2_exchange_initiator(struct ike_sa *ike,
					const struct msg_digest *md)
{
	PEXPECT(ike->sa.logger, v2_msg_role(md) == NO_MESSAGE);
	LLOG_JAMBUF(RC_LOG, ike->sa.logger, buf) {
		jam_string(buf, "sent ");
		jam_enum_short(buf, &ikev2_exchange_names, ike->sa.st_v2_transition->exchange);
		jam_string(buf, " request to ");
		jam_endpoint_address_protocol_port_sensitive(buf, &ike->sa.st_remote_endpoint);
	}
}

void llog_success_ikev2_exchange_responder(struct ike_sa *ike,
					const struct msg_digest *md)
{
	PEXPECT(ike->sa.logger, v2_msg_role(md) == MESSAGE_REQUEST);
	LLOG_JAMBUF(RC_LOG, ike->sa.logger, buf) {
		jam_string(buf, "responder processed ");
		jam_enum_short(buf, &ikev2_exchange_names, ike->sa.st_v2_transition->exchange);
		jam_string(buf, "; ");
		jam_string(buf, ike->sa.st_state->story);
	}
}

void llog_success_ikev2_exchange_response(struct ike_sa *ike,
					  const struct msg_digest *md)
{
	PEXPECT(ike->sa.logger, v2_msg_role(md) == MESSAGE_RESPONSE);
	LLOG_JAMBUF(RC_LOG, ike->sa.logger, buf) {
		jam_string(buf, "initiator processed ");
		jam_enum_short(buf, &ikev2_exchange_names, ike->sa.st_v2_transition->exchange);
		jam_string(buf, "; ");
		jam_string(buf, ike->sa.st_state->story);
	}
}

/*
 * split an incoming message into payloads
 */
struct payload_summary ikev2_decode_payloads(struct logger *logger,
					     struct msg_digest *md,
					     struct pbs_in *in_pbs,
					     enum next_payload_types_ikev2 np)
{
	struct payload_summary summary = {
		.parsed = true,
		.n = v2N_NOTHING_WRONG,
	};

	/*
	 * ??? zero out the digest descriptors -- might nuke
	 * ISAKMP_NEXT_v2SK digest!
	 *
	 * XXX: and v2SKF? Safer to leave them as is and just use new
	 * ones - always add to MD, never take away.
	 */

	/*
	 * XXX: Currently, when a message containing an SK payload is
	 * decoded, the encrypted payloads get appended to the
	 * previously decoded non-encrypted payloads.  For instance,
	 * given a message containing two notifications:
	 *
	 *     N(1), SK{ N(2) }
	 *
	 * The notification digest would contain both the unencrypted
	 * N(1) and encrypted N(2).  Since the unencrypted value is
	 * protected, while not very good, isn't really dangerous.
	 */

	while (np != ISAKMP_NEXT_v2NONE) {
		name_buf b;
		ldbg(logger, "now let's proceed with payload (%s)",
		     str_enum_long(&ikev2_payload_names, np, &b));

		if (md->digest_roof >= elemsof(md->digest)) {
			llog(RC_LOG, logger, "more than %zu payloads in message; ignored",
			     elemsof(md->digest));
			summary.n = v2N_INVALID_SYNTAX;
			break;
		}

		/*
		 * *pd is the payload digest for this payload.
		 * It has three fields:
		 *	pbs is filled in by in_struct
		 *	payload is filled in by in_struct
		 *	next is filled in by list linking logic
		 */
		struct payload_digest *const pd = md->digest + md->digest_roof;

		/*
		 * map the payload onto its payload descriptor which
		 * describes how to decode it
		 */
		const struct_desc *sd = v2_payload_desc(np);

		if (sd == NULL) {
			/*
			 * This payload is unknown to us.  RFCs 4306
			 * and 5996 2.5 say that if the payload has
			 * the Critical Bit, we should be upset but if
			 * it does not, we should just ignore it.
			 */
			diag_t d = pbs_in_struct(in_pbs, &ikev2_generic_desc,
						 &pd->payload, sizeof(pd->payload), &pd->pbs);
			if (d != NULL) {
				llog(RC_LOG, logger,
				     "malformed payload in packet: %s", str_diag(d));
				pfree_diag(&d);
				summary.n = v2N_INVALID_SYNTAX;
				break;
			}
			if (pd->payload.v2gen.isag_critical & ISAKMP_PAYLOAD_CRITICAL) {
				/*
				 * It was critical.  See RFC 5996 1.5
				 * "Version Numbers and Forward
				 * Compatibility"
				 */
				const char *role;
				switch (v2_msg_role(md)) {
				case MESSAGE_REQUEST:
					role = "request";
					break;
				case MESSAGE_RESPONSE:
					role = "response";
					break;
				default:
					bad_case(v2_msg_role(md));
				}
				name_buf b;
				llog(RC_LOG, logger,
				     "message %s contained an unknown critical payload type (%s)",
				     role, str_enum_long(&ikev2_payload_names, np, &b));
				summary.n = v2N_UNSUPPORTED_CRITICAL_PAYLOAD;
				summary.data[0] = np;
				summary.data_size = 1;
				break;
			}
			name_buf eb;
			llog(RC_LOG, logger,
			     "non-critical payload ignored because it contains an unknown or unexpected payload type (%s) at the outermost level",
			     str_enum_long(&ikev2_payload_names, np, &eb));
			np = pd->payload.generic.isag_np;
			continue;
		}

		if (np >= LELEM_ROOF) {
			ldbg(logger, "huge next-payload %u", np);
			summary.n = v2N_INVALID_SYNTAX;
			break;
		}
		summary.repeated |= summary.present & LELEM(np);
		summary.present |= LELEM(np);

		/*
		 * Read in the payload recording what type it should
		 * be.
		 */
		pd->payload_type = np;
		diag_t d = pbs_in_struct(in_pbs, sd,
					 &pd->payload, sizeof(pd->payload),
					 &pd->pbs);
		if (d != NULL) {
			llog(RC_LOG, logger, "malformed payload in packet: %s", str_diag(d));
			pfree_diag(&d);
			summary.n = v2N_INVALID_SYNTAX;
			break;
		}

		ldbg(logger, "processing payload: %s (len=%zu)",
		     str_enum_long(&ikev2_payload_names, np, &b),
		     pbs_left(&pd->pbs));

		/*
		 * Place payload at the end of the chain for this
		 * type.
		 */
		if (md->last[np] == NULL) {
			/* first */
			md->chain[np] = md->last[np] = pd;
			pd->next = NULL;
		} else {
			/* append */
			md->last[np]->next = pd;
			md->last[np] = pd;
			pd->next = NULL;
		}

		/*
		 * Go deeper:
		 *
		 * XXX: should this do 'deeper' analysis of packets.
		 * For instance checking the SPI of a notification
		 * payload?  Probably not as the value may be ignored.
		 *
		 * The exception is seems to be v2N - both cookie and
		 * redirect code happen early and use the values.
		 */

		switch (np) {
		case ISAKMP_NEXT_v2N:
			decode_v2N_payload(logger, md, pd);
			break;
		default:
			break;
		}

		/*
		 * Determine the next payload.
		 *
		 * SK and SKF are special - their next-payload field
		 * is for the first embedded payload - so force it to
		 * NONE:
		 *
		 * RFC 5996 2.14 "Encrypted Payload":
		 *
		 * Next Payload - The payload type of the first
		 * embedded payload.  Note that this is an exception
		 * in the standard header format, since the Encrypted
		 * payload is the last payload in the message and
		 * therefore the Next Payload field would normally be
		 * zero.  But because the content of this payload is
		 * embedded payloads and there was no natural place to
		 * put the type of the first one, that type is placed
		 * here.
		 */
		switch (np) {
		case ISAKMP_NEXT_v2SK:
		case ISAKMP_NEXT_v2SKF:
			/* special */
			np = ISAKMP_NEXT_v2NONE;
			break;
		default:
			np = pd->payload.generic.isag_np;
			break;
		}

		md->digest_roof++;
	}

	return summary;
}

/*
 * Is this a duplicate of a previous exchange request?
 *
 * - the Message ID is old; drop the message as the exchange is old
 *
 * - the Message ID is matches the last exchange response; retransmit
 *   that response (for fragments, only retransmit when the first
 *   fragment)
 *
 * - the Message ID matches WIP; drop the message as the exchange
 *   response, which is being worked on, is not yet ready
 *
 * else, the exchange is assumed to be for a new, yet to be decrypted,
 * request
 *
 * Note: this code does not check to see if two fragments for a new
 * exchange have an identical fragment number; that's handled later
 * after the fragments have been decrypted
 */

static bool is_duplicate_request_msgid(struct ike_sa *ike,
					struct msg_digest *md)
{
	passert(v2_msg_role(md) == MESSAGE_REQUEST);
	passert(ike->sa.st_state->v2.secured); /* not IKE_SA_INIT */
	intmax_t msgid = md->hdr.isa_msgid; /* zero extend */

	/* the sliding window is really small?!? */
	pexpect(ike->sa.st_v2_msgid_windows.responder.recv ==
		ike->sa.st_v2_msgid_windows.responder.sent);

	/*
	 * Is this request old?  Yes, drop it.
	 *
	 * If the Message ID is earlier than the last response sent,
	 * then the message is too old and not worth a retransmit:
	 * since a message with ID SENT was received, the initiator
	 * must have received up to SENT-1 responses.
	 */
	if (msgid < ike->sa.st_v2_msgid_windows.responder.sent) {
		name_buf xb;
		llog_sa(RC_LOG, ike,
			"%s request has duplicate Message ID %jd but it is older than last response (%jd); message dropped",
			str_enum_short(&ikev2_exchange_names, md->hdr.isa_xchg, &xb),
			msgid, ike->sa.st_v2_msgid_windows.responder.sent);
		return true;
	}

	/*
	 * Is this request for last response? Yes, retransmit.
	 *
	 * Since the request Message ID matches the most recent
	 * response, the response was presumably lost.  Retransmit
	 * (with some fuzzy logic around fragments).
	 *
	 * The code is using just the Message ID.  Shouldn't this code
	 * instead compare entire message before retransmitting?
	 *
	 * Little point:
	 *
	 * - the attacker is both in-the-middle and active
	 *
	 *   Only messages that match the randomly chosen IKE
	 *   responder's SPI can reach this point.  Obtaining this
	 *   means being in-the-middle.  Exploiting it means being
	 *   active.
	 *
	 * - the attacker will just re-transmit the original message
	 *
	 *   Since it is capturing the IKE responder's SPI then it can
	 *   just as easily save the entire message.  Hence, such a
	 *   check could easily be defeated.
	 *
	 *   OTOH, making the attacker do this would give them
	 *   slightly more work.  Is it worth it?
	 *
	 * Besides, RFC 7296 in:
	 *
	 *   2.1.  Use of Retransmission Timers
	 *
	 * say to focus on the message IDs:
	 *
	 *   The responder MUST remember each response until it
	 *   receives a request whose sequence number is larger than
	 *   or equal to the sequence number in the response plus its
	 *   window size
	 *
	 * Where there is a problem, abet theoretical, is with
	 * fragments.  The code assumes that a message fragment only
	 * contains the SKF payload - if there were ever to be other
	 * payloads then the check would fail.
	 *
	 * Fortunately RFC 7383 (once it's wording is fixed) in:
	 *
	 *   2.5.3.  Fragmenting Messages Containing [unencrypted] payloads
	 *
	 * points out that:
	 *
	 *   Currently, there are no IKEv2 exchanges that define
	 *   messages, containing both [integrity protected payloads,
	 *   and encrypted and integrity protected payloads].
	 *
	 * Lets hold our breath.
	 */
	if (msgid == ike->sa.st_v2_msgid_windows.responder.sent) {
		/*
		 * XXX: should a local timer delete the last outgoing
		 * message after a short while so that retransmits
		 * don't go for ever?  The RFC seems to think so:
		 *
		 * 2.1.  Use of Retransmission Timers
		 *
		 *   [...] In order to allow saving memory, responders
		 *   are allowed to forget the response after a
		 *   timeout of several minutes.
		 */
		if (ike->sa.st_v2_msgid_windows.responder.outgoing_fragments == NULL) {
			name_buf xb;
			llog_pexpect_v2_msgid(ike,
					      "%s request has duplicate Message ID %jd but there is no saved message to retransmit; message dropped",
					      str_enum_long(&ikev2_exchange_names, md->hdr.isa_xchg, &xb),
					      msgid);
			return true;
		}

		/*
		 * Does the message only contain an SKF payload?  (no
		 * exchange is defined that contains more than just
		 * that payload).
		 *
		 * The RFC 7383, in:
		 *
		 *   2.6.1.  Replay Detection and Retransmissions
		 *
		 * says to check:
		 *
		 *   If an incoming message contains an Encrypted
		 *   Fragment payload, the values of the Fragment
		 *   Number and Total Fragments fields MUST be used
		 *   along with the Message ID to detect
		 *   retransmissions and replays.
		 */

		switch (md->hdr.isa_np) {
		case ISAKMP_NEXT_v2SK:
			if (ike->sa.st_v2_msgid_windows.responder.recv_frags > 0 &&
			    md->hdr.isa_np == ISAKMP_NEXT_v2SKF) {
				name_buf xb;
				llog_sa(RC_LOG, ike,
					"%s request has duplicate Message ID %jd but original was fragmented; message dropped",
					str_enum_short(&ikev2_exchange_names, md->hdr.isa_xchg, &xb),
					msgid);
				return true;
			}
			name_buf xb;
			llog_sa(RC_LOG, ike,
				"%s request has duplicate Message ID %jd; retransmitting response",
				str_enum_short(&ikev2_exchange_names, md->hdr.isa_xchg, &xb),
				msgid);
			break;
		case ISAKMP_NEXT_v2SKF:
			if (ike->sa.st_v2_msgid_windows.responder.recv_frags == 0) {
				name_buf xb;
				llog_sa(RC_LOG, ike,
					"%s request fragment has duplicate Message ID %jd but original was not fragmented; message dropped",
					str_enum_short(&ikev2_exchange_names, md->hdr.isa_xchg, &xb),
					msgid);
				return true;
			}
			pexpect(md->chain[ISAKMP_NEXT_v2SKF] == NULL); /* not yet parsed */
			struct ikev2_skf skf;
			struct pbs_in in_pbs = md->message_pbs; /* copy */
			struct pbs_in ignored;
			diag_t d = pbs_in_struct(&in_pbs, &ikev2_skf_desc,
						 &skf, sizeof(skf), &ignored);
			if (d != NULL) {
				llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
				pfree_diag(&d);
				return true;
			}
			if (skf.isaskf_total != ike->sa.st_v2_msgid_windows.responder.recv_frags) {
				name_buf xb;
				dbg_v2_msgid(ike,
					     "%s request fragment %u of %u has duplicate Message ID %jd but should have fragment total %u; message dropped",
					     str_enum_short(&ikev2_exchange_names, md->hdr.isa_xchg, &xb),
					     skf.isaskf_number, skf.isaskf_total, msgid,
					     ike->sa.st_v2_msgid_windows.responder.recv_frags);
				return true;
			}
			if (skf.isaskf_number != 1) {
				name_buf xb;
				dbg_v2_msgid(ike,
					     "%s request fragment %u of %u has duplicate Message ID %jd but is not fragment 1; message dropped",
					     str_enum_short(&ikev2_exchange_names, md->hdr.isa_xchg, &xb),
					     skf.isaskf_number, skf.isaskf_total, msgid);
				return true;
			}
			name_buf fxb;
			llog_sa(RC_LOG, ike,
				"%s request fragment %u of %u has duplicate Message ID %jd; retransmitting response",
				str_enum_short(&ikev2_exchange_names, md->hdr.isa_xchg, &fxb),
				skf.isaskf_number, skf.isaskf_total, msgid);
			break;
		default:
		{
			/* until there's evidence that this is valid */
			name_buf xb;
			llog_sa(RC_LOG, ike,
				"%s request has duplicate Message ID %jd but does not start with SK or SKF payload; message dropped",
				str_enum_short(&ikev2_exchange_names, md->hdr.isa_xchg, &xb),
				msgid);
			return true;
		}
		}
		send_recorded_v2_message(ike, "ikev2-responder-retransmit",
					 ike->sa.st_v2_msgid_windows.responder.outgoing_fragments);
		return true;
	}

	/* all that is left */
	pexpect(msgid > ike->sa.st_v2_msgid_windows.responder.sent);

	/*
	 * Is the secured IKE SA responder already working on this
	 * secured exchange request?
	 *
	 * (remember, this code path is only for secured exchanges,
	 * IKE_SA_INIT goes elsewhere)
	 *
	 * The IKE SA responder only starts working on the message
	 * (setting wip.responder) when:
	 *
	 * - the IKE SA's keying material (SKEYSEED) has been computed
	 *
	 * - all fragments decrypt
	 *
	 * - the message has been re-assembled from decrypted
	 *   fragments
	 */

	if (ike->sa.st_v2_msgid_windows.responder.wip == msgid) {
		llog(RC_LOG, ike->sa.logger,
		     "discarding packet received during asynchronous work (DNS or crypto) in %s",
		     ike->sa.st_state->name);
		return true;
	}

	if (PBAD(ike->sa.logger, ike->sa.st_state == NULL)) {
		return true;
	}

	/*
	 * If the message is not a "duplicate", then what is it?
	 * Following code gets to decide.
	 */
	return false;
}

/*
 * A duplicate response could be:
 *
 * - for an old request where there's no longer an initiator waiting,
 *   it can be dropped
 *
 * - the initiator is busy, presumably because this response is a
 *   duplicate and the initiator is waiting on crypto to complete so
 *   it can decrypt the response
 */
static bool is_duplicate_response(struct ike_sa *ike,
				  struct msg_digest *md)
{
	PASSERT(ike->sa.logger, v2_msg_role(md) == MESSAGE_RESPONSE);
	intmax_t msgid = md->hdr.isa_msgid;

	/* the sliding window is really small!?! */
	PEXPECT(ike->sa.logger, (ike->sa.st_v2_msgid_windows.initiator.sent >=
				 ike->sa.st_v2_msgid_windows.initiator.recv));

	if (ike->sa.st_v2_msgid_windows.initiator.recv >= msgid) {
		/*
		 * Processing of the response was completed so drop as
		 * too old.
		 *
		 * XXX: Should be limited_llog_md() but that shows up
		 * in the whack output.  While "correct" it messes
		 * with test output.  The old log line didn't show up
		 * because current-state wasn't set.
		 *
		 * Here's roughly why INITIATOR can be non-NULL:
		 *
		 * - west.#8 needs a rekey, so west.#11 is created and
		 * it sends a CREATE_CHILD_SA with Message ID 3.
		 *
		 * - west.#8 gives up on the re-key so it forces a
		 * delete request (aka record'n'send), sending a
		 * second message with ID 4
		 *
		 * West has two outstanding messages yet its window
		 * size of 1!
		 *
		 * - east receives the rekey with ID 3, creates
		 * east.#11 and and sends it off for further
		 * processing
		 *
		 * - east receives the delete with ID 4, forces a
		 * message ID update and sends an ID 4 response
		 * confirming the delete
		 *
		 * - east.#11 finishes its crypto so east sends back
		 * its response with Message ID 3 for a re-keyed SA it
		 * just deleted?!?!
		 *
		 * East has responded with two out-of-order messages
		 * (if the window size was 2 this would be ok but it
		 * isn't).
		 *
		 * - west receives the ID 4 response, tries to delete
		 * the IKE SA but can't because west.#11 is lurking;
		 * but regardless the ID window is forced 2->4
		 *
		 * - west receives the ID 3 response, which is clearly
		 * to-old so doesn't expect there to be a matching
		 * initiator, arrg
		 */
		name_buf xb;
		dbg_v2_msgid(ike, "unexpected %s response with Message ID %ju (last received was %jd); dropping packet",
			     str_enum_short(&ikev2_exchange_names, md->hdr.isa_xchg, &xb),
			     msgid, ike->sa.st_v2_msgid_windows.initiator.recv);
		return true;
	}

	if (ike->sa.st_v2_msgid_windows.initiator.sent != msgid) {
		/*
		 * While there's an IKE SA matching the IKE SPIs,
		 * there's no corresponding initiator for the message.
		 */
		name_buf xb;
		llog_sa(RC_LOG, ike,
			"unexpected %s response with Message ID %jd (last sent was %jd); dropping packet",
			str_enum_long(&ikev2_exchange_names, md->hdr.isa_xchg, &xb),
			msgid, ike->sa.st_v2_msgid_windows.initiator.sent);
		return true;
	}

	if (ike->sa.st_v2_msgid_windows.initiator.wip == msgid) {
		/*
		 * Initiator is already working on this response.
		 * Presumably a re-transmit so quietly drop it.
		 */
		name_buf xb;
		dbg_v2_msgid(ike,
			     "%s response with Message ID %jd is work-in-progress; dropping packet",
			     str_enum_long(&ikev2_exchange_names, md->hdr.isa_xchg, &xb),
			     msgid);
		return true;
	}

	if (ike->sa.st_v2_msgid_windows.initiator.wip != -1) {
		/*
		 * While there's an IKE SA matching the IKE SPIs,
		 * there's no corresponding initiator for the message.
		 */
		name_buf xb;
		llog_sa(RC_LOG, ike,
			"unexpected %s response with Message ID %jd (processing %jd); dropping packet",
			str_enum_long(&ikev2_exchange_names, md->hdr.isa_xchg, &xb),
			msgid, ike->sa.st_v2_msgid_windows.initiator.wip);
		return true;
	}

	if (PBAD(ike->sa.logger, ike->sa.st_v2_msgid_windows.initiator.exchange == NULL)) {
		return true;
	}

	return false;
}

/*
 * process an input packet, possibly generating a reply.
 *
 * If all goes well, this routine eventually calls a state-specific
 * transition function.
 *
 * This routine will not md_delref(mdp).
 *
 * Start by looking for (or creating) the IKE SA responsible for the
 * IKE SPIs group .....
 */

void ikev2_process_packet(struct msg_digest *md)
{
	/*
	 * Caller did their job?
	 *
	 * Message role is determined by 1 bit, so one of these must
	 * be tree.
	 */
	passert(md != NULL);
	passert(hdr_ike_version(&md->hdr) == IKEv2);
	passert(v2_msg_role(md) == MESSAGE_REQUEST ||
		v2_msg_role(md) == MESSAGE_RESPONSE);

	/*
	 * If the IKE SA initiator (IKE_I) sent the message then this
	 * end is looking for the IKE SA responder (and vice versa).
	 */
	enum sa_role expected_local_ike_role =
		(md->hdr.isa_flags & ISAKMP_FLAGS_v2_IKE_I) ? SA_RESPONDER :
		SA_INITIATOR;

	/*
	 * Dump what the message says, once a state has been found
	 * this can be checked against what is.
	 */

	const enum ikev2_exchange ix = md->hdr.isa_xchg;
	LDBGP_JAMBUF(DBG_BASE, md->logger, buf) {
		switch (expected_local_ike_role) {
		case SA_RESPONDER:
			jam(buf, "I am the IKE SA Original Responder");
			break;
		case SA_INITIATOR:
			jam(buf, "I am the IKE SA Original Initiator");
			break;
		default:
			bad_case(expected_local_ike_role);
		}
		jam(buf, " receiving an IKEv2 ");
		jam_enum_short(buf, &ikev2_exchange_names, ix);
		switch (v2_msg_role(md)) {
		case MESSAGE_RESPONSE:
			jam(buf, " response ");
			break;
		case MESSAGE_REQUEST:
			jam(buf, " request ");
			break;
		default:
			bad_case(v2_msg_role(md));
		}
	}

	/*
	 * Handle an unsecured IKE exchange (IKE_SA_INIT or
	 * IKE_SESSION_RESUME).
	 *
	 * Unlike for later exchanges (which requires an existing
	 * secured IKE SA), the code processing an unsecured
	 * IKE_SA_INIT message may never need, create, or search for
	 * an IKE SA; and when it does it uses a specalized lookup.
	 *
	 * For instance, when a cookie is required, a message with no
	 * cookie is rejected before the IKE SA is created.
	 *
	 * Hence, the unsecured exchanges are given their own separate
	 * code path.
	 */

	if (ix == ISAKMP_v2_IKE_SA_INIT) {
		process_v2_UNSECURED_message(md);
		return;
	}

	if (ix == ISAKMP_v2_IKE_SESSION_RESUME) {
		process_v2_UNSECURED_message(md);
		return;
	}

	/*
	 * Find the IKE SA with matching SPIs.
	 *
	 * The IKE SA's Message IDs can then be used to determine if
	 * the message fits in the message window (new request,
	 * expected response, or old message).
	 */
	struct ike_sa *ike = find_v2_ike_sa(&md->hdr.isa_ike_spis,
					    expected_local_ike_role);
	if (ike == NULL) {
		name_buf ixb;
		limited_llog_md(md, "%s %s has no corresponding IKE SA; message dropped",
				str_enum_short(&ikev2_exchange_names, ix, &ixb),
				v2_msg_role(md) == MESSAGE_REQUEST ? "request" : "response");
		return;
	}

	/*
	 * Re-check ST's IKE SA's role against the I(Initiator) flag
	 * in the headers.  Since above searches will only find an IKE
	 * SA when the IKE SA's role is correct, this should always
	 * work.
	 */
	if (!pexpect(ike->sa.st_sa_role == expected_local_ike_role)) {
		return;
	}

	/*
	 * Since unsecured exchanges (IKE_SA_INIT, IKE_SESSION_RESUME)
	 * have been excluded, the only acceptable option is a
	 * protected exchange (has SK or SKF) using a secured IKE SA.
	 *
	 * Narrow things further by ensuring that the IKE SA is,
	 * indeed, secured.
	 *
	 * An attacker sending a non IKE_SA_INIT response to an
	 * IKE_SA_INIT request, for instance, would tickle this code
	 * path.
	 */
	if (!ike->sa.st_state->v2.secured) {
		name_buf ixb;
		/* there's no rate_llog() */
		limited_llog_md(md, "IKE SA "PRI_SO" for %s %s has not been secured; message dropped",
				pri_so(ike->sa.st_serialno),
				str_enum_short(&ikev2_exchange_names, ix, &ixb),
				v2_msg_role(md) == MESSAGE_REQUEST ? "request" : "response");
		return;
	}

	/*
	 * Since there's an IKE SA start billing and logging against
	 * it.
	 */
	statetime_t start = statetime_backdate(&ike->sa, &md->md_inception);
	process_packet_with_secured_ike_sa(md, ike);
	statetime_stop(&start, "%s()", __func__);
}

/*
 * Payload decrypted and integrity was ok but contents weren't valid.
 * Either because the secured payload didn't unpack, or the contents
 * of the unpacked secured weren't recognized (didn't match any state
 * transition).
 *
 * XXX: According to "2.21.2.  Error Handling in IKE_AUTH" and
 * "2.21.3.  Error Handling after IKE SA is Authenticated" this should
 * be fatal, killing the IKE SA.  Oops.
 *
 * Since there's no state transition to complete, find one vaguely
 * plausible, and then complete it with a fatal error, triggering the
 * delete of the IKE family.
 *
 * This is largely astetic.  It could use the first transition but
 * often a later transition reads better.  Perhaps the last transition
 * since, presumably, that is the most generic?
 *
 * XXX: the transition should match the exchange, the below probably
 * gets that wrong?
 */

static void complete_protected_but_fatal_exchange(struct ike_sa *ike, struct msg_digest *md,
						  v2_notification_t n, shunk_t data)
{
	PASSERT(ike->sa.logger, md != NULL);
	enum message_role recv_role = v2_msg_role(md);

	const struct finite_state *state = ike->sa.st_state;

	/* starting point */
	const struct v2_transition undefined_transition = {
		.story = "suspect message",
		.to = finite_states[STATE_UNDEFINED],
		.recv_role = recv_role,
		.llog_success = ldbg_success_ikev2,
	};
	const struct v2_transition *transition = &undefined_transition;

	switch (recv_role) {
	case MESSAGE_REQUEST:
	{
		const struct v2_exchanges *responder_exchanges =
			&state->v2.ike_responder_exchanges;
		if (responder_exchanges->len > 0) {
			const struct v2_transitions *transitions =
				&responder_exchanges->list[0]->transitions.responder;
			if (transitions->len > 0) {
				transition = &transitions->list[transitions->len - 1];
				break;
			}
		}
		break;
	}
	case MESSAGE_RESPONSE:
	{
		/*
		 * Responding to either an IKE_INTERMEDIATE or
		 * IKE_AUTH request.  Grab the last one.
		 */
		{
			const struct v2_exchange *exchange = ike->sa.st_v2_msgid_windows.initiator.exchange;
			if (exchange != NULL) {
				const struct v2_transitions *transitions =
					&exchange->transitions.response;
				if (transitions->len > 0) {
					transition = &transitions->list[transitions->len - 1];
					break;
				}
			}
		}
		break;
	}
	case NO_MESSAGE:
		bad_case(recv_role);
	}

	/*
	 * Fudge things so that the IKE SA appears to be processing MD
	 * using TRANSITION.
	 */
	start_v2_transition(ike, transition, md, HERE);

	/*
	 * Respond to the request (can't respond to a response).
	 */
	switch (v2_msg_role(md)) {
	case MESSAGE_REQUEST:
		record_v2N_response(ike->sa.logger, ike, md,
				    n, data,
				    ENCRYPTED_PAYLOAD);
		break;
	case MESSAGE_RESPONSE:
		break;
	default:
		bad_case(v2_msg_role(md));
	}

	/* XXX: deletes IKE SA */
	complete_v2_state_transition(ike, md, STF_FATAL);
}

/*
 * A secured IKE SA for the message has been found (the message also
 * needs to be protected, but that has yet to be confirmed).
 *
 * First though filter, use the Message ID to filter out duplicates.
 */

static void process_packet_with_secured_ike_sa(struct msg_digest *md, struct ike_sa *ike)
{
	struct logger *logger = ike->sa.logger;
	passert(ike->sa.st_state->v2.secured);
	passert(md->hdr.isa_xchg != ISAKMP_v2_IKE_SA_INIT);

	/*
	 * Deal with duplicate messages and busy states.
	 */
	switch (v2_msg_role(md)) {
	case MESSAGE_REQUEST:
		/*
		 * The IKE SA always processes requests.
		 */
		if (md->fake_clone) {
			llog_sa(RC_LOG, ike, "IMPAIR: processing a fake (cloned) message");
		}
		/*
		 * Based on the Message ID, is this a true duplicate?
		 *
		 * If MD is a fragment then it isn't considered a
		 * duplicate.
		 */
		if (is_duplicate_request_msgid(ike, md)) {
			return;
		}
		break;
	case MESSAGE_RESPONSE:
		/*
		 * This is the response to an earlier request; use the
		 * IKE SA to find the state that initiated the
		 * exchange (sent that request).
		 *
		 * If the response is a fragment then ST will be
		 * non-NULL; is_duplicate_response() gets to figure
		 * out if the fragments are complete or need to wait
		 * longer.
		 */
		if (md->fake_clone) {
			llog_sa(RC_LOG, ike, "IMPAIR: processing a fake (cloned) message");
		}
		if (is_duplicate_response(ike, md)) {
			return;
		}
		break;
	default:
		bad_case(v2_msg_role(md));
	}

	/*
	 * Is the message protected, or at least looks to be protected
	 * (i.e., does it have an SK or SKF payload).
	 *
	 * Because there can be other payloads before SK or SKF, the
	 * only way to truly confirm this is to unpack the all the
	 * payload headers.
	 *
	 * Remember, the unprotected IKE_SA_INIT exchange was excluded
	 * earlier, and the IKE SA is confirmed as secure.
	 */
	ldbg(logger, "unpacking clear payload");
	passert(!md->message_payloads.parsed);
	md->message_payloads =
		ikev2_decode_payloads(ike->sa.logger, md,
				      &md->message_pbs,
				      md->hdr.isa_np);
	if (md->message_payloads.n != v2N_NOTHING_WRONG) {
		/*
		 * Should only respond when the message is an
		 * IKE_SA_INIT request.  But that was handled above
		 * when dealing with cookies so here, there's zero
		 * reason to respond.
		 *
		 * already logged:
		 *
		 * Decode calls packet code and that logs errors on
		 * the spot
		 */
		return;
	}

	/*
	 * Using the (in theory) protected but not encrypted parts of
	 * the message, weed out anything that isn't at least vaguely
	 * plausible:
	 *
	 * - if the IKE SA isn't protecting exchanges then this will
         *   reject everything
	 *
	 *   IKE_SA_INIT was handled earlier, all further exchanges
	 *   are protected.
	 *
	 * - if the IKE SA is protecting exchanges then this will
         *   reject any message that doesn't contain an SK or SKF
         *   payload
	 *
	 *   Any transition from a secured state must involve a
	 *   protected payload.
	 *
	 * - for a request, if the responder's state doesn't have the
	 *   the exchange listed, then reject
	 *
	 *   All responder transitions have an exchange and all
	 *   exchanges have a responder transition.
	 *
	 * - for a response, if the exchange doesn't match the state's
	 *   exchange, reject everything
	 *
	 *   Only accept current exchange's responses.
	 *
	 * If the message is valid then the states/exchanges are
	 * scanned twice: first here and then, further down, when
	 * looking for the real transition.  Fortunately we're talking
	 * about at most 7 exchanges and, in this case, a relatively
	 * cheap compare (the old code scanned all transitions).
	 */
	if (!is_plausible_secured_v2_exchange(ike, md)) {
		/* already logged */
		/* drop packet on the floor */
		return;
	}

	/*
	 * The message looks protected, only step left is to validate
	 * the message.
	 */
	passert(ike->sa.st_state->v2.secured);
	passert(md != NULL);
	passert(!md->encrypted_payloads.parsed);
	passert(md->message_payloads.present & (v2P(SK) | v2P(SKF)));

	/*
	 * If the SKEYSEED is missing, compute it now (unless, of
	 * course, it is already being computed in the background).
	 *
	 * If necessary, this code will also accumulate unvalidated
	 * fragments / messages.
	 */
	if (!ike->sa.hidden_variables.st_skeyid_calculated) {
		/*
		 * Responder only.  On the initiator, SKEYSEED is
		 * handled by the IKE_SA_INIT response processor
		 * (i.e., not on this path).
		 */
		if (!PEXPECT(md->logger, v2_msg_role(md) == MESSAGE_REQUEST)) {
			return;
		}
		process_v2_request_no_skeyseed(ike, md);
		return;
	}

	/*
	 * Decrypt the message, verifying the protection.
	 *
	 * For fragments, also accumulate them (they are encrypted as
	 * they arrive), and once all are present, reassemble them.
	 *
	 * PROTECTED_MD will need to be released by this function (MD
	 * is released by the caller).
	 */
	passert(ike->sa.hidden_variables.st_skeyid_calculated);
	struct msg_digest *protected_md; /* MUST md_delref() */
	switch (md->message_payloads.present & (v2P(SK) | v2P(SKF))) {
	case v2P(SKF):
	{
		struct v2_msgid_window *window = v2_msgid_window(ike, v2_msg_role(md));
		struct v2_incoming_fragments **frags = &window->incoming_fragments;
		switch (collect_v2_incoming_fragment(ike, md, frags)) {
		case FRAGMENT_IGNORED:
			return;
		case FRAGMENTS_MISSING:
			ldbg(logger, "waiting for more fragments");
			return;
		case FRAGMENTS_COMPLETE:
			break;
		}
		/*
		 * Replace MD with a message constructed starting with
		 * fragment 1 (which also contains unencrypted
		 * payloads).
		 */
		protected_md = reassemble_v2_incoming_fragments(frags, ike->sa.logger);
		break;
	}
	case v2P(SK):
		if (!ikev2_decrypt_msg(ike, md)) {
			llog_sa(RC_LOG, ike,
				"encrypted payload seems to be corrupt; dropping packet");
			/* Secure exchange: NEVER EVER RESPOND */
			return;
		}
		protected_md = md_addref(md);
		break;
	default:
		/* packet decode should have rejected this */
		llog_pexpect(ike->sa.logger, HERE,
			     "message contains both SK and SKF payloads");
		return;
	}

	process_protected_v2_message(ike, protected_md);
	md_delref(&protected_md);
}

void process_protected_v2_message(struct ike_sa *ike, struct msg_digest *md)
{
	struct logger *logger = ike->sa.logger;
	/*
	 * The message successfully decrypted and passed integrity
	 * protected so definitely sent by the other end of the
	 * secured IKE SA channel.
	 *
	 * However, for IKE_AUTH (and an INFORMATIONAL exchange
	 * immediately following IKE_AUTH be due to failed
	 * authentication), the other end hasn't yet been
	 * authenticated so the secured contents can't always be
	 * trusted.
	 *
	 * If there's something wrong with the message contents, then
	 * the IKE SA gets abandoned, but a new new one may be
	 * initiated.
	 *
	 * See "2.21.2.  Error Handling in IKE_AUTH"
	 * and "2.21.3.  Error Handling after IKE SA is Authenticated".
	 *
	 * For UNSUPPORTED_CRITICAL_PAYLOAD, while the RFC clearly
	 * states that for the initial exchanges and an INFORMATIONAL
	 * exchange immediately following, the notification causes a
	 * delete, it says nothing for exchanges that follow.
	 *
	 * For moment treat it the same.  Given the PAYLOAD ID that
	 * should identify the problem isn't being returned this is
	 * the least of our problems.
	 */
	struct payload_digest *sk = md->chain[ISAKMP_NEXT_v2SK];
	md->encrypted_payloads = ikev2_decode_payloads(ike->sa.logger, md, &sk->pbs,
						       sk->payload.generic.isag_np);
	if (md->encrypted_payloads.n != v2N_NOTHING_WRONG) {
		shunk_t data = shunk2(md->encrypted_payloads.data,
				      md->encrypted_payloads.data_size);
		complete_protected_but_fatal_exchange(ike, md, md->encrypted_payloads.n, data);
		return;
	}

	/*
	 * XXX: is SECURED_PAYLOAD_FAILED redundant?  Earlier checks
	 * that the message payload is valid mean this can only fail
	 * on the secured payload?
	 */

	bool secured_payload_failed = false;
	const struct v2_transition *svm =
		find_v2_secured_transition(ike, md, &secured_payload_failed);

	/* no useful state microcode entry? */
	if (svm == NULL) {
		/* already logged */
		/* count all the error notifications */
		for (struct payload_digest *ntfy = md->chain[ISAKMP_NEXT_v2N];
		     ntfy != NULL; ntfy = ntfy->next) {
			pstat(ikev2_recv_notifies_e, ntfy->payload.v2n.isan_type);
		}
		pexpect(secured_payload_failed);
		/* XXX: calls delete_ike_sa() */
		complete_protected_but_fatal_exchange(ike, md, v2N_INVALID_SYNTAX, empty_shunk);
		return;
	}

	ldbg(logger, "selected state microcode %s", svm->story);

	v2_dispatch(ike, md, svm);
}

void v2_dispatch(struct ike_sa *ike, struct msg_digest *md,
		 const struct v2_transition *svm)
{
	struct logger *logger = ike->sa.logger;

	/*
	 * Start the state transition, including any updates to
	 * work-in-progress Message IDs.
	 */
	start_v2_transition(ike, svm, md, HERE);

	if (LDBGP(DBG_BASE, logger)) {
		if (pbs_left(&md->message_pbs) != 0)
			LDBG_log(logger, "removing %d bytes of padding",
				 (int) pbs_left(&md->message_pbs));
	}

	md->message_pbs.roof = md->message_pbs.cur;	/* trim padding (not actually legit) */

	ldbg(logger, "calling processor %s", svm->story);

	/*
	 * XXX: for now pass in NULL for the child.
	 *
	 * Should it be passing in the Message ID window that matched
	 * the message (assuming there is ever more than one Message
	 * ID window)?  For something like CREATE_CHILD_SA, it
	 * contains contain the work-in-progress Child SA.
	 */
	so_serial_t old_ike = ike->sa.st_serialno;
	statetime_t start = statetime_start(&ike->sa);
	stf_status e = svm->processor(ike, NULL/*child*/, md);
	/* danger: IKE may not be valid */

	if (e == STF_SKIP_COMPLETE_STATE_TRANSITION) {
		/*
		 * Danger! Processor did something dodgy like free the
		 * IKE SA!
		 */
		ldbg(logger, "processor '%s' for "PRI_SO" suppressed complete st_v2_transition",
		     svm->story, pri_so(old_ike));
	} else {
		complete_v2_state_transition(ike, md, e);
	}

	statetime_stop(&start, "processing: %s in %s()", svm->story, __func__);
	/* our caller with md_delref(mdp) */
}

static void success_v2_state_transition(struct ike_sa *ike,
					struct msg_digest *md,
					const struct v2_transition *transition)
{
	struct logger *logger = ike->sa.logger;
	passert(ike != NULL);

	LDBGP_JAMBUF(DBG_BASE, ike->sa.logger, buf) {
		jam(buf, "IKE SA in state %s transitioning to ",
		    ike->sa.st_state->short_name);
		jam_v2_transition(buf, transition);
	}

	/*
	 * Update counters, and if part of the transition, send the
	 * new message.
	 */

	v2_msgid_finish(ike, md, HERE);

	bool established_before = IS_IKE_SA_ESTABLISHED(&ike->sa);

	change_v2_state(&ike->sa);
	v2_msgid_schedule_next_initiator(ike);

	passert(ike->sa.st_state->kind >= STATE_IKEv2_FLOOR);
	passert(ike->sa.st_state->kind <  STATE_IKEv2_ROOF);

	bool established_after = IS_IKE_SA_ESTABLISHED(&ike->sa);

	bool just_established = (!established_before && established_after);

	/*
	 * 2.23.  NAT Traversal
	 *
	 * [...]
	 *
	 * o There are cases where a NAT box decides to remove
	 *   mappings that are still alive (for example, the keepalive
	 *   interval is too long, or the NAT box is rebooted).  This
	 *   will be apparent to a host if it receives a packet whose
	 *   integrity protection validates, but has a different port,
	 *   address, or both from the one that was associated with
	 *   the SA in the validated packet.  When such a validated
	 *   packet is found, a host that does not support other
	 *   methods of recovery such as IKEv2 Mobility and
	 *   Multihoming (MOBIKE) [MOBIKE], and that is not behind a
	 *   NAT, SHOULD send all packets (including retransmission
	 *   packets) to the IP address and port in the validated
	 *   packet, and SHOULD store this as the new address and port
	 *   combination for the SA (that is, they SHOULD dynamically
	 *   update the address).  A host behind a NAT SHOULD NOT do
	 *   this type of dynamic address update if a validated packet
	 *   has different port and/or address values because it opens
	 *   a possible DoS attack (such as allowing an attacker to
	 *   break the connection with a single packet).  Also,
	 *   dynamic address update should only be done in response to
	 *   a new packet; otherwise, an attacker can revert the
	 *   addresses with old replayed packets.  Because of this,
	 *   dynamic updates can only be done safely if replay
	 *   protection is enabled.  When IKEv2 is used with MOBIKE,
	 *   dynamically updating the addresses described above
	 *   interferes with MOBIKE's way of recovering from the same
	 *   situation.  See Section 3.8 of [MOBIKE] for more
	 *   information.
	 *
	 * XXX: so ....
	 *
	 * do nothing
	 */
	if (ike->sa.st_iface_endpoint->esp_encapsulation_enabled &&
	    /*
	     * Only when MOBIKE is not in the picture.
	     */
	    !ike->sa.st_v2_mobike.enabled &&
	    /*
	     * Only when responding ...
	     */
	    v2_msg_role(md) == MESSAGE_REQUEST &&
	    /*
	     * Only when the request changes the remote's endpoint ...
	     */
	    !endpoint_eq_endpoint(ike->sa.st_remote_endpoint, md->sender) &&
	    /*
	     * Only when the request was protected and passes
	     * integrity ...
	     *
	     * Once keymat is present, only encrypted messessages with
	     * valid integrity can successfully complete a transaction
	     * with STF_OK.  True?  True.
	     *
	     * IS_IKE_SA_ESTABLISHED() better?  False.  IKE_AUTH
	     * messages meet the above requirements.
	     */
	    ike->sa.hidden_variables.st_skeyid_calculated &&
	    md->encrypted_payloads.parsed &&
	    md->encrypted_payloads.n == v2N_NOTHING_WRONG &&
	    /*
	     * Only when the local IKE SA isn't behind NAT but the
	     * remote IKE SA is ...
	     */
	    !ike->sa.hidden_variables.st_nated_host &&
	    ike->sa.hidden_variables.st_nated_peer) {
		/*
		 * XXX: are these guards sufficient?
		 */
		endpoint_buf sb, mb;
		llog_sa(RC_LOG, ike, "NAT: MOBIKE disabled, ignoring peer endpoint change from %s to %s",
			str_endpoint(&ike->sa.st_remote_endpoint, &sb),
			str_endpoint(&md->sender, &mb));
#if 0
		/*
		 * Implementing this properly requires:
		 *
		 * + an audit of the above guards; are they
		 *   sufficient?
		 *
		 * + an update to the IKE SA's remote endpoint per
		 *   below
		 *
		 * + an update to any installed IPsec kernel state and
		 *   policy
		 *
		 * While this code was added in some form in '05, the
		 * code to update IPsec - was never implemented.  The
		 * result was an IKE SA yet the IPsec SAs had no
		 * traffic flow.
		 *
		 * See github/1529 and github/1492.
		 */
		ike->sa.st_remote_endpoint = md->sender;
#endif
	}
	/*
	 * Schedule for whatever timeout is specified (and shut down
	 * any short term timers).
	 */

	switch (transition->timeout_event) {

	case EVENT_v2_RETRANSMIT:
		/*
		 * Event retransmit is really a secret code to
		 * indicate that a request is being sent and a
		 * retransmit should already be scheduled.
		 */
		ldbg(logger, "checking that a retransmit timeout_event was already");
		event_delete(EVENT_v2_DISCARD, &ike->sa); /* relying on retransmit */
		pexpect(ike->sa.st_v2_retransmit_event != NULL);
		/* reverse polarity */
		pexpect(transition->recv_role == NO_MESSAGE);
		break;

	case EVENT_v2_REPLACE: /* IKE or Child SA replacement event */
		event_delete(EVENT_v2_DISCARD, &ike->sa); /* relying on replace */
		schedule_v2_replace_event(&ike->sa);
		break;

	case EVENT_v2_DISCARD:
		event_delete(EVENT_v2_DISCARD, &ike->sa);
		event_schedule(EVENT_v2_DISCARD, EXCHANGE_TIMEOUT_DELAY, &ike->sa);
		break;

	case EVENT_NULL:
		/*
		 * Is there really no case where we want to
		 * set no timer?  more likely an accident?
		 */
		llog_pexpect(ike->sa.logger, HERE,
			     "v2 microcode entry (%s) has unspecified timeout_event",
			     transition->story);
		break;

	case EVENT_RETAIN:
	{
		/* the previous lifetime event is retained */
		event_delete(EVENT_v2_DISCARD, &ike->sa); /* relying on retained */
		const struct state_event *lifetime_event = st_v2_lifetime_event(&ike->sa);
		if (PEXPECT(ike->sa.logger, lifetime_event != NULL)) {
			name_buf tb;
			ldbg(ike->sa.logger, ""PRI_SO" is retaining %s with is previously set timeout",
			     pri_so(ike->sa.st_serialno),
			     str_enum_long(&event_type_names, lifetime_event->ev_type, &tb));
		}
		break;
	}

	default:
		bad_case(transition->timeout_event);
	}

	/*
	 * If requested, send the new reply packet.
	 *
	 * XXX: On responder, should this schedule a timer that deletes the
	 * re-transmit buffer?
	 */
	switch (transition->recv_role) {
	case NO_MESSAGE: /* initiating a new exchange */
		send_recorded_v2_message(ike, transition->story,
					 ike->sa.st_v2_msgid_windows.initiator.outgoing_fragments);
		break;
	case MESSAGE_REQUEST: /* responding */
		send_recorded_v2_message(ike, transition->story,
					 ike->sa.st_v2_msgid_windows.responder.outgoing_fragments);
		break;
	case MESSAGE_RESPONSE: /* finishing exchange */
		break;
	default:
		bad_case(transition->recv_role);
	}

	/*
	 * Tell whack and logs of our progress.
	 */

        if (PBAD(ike->sa.logger, transition->llog_success == NULL)) {
		ldbg_success_ikev2(ike, md);
	} else {
		transition->llog_success(ike, md);
	}

	if (just_established) {
		release_whack(ike->sa.logger, HERE);
	} else if (transition->flags.release_whack) {
		release_whack(ike->sa.logger, HERE);
	}
}

void start_v2_transition(struct ike_sa *ike,
			 const struct v2_transition *next_transition,
			 struct msg_digest *md,
			 where_t where)
{
	set_v2_transition(&ike->sa, next_transition, where);
	v2_msgid_start(ike, NULL, md, HERE);
}

void start_v2_exchange(struct ike_sa *ike,
		       const struct v2_exchange *exchange,
		       where_t where)
{
	set_v2_transition(&ike->sa, exchange->initiate.transition, where);
	v2_msgid_start(ike, exchange, NULL, HERE);
}

stf_status next_v2_exchange(struct ike_sa *ike, struct msg_digest *md,
			    const struct v2_exchange *next_exchange,
			    where_t where)
{
	PEXPECT_WHERE(ike->sa.logger, where, v2_msg_role(md) == MESSAGE_RESPONSE);
	/* nothing ahead in the queue */
	PEXPECT_WHERE(ike->sa.logger, where, v2_msgid_request_pending(ike) == false);
	/* queue transition; it's at the front */
	v2_msgid_queue_exchange(ike, /*child*/NULL, next_exchange);
	/* complete current transition */
	return STF_OK;
}

/*
 * Dependent on RESULT, either complete, suspend, abandon, or abort
 * (delete state) the state transition started by the state-specific
 * state transition function.
 *
 * Since this is function is meaningless without a state, ST really
 * should be non-NULL.
 *
 * XXX: A broken exception is when responding to an IKE_SA_INIT
 * request - the state machine calls the state transition function
 * with no state (trusting that the transition function will do the
 * job, but that isn't always true).  The fix is to create the state
 * before calling the state transition function (like is done for the
 * CHILD_SA code).
 *
 * Since, when initiating an exchange there is no message, code can't
 * assume that (*MDP) is non-NULL.
 *
 * XXX: Some state transition functions switch state part way (see
 * AUTH child code) and then tunnel the new state to this code via
 * (*MDP)->st and some callers passing in (*MDP)->st).  The fix is for
 * the AUTH code to handle the CHILD SA as a nested or separate
 * transition.
 *
 * XXX: The state transition structure (microcode) is stored in (*MDP)
 * forcing that structure to be created.  The fix is to store the
 * state's transition in the state.  As a bonus this makes determining
 * if a state is busy really really easy - if there's a
 * state-transition then it must be.
 *
 * This routine does not free (*MDP) (using md_delref(mdp)).
 * However, when suspending a state transition, it will save it in ST
 * and zap (*MDP) so that the caller can't free it.  Hence, the caller
 * must be prepared for (*MDP) being set to NULL.
 *
 * XXX: At some point (*MDP) was being used for:
 *
 * - find st
 * - success_v2_state_transition(st, md);
 *   - for svm:
 *     - svm->next_state,
 *     - svm->flags & SMF2_SEND,
 *     - svm->timeout_event,
 *     -svm->flags, story
 *   - find from_state (st might be gone)
 *   - ikev2_update_msgid_counters(md);
 *   - ikev2_nat_change_port_lookup(md, st)
 * - !(md->hdr.isa_flags & ISAKMP_FLAGS_v2_MSG_R) to gate Notify payloads/exchanges [WRONG]
 * - find note for STF_INTERNAL_ERROR
 * - find note for STF_FAIL_v1N (might not be part of result (STF_FAIL_v1N+note))
 *
 * We don't use these but complete_v1_state_transition does:
 * - record md->event_already_set
 * - remember_received_packet(st, md);
 * - fragvid, dpd, nortel
 */

void complete_v2_state_transition(struct ike_sa *ike,
				  struct msg_digest *md,
				  stf_status result)
{
	if (!pexpect(ike != NULL)) {
		return;
	}

	const struct v2_transition *transition = ike->sa.st_v2_transition;
	if (!pexpect(transition != NULL)) {
		return;
	}

	/* statistics */
	pstat(stf_status, result);

	LDBGP_JAMBUF(DBG_BASE, ike->sa.logger, buf) {
		jam_so(buf, ike->sa.st_serialno);
		jam_string(buf, " complete_v2_state_transition() status ");
		jam_enum_long(buf, &stf_status_names, result);
		jam(buf, " transitioning from state %s to ", ike->sa.st_state->short_name);
		jam_v2_transition(buf, transition);
	}

	switch (result) {

	case STF_SKIP_COMPLETE_STATE_TRANSITION:
		/* should never get here */
		bad_case(result);

	case STF_SUSPEND:
		/*
		 * Code off-loading work should have scheduled a
		 * timeout.
		 */
		switch (ike->sa.st_ike_version) {
		case IKEv1:
			PEXPECT(ike->sa.logger, (ike->sa.st_v1_event != NULL &&
						 (ike->sa.st_v1_event->ev_type == EVENT_v1_CRYPTO_TIMEOUT)));
			break;
		case IKEv2:
			PEXPECT(ike->sa.logger, (ike->sa.st_v2_timeout_initiator_event != NULL ||
						 ike->sa.st_v2_timeout_responder_event != NULL ||
						 ike->sa.st_v2_timeout_response_event != NULL));
			break;
		}
		return;

	case STF_IGNORE:
		/*
		 * Logged earlier (where the decision to ignore
		 * occurred).
		 */
		v2_msgid_cancel(ike, md, HERE);
		return;

	case STF_OK:
		/* advance the state */
		success_v2_state_transition(ike, md, transition);
		return;

	case STF_INTERNAL_ERROR:
		llog_pexpect(ike->sa.logger, HERE,
			     "state transition function for %s had internal error",
			     ike->sa.st_state->name);
		release_pending_whacks(&ike->sa, "internal error");
		return;

	case STF_OK_RESPONDER_DELETE_IKE:
		/*
		 * Responder processing something that triggered a
		 * delete IKE family (but not for reasons that are
		 * fatal).
		 *
		 * For instance, a N(D(IKE)) request.
		 *
		 * XXX: should this zombify the IKE SA so that
		 * re-transmits have something that can respond.
		 */
		/* send the response */
		dbg_v2_msgid(ike, "finishing old exchange (STF_OK_RESPONDER_DELETE_IKE)");
		pexpect(transition->recv_role == MESSAGE_REQUEST);
		v2_msgid_finish(ike, md, HERE);
		send_recorded_v2_message(ike, "DELETE_IKE_FAMILY",
					 ike->sa.st_v2_msgid_windows.responder.outgoing_fragments);
		/* do the deed */
		on_delete(&ike->sa, skip_send_delete);
		terminate_ike_family(&ike, REASON_DELETED, HERE);
		pexpect(ike == NULL);
		return;

	case STF_OK_INITIATOR_DELETE_IKE:
		/*
		 * Initiator processing response, finish current
		 * exchange and then delete the IKE SA.
		 */
		dbg_v2_msgid(ike, "finishing old exchange (STF_OK_INITIATOR_DELETE_IKE)");
		pexpect(transition->recv_role == MESSAGE_RESPONSE);
		v2_msgid_finish(ike, md, HERE);
		/* do the deed */
		on_delete(&ike->sa, skip_send_delete);
		terminate_ike_family(&ike, REASON_DELETED, HERE);
		/* get out of here -- everything is invalid */
		pexpect(ike == NULL);
		return;

	case STF_OK_INITIATOR_SEND_DELETE_IKE:
		/*
		 * Initiator processing response, finish current
		 * exchange and then record'n'send a fire'n'forget
		 * delete.
		 *
		 * For instance, when the IKE_AUTH response's
		 * authentication fails the initiator needs to quickly
		 * send out a delete (this is IKEv2's documented
		 * violation to the don't respond to a response rule).
		 *
		 * XXX: this should instead jump to a new transition
		 * that performs a proper delete exchange.
		 */
		dbg_v2_msgid(ike, "finishing old exchange (STF_OK_INITIATOR_SEND_DELETE_IKE)");
		pexpect(transition->recv_role == MESSAGE_RESPONSE);
		v2_msgid_finish(ike, md, HERE);
		/* do the deed; record'n'send logs */
		record_n_send_n_log_v2_delete(ike, HERE);
		/* do the deed */
		terminate_ike_family(&ike, REASON_DELETED, HERE);
		/* get out of here -- everything is invalid */
		pexpect(ike == NULL);
		return;

	case STF_FATAL:
		llog_rc(RC_FATAL, ike->sa.logger,
			"encountered fatal error in state %s", ike->sa.st_state->name);
		switch (v2_msg_role(md)) {
		case MESSAGE_RESPONSE:
			dbg_v2_msgid(ike, "forcing a response received update (STF_FATAL)");
			v2_msgid_finish(ike, md, HERE);
			break;
		case MESSAGE_REQUEST:
			if (ike->sa.st_v2_msgid_windows.responder.outgoing_fragments != NULL) {
				dbg_v2_msgid(ike, "responding with recorded fatal message");
				v2_msgid_finish(ike, md, HERE);
				send_recorded_v2_message(ike, "STF_FATAL",
							 ike->sa.st_v2_msgid_windows.responder.outgoing_fragments);
			} else {
				llog_pexpect_v2_msgid(ike, "exchange zombie: no FATAL message response was recorded!?!");
			}
			break;
		case NO_MESSAGE:
			/*
			 * For instance, something really messed up
			 * while initiating an exchange.
			 */
			dbg_v2_msgid(ike, "no message yet fatal error?");
			break;
		}

		on_delete(&ike->sa, skip_send_delete);
		terminate_ike_family(&ike, REASON_DELETED, HERE);
		pexpect(ike == NULL);
		return;

	case STF_FAIL_v1N:
		break;
	}

	/* default */
	passert(result >= STF_FAIL_v1N);
	v2_notification_t notification = result - STF_FAIL_v1N;
	name_buf nb;
	llog_pexpect(ike->sa.logger, HERE,
		     "state transition '%s' failed with %s",
		     transition->story,
		     str_enum_long(&v2_notification_names, notification, &nb));
	on_delete(&ike->sa, skip_send_delete);
	terminate_ike_family(&ike, REASON_DELETED, HERE);
}

static void reinitiate_v2_ike_sa_init(const char *story, struct state *st, void *arg)
{
	stf_status (*resume)(struct ike_sa *ike) = arg;

	if (st == NULL) {
		ldbg(&global_logger, " lost state for %s", story);
		return;
	}

	struct ike_sa *ike = pexpect_ike_sa(st);
	if (ike == NULL) {
		/* already logged */
		return;
	}

	/*
	 * Need to wind back the Message ID counters so that the send
	 * code things it is creating Message 0.
	 */
	free_v2_message_queues(st);
	v2_msgid_init_ike(ike);

	/*
	 * Pretend to be running the initiate state transition.
	 */
	start_v2_exchange(ike, &v2_IKE_SA_INIT_exchange, HERE); /* first */

	/*
	 * Need to re-open TCP.
	 */
	if (ike->sa.st_iface_endpoint != NULL &&
	    ike->sa.st_iface_endpoint->io->protocol == &ip_protocol_tcp) {
		ldbg(ike->sa.logger, "TCP: freeing interface as "PRI_SO" is restarting",
		     pri_so(ike->sa.st_serialno));
		/* create new-from-old first; must delref; blocking call */
		struct iface_endpoint *p = connect_to_tcp_endpoint(ike->sa.st_iface_endpoint->ip_dev,
								   ike->sa.st_remote_endpoint,
								   ike->sa.logger);
		if (p == NULL) {
			/* already logged */
			complete_v2_state_transition(ike, NULL, STF_FATAL);
			return;
		}
		/* replace */
		iface_endpoint_delref(&ike->sa.st_iface_endpoint);
		ike->sa.st_iface_endpoint = p;
	}

	so_serial_t old_st = st->st_serialno;
	statetime_t start = statetime_start(st);
	stf_status e = resume(ike);
	if (e == STF_SKIP_COMPLETE_STATE_TRANSITION) {
		/*
		 * Danger! Processor did something dodgy like free ST!
		 *
		 * DO NOT USE ST; it is broken.
		 */
		ldbg(&global_logger, "processor '%s' for "PRI_SO" suppressed complete st_v2_transition",
		     story, pri_so(old_st));
	} else {
		complete_v2_state_transition(ike, NULL, e);
	}
	statetime_stop(&start, "processing: %s in %s()", story, __func__);
}

void schedule_reinitiate_v2_ike_sa_init(struct ike_sa *ike,
					stf_status (*resume)(struct ike_sa *ike))
{
	schedule_callback("reinitiating IKE_SA_INIT", deltatime(0),
			  ike->sa.st_serialno,
			  reinitiate_v2_ike_sa_init, resume);
}

bool v2_notification_fatal(v2_notification_t n)
{
	return (n == v2N_INVALID_SYNTAX ||
		n == v2N_AUTHENTICATION_FAILED ||
		n == v2N_UNSUPPORTED_CRITICAL_PAYLOAD);
}

bool already_has_larval_v2_child(struct ike_sa *ike, const struct connection *c)
{
	const lset_t pending_states = (LELEM(STATE_V2_NEW_CHILD_I1) |
				       LELEM(STATE_V2_NEW_CHILD_I0) |
				       LELEM(STATE_V2_NEW_CHILD_R0));

	struct state_filter sf = {
		.search = {
			.order = OLD2NEW,
			.verbose.logger = &global_logger,
			.where = HERE,
		},
		.ike_version = IKEv2,
		.ike_spis = &ike->sa.st_ike_spis,
		/* only children */
		.clonedfrom = ike->sa.st_serialno,
	};

	while (next_state(&sf)) {
		struct state *st = sf.st;

		/* larval child state? */
		if (!LHAS(pending_states, st->st_state->kind)) {
			continue;
		}
		/*
		 * not an instance, but a connection?
		 *
		 * XXX: what is this trying to do?
		 *
		 * The below skips all connections (templates and
		 * instances) except those that share their ancestry
		 * with the SA's connection.  The log message would
		 * suggest it is instead trying to find an existing
		 * larval state for the connection?
		 */
		if (!streq(st->st_connection->base_name, c->base_name)) {
			continue;
		}
		llog(RC_LOG, c->logger, "connection already has the pending Child SA negotiation "PRI_SO" using IKE SA "PRI_SO"",
		     pri_so(st->st_serialno), pri_so(ike->sa.st_serialno));
		return true;
	}

	return false;
}

bool accept_v2_notification(v2_notification_t n,
			    struct logger *logger,
			    struct msg_digest *md,
			    bool enabled)
{
	enum v2_pd pd = v2_pd_from_notification(n);
	if (md->pd[pd] != NULL) {
		if (enabled) {
			name_buf eb, rb;
			ldbg(logger, "accepted %s notification %s",
			     str_enum_short(&v2_notification_names, n, &eb),
			     str_enum_short(&message_role_names, v2_msg_role(md), &rb));
			return true;
		}
		if (v2_msg_role(md) == MESSAGE_RESPONSE) {
			name_buf eb;
			llog(RC_LOG, logger,
			     "unsolicited %s notification response ignored",
			     str_enum_short(&v2_notification_names, n, &eb));
		} else {
			name_buf eb;
			ldbg(logger, "%s notification request ignored",
			     str_enum_short(&v2_notification_names, n, &eb));
		}
		return false;
	}
	name_buf eb;
	ldbg(logger, "%s neither requested nor accepted",
	     str_enum_short(&v2_notification_names, n, &eb));
	return false;
}

void jam_v2_transition(struct jambuf *buf, const struct v2_transition *transition)
{
	if (transition == NULL) {
		jam_string(buf, "<null-transition>");
		return;
	}
	jam_string(buf, transition->to->short_name);
	jam_string(buf, " (");
	jam_enum_long(buf, &ikev2_exchange_names, transition->exchange);
	jam_string(buf, " ");
	jam_enum_long(buf, &message_role_names, transition->recv_role);
	jam_string(buf, ": ");
	jam_string(buf, transition->story);
	jam_string(buf, ")");
}

bool v2_ike_sa_can_initiate_exchange(const struct ike_sa *ike, const struct v2_exchange *exchange)
{
	const struct finite_state *state = ike->sa.st_state;
	ldbg(ike->sa.logger, "looking for exchange '%s' in state '%s'",
	     exchange->subplot, state->short_name);
	FOR_EACH_ELEMENT(f, exchange->initiate.from) {
		if (*f == state) {
			return true;
		}
	}
	return false;
}
