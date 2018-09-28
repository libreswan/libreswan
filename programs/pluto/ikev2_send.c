/* IKEv2 packet send routines, for Libreswan
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
 * Copyright (C) 2017 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
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
 */

#include "defs.h"

#include "send.h"
#include "ikev2_send.h"
#include "server.h"
#include "state.h"
#include "connections.h"
#include "lswlog.h"
#include "ike_alg.h"
#include "pluto_stats.h"
#include "demux.h"	/* for struct msg_digest */
#include "rnd.h"

bool record_and_send_v2_ike_msg(struct state *st, pb_stream *pbs,
				const char *what)
{
	record_outbound_ike_msg(st, pbs, what);
	return send_recorded_v2_ike_msg(st, what);
}

bool send_recorded_v2_ike_msg(struct state *st, const char *where)
{
	if (st->st_interface == NULL) {
		libreswan_log("Cannot send packet - interface vanished!");
		return false;
	} else if (st->st_v2_tfrags != NULL) {
		/* if a V2 packet needs fragmenting it would have already happened */
		passert(st->st_ikev2);
		passert(st->st_tpacket.ptr == NULL);
		unsigned nr_frags = 0;
		DBGF(DBG_CONTROL|DBG_RETRANSMITS,
		     "sending fragments ...");
		for (struct v2_ike_tfrag *frag = st->st_v2_tfrags;
		     frag != NULL; frag = frag->next) {
			if (!send_chunk_using_state(st, where, frag->cipher)) {
				DBGF(DBG_CONTROL|DBG_RETRANSMITS,
				     "send of fragment %u failed",
				     nr_frags);
				return false;
			}
			nr_frags++;

		}
		DBGF(DBG_CONTROL|DBG_RETRANSMITS,
		     "sent %u fragments", nr_frags);
		return true;
	} else {
		return send_chunk_using_state(st, where, st->st_tpacket);
	}
}

/*
 * Send a payload.
 */

bool ship_v2UNKNOWN(pb_stream *outs, const char *victim)
{
	libreswan_log("IMPAIR: adding an unknown payload of type %d to %s",
		      ikev2_unknown_payload_desc.pt, victim);
	struct ikev2_generic gen = {
		.isag_np = ISAKMP_NEXT_v2NONE,
		.isag_critical = build_ikev2_critical(IMPAIR(UNKNOWN_PAYLOAD_CRITICAL)),
	};
	pb_stream pbs = open_output_struct_pbs(outs, &gen, &ikev2_unknown_payload_desc);
	if (!pbs_ok(&pbs)) {
		return false;
	}
	close_output_pbs(&pbs);
	return true;
}

/*
 * Send the STRING out as a V2 Vendor payload.
 *
 * XXX: Perhaps someday STRING will be replaced by enum
 * known_vendorid.
 */
bool ship_v2V(pb_stream *outs, enum next_payload_types_ikev2 np,
	      const char *string)
{
	struct ikev2_generic gen = {
		.isag_np = np,
	};
	pb_stream pbs = open_output_struct_pbs(outs, &gen,
					       &ikev2_vendor_id_desc);
	if (!pbs_ok(&pbs)) {
		return false;
	}
	if (!out_raw(string, strlen(string), &pbs, string)) {
		return false;
	}
	close_output_pbs(&pbs);
	return true;
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
uint8_t build_ikev2_version(void)
{
	/* TODO: if bumping, we should also set the Version flag in the ISAKMP header */
	return ((IKEv2_MAJOR_VERSION + (IMPAIR(MAJOR_VERSION_BUMP) ? 1 : 0))
			<< ISA_MAJ_SHIFT) |
	       (IKEv2_MINOR_VERSION + (IMPAIR(MINOR_VERSION_BUMP) ? 1 : 0));
}

uint8_t build_ikev2_critical(bool impair)
{
	uint8_t octet = 0;
	if (impair) {
		/* flip the expected bit */
		libreswan_log("IMPAIR: setting (should be off) critical payload bit");
		octet = ISAKMP_PAYLOAD_CRITICAL;
	} else {
		octet = ISAKMP_PAYLOAD_NONCRITICAL;
	}
	if (IMPAIR(SEND_BOGUS_PAYLOAD_FLAG)) {
		libreswan_log("IMPAIR: adding bogus bit to critical octet");
		octet |= ISAKMP_PAYLOAD_LIBRESWAN_BOGUS;
	}
	return octet;
}

/*
 * ship_v2N: add notify payload to the rbody
 * (See also specialized versions ship_v2Nsp and ship_v2Ns.)
 *
 * - RFC 7296 3.10 "Notify Payload" says:
 *
 * o  Protocol ID (1 octet) - If this notification concerns an existing
 *    SA whose SPI is given in the SPI field, this field indicates the
 *    type of that SA.  For notifications concerning Child SAs, this
 *    field MUST contain either (2) to indicate AH or (3) to indicate
 *    ESP.  Of the notifications defined in this document, the SPI is
 *    included only with INVALID_SELECTORS, REKEY_SA, and
 *    CHILD_SA_NOT_FOUND.  If the SPI field is empty, this field MUST be
 *    sent as zero and MUST be ignored on receipt.
 *
 * o  SPI Size (1 octet) - Length in octets of the SPI as defined by the
 *    IPsec protocol ID or zero if no SPI is applicable.  For a
 *    notification concerning the IKE SA, the SPI Size MUST be zero and
 *    the field must be empty.
 */
bool ship_v2N(enum next_payload_types_ikev2 np,
	      uint8_t critical,
	      enum ikev2_sec_proto_id protoid,
	      const chunk_t *spi,
	      v2_notification_t type,
	      const chunk_t *n_data,
	      pb_stream *rbody)
{
	/* See RFC 5996 section 3.10 "Notify Payload" */
	passert(protoid == PROTO_v2_RESERVED || protoid == PROTO_v2_AH || protoid == PROTO_v2_ESP);
	passert((protoid == PROTO_v2_RESERVED) == (spi->len == 0));

	switch (type) {
	case v2N_INVALID_SELECTORS:
	case v2N_REKEY_SA:
	case v2N_CHILD_SA_NOT_FOUND:
		/* must have SPI. XXX: ??? this is checking protoid! */
		if (protoid == PROTO_v2_RESERVED) {
			DBGF(DBG_MASK, "XXX: type and protoid mismatch");
		}
		break;
	default:
		/* must not have SPI. XXX: ??? this is checking protoid! */
		if (protoid != PROTO_v2_RESERVED) {
			DBGF(DBG_MASK, "XXX: type and protoid mismatch");
		}
		break;
	}

	DBG(DBG_CONTROLMORE, DBG_log("Adding a v2N Payload"));

	struct ikev2_notify n = {
		.isan_np = np,
		.isan_critical = critical,
		.isan_protoid = protoid,
		.isan_spisize = spi->len,
		.isan_type = type,
	};
	pb_stream n_pbs;

	if (!out_struct(&n, &ikev2_notify_desc, rbody, &n_pbs)) {
		libreswan_log(
			"error initializing notify payload for notify message");
		return FALSE;
	}

	if (spi->len > 0) {
		if (!out_chunk(*spi, &n_pbs, "SPI")) {
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
 * ship_v2Nsp: partially parameterized shipv2N
 *
 * - critical: ISAKMP_PAYLOAD_NONCRITICAL
 * - protoid: IKEv2_SEC_PROTO_NONE
 * - spi: none
 * pass through: all params
 *
 * This case is common since
 *
 * - almost all notifications are non-critical
 * - only a specified few include protocol or SPI
 */

bool ship_v2Nsp(enum next_payload_types_ikev2 np,
		v2_notification_t type,
		const chunk_t *n_data,
		pb_stream *rbody)
{
	return ship_v2N(np, build_ikev2_critical(false),
			PROTO_v2_RESERVED, &empty_chunk, type, n_data, rbody);
}

/* ship_v2Ns: like ship_v2Nsp except n_data is &empty_chunk */

bool ship_v2Ns(enum next_payload_types_ikev2 np,
	      v2_notification_t type,
	      pb_stream *rbody)
{
	return ship_v2Nsp(np, type, &empty_chunk, rbody);
}

/*
 * Open an IKEv2 message.
 *
 * At least one of the IKE SA and/or MD must be specified.
 *
 * The opened PBS is put into next-payload back-patch mode so
 * containing payloads should not specify their payload-type.  It will
 * instead be taken from the payload struct descriptor.
 */
pb_stream open_v2_message(pb_stream *reply,
			  struct ike_sa *ike, struct msg_digest *md,
			  enum isakmp_xchg_types exchange_type)
{
	/* at least one, possibly both */
	passert(ike != NULL || md != NULL);

	struct isakmp_hdr hdr = {
		.isa_flags = IMPAIR(SEND_BOGUS_ISAKMP_FLAG) ? ISAKMP_FLAGS_RESERVED_BIT6 : LEMPTY,
		.isa_version = build_ikev2_version(),
		.isa_xchg = exchange_type,
		.isa_length = 0, /* filled in when PBS is closed */
		.isa_np = ISAKMP_NEXT_v2NONE, /* filled in when next payload is added */
	};

	/*
	 * I(Initiator) flag
	 *
	 * If there was no IKE SA then this must be the original
	 * responder (the only time that pluto constructs a packet
	 * with no state is when replying to an SA_INIT or AUTH
	 * request with an unencrypted response), else just use the
	 * IKE SA's role.
	 */
	if (ike != NULL) {
		switch (ike->sa.st_sa_role) {
		case SA_INITIATOR:
			hdr.isa_flags |= ISAKMP_FLAGS_v2_IKE_I;
			break;
		case SA_RESPONDER:
			break;
		default:
			bad_case(ike->sa.st_sa_role);
		}
	}

	/*
	 * R(Responder) flag
	 *
	 * If there's no MD, then this must be a new request -
	 * R(Responder) flag clear.
	 *
	 * If there is an MD, and it contains a message request, then
	 * this end must be sending a response - R(Responder) flag
	 * set.
	 *
	 * If there is an MD, and it contains a message response, then
	 * the caller is trying to respond to a response (or someone's
	 * been faking MDs), which is pretty messed up.
	 */
	if (md != NULL) {
		switch (md->message_role) {
		case MESSAGE_REQUEST:
			hdr.isa_flags |= ISAKMP_FLAGS_v2_MSG_R;
			break;
		case MESSAGE_RESPONSE:
			PEXPECT_LOG("trying to respond to a message response%s", "");
			return empty_pbs;
		default:
			bad_case(MESSAGE_RESPONSE);
		}
	}

	/*
	 * SPI (aka cookies).
	 */
	if (ike != NULL) {
		/*
		 * Note that when the original initiator sends the
		 * SA_INIT request, the still zero RCOOKIE will be
		 * copied.
		 */
		memcpy(hdr.isa_icookie, ike->sa.st_icookie, COOKIE_SIZE);
		memcpy(hdr.isa_rcookie, ike->sa.st_rcookie, COOKIE_SIZE);
	} else {
		/*
		 * Not that when responding to an SA_INIT with an
		 * error notification (hence no state), the copied
		 * RCOOKIE will (should be?).
		 */
		passert(md != NULL);
		memcpy(hdr.isa_icookie, md->hdr.isa_icookie, COOKIE_SIZE);
		memcpy(hdr.isa_rcookie, md->hdr.isa_rcookie, COOKIE_SIZE);
	}

	/*
	 * Message ID
	 *
	 * If there's a message digest (MD) (presumably containing a
	 * message request) then this must be a response - use the
	 * message digest's message ID.  A better choice should be
	 * .st_msgid_lastrecv (or .st_msgid_lastrecv+1), but it isn't
	 * clear if/when that value is updated.
	 *
	 * If it isn't a response then use the IKE SA's
	 * .st_msgid_nextuse.  The caller still needs to both
	 * increment .st_msgid_nextuse (can't do this until the packet
	 * is finished) and update .st_msgid (only caller knows if
	 * this is for the IKE SA or a CHILD SA).
	 */
	if (md != NULL) {
		hdr.isa_msgid = htonl(md->msgid_received);
	} else {
		passert(ike != NULL);
		hdr.isa_msgid = htonl(ike->sa.st_msgid_nextuse);
	}

	return open_output_struct_pbs(reply, &hdr, &isakmp_hdr_desc);
}

/*
 *
 ***************************************************************
 *                       NOTIFICATION_OUT Complete packet  *****
 ***************************************************************
 *
 */

void send_v2_notification_from_state(struct state *pst, struct msg_digest *md,
				     v2_notification_t ntype,
				     chunk_t *ndata)
{
	passert(md != NULL); /* always a reply */
	const char *const notify_name = enum_short_name(&ikev2_notify_names, ntype);

	enum isakmp_xchg_types exchange_type = md->hdr.isa_xchg;
	const char *const exchange_name = enum_short_name(&ikev2_exchange_names, exchange_type);

	ipstr_buf b;
	libreswan_log("responding to %s message (ID %u) from %s:%u with encrypted notification %s",
		      exchange_name, md->msgid_received,
		      sensitive_ipstr(&pst->st_remoteaddr, &b),
		      pst->st_remoteport,
		      notify_name);

	/*
	 * For encrypted messages, the EXCHANGE TYPE can't be SA_INIT.
	 */
	switch (exchange_type) {
	case ISAKMP_v2_SA_INIT:
		PEXPECT_LOG("exchange type %s invalid for encrypted notification",
			    exchange_name);
		return;
	default:
		break;
	}

	uint8_t buf[MIN_OUTPUT_UDP_SIZE];
	pb_stream reply = open_out_pbs("encrypted notification",
				       buf, sizeof(buf));

	pb_stream rbody = open_v2_message(&reply, ike_sa(pst), md,
					  exchange_type);
	if (!pbs_ok(&rbody)) {
		libreswan_log("error initializing hdr for encrypted notification");
		return;
	}

	struct v2sk_payload sk = open_v2sk_payload(&rbody, ike_sa(pst));
	if (!pbs_ok(&sk.pbs)) {
		return;
	}

	/* actual data */

	switch (ntype) {
	case v2N_INVALID_SELECTORS:	/* ??? we never actually generate this */
	case v2N_REKEY_SA:	/* never follows this path */
	case v2N_CHILD_SA_NOT_FOUND:
		DBGF(DBG_MASK, "notification %s needs SPI!", notify_name);
		/* ??? how can we figure out the protocol and SPI? */
		if (!ship_v2N(ISAKMP_NEXT_v2NONE,
			      build_ikev2_critical(false),
			      PROTO_v2_RESERVED, &empty_chunk,
			      ntype, ndata, &sk.pbs)) {
			return;
		}
		break;
	default:
		if (!ship_v2Nsp(ISAKMP_NEXT_v2NONE, ntype, ndata, &sk.pbs))
			return;
		break;
	}

	if (!close_v2sk_payload(&sk)) {
		return;
	}
	close_output_pbs(&rbody);
	close_output_pbs(&reply);

	stf_status ret = encrypt_v2sk_payload(&sk);
	if (ret != STF_OK) {
		libreswan_log("error encrypting notify message");
		return;
	}

	/*
	 * The notification is piggybacked on the existing parent
	 * state.  This notification is fire-and-forget (not a proper
	 * exchange, one with retrying).  So we need not preserve the
	 * packet we are sending.
	 */
	send_chunk_using_state(pst, "v2 notify", pbs_as_chunk(&reply));
	pstat(ikev2_sent_notifies_e, ntype);
}

void send_v2_notification_from_md(struct msg_digest *md,
				  v2_notification_t ntype,
				  chunk_t *ndata)
{
	const char *const notify_name = enum_short_name(&ikev2_notify_names, ntype);

	passert(md != NULL); /* always a response */
	enum isakmp_xchg_types exchange_type = md->hdr.isa_xchg;
	const char *const exchange_name = enum_short_name(&ikev2_exchange_names, exchange_type);

	ipstr_buf b;
	libreswan_log("responding to %s message (ID %u) from %s:%u with unencrypted notification %s",
		      exchange_name, md->msgid_received,
		      sensitive_ipstr(&md->sender, &b),
		      hportof(&md->sender),
		      notify_name);

	/*
	 * For unencrypted messages, the EXCHANGE TYPE can only be
	 * INIT or AUTH (if DH fails, AUTH gets an unencrypted
	 * response).
	 */
	switch (exchange_type) {
	case ISAKMP_v2_SA_INIT:
	case ISAKMP_v2_AUTH:
		break;
	default:
		PEXPECT_LOG("exchange type %s invalid for unencrypted notification",
			    exchange_name);
		return;
	}

	uint8_t buf[MIN_OUTPUT_UDP_SIZE];
	pb_stream reply = open_out_pbs("unencrypted notification",
				       buf, sizeof(buf));
	pb_stream rbody = open_v2_message(&reply, NULL, md, exchange_type);
	if (!pbs_ok(&rbody)) {
		PEXPECT_LOG("error building header for unencrypted %s %s notification with message ID %u",
			    exchange_name, notify_name, md->msgid_received);
		return;
	}

	/* build and add v2N payload to the packet */
	if (!ship_v2Nsp(ISAKMP_NEXT_v2NONE, ntype, ndata, &rbody)) {
		PEXPECT_LOG("error building unencrypted %s %s notification with message ID %u",
			    exchange_name, notify_name, md->msgid_received);
		return;
	}

	close_output_pbs(&rbody);
	close_output_pbs(&reply);

	/*
	 * The notification is piggybacked on the existing parent state.
	 * This notification is fire-and-forget (not a proper exchange,
	 * one with retrying).  So we need not preserve the packet we
	 * are sending.
	 */
	send_chunk("v2 notify", SOS_NOBODY, md->iface, md->sender,
		   pbs_as_chunk(&reply));

	pstat(ikev2_sent_notifies_e, ntype);
}

void send_v2_notification_invalid_ke(struct msg_digest *md,
				     const struct oakley_group_desc *group)
{
	DBG(DBG_CONTROL, {
		DBG_log("sending INVALID_KE back with %s(%d)",
			group->common.name, group->group);
	});
	/* convert group to a raw buffer */
	const uint16_t gr = htons(group->group);
	chunk_t nd;
	setchunk(nd, (void*)&gr, sizeof(gr));

	send_v2_notification_from_md(md, v2N_INVALID_KE_PAYLOAD, &nd);
}

/*
 * Send an Informational Exchange announcing a deletion.
 *
 * CURRENTLY SUPPRESSED:
 * If we fail to send the deletion, we just go ahead with deleting the state.
 * The code in delete_state would break if we actually did this.
 *
 * Deleting an IKE SA is a bigger deal than deleting an IPsec SA.
 */

void send_v2_delete(struct state *const st)
{
	struct ike_sa *ike = ike_sa(st);
	if (ike == NULL) {
		/* ike_sa() will have already complained loudly */
		return;
	}

	/* make sure HDR is at start of a clean buffer */
	uint8_t buf[MIN_OUTPUT_UDP_SIZE];
	pb_stream packet = open_out_pbs("informational exchange delete request",
					buf, sizeof(buf));
	pb_stream rbody = open_v2_message(&packet, ike, NULL,
					  ISAKMP_v2_INFORMATIONAL);
	if (!pbs_ok(&packet)) {
		return;
	}

	struct v2sk_payload sk = open_v2sk_payload(&rbody, ike);
	if (!pbs_ok(&sk.pbs)) {
		return;
	}

	{
		pb_stream del_pbs;
		struct ikev2_delete v2del_tmp;
		/*
		 * uint16_t i, j=0;
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
				&sk.pbs, &del_pbs))
			return;

		/* Emit values of spi to be sent to the peer */
		if (IS_CHILD_SA(st)) {
			if (!out_raw((u_char *)&st->st_esp.our_spi,
				     sizeof(ipsec_spi_t), &del_pbs,
				     "local spis"))
				return;
		}

		close_output_pbs(&del_pbs);
	}

	if (!close_v2sk_payload(&sk)) {
		return;
	}
	close_output_pbs(&rbody);
	close_output_pbs(&packet);

	stf_status ret = encrypt_v2sk_payload(&sk);
	if (ret != STF_OK) {
		libreswan_log("error encrypting notify message");
		return;
	}

	record_and_send_v2_ike_msg(st, &packet,
				   "packet for ikev2 delete informational");

	/* increase message ID for next delete message */
	/* ikev2_update_msgid_counters need an md */
	ike->sa.st_msgid_nextuse++;
	st->st_msgid = htonl(ike->sa.st_msgid_nextuse);
}

/*
 * Construct and send an informational request.
 *
 * XXX: This and send_v2_delete() should be merged.  However, there
 * are annoying differences.  For instance, send_v2_delete() updates
 * st->st_msgid but the below doesn't.
 */
stf_status send_v2_informational_request(const char *name,
					 struct state *st,
					 struct ike_sa *ike,
					 stf_status (*payloads)(struct state *st,
								pb_stream *pbs))
{
	/*
	 * Buffer in which to marshal our informational message.  We
	 * don't use reply_buffer/reply_stream because it might be in
	 * use.
	 */
	u_char buffer[MIN_OUTPUT_UDP_SIZE];	/* ??? large enough for any informational? */
	pb_stream packet = open_out_pbs(name, buffer, sizeof(buffer));
	if (!pbs_ok(&packet)) {
		return STF_INTERNAL_ERROR;
	}

	pb_stream message = open_v2_message(&packet, ike, NULL,
					    ISAKMP_v2_INFORMATIONAL);
	if (!pbs_ok(&message)) {
		return STF_INTERNAL_ERROR;
	}

	struct v2sk_payload sk = open_v2sk_payload(&message, ike);
	if (!pbs_ok(&sk.pbs)) {
		return STF_INTERNAL_ERROR;
	}

	if (payloads != NULL) {
		stf_status e = payloads(st, &sk.pbs);
		if (e != STF_OK) {
			return  e;
		}
	}

	if (!close_v2sk_payload(&sk)) {
		return STF_INTERNAL_ERROR;
	}
	close_output_pbs(&message);
	close_output_pbs(&packet);

	stf_status ret = encrypt_v2sk_payload(&sk);
	if (ret != STF_OK) {
		return ret;
	}

	/* cannot use ikev2_update_msgid_counters - no md here */
	/* But we know we are the initiator for thie exchange */
	ike->sa.st_msgid_nextuse += 1;

	ike->sa.st_pend_liveness = TRUE; /* we should only do this when dpd/liveness is active? */
	record_and_send_v2_ike_msg(st, &packet, name);

	return STF_OK;
}

struct v2sk_payload open_v2sk_payload(pb_stream *container,
				      struct ike_sa *ike)
{
	static const struct v2sk_payload empty_sk;
	struct v2sk_payload sk = {
		.ike = ike,
	};

	/* insert an Encryption payload header */

	struct ikev2_generic e = {
		.isag_length = 0, /* filled in later */
		.isag_critical = build_ikev2_critical(false),
	};
	if (!out_struct(&e, &ikev2_sk_desc, container, &sk.pbs)) {
		libreswan_log("error initializing SK header for encrypted %s message",
			      container->name);
		return empty_sk;
	}

	/* insert IV */

	sk.iv = sk.pbs.cur;
	passert(sk.pbs.cur <= sk.iv);
	if (!emit_wire_iv(&ike->sa, &sk.pbs)) {
		libreswan_log("error initializing IV for encrypted %s message",
			      container->name);
		return empty_sk;
	}

	/* save the start of cleartext proper */

	sk.cleartext = sk.pbs.cur;
	passert(sk.iv <= sk.cleartext);
	passert(sk.pbs.container->name == container->name);

	return sk;
}

bool close_v2sk_payload(struct v2sk_payload *sk)
{
	/* padding + pad-length */

	size_t padding;
	if (sk->ike->sa.st_oakley.ta_encrypt->pad_to_blocksize) {
		const size_t blocksize = sk->ike->sa.st_oakley.ta_encrypt->enc_blocksize;
		padding = pad_up(sk->pbs.cur - sk->cleartext, blocksize);
		if (padding == 0) {
			padding = blocksize;
		}
	} else {
		padding = 1;
	}
	DBG(DBG_EMITTING,
	    DBG_log("adding %zd bytes of padding (including 1 byte padding-length)",
		    padding));
	char b[MAX_CBC_BLOCK_SIZE];
	passert(sizeof(b) >= padding);
	for (unsigned i = 0; i < padding; i++) {
		b[i] = i;
	}
	if (!out_raw(b, padding, &sk->pbs, "padding and length")) {
		libreswan_log("error initializing padding for encrypted %s payload",
			      sk->pbs.container->name);
		return false;
	}

	/* integrity checksum data */

	sk->integrity = ikev2_authloc(&sk->ike->sa, &sk->pbs);
	passert(sk->cleartext <= sk->integrity);
	if (sk->integrity == NULL) {
		libreswan_log("error initializing integrity checksum for encrypted %s payload",
			      sk->pbs.container->name);
		return false;
	}

	/* close the SK payload */

	close_output_pbs(&sk->pbs);
	return true;
}

stf_status encrypt_v2sk_payload(struct v2sk_payload *sk)
{
	return ikev2_encrypt_msg(sk->ike, sk->pbs.container->start,
				 sk->iv, sk->cleartext,
				 sk->integrity);
}
