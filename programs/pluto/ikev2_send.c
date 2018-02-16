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
 * Copyright (C) 2017 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
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
		for (struct v2_ike_tfrag *frag = st->st_v2_tfrags;
		     frag != NULL; frag = frag->next) {
			if (!send_chunk_using_state(st, where, frag->cipher))
				return false;
		}
		return true;
	} else {
		return send_chunk_using_state(st, where, st->st_tpacket);
	}
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
int build_ikev2_version(void)
{
	/* TODO: if bumping, we should also set the Version flag in the ISAKMP header */
	return ((IKEv2_MAJOR_VERSION + (DBGP(IMPAIR_MAJOR_VERSION_BUMP) ? 1 : 0))
			<< ISA_MAJ_SHIFT) |
	       (IKEv2_MINOR_VERSION + (DBGP(IMPAIR_MINOR_VERSION_BUMP) ? 1 : 0));
}

/* add notify payload to the rbody */
bool ship_v2N(enum next_payload_types_ikev2 np,
	      u_int8_t critical,
	      enum ikev2_sec_proto_id protoid,
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

pb_stream open_v2_message(pb_stream *reply,
			  uint8_t *icookie, uint8_t *rcookie, /* aka SPI */
			  enum next_payload_types_ikev2 next_payload,
			  enum isakmp_xchg_types exchange_type,
			  lset_t flags, int message_id)
{
	struct isakmp_hdr hdr;

	zero(&hdr);	/* OK: no pointer fields */
	/* SPI: initial initiator will send 0 as responder's SPI */
	if (rcookie != NULL)
		memcpy(hdr.isa_rcookie, rcookie, COOKIE_SIZE);
	memcpy(hdr.isa_icookie, icookie, COOKIE_SIZE);

	hdr.isa_np = next_payload;
	hdr.isa_version = build_ikev2_version();
	hdr.isa_xchg = exchange_type;
	hdr.isa_flags = flags;
	if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
		hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
	}
	hdr.isa_msgid = htonl(message_id);
	hdr.isa_length = 0; /* filled in when PBS is closed */

	return open_output_struct_pbs(reply, &hdr, &isakmp_hdr_desc);
}

/*
 *
 ***************************************************************
 *                       NOTIFICATION_OUT Complete packet  *****
 ***************************************************************
 *
 */

void send_v2_notification_from_state(struct state *pst,
				     v2_notification_t ntype,
				     chunk_t *ndata)
{
	const char *const notify_name = enum_short_name(&ikev2_notify_names, ntype);

	/* XXX: while bogus, still less bogus the SA_INIT and message ID 0 */
	const enum isakmp_xchg_types exchange_type = ISAKMP_v2_AUTH;
	const char *const exchange_name = enum_short_name(&ikev2_exchange_names, exchange_type);
	const unsigned message_id = 1;

	ipstr_buf b;
	libreswan_log("responding to %s message (ID %u) from %s:%u with encrypted notification %s",
		      exchange_name, message_id,
		      sensitive_ipstr(&pst->st_remoteaddr, &b),
		      pst->st_remoteport,
		      notify_name);

	/*
	 * Since this is a notification, it must always be a response.
	 *
	 * XXX: What about IKE_I, can't assume this is the original
	 * responder.
	 */
	lset_t flags = ISAKMP_FLAGS_v2_MSG_R;

	pb_stream *reply = open_reply_pbs("encrypted notification msg");

	pb_stream rbody = open_v2_message(reply,
					  pst->st_icookie, pst->st_rcookie,
					  ISAKMP_NEXT_v2SK, exchange_type,
					  flags, message_id);
	if (!pbs_ok(&rbody)) {
		libreswan_log("error initializing hdr for notify message");
		return;
	}

	struct v2sk_stream sk = ikev2_open_encrypted_payload(&rbody, ISAKMP_NEXT_v2N,
							     ike_sa(pst), "notify");
	if (!pbs_ok(&sk.payload)) {
		return;
	}

	/* actual data */

	if (!ship_v2N(ISAKMP_NEXT_v2NONE,
		      DBGP(IMPAIR_SEND_BOGUS_PAYLOAD_FLAG) ?
		      (ISAKMP_PAYLOAD_NONCRITICAL | ISAKMP_PAYLOAD_LIBRESWAN_BOGUS) :
		      ISAKMP_PAYLOAD_NONCRITICAL,
		      IKEv2_SEC_PROTO_NONE, &empty_chunk, /* SPI */
		      ntype, ndata, &sk.payload)) {
		/*
		 * XXX: always omitting SPI but ESP/AH packets need
		 * it!?!
		 */
		return;
	}

	if (!ikev2_close_encrypted_payload(&sk)) {
		return;
	}
	close_output_pbs(&rbody);
	close_output_pbs(reply);

	stf_status ret = ikev2_encrypt_payload(&sk);
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
	send_chunk_using_state(pst, "v2 notify", pbs_as_chunk(reply));
	pstats(ikev2_sent_notifies_e, ntype);
}

void send_v2_notification_from_md(struct msg_digest *md,
				  v2_notification_t ntype,
				  chunk_t *ndata)
{
	const char *const notify_name = enum_short_name(&ikev2_notify_names, ntype);
	const unsigned message_id = md->msgid_received;
	enum isakmp_xchg_types exchange_type = md->hdr.isa_xchg;
	const char *const exchange_name = enum_short_name(&ikev2_exchange_names, exchange_type);

	ipstr_buf b;
	libreswan_log("responding to %s message (ID %u) from %s:%u with unencrypted %s notification",
		      exchange_name, message_id,
		      sensitive_ipstr(&md->sender, &b),
		      hportof(&md->sender),
		      notify_name);

	/*
	 * Since only the initial responder (where there may not yet
	 * be a state) is allowed to reply with an unencrypted
	 * notification, the MSG_R flag can be hardwired.
	 */
	lset_t flags = ISAKMP_FLAGS_v2_MSG_R;

	/*
	 * The MESSAGE ID can either be 0 (responding to SA_INIT) or 1
	 * (responding to AUTH with failed encryption).
	 */
	if (message_id > 1) {
		PEXPECT_LOG("message ID %u invalid for un-encrypted notification",
			    message_id);
		return;
	}

	/*
	 * The EXCHANGE TYPE can either be INIT or AUTH.
	 */
	switch (exchange_type) {
	case ISAKMP_v2_SA_INIT:
	case ISAKMP_v2_AUTH:
		break;
	default:
		PEXPECT_LOG("exchange type %s invalid for un-encrypted notification",
			    exchange_name);
		return;
	}

	pb_stream *reply = open_reply_pbs("unencrypted notification");
	pb_stream rbody = open_v2_message(reply,
					  md->hdr.isa_icookie,
					  md->hdr.isa_rcookie,
					  ISAKMP_NEXT_v2N,
					  exchange_type,
					  flags,
					  message_id);
	if (!pbs_ok(&rbody)) {
		PEXPECT_LOG("error building header for unencrypted %s %s notification with message ID %u",
			    exchange_name, notify_name, message_id);
		return;
	}

	/* build and add v2N payload to the packet */
	if (!ship_v2N(ISAKMP_NEXT_v2NONE,
		      DBGP(IMPAIR_SEND_BOGUS_PAYLOAD_FLAG) ?
		      (ISAKMP_PAYLOAD_NONCRITICAL | ISAKMP_PAYLOAD_LIBRESWAN_BOGUS) :
		      ISAKMP_PAYLOAD_NONCRITICAL,
		      IKEv2_SEC_PROTO_NONE, &empty_chunk, /* SPI */
		      ntype, ndata, &rbody)) {
		PEXPECT_LOG("error building unencrypted %s %s notification with message ID %u",
			    exchange_name, notify_name, message_id);
		return;
	}

	close_output_pbs(&rbody);
	close_output_pbs(reply);

	/*
	 * The notification is piggybacked on the existing parent state.
	 * This notification is fire-and-forget (not a proper exchange,
	 * one with retrying).  So we need not preserve the packet we
	 * are sending.
	 */
	send_chunk("v2 notify", SOS_NOBODY, md->iface, md->sender,
		   pbs_as_chunk(reply));

	pstats(ikev2_sent_notifies_e, ntype);
}

void send_v2_notification_invalid_ke(struct msg_digest *md,
				     const struct oakley_group_desc *group)
{
	DBG(DBG_CONTROL, {
		DBG_log("sending INVALID_KE back with %s(%d)",
			group->common.name, group->group);
	});
	/* convert group to a raw buffer */
	const u_int16_t gr = htons(group->group);
	chunk_t nd;
	setchunk(nd, (void*)&gr, sizeof(gr));

	send_v2_notification_from_md(md, v2N_INVALID_KE_PAYLOAD, &nd);
}
