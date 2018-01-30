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

/*
 *
 ***************************************************************
 *                       NOTIFICATION_OUT Complete packet  *****
 ***************************************************************
 *
 */

static void send_v2_notification(struct state *pst,
				 v2_notification_t ntype,
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
	 * TBD when there is a child SA use that SPI in the notify payload.
	 * TBD support encrypted notifications payloads.
	 * TBD accept Critical bit as an argument. default is set.
	 * TBD accept exchange type as an arg, default is ISAKMP_v2_SA_INIT
	 * do we need to send a notify with empty data?
	 * do we need to support more Protocol ID? more than PROTO_ISAKMP
	 */

	{
		ipstr_buf b;

		libreswan_log("sending unencrypted notification %s to %s:%u",
			      enum_name(&ikev2_notify_names, ntype),
			      sensitive_ipstr(&pst->st_remoteaddr, &b),
			      pst->st_remoteport);
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
		switch (pst->st_state) {
		case STATE_PARENT_R2:
			hdr.isa_xchg = ISAKMP_v2_AUTH;
			break;
		default:
			/* default to old behaviour of hardcoding ISAKMP_v2_SA_INIT */
			hdr.isa_xchg = ISAKMP_v2_SA_INIT;
			break;
		}
		if (pst->st_reply_xchg != 0)
			hdr.isa_xchg = pst->st_reply_xchg; /* use received exchange type */

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

	close_output_pbs(&rbody);
	close_output_pbs(&reply_stream);

	/*
	 * The notification is piggybacked on the existing parent state.
	 * This notification is fire-and-forget (not a proper exchange,
	 * one with retrying).  So we need not preserve the packet we
	 * are sending.
	 */
	send_ike_msg_without_recording(pst, &reply_stream, "v2 notify");

	if (ntype < v2N_ERROR_ROOF)
		pstats(ikev2_sent_notifies_e, ntype);
}

void send_v2_notification_from_state(struct state *st,
				     v2_notification_t ntype,
				     chunk_t *data)
{
	send_v2_notification(st, ntype, st->st_icookie, st->st_rcookie,
			     data);
}

void send_v2_notification_from_md(struct msg_digest *md,
				  v2_notification_t ntype,
				  chunk_t *data)
{
	/*
	 * Note: send_notification_from_md and send_v2_notification_from_md
	 * share code (and bugs).  Any fix to one should be done to both.
	 *
	 * Create a fake state object to be able to use send_notification.
	 * This is somewhat dangerous: the fake state must not be deleted
	 * or have almost any other operation performed on it.
	 * Ditto for fake connection.
	 *
	 * ??? how can we be sure to have faked all salient fields correctly?
	 *
	 * Most details must be left blank (eg. pointers
	 * set to NULL).  struct initialization is good at this.
	 *
	 * We need to set [??? we don't -- is this still true?]:
	 *   st_connection->that.host_addr
	 *   st_connection->that.host_port
	 *   st_connection->interface
	 */
	struct connection fake_connection = {
		.interface = md->iface,
		.addr_family = addrtypeof(&md->sender),	/* for ikev2_record_fragments() */
	};

	struct state fake_state = {
		.st_serialno = SOS_NOBODY,
		.st_connection = &fake_connection,
		.st_reply_xchg = md->hdr.isa_xchg,
		.st_finite_state = finite_states[STATE_UNDEFINED],
	};

	passert(md != NULL);

	update_ike_endpoints(&fake_state, md);

	send_v2_notification(&fake_state, ntype,
			     md->hdr.isa_icookie, md->hdr.isa_rcookie, data);

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
