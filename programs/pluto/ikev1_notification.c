/*
 * IKEv1 send packets, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002,2013,2016-2017 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Ilia Sotnikov
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009 Seong-hun Lim
 * Copyright (C) 2009,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010-2019 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2019 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012-2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
 * Copyright (C) 2016-2024 Andrew Cagney
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

#include "ikev1_notification.h"

#include "monotime.h"

#include "defs.h"
#include "state.h"
#include "log.h"
#include "terminate.h"		/* for connection_delete_v1_state() ULGH */
#include "ikev1_hash.h"
#include "ikev1_message.h"
#include "ikev1_send.h"
#include "ikev1_msgid.h"
#include "pluto_stats.h"
#include "demux.h"
#include "send.h"

static monotime_t last_v1N_PAYLOAD_MALFORMED = MONOTIME_EPOCH;

/*
 * Send a notification to the peer. We could decide whether to send
 * the notification, based on the type and the destination, if we care
 * to.
 *
 * Note: msgid is in different order here from other calls :/
 */

static void send_v1_notification(struct logger *logger,
				 struct state *sndst,
				 v1_notification_t type,
				 struct ike_sa *isakmp_encrypt, /*possibly NULL*/
				 msgid_t msgid,
				 uint8_t *icookie,
				 uint8_t *rcookie,
				 uint8_t protoid)
{
	struct pbs_out r_hdr_pbs;
	const monotime_t now = mononow();

	switch (type) {
	case v1N_PAYLOAD_MALFORMED:
		/* only send one per second. */
		if (monotime_cmp(monotime_add(last_v1N_PAYLOAD_MALFORMED, deltatime(1)),
				 <, now))
			return;
		last_v1N_PAYLOAD_MALFORMED = now;

		/*
		 * If a state gets too many of these, delete it.
		 *
		 * Note that the fake state of send_notification_from_md
		 * will never trigger this (a Good Thing since it
		 * must not be deleted).
		 */
		sndst->hidden_variables.st_malformed_sent++;
		if (sndst->hidden_variables.st_malformed_sent > MAXIMUM_MALFORMED_NOTIFY) {
			llog(RC_LOG, logger, "too many (%d) malformed payloads. Deleting state",
			     sndst->hidden_variables.st_malformed_sent);
			connection_delete_v1_state(&sndst, HERE);
			/* note: no md->v1_st to clear */
			return;
		}

		if (sndst->st_v1_iv.len != 0) {
			LLOG_JAMBUF(RC_LOG, logger, buf) {
				jam(buf, "payload malformed.  IV: ");
				jam_dump_bytes(buf, sndst->st_v1_iv.ptr,
					       sndst->st_v1_iv.len);
			}
		}

		/*
		 * Do not encrypt notification, since #1 reason for
		 * malformed payload is that the keys are all messed
		 * up.
		 */
		isakmp_encrypt = NULL;
		break;

	case v1N_INVALID_FLAGS:
		/*
		 * Invalid flags usually includes encryption flags, so
		 * do not send encrypted.
		 */
		isakmp_encrypt = NULL;
		break;

	default:
		/* quiet GCC warning */
		break;
	}

	/* handled by caller? */
	if (!PEXPECT(logger, (isakmp_encrypt == NULL ||
			      IS_V1_ISAKMP_ENCRYPTED(isakmp_encrypt->sa.st_state->kind)))) {
		return;
	}

	{
		endpoint_buf b;
		enum_buf nb;
		llog(RC_LOG, logger,
		     "sending %snotification %s to %s",
		     (isakmp_encrypt != NULL ? "encrypted " : ""),
		     str_enum_short(&v1_notification_names, type, &nb),
		     str_endpoint(&sndst->st_remote_endpoint, &b));
	}

	uint8_t buffer[1024];	/* ??? large enough for any notification? */
	struct pbs_out pbs = open_pbs_out("notification msg", buffer, sizeof(buffer), logger);

	/* HDR* */
	{
		/* ??? "keep it around for TPM" */
		struct isakmp_hdr hdr = {
			.isa_version = (ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
					ISAKMP_MINOR_VERSION),
			.isa_xchg = ISAKMP_XCHG_INFO,
			.isa_msgid = msgid,
			.isa_flags = (isakmp_encrypt != NULL ? ISAKMP_FLAGS_v1_ENCRYPTION : 0),
		};
		if (icookie != NULL)
			memcpy(hdr.isa_ike_initiator_spi.bytes, icookie, COOKIE_SIZE);
		if (rcookie != NULL)
			memcpy(hdr.isa_ike_responder_spi.bytes, rcookie, COOKIE_SIZE);
		passert(out_struct(&hdr, &isakmp_hdr_desc, &pbs, &r_hdr_pbs));
	}

	/* HASH -- value to be filled later */
	struct v1_hash_fixup hash_fixup = {0};
	if (isakmp_encrypt != NULL) {
		if (!emit_v1_HASH(V1_HASH_1, "send notification",
				  IMPAIR_v1_NOTIFICATION_EXCHANGE,
				  &isakmp_encrypt->sa, &hash_fixup, &r_hdr_pbs)) {
			/* return STF_INTERNAL_ERROR; */
			return;
		}
	}

	/* Notification Payload */
	{
		struct pbs_out not_pbs;
		struct isakmp_notification isan = {
			.isan_doi = ISAKMP_DOI_IPSEC,
			.isan_type = type,
			.isan_spisize = 0,
			.isan_protoid = protoid,
		};

		if (!out_struct(&isan, &isakmp_notification_desc,
					&r_hdr_pbs, &not_pbs)) {
			llog(RC_LOG, logger,
				    "failed to build notification in send_notification");
			return;
		}

		close_output_pbs(&not_pbs);
	}

	if (isakmp_encrypt != NULL) {
		/* calculate hash value and patch into Hash Payload */
		fixup_v1_HASH(&isakmp_encrypt->sa, &hash_fixup, msgid, r_hdr_pbs.cur);

		/* Encrypt message (preserve st_iv) */
		/* ??? why not preserve st_new_iv? */
		struct crypt_mac old_iv;

		save_iv(&isakmp_encrypt->sa, old_iv);

		if (!IS_V1_ISAKMP_SA_ESTABLISHED(&isakmp_encrypt->sa)) {
			update_iv(&isakmp_encrypt->sa);
		}
		init_phase2_iv(&isakmp_encrypt->sa, &msgid);
		passert(close_and_encrypt_v1_message(&r_hdr_pbs, &isakmp_encrypt->sa));

		restore_iv(&isakmp_encrypt->sa, old_iv);
	} else {
		close_output_pbs(&r_hdr_pbs);
	}

	send_pbs_out_using_state(sndst, "notification packet", &pbs);
}

void send_v1_notification_from_state(struct state *st, enum state_kind from_state,
				     v1_notification_t type)
{
	passert(st != NULL);

	if (from_state == STATE_UNDEFINED)
		from_state = st->st_state->kind;

	if (IS_V1_QUICK(from_state)) {
		/*
		 * Don't use established_isakmp_sa_for_state().
		 *
		 * It returns NULL when ST isn't established and here
		 * ST is still larval.
		 *
		 * Don't require a viable ISAKMP (i.e., can start new
		 * quick mode exchanges), but does it really matter?
		 */
		struct ike_sa *isakmp = find_ike_sa_by_connection(st->st_connection,
								  V1_ISAKMP_SA_ESTABLISHED_STATES,
								  /*viable-parent*/false);
		if (isakmp == NULL) {
			llog(RC_LOG, st->logger,
			     "no ISAKMP SA for Quick mode notification");
			return;
		}
		if (!IS_V1_ISAKMP_ENCRYPTED(isakmp->sa.st_state->kind)) {
			/*passert?*/
			llog(RC_LOG, st->logger,
			     "ISAKMP SA for Quick mode notification is not encrypted");
			return;
		}
		send_v1_notification(st->logger, st, type,
				     isakmp, generate_msgid(&isakmp->sa),
				     st->st_ike_spis.initiator.bytes,
				     st->st_ike_spis.responder.bytes,
				     PROTO_ISAKMP);
		return;
	}

	if (IS_V1_ISAKMP_ENCRYPTED(from_state)) {
		send_v1_notification(st->logger, st, type,
				     pexpect_parent_sa(st),
				     generate_msgid(st),
				     st->st_ike_spis.initiator.bytes,
				     st->st_ike_spis.responder.bytes,
				     PROTO_ISAKMP);
		return;
	}

	/* no ISAKMP SA established - don't encrypt notification */
	send_v1_notification(st->logger, st, type,
			     /*no-ISAKMP*/NULL, v1_MAINMODE_MSGID,
			     st->st_ike_spis.initiator.bytes,
			     st->st_ike_spis.responder.bytes,
			     PROTO_ISAKMP);
}

void send_v1_notification_from_md(struct msg_digest *md, v1_notification_t type)
{
	pstats(ikev1_sent_notifies_e, type);

	struct pbs_out r_hdr_pbs;
	const monotime_t now = mononow();

	switch (type) {
	case v1N_PAYLOAD_MALFORMED:
		/* only send one per second. */
		if (monotime_cmp(monotime_add(last_v1N_PAYLOAD_MALFORMED, deltatime(1)),
				 <, now))
			return;
		last_v1N_PAYLOAD_MALFORMED = now;
		break;

	case v1N_INVALID_FLAGS:
		break;

	default:
		/* quiet GCC warning */
		break;
	}

	endpoint_buf b;
	enum_buf nb;
	llog(RC_LOG, md->logger,
	     "sending notification %s to %s",
	     str_enum_short(&v1_notification_names, type, &nb),
	     str_endpoint(&md->sender, &b));

	uint8_t buffer[1024];	/* ??? large enough for any notification? */
	struct pbs_out pbs = open_pbs_out("notification msg",
					  buffer, sizeof(buffer),
					  md->logger);

	/* HDR* */

	{
		/* ??? "keep it around for TPM" */
		struct isakmp_hdr hdr = {
			.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
				ISAKMP_MINOR_VERSION,
			.isa_xchg = ISAKMP_XCHG_INFO,
			.isa_msgid = 0,
			.isa_flags = 0,
			.isa_ike_initiator_spi = md->hdr.isa_ike_initiator_spi,
			.isa_ike_responder_spi = md->hdr.isa_ike_responder_spi,
		};
		passert(out_struct(&hdr, &isakmp_hdr_desc, &pbs, &r_hdr_pbs));
	}

	/* Notification Payload */

	{
		struct pbs_out not_pbs;
		struct isakmp_notification isan = {
			.isan_doi = ISAKMP_DOI_IPSEC,
			.isan_type = type,
			.isan_spisize = 0,
			.isan_protoid = PROTO_ISAKMP,
		};

		if (!out_struct(&isan, &isakmp_notification_desc,
					&r_hdr_pbs, &not_pbs)) {
			llog(RC_LOG, md->logger,
			     "failed to build notification in send_notification");
			return;
		}

		close_output_pbs(&not_pbs);
	}

	close_output_pbs(&r_hdr_pbs);
	send_pbs_out_using_md(md, "notification packet", &pbs);
}
