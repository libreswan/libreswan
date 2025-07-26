/* IKEv2 packet send routines, for Libreswan
 *
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012-2017 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Sahana Prasad <sahana.prasad07@gmail.com>
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
 */

#include "defs.h"

#include "log.h"
#include "send.h"
#include "ikev2_send.h"
#include "ikev2_message.h"
#include "server.h"
#include "state.h"
#include "connections.h"
#include "ike_alg.h"
#include "pluto_stats.h"
#include "demux.h"	/* for struct msg_digest */
#include "rnd.h"
#include "kernel.h"	/* for get_my_cpi() */
#include "log_limiter.h"
#include "ikev2_notification.h"

#ifdef USE_XFRM_INTERFACE
#include "kernel_xfrm_interface.h"	/* for set_ike_mark_out() */
#endif

bool send_recorded_v2_message(struct ike_sa *ike,
			      const char *where,
			      struct v2_outgoing_fragment *frags)
{
	if (ike->sa.st_iface_endpoint == NULL) {
		llog_sa(RC_LOG, ike, "cannot send packet - interface vanished!");
		return false;
	}

	if (frags == NULL) {
		llog_sa(RC_LOG, ike, "no %s message to send", where);
		return false;
	}

#ifdef USE_XFRM_INTERFACE
	set_ike_mark_out(ike->sa.st_connection, &ike->sa.st_remote_endpoint,
			 ike->sa.logger);
#endif

	unsigned nr_frags = 0;
	for (struct v2_outgoing_fragment *frag = frags;
	     frag != NULL; frag = frag->next) {
		nr_frags++;
		if (!send_hunk_using_state(&ike->sa, where, *frag)) {
			ldbg(ike->sa.logger, "send of %s fragment %u failed", where, nr_frags);
			return false;
		}
	}
	ldbg(ike->sa.logger, "sent %u messages", nr_frags);
	return true;
}

void record_v2_outgoing_fragment(shunk_t fragment,
				 struct v2_outgoing_fragment **fragments,
				 struct logger *logger)
{
	PEXPECT(logger, (*fragments) == NULL);
	(*fragments) = overalloc_thing(struct v2_outgoing_fragment, fragment.len);
	ldbg_alloc(logger, "fragments", (*fragments), HERE);
	(*fragments)->len = fragment.len;
	memcpy((*fragments)->ptr/*array*/, fragment.ptr, fragment.len);
}

void record_v2_message(shunk_t message, struct v2_outgoing_fragment **fragments,
		       struct logger *logger)
{
	free_v2_outgoing_fragments(fragments, logger);
	record_v2_outgoing_fragment(message, fragments, logger);
}

/*
 * Send a payload.
 */

bool emit_v2UNKNOWN(const char *victim,
		    enum ikev2_exchange exchange_type,
		    const struct impair_unsigned *impairment,
		    struct pbs_out *outs)
{
	if (impairment->value != exchange_type) {
		/* successfully did nothing */
		return true;
	}

	name_buf xb;
	llog(RC_LOG, outs->logger,
	     "IMPAIR: adding an unknown%s payload of type %d to %s %s message",
	     impair.unknown_v2_payload_critical ? " critical" : "",
	     ikev2_unknown_payload_desc.pt,
	     victim,
	     str_enum_short(&ikev2_exchange_names, exchange_type, &xb));
	struct ikev2_generic gen = {
		.isag_critical = build_ikev2_critical(impair.unknown_v2_payload_critical, outs->logger),
	};
	struct pbs_out pbs;
	if (!pbs_out_struct(outs, gen, &ikev2_unknown_payload_desc, &pbs)) {
		/* already logged */
		return false; /*fatal*/
	}
	close_pbs_out(&pbs);
	return true;
}

bool send_v2_response_from_md(struct msg_digest *md, const char *what,
			      emit_v2_response_fn *emit_v2_response,
			      struct emit_v2_response_context *context)
{
	PASSERT(md->logger, md != NULL); /* always a response */

	enum ikev2_exchange exchange = md->hdr.isa_xchg;

	/*
	 * Normally an unencrypted response is only valid for
	 * IKE_SA_INIT or IKE_AUTH (when DH fails).  However "1.5.
	 * Informational Messages outside of an IKE SA" says to
	 * respond to other crud using the initiator's exchange type
	 * and Message ID and an unencrypted response.
	 */
	switch (exchange) {
	case ISAKMP_v2_IKE_SA_INIT:
	case ISAKMP_v2_IKE_SESSION_RESUME:
	case ISAKMP_v2_IKE_AUTH:
		break;
	default:
	{
		name_buf eb;
		ldbg(md->logger, "normally exchange type %s is encrypted",
		     str_enum_short(&ikev2_exchange_names, exchange, &eb));
		break;
	}
	}

	uint8_t buf[MIN_OUTPUT_UDP_SIZE];
	struct v2_message response;
	if (!open_v2_message(what, NULL/*no-IKE*/, md->logger, md/*response*/,
			     exchange, buf, sizeof(buf),
			     &response, UNENCRYPTED_PAYLOAD)) {
		name_buf eb;
		llog_pexpect(md->logger, HERE,
			     "error emitting header of unencrypted %s %s response with Message ID %u",
			     str_enum_short(&ikev2_exchange_names, exchange, &eb),
			     what, md->hdr.isa_msgid);
		return false;
	}

	if (!emit_v2_response(response.pbs, context)) {
		name_buf eb;
		llog_pexpect(md->logger, HERE,
			     "error emitting body of unencrypted %s %s response with message ID %u",
			     str_enum_short(&ikev2_exchange_names, exchange, &eb),
			     what, md->hdr.isa_msgid);
		return false;
	}

	close_v2_message(&response);

	/*
	 * This notification is fire-and-forget (not a proper
	 * exchange, one with retrying) so it is not saved.
	 */
	send_pbs_out_using_md(md, what, &response.message);
	return true;
}

void free_v2_outgoing_fragments(struct v2_outgoing_fragment **frags,
				struct logger *logger)
{
	if (*frags != NULL) {
		struct v2_outgoing_fragment *frag = *frags;
		do {
			struct v2_outgoing_fragment *next = frag->next;
			ldbg_free(logger, "frags", frag, HERE);
			pfree(frag);
			frag = next;
		} while (frag != NULL);
		*frags = NULL;
	}
}

void free_v2_incoming_fragments(struct v2_incoming_fragments **frags)
{
	if (*frags != NULL) {
		for (unsigned i = 0; i < elemsof((*frags)->frags); i++) {
			struct v2_incoming_fragment *frag = &(*frags)->frags[i];
			free_chunk_content(&frag->text);
		}
		md_delref(&(*frags)->md);
		pfree(*frags);
		*frags = NULL;
	}
}

void free_v2_message_queues(struct state *st)
{
	FOR_EACH_THING(window, &st->st_v2_msgid_windows.initiator, &st->st_v2_msgid_windows.responder) {
		free_v2_incoming_fragments(&window->incoming_fragments);
		free_v2_outgoing_fragments(&window->outgoing_fragments, st->logger);
	}
}
