/*
 * sending packets, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002, 2013,2016 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
 * Copyright (C) 2016-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2019 Antony Antony <antony@phenome.org>
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

#include <unistd.h>	/* for usleep() */
#include <errno.h>

#include "defs.h"

#include "send.h"

#include "log.h"
#include "state.h"
#include "server.h"
#include "demux.h"
#include "pluto_stats.h"
#include "ip_endpoint.h"
#include "ip_sockaddr.h"
#include "ip_protocol.h"
#include "iface.h"
#include "impair_message.h"

/* send_ike_msg logic is broken into layers.
 * The rest of the system thinks it is simple.
 * We have three entrypoints that control options
 * for reporting write failure and actions on resending (fragment?):
 * send_ike_msg(), resend_ike_v1_msg(), and send_keepalive().
 *
 * The first two call send_or_resend_ike_msg().
 * That handles an IKE message.
 * It calls send_v1_frags() if the message needs to be fragmented.
 * Otherwise it calls send_packet() to send it in one gulp.
 *
 * send_v1_frags() breaks an IKE message into fragments and sends
 * them by send_packet().
 *
 * send_keepalive() calls send_packet() directly: uses a special
 * tiny packet; non-ESP marker does not apply; logging on write error
 * is suppressed.
 *
 * send_packet() sends a UDP packet, possibly prefixed by a non-ESP Marker
 * for NATT.  It accepts two chunks because this avoids double-copying.
 */

static bool send_chunks(const char *where, bool just_a_keepalive,
			so_serial_t serialno, /* can be SOS_NOBODY */
			const struct iface_endpoint *interface,
			ip_endpoint remote_endpoint,
			chunk_t a, chunk_t b,
			struct logger *logger)
{
	/* NOTE: on system with limited stack, buf could be made static */
	uint8_t buf[MAX_OUTPUT_UDP_SIZE];

	/* Each fragment, if we are doing NATT, needs a non-ESP_Marker prefix.
	 * natt_bonus is the size of the addition (0 if not needed).
	 */
	size_t natt_bonus;

	if (interface == NULL) {
		llog(RC_LOG, logger, "cannot send packet - interface vanished!");
		return false;
	}

	/* bandaid */
	if (a.ptr == NULL) {
		llog(RC_LOG, logger, "cannot send packet - a.ptr is NULL");
		return false;
	}

	/*
	 * XXX:
	 *
	 * Isn't it a bit late to be checking for this?  demux should
	 * have rejected a packet with a bogus remote address, and
	 * connection should have rejected a bogus address in a
	 * connection configuration?
	 *
	 * Code attempting to call this function with
	 * hsetportof(port,addr) where addr is invalid also get an
	 * expecation failed message.
	 */
	if (!endpoint_is_specified(remote_endpoint)) {
		/* not asserting, who knows what nonsense a user can generate */
		endpoint_buf b;
		llog(RC_LOG, logger,
			    "will not send packet to bogus address %s",
			    str_endpoint_sensitive(&remote_endpoint, &b));
		return false;
	}

	/*
	 * If we are doing NATT, so that the other end doesn't mistake
	 * this message for ESP, each message needs a non-ESP_Marker
	 * prefix.  natt_bonus is the size of the addition (0 if not
	 * needed).
	 */
	natt_bonus = !just_a_keepalive &&
				  interface->esp_encapsulation_enabled ?
				  NON_ESP_MARKER_SIZE : 0;

	const uint8_t *ptr;
	size_t len = natt_bonus + a.len + b.len;

	if (len > MAX_OUTPUT_UDP_SIZE) {
		/* XXX: UDP centric? */
		llog(RC_LOG_SERIOUS, logger,
			    "send_ike_msg(): really too big %zu bytes", len);
		return false;
	}

	if (len != a.len) {
		/* copying required */

		/* 1. non-ESP Marker (0x00 octets) */
		memset(buf, 0x00, natt_bonus);

		/* 2. chunk a */
		memcpy(buf + natt_bonus, a.ptr, a.len);

		/* 3. chunk b */
		memcpy(buf + natt_bonus + a.len, b.ptr, b.len);

		ptr = buf;
	} else {
		ptr = a.ptr;
	}

	if (DBGP(DBG_BASE)) {
		endpoint_buf lb;
		endpoint_buf rb;
		llog(DEBUG_STREAM, logger,
			    "sending %zu bytes for %s through %s from %s to %s using %s (for #%lu)",
			    len, where,
			    interface->ip_dev->id_rname,
			    str_endpoint(&interface->local_endpoint, &lb),
			    str_endpoint(&remote_endpoint, &rb),
			    interface->protocol->name,
			    serialno);
		DBG_dump(NULL, ptr, len);
	}

	if (!impair_outgoing_message(shunk2(ptr, len), logger)) {
		ssize_t wlen = interface->io->write_packet(interface, ptr, len,
							   &remote_endpoint, logger);
		if (wlen != (ssize_t)len) {
			if (!just_a_keepalive) {
				endpoint_buf lb;
				endpoint_buf rb;
				log_errno(logger, errno,
					  "send on %s from %s to %s using %s failed in %s",
					  interface->ip_dev->id_rname,
					  str_endpoint(&interface->local_endpoint, &lb),
					  str_endpoint_sensitive(&remote_endpoint, &rb),
					  interface->protocol->name,
					  where);
			}
			return false;
		}
		pstats_ike_out_bytes += len;
	}

	/*
	 * For testing: send a duplicate packet when this impair is
	 * enabled.
	 *
	 * XXX: sends the packet out using UDP?  Merge with above?
	 */
	if (impair.jacob_two_two) {
		/* sleep for half a second, and second another packet */
		usleep(500000);
		endpoint_buf b;
		endpoint_buf ib;
		llog(RC_LOG, logger,
			    "IMPAIR: JACOB 2-2: resending %zu bytes for %s through %s from %s to %s:",
			    len, where,
			    interface->ip_dev->id_rname,
			    str_endpoint(&interface->local_endpoint, &ib),
			    str_endpoint(&remote_endpoint, &b));

		ip_sockaddr remote_sa = sockaddr_from_endpoint(remote_endpoint);
		ssize_t wlen = sendto(interface->fd, ptr, len, 0, &remote_sa.sa.sa, remote_sa.len);
		if (wlen != (ssize_t)len) {
			if (!just_a_keepalive) {
				log_errno(logger, errno,
					  "sendto on %s to %s failed in %s",
					  interface->ip_dev->id_rname,
					  str_endpoint(&remote_endpoint, &b),
					  where);
			}
			return false;
		}
	}
	return true;
}

bool send_pbs_out_using_md(struct msg_digest *md, const char *where, struct pbs_out *packet)
{
	return send_chunks(where, false, SOS_NOBODY,
			   md->iface, md->sender,
			   same_out_pbs_as_chunk(packet), EMPTY_CHUNK,
			   md->md_logger);
}

bool send_chunks_using_state(struct state *st, const char *where,
			     chunk_t chunk_a, chunk_t chunk_b)
{
	return send_chunks(where, false, st->st_serialno,
			   st->st_interface, st->st_remote_endpoint,
			   chunk_a, chunk_b,
			   st->st_logger);
}

bool send_chunk_using_state(struct state *st, const char *where, chunk_t packet)
{
	return send_chunks_using_state(st, where, packet, EMPTY_CHUNK);
}

bool send_pbs_out_using_state(struct state *st, const char *where, struct pbs_out *pbs)
{
	return send_chunk_using_state(st, where, same_out_pbs_as_chunk(pbs));
}

/*
 * send keepalive is special in two ways:
 * We don't want send errors logged (too noisy).
 * We don't want the packet prefixed with a non-ESP Marker.
 */
bool send_keepalive_using_state(struct state *st, const char *where)
{
	static unsigned char ka_payload = 0xff;

	return send_chunks(where, true, st->st_serialno, st->st_interface,
			   st->st_remote_endpoint,
			   THING_AS_CHUNK(ka_payload), EMPTY_CHUNK,
			   st->st_logger);
}
