/* whack initiate, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001,2013-2016 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2011 Mika Ilmaranta <ilmis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2014-2020 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2014-2017 Antony Antony <antony@phenome.org>
 * Copyright (C) 2019-2023 Andrew Cagney <cagney@gnu.org>
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

#include "whack_initiate.h"

#include "whack.h"

#include "defs.h"
#include "server.h"		/* for listening; */
#include "log.h"
#include "show.h"
#include "visit_connection.h"
#include "connections.h"
#include "initiate.h"
#include "kernel.h"		/* for struct kernel_acquire [oppo] */
#include "acquire.h"		/* for initiate_ondemand() [oppo] */

static unsigned whack_initiate_connection(const struct whack_message *m,
					  struct show *s,
					  struct connection *c)
{
	struct logger *logger = show_logger(s);
	switch (c->local->kind) {
	case CK_TEMPLATE:
	case CK_LABELED_TEMPLATE:
	case CK_PERMANENT:
		/* abuse bool; for connection counts */
		return initiate_connection(c,
					   m->remote_host,
					   m->whack_async/*background*/,
					   logger);
	case CK_LABELED_PARENT:
	case CK_LABELED_CHILD:
	case CK_GROUP:
	case CK_INSTANCE:
		connection_attach(c, logger);
		llog(RC_LOG, c->logger, "cannot initiate");
		connection_detach(c, logger);
		return 0; /* the connection doesn't count */
	case CK_INVALID:
		break;
	}
	bad_enum(show_logger(s), &connection_kind_names, c->local->kind);
}

void whack_initiate(const struct whack_message *m, struct show *s)
{
	struct logger *logger = show_logger(s);

	if (!listening) {
		whack_log(RC_DEAF, s,
			  "need --listen before --initiate");
		return;
	}

	if (m->name == NULL) {
		/* leave bread crumb */
		llog(RC_FATAL, logger,
		     "received command to initiate connection, but did not receive the connection name - ignored");
		return;
	}

	/*
	 * Initiate alias connections OLD2NEW so that they start in
	 * the same order that they were generated.
	 */
	visit_root_connection(m, s, whack_initiate_connection,
			      /*alias_order*/OLD2NEW,
			      (struct each) {
				      .future_tense = "initiating",
				      .past_tense = "initiating",
				      .log_unknown_name = true,
			      });
}

void whack_acquire(const struct whack_message *wm, struct show *s)
{
	struct logger *logger = show_logger(s);

	if (!listening) {
		whack_log(RC_DEAF, s,
			  "need --listen before opportunistic initiation");
		return;
	}

	const struct whack_acquire *wa = &wm->whack.acquire;

	const struct ip_protocol *protocol = protocol_from_ipproto(wa->ipproto);
	ip_packet packet = packet_from_raw(HERE,
					   address_info(wa->local.address),
					   &wa->local.address.bytes,
					   &wa->remote.address.bytes,
					   protocol,
					   wa->local.port,
					   wa->remote.port);

	struct kernel_acquire b = {
		.packet = packet,
		.by_acquire = false,
		.logger = logger, /*on-stack*/
		.background = wm->whack_async,
		.sec_label = null_shunk,
	};

	initiate_ondemand(&b);
}
