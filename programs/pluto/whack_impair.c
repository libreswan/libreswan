/* whack impair routines, for libreswan
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

#include "defs.h"
#include "whack_impair.h"
#include "log.h"
#include "show.h"
#include "connections.h"
#include "server.h"		/* for call_global_event_inline() */
#include "timer.h"		/* for call_state_event_inline() */
#include "ikev2_liveness.h"	/* for submit_v2_liveness_exchange() */
#include "send.h"		/* for send_keep_alive_using_state() */
#include "impair_message.h"
#include "connection_event.h"

static struct state *find_impaired_state(so_serial_t so, struct logger *logger)
{
	struct state *st = state_by_serialno(so);
	if (st == NULL) {
		llog(RC_LOG, logger, "state #%lu not found", so);
		return NULL;
	}
	return st;
}

static struct connection *find_impaired_connection(co_serial_t co,
						   struct logger *logger)
{
	struct connection *c = connection_by_serialno(co);
	if (c == NULL) {
		llog(RC_LOG, logger, "connection "PRI_CO" not found", co);
		return NULL;
	}
	return c;
}

static struct logger *merge_loggers(struct logger *o_logger,
				   bool background,
				   struct logger *g_logger)
{
	/*
	 * Create a logger that looks like the object; but also has
	 * whack attached.
	 */
	struct logger *logger = clone_logger(o_logger, HERE);
	whack_attach(logger, g_logger);
	if (!background) {
		whack_attach(o_logger, g_logger);
	}
	return logger;
}

static void whack_impair_action(enum impair_action impairment_action,
				unsigned impairment_param,
				bool whack_enable,
				unsigned whack_value,
				bool detach_whack,
				struct logger *logger)
{
	switch (impairment_action) {
	case CALL_IMPAIR_UPDATE:
		/* err... */
		break;
	case CALL_GLOBAL_EVENT_HANDLER:
		whack_impair_call_global_event_handler(whack_value, logger);
		break;
	case CALL_STATE_EVENT_HANDLER:
	{
		struct state *st = find_impaired_state(whack_value, logger);
		if (st == NULL) {
			/* already logged */
			return;
		}
		/* will log */
		struct logger *loggers = merge_loggers(st->logger, detach_whack, logger);
		enum event_type event = impairment_param;
		whack_impair_call_state_event_handler(loggers, st, event, detach_whack);
		free_logger(&loggers, HERE);
		break;
	}
	case CALL_CONNECTION_EVENT_HANDLER:
	{
		struct connection *c = find_impaired_connection(whack_value, logger);
		if (c == NULL) {
			/* already logged */
			return;
		}
		c = connection_addref(c, logger); /*must-delref*/
		/* will log */
		struct logger *loggers = merge_loggers(c->logger, detach_whack, logger);
		enum connection_event_kind event_kind = impairment_param;
		whack_impair_call_connection_event_handler(c, event_kind, loggers);
		free_logger(&loggers, HERE);
		/* release whack, possibly attached to C by
		 * merge_loggers */
		connection_detach(c, logger);
		connection_delref(&c, logger);
		break;
	}
	case CALL_INITIATE_v2_LIVENESS:
	{
		struct state *st = find_impaired_state(whack_value, logger);
		if (st == NULL) {
			/* already logged */
			return;
		}
		/* will log */
		struct ike_sa *ike = ike_sa(st, HERE);
		if (ike == NULL) {
			/* already logged */
			return;
		}
		struct logger *loggers = merge_loggers(ike->sa.logger, detach_whack, logger);
		llog(RC_LOG, loggers, "IMPAIR: initiating liveness");
		submit_v2_liveness_exchange(ike, st->st_serialno);
		free_logger(&loggers, HERE);
		break;
	}
	case CALL_SEND_KEEPALIVE:
	{
		struct state *st = find_impaired_state(whack_value, logger);
		if (st == NULL) {
			/* already logged */
			return;
		}
		/* will log */
		struct logger *loggers = merge_loggers(st->logger,
						       true/*detach_whack*/, logger);
		llog(RC_LOG, loggers, "IMPAIR: sending keepalive");
		send_keepalive_using_state(st, "inject keep-alive");
		free_logger(&loggers, HERE);
		break;
	}
	case CALL_IMPAIR_MESSAGE_DRIP:
	case CALL_IMPAIR_MESSAGE_DROP:
	case CALL_IMPAIR_MESSAGE_BLOCK:
	case CALL_IMPAIR_MESSAGE_DUPLICATE:
	case CALL_IMPAIR_MESSAGE_REPLAY:
		add_message_impairment(impairment_action,
				       (enum impair_message_direction)impairment_param,
				       whack_enable, whack_value, logger);
		break;
	}
}

void whack_impair(const struct whack_message *m, struct show *s)
{
	struct logger *logger = show_logger(s);
	if (m->name == NULL) {
		FOR_EACH_ITEM(impairment, &m->impairments) {
			/* ??? what should we do with return value? */
			process_impair(impairment,
				       whack_impair_action,
				       m->whack_async/*detach_whack*/,
				       logger);
		}
	} else if (m->whack_command != WHACK_ADD) {
		ldbg(logger, "per-connection impairment not implemented");
	}
}
