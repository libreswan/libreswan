/* show functions, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2005-2007 Michael Richardson
 * Copyright (C) 2006-2010 Bart Trojanowski
 * Copyright (C) 2008-2012 Paul Wouters
 * Copyright (C) 2008-2010 David McCullough.
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
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

#include "sysdep.h"
#include "constants.h"
#include "lswconf.h"
#include "lswfips.h"


#include "defs.h"
#include "log.h"
#include "server.h"
#include "state.h"
#include "pluto_stats.h"
#include "connections.h"
#include "kernel.h"
#include "virtual_ip.h"
#include "plutoalg.h"
#include "crypto.h"
#include "ikev1_db_ops.h"
#include "kernel_xfrm_interface.h"
#include "iface.h"
#include "show.h"
#ifdef USE_SECCOMP
#include "pluto_seccomp.h"
#endif

struct show {
	/*
	 * where to send the output
	 */
	struct logger *logger;
	/*
	 * Should the next output be preceded by a blank line?
	 */
	enum separation { NO_SEPARATOR = 1, HAD_OUTPUT, SEPARATE_NEXT_OUTPUT, } separator;
	/*
	 * Where to build the messages.
	 */
	char scratch_array[LOG_WIDTH];
	struct jambuf scratch_jambuf;
};

struct show *alloc_show(struct logger *logger)
{
	struct show s = {
		.separator = NO_SEPARATOR,
		.logger = logger,
	};
	return clone_thing(s, "on show");
}

static void blank_line(struct show *s)
{
	/* XXX: must not use s->jambuf */
	char blank_buf[sizeof(" "/*\0*/) + 1/*canary*/ + 1/*why-not*/];
	struct jambuf buf = ARRAY_AS_JAMBUF(blank_buf);
	jam_string(&buf, " ");
	jambuf_to_logger(&buf, s->logger, RC_COMMENT|WHACK_STREAM);
}

void free_show(struct show **sp)
{
	{
		struct show *s = *sp;
		switch (s->separator) {
		case NO_SEPARATOR:
		case HAD_OUTPUT:
			break;
		case SEPARATE_NEXT_OUTPUT:
			blank_line(s);
			break;
		default:
			bad_case(s->separator);
		}
	}
	pfree(*sp);
	*sp = NULL;
}

void show_separator(struct show *s)
{
	switch (s->separator) {
	case NO_SEPARATOR:
		break;
	case HAD_OUTPUT:
	case SEPARATE_NEXT_OUTPUT:
		s->separator = SEPARATE_NEXT_OUTPUT;
		break;
	default:
		bad_case(s->separator);
		break;
	}
}

void show_blank(struct show *s)
{
	s->separator = SEPARATE_NEXT_OUTPUT;
}

struct jambuf *show_jambuf(struct show *s)
{
	s->scratch_jambuf = ARRAY_AS_JAMBUF(s->scratch_array);
	return &s->scratch_jambuf;
}

struct logger *show_logger(struct show *s)
{
	return s->logger;
}

void jambuf_to_show(struct jambuf *buf, struct show *s, enum rc_type rc)
{
	switch (s->separator) {
	case NO_SEPARATOR:
	case HAD_OUTPUT:
		break;
	case SEPARATE_NEXT_OUTPUT:
		blank_line(s);
		break;
	default:
		bad_case(s->separator);
	}
	pexpect(rc == RC_RAW ||
		rc == RC_COMMENT ||
		rc == RC_INFORMATIONAL_TRAFFIC/*show_state_traffic()*/ ||
		rc == RC_UNKNOWN_NAME/*show_traffic_status()*/);
	jambuf_to_logger(buf, s->logger, rc|WHACK_STREAM);
	s->separator = HAD_OUTPUT;
}

static void show_rc_va_list(struct show *s, enum rc_type rc,
			    const char *message, va_list ap)
{
	struct jambuf *buf = show_jambuf(s);
	jam_va_list(buf, message, ap);
	jambuf_to_show(buf, s, rc);
}

void show_comment(struct show *s, const char *message, ...)
{
	va_list ap;
	va_start(ap, message);
	show_rc_va_list(s, RC_COMMENT, message, ap);
	va_end(ap);
}

void show_rc(struct show *s, enum rc_type rc, const char *message, ...)
{
	va_list ap;
	va_start(ap, message);
	show_rc_va_list(s, rc, message, ap);
	va_end(ap);
}

void show_raw(struct show *s, const char *message, ...)
{
	va_list ap;
	va_start(ap, message);
	show_rc_va_list(s, RC_RAW, message, ap);
	va_end(ap);
}

/*
 * We store runtime info for stats/status this way.
 * You may be able to do something similar using these hooks.
 */

struct log_conn_info {
	struct connection *conn;
	struct state *ignore;           /* ignore this state */

	/* best completed state of connection */

	enum {
		tun_down=0,
		tun_phase1,
		tun_phase1up,
		tun_phase15,
		tun_phase2,
		tun_up
	} tunnel;

	/* best uncompleted state info for each phase */

	enum {
		p1_none=0,
		p1_init,
		p1_encrypt,
		p1_auth,
		p1_up,
		p1_down
	} phase1;

	enum {
		p2_none=0,
		p2_neg,
		p2_up,
	} phase2;
};

/*
 * we need to make sure we do not saturate the stats daemon
 * so we track what we have told it in a long (triple)
 */
#define LOG_CONN_STATSVAL(lci) \
	((lci)->tunnel | ((lci)->phase1 << 4) | ((lci)->phase2 << 8))

static void connection_state(struct state *st, struct log_conn_info *lc)
{
	if (st == NULL || st == lc->ignore ||
	    st->st_connection == NULL || lc->conn == NULL)
		return;

	if (st->st_connection != lc->conn) {
		if (lc->conn->host_pair != st->st_connection->host_pair ||
		    !same_peer_ids(lc->conn, st->st_connection, NULL))
			return;
		/* phase1 is shared with another connection */
	}

	/* ignore undefined states (i.e. just deleted) */
	if (st->st_state->kind == STATE_UNDEFINED)
		return;

	if (IS_IKE_SA(st)) {
		if (lc->tunnel < tun_phase1)
			lc->tunnel = tun_phase1;
		if (IS_IKE_SA_ESTABLISHED(st) ||
		    IS_V1_ISAKMP_SA_ESTABLISHED(st)) {
			if (lc->tunnel < tun_phase1up)
				lc->tunnel = tun_phase1up;
			lc->phase1 = p1_up;
		} else {
			if (lc->phase1 < p1_init)
				lc->phase1 = p1_init;
#ifdef USE_IKEv1
/* PW: This seems an unintensional flaw of using ikev1 only checks ??? */
			if (IS_V1_ISAKMP_ENCRYPTED(st->st_state->kind) &&
			    lc->phase1 < p1_encrypt)
				lc->phase1 = p1_encrypt;
			if (IS_V1_ISAKMP_AUTHENTICATED(st->st_state) &&
			    lc->phase1 < p1_auth)
				lc->phase1 = p1_auth;
#endif
		}
	} else {
		lc->phase1 = p1_down;
	}

	/* only phase one shares across connections, so we can quit now */
	if (st->st_connection != lc->conn)
		return;

#ifdef USE_IKEv1
	if (IS_V1_PHASE15(st->st_state->kind)) {
		if (lc->tunnel < tun_phase15)
			lc->tunnel = tun_phase15;
	}
#endif

	if (IS_CHILD_SA(st)) {
		if (lc->tunnel < tun_phase2)
			lc->tunnel = tun_phase2;
		if (IS_IPSEC_SA_ESTABLISHED(st)) {
			if (lc->tunnel < tun_up)
				lc->tunnel = tun_up;
			lc->phase2 = p2_up;
		} else {
			if (lc->phase2 < p2_neg)
				lc->phase2 = p2_neg;
		}
	}
}

void binlog_state(struct state *st, enum state_kind new_state)
{
	if (pluto_stats_binary == NULL)
		return;

	if (st == NULL) {
		dbg("log_state() called without state");
		return;
	}

	struct connection *conn = st->st_connection;

	if (conn == NULL || st->st_connection->name == NULL) {
		dbg("log_state() called without st->st_connection or without st->st_connection->name");
		return;
	}

	dbg("log_state called for state update for connection %s ", conn->name);

	struct log_conn_info lc = {
		.conn = conn,
		.ignore = NULL,
		.tunnel = tun_down,
		.phase1 = p1_none,
		.phase2 = p2_none
	};

	{
		const struct finite_state *save_state = st->st_state;
		st->st_state = finite_states[new_state];
		struct state_filter sf = { .where = HERE, };
		while (next_state_new2old(&sf)) {
			connection_state(sf.st, &lc);
		}
		st->st_state = save_state;
	}

	const char *tun;

	switch (lc.tunnel) {
	case tun_phase1:	tun = "phase1";		break;
	case tun_phase1up:	tun = "phase1up";	break;
	case tun_phase15:	tun = "phase15";	break;
	case tun_phase2:	tun = "phase2";		break;
	case tun_up:		tun = "up";		break;
	case tun_down:		tun = "down";		break;
	default:		tun = "unchanged";	break;
	}

	const char *p1;

	switch (lc.phase1) {
	case p1_init:	p1 = "init";	break;
	case p1_encrypt:p1 = "encrypt";	break;
	case p1_auth:	p1 = "auth";	break;
	case p1_up:	p1 = "up";	break;
	case p1_down:	p1 = "down";	break;
	default:	p1 = "unchanged";break;
	}

	const char *p2;

	switch (lc.phase2) {
	case p2_neg:	p2 = "neg";	break;
	case p2_up:	p2 = "up";	break;
	default:	p2 = "down";	break;
	}
	dbg("log_state calling %s for connection %s with tunnel(%s) phase1(%s) phase2(%s)",
	    pluto_stats_binary, conn->name, tun, p1, p2);

	char buf[1024];

	snprintf(buf, sizeof(buf), "%s "
		 "%s ipsec-tunnel-%s if_stats /proc/net/dev/%s \\; "
		 "push ipsec-tunnel-%s tunnel %s \\; "
		 "push ipsec-tunnel-%s phase1 %s \\; "
		 "push ipsec-tunnel-%s phase2 %s",

		 pluto_stats_binary,
		 conn->interface ? "push" : "drop", conn->name,
		 (conn->xfrmi != NULL && conn->xfrmi->name != NULL) ? conn->xfrmi->name : "",
		 conn->name, tun,
		 conn->name, p1,
		 conn->name, p2);
	if (system(buf) == -1) {
		log_state(RC_LOG_SERIOUS, st, "statsbin= failed to send status update notification");
	}
	dbg("log_state for connection %s completed", conn->name);
}
