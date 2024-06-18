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
#include "fips_mode.h"


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
	struct logjam logjam;
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
	jambuf_to_logger(&buf, s->logger, RC_LOG|WHACK_STREAM);
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

struct jambuf *show_jambuf(struct show *s, enum rc_type rc)
{
	pexpect(rc == RC_LOG ||
		rc == RC_UNKNOWN_NAME/*show_traffic_status()*/);
	return jambuf_from_logjam(&s->logjam, s->logger,
				  /*pluto_exit_code*/0,
				  /*where*/NULL,
				  WHACK_STREAM|rc|NO_PREFIX);
}

struct logger *show_logger(struct show *s)
{
	return s->logger;
}

void show_to_logger(struct show *s)
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
	logjam_to_logger(&s->logjam);
	s->separator = HAD_OUTPUT;
}

static void show_rc_va_list(struct show *s, enum rc_type rc,
			    const char *message, va_list ap)
{
	struct jambuf *buf = show_jambuf(s, rc);
	jam_va_list(buf, message, ap);
	show_to_logger(s);
}

void show(struct show *s, const char *message, ...)
{
	va_list ap;
	va_start(ap, message);
	show_rc_va_list(s, RC_LOG, message, ap);
	va_end(ap);
}

void whack_log(enum rc_type rc, struct show *s, const char *message, ...)
{
	va_list ap;
	va_start(ap, message);
	show_rc_va_list(s, rc, message, ap);
	va_end(ap);
}
