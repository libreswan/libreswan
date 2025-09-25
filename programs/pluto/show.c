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
#include "iface.h"
#include "show_ops.h"
#include "show.h"

#define MAX_SHOW_STATES 5	/* maximum depth of a structure */

enum show_state {
	SHOW_NONE = 0,
	SHOW_OBJECT,
	SHOW_ARRAY,
	SHOW_MEMBER,
};

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
	/*
	 * Function table per backend.
	 */
	const struct show_ops *ops;

	struct jambuf *jambuf;
	enum show_state states[MAX_SHOW_STATES];
	size_t state_index;
	bool insert_separator;
};

struct show *alloc_show(struct logger *logger,
			const struct show_ops *ops)
{
	struct show s = {
		.separator = NO_SEPARATOR,
		.logger = logger,
		.ops = ops,
	};
	return clone_thing(s, "on show");
}

static void blank_line(struct show *s)
{
	/* XXX: must not use s->jambuf */
	char blank_buf[sizeof(" "/*\0*/) + 1/*canary*/ + 1/*why-not*/];
	struct jambuf buf = ARRAY_AS_JAMBUF(blank_buf);
	jam_string(&buf, " ");
	jambuf_to_logger(&buf, s->logger, WHACK_STREAM);
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
	return jambuf_from_logjam(&s->logjam, s->logger,
				  /*pluto_exit_code*/0,
				  /*where*/NULL,
				  PRINTF_STREAM);
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

VPRINTF_LIKE(2)
static void show_va_list(struct show *s, const char *message, va_list ap)
{
	struct jambuf *buf = show_jambuf(s);
	jam_va_list(buf, message, ap);
	show_to_logger(s);
}

void show(struct show *s, const char *message, ...)
{
	va_list ap;
	va_start(ap, message);
	show_va_list(s, message, ap);
	va_end(ap);
}

void show_rc(enum rc_type rc, struct show *s, const char *message, ...)
{
	va_list ap;
	va_start(ap, message);
	show_va_list(s, message, ap);
	va_end(ap);
	whack_rc(rc, s->logger);
}

static bool push_state(struct show *s, enum show_state state)
{
	if (s->state_index > MAX_SHOW_STATES) {
		return false;
	}
	s->states[s->state_index++] = state;
	return true;
}

static bool pop_state(struct show *s, enum show_state state)
{
	if (s->state_index == 0) {
		return false;
	}
	if (s->states[--s->state_index] != state) {
		return false;
	}
	return true;
}

static void assert_state(struct show *s, enum show_state state)
{
#define A(ASSERTION) if (!(ASSERTION)) abort()
	A(s->state_index > 0);
	A(s->states[s->state_index - 1] == state);
#undef A
}

void show_structured_start(struct show *s)
{
	s->jambuf = show_jambuf(s);
}

void show_structured_end(struct show *s)
{
	show_to_logger(s);
	s->jambuf = NULL;
	s->state_index = 0;
	s->insert_separator = false;
}

void show_raw(struct show *s, const char *message, ...)
{
	if (s->insert_separator)
		s->ops->separator(s->jambuf);

	va_list ap;
	va_start(ap, message);
	s->ops->raw_va_list(s->jambuf, message, ap);
	va_end(ap);

	s->insert_separator = true;
}

void show_string(struct show *s, const char *message, ...)
{
	if (s->insert_separator)
		s->ops->separator(s->jambuf);

	va_list ap;
	va_start(ap, message);
	s->ops->string_va_list(s->jambuf, message, ap);
	va_end(ap);

	s->insert_separator = true;
}

void show_member_start(struct show *s, const char *name)
{
	assert_state(s, SHOW_OBJECT);
	if (s->insert_separator)
		s->ops->separator(s->jambuf);

	s->ops->member_start(s->jambuf, name);

	s->insert_separator = false;
	push_state(s, SHOW_MEMBER);
}

void show_member_end(struct show *s)
{
	s->ops->member_end(s->jambuf);

	s->insert_separator = true;
	pop_state(s, SHOW_MEMBER);
}

void show_array_start(struct show *s)
{
	if (s->insert_separator)
		s->ops->separator(s->jambuf);

	s->ops->array_start(s->jambuf);

	s->insert_separator = false;
	push_state(s, SHOW_ARRAY);
}

void show_array_end(struct show *s)
{
	s->ops->array_end(s->jambuf);

	s->insert_separator = true;
	pop_state(s, SHOW_ARRAY);
}

void show_object_start(struct show *s)
{
	if (s->insert_separator)
		s->ops->separator(s->jambuf);

	s->ops->object_start(s->jambuf);

	s->insert_separator = false;
	push_state(s, SHOW_OBJECT);
}

void show_object_end(struct show *s)
{
	s->ops->object_end(s->jambuf);

	s->insert_separator = true;
	pop_state(s, SHOW_OBJECT);
}
