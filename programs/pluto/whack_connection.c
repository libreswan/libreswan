/* whack communicating routines, for libreswan
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
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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

#include "whack_connection.h"

#include "show.h"
#include "connections.h"
#include "log.h"

/*
 * When there's no name, whack all connections.
 *
 * How to decorate this with a header / footer?
 */

void whack_all_connections(const struct whack_message *m, struct show *s,
			   bool (*whack_connection)
			   (struct show *s,
			    struct connection **c,
			    const struct whack_message *m))
{
	struct connection **connections = sort_connections();
	if (connections == NULL) {
		return;
	}

	for (struct connection **cp = connections; *cp != NULL; cp++) {
		whack_connection(s, cp, m);
	}
	pfree(connections);
}

void whack_each_connection(const struct whack_message *m, struct show *s,
			   bool (*whack_connection)
			   (struct show *s,
			    struct connection **c,
			    const struct whack_message *m),
			   struct each each)
{
	struct logger *logger = show_logger(s);
	unsigned nr_found = 0;

	/*
	 * First try by name.
	 */
	struct connection_filter by_name = {
		.name = m->name,
		.where = HERE,
	};
	while (next_connection_new2old(&by_name)) {
		/*
		 * XXX: broken, other whack_connection() calls do not have this guard.
		 *
		 * Instead instead let whack_connection() decide if
		 * the connection should be skipped and return true
		 * when the connection should be counted?
		 */
		if (each.skip_instances && is_instance(by_name.c)) {
			continue;
		}
		whack_connection(s, &by_name.c, m);
		nr_found++;
	}
	if (nr_found > 0) {
		return;
	}

	/*
	 * When name fails, try by alias.
	 */
	struct connection_filter by_alias = {
		.alias = m->name,
		.where = HERE,
	};
	while (next_connection_new2old(&by_alias)) {
		if (nr_found == 0 && each.future_tense != NULL) {
			llog(RC_COMMENT, logger, "%s all connections with alias=\"%s\"",
			     each.future_tense, m->name);
		}
		whack_connection(s, &by_alias.c, m);
		nr_found++;
	}
	if (nr_found == 1) {
		if (each.past_tense != NULL) {
			llog(RC_COMMENT, logger, "%s %u connection",
			     each.past_tense, nr_found);
		}
		return;
	}
	if (nr_found > 1) {
		if (each.past_tense != NULL) {
			llog(RC_COMMENT, logger, "%s %u connections",
			     each.past_tense, nr_found);
		}
		return;
	}

	/*
	 * When alias fails, see if the name is a connection ($
	 * prefix) and/or state (# prefix) number.
	 */

	if (m->name[0] == '$' ||
	    m->name[0] == '#') {
		ldbg(logger, "looking up '%s' by serialno", m->name);
		uintmax_t serialno = 0;
		err_t e = shunk_to_uintmax(shunk1(m->name + 1), NULL, /*base*/0, &serialno);
		if (e != NULL) {
			llog(RC_LOG, logger, "invalid serial number '%s': %s",
			     m->name, e);
			return;
		}
		if (serialno >= INT_MAX) {/* arbitrary limit */
			llog(RC_LOG, logger, "serial number '%s' is huge", m->name);
			return;
		}
		switch (m->name[0]) {
		case '$':
		{
			struct connection *c = connection_by_serialno(serialno);
			if (c != NULL) {
				whack_connection(s, &c, m);
				return;
			}
			break;
		}
		case '#':
		{
			struct state *st = state_by_serialno(serialno);
			if (st != NULL) {
				struct connection *c = st->st_connection;
				whack_connection(s, &c, m);
				return;
			}
			break;
		}
		}
		llog(RC_LOG, logger, "serialno '%s' not found", m->name);
		return;
	}

	/*
	 * Danger:
	 *
	 * Logging with RC_UNKNOWN_NAME is "fatal" - when whack sees
	 * it it, it detaches immediately.  For instance, adding a
	 * connection is performed in two steps: DELETE+ADD; KEYS.
	 * When there's no connection to delete that should not be
	 * logged as it A. is confusing and B. would cause whack to
	 * detach stopping the KEYS from being added.
	 */
	if (each.log_unknown_name) {
#define MESSAGE "no connection or alias named \"%s\"'", m->name
		/* what means leave more breadcrumbs */
		if (each.past_tense != NULL) {
			llog(RC_UNKNOWN_NAME, logger, MESSAGE);
		} else {
			whack_log(RC_UNKNOWN_NAME, s, MESSAGE);
		}
	}
#undef MESSAGE
}

static unsigned whack_bottom_up(struct connection **c,
				const struct whack_message *m,
				struct show *s,
				bool (*whack_connection)
				(struct show *s,
				 struct connection **c,
				 const struct whack_message *m),
				const struct each *each)
{
	unsigned nr = 0;
	struct connection_filter instances = {
		.clonedfrom = *c,
		.where = HERE,
	};
	while (next_connection_new2old(&instances)) {
		/* abuse bool */
		nr += whack_bottom_up(&instances.c, m, s, whack_connection, each);
	}
	/* abuse bool */
	nr += whack_connection(s, c, m);
	return nr;
}

void whack_connections_bottom_up(const struct whack_message *m,
				 struct show *s,
				 bool (*whack_connection)
				 (struct show *s,
				  struct connection **c,
				  const struct whack_message *m),
				 struct each each)
{
	struct logger *logger = show_logger(s);

	/*
	 * Try by name.
	 *
	 * A templte connection ends up giving instances the same
	 * name.  Hence use OLD2NEW so that the ancestral root (i.e.,
	 * template) is found first.  Then whack_bottom_up() visits
	 * instances before templates.
	 */
	struct connection_filter by_name = {
		.name = m->name,
		.where = HERE,
	};
	if (next_connection_old2new(&by_name)) {
		whack_bottom_up(&by_name.c, m, s,
				whack_connection,
				&each);
		return;
	}

	/*
	 * Try by alias.
	 *
	 * A connection like:
	 *
	 *   conn foo
	 *     subnets=...
	 *
	 * will expand into alias=FOO name=FOO/1x1 et.al.
	 *
	 * If FOO is a template, the whack_bottom_up() call will
	 * further expand that.
	 */
	struct connection_filter by_alias = {
		.alias = m->name,
		.where = HERE,
	};
	if (next_connection_new2old(&by_alias)) {
		if (each.future_tense != NULL) {
			llog(RC_COMMENT, logger, "%s all connections with alias=\"%s\"",
			     each.future_tense, m->name);
		}
		unsigned nr = 0;
		do {
			nr += whack_bottom_up(&by_alias.c, m, s, whack_connection, &each);
		} while (next_connection_new2old(&by_alias));
		if (nr == 1) {
			if (each.past_tense != NULL) {
				llog(RC_COMMENT, logger, "%s %u connection",
				     each.past_tense, nr);
			}
		} else {
			PEXPECT(logger, (nr == 0 ||
					 nr > 1 ));
			if (each.past_tense != NULL) {
				llog(RC_COMMENT, logger, "%s %u connections",
				     each.past_tense, nr);
			}
		}
		return;
	}

	/*
	 * Try by serial number
	 *
	 * When alias fails, see if the name is a connection serial
	 * number ("$" prefix) or a state serial number ("#" prefix).
	 */

	if (m->name[0] == '$' ||
	    m->name[0] == '#') {
		ldbg(logger, "looking up '%s' by serialno", m->name);
		uintmax_t serialno = 0;
		err_t e = shunk_to_uintmax(shunk1(m->name + 1), NULL, /*base*/0, &serialno);
		if (e != NULL) {
			llog(RC_LOG, logger, "invalid serial number '%s': %s",
			     m->name, e);
			return;
		}
		if (serialno >= INT_MAX) {/* arbitrary limit */
			llog(RC_LOG, logger, "serial number '%s' is huge", m->name);
			return;
		}
		switch (m->name[0]) {
		case '$':
		{
			struct connection *c = connection_by_serialno(serialno);
			if (c != NULL) {
				whack_bottom_up(&c, m, s, whack_connection, &each);
				return;
			}
			break;
		}
		case '#':
		{
			struct state *st = state_by_serialno(serialno);
			if (st != NULL) {
				struct connection *c = st->st_connection;
				whack_bottom_up(&c, m, s, whack_connection, &each);
				return;
			}
			break;
		}
		}
		llog(RC_LOG, logger, "connection matching serial number '%s' not found", m->name);
		return;
	}

	/*
	 * Danger:
	 *
	 * Logging with RC_UNKNOWN_NAME is "fatal" - when whack sees
	 * it it, it detaches immediately.  For instance, adding a
	 * connection is performed in two steps: DELETE+ADD; KEYS.
	 * When there's no connection to delete that should not be
	 * logged as it A. is confusing and B. would cause whack to
	 * detach stopping the KEYS from being added.
	 */
	if (each.log_unknown_name) {
#define MESSAGE "no connection or alias named \"%s\"'", m->name
		/* what means leave more breadcrumbs */
		if (each.past_tense != NULL) {
			llog(RC_UNKNOWN_NAME, logger, MESSAGE);
		} else {
			whack_log(RC_UNKNOWN_NAME, s, MESSAGE);
		}
	}
#undef MESSAGE
}
