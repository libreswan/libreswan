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
#include "ikev1.h"		/* for send_n_log_v1_delete() */
#include "ikev2_delete.h"

/*
 * When there's no name, whack all connections.
 *
 * How to decorate this with a header / footer?
 */

void whack_all_connections_sorted(const struct whack_message *m, struct show *s,
				  bool (*whack_connection)
				  (struct show *s,
				   struct connection **cp,
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
			    struct connection **cp,
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

static unsigned whack_connection_bottom_up(struct connection **cp,
					   const struct whack_message *m,
					   struct show *s,
					   bool (*whack_connection)
					   (struct show *s,
					    struct connection *c,
					    const struct whack_message *m),
					   const struct each *each)
{
	struct logger *logger = show_logger(s);

	unsigned nr = 0;
	struct connection_filter instances = {
		.clonedfrom = (*cp),
		.where = HERE,
	};
	while (next_connection_new2old(&instances)) {
		/* abuse bool */
		nr += whack_connection_bottom_up(&instances.c, m, s, whack_connection, each);
	}
	/* abuse bool */
	nr += whack_connection(s, connection_addref((*cp), logger), m);
	connection_delref(cp, logger); /* kill addref() and caller's pointer */
	return nr;
}

void whack_connections_bottom_up(const struct whack_message *m,
				 struct show *s,
				 bool (*whack_connection)
				 (struct show *s,
				  struct connection *c,
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
		whack_connection_bottom_up(&by_name.c, m, s,
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
			nr += whack_connection_bottom_up(&by_alias.c, m, s, whack_connection, &each);
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
				whack_connection_bottom_up(&c, m, s, whack_connection, &each);
				return;
			}
			break;
		}
		case '#':
		{
			struct state *st = state_by_serialno(serialno);
			if (st != NULL) {
				struct connection *c = st->st_connection;
				whack_connection_bottom_up(&c, m, s, whack_connection, &each);
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

void whack_connection_states(struct connection *c,
			     void (whack_state)(struct connection *c,
						struct ike_sa **ike,
						struct child_sa **child,
						enum whack_state),
			     where_t where)
{
	pdbg(c->logger, "%s()", __func__);
	struct ike_sa *ike = ike_sa_by_serialno(c->newest_ike_sa); /* could be NULL */
	if (ike != NULL) {
		pdbg(c->logger, "%s()  dispatching START to "PRI_SO,
		     __func__, pri_so(ike->sa.st_serialno));
		whack_state(c, &ike, NULL, WHACK_START_IKE);
	} else {
		pdbg(c->logger, "%s()  skipping START, no IKE", __func__);
	}

	/*
	 * Weed out any larval or lingering SAs.
	 *
	 * These are SAs that are using the connection yet are not the
	 * owner (newest IKE SA or Child SA).  For instance:
	 *
	 * + an IKE SA that failed to establish
	 *
	 * + an IKE SA that was replaced but hasn't yet expired
	 *
	 * + children that are part way through an IKE_AUTH or
	 *   CREATE_CHILD_SA exchange and don't yet own their
	 *   connection's route.
	 *
	 * Typically these states can be deleted outright.
	 */

	pdbg(c->logger, "%s()  weeding out larval and lingering SAs", __func__);
	struct state_filter weed = {
		.connection_serialno = c->serialno,
		.where = where,
	};
	unsigned nr_parents = 0;
	unsigned nr_children = 0;
	while (next_state_new2old(&weed)) {
		if (weed.st->st_serialno == c->newest_ike_sa) {
			pdbg(c->logger, "%s()    skipping "PRI_SO" as newest IKE SA",
			      __func__, pri_so(weed.st->st_serialno));
			continue;
		}
		if (weed.st->st_serialno == c->newest_ipsec_sa) {
			pdbg(c->logger, "%s()    skipping "PRI_SO" as newest Child SA",
			      __func__, pri_so(weed.st->st_serialno));
			continue;
		}
		if (weed.st->st_serialno == c->child.newest_routing_sa) {
			pdbg(c->logger, "%s()    skipping "PRI_SO" as newest routing SA",
			      __func__, pri_so(weed.st->st_serialno));
			continue;
		}
		if (IS_PARENT_SA(weed.st)) {
			pdbg(c->logger, "%s()    dispatch lurking IKE SA to "PRI_SO,
			     __func__, pri_so(weed.st->st_serialno));
			struct ike_sa *lingering_ike = pexpect_ike_sa(weed.st);
			whack_state(c, &lingering_ike, NULL, WHACK_LURKING_IKE);
			nr_parents++;
		} else {
			pdbg(c->logger, "%s()    dispatch lurking Child SA to "PRI_SO,
			     __func__, pri_so(weed.st->st_serialno));
			struct child_sa *lingering_child = pexpect_child_sa(weed.st);
			/* may not have IKE as parent? */
			nr_children++;
			whack_state(c, NULL, &lingering_child, WHACK_LURKING_CHILD);
		}
	}
	pdbg(c->logger, "%s()    weeded %u parents and %u children",
	     __func__, nr_parents, nr_children);

	/*
	 * Notify the connection's child.
	 *
	 * Do this before any siblings.  If this isn't done, the IKE
	 * SAs children constantly swap the revival pole position.
	 */

	bool whack_ike;
	struct child_sa *connection_child =
		child_sa_by_serialno(c->child.newest_routing_sa);
	if (connection_child == NULL) {
		pdbg(c->logger, "%s()  skipping Child SA, as no "PRI_SO,
		     __func__, pri_so(c->child.newest_routing_sa));
		whack_ike = true;
	} else if (connection_child->sa.st_clonedfrom != c->newest_ike_sa) {
		/* st_clonedfrom can't be be SOS_NOBODY */
		pdbg(c->logger, "%s()  dispatch cuckoo Child SA "PRI_SO,
		     __func__,
		     pri_so(connection_child->sa.st_serialno));
		whack_ike = true;
		whack_state(c, NULL, &connection_child, WHACK_CUCKOO);
	} else if (ike == NULL) {
		pdbg(c->logger, "%s()  dispatch orphaned Child SA "PRI_SO,
		     __func__,
		     pri_so(connection_child->sa.st_serialno));
		whack_ike = false;
		whack_state(c, NULL, &connection_child, WHACK_ORPHAN);
	} else {
		pdbg(c->logger, "%s()  dispatch Child SA "PRI_SO,
		     __func__,
		     pri_so(connection_child->sa.st_serialno));
		whack_ike = false;
		whack_state(c, &ike, &connection_child, WHACK_CHILD);
	}

	/*
	 * Now go through any remaining children.
	 *
	 * This could include children of the first IKE SA that are
	 * been replaced.
	 */

	if (ike != NULL) {
		pdbg(c->logger, "%s()  poking siblings", __func__);
		struct state_filter child_filter = {
			.clonedfrom = ike->sa.st_serialno,
			.where = where,
		};
		unsigned nr = 0;
		while (next_state_new2old(&child_filter)) {
			struct child_sa *child = pexpect_child_sa(child_filter.st);
			if (!PEXPECT(c->logger,
				     child->sa.st_connection->child.newest_routing_sa ==
				     child->sa.st_serialno)) {
				continue;
			}
			nr++;
			pdbg(c->logger, "%s()    dispatching to sibling Child SA "PRI_SO,
			     __func__, pri_so(child->sa.st_serialno));
			whack_state(c, &ike, &child, WHACK_SIBLING);
		}
		pdbg(c->logger, "%s()    poked %u siblings", __func__, nr);
	}

	/*
	 * With everything cleaned up decide what to do with the IKE
	 * SA.
	 */

	if (ike != NULL && whack_ike) {
		pdbg(c->logger, "%s()  dispatch to IKE SA "PRI_SO" as child skipped",
		     __func__, pri_so(ike->sa.st_serialno));
		whack_state(c, &ike, NULL, WHACK_IKE);
	}

	if (ike != NULL) {
		pdbg(c->logger, "%s()  dispatch STOP as reached end", __func__);
		whack_state(c, &ike, NULL, WHACK_STOP_IKE);
	} else {
		pdbg(c->logger, "%s()  skipping STOP, no IKE", __func__);
	}
}
