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

typedef unsigned (whack_connections_visitor_cb)
(struct connection *c,
 const struct whack_message *m,
 struct show *s,
 whack_connection_visitor_cb *visit_connection);

static whack_connections_visitor_cb visit_connections_bottom_up;
static whack_connections_visitor_cb visit_connections_root;

/*
 * When there's no name, whack all connections.
 *
 * How to decorate this with a header / footer?
 */

void whack_all_connections_sorted(const struct whack_message *m, struct show *s,
				  whack_connection_visitor_cb *visit_connection)
{
	struct connection **connections = sort_connections();
	if (connections == NULL) {
		return;
	}

	for (struct connection **cp = connections; *cp != NULL; cp++) {
		visit_connection(m, s, (*cp));
	}
	pfree(connections);
}

/*
 * Try by name.
 *
 * Search OLD2NEW so that a template connection matching name is found
 * before any of its instantiated instances (which have the same name,
 * ugh).  WHACK_CONNECTIONS() will then vist it any any instances.
 */

static bool whack_connections_by_name(const struct whack_message *m,
				      struct show *s,
				      whack_connections_visitor_cb *visit_connections,
				      whack_connection_visitor_cb *visit_connection,
				      const struct each *each UNUSED)
{
	struct connection_filter by_name = {
		.name = m->name,
		.where = HERE,
	};
	if (next_connection_old2new(&by_name)) {
		visit_connections(by_name.c, m, s,
				  visit_connection);
		return true; /* found something, stop */
	}
	return false; /* keep looking */
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
 * If FOO is a template, then that will be further expanded into alias-instances.
 *
 * The visit_connections() call-back is is passed the root of this
 * connection tree, it will in turn call visit_connection().
 */

static bool whack_connections_by_alias(const struct whack_message *m,
				       struct show *s,
				       whack_connections_visitor_cb *visit_connections,
				       whack_connection_visitor_cb *visit_connection,
				       const struct each *each)
{
	struct logger *logger = show_logger(s);
	struct connection_filter by_alias = {
		.alias = m->name,
		.where = HERE,
	};
	/*
	 * Search new-to-old so that when the alias root is a template
	 * there are no instances of that alias ahead in the search
	 * list list (instances of an (alias) connection are newer
	 * than the template).
	 *
	 * This way deleting an alias connection tree can't corrupt
	 * the search list.
	 */
	if (next_connection_new2old(&by_alias)) {
		/* header */
		if (each->future_tense != NULL) {
			llog(RC_COMMENT, logger, "%s all connections with alias=\"%s\"",
			     each->future_tense, m->name);
		}
		unsigned nr = 0;
		do {
			/*
			 * Only pass the matching connection root to
			 * visit_connections().  i.e., ignore aliased
			 * instances.  Instead visit_connections()
			 * will then recurse through all the instances
			 * if needed.
			 *
			 * Only the alias roots have .root_config
			 * non-NULL.
			 */
			if (by_alias.c->root_config == NULL) {
				continue;
			}
			nr += visit_connections(by_alias.c, m, s, visit_connection);
		} while (next_connection_new2old(&by_alias));
		/* footer */
		if (each->past_tense != NULL) {
			if (nr == 1) {
				llog(RC_COMMENT, logger, "%s %u connection",
				     each->past_tense, nr);
			} else {
				llog(RC_COMMENT, logger, "%s %u connections",
				     each->past_tense, nr);
			}
		}
		return true; /* found something, stop */
	}
	return false; /* keep looking */
}

/*
 * If NAME is of the form "$N" or "#N", use that to find and whack a
 * connection.
 *
 * Return true if the search for a connection should stop; not that
 * the search was sucessful.
 */

static bool whack_connection_by_serialno(const struct whack_message *m,
					 struct show *s,
					 whack_connections_visitor_cb *visit_connections,
					 whack_connection_visitor_cb *visit_connection,
					 const struct each *each UNUSED)
{
	struct logger *logger = show_logger(s);
	if (m->name[0] == '$' ||
	    m->name[0] == '#') {
		ldbg(logger, "looking up '%s' by serialno", m->name);
		uintmax_t serialno = 0;
		err_t e = shunk_to_uintmax(shunk1(m->name + 1), NULL, /*base*/0, &serialno);
		if (e != NULL) {
			llog(RC_LOG, logger, "invalid serial number '%s': %s",
			     m->name, e);
			return true; /* found something, stop */
		}
		if (serialno >= INT_MAX) {/* arbitrary limit */
			llog(RC_LOG, logger, "serial number '%s' is huge", m->name);
			return true; /* found something, stop */
		}
		switch (m->name[0]) {
		case '$':
		{
			struct connection *c = connection_by_serialno(serialno);
			if (c != NULL) {
				visit_connections(c, m, s, visit_connection);
				return true; /* found something, stop */
			}
			break;
		}
		case '#':
		{
			struct state *st = state_by_serialno(serialno);
			if (st != NULL) {
				struct connection *c = st->st_connection;
				visit_connections(c, m, s, visit_connection);
				return true; /* found something, stop */
			}
			break;
		}
		}
		llog(RC_LOG, logger, "serialno '%s' not found", m->name);
		return true; /* found something, stop (YES!) */
	}
	return false; /* keep looking */
}

static unsigned visit_connections_root(struct connection *c,
				       const struct whack_message *m,
				       struct show *s,
				       whack_connection_visitor_cb *visit_connection)
{
	return visit_connection(m, s, c);
}


unsigned whack_connection_instances(const struct whack_message *m,
				    struct show *s,
				    struct connection *c,
				    whack_connection_visitor_cb *visit_connection)
{
	unsigned nr = 0;
	struct connection_filter instances = {
		.clonedfrom = c,
		.where = HERE,
	};
	while (next_connection_new2old(&instances)) {
		/* abuse bool */
		nr += visit_connection(m, s, instances.c);
	}

	return nr;
}

static unsigned visit_connections_bottom_up(struct connection *c,
					    const struct whack_message *m,
					    struct show *s,
					    whack_connection_visitor_cb *visit_connection)
{
	struct logger *logger = show_logger(s);
	connection_addref(c, logger); /* must delref */

	unsigned nr = 0;
	struct connection_filter instances = {
		.clonedfrom = c,
		.where = HERE,
	};
	while (next_connection_new2old(&instances)) {
		/* abuse bool */
		nr += visit_connections_bottom_up(instances.c, m, s, visit_connection);
	}
	/* abuse bool */
	nr += visit_connection(m, s, c);

	/* kill addref() and caller's pointer */
	connection_delref(&c, logger);
	return nr;
}

static void whack_connections(const struct whack_message *m,
			      struct show *s,
			      whack_connections_visitor_cb *visit_connections,
			      whack_connection_visitor_cb *visit_connection,
			      const struct each *each)
{
	struct logger *logger = show_logger(s);

	/*
	 * Try by name, alias, then serial no.
	 */

	if (whack_connections_by_name(m, s,
				      visit_connections,
				      visit_connection,
				      each)) {
		return;
	}
 
	if (whack_connections_by_alias(m, s,
				       visit_connections,
				       visit_connection,
				       each)) {
		return;
	}

	if (whack_connection_by_serialno(m, s,
					 visit_connections,
					 visit_connection,
					 each)) {
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
	if (each->log_unknown_name) {
#define MESSAGE "no connection or alias named \"%s\"'", m->name
		/* what means leave more breadcrumbs */
		if (each->past_tense != NULL) {
			llog(RC_UNKNOWN_NAME, logger, MESSAGE);
		} else {
			whack_log(RC_UNKNOWN_NAME, s, MESSAGE);
		}
	}
#undef MESSAGE
}

void whack_connection(const struct whack_message *m,
		      struct show *s,
		      whack_connection_visitor_cb *visit_connection,
		      struct each each)
{
	whack_connections(m, s, visit_connections_root,
			  visit_connection, &each);
}

void whack_connections_bottom_up(const struct whack_message *m,
				 struct show *s,
				 whack_connection_visitor_cb *visit_connection,
				 struct each each)
{
	whack_connections(m, s, visit_connections_bottom_up,
			  visit_connection, &each);
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
