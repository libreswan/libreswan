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

#include "visit_connection.h"

#include "show.h"
#include "connections.h"
#include "log.h"
#include "ikev1.h"		/* for send_n_log_v1_delete() */
#include "ikev2_delete.h"

typedef unsigned (connection_node_visitor_cb)
(struct connection *c,
 const struct whack_message *m,
 struct show *s,
 enum chrono order,
 connection_visitor_cb *connection_visitor);

static connection_node_visitor_cb visit_connection_node;
static connection_node_visitor_cb walk_connection_tree;

bool visit_connection_principal_child(struct connection *c,
				      struct ike_sa **ike,
				      visit_connection_state_cb *visit_connection_state,
				      struct visit_connection_state_context *context,
				      struct verbose verbose);
static struct ike_sa *nudge_connection_established_parents(struct connection *c,
							   visit_connection_state_cb *visit_connection_state,
							   struct visit_connection_state_context *context,
							   struct verbose verbose);

/*
 * Try by name.
 *
 * Search OLD2NEW so that a template connection matching name is found
 * before any of its instantiated instances (which have the same name,
 * ugh).  WHACK_CONNECTIONS() will then visit it any any instances.
 */

static bool whack_connection_by_base_name(const struct whack_message *m,
					  struct show *s,
					  enum chrono order,
					  connection_node_visitor_cb *connection_node_visitor,
					  connection_visitor_cb *connection_visitor,
					  const struct each *each UNUSED)
{
#if 0
	/*
	 * While base names, such as 'conn', probably never start with
	 * a quote, the scanner does seem to allow it!
	 */
	if (m->name[0] == '"') {
		return false;
	}
#endif

	struct connection_filter by_base_name = {
		.base_name = m->name,
		.search = {
			.order = OLD2NEW, /* find template before
					   * instance */
			.verbose.logger = show_logger(s),
			.where = HERE,
		},
	};
	if (next_connection(&by_base_name)) {
		connection_node_visitor(by_base_name.c, m, s, order, connection_visitor);
		return true; /* found something, stop */
	}
	return false; /* keep looking */
}

static bool whack_connection_by_name(const struct whack_message *m,
				     struct show *s,
				     enum chrono order,
				     connection_node_visitor_cb *connection_node_visitor,
				     connection_visitor_cb *connection_visitor,
				     const struct each *each UNUSED)
{
	/*
	 * Fully qualified names, such as '"conn#1.2.3.0/24"[1]',
	 * always start with a quote, so no point searching when there
	 * isn't one.
	 */
	if (m->name[0] != '"') {
		return false;
	}

	struct connection_filter by_name = {
		.name = m->name,
		.search = {
			.order = OLD2NEW, /* only one, order doesn't
					   * matter! */
			.verbose.logger = show_logger(s),
			.where = HERE,
		},
	};
	if (next_connection(&by_name)) {
		connection_node_visitor(by_name.c, m, s, order, connection_visitor);
		return true; /* only one, stop */
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
 * The connection_node_visitor() call-back is is passed the root of this
 * connection tree, it will in turn call connection_visitor().
 */

static bool whack_connections_by_alias(const struct whack_message *m,
				       struct show *s,
				       enum chrono order,
				       connection_node_visitor_cb *connection_node_visitor,
				       connection_visitor_cb *connection_visitor,
				       const struct each *each)
{
#if 0
	/*
	 * Aliases, such as 'aliasname', never start with a quote(?),
	 * so no point searching when there is one.
	 */
	if (m->name[0] == '"') {
		return false;
	}
#endif

	struct logger *logger = show_logger(s);
	struct connection_filter by_alias_root = {
		.alias_root = m->name,
		.search = {
			.order = order,
			.verbose.logger = logger,
			.where = HERE,
		},
	};

	/*
	 * Danger:
	 *
	 * When deleting connections, ALIAS_ORDER should be NEW2OLD so
	 * that when the alias root is a template all instances are
	 * deleted before the template (instances are always newer
	 * than their templates).
	 *
	 * This way deleting an alias connection tree can't corrupt
	 * the search list.
	 */
	if (all_connections(&by_alias_root)) {
		/* header */
		if (each->future_tense != NULL) {
			/*
			 * The config option is connalias= but, given
			 * we want this to go away, better to not
			 * tell any one and instead use something
			 * closer to connectionstatus which logs
			 * "aliases: ...".
			 */
			llog(RC_LOG, logger, "%s all connections with alias \"%s\"",
			     each->future_tense, m->name);
		}
		unsigned nr = 0;
		do {
			nr += connection_node_visitor(by_alias_root.c, m, s, order, connection_visitor);
		} while (all_connections(&by_alias_root));
		/* footer */
		if (each->past_tense != NULL) {
			if (nr == 1) {
				llog(RC_LOG, logger, "%s %u connection",
				     each->past_tense, nr);
			} else {
				llog(RC_LOG, logger, "%s %u connections",
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
 * the search was successful.
 */

static bool whack_connection_by_serialno(const struct whack_message *m,
					 struct show *s,
					 enum chrono order,
					 connection_node_visitor_cb *connection_node_visitor,
					 connection_visitor_cb *connection_visitor,
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
				connection_node_visitor(c, m, s, order, connection_visitor);
				return true; /* found something, stop */
			}
			break;
		}
		case '#':
		{
			struct state *st = state_by_serialno(serialno);
			if (st != NULL) {
				struct connection *c = st->st_connection;
				connection_node_visitor(c, m, s, order, connection_visitor);
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

/*
 * Just visit the NODE.
 */
static unsigned visit_connection_node(struct connection *c,
				      const struct whack_message *m,
				      struct show *s,
				      enum chrono order UNUSED,
				      connection_visitor_cb *connection_visitor)
{
	return connection_visitor(m, s, c);
}

unsigned whack_connection_instance_new2old(const struct whack_message *m,
					   struct show *s,
					   struct connection *c,
					   connection_visitor_cb *connection_visitor)
{
	PEXPECT(c->logger, (is_template(c) ||
			    is_labeled_template(c) ||
			    is_labeled_parent(c)));

	unsigned nr = 0;
	struct connection_filter instances = {
		.clonedfrom = c,
		.ike_version = c->config->ike_version, /*redundant but meh*/
		.search = {
			.order = NEW2OLD,
			.verbose.logger = show_logger(s),
			.where = HERE,
		},
	};
	while (next_connection(&instances)) {

		ldbg(c->logger, "visiting instance %s", c->name);
		PEXPECT(c->logger, ((is_template(c) && is_instance(instances.c)) ||
				    (is_labeled_template(c) && is_labeled_parent(instances.c)) ||
				    (is_labeled_parent(c) && is_labeled_child(instances.c))));

		/* abuse bool */
		connection_addref(instances.c, c->logger);
		nr += connection_visitor(m, s, instances.c);
		connection_delref(&instances.c, c->logger);
	}

	return nr;
}

static unsigned walk_connection_tree(struct connection *c,
				     const struct whack_message *m,
				     struct show *s,
				     enum chrono order,
				     connection_visitor_cb *connection_visitor)
{
	struct logger *logger = show_logger(s);
	connection_addref(c, logger); /* must delref */

	unsigned nr = 0;

	/* prefix tree walk */
	if (order == OLD2NEW) {
		/* abuse bool */
		nr += connection_visitor(m, s, c);
	}

	struct connection_filter instances = {
		.clonedfrom = c,
		.ike_version = c->config->ike_version, /*redundant but meh*/
		.search = {
			.order = order,
			.verbose.logger = logger,
			.where = HERE,
		},
	};
	while (next_connection(&instances)) {
		nr += walk_connection_tree(instances.c, m, s, order, connection_visitor);
	}

	/* postfix tree walk */
	if (order == NEW2OLD) {
		/* abuse bool */
		nr += connection_visitor(m, s, c);
	}

	/* kill addref() and caller's pointer */
	connection_delref(&c, logger);
	return nr;
}

static void visit_connections(const struct whack_message *m,
			      struct show *s,
			      enum chrono order,
			      connection_node_visitor_cb *connection_node_visitor,
			      connection_visitor_cb *connection_visitor,
			      const struct each *each)
{
	struct logger *logger = show_logger(s);

	/*
	 * Try by base_name, name, alias, then serial no.
	 */

	if (whack_connection_by_base_name(m, s, order,
					  connection_node_visitor,
					  connection_visitor,
					  each)) {
		return;
	}

	if (whack_connection_by_name(m, s, order,
				     connection_node_visitor,
				     connection_visitor,
				     each)) {
		return;
	}

	/*
	 * Danger:
	 *
	 * When deleting connections, ALIAS_ORDER should be NEW2OLD so
	 * that when the alias root is a template all instances are
	 * deleted before the template (instances are always newer
	 * than their templates).
	 *
	 * This way deleting an alias connection tree can't corrupt
	 * the search list.
	 */
	if (whack_connections_by_alias(m, s, order,
				       connection_node_visitor,
				       connection_visitor,
				       each)) {
		return;
	}

	if (whack_connection_by_serialno(m, s, order,
					 connection_node_visitor,
					 connection_visitor,
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
			llog_rc(RC_UNKNOWN_NAME, logger, MESSAGE);
		} else {
			whack_log(RC_UNKNOWN_NAME, s, MESSAGE);
		}
	}
#undef MESSAGE
}

void visit_root_connection(const struct whack_message *wm,
			   struct show *s,
			   connection_visitor_cb *connection_visitor,
			   enum chrono order, struct each each)
{
	/*
	 * Danger:
	 *
	 * When deleting connections, ALIAS_ORDER should be NEW2OLD so
	 * that when the alias root is a template all instances are
	 * deleted before the template (instances are always newer
	 * than their templates).
	 *
	 * This way deleting an alias connection tree can't corrupt
	 * the search list.
	 */
	visit_connections(wm, s, order, visit_connection_node,
			  connection_visitor, &each);
}

void visit_connection_tree(const struct whack_message *wm,
			   struct show *s,
			   enum chrono order,
			   connection_visitor_cb *connection_visitor,
			   struct each each)
{
	/*
	 * Danger:
	 *
	 * When performing an operation that can delete connections,
	 * ORDER MUST be NEW2OLD so that when the alias root is a
	 * template all instances are deleted before the template
	 * (instances are always newer than their templates).
	 *
	 * This way deleting an alias connection tree can't corrupt
	 * the search list.
	 */
	visit_connections(wm, s, order,
			  walk_connection_tree,
			  connection_visitor, &each);
}

/*
 * Give all the connection parents a gentle nudge so that they can do
 * preliminary work before they, and their children, are visited
 * (deleted).
 *
 * For instance, mark the IKE SA as non-viable; and for IKEv2
 * record'n'send a delete notification (IKEv1 deletes the IKE SA after
 * the Children).
 *
 * This callback MUST NOT delete the IKE SA.
 */

struct ike_sa *nudge_connection_established_parents(struct connection *c,
						    visit_connection_state_cb *visit_connection_state,
						    struct visit_connection_state_context *context,
						    struct verbose verbose)
{
	vdbg("nudging established IKE SAs");
	struct ike_sa *principal_ike_sa = NULL;

	struct state_filter parents = {
		.connection_serialno = c->serialno,
		.search = {
			.order = OLD2NEW,
			.verbose = verbose,
			.where = HERE,
		},
	};

	while (next_state(&parents)) {
		struct verbose verbose = parents.search.verbose;
		struct state *st = parents.st;

		if (!IS_PARENT_SA_ESTABLISHED(st)) {
			vdbg("skipping "PRI_SO" as not established IKE SA",
			     pri_so(st->st_serialno));
			continue;
		}

		if (st->st_serialno == c->established_ike_sa) {
			vdbg("nudging principal established IKE SA "PRI_SO, pri_so(st->st_serialno));
			principal_ike_sa = pexpect_ike_sa(st);
			visit_connection_state(c, &principal_ike_sa, NULL, NUDGE_CONNECTION_PRINCIPAL_IKE_SA, context);
			vexpect(principal_ike_sa != NULL);
			continue;
		}

		vdbg("nudging double-crossed established IKE SA "PRI_SO, pri_so(st->st_serialno));
		struct ike_sa *parent = pexpect_ike_sa(st);
		visit_connection_state(c, &parent, NULL, NUDGE_CONNECTION_CROSSED_IKE_SA, context);
		vexpect(parent != NULL);
	}

	return principal_ike_sa;
}

/*
 * Visit the Child SA that currently owns (i.e., negotiating or
 * established) the connection.
 *
 * Return TRUE if the connection is visited using the Child SA, FALSE
 * otherwize.
 *
 * When visited by the Child SA, code will supress visiting it as the
 * IKE SA (hopefully stopping double routing).
 */

bool visit_connection_principal_child(struct connection *c,
				      struct ike_sa **ike,
				      visit_connection_state_cb *visit_connection_state,
				      struct visit_connection_state_context *context,
				      struct verbose verbose)
{
	/*
	 * The NEGOTIATING Child SA is the owner, NOT the ESTABLISHED
	 * Child SA.
	 *
	 * For instance, an IKEv1 Quick mode responder sets
	 * NEGOTIATING when processing the first message, and
	 * ESTABLISHED when processing the second.  This means that
	 * during a replace, there's a period where ESTABLISHED is for
	 * the old SA, and NEGOTIATING for the new.
	 */

	if (c->negotiating_child_sa == SOS_NOBODY) {
		vdbg("skipping principal Child SA, connection doesn't have one you see");
		return false;
	}

	struct child_sa *child = child_sa_by_serialno(c->negotiating_child_sa);
	if (child == NULL) {
		llog_pexpect(verbose.logger, HERE,
			     "skipping principal Child SA, as negotiating "PRI_SO" was not found",
			     pri_so(c->negotiating_child_sa));
		return false;
	}

	const char *child_state =
		(c->established_child_sa == child->sa.st_serialno ? "established" :
		 "negotiating");

	if (c->established_ike_sa == child->sa.st_clonedfrom) {
		/*
		 * The Child SA and IKE SA share the same parent.
		 */
		vdbg("dispatch %s principal Child SA "PRI_SO" with principal established IKE SA "PRI_SO,
		     child_state, pri_so(child->sa.st_serialno),
		     pri_so(child->sa.st_clonedfrom));
		visit_connection_state(c, ike, &child, VISIT_CONNECTION_CHILD_OF_PRINCIPAL_IKE_SA, context);
		return true;
	}

	struct ike_sa *ike_of_child = parent_sa(child);

	if (ike_of_child == NULL) {
		/*
		 * The Child SA has no parent; presumably IKEv1 where
		 * they keep being deleted (IKEv2 never orphans
		 * children).
		 */
		vdbg("dispatch %s principal Child SA "PRI_SO" with no IKE SA (IKEv1 orphan)",
		     child_state, pri_so(child->sa.st_serialno));
		visit_connection_state(c, NULL, &child, VISIT_CONNECTION_CHILD_OF_NONE, context);
		return true;
	}

	if (ike_of_child->sa.st_connection == c) {
		/*
		 * The Child SA has an established IKE SA with the same
		 * connection yet, somehow, that IKE SA isn't the connection's
		 * owner.
		 *
		 * Presumably it once was but then some other IKE SA
		 * established stealing the connection, leaving IKE_OF_CHILD
		 * lurking i.e., the IKE SA was double crossed.
		 */
		vdbg("dispatch %s principal Child SA "PRI_SO" with double-crossed established IKE SA "PRI_SO,
		     child_state ,pri_so(child->sa.st_serialno),
		     pri_so(ike_of_child->sa.st_serialno));
		visit_connection_state(c, &ike_of_child, &child, VISIT_CONNECTION_CHILD_OF_CROSSED_IKE_SA, context);
		return true;
	}

	/*
	 * The Child SA's IKE SA is for another connection's
	 * (unwitting) IKE SA.
	 */
	vexpect(ike_of_child->sa.st_connection != c);
	state_buf sb;
	vdbg("dispatch %s principal Child SA "PRI_SO" (cuckoo) with another connection's established IKE SA "PRI_STATE" (cuckold)",
	     child_state, pri_so(child->sa.st_serialno),
	     pri_state(&ike_of_child->sa, &sb));
	visit_connection_state(c, &ike_of_child, &child, VISIT_CONNECTION_CHILD_OF_CUCKOLD_IKE_SA, context);
	return true;
}

void visit_connection_states(struct connection *c,
			     visit_connection_state_cb *visit_connection_state,
			     struct visit_connection_state_context *context,
			     where_t where)
{
	VERBOSE_DBGP(DBG_BASE, c->logger,
		     "%s .routing_ike_sa "PRI_SO" .negotiating_ike_sa "PRI_SO" .established_ike_sa "PRI_SO" .negotiating_child_sa "PRI_SO" .established_child_sa "PRI_SO,
		     c->name,
		     pri_so(c->routing_sa),
		     pri_so(c->negotiating_ike_sa),
		     pri_so(c->established_ike_sa),
		     pri_so(c->negotiating_child_sa),
		     pri_so(c->established_child_sa));

	/*
	 * Start by nudging all the connection's IKE SAs (assuming
	 * they are present).
	 *
	 * Cases when there isn't include IKEv1 where the ISAKMP was
	 * deleted, and IKEv2 when the connection is a cuckoo (i.e.,
	 * the Child SA is using another connection's IKE SA).
	 */

	struct ike_sa *ike = nudge_connection_established_parents(c, visit_connection_state, context, verbose);

	/*
	 * Notify the connection's Child SA (i.e., negotiating or
	 * established) before notifying any other children.
	 *
	 * This is to ensure that the connection's Child SA is the
	 * first with an opportunity to put the connection on the
	 * revival queue.  Without this, one of the siblings and their
	 * connection ends up going first and this results in each
	 * revival using a different connection (very confusing).
	 *
	 * Only need to full-on visit the connection once.  Either
	 * with the Child SA, or later with the IKE SA.  VISITED_CHILD
	 * keeps track of this.
	 */

	bool visited_principal_child = visit_connection_principal_child(c, &ike, visit_connection_state,
									context, verbose);

	/* debug-log when callback zapps IKE SA */
	if (c->established_ike_sa != SOS_NOBODY && ike == NULL) {
		vdbg("IKE SA "PRI_SO" wiped when visiting child",
		     pri_so(c->established_ike_sa));
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
	 * + an IKE SA, possibly with children, that was
	 *   double-crossed (the IKE SA no longer owns the connection,
	 *   but the Child SA does!)
	 *
	 * + children that are part way through an IKE_AUTH or
	 *   CREATE_CHILD_SA exchange and don't yet own their
	 *   connection's route.
	 *
	 * Typically these states can be deleted outright.
	 */

	vdbg("weeding out larval and lingering SAs");

	struct state_filter weed = {
		.connection_serialno = c->serialno,
		.search = {
			.order = NEW2OLD,
			.verbose = verbose,
			.where = where,
		},
	};
	unsigned nr_parents = 0;
	unsigned nr_children = 0;
	while (next_state(&weed)) {
		struct verbose verbose = weed.search.verbose;

		if (weed.st->st_serialno == c->established_ike_sa) {
			vdbg("skipping "PRI_SO" as newest IKE SA",
			     pri_so(weed.st->st_serialno));
			continue;
		}

		if (weed.st->st_serialno == c->established_child_sa) {
			vdbg("skipping "PRI_SO" as newest Child SA",
			      pri_so(weed.st->st_serialno));
			continue;
		}

		if (weed.st->st_serialno == c->negotiating_child_sa) {
			vdbg("skipping "PRI_SO" as newest routing SA",
			      pri_so(weed.st->st_serialno));
			continue;
		}

		if (IS_PARENT_SA(weed.st)) {
			vdbg("dispatch lurking IKE SA to "PRI_SO,
			     pri_so(weed.st->st_serialno));
			struct ike_sa *lingering_ike = pexpect_ike_sa(weed.st);
			visit_connection_state(c, &lingering_ike, NULL, VISIT_CONNECTION_LURKING_IKE_SA, context);
			nr_parents++;
			continue;
		}

		vdbg("dispatch lurking Child SA to "PRI_SO,
		     pri_so(weed.st->st_serialno));
		struct child_sa *lingering_child = pexpect_child_sa(weed.st);
		/* may not have IKE as parent? */
		nr_children++;
		visit_connection_state(c, NULL, &lingering_child, VISIT_CONNECTION_LURKING_CHILD_SA, context);
	}

	vdbg("weeded %u parents and %u children", nr_parents, nr_children);

	/*
	 * Now go through any remaining children.
	 *
	 * This could include children of the first IKE SA that are
	 * been replaced.
	 */

	if (ike != NULL) {
		vdbg("poking siblings");
		struct state_filter child_filter = {
			.clonedfrom = ike->sa.st_serialno,
			.search = {
				.order = NEW2OLD,
				.verbose = verbose,
				.where = where,
			},
		};
		unsigned nr = 0;
		while (next_state(&child_filter)) {
			struct verbose verbose = child_filter.search.verbose;

			struct child_sa *child = pexpect_child_sa(child_filter.st);
			state_buf sb;
			vdbg("dispatching to sibling Child SA "PRI_STATE,
			     pri_state(&child->sa, &sb));
			visit_connection_state(c, &ike, &child, VISIT_CONNECTION_CUCKOO_OF_PRINCIPAL_IKE_SA, context);
			nr++;
		}
		vdbg("poked %u siblings", nr);
	}

	/*
	 * With everything cleaned up decide what to do with the IKE
	 * SA.
	 *
	 * CHILDLESS here referes to to the connection's principal
	 * child.
	 */

	if (ike != NULL && !visited_principal_child) {
		vdbg("dispatch to IKE SA "PRI_SO" as child skipped",
		     pri_so(ike->sa.st_serialno));
		visit_connection_state(c, &ike, NULL, VISIT_CONNECTION_CHILDLESS_PRINCIPAL_IKE_SA, context);
	}

	if (ike != NULL) {
		vdbg("dispatch STOP as reached end");
		visit_connection_state(c, &ike, NULL, FINISH_CONNECTION_PRINCIPAL_IKE_SA, context);
	} else {
		vdbg("skipping STOP, no IKE");
	}
}
