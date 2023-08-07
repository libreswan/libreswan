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

void whack_connection_states(struct connection *c,
			     void (whack_state)(struct connection *c,
						struct ike_sa **ike,
						struct child_sa **child,
						enum whack_state),
			     where_t where)
{
	struct ike_sa *ike = ike_sa_by_serialno(c->newest_ike_sa); /* could be NULL */
	if (ike != NULL) {
		ldbg(c->logger, "%s() dispatching START to "PRI_SO,
		     __func__, pri_so(ike->sa.st_serialno));
		whack_state(c, &ike, NULL, WHACK_START_IKE);
	} else {
		ldbg(c->logger, "%s() skipping START, no IKE", __func__);
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

	ldbg(c->logger, "%s()  weeding out larval and lingering SAs", __func__);
	struct state_filter weed = {
		.connection_serialno = c->serialno,
		.where = where,
	};
	while (next_state_new2old(&weed)) {
		if (weed.st->st_serialno == c->newest_ike_sa) {
			ldbg(c->logger, "%s()    skipping "PRI_SO" as newest IKE SA",
			     __func__, pri_so(weed.st->st_serialno));
			continue;
		}
		if (weed.st->st_serialno == c->newest_ipsec_sa) {
			ldbg(c->logger, "%s()    skipping "PRI_SO" as newest Child SA",
			     __func__, pri_so(weed.st->st_serialno));
			continue;
		}
		if (weed.st->st_serialno == c->child.newest_routing_sa) {
			ldbg(c->logger, "%s()    skipping "PRI_SO" as newest routing SA",
			     __func__, pri_so(weed.st->st_serialno));
			continue;
		}
		if (IS_PARENT_SA(weed.st)) {
			ldbg(c->logger, "%s()    dispatch lurking IKE SA to "PRI_SO,
			     __func__, pri_so(weed.st->st_serialno));
			struct ike_sa *lingering_ike = pexpect_ike_sa(weed.st);
			whack_state(c, &lingering_ike, NULL, WHACK_LURKING_IKE);
		} else {
			ldbg(c->logger, "%s()    dispatch lurking Child SA to "PRI_SO,
			     __func__, pri_so(weed.st->st_serialno));
			struct child_sa *lingering_child = pexpect_child_sa(weed.st);
			/* may not have IKE as parent? */
			whack_state(c, NULL, &lingering_child, WHACK_LURKING_CHILD);
		}
	}

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
		ldbg(c->logger, "%s()   skipping Child SA, as no "PRI_SO,
		     __func__, pri_so(c->child.newest_routing_sa));
		whack_ike = true;
	} else if (connection_child->sa.st_clonedfrom != c->newest_ike_sa) {
		/* st_clonedfrom can't be be SOS_NOBODY */
		ldbg(c->logger, "%s()   dispatch cuckoo Child SA "PRI_SO,
		     __func__,
		     pri_so(connection_child->sa.st_serialno));
		whack_ike = true;
		whack_state(c, NULL, &connection_child, WHACK_CUCKOO);
	} else if (ike == NULL) {
		ldbg(c->logger, "%s()   dispatch orphaned Child SA "PRI_SO,
		     __func__,
		     pri_so(connection_child->sa.st_serialno));
		whack_ike = false;
		whack_state(c, NULL, &connection_child, WHACK_ORPHAN);
	} else {
		ldbg(c->logger, "%s()   dispatch Child SA "PRI_SO,
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
		struct state_filter child_filter = {
			.ike = ike,
			.where = where,
		};
		while (next_state_new2old(&child_filter)) {
			struct child_sa *child = pexpect_child_sa(child_filter.st);
			if (!PEXPECT(c->logger,
				     child->sa.st_connection->child.newest_routing_sa ==
				     child->sa.st_serialno)) {
				continue;
			}
			ldbg(c->logger, "%s()   dispatching to sibling Child SA "PRI_SO,
			     __func__, pri_so(child->sa.st_serialno));
			whack_state(c, &ike, &child, WHACK_SIBLING);
		}
	}

	/*
	 * With everything cleaned up decide what to do with the IKE
	 * SA.
	 */

	if (ike != NULL && whack_ike) {
		ldbg(c->logger, "%s()  dispatch to IKE SA "PRI_SO" as child skipped",
		     __func__, pri_so(ike->sa.st_serialno));
		whack_state(c, &ike, NULL, WHACK_IKE);
	}

	if (ike != NULL) {
		ldbg(c->logger, "%s() dispatch STOP as reached end", __func__);
		whack_state(c, &ike, NULL, WHACK_STOP_IKE);
	} else {
		ldbg(c->logger, "%s() skipping STOP, no IKE", __func__);
	}
}

static void delete_v1_states(struct connection *c,
			     struct ike_sa **ike,
			     struct child_sa **child,
			     enum whack_state whacamole)
{
	switch (whacamole) {
	case WHACK_START_IKE:
		/*
		 * IKEv1 announces the death of the ISAKMP SA after
		 * all the children have gone (reverse of IKEv2).
		 */
		state_attach(&(*ike)->sa, c->logger);
		(*ike)->sa.st_viable_parent = false;
		return;
	case WHACK_LURKING_CHILD:
		state_attach(&(*child)->sa, c->logger);
		delete_child_sa(child);
		return;
	case WHACK_LURKING_IKE:
		state_attach(&(*ike)->sa, c->logger);
		delete_ike_sa(ike);
		return;
	case WHACK_CHILD:
		state_attach(&(*child)->sa, c->logger);
		send_n_log_v1_delete(&(*child)->sa, HERE);
		PEXPECT(c->logger, (*ike) != NULL);
		connection_delete_child(*ike, child, HERE);
		return;
	case WHACK_CUCKOO:
		/* IKEv1 has cuckoos */
		state_attach(&(*child)->sa, c->logger);
		send_n_log_v1_delete(&(*child)->sa, HERE);
		PEXPECT(c->logger, ike == NULL);
		connection_delete_child(isakmp_sa(*child, HERE)/*could-be-null*/,
					child, HERE);
		return;
	case WHACK_ORPHAN:
		/* IKEv1 has orphans */
		state_attach(&(*child)->sa, c->logger);
		PEXPECT(c->logger, ike == NULL);
		connection_delete_child(*ike, child, HERE);
		return;
	case WHACK_SIBLING:
		/*
		 * When IKEv1 deletes an IKE SA any siblings are
		 * orphaned.
		 */
		return;
	case WHACK_IKE:
		/*
		 * When IKEv1 deletes an IKE SA it always sends a
		 * delete notify; hence handle this in WHACK_STOP_IKE.
		 */
		return;
	case WHACK_STOP_IKE:
		/*
		 * Can't use connection_delete_ike() as that has IKEv2
		 * semantics - deletes all siblings skipped above.
		 */
		send_n_log_v1_delete(&(*ike)->sa, HERE);
		delete_ike_sa(ike);
		connection_unroute(c, HERE);
		return;
	}
	bad_case(whacamole);
}

static void delete_v2_states(struct connection *c,
			     struct ike_sa **ike,
			     struct child_sa **child,
			     enum whack_state whacamole)
{
	switch (whacamole) {
	case WHACK_START_IKE:
		/* announce to the world */
		state_attach(&(*ike)->sa, c->logger);
		(*ike)->sa.st_viable_parent = false;
		record_n_send_n_log_v2_delete(*ike, HERE);
		return;
	case WHACK_LURKING_CHILD:
		state_attach(&(*child)->sa, c->logger);
		delete_child_sa(child);
		return;
	case WHACK_LURKING_IKE:
		state_attach(&(*ike)->sa, c->logger);
		delete_ike_sa(ike);
		return;
	case WHACK_CHILD:
		state_attach(&(*child)->sa, c->logger);
		connection_delete_child(*ike, child, HERE);
		return;
	case WHACK_CUCKOO:
		state_attach(&(*child)->sa, c->logger);
		PEXPECT(c->logger, ike == NULL);
		connection_delete_child(ike_sa(&(*child)->sa, HERE), child, HERE);
		return;
	case WHACK_ORPHAN:
		state_attach(&(*child)->sa, c->logger);
		llog_pexpect(c->logger, HERE, "unexpected orphan Child SA "PRI_SO,
			     (*child)->sa.st_serialno);
		PEXPECT(c->logger, ike == NULL);
		delete_child_sa(child);
		return;
	case WHACK_SIBLING:
		state_attach(&(*child)->sa, c->logger);
		connection_delete_child(*ike, child, HERE);
		return;
	case WHACK_IKE:
		connection_delete_ike(ike, HERE);
		return;
	case WHACK_STOP_IKE:
		delete_ike_sa(ike);
		return;
	}
	bad_case(whacamole);
}

static void delete_states(struct connection *c,
			  struct ike_sa **ike,
			  struct child_sa **child,
			  enum whack_state whacamole)
{
	switch (c->config->ike_version) {
	case IKEv1:
		delete_v1_states(c, ike, child, whacamole);
		return;
	case IKEv2:
		delete_v2_states(c, ike, child, whacamole);
		return;
	}
	bad_case(c->config->ike_version);
}

void whack_connection_delete_states(struct connection *c, where_t where)
{
	whack_connection_states(c, delete_states, where);
}
