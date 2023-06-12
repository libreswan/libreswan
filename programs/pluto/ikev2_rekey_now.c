/* rekey connections: IKEv2
 *
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 Antony Antony <antony@phenome.org>
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

#include "defs.h"
#include "log.h"
#include "connections.h"
#include "state.h"
#include "timer.h"

struct rekey_how {
	bool background;
	enum sa_type sa_type;
};

static void rekey_state(struct state *st, bool background, struct logger *logger)
{
	if (!background) {
		state_attach(st, logger);
		if (IS_CHILD_SA(st)) {
			struct ike_sa *ike = ike_sa(st, HERE);
			state_attach(&ike->sa, logger);
		}
	}
	event_force(EVENT_v2_REKEY, st);
}

static int rekey_connection(struct connection *c,
			    const struct rekey_how *how,
			    struct logger *logger)
{
	if (c->config->ike_version != IKEv2) {
		llog(RC_LOG, logger, "cannot force rekey of %s connection",
		     c->config->ike_info->version_name);
		return 0;
	}
	struct state *st;
	switch (how->sa_type) {
	case IKE_SA:
		st = state_by_serialno(c->newest_ike_sa);
		break;
	case IPSEC_SA:
		st = state_by_serialno(c->newest_ipsec_sa);
		break;
	default:
		bad_case(how->sa_type);
	}
	if (st == NULL) {
		llog(RC_LOG, logger, "connection does not have %s",
		     c->config->ike_info->sa_type_name[how->sa_type]);
		return 0;
	}
	rekey_state(st, how->background, logger);
	return 1;
}

/*
 * return -1 if nothing was found at all; else total from
 * rekey_connection().
 *
 * XXX: A better strategy is to find the connection root and then use
 * recursion to terminate its clones (which might also be recursive).
 */

static bool rekey_connections_by_name(const char *name,
				      const struct rekey_how *how,
				      struct logger *logger)
{
	/*
	 * Rekey all permenant/instance connections matching name.
	 */
	struct connection_filter cq = {
		.name = name,
		.where = HERE,
	};
	bool found = false;
	while (next_connection_old2new(&cq)) {
		struct connection *c = cq.c;
		if (never_negotiate(c)) {
			continue;
		}
		if (!is_permanent(c) && !is_instance(c)) {
			/* something concrete */
			continue;
		}
		rekey_connection(c, how, logger);
		found = true;
	}
	return found;
}

static int rekey_connections_by_alias(const char *alias,
				      const struct rekey_how *how,
				      struct logger *logger)
{
	int count = 0;

	struct connection_filter by_alias = {
		.alias = alias,
		.where = HERE,
	};
	while (next_connection_new2old(&by_alias)) {
		struct connection *p = by_alias.c;
		count += rekey_connection(p, how, logger);
	}
	return count;
}

void rekey_now(const char *str, enum sa_type sa_type,
	       bool background, struct logger *logger)
{

	/* see if we got a stat enumber or name */
	char *err = NULL;
	int num = strtol(str, &err, 0);

	if (str == err || *err != '\0') {

		struct rekey_how how = {
			.background = background,
			.sa_type = sa_type,
		};

		/*
		 * Loop because more than one may match (template and
		 * instances) but only interested in instances.  Don't
		 * log an error if not found before we checked
		 * aliases.
		 *
		 * connection instances may need more work to work ???
		 */

		if (rekey_connections_by_name(str, &how, logger)) {
			/* logged by rekey_connection_now() */
			dbg("found connections by name");
			return;
		}

		int count = rekey_connections_by_alias(str, &how, logger);
		if (count == 0) {
			llog(RC_UNKNOWN_NAME, logger,
			     "no such connection or aliased connection named \"%s\"", str);
		} else {
			llog(RC_COMMENT, logger,
			     "rekeyed %d connections from aliased connection \"%s\"",
			     count, str);
		}

	} else {
		/* str is a state number - this overrides ike vs ipsec rekey command */
		struct state *st = state_by_serialno(num);
		if (st == NULL) {
			llog(RC_LOG, logger, "can't find SA #%d to rekey", num);
			return;
		}

		struct connection *c = st->st_connection;
		if (IS_IKE_SA(st)) {
			connection_buf cb;
			llog(RC_LOG, logger, "rekeying IKE SA state #%d of connection "PRI_CONNECTION"",
			     num, pri_connection(c, &cb));
			rekey_state(st, background, logger);
		} else {
			connection_buf cb;
			llog(RC_LOG, logger, "rekeying IPsec SA state #%d of connection "PRI_CONNECTION"",
			     num, pri_connection(c, &cb));
			rekey_state(st, background, logger);
		}
	}
}
