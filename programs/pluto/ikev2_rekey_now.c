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
#include "state_db.h"

struct rekey_how {
	bool background;
	enum sa_type sa_type;
};

static void rekey_state(struct state *st, struct fd *whackfd, bool background)
{
	if (!background) {
		/* XXX: something better */
		close_any(&st->st_logger->object_whackfd);
		st->st_logger->object_whackfd = dup_any(whackfd);
	}
	event_force(EVENT_SA_REKEY, st);
}

static int rekey_connection_now(struct connection *c,
				struct fd *whackfd,
				void *arg)
{
	if (c->ike_version != IKEv2) {
		log_global(RC_LOG, whackfd, "cannot force rekey of %s connection",
			   enum_name(&ike_version_names, c->ike_version));
		return 1;
	}
	struct rekey_how *how = arg;
	struct state *st;
	switch (how->sa_type) {
	case IKE_SA:
		st = state_by_serialno(c->newest_isakmp_sa);
		break;
	case IPSEC_SA:
		st = state_by_serialno(c->newest_ipsec_sa);
		break;
	default:
		bad_case(how->sa_type);
	}
	if (st == NULL) {
		log_global(RC_LOG, whackfd, "connection does not have %s",
			   enum_enum_name(&sa_type_names, c->ike_version, how->sa_type));
		return 1;
	}
	rekey_state(st, whackfd, how->background);
	return 0;
}

void rekey_now(const char *str, enum sa_type sa_type,
	       struct fd *whackfd, bool background)
{
	struct rekey_how how = {
		.background = background,
		.sa_type = sa_type,
	};

	/*
	 * Loop because more than one may match (template and
	 * instances) But at least one is required (enforced by
	 * conn_by_name).  Don't log an error if not found before we
	 * checked aliases
	 *
	 * connection instances may need more work to work ???
	 */

	/* see if we got a stat enumber or name */
	char *err = NULL;
	int num = strtol(str, &err, 0);

	if (str == err || *err != '\0') {

		/* str is a connection name */
		struct connection *c = conn_by_name(str, true/*strict*/);
		if (c != NULL) {
			while (c != NULL) {
				if (streq(c->name, str) &&
				    c->kind >= CK_PERMANENT &&
				    !NEVER_NEGOTIATE(c->policy)) {
					rekey_connection_now(c, whackfd, &how);
				}
				c = c->ac_next;
			}
		} else {
			int count = foreach_connection_by_alias(str, whackfd,
								rekey_connection_now,
								&how);
			if (count == 0) {
				log_global(RC_UNKNOWN_NAME, whackfd,
					   "no such connection or aliased connection named \"%s\"", str);
			} else {
				log_global(RC_COMMENT, whackfd,
					   "terminated %d connections from aliased connection \"%s\"",
					   count, str);
			}
		}
	} else {
		/* str is a state number - this overrides ike vs ipsec rekey command */
		struct state *st = state_by_serialno(num);
		if (st == NULL) {
			log_global(RC_LOG, whackfd, "can't find SA #%d to rekey", num);
			return;
		}

		struct connection *c = st->st_connection;
		if (IS_IKE_SA(st)) {
			connection_buf cb;
			log_global(RC_LOG, whackfd, "rekeying IKE SA state #%d of connection "PRI_CONNECTION"",
				   num, pri_connection(c, &cb));
			rekey_state(st, whackfd, background);
		} else {
			connection_buf cb;
			log_global(RC_LOG, whackfd, "rekeying IPsec SA state #%d of connection "PRI_CONNECTION"",
				   num, pri_connection(c, &cb));
			rekey_state(st, whackfd, background);
		}
	}
}
