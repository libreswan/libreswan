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

static void rekey_by_state(struct state *st)
{
		event_force(EVENT_SA_REKEY, st);
}

static void rekey_by_conn(struct connection *c, enum sa_type sa_type)
{
	struct state *st = NULL;
	if (sa_type == IPSEC_SA) {
		st = state_by_serialno(c->newest_ipsec_sa);
	} else if (sa_type == IKE_SA) {
		st = state_by_serialno(c->newest_isakmp_sa);
	} else {
		libreswan_log("unknown SA type %d", sa_type);
		return;
	}
	if (c->ike_version == IKEv1) {
		/* the behaviour of IKEv1 is not clear, so lets block it for now */
		loglog(RC_FATAL, "--rekey-ike-now and --rekey-ipsec-now requires ikev2");
	} else {
		event_force(EVENT_SA_REKEY, st);
	}
}

static int rekey_connection_now(struct connection *c,  void *arg)
{
	enum sa_type sa_type = *(enum sa_type *)arg;
	int ret = 0;

	set_cur_connection(c);

	if (sa_type == IKE_SA && c->newest_isakmp_sa == SOS_NOBODY) {
		libreswan_log("can not rekey IKE SA, newest IKE SA is SOS_NOBODY");
		ret = 1;
	} else if (sa_type == IPSEC_SA && c->newest_ipsec_sa == SOS_NOBODY) {
		libreswan_log("can not rekey IPsec SA, newest IPsec SA is SOS_NOBODY");
		ret = 1;
	} else {
		rekey_by_conn(c, sa_type);
	}
	reset_cur_connection();

	return ret;
}

void rekey_now(const char *str, enum sa_type sa_type)
{
	/*
	 * Loop because more than one may match (master and instances)
	 * But at least one is required (enforced by conn_by_name).
	 * Don't log an error if not found before we checked aliases
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
					(void)rekey_connection_now(c, &sa_type);
				}
				c = c->ac_next;
			}
		} else {
			int count = foreach_connection_by_alias(str, rekey_connection_now, &sa_type);
			if (count == 0) {
				loglog(RC_UNKNOWN_NAME, "no such connection or aliased connection named \"%s\"", str);
			} else {
				loglog(RC_COMMENT, "terminated %d connections from aliased connection \"%s\"",
					count, str);
			}
		}
	} else {
		/* str is a state number - this overrides ike vs ipsec rekey command */
		struct state *st = state_by_serialno(num);
		struct connection *c = st->st_connection;
		if (IS_IKE_SA(st)) {
			libreswan_log("rekeying IKE SA state #%d of connection %s", num, c->name);
			rekey_by_state(st);
		} else {
			libreswan_log("rekeying IPsec SA state #%d of connection %s", num, c->name);
			rekey_by_state(st);
		}
	}
}
