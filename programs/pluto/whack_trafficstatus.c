/* routines for state objects, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001, 2013-2017 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009, 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2012 Bram <bram-bcrafjna-erqzvar@spam.wizbit.be>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2015-2018 Antony Antony <antony@phenome.org>
 * Copyright (C) 2015-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2017 Richard Guy Briggs <rgb@tricolour.ca>
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
 * Copyright (C) 2021 Paul Wouters <paul.wouters@aiven.io>
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
#include "connections.h"
#include "state.h"
#include "log.h"
#include "kernel.h"		/* for get_ipsec_traffic() */
#include "show.h"
#include "visit_connection.h"		/* for whack_each_connection() */
#include "whack_trafficstatus.h"
#include "iface.h"

/* note: this mutates *child by calling get_ipsec_traffic */
static void show_child_sa_traffic_object(struct show *s, struct child_sa *child)
{
	const struct connection *c = child->sa.st_connection;

	SHOW_MEMBER(s, serialno, "serial") {
		show_string(s, PRI_SO, pri_so(child->sa.st_serialno));
	}

	SHOW_MEMBER(s, connection, "connection") {
		connection_buf cb;
		show_string(s, "%s%s", c->name, str_connection_suffix(c, &cb));
	}

	if (child->sa.st_xauth_username[0] != '\0') {
		SHOW_MEMBER(s, username, "username") {
			show_string(s, "%s", child->sa.st_xauth_username);
		}
	}

	/* traffic */
	SHOW_MEMBER(s, type_, "type") {
		show_string(s, "%s",
		     (child->sa.st_esp.protocol == &ip_protocol_esp ? "ESP" :
		      child->sa.st_ah.protocol == &ip_protocol_ah ? "AH" :
		      child->sa.st_ipcomp.protocol == &ip_protocol_ipcomp ? "IPCOMP" :
		      "UNKNOWN"));
	}

	if (c->iface->nic_offload && c->config->nic_offload != NIC_OFFLOAD_NO) {
		SHOW_MEMBER(s, nic_offload, "nic-offload") {
			switch (c->config->nic_offload) {
			case NIC_OFFLOAD_PACKET: show_string(s, "%s", "packet"); break;
			case NIC_OFFLOAD_CRYPTO: show_string(s, "%s", "crypto"); break;
			case NIC_OFFLOAD_UNSET: show_string(s, "%s", "UNSET"); break;
			default:
				break;
			}
		}
	}

	SHOW_MEMBER(s, add_time, "add_time") {
		show_raw(s, "%"PRIu64, child->sa.st_esp.add_time);
	}

	struct ipsec_proto_info *first_ipsec_proto = outer_ipsec_proto_info(child);
	passert(first_ipsec_proto != NULL);

	if (get_ipsec_traffic(child, first_ipsec_proto, DIRECTION_INBOUND)) {
		SHOW_MEMBER(s, in_bytes, "inBytes"){
			show_raw(s, "%ju", first_ipsec_proto->inbound.bytes);
		}
	}

	if (get_ipsec_traffic(child, first_ipsec_proto, DIRECTION_OUTBOUND)) {
		SHOW_MEMBER(s, out_bytes, "outBytes") {
			show_raw(s, "%ju", first_ipsec_proto->outbound.bytes);
		}
		if (c->config->sa_ipsec_max_bytes != 0) {
			SHOW_MEMBER(s, max_bytes, "maxBytes") {
				humber_buf hb;
				show_string(s, "%s", str_humber_uintmax("", c->config->sa_ipsec_max_bytes, "B", &hb));
			}
		}
	}

	if (child->sa.st_xauth_username[0] == '\0') {
		SHOW_MEMBER(s, id, "id") {
			id_buf ib;
			show_string(s, "%s", str_id_bytes(&c->remote->host.id, jam_sanitized_bytes, &ib));
		}
	}

	/*
	 * Only one end can have a lease.
	 */
	FOR_EACH_THING(end,
		       /* "this" gave "that" a lease from "this"
			* address pool. */
		       &c->remote,
		       /* "this" received an internal address from
			* "that"; presumably from "that"'s address
			* pool. */
		       &c->local) {
		if (nr_child_leases(*end) > 0) {
			SHOW_MEMBER(s, lease_, "lease") {
				SHOW_ARRAY(s, leases) {
					FOR_EACH_ELEMENT(lease, (*end)->child.lease) {
						if (lease->ip.is_set) {
							/* XXX: lease should be CIDR */
							ip_subnet sn = subnet_from_address(*lease);
							subnet_buf sb;
							show_string(s, "%s", str_subnet(&sn, &sb));
						}
					}
				}
			}
		}
	}
}

/* note: this mutates *child by calling get_ipsec_traffic */
static void show_child_sa_traffic(struct show *s, struct child_sa *child)
{
	if (!pexpect(child != NULL)) {
		return;
	}

	SHOW_STRUCTURED(s, child_sa_traffic) {
		SHOW_OBJECT(s, child_sa_traffic_connection) {
			show_child_sa_traffic_object(s, child);
		}
	}
}

static unsigned whack_trafficstatus_connection(const struct whack_message *m UNUSED,
					       struct show *s,
					       struct connection *c,
					       struct connection_visitor_context *context UNUSED)
{
	if (!can_have_sa(c, CHILD_SA)) {
		return 0; /* the connection doesn't count */
	}

	/*
	 * Look for all states with C as the connection.  And then
	 * from there dump the traffic status of any children.
	 *
	 * Using .established_child_sa or .negotiating_child_sa isn't
	 * sufficient as this won't include established Child SAs that
	 * are in the process of being replaced.
	 */

	struct state_filter state_by_connection = {
		.connection_serialno = c->serialno,
		.search = {
			.order = OLD2NEW,
			.verbose.logger = &global_logger,
			.where = HERE,
		},
	};
	unsigned nr = 0;
	while (next_state(&state_by_connection)) {

		struct state *st = state_by_connection.st;

		if (IS_IKE_SA(st)) {
			continue;
		}

		if (!IS_IPSEC_SA_ESTABLISHED(st)) {
			continue;
		}

		/* whack-log-global - no prefix */
		nr++;
		/* note: this mutates *st by calling
		 * get_ipsec_traffic */
		show_child_sa_traffic(s, pexpect_child_sa(st));
	}

	return nr; /* return count */
}

void whack_trafficstatus(const struct whack_message *m, struct show *s)
{
	if (m->name == NULL) {
		struct connections *connections = sort_connections();
		ITEMS_FOR_EACH(cp, connections) {
			whack_trafficstatus_connection(m, s, (*cp), NULL);
		}
		pfree(connections);
		return;
	}

	whack_connection_trees(m, s, OLD2NEW,
			       whack_trafficstatus_connection, NULL,
			       (struct each) {
				       .log_unknown_name = true,
			       });
}
