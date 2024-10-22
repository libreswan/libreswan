/* ipsec briefconnectionstatus, for libreswan
 *
 * Copyright (C) 2023  Brady Johnson <bradyjoh@redhat.com>
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

#include "whack_briefconnectionstatus.h"
#include "whack_connectionstatus.h"
#include "whack_connection.h"

#include "ike_alg.h"

#include "defs.h"
#include "connections.h"
#include "orient.h"
#include "virtual_ip.h"        /* needs connections.h */
#include "iface.h"
#include "nat_traversal.h"
#include "log.h"
#include "show.h"
#include "crypto.h"		/* for show_ike_alg_connection() */
#include "plutoalg.h"	/* for show_kernel_alg_connection() */
#include "kernel.h"		/* for enum direction */

/*
 * Brief connection status functions
 */

static uint64_t get_child_bytes(const struct connection *c, enum direction direction)
{
	uint64_t bytes = 0;

	/* Code partially copied from whack_trafficstatus.c
	 *
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
	while (next_state(&state_by_connection)) {

		struct state *st = state_by_connection.st;

		if (IS_IKE_SA(st)) {
			continue;
		}

		if (!IS_IPSEC_SA_ESTABLISHED(st)) {
			continue;
		}

		/* note: this mutates *st by calling
		 * get_sa_bundle_info */
		struct child_sa *child = pexpect_child_sa(st);
		struct ipsec_proto_info *first_ipsec_proto =
		    (child->sa.st_esp.protocol == &ip_protocol_esp ? &child->sa.st_esp:
		     child->sa.st_ah.protocol == &ip_protocol_ah ? &child->sa.st_ah :
		     child->sa.st_ipcomp.protocol == &ip_protocol_ipcomp ? &child->sa.st_ipcomp :
		     NULL);
		passert(first_ipsec_proto != NULL);

		// direction should be one of [DIRECTION_INBOUND, DIRECTION_OUTBOUND]
		if (! get_ipsec_traffic(child, first_ipsec_proto, direction)) {
			continue;
		}

		if (direction == DIRECTION_INBOUND) {
			bytes += first_ipsec_proto->inbound.bytes;
		} else if (direction == DIRECTION_OUTBOUND) {
			bytes += first_ipsec_proto->outbound.bytes;
		}

	}

	return bytes;
}

static void show_one_spd_brief(struct show *s,
			 const struct connection *c,
			 const struct spd *spd)
{
	bool local_client_eq_host = false;
	bool remote_client_eq_host = false;

	// jam_end_client() will do nothing if client == host
	if (selector_eq_address(spd->local->client, spd->local->host->addr)) {
		local_client_eq_host = true;
	}
	if (selector_eq_address(spd->remote->client, spd->remote->host->addr)) {
		remote_client_eq_host = true;
	}

	SHOW_JAMBUF(s, buf) {
		if (local_client_eq_host == false && remote_client_eq_host == false) {
			// subnet-to-subnet
			jam_end_client(buf, c, spd->local, LEFT_END, NULL);
			jam_string(buf, " <==> ");
			jam_end_client(buf, c, spd->remote, RIGHT_END, NULL);
		} else if (local_client_eq_host == false) {
			// subnet-to-host
			jam_end_client(buf, c, spd->local, LEFT_END, NULL);
			jam_string(buf, " <==> ");
			jam_end_host(buf, c, spd->remote->host);
		} else if (remote_client_eq_host == false) {
			// host-to-subnet
			jam_end_host(buf, c, spd->local->host);
			jam_string(buf, " <==> ");
			jam_end_client(buf, c, spd->remote, RIGHT_END, NULL);
		} else {
			// if local_client_eq_host == true && remote_client_eq_host == true
			// then its a host-to-host transport tunnel
			jam_end_host(buf, c, spd->local->host);
			jam_string(buf, " <==> ");
			jam_end_host(buf, c, spd->remote->host);
		}

		jam_string(buf, "\tfrom ");
		jam_end_host(buf, c, spd->local->host);
		jam_string(buf, " to ");
		jam_end_host(buf, c, spd->remote->host);
		jam_humber_uintmax(buf, " (", get_child_bytes(c, DIRECTION_INBOUND), "B");
		jam_humber_uintmax(buf, "/", get_child_bytes(c, DIRECTION_OUTBOUND), "B)\t");

		jam_connection_short(buf, c);
		jam(buf, ", reqid="PRI_REQID, pri_reqid(c->child.reqid));
	}
}

static void show_brief_connection_status(struct show *s, const struct connection *c)
{
	/* Show topology. */
	FOR_EACH_ITEM(spd, &c->child.spds) {
		show_one_spd_brief(s, c, spd);
	}
}

static void show_brief_connection_statuses(struct show *s)
{
	int count = 0;
	int active = 0;

	struct connection **connections = sort_connections();
	if (connections != NULL) {
		/* make an array of connections, sort it, and report it */
		for (struct connection **c = connections; *c != NULL; c++) {
			count++;
			if ((*c)->routing.state == RT_ROUTED_TUNNEL ||
			    (*c)->routing.state == RT_UNROUTED_TUNNEL) {
				active++;
				show_brief_connection_status(s, *c);
			}
		}
		pfree(connections);
	}

	show(s, "# Total IPsec connections: loaded %d, active %d",
		     count, active);
}

/* Callback function from whack_briefconnectionstatus() -> whack_connections_bottom_up() */
static unsigned whack_briefconnectionstatus_cb(const struct whack_message *m UNUSED,
					struct show *s,
					struct connection *c)
{
	show_brief_connection_status(s, c);
	return 1; /* the connection counts */
}

/* Main API entry point for brief connection status */
void whack_briefconnectionstatus(const struct whack_message *m, struct show *s)
{
	if (m->name == NULL) {
		// Display all active connections
		show_brief_connection_statuses(s);
		return;
	}

	/* Iterate the connections looking for the m->name connection. Calls the
	 * whack_briefconnectionstatus_cb() callback if found, which directly calls
	 * show_brief_connection_status() */
	whack_connections_bottom_up(m, s, whack_briefconnectionstatus_cb,
				    (struct each) {
					    .log_unknown_name = true,
				    });
}
