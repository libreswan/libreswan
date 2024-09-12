/* showstates, for libreswan
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


#include "whack_showstates.h"

#include "passert.h"
#include "ip_said.h"
#include "show.h"
#include "defs.h"
#include "state.h"
#include "connections.h"
#include "log.h"
#include "iface.h"
#include "timer.h"		/* for state_event_sort() */
#include "kernel.h"		/* for get_ipsec_traffic() */
#include "pending.h"

/*
 * sorting logic is:
 *
 *  name
 *  type
 *  instance#
 *  isakmp_sa (XXX probably wrong)
 *  state serial no#
 */

static int state_compare(const struct state *sl,
			 const struct state *sr)
{
	struct connection *cl = sl->st_connection;
	struct connection *cr = sr->st_connection;

	/* DBG_log("comparing %s to %s", ca->name, cb->name); */

	int order = connection_compare(cl, cr);
	if (order != 0) {
		return order;
	}

	const so_serial_t sol = sl->st_serialno;
	const so_serial_t sor = sr->st_serialno;

	/* sol - sor */
	return (sol < sor ? -1 :
		sol > sor ? 1 :
		0);
}

static int state_cmp(const void *l, const void *r)
{
	const struct state *sl = *(const struct state *const *)l;
	const struct state *sr = *(const struct state *const *)r;
	return state_compare(sl, sr);
}

/*
 * NULL terminated array of state pointers.
 *
 * Returns NULL (rather than an array containing one NULL) when there
 * are no states.
 *
 * Caller is responsible for freeing the structure.
 */

static struct state **sort_states(where_t where)
{
	/* COUNT the number of states. */
	int count = 0;
	{
		struct state_filter sf = { .where = where, };
		while (next_state(NEW2OLD, &sf)) {
			count++;
		}
	}

	if (count == 0) {
		return NULL;
	}

	/*
	 * Create an array of COUNT+1 (NULL terminal) state pointers.
	 */
	struct state **array = alloc_things(struct state *, count + 1, "sorted state");
	{
		int p = 0;

		struct state_filter sf = { .where = where, };
		while (next_state(NEW2OLD, &sf)) {
			struct state *st = sf.st;
			passert(st != NULL);
			array[p++] = st;
		}
		passert(p == count);
		array[p] = NULL;
	}

	/* sort it! */
	qsort(array, count, sizeof(struct state *), state_cmp);

	return array;
}

static size_t jam_readable_humber(struct jambuf *buf, uint64_t num, bool kilos)
{
	uint64_t to_print = num;
	const char *suffix;

	if (!kilos && num < 1024) {
		suffix = "B";
	} else {
		if (!kilos)
			to_print /= 1024;

		if (to_print < 1024) {
			suffix = "KB";
		} else {
			to_print /= 1024;
			suffix = "MB";
		}
	}

	return jam(buf, "%" PRIu64 "%s", to_print, suffix + kilos);
}

/*
 * Note: st cannot be const because we call get_sa_bundle_info on it
 */

static void show_state(struct show *s, struct state *st, const monotime_t now)
{
	/* what the heck is interesting about a state? */
	SHOW_JAMBUF(s, buf) {

		const struct connection *c = st->st_connection;

		jam_so(buf, st->st_serialno);
		jam_string(buf, ": ");
		jam_connection(buf, c);
		jam(buf, ":%u", endpoint_hport(st->st_remote_endpoint));

		if (st->st_iface_endpoint->io->protocol == &ip_protocol_tcp) {
			jam(buf, "(tcp)");
		}
		jam(buf, " %s (%s);", st->st_state->name, st->st_state->story);

		/*
		 * Hunt and peck for events (needs fixing).
		 *
		 * XXX: use two loops as a hack to avoid short term
		 * output churn.  This entire function needs an
		 * update, start listing all events then.
		 */
		const struct state_event *events[] = {
			st->st_v1_event,
			st->st_v1_retransmit_event,
			st->st_v1_send_xauth_event,
			st->st_v2_retransmit_event,
			st->st_v2_liveness_event,
			st->st_v2_addr_change_event,
			st->st_v2_rekey_event,
			st->st_v2_replace_event,
			st->st_v2_expire_event,
		};
		/* remove NULLs */
		unsigned nr_events = 0;
		FOR_EACH_ELEMENT(event, events) {
			if (*event != NULL) {
				events[nr_events] = *event;
				nr_events++;
			}
		}
		/* sort */
		state_event_sort(events, nr_events);
		/* and log */
		for (const struct state_event **event = events; event < events+nr_events; event++) {
			jam_string(buf, " ");
			jam_enum_short(buf, &event_type_names, (*event)->ev_type);
			intmax_t delta = deltasecs(monotimediff((*event)->ev_time, now));
			jam(buf, " in %jds;", delta);
		}

		if (c->established_ike_sa == st->st_serialno ||
		    c->established_child_sa == st->st_serialno) {
			jam(buf, " newest;");
		}

		/* XXX spd-enum */ /* XXX: huh? */
		if (c->negotiating_child_sa == st->st_serialno) {
			jam(buf, " eroute owner;");
		}

		if (IS_IPSEC_SA_ESTABLISHED(st)) {
			jam(buf, " %s "PRI_SO";",
			    c->config->ike_info->parent_sa_name,
			    pri_so(st->st_clonedfrom));
		} else if (st->hidden_variables.st_peer_supports_dpd) {
			/* ??? why is printing -1 better than 0? */
			/* XXX: because config uses -1 for disabled? */
			jam(buf, " lastdpd=%jds(seq in:%u out:%u);",
			    (!is_monotime_epoch(st->st_last_dpd) ?
			     deltasecs(monotimediff(now, st->st_last_dpd)) :
			     (intmax_t)-1),
			    st->st_dpd_seqno,
			    st->st_dpd_expectseqno);
		} else if (dpd_active_locally(st->st_connection) && (st->st_ike_version == IKEv2)) {
			/* stats are on parent sa */
			if (IS_CHILD_SA(st)) {
				struct state *pst = state_by_serialno(st->st_clonedfrom);
				if (pst != NULL) {
					jam(buf, " lastlive=%jds;",
					    deltasecs(monotimediff(now, pst->st_v2_msgid_windows.last_recv)));
				}
			}
		} else if (st->st_ike_version == IKEv1) {
			jam(buf, " nodpd;");
		}

		if (st->st_offloaded_task != NULL &&
		    !st->st_v1_offloaded_task_in_background) {
			jam(buf, " crypto_calculating;");
		} else {
			jam(buf, " idle;");
		}
	}
}

static void show_established_child_details(struct show *s, struct child_sa *child,
					   const monotime_t now)
{
	SHOW_JAMBUF(s, buf) {
		const struct connection *c = child->sa.st_connection;

		jam_so(buf, child->sa.st_serialno);
		jam_string(buf, ": ");
		jam_connection(buf, c);

		/*
		 * XXX - mcr last used is really an attribute of
		 * the connection
		 */
		if (c->negotiating_child_sa == child->sa.st_serialno &&
		    child->sa.st_outbound_count != 0) {
			jam(buf, " used %jds ago;",
			    deltasecs(monotimediff(now , child->sa.st_outbound_time)));
		}

#define add_said(ADDRESS, PROTOCOL, SPI)				\
		{							\
			ip_said s = said_from_address_protocol_spi(ADDRESS, \
								   PROTOCOL, \
								   SPI); \
			jam(buf, " ");					\
			jam_said(buf, &s);				\
		}

		/* SAIDs */

		if (child->sa.st_ah.protocol == &ip_protocol_ah) {
			add_said(c->remote->host.addr,
				 &ip_protocol_ah,
				 child->sa.st_ah.outbound.spi);
			add_said(c->local->host.addr,
				 &ip_protocol_ah,
				 child->sa.st_ah.inbound.spi);
		}
		if (child->sa.st_esp.protocol == &ip_protocol_esp) {
			add_said(c->remote->host.addr,
				 &ip_protocol_esp,
				 child->sa.st_esp.outbound.spi);
			add_said(c->local->host.addr,
				 &ip_protocol_esp,
				 child->sa.st_esp.inbound.spi);
		}
		if (child->sa.st_ipcomp.protocol == &ip_protocol_ipcomp) {
			add_said(c->remote->host.addr,
				 &ip_protocol_ipcomp,
				 child->sa.st_ipcomp.outbound.spi);
			add_said(c->local->host.addr,
				 &ip_protocol_ipcomp,
				 child->sa.st_ipcomp.inbound.spi);
		}
#if defined(KERNEL_XFRM)
		if (child->sa.st_kernel_mode == KERNEL_MODE_TUNNEL) {
			add_said(c->remote->host.addr,
				 &ip_protocol_ipip,
				 (ipsec_spi_t)0);
			add_said(c->local->host.addr,
				 &ip_protocol_ipip,
				 (ipsec_spi_t)0);
		}
#endif
#       undef add_said

		jam(buf, " Traffic:");

		/*
		 * this code is counter-intuitive because counts only
		 * appear in the first SA in a bundle.  So we ascribe
		 * flow in the first SA to all of the SAs in a bundle.
		 *
		 * This leads to incorrect IPCOMP counts since the
		 * number of bytes changes with compression.
		 */

		struct ipsec_proto_info *first_proto_info =
			(child->sa.st_ah.protocol == &ip_protocol_ah ? &child->sa.st_ah :
			 child->sa.st_esp.protocol == &ip_protocol_esp ? &child->sa.st_esp :
			 child->sa.st_ipcomp.protocol == &ip_protocol_ipcomp ? &child->sa.st_ipcomp :
			 NULL);

		bool in_info = get_ipsec_traffic(child, first_proto_info, DIRECTION_INBOUND);
		bool out_info = get_ipsec_traffic(child, first_proto_info, DIRECTION_OUTBOUND);

		if (child->sa.st_ah.protocol == &ip_protocol_ah) {
			if (in_info) {
				jam(buf, " AHin=");
				jam_readable_humber(buf, first_proto_info->inbound.bytes, false);
			}
			if (out_info) {
				jam(buf, " AHout=");
				jam_readable_humber(buf, first_proto_info->outbound.bytes, false);
			}
			jam_humber_uintmax(buf, " AHmax=", c->config->sa_ipsec_max_bytes, "B");
		}
		if (child->sa.st_esp.protocol == &ip_protocol_esp) {
			if (in_info) {
				jam(buf, " ESPin=");
				jam_readable_humber(buf, first_proto_info->inbound.bytes, false);
			}
			if (out_info) {
				jam(buf, " ESPout=");
				jam_readable_humber(buf, first_proto_info->outbound.bytes, false);
			}
			jam_humber_uintmax(buf, " ESPmax=", c->config->sa_ipsec_max_bytes, "B");
		}
		if (child->sa.st_ipcomp.protocol == &ip_protocol_ipcomp) {
			if (in_info) {
				jam(buf, " IPCOMPin=");
				jam_readable_humber(buf, first_proto_info->inbound.bytes, false);
			}
			if (out_info) {
				jam(buf, " IPCOMPout=");
				jam_readable_humber(buf, first_proto_info->outbound.bytes, false);
			}
			jam_humber_uintmax(buf, " IPCOMPmax=", c->config->sa_ipsec_max_bytes, "B");
		}

		jam(buf, " "); /* TBD: trailing blank */
		if (child->sa.st_xauth_username[0] != '\0') {
			jam(buf, "username=%s", child->sa.st_xauth_username);
		}
	}
}

static void show_pending_child_details(struct show *s,
				       const struct ike_sa *ike)
{
	for (struct pending *p = ike->sa.st_pending;
	     p != NULL; p = p->next) {
		/* connection-name state-number [replacing state-number] */
		SHOW_JAMBUF(s, buf) {
			jam_so(buf, ike->sa.st_serialno);
			jam_string(buf, ": pending ");
			jam_string(buf, p->connection->config->ike_info->child_sa_name);
			jam(buf, " for ");
			jam_connection(buf, p->connection);
			if (p->replacing != SOS_NOBODY) {
				jam_string(buf, " replacing ");
				jam_so(buf, p->replacing);
			}
		}
	}
}

void whack_showstates(struct show *s, const monotime_t now)
{
	show_separator(s);
	struct state **array = sort_states(HERE);

	if (array != NULL) {
		/* now print sorted results */
		int i;
		for (i = 0; array[i] != NULL; i++) {
			struct state *st = array[i];
			show_state(s, st, now);
			if (IS_IPSEC_SA_ESTABLISHED(st)) {
				/* print out SPIs if SAs are established */
				struct child_sa *child = pexpect_child_sa(st);
				show_established_child_details(s, child, now);
			}  else if (IS_IKE_SA(st)) {
				/* show any associated pending Phase 2s */
				struct ike_sa *ike = pexpect_ike_sa(st);
				show_pending_child_details(s, ike);
			}

		}
		pfree(array);
	}
}
