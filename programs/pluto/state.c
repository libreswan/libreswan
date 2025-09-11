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

#include "constants.h"
#include "defs.h"
#ifdef USE_PAM_AUTH
#include "pam_auth.h"		/* for pam_auth_cancel() */
#endif
#include "connections.h"	/* needs id.h */
#include "state.h"
#include "state_db.h"
#include "ikev1_msgid.h"
#include "log.h"
#include "rnd.h"
#include "demux.h"	/* needs packet.h */
#include "pending.h"
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "crypt_symkey.h"
#include "crypt_kem.h"		/* for free_kem_initiator(), free_kem_responder() */
#include "ikev2.h"
#include "secrets.h"    	/* for pubkey_delref() */
#include "enum_names.h"
#include "crypt_dh.h"
#include "kernel.h"
#include "iface.h"
#include "ikev1_send.h"		/* for free_v1_messages() */
#include "ikev2_send.h"		/* for free_v2_messages() */
#include "pluto_stats.h"
#include "ip_info.h"
#include "revival.h"
#include "ikev1.h"			/* for established_isakmp_for_state() */
#include "ikev1_delete.h"	/* for send_n_log_v1_delete() */
#include "ikev2_delete.h"	/* for record_v2_delete() */
#include "orient.h"
#include "ikev2_proposals.h"		/* for free_ikev2_proposal() */
#include "ikev2_eap.h"			/* for free_eap_state() */
#include "fips_mode.h"			/* for is_fips_mode() */
#include "show.h"
#include "ikev1_replace.h"
#include "ikev2_replace.h"
#include "routing.h"
#include "terminate.h"
#include "whack_shutdown.h"		/* for exiting_pluto; */
#include "ikev2_states.h"
#include "crypt_cipher.h"		/* for cipher_context_destroy() */
#include "ddos.h"
#include "config_setup.h"

static void delete_state(struct state *st);

bool pluto_uniqueIDs; /* see plutomain and config_setup.[hc] */

/*
 * Handle for each and every state.
 *
 * XXX: The array finite_states[] is something of a hack until it is
 * figured out if the array or separate objects for each state is
 * better.
 */

static struct finite_state state_undefined = {
	.kind = STATE_UNDEFINED,
	.name = "STATE_UNDEFINED",
	.short_name = "UNDEFINED",
	.story = "not defined - either very new or dead (internal)",
	.category = CAT_IGNORE,
};

#ifdef USE_IKEv1
static struct finite_state state_ikev1_roof = {
	.kind = STATE_IKEv1_ROOF,
	.name = "STATE_IKEv1_ROOF",
	.short_name = "IKEv1_ROOF",
	.story = "invalid state - IKEv1 roof",
	.category = CAT_IGNORE,
};
#endif

static struct finite_state state_ikev2_roof = {
	.kind = STATE_IKEv2_ROOF,
	.name = "STATE_IKEv2_ROOF",
	.short_name = "IKEv2_ROOF",
	.story = "invalid state - IKEv2 roof",
	.category = CAT_IGNORE,
};

const struct finite_state *finite_states[STATE_IKE_ROOF] = {
	[STATE_UNDEFINED] = &state_undefined,
#ifdef USE_IKEv1
	[STATE_IKEv1_ROOF] = &state_ikev1_roof,
#endif
	[STATE_IKEv2_ROOF] = &state_ikev2_roof,
};

void jam_finite_state(struct jambuf *buf, const struct finite_state *fs)
{
	if (fs == NULL) {
		jam_string(buf, "NULL-FINITE_STATE");
	} else {
		jam(buf, "%s:", fs->short_name);
		jam(buf, " category: ");
		jam_enum_short(buf, &state_category_names, fs->category);
		switch (fs->ike_version) {
		case IKEv1:
			/* no enum_name available? */
			jam(buf, "; v1.flags: "PRI_LSET, fs->v1.flags);
			break;
		case IKEv2:
			jam(buf, "; v2.secured: %s", bool_str(fs->v2.secured));
			break;
		}
	}
}

/*
 * Track the categories and for ESTABLISHED, also track if the SA was
 * AUTHENTICATED or ANONYMOUS.  Among other things used for DDoS
 * tracking.
 *
 * Hack: CAT_T is unsigned (like values it gets compared against), and
 * assumed to be implemented using 2's complement.  However, the value
 * is printed as a "signed" value - so that should underflow occur it
 * is displayed as -ve (rather than a huge positive).
 */

typedef unsigned long cat_t;
#define PRI_CAT "%ld"

static cat_t cat_count[CAT_ROOF] = { 0 };

/* see .st_ikev2_anon, enum would be better */
#define CAT_AUTHENTICATED false
#define CAT_ANONYMOUS true
static cat_t cat_count_ike_sa[2];
static cat_t cat_count_child_sa[2];
static cat_t state_count[STATE_IKE_ROOF];

cat_t total_halfopen_ike(void)
{
	return cat_count[CAT_HALF_OPEN_IKE_SA];
}

static cat_t total_ike_sa(void)
{
	return (cat_count[CAT_HALF_OPEN_IKE_SA] +
		cat_count[CAT_OPEN_IKE_SA] +
		cat_count[CAT_ESTABLISHED_IKE_SA]);
}

static cat_t total_sa(void)
{
	return total_ike_sa() + cat_count[CAT_ESTABLISHED_CHILD_SA];
}

/*
 * Count everything except STATE_UNDEFINED (CAT_IGNORE) et.al. All
 * states start and end in those states.
 */
static void update_state_stat(struct state *st,
			      const struct finite_state *state,
			      int delta)
{
	if (state->category != CAT_IGNORE) {
		state_count[state->kind] += delta;
		cat_count[state->category] += delta;
		/*
		 * When deleting, st->st_connection can be NULL, so we
		 * cannot look at the policy to determine
		 * anonymity. We therefore use a scratchpad at
		 * st->st_ikev2_anon (a bool) which is copied from
		 * parent to child states
		 */
		switch (state->category) {
		case CAT_ESTABLISHED_IKE_SA:
			cat_count_ike_sa[st->st_ikev2_anon] += delta;
			break;
		case CAT_ESTABLISHED_CHILD_SA:
			cat_count_child_sa[st->st_ikev2_anon] += delta;
			break;
		default: /* ignore */
			break;
		}
	}
}

static void update_state_stats(struct state *st,
			       const struct finite_state *old_state,
			       const struct finite_state *new_state)
{
	/* catch / log unexpected cases */
	pexpect(old_state->category != 0);
	pexpect(new_state->category != 0);

	update_state_stat(st, old_state, -1);
	update_state_stat(st, new_state, +1);

	/*
	 * ??? this seems expensive: on each state change we do this
	 * whole rigamarole.
	 *
	 * XXX: It's an assertion check only executed when debugging.
	 */
	if (LDBGP(DBG_BASE, st->logger)) {
		name_buf ocb, ncb;
		LDBG_log(st->logger, "%s state "PRI_SO": %s(%s) => %s(%s)",
			 (IS_IKE_SA(st) ? "parent" : "child"),
			 pri_so(st->st_serialno),
			 old_state->short_name,
			 str_enum_long(&state_category_names, old_state->category, &ocb),
			 new_state->short_name,
			 str_enum_long(&state_category_names, new_state->category, &ncb));

		cat_t category_states = 0;
		for (unsigned cat = 0; cat < elemsof(cat_count); cat++) {
			category_states += cat_count[cat];
		}

		cat_t count_states = 0;
		for (unsigned s = 0; s < elemsof(state_count); s++) {
			count_states += state_count[s];
		}

		if (category_states != count_states) {
			/* not really ST's fault? */
			llog_pexpect(st->logger, HERE,
				     "category states: "PRI_CAT" != count states: "PRI_CAT,
				     category_states, count_states);
		}

		if (cat_count[CAT_ESTABLISHED_IKE_SA] !=
		    (cat_count_ike_sa[CAT_AUTHENTICATED] + cat_count_ike_sa[CAT_ANONYMOUS])) {
			/* not really ST's fault? */
			llog_pexpect(st->logger, HERE,
				     "established IKE SA: "PRI_CAT" != authenticated: "PRI_CAT" + anoynmous: "PRI_CAT,
				     cat_count[CAT_ESTABLISHED_IKE_SA],
				     cat_count_ike_sa[CAT_AUTHENTICATED],
				     cat_count_ike_sa[CAT_ANONYMOUS]);
		}

		if (cat_count[CAT_ESTABLISHED_CHILD_SA] !=
		    (cat_count_child_sa[CAT_AUTHENTICATED] + cat_count_child_sa[CAT_ANONYMOUS])) {
			/* not really ST's fault? */
			llog_pexpect(st->logger, HERE,
				     "established CHILD SA: "PRI_CAT" != authenticated: "PRI_CAT" + anoynmous: "PRI_CAT,
				     cat_count[CAT_ESTABLISHED_CHILD_SA],
				     cat_count_child_sa[CAT_AUTHENTICATED],
				     cat_count_child_sa[CAT_ANONYMOUS]);
		}
	}
}

/*
 * This file has the functions that handle the
 * state hash table and the Message ID list.
 */

static void change_state(struct state *st, enum state_kind new_state_kind)
{
	const struct finite_state *old_state = st->st_state;
	const struct finite_state *new_state = finite_states[new_state_kind];
	passert(new_state != NULL);
	if (new_state != old_state) {
		update_state_stats(st, old_state, new_state);
		binlog_state(st, new_state_kind /* XXX */);
		ldbg(st->logger, "transition %s->%s", old_state->short_name, new_state->short_name);
		st->st_state = new_state;
	}
}

void change_v1_state(struct state *st, enum state_kind new_state_kind)
{
	change_state(st, new_state_kind);
}

void change_v2_state(struct state *st)
{
	if (pexpect(st->st_v2_transition != NULL)) {
		change_state(st, st->st_v2_transition->to->kind);
#if 0
		/*
		 * Breaks IKE_AUTH where IKE SA changes state twice:
		 * mid transition when authentication is established;
		 * and at the end by success_v2_state_transition()).
		 */
		 st->st_v2_transition = NULL;
#endif
	}
}

/*
 * Get the IKE SA managing the security association.
 */

struct ike_sa *ike_sa(struct state *st, where_t where)
{
	if (st != NULL && IS_CHILD_SA(st)) {
		struct state *pst = state_by_serialno(st->st_clonedfrom);
		if (pst == NULL) {
			llog_pexpect(st->logger, where,
				     "child state missing parent state "PRI_SO,
				     pri_so(st->st_clonedfrom));
			/* about to crash with an NPE? */
			return NULL;
		}
		return (struct ike_sa*) pst;
	}
	return (struct ike_sa*) st;
}

struct ike_sa *parent_sa_where(struct child_sa *child, where_t where)
{
	if (child == NULL) {
		return NULL;
	}

	/* the definition of a child */
	if (!IS_CHILD_SA(&child->sa)) {
		llog_passert(child->sa.logger, where,
			     "Child SA is not a child");
	}

	struct ike_sa *parent = ike_sa_by_serialno(child->sa.st_clonedfrom); /* could be NULL */
	if (parent != NULL) {
		return parent;
	}

	if (child->sa.st_ike_version == IKEv1) {
		ldbg(child->sa.logger,
		     "IKEv1 IPsec SA "PRI_SO" missing ISAKMP SA "PRI_SO" "PRI_WHERE,
		     pri_so(child->sa.st_serialno),
		     pri_so(child->sa.st_clonedfrom),
		     pri_where(where));
		return NULL;
	}

	llog_pexpect(child->sa.logger, where,
		     "child state missing parent state "PRI_SO,
		     pri_so(child->sa.st_clonedfrom));
	/* about to crash? */
	return NULL;
}

struct ike_sa *isakmp_sa_where(struct child_sa *child, where_t where)
{
	if (child == NULL) {
		return NULL;
	}

	if (!PEXPECT(child->sa.logger, child->sa.st_ike_version == IKEv1)) {
		return NULL;
	}

	return parent_sa_where(child, where);
}

struct ike_sa *ike_sa_where(struct child_sa *child, where_t where)
{
	if (child == NULL) {
		return NULL;
	}

	if (!PEXPECT(child->sa.logger, child->sa.st_ike_version >= IKEv2)) {
		return NULL;
	}

	return parent_sa_where(child, where);
}

struct ike_sa *pexpect_ike_sa_where(struct state *st, where_t where)
{
	if (st == NULL) {
		return NULL;
	}
	if (!IS_IKE_SA(st)) {
		llog_pexpect(st->logger, where, "state "PRI_SO" is not an IKE SA",
			     pri_so(st->st_serialno));
		return NULL; /* kaboom */
	}
	return (struct ike_sa*) st;
}

struct child_sa *pexpect_child_sa_where(struct state *st, where_t where)
{
	if (st == NULL) {
		return NULL;
	}
	if (!IS_CHILD_SA(st)) {
		/* In IKEv2 a re-keying IKE SA starts life as a child */
		llog_pexpect(st->logger, where, "state "PRI_SO" is not a CHILD",
			     pri_so(st->st_serialno));
		return NULL; /* kaboom */
	}
	return (struct child_sa*) st;
}

/*
 * Get a state object.
 *
 * Caller must schedule an event for this object so that it doesn't
 * leak.  Caller must add_state_to_db().
 */

static struct state *new_state(struct connection *c,
			       so_serial_t clonedfrom,
			       struct iface_endpoint *local_iface_endpoint,
			       ip_endpoint remote_endpoint,
			       const ike_spi_t ike_initiator_spi,
			       const ike_spi_t ike_responder_spi,
			       enum sa_kind sa_kind,
			       enum sa_role sa_role,
			       where_t where)
{
	union sas {
		struct child_sa child;
		struct ike_sa ike;
		struct state st;
	};
	union sas *sap = alloc_thing(union sas, "struct state");
	passert(&sap->st == &sap->child.sa);
	passert(&sap->st == &sap->ike.sa);
	struct state *st = &sap->st;

	/*
	 * Create a minmally viable logger ASAP (which requires a
	 * minimally viable state).
	 *
	 * At the time of writing that was: .st_serialno, .st_state,
	 * and .st_connection.
	 *
	 * See github#2338 (.st_state was being dereferenced by the
	 * logger) causing state_attach(), which debug-logs, to core
	 * dump.
	 *
	 * Note:
	 *
	 * There's a catch-22 with .st_connection.  It can't be set to
	 * addref(st->logger) because there isn't yet a logger.  Get
	 * around this by setting .st_connection to c and then, later,
	 * updating it with the reference.
	 *
	 * delete_state() has a similar problem.
	 */

	/* Determine the serialno.  */
	static so_serial_t state_serialno;
	state_serialno++;
	passert(state_serialno > 0); /* can't overflow */
	st->st_serialno = state_serialno;

	st->st_state = &state_undefined;
	st->st_connection = c; /* HACK: can't yet call addref(st->logger) */

	st->logger = alloc_logger(st, &logger_state_vec,
				  c->logger->debugging,
				  where);

	/* the logger is minimally viable */

	/* causes first (debug-log) gasp */
	state_attach(st, c->logger);

	/* fix HACK: above with real reference */
	st->st_connection = connection_addref(c, st->logger);
	state_db_init_state(st); /* hash called below */

	/* parameter values */
	st->st_clonedfrom = clonedfrom;
	st->st_inception = realnow();
	st->st_sa_role = sa_role;
	st->st_sa_kind_when_established = sa_kind;

	st->st_ike_spis.initiator = ike_initiator_spi;
	if (sa_kind == IKE_SA && sa_role == SA_INITIATOR &&
	    impair.ike_initiator_spi.enabled) {
		uintmax_t v = impair.ike_initiator_spi.value;
		llog(RC_LOG, st->logger, "IMPAIR: forcing IKE initiator SPI to 0x%jx", v);
		hton_chunk(v, THING_AS_CHUNK(st->st_ike_spis.initiator));
	}

	st->st_ike_spis.responder = ike_responder_spi;
	if (sa_kind == IKE_SA && sa_role == SA_RESPONDER &&
	    impair.ike_responder_spi.enabled) {
		uintmax_t v = impair.ike_responder_spi.value;
		llog(RC_LOG, st->logger, "IMPAIR: forcing IKE responder SPI to 0x%jx", v);
		hton_chunk(v, THING_AS_CHUNK(st->st_ike_spis.responder));
	}

	st->hidden_variables.st_nat_oa = ipv4_info.address.zero;
	st->hidden_variables.st_natd = ipv4_info.address.zero;
	st->st_remote_endpoint = remote_endpoint;
	st->st_iface_endpoint = local_iface_endpoint;

	ldbg(st->logger,
	     "creating state object "PRI_SO" at %p",
	     pri_so(st->st_serialno), (void *) st);

	state_db_add(st);
	pstat_sa_started(st);

	return st;
}

static bool get_initiator_endpoints(struct connection *c,
				    ip_endpoint *remote_endpoint,
				    struct iface_endpoint **local_iface_endpoint)
{
	PASSERT(c->logger, oriented(c));
	(*remote_endpoint) = unset_endpoint;
	(*local_iface_endpoint) = NULL;

	/*
	 * reset our choice of interface
	 *
	 * XXX: why? suspect this has the side effect of restoring /
	 * updating connection's ends?
	 *
	 * No.  More evil.
	 *
	 * When NATed, the revival code updates the connection's
	 * .local.host.port (to the NAT port) and .remote.host.encap
	 * (to true).  The orient below then sees this causing the
	 * connection to switch to the encapsulated interface so that
	 * the first message goes out on that.
	 *
	 * See github/1094 and ikev2-revive-through-nat-01-down.
	 */

	/* 1,3,5,7-> 1; 0,2,4,6->0 */
	unsigned mod_revival = (c->revival.attempt % 2);

	ip_address remote_addr = (c->redirect.attempt > 0 ? c->redirect.ip :
				  c->remote->host.first_addr);

	if (c->revival.attempt > 0 &&
	    c->revival.local != NULL &&
	    c->revival.remote.ip.is_set) {

		ldbg(c->logger, "TCP: using revival revival endpoints");
		/* transfer (with some logging) */
		(*remote_endpoint) = c->revival.remote;
		c->revival.remote = unset_endpoint;
		(*local_iface_endpoint) = iface_endpoint_addref(c->revival.local);
		iface_endpoint_delref(&c->revival.local);

	} else if ((c->local->config->host.iketcp == IKE_TCP_NO) ||
		   (c->local->config->host.iketcp == IKE_TCP_FALLBACK && mod_revival == 0)) {

		ldbg(c->logger, "TCP: using UDP endpoints");
		if (!pluto_listen_udp) {
			llog(RC_LOG, c->logger,
			     "initiating UDP requires listen-udp=yes");
			return false;
		}

		(*remote_endpoint) =
			endpoint_from_address_protocol_port(remote_addr, &ip_protocol_udp,
							    ip_hport(c->remote->host.port));
		ip_endpoint local_endpoint =
			endpoint_from_address_protocol_port(c->iface->local_address,
							    &ip_protocol_udp, local_host_port(c));
		(*local_iface_endpoint) = find_iface_endpoint_by_local_endpoint(local_endpoint);

	} else {

		address_buf ab;
		ldbg(c->logger, "TCP: open TCP connection to TCP %s with port "PRI_HPORT,
			str_address(&c->remote->host.first_addr, &ab),
			pri_hport(c->config->remote_tcpport));
		PEXPECT(c->logger, ((c->local->config->host.iketcp == IKE_TCP_ONLY) ||
				    (c->local->config->host.iketcp == IKE_TCP_FALLBACK && mod_revival == 1)));
		(*remote_endpoint) =
			endpoint_from_address_protocol_port(remote_addr, &ip_protocol_tcp,
							    c->config->remote_tcpport);

		/* create new-from-old first; must delref; blocking call */
		(*local_iface_endpoint) =
			connect_to_tcp_endpoint(c->iface, (*remote_endpoint), c->logger);
		if ((*local_iface_endpoint) == NULL) {
			return false;
		}
	}

	endpoint_buf lb, rb;
	ldbg(c->logger,
	     "in %s with local endpoint %s and remote endpoint set to %s",
	     __func__,
	     str_endpoint(&(*local_iface_endpoint)->local_endpoint, &lb),
	     str_endpoint(remote_endpoint, &rb));
	return true;
}

static void get_responder_endpoints(const struct msg_digest *md,
				    ip_endpoint *remote_endpoint,
				    struct iface_endpoint **local_iface_endpoint)
{
	(*remote_endpoint) = md->sender;
	(*local_iface_endpoint) = iface_endpoint_addref(md->iface);
}

struct ike_sa *new_v1_istate(struct connection *c,
			     enum state_kind new_state_kind)
{
	ip_endpoint remote_endpoint;
	struct iface_endpoint *local_iface_endpoint;
	if (!get_initiator_endpoints(c, &remote_endpoint, &local_iface_endpoint)) {
		return NULL;
	}

	struct ike_sa *parent =
		pexpect_parent_sa(new_state(c, SOS_NOBODY,
					    local_iface_endpoint, remote_endpoint,
					    ike_initiator_spi(), zero_ike_spi,
					    IKE_SA, SA_INITIATOR, HERE));
	change_v1_state(&parent->sa, new_state_kind);

	if (c->local->host.config->xauth.client) {
		if (c->local->host.config->xauth.username != NULL) {
			jam_str(parent->sa.st_xauth_username,
				sizeof(parent->sa.st_xauth_username),
				c->local->host.config->xauth.username);
		}
	}

	return parent;
}

struct ike_sa *new_v1_rstate(struct connection *c, struct msg_digest *md)
{
	ip_endpoint remote_endpoint;
	struct iface_endpoint *local_iface_endpoint;
	get_responder_endpoints(md, &remote_endpoint, &local_iface_endpoint);
	struct ike_sa *parent =
		pexpect_parent_sa(new_state(c, SOS_NOBODY,
					    local_iface_endpoint, remote_endpoint,
					    md->hdr.isa_ike_spis.initiator,
					    ike_responder_spi(&md->sender, md->logger),
					    IKE_SA, SA_RESPONDER, HERE));

	return parent;
}

static struct ike_sa *new_v2_ike_sa(struct connection *c,
				    enum sa_role sa_role,
				    const struct finite_state *state,
				    struct iface_endpoint *local_iface_endpoint,
				    ip_endpoint remote_endpoint,
				    const ike_spi_t ike_initiator_spi,
				    const ike_spi_t ike_responder_spi)
{
	struct state *st = new_state(c, SOS_NOBODY,
				     local_iface_endpoint, remote_endpoint,
				     ike_initiator_spi, ike_responder_spi,
				     IKE_SA, sa_role, HERE);
	struct ike_sa *ike = pexpect_ike_sa(st);
	v2_msgid_init_ike(ike);
	change_state(&ike->sa, state->kind);
	event_schedule(EVENT_v2_DISCARD, EXCHANGE_TIMEOUT_DELAY, &ike->sa);
	return ike;
}

struct ike_sa *new_v2_ike_sa_initiator(struct connection *c)
{
	ip_endpoint remote_endpoint;
	struct iface_endpoint *local_iface_endpoint;
	if (!get_initiator_endpoints(c, &remote_endpoint, &local_iface_endpoint)) {
		return NULL;
	}

	struct ike_sa *ike = new_v2_ike_sa(c, SA_INITIATOR, &state_v2_IKE_SA_INIT_I0,
					   local_iface_endpoint, remote_endpoint,
					   ike_initiator_spi(), zero_ike_spi);
	return ike;
}

struct ike_sa *new_v2_ike_sa_responder(struct connection *c,
				       const struct finite_state *state,
				       struct msg_digest *md)
{
	ip_endpoint remote_endpoint;
	struct iface_endpoint *local_iface_endpoint;
	get_responder_endpoints(md, &remote_endpoint, &local_iface_endpoint);

	return new_v2_ike_sa(c, SA_RESPONDER, state,
			     local_iface_endpoint, remote_endpoint,
			     md->hdr.isa_ike_spis.initiator,
			     ike_responder_spi(&md->sender, md->logger));
}

/*
 * Initialize the state table.
 */
void init_states(void)
{
	/* did IKEv1/IKEv2 do their job? */
	for (unsigned kind = 0; kind < elemsof(finite_states); kind++) {
		const struct finite_state *s = finite_states[kind];
		passert(s != NULL);
		passert(s->name != NULL);
		passert(s->short_name != NULL);
		passert(s->story != NULL);
		passert(s->kind == kind);
		passert(s->category != CAT_UNKNOWN);
	}
}

static void flush_incomplete_children(struct ike_sa *ike)
{
	struct state_filter sf = {
		.clonedfrom = ike->sa.st_serialno,
		.search = {
			.order = OLD2NEW,
			.verbose.logger = &global_logger,
			.where = HERE,
		},
	};
	while (next_state(&sf)) {
		struct child_sa *child = pexpect_child_sa(sf.st);
		switch (child->sa.st_ike_version) {
		case IKEv1:
			if (!IS_IPSEC_SA_ESTABLISHED(&child->sa)) {
				state_attach(&child->sa, ike->sa.logger);
				connection_teardown_child(&child, REASON_DELETED, HERE);
			}
			continue;
		case IKEv2:
			state_attach(&child->sa, ike->sa.logger);
			connection_teardown_child(&child, REASON_DELETED, HERE);
			continue;
		}
		bad_enum(ike->sa.logger, &ike_version_names, child->sa.st_ike_version);
	}
}

void delete_child_sa(struct child_sa **child)
{
	if (pbad(child == NULL) ||
	    pbad((*child) == NULL)) {
		return;
	}

	struct state *st = &(*child)->sa;
	*child = NULL;
	on_delete(st, skip_send_delete);
	delete_state(st);
}

void delete_ike_sa(struct ike_sa **ike)
{
	if (pbad(ike == NULL) ||
	    pbad((*ike) == NULL)) {
		return;
	}

	struct state *st = &(*ike)->sa;
	*ike = NULL;
	on_delete(st, skip_send_delete);
	delete_state(st);
}

static void update_and_log_traffic(struct child_sa *child, const char *name,
				   struct ipsec_proto_info *proto,
				   struct pstats_bytes *pstats)
{
	/* pull in the traffic counters into state before they're lost */
	if (!get_ipsec_traffic(child, proto, DIRECTION_OUTBOUND)) {
		llog_sa(RC_LOG, child, "failed to pull traffic counters from outbound IPsec SA");
	}
	if (!get_ipsec_traffic(child, proto, DIRECTION_INBOUND)) {
		llog_sa(RC_LOG, child, "failed to pull traffic counters from inbound IPsec SA");
	}

	LLOG_JAMBUF(RC_LOG, child->sa.logger, buf) {
		jam(buf, "%s traffic information:", name);
		/* in */
		jam_string(buf, " in=");
		jam_humber(buf, proto->inbound.bytes);
		jam_string(buf, "B");
		/* out */
		jam_string(buf, " out=");
		jam_humber(buf, proto->outbound.bytes);
		jam_string(buf, "B");
		if (child->sa.st_xauth_username[0] != '\0') {
			jam_string(buf, " XAUTHuser=");
			jam_string(buf, child->sa.st_xauth_username);
		}
	}

	pstats->in += proto->inbound.bytes;
	pstats->out += proto->outbound.bytes;
}

void llog_sa_delete_n_send(struct ike_sa *ike, struct state *st)
{
	PEXPECT(st->logger, !st->st_on_delete.skip_log_message);
	LLOG_JAMBUF(RC_LOG, st->logger, buf) {
		/* deleting {IKE,Child,IPsec,ISAKMP} SA */
		jam_string(buf, "deleting ");
		jam_string(buf, state_sa_name(st));
		/* (STATE-NAME) XXX: drop this? */
		jam_string(buf, " (");
		jam_string(buf, st->st_state->short_name);
		jam_string(buf, ")");
		/* aged NNNs */
		jam_string(buf, " aged ");
		jam_deltatime(buf, realtime_diff(realnow(), st->st_inception));
		jam_string(buf, "s");
		if (ike == NULL) {
			jam_string(buf, " and NOT sending notification");
			if (IS_CHILD_SA_ESTABLISHED(st)) {
				jam_string(buf, " (");
				jam_string(buf, st->st_connection->config->ike_info->parent_sa_name);
				jam_string(buf, " was ");
				jam_so(buf, st->st_clonedfrom);
				jam_string(buf, ")");
			}
		} else if (ike->sa.st_connection != st->st_connection) {
			jam_string(buf, " and sending notification using ");
			jam_string(buf, st->st_connection->config->ike_info->parent_sa_name);
			jam_string(buf, " ");
			jam_prefix(buf, ike->sa.logger);
		} else if (st->st_clonedfrom != SOS_NOBODY) {
			jam_string(buf, " and sending notification using ");
			jam_string(buf, st->st_connection->config->ike_info->parent_sa_name);
			jam_string(buf, " ");
			jam_so(buf, ike->sa.st_serialno);
		} else {
			jam_string(buf, " and sending notification");
		}
	}
	on_delete(st, skip_log_message);
}

/* delete a state object */
void delete_state(struct state *st)
{
	ldbg(st->logger, "%s() skipping log_message:%s",
	     __func__,
	     bool_str(st->st_on_delete.skip_log_message));

	/* must be as set by delete_{ike,child}_sa() */
	PEXPECT(st->logger, st->st_on_delete.skip_send_delete);

	/*
	 * An IKEv2 IKE SA can only be deleted after all children.
	 */
	if (st->st_connection->config->ike_version == IKEv2 &&
	    IS_IKE_SA(st) &&
	    LDBGP(DBG_BASE, st->logger)) {
		struct state_filter sf = {
			.clonedfrom = st->st_serialno,
			.search = {
				.order = OLD2NEW,
				.verbose.logger = &global_logger,
				.where = HERE,
			},
		};
		while (next_state(&sf)) {
			state_buf sb;
			barf((LDBGP(DBG_BASE, st->logger) ? PASSERT_STREAM : PEXPECT_STREAM),
			     st->logger, /*ignore-exit-code*/0, HERE,
			     "unexpected Child SA "PRI_STATE,
			     pri_state(sf.st, &sb));
		}
	}

	if (!st->st_on_delete.skip_log_message) {
		if (st->st_ike_version == IKEv1) {
			/* actually logs NOT sending delete */
			llog_sa_delete_n_send(NULL, st);
		} else if (IS_PARENT_SA(st)) {
			llog(RC_LOG, st->logger, "deleting IKE SA (%s)",
			     st->st_state->story);
		}
		on_delete(st, skip_log_message);
	}

	pstat_sa_deleted(st);

	/*
	 * Even though code tries to always track CPU time, only log
	 * it when debugging - values range from very approximate to
	 * (in the case of IKEv1) simply wrong.
	 */
	if (LDBGP(DBG_CPU_USAGE, st->logger) || LDBGP(DBG_BASE, st->logger)) {
		LDBG_log(st->logger, PRI_SO" main thread "PRI_CPU_USAGE" helper thread "PRI_CPU_USAGE" in total",
			 pri_so(st->st_serialno),
			 pri_cpu_usage(st->st_timing.main_usage),
			 pri_cpu_usage(st->st_timing.helper_usage));
	}

	/*
	 * Audit-log failures.  Just assume any state failing to
	 * establish needs reporting.
	 */
	switch (st->st_ike_version) {
	case IKEv1:
#ifdef USE_IKEv1
		if (IS_V1_ISAKMP_SA(st) && !IS_V1_ISAKMP_SA_ESTABLISHED(st)) {
			linux_audit_conn(st, LAK_PARENT_FAIL);
		}
#endif
		break;
	case IKEv2:
		if (IS_IKE_SA(st) && st->st_state->kind < STATE_V2_ESTABLISHED_IKE_SA) {
			linux_audit_conn(st, LAK_PARENT_FAIL);
		}
		if (IS_CHILD_SA(st) && st->st_state->kind < STATE_V2_ESTABLISHED_CHILD_SA) {
			linux_audit_conn(st, LAK_CHILD_FAIL);
		}
		break;
	}

	/*
	 * only log parent state deletes, we log children in
	 * ipsec_delete_sa()
	 */
	if (IS_IKE_SA_ESTABLISHED(st) ||
	    IS_V1_ISAKMP_SA_ESTABLISHED(st))
		linux_audit_conn(st, LAK_PARENT_DESTROY);

	if (IS_IPSEC_SA_ESTABLISHED(st) ||
	    IS_CHILD_SA_ESTABLISHED(st)) {
		/*
		 * Note that a state/SA can have more then one of
		 * ESP/AH/IPCOMP
		 */
		struct child_sa *child = pexpect_child_sa(st);
		if (st->st_esp.protocol == &ip_protocol_esp) {
			update_and_log_traffic(child, "ESP", &st->st_esp,
					       &pstats_esp_bytes);
			pstats_ipsec_bytes.in += st->st_esp.inbound.bytes;
			pstats_ipsec_bytes.out += st->st_esp.outbound.bytes;
		}

		if (st->st_ah.protocol == &ip_protocol_ah) {
			update_and_log_traffic(child, "AH", &st->st_ah,
					       &pstats_ah_bytes);
			pstats_ipsec_bytes.in += st->st_ah.inbound.bytes;
			pstats_ipsec_bytes.out += st->st_ah.outbound.bytes;
		}

		if (st->st_ipcomp.protocol == &ip_protocol_ipcomp) {
			update_and_log_traffic(child, "IPCOMP", &st->st_ipcomp,
					       &pstats_ipcomp_bytes);
			/* XXX: not ipcomp */
		}
	}

#ifdef USE_PAM_AUTH
	if (st->st_pam_auth != NULL) {
		struct ike_sa *ike = pexpect_ike_sa(st);
		if (ike != NULL) {
			pam_auth_abort(ike, "deleting state");
		}
	}
#endif

	/* intermediate */
	free_chunk_content(&st->st_v2_ike_intermediate.initiator);
	free_chunk_content(&st->st_v2_ike_intermediate.responder);

	/* session resumption */
	pfreeany(st->st_v2_resume_session);

	/* if there's an IKEv1 background md, release it */
	if (st->st_v1_background_md != NULL) {
		ldbg(st->logger, "releasing IKEv1 MD received during background task");
		md_delref(&st->st_v1_background_md);
	}

	/* delete any pending timer event */
	delete_state_event(&st->st_v1_event, HERE);
	delete_state_event(&st->st_v1_retransmit_event, HERE);
	delete_state_event(&st->st_v1_send_xauth_event, HERE);
	delete_state_event(&st->st_v1_dpd_event, HERE);
	delete_state_event(&st->st_v1_nat_keepalive_event, HERE);
	delete_state_event(&st->st_v2_timeout_initiator_event, HERE);
	delete_state_event(&st->st_v2_timeout_responder_event, HERE);
	delete_state_event(&st->st_v2_timeout_response_event, HERE);
	delete_state_event(&st->st_v2_retransmit_event, HERE);
	delete_state_event(&st->st_v2_liveness_event, HERE);
	delete_state_event(&st->st_v2_addr_change_event, HERE);
	delete_state_event(&st->st_v2_rekey_event, HERE);
	delete_state_event(&st->st_v2_replace_event, HERE);
	delete_state_event(&st->st_v2_expire_event, HERE);
	delete_state_event(&st->st_v2_nat_keepalive_event, HERE);
	delete_state_event(&st->st_v2_discard_event, HERE);
	clear_retransmits(st);

	/*
	 * Ditch anything pending on ISAKMP SA being established.
	 * Note: this must be done before the unhash_state to prevent
	 * flush_pending_by_state inadvertently and prematurely
	 * deleting our connection.
	 */
	if (IS_IKE_SA(st)) {
		flush_pending_by_state(pexpect_ike_sa(st));
	}

	/* flush unestablished child states */
	if (IS_IKE_SA(st)) {
		flush_incomplete_children(pexpect_ike_sa(st));
	}

	/*
	 * if there is anything in the cryptographic queue, then remove this
	 * state from it.
	 */
	delete_cryptographic_continuation(st);

	/*
	 * Tell kernel to uninstall any kernel state.
	 *
	 * Caller, via routing.[hc], is responsible for adding,
	 * deleting or modifying kernel policy.
	 */

	if (IS_CHILD_SA(st)) {
		/* this function just returns when the call is
		 * invalid */
		teardown_ipsec_kernel_states(pexpect_child_sa(st));
	}

	state_disowns_connection(st);

	/*
	 * fake a state change here while we are still associated with a
	 * connection.  Without this the state logging (when enabled) cannot
	 * work out what happened.
	 */
	binlog_fake_state(st, STATE_UNDEFINED);

	iface_endpoint_delref(&st->st_iface_endpoint);

	/*
	 * Release stored IKE fragments. This is a union in st so only
	 * call one!  XXX: should be a union???
	 */
	switch (st->st_ike_version) {
	case IKEv1:
#ifdef USE_IKEv1
		free_v1_message_queues(st);
#endif
		break;
	case IKEv2:
		free_v2_message_queues(st);
		break;
	default:
		bad_case(st->st_ike_version);
	}

	/*
	 * This, effectively,  deletes any ISAKMP SA that this state
	 * represents - lookups for this state no longer work.
	 */
	state_db_del(st);

	change_state(st, STATE_UNDEFINED);

	/*
	 * Break the STATE->CONNECTION link.  If CONNECTION is an
	 * instance, then it too will be deleted.
	 *
	 * - checks ST's POLICY_UP
	 *
	 *   is the established IKE SA being revived and, hence, the
	 *   connection should not be deleted
	 *
	 * - checks for a another state still using the connection
	 *
	 *   since this state was removed from the CONNECTION -> STATE
	 *   hash table this succeeding means that there must be a
	 *   second state using the connection
	 */
	connection_delref(&st->st_connection, st->logger);

	v2_msgid_free(st);

	release_whack(st->logger, HERE);

	/* from here on we are just freeing RAM */

#ifdef USE_IKEv1
	ikev1_clear_msgid_list(st);
#endif
	pubkey_delref(&st->st_peer_pubkey);
	md_delref(&st->st_eap_sa_md);
	free_eap_state(&st->st_eap);

	free_ikev2_proposals(&st->st_v2_create_child_sa_proposals);
	free_ikev2_proposal(&st->st_v2_accepted_proposal);

	/* helper may have its own ref */
	dh_local_secret_delref(&st->st_dh_local_secret, HERE);

	/* without st_connection, st isn't complete */
	/* from here on logging is for the wrong state */

	release_certs(&st->st_remote_certs.verified);
	free_public_keys(&st->st_remote_certs.pubkey_db);

	free_generalNames(st->st_v1_requested_ca, true);

	free_chunk_content(&st->st_firstpacket_me);
	free_chunk_content(&st->st_firstpacket_peer);
#ifdef USE_IKEv1
	free_chunk_content(&st->st_v1_tpacket);
	free_chunk_content(&st->st_v1_rpacket);
#endif
	free_chunk_content(&st->st_p1isa);
	free_chunk_content(&st->st_gi);
	free_chunk_content(&st->st_gr);
	free_chunk_content(&st->st_ni);
	free_chunk_content(&st->st_nr);
	free_chunk_content(&st->st_dcookie);
	free_chunk_content(&st->st_v2_id_payload.data);

	cipher_context_destroy(&st->st_ike_encrypt_cipher_context, st->logger);
	cipher_context_destroy(&st->st_ike_decrypt_cipher_context, st->logger);

#    define free_any_nss_symkey(p)  symkey_delref(st->logger, #p, &(p))

	free_any_nss_symkey(st->st_dh_shared_secret);
	free_any_nss_symkey(st->st_skeyid_nss);
	free_any_nss_symkey(st->st_skey_d_nss);	/* aka st_skeyid_d_nss */
	free_any_nss_symkey(st->st_skey_ai_nss); /* aka st_skeyid_a_nss */
	free_any_nss_symkey(st->st_skey_ar_nss);
	free_any_nss_symkey(st->st_skey_ei_nss); /* aka st_skeyid_e_nss */
	free_any_nss_symkey(st->st_skey_er_nss);
	free_any_nss_symkey(st->st_skey_pi_nss);
	free_any_nss_symkey(st->st_skey_pr_nss);
	free_any_nss_symkey(st->st_enc_key_nss);

	free_any_nss_symkey(st->st_sk_d_no_ppk);
	free_any_nss_symkey(st->st_sk_pi_no_ppk);
	free_any_nss_symkey(st->st_sk_pr_no_ppk);

#   undef free_any_nss_symkey

	free_chunk_content(&st->st_skey_initiator_salt);
	free_chunk_content(&st->st_skey_responder_salt);

	free_kem_initiator(&st->st_kem.initiator, st->logger);

#define wipe_any_chunk(C)				\
	{						\
		if (C.ptr != NULL) {			\
			memset(C.ptr, 0, C.len);	\
			free_chunk_content(&(C));	\
		}					\
	}
	wipe_any_chunk(st->st_ah.inbound.keymat);
	wipe_any_chunk(st->st_ah.outbound.keymat);
	wipe_any_chunk(st->st_esp.inbound.keymat);
	wipe_any_chunk(st->st_esp.outbound.keymat);
#undef wipe_any_chunk

#   define wipe_any(p, l) { \
		if ((p) != NULL) { \
			memset((p), 0x00, (l)); \
			pfree(p); \
			(p) = NULL; \
		} \
	}
	wipe_any(st->st_xauth_password.ptr, st->st_xauth_password.len);
#   undef wipe_any

	/* st_xauth_username is an array on the state itself, not clone_str()'ed */
	pfreeany(st->st_seen_cfg_dns);
	pfreeany(st->st_seen_cfg_domains);
	pfreeany(st->st_seen_cfg_banner);

	free_chunk_content(&st->st_no_ppk_auth);
	pfreeany(st->st_active_redirect_gw);

	free_logger(&st->logger, HERE);
	messup(st);
	pfree(st);
}

/*
 * IKEv1: Duplicate a Phase 1 state object, to create a Phase 2 object.
 *
 * IKEv2: Duplicate an IKE SA state object, to create either a CHILD
 * SA or IKE SA (rekeying parent) object.
 *
 * Caller must schedule an event for this object so that it doesn't leak.
 * Caller must insert_state().
 */
static struct child_sa *duplicate_state(struct connection *c,
					struct ike_sa *ike,
					enum sa_kind sa_kind,
					enum sa_role sa_role)
{
	if (sa_kind == CHILD_SA) {
		/* record use of the Phase 1 / Parent state */
		ike->sa.st_outbound_count++;
		ike->sa.st_outbound_time = mononow();
	}

	struct iface_endpoint *local_iface_endpoint =
		iface_endpoint_addref(ike->sa.st_iface_endpoint);
	ip_endpoint remote_endpoint = ike->sa.st_remote_endpoint;

	struct child_sa *child =
		pexpect_child_sa(new_state(c, ike->sa.st_serialno,
					   local_iface_endpoint, remote_endpoint,
					   ike->sa.st_ike_spis.initiator,
					   ike->sa.st_ike_spis.responder,
					   sa_kind, sa_role, HERE));

	ldbg(ike->sa.logger, "duplicating state object %s "PRI_SO" as "PRI_SO" for %s",
	     ike->sa.st_connection->name,
	     pri_so(ike->sa.st_serialno),
	     pri_so(child->sa.st_serialno),
	     (sa_kind == CHILD_SA ? "IPSEC SA" : "IKE SA"));

	/*
	 * Some sloppy value inheritance.
	 *
	 * A child created during IKE_AUTH uses the IKE SA's PRF,
	 * while a child created using CREATE_CHILD_SA uses its own
	 * negotiated PRF.
	 *
	 * A child created during IKE_AUTH uses the N[ir] from the IKE
	 * SA's IKE_SA_INIT exchange, while a child created using
	 * CREATE_CHILD_SA uses N[ir] from that exchange.
	 *
	 * See 2.17. Generating Keying Material for Child SAs
	 *
	 * IKEv1 probably does something similar.
	 *
	 * Should code instead be copying values explicitly and only
	 * during IKE_AUTH?
	 */
	if (sa_kind == CHILD_SA) {
		child->sa.st_oakley = ike->sa.st_oakley;
#   define state_clone_chunk(CHUNK) child->sa.CHUNK = clone_hunk(ike->sa.CHUNK, #CHUNK " in duplicate state")
		state_clone_chunk(st_ni);
		state_clone_chunk(st_nr);
#   undef state_clone_chunk
	}

	/*
	 * Due to IKEv1, these IKE (ISAKMP) SA fields need to be
	 * copied to the Child SA so that they are still available
	 * when the IKE (ISAKMP) SA gets deleted.
	 *
	 * For instance the "generic" Child SA code for up-down
	 * expects .st_seen_cfg_dns, and the "generic" show-status
	 * code expects the NAT result.
	 */
	child->sa.hidden_variables = ike->sa.hidden_variables;
	child->sa.st_seen_cfg_dns = clone_str(ike->sa.st_seen_cfg_dns, "child st_seen_cfg_dns");
	child->sa.st_seen_cfg_domains = clone_str(ike->sa.st_seen_cfg_domains, "child st_seen_cfg_domains");
	child->sa.st_seen_cfg_banner = clone_str(ike->sa.st_seen_cfg_banner, "child st_seen_cfg_banner");
	jam_str(child->sa.st_xauth_username, sizeof(child->sa.st_xauth_username), ike->sa.st_xauth_username);

	return child;
}

struct child_sa *new_v1_child_sa(struct connection *c,
				 struct ike_sa *ike,
				 enum sa_role sa_role)
{
	struct child_sa *child = duplicate_state(c, ike, CHILD_SA, sa_role);

	/*
	 * Propagate IKEv1's IKE (ISAKMP) bits to the child so that
	 * they are still available after the ISAKMP has been deleted.
	 */
	child->sa.st_v1_seen_fragmentation_supported =
		ike->sa.st_v1_seen_fragmentation_supported;
	child->sa.st_v1_seen_fragments =
		ike->sa.st_v1_seen_fragments;

	child->sa.st_v1_quirks = ike->sa.st_v1_quirks;

#   define clone_nss_symkey_field(field) child->sa.field = symkey_addref(ike->sa.logger, #field, ike->sa.field)
	clone_nss_symkey_field(st_skeyid_nss);
	clone_nss_symkey_field(st_skeyid_a_nss); /* aka st_skey_ai_nss */
	clone_nss_symkey_field(st_skeyid_e_nss); /* aka st_skey_ei_nss */
	clone_nss_symkey_field(st_enc_key_nss);
#   undef clone_nss_symkey_field

	return child;
}

struct child_sa *new_v2_child_sa(struct connection *c,
				 struct ike_sa *ike,
				 enum sa_kind sa_kind,
				 enum sa_role sa_role,
				 /* const struct v2_transition *transition */
				 enum state_kind kind)
{
	struct child_sa *child = duplicate_state(c, ike, sa_kind, sa_role);

	/* XXX: transitions should be parameter */
	const struct finite_state *fs = finite_states[kind];
	const struct v2_transition *transition = fs->v2.child_transition;
	PASSERT(c->logger, transition != NULL);

	/*
	 * Propagate IKEv2 IKE SA bits to the larval IKE SA replacement.
	 *
	 * XXX: Handle this in emancipate?
	 * XXX: are these all really IKE SA bits?
	 */
	child->sa.st_ikev2_anon = ike->sa.st_ikev2_anon;
	child->sa.st_v2_ike_fragmentation_enabled = ike->sa.st_v2_ike_fragmentation_enabled;
	child->sa.st_seen_redirect_sup = ike->sa.st_seen_redirect_sup;
	child->sa.st_sent_redirect = ike->sa.st_sent_redirect;

	change_state(&child->sa, fs->kind);
	set_v2_transition(&child->sa, transition, HERE);

	return child;
}

/*
 * Find the IKEv2 IKE SA with the specified SPIs.
 */
struct ike_sa *find_v2_ike_sa(const ike_spis_t *ike_spis,
			      enum sa_role local_ike_role)
{
	const so_serial_t sos_nobody = SOS_NOBODY;
	struct state *st = state_by_ike_spis(IKEv2,
					     &sos_nobody/*clonedfrom: IKE SA*/,
					     NULL /*ignore v1 msgid*/,
					     &local_ike_role,
					     ike_spis, NULL, NULL, __func__);
	return pexpect_ike_sa(st);
}

/*
 * Find an IKEv2 IKE SA with a matching SPIi.
 *
 * This is used doring the IKE_SA_INIT exchange where SPIr is either
 * zero (message request) or not-yet-known (message response).
 */
struct ike_sa *find_v2_ike_sa_by_initiator_spi(const ike_spi_t *ike_initiator_spi,
					       enum sa_role local_ike_role)
{
	const so_serial_t sos_nobody = SOS_NOBODY;
	struct state *st = state_by_ike_initiator_spi(IKEv2,
						      &sos_nobody/*clonedfrom: IKE_SA*/,
						      NULL/*ignore v1 msgid*/,
						      &local_ike_role,
						      ike_initiator_spi, __func__);
	return pexpect_ike_sa(st);
}

/*
 * Find an IKEv2 CHILD SA using the protocol and the (from our POV)
 * 'outbound' SPI.
 *
 * The remote end, when identifying a CHILD SA in a Delete or REKEY_SA
 * notification, sends its end's inbound SPI, which from our
 * point-of-view is the outbound SPI aka 'attrs.spi'.
 *
 * From 1.3.3.  Rekeying Child SAs with the CREATE_CHILD_SA Exchange:
 * The SA being rekeyed is identified by the SPI field in the
 * [REKEY_SA] Notify payload; this is the SPI the exchange initiator
 * would expect in inbound ESP or AH packets.
 *
 * From 3.11.  Delete Payload: [the delete payload will] contain the
 * IPsec protocol ID of that protocol (2 for AH, 3 for ESP), and the
 * SPI is the SPI the sending endpoint would expect in inbound ESP or
 * AH packets.
 */

struct v2_spi_filter {
	uint8_t protoid;
	ipsec_spi_t outbound_spi;
	ipsec_spi_t inbound_spi;
	ip_address *dst;
};

static bool v2_spi_predicate(struct state *st, void *context)
{
	struct v2_spi_filter *filter = context;
	bool ret = false;

	struct ipsec_proto_info *pr;
	switch (filter->protoid) {
	case PROTO_IPSEC_AH:
		pr = &st->st_ah;
		break;
	case PROTO_IPSEC_ESP:
		pr = &st->st_esp;
		break;
	case PROTO_IPCOMP:
		pr = &st->st_ipcomp;
		break;
	default:
		bad_case(filter->protoid);
	}

	if (pr->protocol != NULL) {
		if (pr->outbound.spi == filter->outbound_spi) {
			ldbg(st->logger, "v2 CHILD SA "PRI_SO" found using their inbound (our outbound) SPI, in %s",
			     pri_so(st->st_serialno), st->st_state->name);
			ret = true;
			if (filter->dst != NULL) {
				ret = false;
				if (sameaddr(&st->st_connection->remote->host.addr,
					     filter->dst))
					ret = true;
			}
		} else if (filter->inbound_spi > 0 &&
			   filter->inbound_spi == pr->inbound.spi) {
			ldbg(st->logger, "v2 CHILD SA "PRI_SO" found using their our SPI, in %s",
			     pri_so(st->st_serialno), st->st_state->name);
			ret = true;
			if (filter->dst != NULL) {
				ret = false;
				if (sameaddr(&st->st_connection->local->host.addr,
					     filter->dst))
					ret = true;
			}
		}
#if 0
		/* see function description above */
		if (pr->inbound.spi == filter->outbound_spi) {
			ldbg(st->logger,
			     "v2 CHILD SA "PRI_SO" found using our inbound (their outbound) !?! SPI, in %s",
			     st->st_serialno,
			     st->st_state->name);
			return true;
		}
#endif
	}
	return ret;
}

struct child_sa *find_v2_child_sa_by_spi(ipsec_spi_t spi, int8_t protoid,
					 ip_address dst)
{
	struct v2_spi_filter filter = {
		.protoid = protoid,
		.outbound_spi = spi,
		/* fill the same spi, the kernel expire has no direction */
		.inbound_spi = spi,
		.dst = &dst,
	};
	struct state_filter sf = {
		.search = {
			.order = NEW2OLD,
			.verbose.logger = &global_logger,
			.where = HERE,
		},
	};
	while (next_state(&sf)) {
		struct state *st = sf.st;
		if (v2_spi_predicate(st, &filter))
			break;
	};
	return pexpect_child_sa(sf.st);
}

struct child_sa *find_v2_child_sa_by_outbound_spi(struct ike_sa *ike,
						  uint8_t protoid,
						  ipsec_spi_t outbound_spi)
{
	struct v2_spi_filter filter = {
		.protoid = protoid,
		.outbound_spi = outbound_spi,
	};
	struct state *st = state_by_ike_spis(IKEv2,
					     &ike->sa.st_serialno,
					     NULL /* ignore v1 msgid */,
					     NULL /* ignore-role */,
					     &ike->sa.st_ike_spis,
					     v2_spi_predicate, &filter, __func__);
	return pexpect_child_sa(st);
}

struct ike_sa *find_ike_sa_by_connection(const struct connection *c,
					 lset_t ok_states,
					 bool viable_parent)
{
	struct ike_sa *best = NULL;

	struct state_filter sf = {
		.search = {
			.order = NEW2OLD,
			.verbose.logger = &global_logger,
			.where = HERE,
		},
	};
	while (next_state(&sf)) {
		struct state *st = sf.st;
		if (!IS_PARENT_SA(st)) {
			continue;
		}
		if (!connections_can_share_parent(c, st->st_connection)) {
			continue;
		}
		if (!LHAS(ok_states, st->st_state->kind)) {
			continue;
		}
		/*
		 * Looking for something that can support new
		 * children.
		 *
		 * A larval SA (not yet established) is considered
		 * viable, even though .st_viable_parent hasn't yet
		 * been set (that happens when the state establishes).
		 */
		if (IS_PARENT_SA_ESTABLISHED(st)) {
			if (viable_parent) {
				if (!st->st_viable_parent) {
					continue;
				}
			}
		}
		if (best != NULL && best->sa.st_serialno >= st->st_serialno) {
			continue;
		}
		best = pexpect_ike_sa(st);
	}

	return best;
}

struct ike_sa *find_viable_parent_for_connection(const struct connection *c)
{
	lset_t ok_states;
	switch (c->config->ike_info->version) {
	case IKEv1:
		ok_states = (V1_ISAKMP_SA_ESTABLISHED_STATES |
			     V1_PHASE1_INITIATOR_STATES);
		break;
	case IKEv2:
		ok_states = (LELEM(STATE_V2_ESTABLISHED_IKE_SA) |
			     IKEV2_ISAKMP_INITIATOR_STATES);
		break;
	default:
		bad_enum(c->logger, &ike_version_names, c->config->ike_info->version);
	}

	struct ike_sa *best = NULL;

	struct state_filter sf = {
		.search = {
			.order = NEW2OLD,
			.verbose.logger = &global_logger,
			.where = HERE,
		},
	};
	while (next_state(&sf)) {
		struct state *st = sf.st;
		if (!IS_PARENT_SA(st)) {
			continue;
		}
		if (!connections_can_share_parent(c, st->st_connection)) {
			continue;
		}
		/*
		 * Looking for something that can support new
		 * children.
		 *
		 * A larval SA (not yet established) is considered
		 * viable, even though .st_viable_parent hasn't yet
		 * been set (that happens when the state establishes).
		 */
		PEXPECT(st->logger, IS_PARENT_SA(st)); /* by parent_ok() */
		if (IS_PARENT_SA_ESTABLISHED(st)) {
			if (!st->st_viable_parent) {
				/* past it's use-by date */
				continue;
			}
			if (st->st_connection->established_ike_sa != st->st_serialno) {
				/* er, our connection was stolen */
				continue;
			}
		} else {
			if (st->st_sa_role != SA_INITIATOR) {
				PEXPECT(st->logger,
					!LHAS(ok_states, st->st_state->kind));
				continue;
			}
			PEXPECT(st->logger,
				LHAS(ok_states, st->st_state->kind));
		}
		/* better? */
		if (best != NULL && best->sa.st_serialno >= st->st_serialno) {
			continue;
		}
		best = pexpect_ike_sa(st);
	}

	return best;
}

void jam_humber_uintmax(struct jambuf *buf,
			const char *prefix, uintmax_t val, const char *suffix)
{
	jam_string(buf, prefix);
	if (/*double-negative*/ !(pexpect(val <= IPSEC_SA_MAX_OPERATIONS))) {
		jam(buf, "%ju", val);
	} else if (val == IPSEC_SA_MAX_OPERATIONS) {
		jam_string(buf, IPSEC_SA_MAX_OPERATIONS_STRING);
	} else {
		jam_humber(buf, val);
	}
	jam_string(buf, suffix);
}

void whack_briefstatus(const struct whack_message *wm UNUSED, struct show *s)
{
	show_separator(s);
	show(s, "State Information: DDoS cookies %s, %s new IKE connections",
	     require_ddos_cookies() ? "REQUIRED" : "not required",
	     (drop_new_exchanges(show_logger(s)) == NULL ? "Accepting" : "NOT ACCEPTING"));

	show(s, "IKE SAs: total("PRI_CAT"), half-open("PRI_CAT"), open("PRI_CAT"), authenticated("PRI_CAT"), anonymous("PRI_CAT")",
		  total_ike_sa(),
		  cat_count[CAT_HALF_OPEN_IKE_SA],
		  cat_count[CAT_OPEN_IKE_SA],
		  cat_count_ike_sa[CAT_AUTHENTICATED],
		  cat_count_ike_sa[CAT_ANONYMOUS]);
	show(s, "IPsec SAs: total("PRI_CAT"), authenticated("PRI_CAT"), anonymous("PRI_CAT")",
		  cat_count[CAT_ESTABLISHED_CHILD_SA],
		  cat_count_child_sa[CAT_AUTHENTICATED],
		  cat_count_child_sa[CAT_ANONYMOUS]);
}

/*
 * Muck with high-order 16 bits of this SPI in order to make
 * the corresponding SAID unique.
 * Its low-order 16 bits hold a well-known IPCOMP CPI.
 * Oh, and remember that SPIs are stored in network order.
 * Kludge!!!  So I name it with the non-English word "uniquify".
 * If we can't find one easily, return 0 (a bad SPI,
 * no matter what order) indicating failure.
 *
 * v1-only.
 * cpi is in network order.
 */
ipsec_spi_t uniquify_peer_cpi(ipsec_spi_t cpi, const struct state *st, int tries)
{
	/* cpi is in network order so first two bytes are the high order ones */
	get_rnd_bytes((uint8_t *)&cpi, 2);

	/*
	 * Make sure that the result is unique.
	 * Hard work.  If there is no unique value, we'll loop forever!
	 */
	struct state_filter sf = {
		.search = {
			.order = NEW2OLD,
			.verbose.logger = &global_logger,
			.where = HERE,
		},
	};
	while (next_state(&sf)) {
		struct state *s = sf.st;
		if (s->st_ipcomp.protocol == &ip_protocol_ipcomp &&
		    sameaddr(&s->st_connection->remote->host.addr,
			     &st->st_connection->remote->host.addr) &&
		    cpi == s->st_ipcomp.outbound.spi)
		{
			if (++tries == 20)
				return 0; /* FAILURE */
			return uniquify_peer_cpi(cpi, st, tries);
		}
	}
	return cpi;
}

/*
 * This is for panic situations where the entire IKE family needs to
 * be blown away.
 */

void send_n_log_delete_ike_family_now(struct ike_sa **ike,
				      struct logger *logger,
				      where_t where)
{
	state_attach(&(*ike)->sa, logger); /* no detach, going down */

	ldbg_sa((*ike), "parent is no longer vivable (but can send delete)");
	(*ike)->sa.st_viable_parent = false;
	struct ike_sa *established_isakmp = NULL;

	/*
	 * IKEv2 should send out the delete immediately, IKEv1 delays
	 * things until after the children are all gone.
	 */

	if (IS_PARENT_SA_ESTABLISHED(&(*ike)->sa)) {
		switch ((*ike)->sa.st_ike_version) {
		case IKEv1:
			/*
			 * Because IKEv1 needs the ISAKMP SA to delete
			 * children it only announces its death after
			 * everything is gone.
			 *
			 * Save the established ISAKMP so checking it
			 * is easier.  Announce intent.
			 */
			established_isakmp = (*ike);
			break;
		case IKEv2:
			/*
			 * Per above, we're in a panic, violating
			 * everything is ok.
			 */
			record_n_send_n_log_v2_delete((*ike), where);
			break;
		}
	} else {
		/* announce that delete is not being sent */
		llog_sa_delete_n_send(NULL, &(*ike)->sa);
	}

	struct state_filter cf = {
		.clonedfrom = (*ike)->sa.st_serialno,
		.search = {
			.order = NEW2OLD,
			.verbose.logger = &global_logger,
			.where = where,
		},
	};
	while(next_state(&cf)) {
		struct child_sa *child = pexpect_child_sa(cf.st);
		state_attach(&child->sa, logger); /* no detach, going down */
		switch (child->sa.st_ike_version) {
		case IKEv1:
			llog_sa_delete_n_send(established_isakmp, &child->sa);
			if (established_isakmp != NULL) {
				send_v1_delete(established_isakmp, &child->sa, where);
			}
			connection_teardown_child(&child, REASON_DELETED, where);
			break;
		case IKEv2:
			/* nothing to say? */
			connection_teardown_child(&child, REASON_DELETED, where);
			break;
		}
	}

	if (established_isakmp != NULL) {
		llog_sa_delete_n_send(established_isakmp, &(*ike)->sa);
		send_v1_delete(established_isakmp, &established_isakmp->sa, where);
	}

	terminate_ike_family(ike, REASON_DELETED, where);
}

void show_globalstate_status(struct show *s)
{
	const struct config_setup *oco = config_setup_singleton();
	unsigned shunts = shunt_count();

	show(s, "config.setup.ike.ddos_threshold=%ju", config_setup_option(oco, KBF_DDOS_IKE_THRESHOLD));
	show(s, "config.setup.ike.max_halfopen=%ju", config_setup_option(oco, KBF_MAX_HALFOPEN_IKE));

	/* technically shunts are not a struct state's - but makes it easier to group */
	show(s, "current.states.all="PRI_CAT, shunts + total_sa());
	show(s, "current.states.ipsec="PRI_CAT, cat_count[CAT_ESTABLISHED_CHILD_SA]);
	show(s, "current.states.ike="PRI_CAT, total_ike_sa());
	show(s, "current.states.shunts=%u", shunts);
	show(s, "current.states.iketype.anonymous="PRI_CAT, cat_count_ike_sa[CAT_ANONYMOUS]);
	show(s, "current.states.iketype.authenticated="PRI_CAT, cat_count_ike_sa[CAT_AUTHENTICATED]);
	show(s, "current.states.iketype.halfopen="PRI_CAT, cat_count[CAT_HALF_OPEN_IKE_SA]);
	show(s, "current.states.iketype.open="PRI_CAT, cat_count[CAT_OPEN_IKE_SA]);
#ifdef USE_IKEv1
	for (enum state_kind sk = STATE_IKEv1_FLOOR; sk < STATE_IKEv1_ROOF; sk++) {
		const struct finite_state *fs = finite_states[sk];
		show(s, "current.states.enumerate.%s="PRI_CAT,
			 fs->name, state_count[sk]);
	}
#endif
	for (enum state_kind sk = STATE_IKEv2_FLOOR; sk < STATE_IKEv2_ROOF; sk++) {
		const struct finite_state *fs = finite_states[sk];
		show(s, "current.states.enumerate.%s="PRI_CAT,
			 fs->name, state_count[sk]);
	}
}

/*
 * Moved from ikev1_xauth.c since IKEv2 code now also uses it
 * Converted to store ephemeral data in the state, not connection.
 */

diag_t append_st_cfg_dns(struct pbs_in *pbs, const struct ip_info *afi, struct state *st)
{
	/* XXX: before trying to extract! */
	if (st->st_connection->config->ignore_peer_dns) {
		llog(RC_LOG, st->logger, "ignoring INTERNAL_IP%s_DNS server address payload (ignore-peer-dns=yes)",
		     afi->n_name);
		return NULL;
	}

	ip_address ip;
	diag_t d = pbs_in_address(pbs, &ip, afi, "INTERNAL_IPn_DNS payload");
	if (d != NULL) {
		return diag_diag(&d, "invalid INTERNAL_IP%s_DNS server address payload, ",
				 afi->n_name);
	}

	/* i.e. not all zeros */
	if (!address_is_specified(ip)) {
		address_buf ip_str;
		return diag("invalid INTERNAL_IP%s_DNS server address %s, unspecified",
			    afi->n_name, str_address(&ip, &ip_str));
	}

	address_buf dnsb;
	llog(RC_LOG, st->logger, "received INTERNAL_IP%s_DNS server address %s",
	     afi->n_name, str_address(&ip, &dnsb));

	append_str(&st->st_seen_cfg_dns, " ", dnsb.buf);
	return NULL;
}

void append_st_cfg_domain(struct state *st, struct pbs_in *pbs,
			  char *(*stringify)(shunk_t str, bool *ok))
{
	shunk_t str = pbs_in_left(pbs);
	if (st->st_connection->config->ignore_peer_dns) {
		LLOG_JAMBUF(RC_LOG, st->logger, buf) {
			jam_string(buf, "ignoring INTERNAL_DNS_DOMAIN '");
			jam_sanitized_hunk(buf, str);
			jam_string(buf, "' (ignore-peer-dns=yes)");
		}
		return;
	}

	bool ok;
	char *domain = stringify(str, &ok);
	if (domain == NULL) {
		LLOG_PEXPECT_JAMBUF(st->logger, HERE, buf) {
			jam_string(buf, "ignoring INTERNAL_DNS_DOMAIN '");
			jam_sanitized_hunk(buf, str);
			jam_string(buf, "', invalid");
		}
		return;
	}

	LLOG_JAMBUF(RC_LOG, st->logger, buf) {
		if (ok) {
			jam_string(buf, "received");
		} else {
			jam_string(buf, "truncated"); /* presumably */
		}
		jam_string(buf, " INTERNAL_DNS_DOMAIN '");
		jam_sanitized_hunk(buf, str);
		jam_string(buf, "'");
	}

	append_str(&st->st_seen_cfg_domains, " ", domain);
	pfree(domain);
}

static void list_state_event(struct show *s, struct state *st,
			     struct state_event *pe, const monotime_t now)
{
	if (pe != NULL) {
		pexpect(st == pe->ev_state);
		SHOW_JAMBUF(s, buf) {
			jam_string(buf, "event ");
			jam_enum_short(buf, &event_type_names, pe->ev_type);
			jam_string(buf, " schd: ");
			jam(buf, "%jds", monosecs(pe->ev_time));
			jam_string(buf, " (in ");
			jam(buf, "%jds", deltasecs(monotime_diff(pe->ev_time, now)));
			jam_string(buf, ") ");
			jam_prefix(buf, st->logger);
		}
	}
}

void list_state_events(struct show *s, const monotime_t now)
{
	struct state_filter sf = {
		.search = {
			.order = OLD2NEW,
			.verbose.logger = &global_logger,
			.where = HERE,
		},
	};
	while (next_state(&sf)) {
		struct state *st = sf.st;
		/* order makes no sense */
		FOR_EACH_ELEMENT(event, st->st_events) {
			if (*event != NULL) {
				list_state_event(s, st, (*event), now);
			}
		}
	}
}

#ifdef USE_IKEv1
void set_v1_transition(struct state *st, const struct state_v1_microcode *transition,
		       where_t where)
{
	LDBGP_JAMBUF(DBG_BASE, st->logger, buf) {
		jam_so(buf, st->st_serialno);
		jam_string(buf, ".st_v1_transition ");
		jam_v1_transition(buf, st->st_v1_transition);
		jam(buf, " to ");
		jam_v1_transition(buf, transition);
		jam_string(buf, " ");
		jam_where(buf, where);
	}
	st->st_v1_transition = transition;
}
#endif

void set_v2_transition(struct state *st, const struct v2_transition *transition,
		       where_t where)
{
	LDBGP_JAMBUF(DBG_BASE, st->logger, buf) {
		jam_so(buf, st->st_serialno);
		jam_string(buf, ".st_v2_transition ");
		jam_v2_transition(buf, st->st_v2_transition);
		jam(buf, " -> ");
		jam_v2_transition(buf, transition);
		jam_string(buf, " ");
		jam_where(buf, where);
	}
	st->st_v2_transition = transition;
}

static void jam_st(struct jambuf *buf, struct state *st)
{
	if (st == NULL) {
		jam(buf, "NULL");
	} else {
		jam(buf, "%s "PRI_SO" %s",
		    IS_CHILD_SA(st) ? "CHILD" : "IKE",
		    pri_so(st->st_serialno), st->st_state->short_name);
		jam(buf, "%s "PRI_SO" %s",
		    IS_CHILD_SA(st) ? "CHILD" : "IKE",
		    pri_so(st->st_serialno), st->st_state->short_name);
		jam(buf, "%s "PRI_SO" %s",
		    IS_CHILD_SA(st) ? "CHILD" : "IKE",
		    pri_so(st->st_serialno), st->st_state->short_name);
	}
}

void switch_md_st(struct msg_digest *md, struct state *st, where_t where)
{
	LDBGP_JAMBUF(DBG_BASE, st->logger, buf) {
		jam(buf, "switching IKEv%d MD.ST from ", st->st_ike_version);
		jam_st(buf, md->v1_st);
		jam(buf, " to ");
		jam_st(buf, st);
		jam_string(buf, " ");
		jam_where(buf, where);
	}
	md->v1_st = st;
}

/*
 * Every time a state's connection is changed, the following need to happen:
 *
 * - update the connection->from hash table
 *
 * - discard the old connection when not in use
 */

void connswitch_state_and_log(struct state *st, struct connection *new)
{
	struct connection *old = st->st_connection;
	passert(old != NULL);
	passert(new != NULL);
	passert(old != new);

	connection_buf nb;
	llog(RC_LOG, st->logger, "switched to "PRI_CONNECTION,
	     pri_connection(new, &nb));

	/*
	 * Update the state's logger with the connection's debug flags
	 */
	st->logger->debugging &= ~old->logger->debugging;
	st->logger->debugging |= new->logger->debugging;

	/* and switch */
	st->st_connection = connection_addref(new, st->logger);
	state_db_rehash_connection_serialno(st);
	connection_delref(&old, st->logger);
}

/*
 * An IKE SA has been established.  Check if the freshly established
 * connection is replacing an established version of itself.
 *
 * Note the serial number, and release any connections with the same
 * peer ID but different peer IP address.
 *
 * The use of pluto_uniqueIDs is mostly historic and might be removed
 * in a future version.  It is ignored for PSK based connections, which
 * only act based on being a "server using PSK".
 */

void wipe_old_connections(const struct ike_sa *ike)
{
	struct connection *c = ike->sa.st_connection;
	bool new_remote_is_authnull =
		(c->remote->host.config->authby.null ||
		 /*XXX: redundant? */
		 c->remote->host.config->auth == AUTH_NULL);

	if (c->local->host.config->xauth.server &&
	    c->remote->host.config->authby.psk) {
		/*
		 * If we are a server and authenticate all clients
		 * using PSK then all clients use the same group ID
		 * Note that "xauth.server" also refers to IKEv2 CP
		 */
		ldbg_sa(ike, "%s() skipped, we are a server using PSK and clients are using a group ID", __func__);
		return;
	}

	if (!pluto_uniqueIDs) {
		ldbg_sa(ike, "%s() skipped, uniqueIDs disabled", __func__);
		return;
	}

	ldbg_sa(ike, "%s() contemplating releasing older self", __func__);

	/*
	 * For all existing connections: if the same Phase 1 IDs are
	 * used, unorient the (old) connection (if different from
	 * current connection).
	 *
	 * Only do this for connections with the same name (can be
	 * shared ike sa).
	 */
	struct connection_filter cf = {
		.base_name = c->base_name,
		.kind = c->local->kind,
		.ike_version = c->config->ike_version,
		.this_id_eq = &c->local->host.id,
		.that_id_eq = &c->remote->host.id,
		.search = {
			.order = NEW2OLD,
			.verbose.logger = ike->sa.logger,
			.where = HERE,
		},
	};
	while (next_connection(&cf)) {
		struct connection *d = cf.c;

		/*
		 * If old IKE SA is same as new IKE sa and non-auth
		 * isn't overwrting auth?
		 */
		if (c == d) {
			continue;
		}

		bool old_remote_is_nullauth = (d->remote->host.config->authby.null ||
					       /* XXX: redundant? */
					       d->remote->host.config->auth == AUTH_NULL);
		if (!old_remote_is_nullauth && new_remote_is_authnull) {
			llog_sa(RC_LOG, ike, "cannot replace old authenticated connection with authnull connection");
			continue;
		}

		if (!address_eq_address(c->remote->host.addr, d->remote->host.addr) &&
		    old_remote_is_nullauth &&
		    new_remote_is_authnull) {
			llog_sa(RC_LOG, ike, "NULL auth ID for different IP's cannot replace each other");
			continue;
		}

		ldbg_sa(ike, "unorienting old connection with same IDs");

		/*
		 * Per lookup, C and D have the same kind, which means
		 * that if one is an instance then so is the other and
		 * conversely when one is permanent then so too is the
		 * other.
		 */
		PEXPECT(ike->sa.logger, c->local->kind == d->local->kind);
		PEXPECT(ike->sa.logger, is_instance(c) || is_permanent(c));
		PEXPECT(ike->sa.logger, is_instance(c) == is_instance(d));
		PEXPECT(ike->sa.logger, is_permanent(c) == is_permanent(d));

		/*
		 * XXX: Assume this call doesn't want to log to whack?
		 * Even though the IKE SA may have whack attached,
		 * don't transfer it to the old connection.
		 */
		if (is_instance(d)) {

			/*
			 * NOTE: D not C (github/1247)
			 *
			 * Strip D of all states, and return it to
			 * unrouted.  If the connection is a template,
			 * terminating it will also cause it to be
			 * deleted.  Hence take a reference so it is
			 * deleted here.
			 */

			connection_addref(d, ike->sa.logger);
			terminate_all_connection_states(d, HERE);
			connection_delref(&d, ike->sa.logger);

		} else {

			/*
			 * NOTE: C not D (github/1247)
			 *
			 * The new permanent connection C is deleted
			 * leaving the existing permanent connection D
			 * alone.
			 */

			llog_pexpect(ike->sa.logger, HERE,
				     "why am I deleting the shiny new permanent IKE?");
			terminate_all_connection_states(c, HERE);
		}
	}
}

/*
 * This logs to the main log the authentication and encryption keys
 * for an IKE/ISAKMP SA.  This is done in a format that is compatible
 * with tcpdump 4.0's -E option.
 *
 * The log message will require that a cut command is used to remove
 * the initial text.
 *
 * DANGER: this intentionally leaks cryptographic secrets.
 */
void LDBG_tcpdump_ike_sa_keys(struct logger *logger, const struct ike_sa *ike)
{
	passert(LDBGP(DBG_PRIVATE, logger));
	passert(!is_fips_mode());

	if (ike->sa.st_oakley.ta_integ == NULL ||
	    ike->sa.st_oakley.ta_encrypt == NULL) {
		return;
	}

	/* format initiator SPI */
	char tispi[3 + 2*IKE_SA_SPI_SIZE];
	datatot(ike->sa.st_ike_spis.initiator.bytes,
		sizeof(ike->sa.st_ike_spis.initiator.bytes),
		'x', tispi, sizeof(tispi));

	/* format responder SPI */
	char trspi[3 + 2*IKE_SA_SPI_SIZE];
	datatot(ike->sa.st_ike_spis.responder.bytes,
		sizeof(ike->sa.st_ike_spis.responder.bytes),
		'x', trspi, sizeof(trspi));

	const char *authalgo = ike->sa.st_oakley.ta_integ->integ_tcpdump_name;
	const char *encalgo = ike->sa.st_oakley.ta_encrypt->encrypt_tcpdump_name;

	/*
	 * Text of encryption key length (suffix for encalgo).
	 * No more than 3 digits, but compiler fears it might be 5.
	 */
	char tekl[6] = "";
	if (ike->sa.st_oakley.enckeylen != 0) {
		snprintf(tekl, sizeof(tekl), "%u",
			 ike->sa.st_oakley.enckeylen);
	}

	/* v2 IKE authentication key for initiator (256 bit bound) */
	chunk_t ai = chunk_from_symkey("ai", ike->sa.st_skey_ai_nss,
				       ike->sa.logger);
	char tai[3 + 2 * BYTES_FOR_BITS(256)] = "";
	datatot(ai.ptr, ai.len, 'x', tai, sizeof(tai));
	free_chunk_content(&ai);

	/* v2 IKE encryption key for initiator (256 bit bound) */
	chunk_t ei = chunk_from_symkey("ei", ike->sa.st_skey_ei_nss,
				       ike->sa.logger);
	char tei[3 + 2 * BYTES_FOR_BITS(256)] = "";
	datatot(ei.ptr, ei.len, 'x', tei, sizeof(tei));
	free_chunk_content(&ei);

	LDBG_log(logger, "ikev%d I %s %s %s:%s %s%s:%s",
		ike->sa.st_ike_version,
		tispi, trspi,
		authalgo, tai,
		encalgo, tekl, tei);

	/* v2 IKE authentication key for responder (256 bit bound) */
	chunk_t ar = chunk_from_symkey("ar", ike->sa.st_skey_ar_nss,
				       ike->sa.logger);
	char tar[3 + 2 * BYTES_FOR_BITS(256)] = "";
	datatot(ar.ptr, ar.len, 'x', tar, sizeof(tar));
	free_chunk_content(&ar);

	/* v2 IKE encryption key for responder (256 bit bound) */
	chunk_t er = chunk_from_symkey("er", ike->sa.st_skey_er_nss,
				       ike->sa.logger);
	char ter[3 + 2 * BYTES_FOR_BITS(256)] = "";
	datatot(er.ptr, er.len, 'x', ter, sizeof(ter));
	free_chunk_content(&er);

	LDBG_log(logger, "ikev%d R %s %s %s:%s %s%s:%s",
		ike->sa.st_ike_version,
		tispi, trspi,
		authalgo, tar,
		encalgo, tekl, ter);
}

void set_sa_expire_next_event(enum sa_expire_kind expire, struct child_sa *child)
{
	const struct ike_info *ike_info = child->sa.st_connection->config->ike_info;
	PASSERT(child->sa.logger, expire < elemsof(ike_info->expire_event));
	enum event_type event = ike_info->expire_event[expire];
	event_delete(event, &child->sa);
	event_force(event, &child->sa);
}

/* IKE SA | ISAKMP SA || Child SA | IPsec SA */
const char *state_sa_name(const struct state *st)
{
	return connection_sa_name(st->st_connection,
				  st->st_sa_kind_when_established);
}

/* IKE | ISAKMP || Child | IPsec */
const char *state_sa_short_name(const struct state *st)
{
	return connection_sa_short_name(st->st_connection,
					st->st_sa_kind_when_established);
}

/* print a policy: like bitnamesof, but it also does the non-bitfields.
 * Suppress the shunt and fail fields if 0.
 */

size_t jam_child_policy(struct jambuf *buf, const struct child_policy *policy)
{
	size_t s = 0;

	const char *sep = "";
	if (policy->transport) {
		s += jam_string(buf, sep);
		s += jam_string(buf, "TRANSPORT");
		sep = "+";
	}
	if (policy->compress) {
		s += jam_string(buf, sep);
		s += jam_string(buf, "COMPRESS");
		sep = "+";
	}
	return s;
}

const char *str_child_policy(const struct child_policy *policy, child_policy_buf *dst)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(dst->buf);
	jam_child_policy(&buf, policy);
	return dst->buf;
}

size_t jam_so(struct jambuf *buf, so_serial_t so)
{
	return jam(buf, PRI_SO, so);
}
