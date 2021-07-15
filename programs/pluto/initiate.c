/* information about connections between hosts and clients
 *
 * Copyright (C) 1998-2010,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2009 Stefan Arentz <stefan@arentz.ca>
 * Copyright (C) 2009-2010 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2007-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Panagiotis Tamtamis <tamtamis@gmail.com>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
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
 *
 */

#include "connections.h"
#include "pending.h"
#include "timer.h"
#include "kernel_ops.h"			/* for raw_policy() */
#include "log.h"
#include "ikev1_spdb.h"			/* for kernel_alg_makedb() !?! */
#include "initiate.h"
#include "host_pair.h"
#include "state_db.h"
#include "orient.h"
#include "ikev1.h"			/* for aggr_outI1() and main_outI1() */
#include "ikev1_quick.h"		/* for quick_outI1() */
#include "ikev2.h"			/* for ikev2_state_transition_fn; */
#include "ikev2_ike_sa_init.h"		/* for ikev2_out_IKE_SA_INIT_I() */
#include "ikev2_create_child_sa.h"	/* for initiate_v2_CREATE_CHILD_SA_create_child() */
#include "labeled_ipsec.h"		/* for sec_label_within_range() */
#include "ip_info.h"

static bool initiate_connection_2(struct connection *c, const char *remote_host,
				  bool background, const threadtime_t inception);
static bool initiate_connection_3(struct connection *c, bool background, const threadtime_t inception);

bool initiate_connection(struct connection *c, const char *remote_host, bool background)
{
	connection_buf cb;
	dbg("initiating connection to "PRI_CONNECTION" in the %s with "PRI_LOGGER,
	    pri_connection(c, &cb), background ? "background" : "forground",
	    pri_logger(c->logger));
	threadtime_t inception = threadtime_start();
	bool ok;

	/* If whack supplied a remote IP, fill it in if we can */
	if (remote_host != NULL && (address_is_unset(&c->spd.that.host_addr) ||
				    address_is_any(c->spd.that.host_addr))) {
		ip_address remote_ip;

		ttoaddress_num(shunk1(remote_host), NULL/*UNSPEC*/, &remote_ip);

		if (c->kind != CK_TEMPLATE) {
			llog(RC_NOPEERIP, c->logger,
			     "cannot instantiate non-template connection to a supplied remote IP address");
			return 0;
		}

		struct connection *d = instantiate(c, &remote_ip, NULL);
		/* XXX: something better? */
		close_any(&d->logger->global_whackfd);
		d->logger->global_whackfd = fd_dup(c->logger->global_whackfd, HERE);

		/* XXX: why not write to the log file? */
		llog(WHACK_STREAM|RC_LOG, d->logger,
		     "instantiated connection with remote IP set to %s", remote_host);

		/* flip cur_connection */
		ok = initiate_connection_2(d, remote_host, background, inception);
		if (!ok) {
			delete_connection(&d, false);
		} else {
			/* XXX: something better? */
			close_any(&d->logger->global_whackfd);
		}
	} else {
		/* now proceed as normal */
		ok = initiate_connection_2(c, remote_host, background, inception);
	}
	return ok;
}

bool initiate_connection_2(struct connection *c,
			   const char *remote_host,
			   bool background,
			   const threadtime_t inception)
{
	if (!oriented(*c)) {
		ipstr_buf a;
		ipstr_buf b;
		llog(RC_ORIENT, c->logger,
		     "we cannot identify ourselves with either end of this connection.  %s or %s are not usable",
		     ipstr(&c->spd.this.host_addr, &a),
		     ipstr(&c->spd.that.host_addr, &b));
		return false;
	}

	if (NEVER_NEGOTIATE(c->policy)) {
		llog(RC_INITSHUNT, c->logger,
		     "cannot initiate an authby=never connection");
		return false;
	}

	if ((remote_host == NULL) && (c->kind != CK_PERMANENT) && !(c->policy & POLICY_IKEV2_ALLOW_NARROWING)) {
		if (address_is_unset(&c->spd.that.host_addr) ||
		    address_is_any(c->spd.that.host_addr)) {
			if (c->dnshostname != NULL) {
				esb_buf b;
				llog(RC_NOPEERIP, c->logger,
				     "cannot initiate connection without resolved dynamic peer IP address, will keep retrying (kind=%s)",
				     enum_show(&connection_kind_names, c->kind, &b));
				dbg("%s() connection '%s' +POLICY_UP", __func__, c->name);
				c->policy |= POLICY_UP;
				return true;
			} else {
				esb_buf b;
				llog(RC_NOPEERIP, c->logger,
				     "cannot initiate connection (serial "PRI_CO") without knowing peer IP address (kind=%s)",
				     pri_co(c->serialno),
				     enum_show(&connection_kind_names, c->kind, &b));
			}
			return false;
		}
	}

	if ((address_is_unset(&c->spd.that.host_addr) ||
	     address_is_any(c->spd.that.host_addr)) &&
	    (c->policy & POLICY_IKEV2_ALLOW_NARROWING) ) {
		if (c->dnshostname != NULL) {
			esb_buf b;
			llog(RC_NOPEERIP, c->logger,
			     "cannot initiate connection without resolved dynamic peer IP address, will keep retrying (kind=%s, narrowing=%s)",
			     enum_show(&connection_kind_names, c->kind, &b),
			     bool_str((c->policy & POLICY_IKEV2_ALLOW_NARROWING) != LEMPTY));
			dbg("%s() connection '%s' +POLICY_UP", __func__, c->name);
			c->policy |= POLICY_UP;
			return true;
		} else {
			esb_buf b;
			llog(RC_NOPEERIP, c->logger,
			     "cannot initiate connection without knowing peer IP address (kind=%s narrowing=%s)",
			     enum_show(&connection_kind_names, c->kind, &b),
			     bool_str((c->policy & POLICY_IKEV2_ALLOW_NARROWING) != LEMPTY));
			return false;
		}
	}

	bool ok;
	if (c->ike_version == IKEv2 &&
	    (c->policy & POLICY_IKEV2_ALLOW_NARROWING) &&
	    c->kind == CK_TEMPLATE) {
		struct connection *d = instantiate(c, NULL, NULL);
		/* XXX: something better? */
		close_any(&d->logger->global_whackfd);
		d->logger->global_whackfd = fd_dup(c->logger->global_whackfd, HERE);
		/*
		 * LOGGING: why not log this (other than it messes
		 * with test output)?
		 */
		llog(LOG_STREAM|RC_LOG, d->logger, "instantiated connection");
		/* flip cur_connection */
		ok = initiate_connection_3(d, background, inception);
		if (!ok) {
			delete_connection(&d, false);
		} else {
			/* XXX: something better? */
			close_any(&d->logger->global_whackfd);
		}
	} else {
		ok = initiate_connection_3(c, background, inception);
	}
	return ok;
}

bool initiate_connection_3(struct connection *c, bool background, const threadtime_t inception)
{
	/* We will only request an IPsec SA if policy isn't empty
	 * (ignoring Main Mode items).
	 * This is a fudge, but not yet important.
	 *
	 * XXX:  Is this still useful?
	 *
	 * In theory, by delaying the the kernel algorithm probe until
	 * here when the connection is being initiated, it is possible
	 * to detect kernel algorithms that have been loaded after
	 * pluto has started or are only loaded on-demand.
	 *
	 * In reality, the kernel algorithm DB is "static": PFKEY is
	 * only probed during startup(?); and XFRM, even if it does
	 * support probing, is using static entries.  See
	 * kernel_alg.c.
	 *
	 * Consequently:
	 *
	 * - when the connection's proposal suite is specified, the
	 * algorithm parser will check the algorithms against the
	 * kernel algorithm DB, so calling kernel_alg_makedb() to to
	 * perform an identical check is redundant
	 *
	 * - when default proposals are used (CHILD_PROPOSALS.P==NULL)
	 * (the parser can't see these) kernel_alg_makedb(NULL)
	 * returns a static table and skips all checks
	 *
	 * - finally, kernel_alg_makedb() is IKEv1 only
	 *
	 * A better fix would be to feed the proposal parser the
	 * default proposal suite.
	 *
	 * For moment leave call but make it IKEv1 only - for IKEv2
	 * all it does is give spdb.c some busy work (and log bogus
	 * stats).
	 *
	 * XXX: mumble something about c->ike_version
	 */
#ifdef USE_IKEv1
	if (c->ike_version == IKEv1 &&
	    (c->policy & (POLICY_ENCRYPT | POLICY_AUTHENTICATE))) {
		struct db_sa *phase2_sa = v1_kernel_alg_makedb(c->policy, c->child_proposals,
							       true, c->logger);
		if (c->child_proposals.p != NULL && phase2_sa == NULL) {
			llog(WHACK_STREAM|RC_LOG_SERIOUS, c->logger,
			     "cannot initiate: no acceptable kernel algorithms loaded");
			return false;
		}
		free_sa(&phase2_sa);
	}
#endif

	dbg("%s() connection '%s' +POLICY_UP", __func__, c->name);
	c->policy |= POLICY_UP;

	/*
	 * FOR IKEv2, when the sec_label template connection is
	 * initiated, there is no acquire and, hence, no Child SA to
	 * establish.
	 */

	ipsecdoi_initiate(c, c->policy, 1, SOS_NOBODY, &inception,
			  (c->ike_version == IKEv1 ? HUNK_AS_SHUNK(c->spd.this.sec_label) : null_shunk),
			  background, c->logger);
	return true;
}

void ipsecdoi_initiate(struct connection *c,
		       lset_t policy,
		       unsigned long try,
		       so_serial_t replacing,
		       const threadtime_t *inception,
		       shunk_t sec_label,
		       bool background, struct logger *logger)
{
	if (sec_label.len > 0)
		dbg("ipsecdoi_initiate() called with sec_label "PRI_SHUNK, pri_shunk(sec_label));

	switch (c->ike_version) {
#ifdef USE_IKEv1
	case IKEv1:
	{
		/*
		 * If there's already an IKEv1 ISAKMP SA established,
		 * use that and go directly to Quick Mode.  We are
		 * even willing to use one that is still being
		 * negotiated, but only if we are the Initiator (thus
		 * we can be sure that the IDs are not going to
		 * change; other issues around intent might matter).
		 * Note: there is no way to initiate with a Road
		 * Warrior.
		 */
		struct state *st = find_phase1_state(c,
						     V1_ISAKMP_SA_ESTABLISHED_STATES |
						     V1_PHASE1_INITIATOR_STATES);
		struct fd *whackfd = background ? null_fd : logger->global_whackfd;
		if (st == NULL && (policy & POLICY_AGGRESSIVE)) {
			aggr_outI1(whackfd, c, NULL, policy, try, inception, sec_label);
		} else if (st == NULL) {
			main_outI1(whackfd, c, NULL, policy, try, inception, sec_label);
		} else if (IS_V1_ISAKMP_SA_ESTABLISHED(st)) {
			/*
			 * ??? we assume that peer_nexthop_sin isn't
			 * important: we already have it from when we
			 * negotiated the ISAKMP SA!  It isn't clear
			 * what to do with the error return.
			 */
			quick_outI1(whackfd, st, c, policy, try,
				    replacing, sec_label);
		} else {
			/* leave our Phase 2 negotiation pending */
			add_pending(whackfd, pexpect_ike_sa(st),
				    c, policy, try,
				    replacing, sec_label,
				    false /*part of initiate*/);
		}
		break;
	}
#endif
	case IKEv2:
	{
		/*
		 * If there's already an IKEv2 IKE SA established, use
		 * that and go directly to Quick Mode.  We are even
		 * willing to use one that is still being negotiated,
		 * but only if we are the Initiator (thus we can be
		 * sure that the IDs are not going to change; other
		 * issues around intent might matter).  Note: there is
		 * no way to initiate with a Road Warrior.
		 */
		struct ike_sa *ike =
			pexpect_ike_sa(find_phase1_state(c,
							 LELEM(STATE_V2_ESTABLISHED_IKE_SA) |
							 IKEV2_ISAKMP_INITIATOR_STATES));
		if (ike == NULL) {
			ikev2_out_IKE_SA_INIT_I(c, NULL, policy, try, inception,
						sec_label, background, logger);
		} else if (!IS_IKE_SA_ESTABLISHED(&ike->sa)) {
			/* leave CHILD SA negotiation pending */
			add_pending(background ? null_fd : logger->global_whackfd,
				    ike, c, policy, try,
				    replacing, sec_label,
				    false /*part of initiate*/);
		} else if (!already_has_larval_v2_child(ike, c)) {
			dbg("initiating child sa with "PRI_LOGGER, pri_logger(logger));
			submit_v2_CREATE_CHILD_SA_new_child(ike, c, policy, try, sec_label,
							    logger->global_whackfd);
		}
		break;
	}
	default:
		bad_case(c->ike_version);
	}
}

struct initiate_stuff {
	bool background;
	const char *remote_host;
	bool log_failure;
};

static int initiate_a_connection(struct connection *c, void *arg, struct logger *logger)
{
	const struct initiate_stuff *is = arg;
	/* XXX: something better? */
	close_any(&c->logger->global_whackfd);
	c->logger->global_whackfd = fd_dup(logger->global_whackfd, HERE);
	int result = initiate_connection(c, is->remote_host, is->background) ? 1 : 0;
	if (!result && is->log_failure) {
		llog(RC_FATAL, c->logger, "failed to initiate connection");
	}
	/* XXX: something better? */
	close_any(&c->logger->global_whackfd);
	return result;
}

void initiate_connections_by_name(const char *name, const char *remote_host,
				  bool background, struct logger *logger)
{
	passert(name != NULL);
	struct connection *c = conn_by_name(name, /*strict-match?*/false);
	if (c != NULL) {
		struct initiate_stuff is = {
			.background = background,
			.remote_host = remote_host,
			.log_failure = true,
		};
		initiate_a_connection(c, &is, logger);
	} else {
		struct initiate_stuff is = {
			.background = background,
			.remote_host = remote_host,
			.log_failure = false,
		};
		llog(RC_COMMENT, logger, "initiating all conns with alias='%s'", name);
		int count = foreach_connection_by_alias(name, initiate_a_connection, &is, logger);
		if (count == 0) {
			llog(RC_UNKNOWN_NAME, logger, "no connection named \"%s\"", name);
		}
	}
}

static bool same_host(const char *a_dnshostname, const ip_address *a_host_addr,
		const char *b_dnshostname, const ip_address *b_host_addr)
{
	/* should this be dnshostname and host_addr ?? */

	return a_dnshostname == NULL ?
		b_dnshostname == NULL && sameaddr(a_host_addr, b_host_addr) :
		b_dnshostname != NULL && streq(a_dnshostname, b_dnshostname);
}

static bool same_in_some_sense(const struct connection *a,
			const struct connection *b)
{
	return same_host(a->dnshostname, &a->spd.that.host_addr,
			b->dnshostname, &b->spd.that.host_addr);
}

void restart_connections_by_peer(struct connection *const c, struct logger *logger)
{
	/*
	 * If c is a CK_INSTANCE, it will be removed by terminate_connection.
	 * Any parts of c we need after that must be copied first.
	 */

	struct host_pair *hp = c->host_pair;
	enum connection_kind c_kind = c->kind;
	struct connection *hp_next = hp->connections->hp_next;

	pexpect(hp != NULL);	/* ??? why would this happen? */
	if (hp == NULL)
		return;

	char *dnshostname = clone_str(c->dnshostname, "dnshostname for restart");

	ip_address host_addr = c->spd.that.host_addr;

	struct connection *d;

	for (d = hp->connections; d != NULL;) {
		struct connection *next = d->hp_next; /* copy before d is deleted, CK_INSTANCE */

		if (same_host(dnshostname, &host_addr,
			      d->dnshostname, &d->spd.that.host_addr)) {
			/* This might delete c if CK_INSTANCE */
			/* ??? is there a chance hp becomes dangling? */
			terminate_connections_by_name(d->name, /*quiet?*/false, logger);
		}
		d = next;
	}

	if (c_kind != CK_INSTANCE) {
		/* reference to c is OK because not CK_INSTANCE */
		update_host_pairs(c);
		/* host_pair/host_addr changes with dynamic dns */
		hp = c->host_pair;
		host_addr = c->spd.that.host_addr;
	}

	if (c_kind == CK_INSTANCE && hp_next == NULL) {
		/* in simple cases this is a dangling hp */
		dbg("no connection to restart after termination");
	} else {
		for (d = hp->connections; d != NULL; d = d->hp_next) {
			if (same_host(dnshostname, &host_addr,
					d->dnshostname, &d->spd.that.host_addr))
				initiate_connections_by_name(d->name, /*remote-host*/NULL,
							     /*background?*/true, logger);
		}
	}
	pfreeany(dnshostname);
}

/* (Possibly) Opportunistic Initiation:
 * Knowing clients (single IP addresses), try to build a tunnel.
 * This may involve discovering a gateway and instantiating an
 * Opportunistic connection.  Called when a packet is caught by
 * a %trap, or when whack --oppohere --oppothere is used.
 * It may turn out that an existing or non-opporunistic connection
 * can handle the traffic.
 *
 * Most of the code will be restarted if an ADNS request is made
 * to discover the gateway.  The only difference between the first
 * and second entry is whether gateways_from_dns is NULL or not.
 *	initiate_opportunistic: initial entrypoint
 *	continue_oppo: where we pickup when ADNS result arrives
 *	initiate_opportunistic_body: main body shared by above routines
 *	cannot_ondemand: a helper function to log a diagnostic
 * This structure repeats a lot of code when the ADNS result arrives.
 * This seems like a waste, but anything learned the first time through
 * may no longer be true!
 *
 * After the first IKE message is sent, the regular state machinery
 * carries negotiation forward.
 */

struct find_oppo_bundle {
	const char *want;
	struct {
		/* traffic that triggered the opportunistic exchange */
		ip_endpoint client;
		/* host addresses for traffic (redundant, but convenient) */
		ip_address host_addr;
	} local, remote;
	/* redundant - prococol involved */
	const struct ip_protocol *transport_proto;
	bool held;
	policy_prio_t policy_prio;
	ipsec_spi_t negotiation_shunt;	/* in host order! */
	ipsec_spi_t failure_shunt;	/* in host order! */
	struct logger *logger;	/* has whack attached */
	bool background;
	shunk_t sec_label;
};

static void jam_oppo_bundle(struct jambuf *buf, struct find_oppo_bundle *b)
{
	jam(buf, "initiate on demand by %s from ", b->want);

	jam_address(buf, &b->local.host_addr);
	jam(buf, ":%d", endpoint_hport(b->local.client));

	jam(buf, " to ");

	jam_address(buf, &b->remote.host_addr);
	jam(buf, ":%d", endpoint_hport(b->remote.client));

	jam(buf, " proto=%s", b->transport_proto->name);

	if (b->sec_label.len > 0) {
		jam(buf, " label=");
		jam_sanitized_hunk(buf, b->sec_label);
	}
}

static void cannot_ondemand(lset_t rc_flags, struct find_oppo_bundle *b, const char *ughmsg)
{
	LLOG_JAMBUF(rc_flags, b->logger, buf) {
		jam(buf, "cannot ");
		jam_oppo_bundle(buf, b);
		jam(buf, ": %s", ughmsg);
	}

	if (b->held) {
		/*
		 * This was filled in for us based on packet trigger
		 * and not whack --oppo trigger.  Hence, there really
		 * is something in the kernel that needs updating.
		 *
		 * Replace negotiationshunt (hold or pass) with
		 * failureshunt (hold or pass).  If no failure_shunt
		 * specified, use SPI_PASS -- THIS MAY CHANGE.
		 */
		dbg("cannot_ondemand() replaced negotiationshunt with bare failureshunt=%s",
		    enum_name_short(&policy_spi_names, b->failure_shunt));
		pexpect(b->failure_shunt != 0); /* PAUL: I don't think this can/should happen? */
		const struct ip_info *afi = address_type(&b->local.host_addr);
		const ip_address null_host = afi->address.any;
		/* ports? assumed wide? */
		ip_selector src = selector_from_address_protocol(b->local.host_addr,
								 b->transport_proto);
		ip_selector dst = selector_from_address_protocol(b->remote.host_addr,
								 b->transport_proto);
		if (!raw_policy(KP_REPLACE_OUTBOUND,
				&null_host, &src, &null_host, &dst,
				/*from*/htonl(b->negotiation_shunt),
				/*to*/htonl(b->failure_shunt),
				b->transport_proto->ipproto,
				ET_INT, esp_transport_proto_info,
				deltatime(SHUNT_PATIENCE),
				BOTTOM_PRIO, /* we don't know connection for priority yet */
				NULL, /* sa_marks */
				0 /* xfrm interface id */,
				b->sec_label, b->logger,
				"%s() %s", __func__, ughmsg)) {
			llog(RC_LOG_SERIOUS, b->logger,
			     "failed to replace negotiationshunt with bare failureshunt");
			return;
		}
	}
}

static ip_selector shunt_from_traffic_end(const char *what,
					  const ip_endpoint traffic_endpoint,
					  const struct end *end)
{
	ip_address shunt_address = endpoint_address(traffic_endpoint);
	const ip_protocol *shunt_protocol;
	ip_port shunt_port;
	if (end->protocol == 0) {
		dbg("widening %s shunt to all protocols + all ports", what);
		pexpect(end->port == 0);
		shunt_protocol = &ip_protocol_unset;
		shunt_port = unset_port;
	} else if (end->port == 0) {
		dbg("widening %s shunt to all ports", what);
		shunt_protocol = protocol_by_ipproto(end->protocol);
		shunt_port = unset_port;
		pexpect(endpoint_protocol(traffic_endpoint) == shunt_protocol);
	} else {
		dbg("leaving %s shunt alone", what);
		shunt_protocol = protocol_by_ipproto(end->protocol);
		shunt_port = endpoint_port(traffic_endpoint);
		pexpect(end->port == hport(shunt_port));
		pexpect(endpoint_protocol(traffic_endpoint) == shunt_protocol);
	}
	return selector_from_address_protocol_port(shunt_address,
						   shunt_protocol,
						   shunt_port);
}

static void initiate_ondemand_body(struct find_oppo_bundle *b)
{
	threadtime_t inception = threadtime_start();

	if (b->sec_label.len > 0) {
		dbg("oppo bundle: received security label string: "PRI_SHUNK,
		    pri_shunk(b->sec_label));
	}

	/*
	 * What connection shall we use?  First try for one that
	 * explicitly handles the clients.
	 */

	if (!endpoint_is_specified(b->local.client) &&
	    !endpoint_is_specified(b->remote.client)) {
		cannot_ondemand(RC_OPPOFAILURE, b, "impossible IP address");
		return;
	}

	if (address_eq_address(b->local.host_addr, b->remote.host_addr)) {
		/*
		 * NETKEY gives us acquires for our own IP. This code
		 * does not handle talking to ourselves on another ip.
		 */
		cannot_ondemand(RC_OPPOFAILURE, b, "acquire for our own IP address");
		return;
	}

	struct spd_route *sr = NULL;
	struct connection *c = find_connection_for_clients(&sr,
							   /*ip_traffic*/&b->local.client, &b->remote.client,
							   b->sec_label, b->logger);
	if (c == NULL) {
		/*
		 * No connection explicitly handles the clients and
		 * there are no Opportunistic connections -- whine and
		 * give up.  The failure policy cannot be gotten from
		 * a connection; we pick %pass.
		 */
		cannot_ondemand(RC_OPPOFAILURE, b, "no routed template covers this pair");
		return;
	}

	if (c->ike_version == IKEv2 && c->spd.this.sec_label.len > 0 && c->kind == CK_TEMPLATE) {
		dbg("IKEv2 connection has security label");

		if (b->sec_label.len == 0) {
			cannot_ondemand(RC_LOG_SERIOUS, b,
					"kernel acquire missing security label");
			return;
		}

		if (!sec_label_within_range(HUNK_AS_SHUNK(b->sec_label),
					    c->spd.this.sec_label , b->logger)) {
			cannot_ondemand(RC_LOG_SERIOUS, b,
					"received kernel security label does not fall within range of our connection");
			return;
		}

		/*
		 * We've found a connection that can serve.  Do we
		 * have to initiate it?  Not if there is currently an
		 * IPSEC SA.  This may be redundant if a
		 * non-opportunistic negotiation is already being
		 * attempted.
		 *
		 * If we are to proceed asynchronously, b->whackfd
		 * will be NULL_WHACKFD.
		 *
		 * We have a connection: fill in the negotiation_shunt
		 * and failure_shunt.
		 */
		b->failure_shunt = shunt_policy_spi(c, false);
		b->negotiation_shunt = (c->policy & POLICY_NEGO_PASS) ? SPI_PASS : SPI_HOLD;

		/*
		 * Annouce this to the world.  Use c->logger instead?
		 */
		LLOG_JAMBUF(RC_LOG, b->logger, buf) {
			jam_oppo_bundle(buf, b);
			/* jam(buf, " using "); */
		}

		ipsecdoi_initiate(c, c->policy, 1, SOS_NOBODY, &inception, b->sec_label,
				  b->background, b->logger);

		endpoint_buf b1;
		endpoint_buf b2;
		dbg("initiated on demand using security label and %s from %s to %s",
		    (c->policy & POLICY_AUTH_NULL) ? "AUTH_NULL" : "RSASIG",
		    str_endpoint(&b->local.client, &b1),
		    str_endpoint(&b->remote.client, &b2));

		return;
	}

	if ((c->policy & POLICY_OPPORTUNISTIC) && !orient(c, b->logger)) {
		/*
		 * happens when dst is ourselves on a different IP
		 */
		cannot_ondemand(RC_OPPOFAILURE, b, "connection to self on another IP?");
		return;
	}

	if (c->kind == CK_TEMPLATE && (c->policy & POLICY_OPPORTUNISTIC) == 0) {
		cannot_ondemand(RC_NOPEERIP, b, "template connection");
		return;
	}

	/* Labeled IPsec and Opportunistic cannot both be used */
	if (c->kind == CK_INSTANCE && b->sec_label.len == 0) {
		connection_buf cib;
		/* there is already an instance being negotiated */
#if 0
		llog(RC_LOG, b->logger,
			    "rekeying existing instance "PRI_CONNECTION", due to acquire",
			    pri_connection(c, &cib));

		/*
		 * We used to return here, but rekeying is a better
		 * choice.  If we got the acquire, it is because
		 * something turned stuff into a %trap, or something
		 * got deleted, perhaps due to an expiry.
		 */
#else
		/*
		 * XXX We got an acquire (NETKEY only?) for
		 * something we already have an instance for ??
		 * We cannot process as normal because the
		 * bare_shunts table and assign_holdpass()
		 * would get confused between this new entry
		 * and the existing one.  So we return without
		 * doing anything.
		 */
		llog(RC_LOG, b->logger,
			    "ignoring found existing connection instance "PRI_CONNECTION" that covers kernel acquire with IKE state #%lu and IPsec state #%lu - due to duplicate acquire?",
			    pri_connection(c, &cib),
			    c->newest_ike_sa, c->newest_ipsec_sa);
		return;
#endif
	}

	if (c->kind != CK_TEMPLATE) {
		/*
		 * We've found a connection that can serve.  Do we
		 * have to initiate it?  Not if there is currently an
		 * IPSEC SA.  This may be redundant if a
		 * non-opportunistic negotiation is already being
		 * attempted.
		 *
		 * If we are to proceed asynchronously, b->whackfd
		 * will be NULL_WHACKFD.
		 *
		 * We have a connection: fill in the negotiation_shunt
		 * and failure_shunt.
		 */
		b->failure_shunt = shunt_policy_spi(c, false);
		b->negotiation_shunt = (c->policy & POLICY_NEGO_PASS) ? SPI_PASS : SPI_HOLD;

		/*
		 * Otherwise, there is some kind of static conn that
		 * can handle this connection, so we initiate it.
		 * Only needed if we this was triggered by a packet,
		 * not by whack
		 */
		if (b->held) {
			/*
			 * Add the kernel shunt to the pluto bare
			 * shunt list.
			 *
			 * We need to do this because the %hold shunt
			 * was installed by kernel and we want to keep
			 * track of it inside pluto.
			 *
			 * XXX: hack to keep code below happy - need
			 * to figigure out what to do with the shunt
			 * functions.
			 */
			ip_selector our_client[] = { selector_from_endpoint(b->local.client), };
			ip_selector peer_client[] = { selector_from_endpoint(b->remote.client), };
			add_bare_shunt(our_client, peer_client, b->transport_proto->ipproto,
				       SPI_HOLD, b->want, b->logger);

			if (assign_holdpass(c, sr, b->transport_proto->ipproto, b->negotiation_shunt,
					    &b->local.host_addr, &b->remote.host_addr)) {
				dbg("initiate_ondemand_body() installed negotiation_shunt,");
			} else {
				llog(RC_LOG, b->logger,
					    "initiate_ondemand_body() failed to install negotiation_shunt,");
			}
		}

		LLOG_JAMBUF(RC_LOG, b->logger, buf) {
			jam_oppo_bundle(buf, b);
			/* jam(buf, " using "); */
		}

		ipsecdoi_initiate(c, c->policy, 1, SOS_NOBODY, &inception, b->sec_label,
				  b->background, b->logger);

		endpoint_buf b1;
		endpoint_buf b2;
		dbg("initiated on demand using %s from %s to %s",
		    (c->policy & POLICY_AUTH_NULL) ? "AUTH_NULL" : "RSASIG",
		    str_endpoint(&b->local.client, &b1),
		    str_endpoint(&b->remote.client, &b2));

		return;
	}

	/*
	 * We are handling an opportunistic situation.  This involves
	 * several DNS lookup steps that require suspension.
	 *
	 * NOTE: will be re-implemented
	 *
	 * old comment:
	 *
	 * The first chunk of code handles the result of the previous
	 * DNS query (if any).  It also selects the kind of the next
	 * step.  The second chunk initiates the next DNS query (if
	 * any).
	 */

	/*
	 * XXX: this is unconditional; at one point it was conditional
	 * on DBG() to file; or whack to whack.
	 */
	LLOG_JAMBUF(RC_LOG, b->logger, buf) {
		jam_oppo_bundle(buf, b);
	}

	connection_buf cib;
	dbg("creating new instance from "PRI_CONNECTION, pri_connection(c, &cib));

	if (sr->routing == RT_ROUTED_PROSPECTIVE && eclipsable(sr)) {
		dbg("route is eclipsed");
		sr->routing = RT_ROUTED_ECLIPSED;
		eclipse_count++;
	}

	pexpect(c->kind == CK_TEMPLATE);
	passert(c->policy & POLICY_OPPORTUNISTIC); /* can't initiate Road Warrior connections */

	/* we have a connection: fill in the negotiation_shunt and failure_shunt */
	b->failure_shunt = shunt_policy_spi(c, false);
	b->negotiation_shunt = (c->policy & POLICY_NEGO_PASS) ? SPI_PASS : SPI_HOLD;

	/*
	 * Always have shunts with protoports, even when no
	 * protoport= settings in conn.
	 */
	const char *const addwidemsg = "oe-negotiating";

	/*
	 * Widen the shunt?
	 *
	 * If we have protoport= set, narrow to it.  Zero the
	 * ephemeral port.
	 *
	 * XXX: should local/remote shunts be computed independently?
	 */
	pexpect(c->spd.this.protocol == c->spd.that.protocol);
	ip_selector local_shunt = shunt_from_traffic_end("local", b->local.client, &c->spd.this);
	ip_selector remote_shunt = shunt_from_traffic_end("remote", b->remote.client, &c->spd.that);

	const ip_protocol *shunt_protocol = selector_protocol(local_shunt);
	pexpect(shunt_protocol == selector_protocol(remote_shunt));

	/* XXX: re-use c */
	/* XXX Shouldn't this pass b->sec_label too in theory?  But we don't support OE with labels. */
	c = build_outgoing_opportunistic_connection(&b->local.client,
						    &b->remote.client);
	if (c == NULL) {
		cannot_ondemand(RC_OPPOFAILURE, b, "no suitable connection between endpoints");
		return;
	}

	selectors_buf sb;
	dbg("going to initiate opportunistic %s, first installing %s negotiationshunt",
	    str_selectors(&local_shunt, &remote_shunt, &sb),
	    enum_name_short(&policy_spi_names, b->negotiation_shunt));

	/*
	 * PAUL: should this use shunt_eroute() instead of API
	 * violation into raw_policy()?
	 */

	if (!raw_policy(KP_ADD_OUTBOUND,
			&b->local.host_addr, &local_shunt,
			&b->remote.host_addr, &remote_shunt,
			htonl(SPI_HOLD), /* kernel induced */
			htonl(b->negotiation_shunt),
			shunt_protocol->ipproto,
			ET_INT, esp_transport_proto_info,
			deltatime(SHUNT_PATIENCE),
			calculate_sa_prio(c, LIN(POLICY_OPPORTUNISTIC, c->policy) ? true : false),
			NULL, 0 /* xfrm-if-id */,
			b->sec_label, b->logger,
			"%s() %s", __func__, addwidemsg)) {
		llog(RC_LOG, b->logger, "adding bare wide passthrough negotiationshunt failed");
	} else {
		dbg("adding bare (possibly wided) passthrough negotiationshunt succeeded (violating API)");
		add_bare_shunt(&local_shunt, &remote_shunt,
			       shunt_protocol->ipproto, SPI_HOLD,
			       addwidemsg, b->logger);
	}

	/* If we are to proceed asynchronously, b->background will be true. */
	passert(c->kind == CK_INSTANCE);
	passert(HAS_IPSEC_POLICY(c->policy));
	passert(LHAS(LELEM(RT_UNROUTED) |
		     LELEM(RT_ROUTED_PROSPECTIVE),
		     c->spd.routing));
	/*
	 * Save the selector in .client.
	 */
	c->spd.this.client = local_shunt;
	c->spd.that.client = remote_shunt;

	if (b->held) {
		if (assign_holdpass(c, &c->spd,
				    b->transport_proto->ipproto,
				    b->negotiation_shunt,
				    &b->local.host_addr,
				    &b->remote.host_addr)) {
			dbg("assign_holdpass succeeded");
		} else {
			llog(RC_LOG, b->logger, "assign_holdpass failed!");
		}
	}

	ipsecdoi_initiate(c, c->policy, 1,
			  SOS_NOBODY, &inception, b->sec_label,
			  b->background, b->logger);
}

void initiate_ondemand(const ip_endpoint *local_client,
		       const ip_endpoint *remote_client,
		       bool by_acquire, bool background,
		       const shunk_t sec_label,
		       struct logger *logger)
{
	const char *why = by_acquire ? "acquire" : "whack"; /*enum?*/
	const struct ip_protocol *transport_proto = endpoint_protocol(*local_client);
	pexpect(transport_proto != NULL);
	pexpect(transport_proto == endpoint_protocol(*remote_client));
	struct find_oppo_bundle b = {
		.want = why,   /* fudge */
		.local.client = *local_client,
		.remote.client = *remote_client,
		.local.host_addr = endpoint_address(*local_client),
		.remote.host_addr = endpoint_address(*remote_client),
		.transport_proto = transport_proto,
		.held = by_acquire,
		.policy_prio = BOTTOM_PRIO,
		.negotiation_shunt = SPI_HOLD, /* until we found connection policy */
		.failure_shunt = SPI_HOLD, /* until we found connection policy */
		.logger = logger, /*on-stack*/
		.background = background,
		.sec_label = sec_label
	};

	initiate_ondemand_body(&b);
}

/*
 * Find a connection that owns the shunt eroute between subnets.
 * There ought to be only one.
 * This might get to be a bottleneck -- try hashing if it does.
 */
struct connection *shunt_owner(const ip_selector *ours, const ip_selector *peers)
{
	struct connection *c;

	dbg("FOR_EACH_CONNECTION_... in %s", __func__);
	for (c = connections; c != NULL; c = c->ac_next) {
		const struct spd_route *sr;

		for (sr = &c->spd; sr; sr = sr->spd_next) {
			if (shunt_erouted(sr->routing) &&
			    selector_subnet_eq_subnet(*ours, sr->this.client) &&
			    selector_subnet_eq_subnet(*peers, sr->that.client))
				return c;
		}
	}
	return NULL;
}


/* time before retrying DDNS host lookup for phase 1 */
#define PENDING_DDNS_INTERVAL secs_per_minute

/*
 * Call me periodically to check to see if any DDNS tunnel can come up.
 * The order matters, we try to do the cheapest checks first.
 */

static void connection_check_ddns1(struct connection *c, struct logger *logger)
{
	struct connection *d;
	ip_address new_addr;
	const char *e;

	/* this is the cheapest check, so do it first */
	if (c->dnshostname == NULL)
		return;

	/* should we let the caller get away with this? */
	if (NEVER_NEGOTIATE(c->policy))
		return;

	/*
	 * We do not update a resolved address once resolved.  That might
	 * be considered a bug.  Can we count on liveness if the target
	 * changed IP?  The connection might need to get its host_addr
	 * updated.  Do we do that when terminating the conn?
	 */
	if (address_is_specified(c->spd.that.host_addr)) {
		connection_buf cib;
		dbg("pending ddns: connection "PRI_CONNECTION" has address",
		    pri_connection(c, &cib));
		return;
	}

	if (c->spd.that.has_port_wildcard ||
	    ((c->policy & POLICY_SHUNT_MASK) == POLICY_SHUNT_TRAP &&
	     c->spd.that.has_id_wildcards)) {
		connection_buf cib;
		dbg("pending ddns: connection "PRI_CONNECTION" with wildcard not started",
		    pri_connection(c, &cib));
		return;
	}

	e = ttoaddress_dns(shunk1(c->dnshostname), NULL/*UNSPEC*/, &new_addr);
	if (e != NULL) {
		connection_buf cib;
		dbg("pending ddns: connection "PRI_CONNECTION" lookup of \"%s\" failed: %s",
		    pri_connection(c, &cib), c->dnshostname, e);
		return;
	}

	if (address_is_unset(&new_addr) || address_is_any(new_addr)) {
		connection_buf cib;
		dbg("pending ddns: connection "PRI_CONNECTION" still no address for \"%s\"",
		    pri_connection(c, &cib), c->dnshostname);
		return;
	}

	/* do not touch what is not broken */
	struct state *newest_ike_sa = state_with_serialno(c->newest_ike_sa);
	if (newest_ike_sa != NULL &&
	    (IS_IKE_SA_ESTABLISHED(newest_ike_sa) ||
	     IS_V1_ISAKMP_SA_ESTABLISHED(newest_ike_sa))) {
		connection_buf cib;
		dbg("pending ddns: connection "PRI_CONNECTION" is established",
		    pri_connection(c, &cib));
		return;
	}

	/*
	 * This cannot currently be reached.  If in the future we do,
	 * don't do weird things
	 */
	if (sameaddr(&new_addr, &c->spd.that.host_addr)) {
		connection_buf cib;
		dbg("pending ddns: IP address unchanged for connection "PRI_CONNECTION"",
		    pri_connection(c, &cib));
		return;
	}

	/* I think this is OK now we check everything above. */

	/*
	 * It seems DNS failure puts a connection into CK_TEMPLATE, so once the
	 * resolve is fixed, it is manually placed in CK_PERMANENT here.
	 * However, that is questionable, eg. for connections that are templates
	 * to begin with, such as those with narrowing=yes. These will mistakenly
	 * be placed into CK_PERMANENT.
	 */

	connection_buf cib;
	dbg("pending ddns: changing connection "PRI_CONNECTION" to CK_PERMANENT",
	    pri_connection(c, &cib));
	c->kind = CK_PERMANENT;

	address_buf old, new;
	dbg("pending ddns: updating IP address for %s from %s to %s",
	    c->dnshostname,
	    str_address_sensitive(&c->spd.that.host_addr, &old),
	    str_address_sensitive(&new_addr, &new));
	c->spd.that.host_addr = new_addr;
	update_ends_from_this_host_addr(&c->spd.that, &c->spd.this);

	/*
	 * reduce the work we do by updating all connections waiting for this
	 * lookup
	 */
	update_host_pairs(c);
	if (c->policy & POLICY_UP) {
		connection_buf cib;
		dbg("pending ddns: re-initiating connection "PRI_CONNECTION"",
		    pri_connection(c, &cib));
		/* XXX: why not call initiate_connection() directly? */
		initiate_connections_by_name(c->name, /*remote-host*/NULL,
					     /*background?*/true, logger);
	} else {
		connection_buf cib;
		dbg("pending ddns: connection "PRI_CONNECTION" was updated, but does not want to be up",
		    pri_connection(c, &cib));
	}

	/* no host pairs, no more to do */
	pexpect(c->host_pair != NULL);	/* ??? surely */
	if (c->host_pair == NULL)
		return;

	for (d = c->host_pair->connections; d != NULL; d = d->hp_next) {
		if (c != d && same_in_some_sense(c, d) && (d->policy & POLICY_UP)) {
			initiate_connections_by_name(d->name, /*remote-host*/NULL,
						     /*background?*/true, logger);
		}
	}
}

void connection_check_ddns(struct logger *logger)
{
	struct connection *c, *cnext;
	threadtime_t start = threadtime_start();

	dbg("FOR_EACH_CONNECTION_... in %s", __func__);
	for (c = connections; c != NULL; c = cnext) {
		cnext = c->ac_next;
		connection_check_ddns1(c, logger);
	}
	check_orientations(logger);

	threadtime_stop(&start, SOS_NOBODY, "in %s for hostname lookup", __func__);
}

/* time between scans of pending phase2 */
#define PENDING_PHASE2_INTERVAL (2 * secs_per_minute)

/*
 * Call connection_check_phase2 periodically to check to see if pending
 * phase2s ever got unstuck, and if not, perform DPD action.
 */
void connection_check_phase2(struct logger *logger)
{
	struct connection *c, *cnext;

	dbg("FOR_EACH_CONNECTION_... in %s", __func__);
	for (c = connections; c != NULL; c = cnext) {
		cnext = c->ac_next;

		if (NEVER_NEGOTIATE(c->policy)) {
			connection_buf cib;
			dbg("pending review: connection "PRI_CONNECTION" has no negotiated policy, skipped",
			    pri_connection(c, &cib));
			continue;
		}

		if (!(c->policy & POLICY_UP)) {
			connection_buf cib;
			dbg("pending review: connection "PRI_CONNECTION" was not up, skipped",
			    pri_connection(c, &cib));
			continue;
		}

		connection_buf cib;
		dbg("pending review: connection "PRI_CONNECTION" checked",
		    pri_connection(c, &cib));

		if (pending_check_timeout(c)) {
			ipstr_buf b;
			connection_buf cib;

			llog(RC_LOG, logger,
				    "pending IPsec SA negotiation with %s "PRI_CONNECTION" took too long -- replacing phase 1",
				    ipstr(&c->spd.that.host_addr, &b),
				    pri_connection(c, &cib));

			struct state *p1st;
			switch (c->ike_version) {
#ifdef USE_IKEv1
			case IKEv1:
				p1st = find_phase1_state(c,
							 (V1_ISAKMP_SA_ESTABLISHED_STATES |
							  V1_PHASE1_INITIATOR_STATES));
				break;
#endif
			case IKEv2:
				p1st = find_phase1_state(c, IKEV2_ISAKMP_INITIATOR_STATES);
				break;
			default:
				bad_case(c->ike_version);
			}

			if (p1st != NULL) {
				/* arrange to rekey the phase 1, if there was one. */
				if (c->dnshostname != NULL) {
					restart_connections_by_peer(c, logger);
				} else {
					event_force(EVENT_SA_REPLACE, p1st);
				}
			} else {
				/* start a new connection. Something wanted it up */
				struct initiate_stuff is = {
					.remote_host = NULL,
				};
				initiate_a_connection(c, &is, logger);
			}
		}
	}
}

void init_connections(void)
{
	enable_periodic_timer(EVENT_PENDING_DDNS, connection_check_ddns,
			      deltatime(PENDING_DDNS_INTERVAL));
	enable_periodic_timer(EVENT_PENDING_PHASE2, connection_check_phase2,
			      deltatime(PENDING_PHASE2_INTERVAL));
}
