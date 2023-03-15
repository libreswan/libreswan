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
#include "kernel_ops.h"			/* for struct kernel_acquire */
#include "log.h"
#include "ikev1_spdb.h"			/* for kernel_alg_makedb() !?! */
#include "initiate.h"
#include "host_pair.h"
#include "orient.h"
#include "ikev1.h"			/* for aggr_outI1() and main_outI1() */
#include "ikev1_quick.h"		/* for quick_outI1() */
#include "ikev2.h"			/* for ikev2_state_transition_fn; */
#include "ikev2_ike_sa_init.h"		/* for ikev2_out_IKE_SA_INIT_I() */
#include "ikev2_create_child_sa.h"	/* for initiate_v2_CREATE_CHILD_SA_create_child() */
#include "labeled_ipsec.h"		/* for sec_label_within_range() */
#include "ip_info.h"
#include "instantiate.h"
#include "routing.h"

static bool initiate_connection_1_basics(struct connection *c,
					 const char *remote_host,
					 bool background);
static bool initiate_connection_2_address(struct connection *c,
					  const char *remote_host,
					  bool background,
					  const threadtime_t inception);
static bool initiate_connection_3_template(struct connection *c,
					   bool background,
					   const threadtime_t inception);
static bool initiate_connection_4_fab(struct connection *c,
				      bool background,
				      const threadtime_t inception);

/* attach FD */

bool initiate_connection(struct connection *c,
			 const char *remote_host,
			 bool background, bool log_failure,
			 struct logger *logger)
{
	ldbg_connection(c, HERE, "initiate: remote_host=%s",
			(remote_host == NULL ? "<null> (using host from connection)" : remote_host));
	/* XXX: something better? */
	fd_delref(&c->logger->global_whackfd);
	c->logger->global_whackfd =
		(/* old IKE SA */ fd_p(logger->object_whackfd) ? fd_addref(logger->object_whackfd) :
		 /* global */ fd_p(logger->global_whackfd) ? fd_addref(logger->global_whackfd) :
		 null_fd);
	bool ok = initiate_connection_1_basics(c, remote_host, background);
	if (log_failure && !ok) {
		llog(RC_FATAL, c->logger, "failed to initiate connection");
	}
	/* XXX: something better? */
	fd_delref(&c->logger->global_whackfd);
	return ok;
}

/*
 * Perform some basic, and presumably cheap, checks on the connection.
 * No point continuing if the connection isn't viable.
 */

static bool initiate_connection_1_basics(struct connection *c,
					 const char *remote_host,
					 bool background)
{
	connection_buf cb;
	dbg("%s() for "PRI_CONNECTION" in the %s with "PRI_LOGGER,
	    __func__, pri_connection(c, &cb),
	    background ? "background" : "foreground",
	    pri_logger(c->logger));

	if (!oriented(c)) {
		ipstr_buf a;
		ipstr_buf b;
		llog(RC_ORIENT, c->logger,
		     "we cannot identify ourselves with either end of this connection.  %s or %s are not usable",
		     ipstr(&c->local->host.addr, &a),
		     ipstr(&c->remote->host.addr, &b));
		return false;
	}

	if (NEVER_NEGOTIATE(c->policy)) {
		llog(RC_INITSHUNT, c->logger,
		     "cannot initiate an authby=never connection");
		return false;
	}

	threadtime_t inception = threadtime_start();
	return initiate_connection_2_address(c, remote_host, background, inception);
}

/*
 * Resolve remote host, If there's a REMOTE_HOST, convert that into an
 * IP address and the instantiate C filling in that address as the
 * peer.
 */

static bool initiate_connection_2_address(struct connection *c,
					  const char *remote_host,
					  bool background,
					  const threadtime_t inception)
{
	connection_buf cb;
	dbg("%s() for "PRI_CONNECTION" in the %s with "PRI_LOGGER,
	    __func__, pri_connection(c, &cb),
	    background ? "background" : "foreground",
	    pri_logger(c->logger));

	if (remote_host != NULL && !address_is_specified(c->remote->host.addr)) {

		/*
		 * The connection has no remote address but whack
		 * supplied one.  Assuming it resolves, use that as
		 * the remote address and then continue.
		 */

		if (c->kind != CK_TEMPLATE) {
			llog(RC_NOPEERIP, c->logger,
			     "cannot instantiate non-template connection to a supplied remote IP address");
			return false;
		}

		ip_address remote_ip;
		err_t e = ttoaddress_dns(shunk1(remote_host), NULL/*UNSPEC*/, &remote_ip);
		if (e != NULL) {
			llog(RC_NOPEERIP, c->logger,
			     "cannot instantiate connection: resolution of \"%s\" failed: %s",
			     remote_host, e);
			return false;
		}

		if (!address_is_specified(remote_ip)) {
			llog(RC_NOPEERIP, c->logger,
			     "cannot instantiate connection: \"%s\" resolved to the unspecified address",
			     remote_host);
			return false;
		}

		struct connection *d;
		if (labeled(c)) {
			d = sec_label_parent_instantiate(c, remote_ip, HERE);
		} else {
			d = spd_instantiate(c, remote_ip, HERE);
		}

		/*
		 * D could either be an instance, or a sec_label
		 * connection?
		 */

		/* XXX: something better? */
		fd_delref(&d->logger->global_whackfd);
		d->logger->global_whackfd = fd_addref(c->logger->global_whackfd);

		address_buf ab;
		llog(RC_LOG, d->logger,
		     "instantiated connection with remote IP set to %s",
		     str_address(&remote_ip, &ab));

		bool ok = initiate_connection_3_template(d, background, inception);

		if (!ok) {
			/* instance so free to delete */
			delete_connection(&d);
		} else {
			/* XXX: something better? */
			fd_delref(&d->logger->global_whackfd);
		}
		return ok;
	}

	if (!address_is_specified(c->remote->host.addr)) {

		/*
		 * Cant proceed; there's no peer address!  However, if
		 * there's a DNS hostname flip things to up so that
		 * the DNS code, below, will kick in.  Try to provide
		 * a really detailed message!!!
		 */

		if (c->config->dnshostname != NULL) {
			if (c->policy & POLICY_IKEV2_ALLOW_NARROWING) {
				esb_buf b;
				llog(RC_NOPEERIP, c->logger,
				     "cannot initiate connection without resolved dynamic peer IP address, will keep retrying (kind=%s, narrowing=%s)",
				     enum_show(&connection_kind_names, c->kind, &b),
				     bool_str((c->policy & POLICY_IKEV2_ALLOW_NARROWING) != LEMPTY));
			} else {
				esb_buf b;
				llog(RC_NOPEERIP, c->logger,
				     "cannot initiate connection without resolved dynamic peer IP address, will keep retrying (kind=%s)",
				     enum_show(&connection_kind_names, c->kind, &b));
			}
			dbg("%s() connection '%s' +POLICY_UP", __func__, c->name);
			c->policy |= POLICY_UP;
			return true;
		}

		if (c->policy & POLICY_IKEV2_ALLOW_NARROWING) {
			esb_buf b;
			llog(RC_NOPEERIP, c->logger,
			     "cannot initiate connection without knowing peer IP address (kind=%s narrowing=%s)",
			     enum_show(&connection_kind_names, c->kind, &b),
			     bool_str((c->policy & POLICY_IKEV2_ALLOW_NARROWING) != LEMPTY));
		} else {
			esb_buf b;
			llog(RC_NOPEERIP, c->logger,
			     "cannot initiate connection (serial "PRI_CO") without knowing peer IP address (kind=%s)",
			     pri_co(c->serialno),
			     enum_show(&connection_kind_names, c->kind, &b));
		}
		return false;
	}

	return initiate_connection_3_template(c, background, inception);
}

static bool initiate_connection_3_template(struct connection *c,
					    bool background,
					    const threadtime_t inception)
{
	connection_buf cb;
	dbg("%s() for "PRI_CONNECTION" in the %s with "PRI_LOGGER,
	    __func__, pri_connection(c, &cb),
	    background ? "background" : "foreground",
	    pri_logger(c->logger));

	passert(address_is_specified(c->remote->host.addr));

	if (labeled_template(c)) {
		struct connection *d =
			sec_label_parent_instantiate(c, c->remote->host.addr, HERE);
		/* XXX: something better? */
		fd_delref(&d->logger->global_whackfd);
		d->logger->global_whackfd = fd_addref(c->logger->global_whackfd);
		/*
		 * LOGGING: why not log this (other than it messes
		 * with test output)?
		 */
		llog(LOG_STREAM|RC_LOG, d->logger, "instantiated connection");
		/* flip cur_connection */
		bool ok = initiate_connection_4_fab(d, background, inception);
		if (!ok) {
			delete_connection(&d);
		} else {
			/* XXX: something better? */
			fd_delref(&d->logger->global_whackfd);
		}
		return ok;
	}

	if (c->kind == CK_TEMPLATE &&
	    c->config->ike_version == IKEv2 &&
	    (c->policy & POLICY_IKEV2_ALLOW_NARROWING)) {
		struct connection *d = spd_instantiate(c, c->remote->host.addr, HERE);
		/* XXX: something better? */
		fd_delref(&d->logger->global_whackfd);
		d->logger->global_whackfd = fd_addref(c->logger->global_whackfd);
		/*
		 * LOGGING: why not log this (other than it messes
		 * with test output)?
		 */
		llog(LOG_STREAM|RC_LOG, d->logger, "instantiated connection");
		/* flip cur_connection */
		bool ok = initiate_connection_4_fab(d, background, inception);
		if (!ok) {
			delete_connection(&d);
		} else {
			/* XXX: something better? */
			fd_delref(&d->logger->global_whackfd);
		}
		return ok;
	}

	return initiate_connection_4_fab(c, background, inception);
}

static bool initiate_connection_4_fab(struct connection *c,
				      bool background,
				      const threadtime_t inception)
{
	connection_buf cb;
	dbg("%s() for "PRI_CONNECTION" in the %s with "PRI_LOGGER,
	    __func__, pri_connection(c, &cb), background ? "background" : "foreground",
	    pri_logger(c->logger));

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
	 * XXX: mumble something about c->config->ike_version
	 */
#ifdef USE_IKEv1
	if (c->config->ike_version == IKEv1 &&
	    (c->policy & (POLICY_ENCRYPT | POLICY_AUTHENTICATE))) {
		struct db_sa *phase2_sa = v1_kernel_alg_makedb(c->policy, c->config->child_proposals,
							       true, c->logger);
		if (c->config->child_proposals.p != NULL && phase2_sa == NULL) {
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
			  (c->config->ike_version == IKEv1 ? HUNK_AS_SHUNK(c->child.sec_label) : null_shunk),
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
	ldbg_connection(c, HERE, "%s() with sec_label "PRI_SHUNK,
			__func__, pri_shunk(sec_label));

	switch (c->config->ike_version) {
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
			add_v1_pending(whackfd, pexpect_ike_sa(st),
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
		 * that and go directly to a CHILD exchange.
		 *
		 * We are even willing to use one that is still being
		 * established, but only if we are the Initiator (thus
		 * we can be sure that the IDs are not going to
		 * change; other issues around intent might matter).
		 * Note: there is no way to initiate with a Road
		 * Warrior.
		 */
		struct ike_sa *ike =
			pexpect_ike_sa(find_phase1_state(c,
							 LELEM(STATE_V2_ESTABLISHED_IKE_SA) |
							 IKEV2_ISAKMP_INITIATOR_STATES));
		if (ike != NULL) {
			dbg("found #%lu in state %s established=%s viable=%s",
			    ike->sa.st_serialno, ike->sa.st_state->name,
			    bool_str(IS_IKE_SA_ESTABLISHED(&ike->sa)),
			    bool_str(ike->sa.st_viable_parent));
		}
		if (ike == NULL) {
			initiate_v2_IKE_SA_INIT_request(c, NULL, policy, try, inception,
							sec_label, background, logger);
		} else if (!IS_IKE_SA_ESTABLISHED(&ike->sa)) {
			/* leave CHILD SA negotiation pending */
			struct connection *cc;
			if (c->config->sec_label.len > 0) {
				/* sec-labels require a separate child connection */
				cc = sec_label_child_instantiate(ike, sec_label, HERE);
			} else {
				cc = c;
			}
			add_v2_pending(background ? null_fd : logger->global_whackfd,
				       ike, cc, policy, try,
				       replacing, sec_label,
				       false /*part of initiate*/);
		} else if (!already_has_larval_v2_child(ike, c)) {
			dbg("initiating child sa with "PRI_LOGGER, pri_logger(logger));
			struct connection *cc;
			if (c->config->sec_label.len > 0) {
				cc = sec_label_child_instantiate(ike, sec_label, HERE);
			} else {
				cc = c;
			}
			submit_v2_CREATE_CHILD_SA_new_child(ike, cc, policy, try,
							    logger->global_whackfd);
		}
		break;
	}
	default:
		bad_case(c->config->ike_version);
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

	char *dnshostname = clone_str(c->config->dnshostname, "dnshostname for restart");

	ip_address host_addr = c->remote->host.addr;

	struct connection *d;

	for (d = hp->connections; d != NULL;) {
		struct connection *next = d->hp_next; /* copy before d is deleted, CK_INSTANCE */

		if (same_host(dnshostname, &host_addr,
			      d->config->dnshostname, &d->remote->host.addr)) {
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
		host_addr = c->remote->host.addr;
	}

	if (c_kind == CK_INSTANCE && hp_next == NULL) {
		/* in simple cases this is a dangling hp */
		dbg("no connection to restart after termination");
	} else {
		for (struct connection *d = hp->connections; d != NULL; d = d->hp_next) {
			if (same_host(dnshostname, &host_addr,
				      d->config->dnshostname,
				      &d->remote->host.addr)) {
				initiate_connection(d, NULL/*remote-host*/,
						    false/*background*/,
						    true/*verbose*/,
						    logger);
			}
		}
	}
	pfreeany(dnshostname);
}

/* (Possibly) Opportunistic Initiation:
 *
 * Knowing clients (single IP addresses), try to build a tunnel.  This
 * may involve discovering a gateway and instantiating an
 * Opportunistic connection.  Called when a packet is caught by a
 * %trap, or when whack --oppohere --oppothere is used.  It may turn
 * out that an existing or non-opporunistic connection can handle the
 * traffic.
 *
 * Most of the code will be restarted if an ADNS request is made to
 * discover the gateway.  The only difference between the first and
 * second entry is whether gateways_from_dns is NULL or not.
 *
 *	initiate_opportunistic: initial entrypoint
 *	continue_oppo: where we pickup when ADNS result arrives
 *	initiate_opportunistic_body: main body shared by above routines
 *	cannot_ondemand: a helper function to log a diagnostic
 *
 * This structure repeats a lot of code when the ADNS result arrives.
 * This seems like a waste, but anything learned the first time
 * through may no longer be true!
 *
 * After the first IKE message is sent, the regular state machinery
 * carries negotiation forward.
 */

static void cannot_ondemand(lset_t rc_flags, const struct kernel_acquire *b, const char *ughmsg)
{
	LLOG_JAMBUF(rc_flags, b->logger, buf) {
		jam(buf, "cannot ");
		jam_kernel_acquire(buf, b);
		jam(buf, ": %s", ughmsg);
	}

	if (b->by_acquire) {
		ldbg(b->logger, "initiate from acquire so kernel policy is assumed to already expire");
	} else {
		ldbg(b->logger, "initiate from whack so nothing to kernel policy to expire");
	}
}

void initiate_ondemand(const struct kernel_acquire *b)
{
	threadtime_t inception = threadtime_start();

	if (impair.cannot_ondemand) {
		llog(RC_LOG, b->logger, "IMPAIR: cannot ondemand forced");
		return;
	}

	/*
	 * What connection shall we use?  First try for one that
	 * explicitly handles the clients.
	 */

	if (!b->packet.is_set) {
		cannot_ondemand(RC_OPPOFAILURE, b, "impossible IP address");
		return;
	}

	/* XXX: shouldn't this have happened earlier? */
	if (thingeq(b->packet.src.bytes, b->packet.dst.bytes)) {
		/*
		 * NETKEY gives us acquires for our own IP. This code
		 * does not handle talking to ourselves on another ip.
		 */
		cannot_ondemand(RC_OPPOFAILURE, b, "acquire for our own IP address");
		return;
	}

	struct connection *c = find_connection_for_packet(b->packet,
							  b->sec_label,
							  b->logger);
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

	/* else C would not have been found */
	PASSERT(b->logger, oriented(c));

	/* spell out types that c can return */
	switch (c->kind) {
	case CK_PERMANENT:
	case CK_TEMPLATE: /* sec_label or opportunistic */
	case CK_INSTANCE:
		break;
	default:
		bad_case(c->kind);
	}

	if (labeled(c)) {
		/*
		 * We've found a sec_label connection that can serve.
		 *
		 * It could be a labeled-template (which needs
		 * instantiated), or labeled-parent (which means a
		 * piggyback), but never a labeled-child.
		 *
		 * Above should only returns sec_label C when below
		 * are true.
		 */
		PASSERT(b->logger, b->sec_label.len > 0);
		PASSERT(b->logger, sec_label_within_range("acquire", HUNK_AS_SHUNK(b->sec_label),
							  c->config->sec_label, b->logger));
		PASSERT(b->logger, (c->policy & POLICY_OPPORTUNISTIC) == LEMPTY);
		PASSERT(b->logger, (labeled_template(c) || labeled_parent(c)));

		/*
		 * Announce this to the world.  Use c->logger instead?
		 */
		LLOG_JAMBUF(RC_LOG, b->logger, buf) {
			jam_kernel_acquire(buf, b);
			/* jam(buf, " using "); */
		}

		/*
		 * ondemand negotiation always requires a parent.
		 */
		struct connection *cc;
		if (labeled_template(c)) {
			cc = sec_label_parent_instantiate(c, c->remote->host.addr, HERE);
		} else {
			cc = c;
		}
		PASSERT(b->logger, labeled_parent(cc));

		connection_ondemand(cc, &inception, b);
		return;
	}

	/* sec_labels are  off the table */
	PASSERT(b->logger, b->sec_label.len == 0);
	PASSERT(b->logger, c->config->sec_label.len == 0);

	/* Labeled IPsec and Opportunistic cannot both be used */
	switch (c->kind) {
	case CK_INSTANCE:
		/*
		 * XXX We got an acquire (NETKEY only?) for something
		 * we already have an instance for ??  We cannot
		 * process as normal because the bare_shunts table and
		 * assign_holdpass() (connection_negotiating()) would
		 * get confused between this new entry and the
		 * existing one.  So we return without doing anything.
		 */
		LLOG_JAMBUF(RC_LOG, b->logger, buf) {
			jam_string(buf, "ignoring found existing connection instance ");
			jam_connection(buf, c);
			jam(buf, " that covers kernel acquire with IKE state #%lu and IPsec state #%lu - due to duplicate acquire?",
			    c->newest_ike_sa, c->newest_ipsec_sa);
		}
		return;
	case CK_PERMANENT:
		PASSERT(b->logger, (c->policy & POLICY_OPPORTUNISTIC) == LEMPTY);
		LLOG_JAMBUF(RC_LOG, b->logger, buf) {
			jam_kernel_acquire(buf, b);
			/* jam(buf, " using "); */
		}
		connection_ondemand(c, &inception, b);
		return;
	case CK_TEMPLATE:
		PASSERT(b->logger, (c->policy & POLICY_OPPORTUNISTIC) != LEMPTY);
		LLOG_JAMBUF(RC_LOG, b->logger, buf) {
			jam_kernel_acquire(buf, b);
		}
		/* XXX: re-use c */
		c = oppo_initiator_instantiate(c, b, HERE);
		/* switched C to instance */
		PASSERT(b->logger, c->kind == CK_INSTANCE);
		PASSERT(b->logger, HAS_IPSEC_POLICY(c->policy));
		PASSERT(b->logger, c->child.routing == RT_UNROUTED); /*instance*/
		connection_ondemand(c, &inception, b);
		return;
	default:
		bad_case(c->kind);
	}
}

/* time before retrying DDNS host lookup for phase 1 */
#define PENDING_DDNS_INTERVAL secs_per_minute

/*
 * Call me periodically to check to see if any DDNS tunnel can come up.
 * The order matters, we try to do the cheapest checks first.
 */

static void connection_check_ddns1(struct connection *c, struct logger *logger)
{
	const char *e;

	/* this is the cheapest check, so do it first */
	if (c->config->dnshostname == NULL)
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
	if (address_is_specified(c->remote->host.addr)) {
		connection_buf cib;
		dbg("pending ddns: connection "PRI_CONNECTION" has address",
		    pri_connection(c, &cib));
		return;
	}

	if (c->remote->config->child.protoport.has_port_wildcard ||
	    (c->config->prospective_shunt == SHUNT_TRAP &&
	     id_has_wildcards(&c->remote->host.id))) {
		connection_buf cib;
		dbg("pending ddns: connection "PRI_CONNECTION" with wildcard not started",
		    pri_connection(c, &cib));
		return;
	}

	/* XXX: blocking call */
	ip_address new_remote_addr;
	e = ttoaddress_dns(shunk1(c->config->dnshostname), NULL/*UNSPEC*/, &new_remote_addr);
	if (e != NULL) {
		connection_buf cib;
		dbg("pending ddns: connection "PRI_CONNECTION" lookup of \"%s\" failed: %s",
		    pri_connection(c, &cib), c->config->dnshostname, e);
		return;
	}

	if (!address_is_specified(new_remote_addr)) {
		connection_buf cib;
		dbg("pending ddns: connection "PRI_CONNECTION" still no address for \"%s\"",
		    pri_connection(c, &cib), c->config->dnshostname);
		return;
	}

	/* do not touch what is not broken */
	struct state *newest_ike_sa = state_by_serialno(c->newest_ike_sa);
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
	if (sameaddr(&new_remote_addr, &c->remote->host.addr)) {
		connection_buf cib;
		dbg("pending ddns: IP address unchanged for connection "PRI_CONNECTION"",
		    pri_connection(c, &cib));
		return;
	}

	/* I think this is OK now we check everything above. */

	address_buf old, new;
	dbg("pending ddns: updating IP address for %s from %s to %s",
	    c->config->dnshostname,
	    str_address_sensitive(&c->remote->host.addr, &old),
	    str_address_sensitive(&new_remote_addr, &new));
	pexpect(!address_is_specified(c->remote->host.addr)); /* per above */

	/* propogate remote address */
	update_hosts_from_end_host_addr(c, c->remote->config->index, new_remote_addr, HERE); /* from DNS */
	discard_connection_spds(c);

	if (c->remote->child.config->selectors.len > 0) {
		ldbg(c->logger, "  %s.child already has a hard-wired selectors; skipping",
		     c->remote->config->leftright);
	} else if (c->remote->child.has_client) {
		pexpect(c->policy & POLICY_OPPORTUNISTIC);
		ldbg(c->logger, "  %s.child.has_client yet no selectors; skipping magic",
		     c->remote->config->leftright);
	} else {
		/*
		 * Default the end's child selector (client)
		 * to a subnet containing only the end's host
		 * address.
		 */
		struct child_end *child = &c->remote->child;
		ip_selector remote_selector =
			selector_from_address_protoport(new_remote_addr, child->config->protoport);
		selector_buf new;
		dbg("  updated %s.selector to %s",
		    c->remote->config->leftright,
		    str_selector(&remote_selector, &new));
		set_first_selector(c, remote, remote_selector);
	}

	add_connection_spds(c, address_info(c->local->host.addr));

	/*
	 * reduce the work we do by updating all connections waiting for this
	 * lookup
	 */
	update_host_pairs(c);
	if (c->policy & POLICY_UP) {
		connection_buf cib;
		dbg("pending ddns: re-initiating connection "PRI_CONNECTION"",
		    pri_connection(c, &cib));
		initiate_connection(c, /*remote-host-name*/NULL,
				    /*background*/true,
				    /*log-failure*/true,
				    logger);
	} else {
		connection_buf cib;
		dbg("pending ddns: connection "PRI_CONNECTION" was updated, but does not want to be up",
		    pri_connection(c, &cib));
	}
}

void connection_check_ddns(struct logger *logger)
{
	threadtime_t start = threadtime_start();

	struct connection_filter cf = { .where = HERE, };
	while (next_connection_new2old(&cf)) {
		struct connection *c = cf.c;
		connection_check_ddns1(c, logger);
	}
	check_orientations(logger);

	threadtime_stop(&start, SOS_NOBODY, "in %s for hostname lookup", __func__);
}

void init_connections_timer(void)
{
	enable_periodic_timer(EVENT_PENDING_DDNS, connection_check_ddns,
			      deltatime(PENDING_DDNS_INTERVAL));
}
