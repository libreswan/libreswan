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

#include "defs.h"	/* for so_serial_t */
#include "initiate.h"

#include "connections.h"
#include "pending.h"
#include "timer.h"
#include "log.h"
#include "orient.h"
#include "ikev1.h"			/* for aggr_outI1() and main_outI1() */
#include "ikev1_spdb.h"
#include "ikev1_quick.h"		/* for quick_outI1() */
#include "ikev2_ike_sa_init.h"		/* for ikev2_out_IKE_SA_INIT_I() */
#include "ikev2_create_child_sa.h"	/* for initiate_v2_CREATE_CHILD_SA_create_child() */
#include "instantiate.h"
#include "terminate.h"

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
			 bool background,
			 struct logger *logger)
{
	ldbg_connection(c, HERE, "initiate: remote_host=%s",
			(remote_host == NULL ? "<null> (using host from connection)" : remote_host));
	connection_attach(c, logger);
	bool ok = initiate_connection_1_basics(c, remote_host, background);
	connection_detach(c, logger);
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

	if (never_negotiate(c)) {
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

		if (!is_template(c)) {
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
		if (is_labeled(c)) {
			d = sec_label_parent_instantiate(c, remote_ip, HERE);
		} else {
			d = spd_instantiate(c, remote_ip, HERE);
		}

		/*
		 * D could either be an instance, or a sec_label
		 * connection?
		 */

		connection_attach(d, c->logger);

		address_buf ab;
		llog(RC_LOG, d->logger,
		     "instantiated connection with remote IP set to %s",
		     str_address(&remote_ip, &ab));

		bool ok = initiate_connection_3_template(d, background, inception);

		connection_detach(d, d->logger);
		connection_delref(&d, c->logger);
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
			if (c->config->ikev2_allow_narrowing) {
				esb_buf b;
				llog(RC_NOPEERIP, c->logger,
				     "cannot initiate connection without resolved dynamic peer IP address, will keep retrying (kind=%s, narrowing=%s)",
				     enum_show(&connection_kind_names, c->local->kind, &b),
				     bool_str(c->config->ikev2_allow_narrowing));
			} else {
				esb_buf b;
				llog(RC_NOPEERIP, c->logger,
				     "cannot initiate connection without resolved dynamic peer IP address, will keep retrying (kind=%s)",
				     enum_show(&connection_kind_names, c->local->kind, &b));
			}
			add_policy(c, policy.up);
			return true;
		}

		if (c->config->ikev2_allow_narrowing) {
			esb_buf b;
			llog(RC_NOPEERIP, c->logger,
			     "cannot initiate connection without knowing peer IP address (kind=%s narrowing=%s)",
			     enum_show(&connection_kind_names, c->local->kind, &b),
			     bool_str(c->config->ikev2_allow_narrowing));
		} else {
			esb_buf b;
			llog(RC_NOPEERIP, c->logger,
			     "cannot initiate connection (serial "PRI_CO") without knowing peer IP address (kind=%s)",
			     pri_co(c->serialno),
			     enum_show(&connection_kind_names, c->local->kind, &b));
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

	if (is_labeled_template(c)) {
		struct connection *d =
			sec_label_parent_instantiate(c, c->remote->host.addr, HERE);
		connection_attach(d, c->logger);
		/*
		 * LOGGING: why not log this (other than it messes
		 * with test output)?
		 */
		llog(LOG_STREAM|RC_LOG, d->logger, "instantiated connection");
		/* flip cur_connection */
		bool ok = initiate_connection_4_fab(d, background, inception);

		connection_detach(d, c->logger);
		connection_delref(&d, c->logger);
		return ok;
	}

	if (is_template(c) &&
	    c->config->ike_version == IKEv2 &&
	    c->config->ikev2_allow_narrowing) {
		struct connection *d = spd_instantiate(c, c->remote->host.addr, HERE);
		connection_attach(d, c->logger);
		/*
		 * LOGGING: why not log this (other than it messes
		 * with test output)?
		 */
		llog(LOG_STREAM|RC_LOG, d->logger, "instantiated connection");
		/* flip cur_connection */
		bool ok = initiate_connection_4_fab(d, background, inception);

		connection_detach(d, c->logger);
		connection_delref(&d, c->logger);
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

	add_policy(c, policy.up);

	/*
	 * FOR IKEv2, when the sec_label template connection is
	 * initiated, there is no acquire and, hence, no Child SA to
	 * establish.
	 */

	shunk_t sec_label = null_shunk;
	struct logger *logger = c->logger;
	so_serial_t replacing = SOS_NOBODY;
	lset_t policy = child_sa_policy(c);

	initiate(c, policy, replacing, &inception,
		 sec_label, background, logger,
		 INITIATED_BY_WHACK/*maybe?*/, HERE);

	return true;
}

void initiate(struct connection *c,
	      lset_t policy,
	      so_serial_t replacing,
	      const threadtime_t *inception,
	      shunk_t sec_label,
	      bool detach_whack,
	      struct logger *logger,
	      enum initiated_by initiated_by,
	      where_t where)
{
	enum_buf ifnb;
	policy_buf pb;
	enum_buf epb;
	ldbg_connection(c, where, "%s() by %s policy=%s proto=%s sec_label="PRI_SHUNK,
			__func__,
			str_enum_short(&initiated_by_names, initiated_by, &ifnb),
			str_policy(policy, &pb),
			str_enum_short(&encap_proto_names, c->config->child_sa.encap_proto, &epb),
			pri_shunk(sec_label));

	/*
	 * Try to find a viable IKE (parent) SA.  A viable IKE SA is
	 * either: established; or negotiating the IKE SA as the
	 * initiator.
	 *
	 * What is wrong with a larval responder?

	 * Possible outcomes are: no IKE SA, so intiate a new one; IKE
	 * SA is a larval initiator, so append connection to pending;
	 * IKE SA is established, so append Child SA to IKE's exchange
	 * queue.
	 */

	struct ike_sa *ike = find_viable_parent_for_connection(c);

	/*
	 * There's no viable IKE (parent) SA, initiate a new one.
	 */

	if (ike == NULL) {
		switch (c->config->ike_version) {
#ifdef USE_IKEv1
		case IKEv1:
			if (c->config->aggressive) {
				ike = aggr_outI1(c, NULL, policy,
						 inception, detach_whack);
			} else {
				ike = main_outI1(c, NULL, policy,
						 inception, detach_whack);
			}
			break;
#endif
		case IKEv2:
			ike = initiate_v2_IKE_SA_INIT_request(c, NULL, policy,
							      inception, sec_label,
							      detach_whack);
			break;
		}
		if (ike == NULL) {
			return;
		}
		if (initiated_by != INITIATED_BY_REPLACE) {
			connection_initiated_ike(ike, initiated_by, HERE);
		}
		if (detach_whack) {
			state_detach(&ike->sa, c->logger);
		}
		return;
	}

	/*
	 * There is a viable IKE (parent) SA and it is established
	 * (ready to negotiate for the connection's child).  Initiate
	 * the child exchange.  For IKEv2 the child will be appended
	 * to the exchange queue.
	 */

	if (IS_PARENT_SA_ESTABLISHED(&ike->sa)) {
		struct child_sa *child;
		switch (c->config->ike_version) {
#ifdef USE_IKEv1
		case IKEv1:
		{
			/*
			 * ??? we assume that peer_nexthop_sin isn't
			 * important: we already have it from when we
			 * negotiated the ISAKMP SA!  It isn't clear
			 * what to do with the error return.
			 */
			child = quick_outI1(ike, c, policy, replacing);
			break;
		}
#endif
		case IKEv2:
		{
			if (already_has_larval_v2_child(ike, c)) {
				child = NULL;
				break;
			}
			dbg("initiating child sa with "PRI_LOGGER, pri_logger(logger));
			struct connection *cc;
			if (c->config->sec_label.len > 0) {
				cc = sec_label_child_instantiate(ike, sec_label, HERE);
				/* propogate whack attached to C */
				connection_attach(cc, c->logger);
			} else {
				cc = connection_addref(c, c->logger);
			}
			child = submit_v2_CREATE_CHILD_SA_new_child(ike, cc, policy,
								    detach_whack);
			if (c != cc) {
				connection_detach(cc, c->logger);
			}
			connection_delref(&cc, cc->logger);
			break;
		}
		default:
			bad_enum(c->logger, &ike_version_names, c->config->ike_version);
		}
		if (child == NULL) {
			return;
		}
		if (initiated_by != INITIATED_BY_REPLACE) {
			connection_initiated_child(ike, child, initiated_by, where);
		}
		if (detach_whack) {
			/*
			 * Silence Children!
			 *
			 * What matters is the FDs attached to the
			 * logger - the choice of C or CC(above) makes
			 * no difference.
			 *
			 * Caller will then detach whack from the
			 * connection.
			 */
			state_detach(&child->sa, c->logger);
		}
		return;
	}

	/*
	 * There's a viable IKE (parent) SA except it is still being
	 * negotiated.  Append the connection to the IKE SA's pending
	 * queue.
	 */

	switch (c->config->ike_version) {
#ifdef USE_IKEv1
	case IKEv1:
	{
		/* leave our Phase 2 negotiation pending */
		append_pending(ike, c, policy,
			       replacing, sec_label,
			       false /*part of initiate*/,
			       detach_whack);
		if (initiated_by != INITIATED_BY_REPLACE) {
			connection_pending(c, initiated_by, where);
		}
		break;
	}
#endif
	case IKEv2:
	{
		/* leave CHILD SA negotiation pending */
		struct connection *cc;
		if (c->config->sec_label.len > 0) {
			/* sec-labels require a separate child connection */
			cc = sec_label_child_instantiate(ike, sec_label, HERE);
		} else {
			cc = connection_addref(c, c->logger);
		}
		append_pending(ike, cc, policy,
			       replacing, sec_label,
			       false /*part of initiate*/,
			       detach_whack);
		if (initiated_by != INITIATED_BY_REPLACE) {
			connection_pending(cc, initiated_by, where);
		}
		connection_delref(&cc, cc->logger);
		break;
	}
	default:
		bad_enum(c->logger, &ike_version_names, c->config->ike_version);
	}
}
