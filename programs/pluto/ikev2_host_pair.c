/* information about connections between hosts
 *
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2008-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2011 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013-2019 Paul Wouters <pwouters@redhat.com>
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

#include "ikev2_host_pair.h"
#include "log.h"
#include "connections.h"
#include "demux.h"
#include "iface.h"
#include "unpack.h"
#include "orient.h"		/* for oriented() */
#include "authby.h"
#include "instantiate.h"
#include "verbose.h"

static bool match_v2_connection(const struct connection *c,
				const struct authby remote_authby,
				const enum ikev2_exchange ix,
				bool *send_reject_response,
				struct verbose verbose)
{
	PEXPECT(verbose.logger, c->config->ike_version == IKEv2);
	PEXPECT(verbose.logger, oriented(c)); /* searching oriented lists */
	PEXPECT(verbose.logger, !is_group(c));

	if (is_instance(c) && c->remote->host.id.kind == ID_NULL) {
		connection_buf cb;
		vdbg("skipping "PRI_CONNECTION", ID_NULL instance",
		     pri_connection(c, &cb));
		return false;
	}

	/*
	 * Connection allow exchange?
	 */
	if (ix == ISAKMP_v2_IKE_SESSION_RESUME) {
		if (!c->config->session_resumption) {
			connection_buf cb;
			vdbg("skipping "PRI_CONNECTION", does not allow IKE_SESSION_RESUME",
			     pri_connection(c, &cb));
			return false;
		}
	}

	/*
	 * Require all the bits to match (there's actually only one).
	 */
	if (!authby_le(remote_authby, c->remote->host.config->authby)) {
		connection_buf cb;
		authby_buf ab, cab;
		vdbg("skipping "PRI_CONNECTION", %s missing required authby %s",
		     pri_connection(c, &cb),
		     str_authby(c->remote->host.config->authby, &cab),
		     str_authby(remote_authby, &ab));
		return false;
	}

	if (never_negotiate(c)) {
		/*
		 * Normally NEVER_NEGOTIATE means, drop packet but
		 * respond with NO_PROPOSAL_CHOSEN (the default
		 * behaviour when no connection matches).
		 *
		 * However, NEVER_NEGOTIATE OE connections, such as
		 * BLOCK and CLEAR, instead want to suppress the
		 * NO_PROPOSAL_CHOSEN response.
		 *
		 * But there's a problem, BLOCK and CLEAR don't have
		 * the OPPORTUNISTIC bit set.  Fortunately they do
		 * have GROUPINSTANCE!  Hence the some what convoluted
		 * logic to detect these cases and clear.
		 */
		enum shunt_policy shunt = c->config->never_negotiate_shunt;
		if (shunt == SHUNT_PASS/*clear*/ ||
		    shunt == SHUNT_REJECT/*block*/) {
			if (is_group_instance(c)) {
				PEXPECT(verbose.logger, remote_authby.never);
				(*send_reject_response) = false;
			}
		}
		connection_buf cb;
		vdbg("skipping "PRI_CONNECTION", never negotiate",
		     pri_connection(c, &cb));
		return false;
	}

	return true;
}

/*
 * Find a connection matching exactly matching <local>-<remote>.
 *
 * This could be a permanent connection, a connection instance
 * instantiated with <remote>, or a template needing to be
 * instantiated.
 *
 * If the exact match is a block; SEND_REJECT_RESPONSE is cleared and
 * the search is abandoned.  See above (yes, confusing).
 *
 * This always returns a reference that needs to be released.
 */

static struct connection *find_v2_exact_peer_connection(const struct msg_digest *md,
							struct authby remote_authby,
							bool *send_reject_response,
							struct verbose verbose)
{
	const ip_endpoint *local_endpoint = &md->iface->local_endpoint;
	const ip_endpoint *remote_endpoint = &md->sender;
	const enum ikev2_exchange ix = md->hdr.isa_xchg;

	/* just the address */
	ip_address local_address = endpoint_address(*local_endpoint);
	ip_address remote_address = endpoint_address(*remote_endpoint);

	address_buf lb;
	address_buf rb;
	authby_buf pb;
	vdbg("searching for exact peer matching inbound %s<-%s remote_authby=%s",
	     str_address(&local_address, &lb),
	     str_address(&remote_address, &rb),
	     str_authby(remote_authby, &pb));
	verbose.level++;

	struct connection *c = NULL;

	struct connection_filter hpf = {
		.host_pair = {
			.local = &local_address,
			.remote = &remote_address,
		},
		.ike_version = ikev2_info.version,
		.search = {
			.order = OLD2NEW,
			.verbose = verbose,
			.where = HERE,
		},
	};

	while (next_connection(&hpf)) {
		struct connection *d = hpf.c;

		if (!match_v2_connection(d, remote_authby, ix,
					 send_reject_response, verbose)){
			continue;
		}

		/*
		 * This could be a shared ISAKMP SA connection, in
		 * which case we prefer to find the connection that
		 * has the ISAKMP SA.
		 */
		if (d->established_ike_sa != SOS_NOBODY) {
			/* instant winner */
			c = d;
			break;
		}
		if (c == NULL) {
			/* first is winner */
			c = d;
		}
	}

	if (c == NULL) {
		endpoint_buf b;
		enum_buf xb;
		authby_buf pb;
		vdbg("no exact peer connection matching inbound %s<-%s with policy %s for %s message, %s",
		     str_endpoint(local_endpoint, &b),
		     str_endpoint(remote_endpoint, &b),
		     str_authby(remote_authby, &pb),
		     str_enum(&ikev2_exchange_names, md->hdr.isa_xchg, &xb),
		     ((*send_reject_response) ? "sending reject response" : "suppressing reject response"));
		return NULL;
	}

	/*
	 * We found a possibly non-wildcard connection.
	 */
	if (is_labeled_template(c)) {
		vdbg("local endpoint is a labeled template - needs instantiation");
		return labeled_template_instantiate(c, remote_address, HERE);
	}

	if (is_template(c) &&
	    c->config->narrowing) {
		vdbg("local endpoint has narrowing=yes - needs instantiation");
		return rw_responder_instantiate(c, remote_address, HERE);
	}

	connection_buf cb;
	vdbg("winner is "PRI_CONNECTION, pri_connection(c, &cb));
	return connection_addref(c, md->logger);

}

/*
 * Find a connection matching <unset>-><local> (aka %any).
 *
 * (only template connections can have <unset>-><local>).
 */

static struct connection *find_v2_unset_peer_connection(const struct msg_digest *md,
							struct authby remote_authby,
							bool *send_reject_response,
							struct verbose verbose)
{
	struct connection *c = NULL;
	const ip_endpoint *local_endpoint = &md->iface->local_endpoint;
	const ip_endpoint *remote_endpoint = &md->sender;
	const enum ikev2_exchange ix = md->hdr.isa_xchg;

	/* just the address */
	ip_address local_address = endpoint_address(*local_endpoint);
	ip_address remote_address = endpoint_address(*remote_endpoint);

	address_buf lb;
	address_buf rb;
	authby_buf pb;
	vdbg("searching for unset peer matching inbound %s<-[%s] remote_authby=%s",
	     str_address(&local_address, &lb),
	     str_address(&remote_address, &rb),
	     str_authby(remote_authby, &pb));
	verbose.level++;


	/*
	 * See if a wildcarded connection can be found.  We cannot
	 * pick the right connection, so we're making a guess.  All
	 * Road Warrior connections are fair game: we pick the first
	 * we come across (if any).  If we don't find any, we pick the
	 * first opportunistic with the smallest subnet that includes
	 * the peer.  There is, of course, no necessary relationship
	 * between an Initiator's address and that of its client, but
	 * Food Groups kind of assumes one.
	 */

	struct connection_filter hpf_unset = {
		.host_pair = {
			.local = &local_address,
			.remote = &unset_address,
		},
		.ike_version = IKEv2,
		.search = {
			.order = OLD2NEW,
			.verbose.logger = md->logger,
			.where = HERE,
		},
	};
	while (next_connection(&hpf_unset)) {
		struct connection *d = hpf_unset.c;

		if (!match_v2_connection(d, remote_authby, ix,
					 send_reject_response, verbose)) {
			continue;
		}

		if (!PEXPECT(md->logger, is_template(d))) {
			continue;
		}

		/*
		 * Road Warrior: we have an instant winner.
		 */
		if (!is_opportunistic(d)) {
			connection_buf cb;
			vdbg("instant winner with non-opportunistic template "PRI_CONNECTION,
			     pri_connection(d, &cb));
			c = d;
			break;
		}

		/*
		 * Opportunistic or Shunt:
		 *
		 * Keep searching refining until the connection with
		 * the narrowed address is found.
		 *
		 * At this point only the peer's address is known so
		 * trying to narrow beyond that (i.e., down to a
		 * protocol/port) is just wild speculation.
		 *
		 * Hence use in_selector_range() and in_selector().
		 *
		 * Since the connections are searched OLD2NEW so the
		 * first connection in the config file is prefered
		 * (but this isn't documented).
		 */

		if (!address_in_selector_range(remote_address, d->spd->remote->client)) {
			address_buf ab;
			selector_buf sb;
			connection_buf cb;
			vdbg("skipping "PRI_CONNECTION", as %s is-not in range %s",
			     pri_connection(d, &cb),
			     str_address(&remote_address, &ab),
			     str_selector(&d->spd->remote->client, &sb));
			continue;
		}

		/*
		 * Per above; when comparing D to the previously
		 * selected connection C, use use in_selector_range()
		 * and not in_selector() - the protocol/port are not
		 * known so any attempt to narrow based on that is
		 * probably wrong.
		 */

		if (c != NULL &&
		    range_in_range(selector_range(c->spd->remote->client),
				   selector_range(d->spd->remote->client))) {
			selector_buf s1, s2;
			connection_buf cb;
			vdbg("skipping "PRI_CONNECTION", as best range of %s is narrower than %s",
			     pri_connection(d, &cb),
			     str_selector(&c->spd->remote->client, &s1),
			     str_selector(&d->spd->remote->client, &s2));
			continue;
		}

		selector_buf s1, s2;
		connection_buf dc;
		vdbg("saving "PRI_CONNECTION", opportunistic %s range better than %s",
		     pri_connection(d, &dc),
		     str_selector(&d->spd->remote->client, &s1),
		     c == NULL ? "n/a" : str_selector(&c->spd->remote->client, &s2));
		c = d;
		/* keep looking */
	}

	if (c == NULL) {
		endpoint_buf b;
		authby_buf pb;
		enum_buf xb;
		vdbg("no unset peer connection matching inbound %s<-[%s] with policy %s for %s message, %s",
		     str_endpoint(local_endpoint, &b),
		     str_endpoint(remote_endpoint, &b),
		     str_authby(remote_authby, &pb),
		     str_enum(&ikev2_exchange_names, md->hdr.isa_xchg, &xb),
		     ((*send_reject_response) ? "sending reject response" : "suppressing reject response"));
		return NULL;
	}

	/*
	 * Since the match was <local>,%any, the connection must be a
	 * wildcard and, hence, must be instantiated.
	 */

	if (is_opportunistic(c)) {
		connection_buf cb;
		vdbg("instantiating opportunistic winner "PRI_CONNECTION, pri_connection(c, &cb));
		return oppo_responder_instantiate(c, remote_address, HERE);
	}

	if (is_labeled_template(c)) {
		/* regular roadwarrior */
		connection_buf cb;
		vdbg("instantiating sec_label winner "PRI_CONNECTION, pri_connection(c, &cb));
		return labeled_template_instantiate(c, remote_address, HERE);
	}

	/* regular roadwarrior */
	connection_buf cb;
	vdbg("instantiating roadwarrior winner "PRI_CONNECTION, pri_connection(c, &cb));
	return rw_responder_instantiate(c, remote_address, HERE);
}

struct connection *find_v2_unsecured_host_pair_connection(const struct msg_digest *md,
							  bool *send_reject_response)
{
	struct verbose verbose = {
		.logger = md->logger,
	};

	endpoint_buf lb;
	endpoint_buf rb;
	vdbg("searching for connection matching inbound %s<-%s",
	     str_endpoint(&md->iface->local_endpoint, &lb),
	     str_endpoint(&md->sender, &rb));
	verbose.level = 1;

	/*
	 * How to authenticate (prove the identity of) the remote
	 * peer; in order of decreasing preference.  NEVER matches
	 * things like BLOCK and CLEAR.
	 */
	static const struct authby remote_authbys[] = {
		{ .ecdsa = true, },
		{ .rsasig = true, },
		{ .rsasig_v1_5 = true, },
		{ .psk = true, },
		{ .null = true, },
		{ .never = true, },
	};

	struct connection *c = NULL;

	/*
	 * This searches the host-pairs REMOTE<->LOCAL and then
	 * ANY->LOCAL for a match with the given PEER_AUTHBY.  This
	 * means a "stronger" template will match before a "weaker"
	 * static connection.
	 *
	 * When no connection matches, SEND_REJECTED_RESPONSE will
	 * contain the value from the final AUTHBY=NEVER pass which
	 * can include BLOCK and CLEAR.
	 *
	 * For instance, if an earlier search returns NULL and flags
	 * SEND_REJECT_RESPONSE, that will be lost.
	 *
	 * XXX: this nested loop could do with a tune up.
	 */
	FOR_EACH_ELEMENT(remote_authby, remote_authbys) {
		authby_buf ab;
		vdbg("trying authby %s", str_authby(*remote_authby, &ab));
		verbose.level = 2;

		/*
		 * Start by assuming that a response will be sent.
		 */
		*send_reject_response = true;

		/*
		 * Pass #1: look for "static" or established
		 * connections which match.
		 *
		 * If send_reject_response was cleared; then a CLEAR
		 * or BLOCK connection matched.
		 */

		*send_reject_response = true;
		c = find_v2_exact_peer_connection(md, *remote_authby,
						  send_reject_response,
						  verbose);
		if (c != NULL) {
			break;
		}

		if (!send_reject_response) {
			vdbg("non-wildcard rejected packet");
			continue;
		}

		c = find_v2_unset_peer_connection(md, *remote_authby,
						  send_reject_response,
						  verbose);
		if (c != NULL) {
			break;
		}
	}

	verbose.level = 1;

	if (c == NULL) {
		vdbg("no connection found, %s",
		     ((*send_reject_response) ? "sending reject response" : "suppressing reject response"));
		return NULL;
	}

	connection_buf ci;
	authby_buf pb;
	vdbg("found connection: "PRI_CONNECTION" with remote authby %s",
	     pri_connection(c, &ci),
	     str_authby(c->remote->host.config->authby, &pb));

	return c;
}
