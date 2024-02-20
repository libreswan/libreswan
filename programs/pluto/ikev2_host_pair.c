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

static bool match_connection(const struct connection *c,
			     struct authby remote_authby,
			     bool *send_reject_response,
			     struct logger *logger)
{
	pexpect(oriented(c)); /* searching oriented lists */

	if (c->config->ike_version != IKEv2) {
		connection_buf cb;
		ldbg(logger, "  skipping "PRI_CONNECTION", not IKEv2",
		     pri_connection(c, &cb));
		return false;
	}

	if (is_group(c)) {
		connection_buf cb;
		ldbg(logger, "  skipping "PRI_CONNECTION", connection group",
		     pri_connection(c, &cb));
		return false;
	}

	if (is_instance(c) && c->remote->host.id.kind == ID_NULL) {
		connection_buf cb;
		ldbg(logger, "  skipping "PRI_CONNECTION", ID_NULL instance",
		     pri_connection(c, &cb));
		return false;
	}

	/*
	 * Require all the bits to match (there's actually ony one).
	 */
	if (!authby_le(remote_authby, c->remote->host.config->authby)) {
		connection_buf cb;
		authby_buf ab, cab;
		ldbg(logger, "  skipping "PRI_CONNECTION", %s missing required authby %s",
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
		 * logic to detect these cases and clear 
		 */
		enum shunt_policy shunt = c->config->never_negotiate_shunt;
		if (shunt == SHUNT_PASS/*clear*/ ||
		    shunt == SHUNT_REJECT/*block*/) {
			if (is_group_instance(c)) {
				pexpect(remote_authby.never);
				*send_reject_response = false;
			}
		}
		connection_buf cb;
		ldbg(logger, "  skipping "PRI_CONNECTION", never negotiate",
		     pri_connection(c, &cb));
		return false;
	}

	return true;
}

/*
 * This always returns a reference that needs to be released.
 */

static struct connection *ikev2_find_host_connection(const struct msg_digest *md,
						     struct authby remote_authby,
						     bool *send_reject_response)
{
	const ip_endpoint *local_endpoint = &md->iface->local_endpoint;
	const ip_endpoint *remote_endpoint = &md->sender;

	/* just the address */
	ip_address local_address = endpoint_address(*local_endpoint);
	ip_address remote_address = endpoint_address(*remote_endpoint);

	address_buf lb;
	address_buf rb;
	authby_buf pb;
	ldbg(md->logger, "%s() %s->%s remote_authby=%s", __func__,
	     str_address(&remote_address, &rb),
	     str_address(&local_address, &lb),
	     str_authby(remote_authby, &pb));

	/*
	 * Pass #1: look for "static" or established connections which
	 * match.
	 */
	struct connection *c = NULL;
	struct connection_filter hpf_remote = {
		.local = &local_address,
		.remote = &remote_address,
		.where = HERE,
	};
	while (next_connection(NEW2OLD, &hpf_remote)) {
		struct connection *d = hpf_remote.c;

		if (!match_connection(d, remote_authby, send_reject_response,
				      md->logger)) {
			continue;
		}

		/*
		 * This could be a shared IKE SA connection, in which
		 * case we prefer to find the connection that has the
		 * IKE SA
		 */
		if (d->established_ike_sa != SOS_NOBODY) {
			/* instant winner */
			connection_buf cb;
			ldbg(md->logger, "  instant winner with "PRI_CONNECTION" IKE SA "PRI_SO,
			     pri_connection(d, &cb),
			     pri_so(d->established_ike_sa));
			c = d;
			break;
		}
		if (c == NULL) {
			ldbg(md->logger, "  saving for later");
			c = d;
		}
	}

	if (c != NULL) {
		/*
		 * We found a possibly non-wildcard connection.
		 */
		if (is_labeled_template(c)) {
			ldbg(md->logger,
			     "local endpoint is a labeled template - needs instantiation");
			return labeled_template_instantiate(c, remote_address, HERE);
		}

		if (is_template(c) &&
		    c->config->ikev2_allow_narrowing) {
			ldbg(md->logger,
			     "local endpoint has narrowing=yes - needs instantiation");
			return rw_responder_instantiate(c, remote_address, HERE);
		}

		connection_buf cb;
		ldbg(md->logger, "winner is "PRI_CONNECTION,
		     pri_connection(c, &cb));
		return connection_addref(c, md->logger);
	}

	/*
	 * A non-wild card connection rejected the packet, go with it.
	 */
	if (!(*send_reject_response)) {
		dbg("  non-wildcard rejected packet");
		return NULL;
	}

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
		.local = &local_address,
		.remote = &unset_address,
		.where = HERE,
	};
	while (next_connection(NEW2OLD, &hpf_unset)) {
		struct connection *d = hpf_unset.c;

		if (!match_connection(d, remote_authby, send_reject_response,
				      md->logger)) {
			continue;
		}

		/*
		 * Road Warrior: we have an instant winner.
		 */
		if (is_template(d) && !is_opportunistic(d)) {
			connection_buf cb;
			ldbg(md->logger,
			     "  instant winner with non-opportunistic template "PRI_CONNECTION,
			     pri_connection(d, &cb));
			c = d;
			break;
		}

		/*
		 * Opportunistic or Shunt:
		 *
		 * Keep searching selecting the narrowest
		 * match, based on addresses, each time.
		 *
		 * Don't consider the protocol/port as, at
		 * this point (just received an IKE_SA_INIT
		 * request), they are not known (and won't be
		 * known until the next exchange - IKE_AUTH).
		 *
		 * The end result, which depends on the order
		 * that the connections are loaded, is
		 * probably going to be wrong (for instance
		 * when connections include protocol / port).
		 */

		if (!address_in_selector_range(remote_address, d->spd->remote->client)) {
			address_buf ab;
			selector_buf sb;
			connection_buf cb;
			dbg("  skipping "PRI_CONNECTION", as %s is-not in range %s",
			    pri_connection(d, &cb),
			    str_address(&remote_address, &ab),
			    str_selector(&d->spd->remote->client, &sb));
			continue;
		}

		if (c != NULL &&
		    selector_range_in_selector_range(c->spd->remote->client,
						     d->spd->remote->client)) {
			selector_buf s1, s2;
			connection_buf cb;
			dbg("  skipping "PRI_CONNECTION", as best range of %s is narrower than %s",
			    pri_connection(d, &cb),
			    str_selector(&c->spd->remote->client, &s1),
			    str_selector(&d->spd->remote->client, &s2));
			continue;
		}

		selector_buf s1, s2;
		connection_buf dc;
		dbg("  saving "PRI_CONNECTION", opportunistic %s range better than %s",
		    pri_connection(d, &dc),
		    str_selector(&d->spd->remote->client, &s1),
		    c == NULL ? "n/a" : str_selector(&c->spd->remote->client, &s2));
		c = d;
		/* keep looking */
	}

	if (c == NULL) {
		endpoint_buf b;
		authby_buf pb;
		ldbg(md->logger,
		     "  %s message received on %s but no connection has been authorized with policy %s, %s",
		     enum_name(&ikev2_exchange_names, md->hdr.isa_xchg),
		     str_endpoint(local_endpoint, &b),
		     str_authby(remote_authby, &pb),
		     ((*send_reject_response) ? "sending reject response" : "suppressing reject response"));
		return NULL;
	}

	/*
	 * Since the match was <local>,%any, the connection must be a
	 * wildcard and, hence, must be instantiated.
	 */

	if (is_opportunistic(c)) {
		connection_buf cb;
		ldbg(md->logger, "  instantiate opportunistic winner "PRI_CONNECTION,
		     pri_connection(c, &cb));
		c = oppo_responder_instantiate(c, remote_address, HERE);
	} else if (is_labeled_template(c)) {
		/* regular roadwarrior */
		connection_buf cb;
		ldbg(md->logger, "  instantiate sec_label winner "PRI_CONNECTION,
		     pri_connection(c, &cb));
		c = labeled_template_instantiate(c, remote_address, HERE);
	} else {
		/* regular roadwarrior */
		connection_buf cb;
		ldbg(md->logger, "  instantiate roadwarrior winner "PRI_CONNECTION,
		     pri_connection(c, &cb));
		c = rw_responder_instantiate(c, remote_address, HERE);
	}

	return c;
}

struct connection *find_v2_host_pair_connection(const struct msg_digest *md,
						bool *send_reject_response)
{
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
	 * XXX: this nested loop could do with a tune up.
	 */
	FOR_EACH_ELEMENT(remote_authby, remote_authbys) {
		/*
		 * This searches the host-pairs REMOTE<->LOCAL and
		 * then ANY->LOCAL for a match with the given
		 * PEER_AUTHBY.  This means a "stronger" template will
		 * match before a "weaker" static connection.
		 *
		 * When no connection matches, SEND_REJECTED_RESPONSE
		 * will contain the value from the final AUTHBY=NEVER
		 * pass which can include BLOCK and CLEAR.
		 *
		 * For instance, if an earlier search returns NULL and
		 * flags SEND_REJECT_RESPONSE, that will be lost.
		 */
		*send_reject_response = true;
		c = ikev2_find_host_connection(md, *remote_authby,
					       send_reject_response);
		if (c != NULL)
			break;
	}

	if (c == NULL) {
		ldbg(md->logger,
		     "  no connection found, %s",
		     ((*send_reject_response) ? "sending reject response" : "suppressing reject response"));
		return NULL;
	}

	connection_buf ci;
	authby_buf pb;
	ldbg(md->logger,
	     "found connection: "PRI_CONNECTION" with remote authby %s",
	     pri_connection(c, &ci),
	     str_authby(c->remote->host.config->authby, &pb));

	return c;
}
