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

#include "host_pair.h"
#include "ikev2_host_pair.h"
#include "log.h"
#include "connections.h"
#include "demux.h"
#include "iface.h"
#include "unpack.h"

static bool match_policy(struct connection *c, lset_t req_policy)
{
	if (c->config->ike_version != IKEv2) {
		connection_buf cb;
		dbg("  skipping "PRI_CONNECTION", not IKEv2",
		    pri_connection(c, &cb));
		return false;
	}

	if (c->kind == CK_INSTANCE && c->spd.that.id.kind == ID_NULL) {
		connection_buf cb;
		dbg("  skipping "PRI_CONNECTION", ID_NULL instance",
		    pri_connection(c, &cb));
		return false;
	}

	if (NEVER_NEGOTIATE(c->policy)) {
		/* are we a block or clear connection? */
		enum shunt_policy shunt = c->config->prospective_shunt;
		if (shunt != SHUNT_TRAP) {
			/*
			 * We need to match block/clear so we can send back
			 * NO_PROPOSAL_CHOSEN, otherwise not match so we
			 * can hit packetdefault to do real IKE.
			 * clear and block do not have POLICY_OPPORTUNISTIC,
			 * but clear-or-private and private-or-clear do, but
			 * they don't do IKE themselves but allow packetdefault
			 * to be hit and do the work.
			 * if not policy_oppo -> we hit clear/block so this is right c
			 */
			if ((c->policy & POLICY_OPPORTUNISTIC)) {
				connection_buf cb;
				dbg("  skipping "PRI_CONNECTION", never negotiate + oe",
				    pri_connection(c, &cb));
				return false;
			}

			/* shunt match - stop the search for another conn if we are groupinstance*/
			if (c->policy & POLICY_GROUPINSTANCE) {
				return true;
			}
		}
		connection_buf cb;
		dbg("  skipping "PRI_CONNECTION", never negotiate",
		    pri_connection(c, &cb));
		return false;
	}

	/*
	 * Skip when any REQ_POLICY bit is unset (negate makes
	 * them set).
	 */
	if ((req_policy & ~c->policy) != LEMPTY) {
		connection_buf cb;
		dbg("  skipping "PRI_CONNECTION", missing policy",
		    pri_connection(c, &cb));
		return false;
	}

	return true;
}

static struct connection *ikev2_find_host_connection(struct msg_digest *md,
						     lset_t req_policy,
						     bool *send_reject_response)
{
	const ip_endpoint *local_endpoint = &md->iface->local_endpoint;
	const ip_endpoint *remote_endpoint = &md->sender;

	/* just the address */
	ip_address local_address = endpoint_address(*local_endpoint);
	ip_address remote_address = endpoint_address(*remote_endpoint);

	address_buf lb;
	address_buf rb;
	policy_buf pb;
	dbg("%s() %s->%s policy=%s", __func__,
	    str_address(&remote_address, &rb),
	    str_address(&local_address, &lb),
	    str_policy(req_policy, &pb));

	struct connection *c = NULL;
	FOR_EACH_HOST_PAIR_CONNECTION(local_address, remote_address, d) {
		if (!match_policy(d, req_policy)) {
			continue;
		}

		/*
		 * This could be a shared IKE SA connection, in which
		 * case we prefer to find the connection that has the
		 * IKE SA
		 */
		if (d->newest_ike_sa != SOS_NOBODY) {
			/* instant winner */
			c = d;
			break;
		}
		if (c == NULL) {
			c = d;
		}
	}

	if (c != NULL) {
		/*
		 * We found a non-wildcard connection.
		 *
		 * Double check whether it needs instantiation anyway
		 * (eg. vnet=)
		 */
		/* vnet=/vhost= should have set CK_TEMPLATE on connection loading */
		passert(c->spd.this.virt == NULL);
		if (c->kind == CK_TEMPLATE && c->spd.that.virt != NULL) {
			ldbg(md->md_logger,
			     "local endpoint has virt (vnet/vhost) set without wildcards - needs instantiation");
			return rw_instantiate(c, &remote_address, NULL, NULL);
		}

		if ((c->kind == CK_TEMPLATE) &&
		    (c->policy & POLICY_IKEV2_ALLOW_NARROWING)) {
			ldbg(md->md_logger,
			     "local endpoint has narrowing=yes - needs instantiation");
			return rw_instantiate(c, &remote_address, NULL, NULL);
		}

		return c;
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
	FOR_EACH_HOST_PAIR_CONNECTION(local_address, unset_address, d) {
		if (!match_policy(d, req_policy)) {
			continue;
		}

		if (d->kind == CK_GROUP) {
			dbg("  skipping as GROUP");
			continue;
		}

		/*
		 * Road Warrior: we have an instant winner.
		 */
		if (d->kind == CK_TEMPLATE && !(d->policy & POLICY_OPPORTUNISTIC)) {
			c = d;
			dbg("  accepting non-opportunistic");
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

		if (!address_in_selector_range(remote_address, d->spd.that.client)) {
			address_buf ab;
			selector_buf sb;
			dbg("  skipping as %s is-not in range:%s",
			    str_address(&remote_address, &ab),
			    str_selector(&d->spd.that.client, &sb));
			continue;
		}

		if (c != NULL &&
		    selector_range_in_selector_range(c->spd.that.client,
						     d->spd.that.client)) {
			selector_buf s1, s2;
			dbg("  skipping as best range of %s is narrower than %s",
			    str_selector(&c->spd.that.client, &s1),
			    str_selector(&d->spd.that.client, &s2));
			continue;
		}

		selector_buf s1, s2;
		dbg("  saving oppo %s for later, previous %s",
		    str_selector(&d->spd.that.client, &s1),
		    c == NULL ? "n/a" : str_selector(&c->spd.that.client, &s2));
		c = d;
		/* keep looking */
	}

	if (c == NULL) {
		endpoint_buf b;
		policy_buf pb;
		ldbg(md->md_logger,
		     "%s message received on %s but no connection has been authorized with policy %s",
		     enum_name(&ikev2_exchange_names, md->hdr.isa_xchg),
		     str_endpoint(local_endpoint, &b),
		     str_policy(req_policy, &pb));
		*send_reject_response = true;
		return NULL;
	}

	if (c->kind != CK_TEMPLATE) {
		endpoint_buf b;
		connection_buf cib;
		ldbg(md->md_logger,
		     "%s message received on %s for "PRI_CONNECTION" with kind=%s dropped",
		     enum_name(&ikev2_exchange_names, md->hdr.isa_xchg),
		     str_endpoint(local_endpoint, &b),
		     pri_connection(c, &cib),
		     enum_name(&connection_kind_names, c->kind));
		/*
		 * This is used when in IKE_INIT request is
		 * received but hits an OE clear
		 * foodgroup. There is no point sending the
		 * message as it is unauthenticated and cannot
		 * be trusted by the initiator. And the
		 * responder is revealing itself to the
		 * initiator while it is configured to never
		 * talk to that particular initiator. With
		 * this, the system does not need to enforce
		 * this policy using a firewall.
		 *
		 * Note that this technically violates the
		 * IKEv2 specification that states we MUST
		 * answer (with NO_PROPOSAL_CHOSEN).
		 */
		*send_reject_response = false;
		return NULL;
	}

	/* only allow opportunistic for IKEv2 connections */
	if (LIN(POLICY_OPPORTUNISTIC, c->policy) &&
	    c->config->ike_version == IKEv2) {
		connection_buf cb;
		ldbg(md->md_logger, "oppo_instantiate called by %s with "PRI_CONNECTION,
		     __func__, pri_connection(c, &cb));
		c = oppo_instantiate(c, &c->spd.that.id,
				     &local_address, &remote_address);
	} else {
		/* regular roadwarrior */
		ldbg(md->md_logger, "rw_instantiate");
		c = rw_instantiate(c, &remote_address, NULL, NULL);
	}

	return c;
}

struct connection *find_v2_host_pair_connection(struct msg_digest *md, lset_t *policy,
						bool *send_reject_response)
{
	/* authentication policy alternatives in order of decreasing preference */
	static const lset_t policies[] = { POLICY_ECDSA, POLICY_RSASIG, POLICY_PSK, POLICY_AUTH_NULL };

	struct connection *c = NULL;
	unsigned int i;

	/*
	 * XXX in the near future, this loop should find
	 * type=passthrough and return STF_DROP
	 */
	for (i=0; i < elemsof(policies); i++) {
		/*
		 * When the connection "isn't found" POLICY and
		 * SEND_REJECTED_RESPONSE end up with the values from
		 * the final POLICY_AUTH_NULL search.
		 *
		 * For instance, if an earlier search returns NULL but
		 * clears SEND_REJECT_RESPONSE, that will be lost.
		 */
		*policy = policies[i];
		*send_reject_response = true;
		c = ikev2_find_host_connection(md, *policy,
					       send_reject_response);
		if (c != NULL)
			break;
	}

	if (c == NULL) {
		/* we might want to change this to a debug log message only */
		endpoint_buf b;
		llog(RC_LOG_SERIOUS, md->md_logger,
		     "%s message received on %s but no suitable connection found with IKEv2 policy",
		     enum_name(&ikev2_exchange_names, md->hdr.isa_xchg),
		     str_endpoint(&md->iface->local_endpoint, &b));
		return NULL;
	}

	passert(c != NULL);	/* (e != STF_OK) == (c == NULL) */

	connection_buf ci;
	policy_buf pb;
	ldbg(md->md_logger,
	     "found connection: "PRI_CONNECTION" with policy %s",
	     pri_connection(c, &ci),
	     str_policy(*policy, &pb));

	/*
	 * Did we overlook a type=passthrough foodgroup?
	 */
	FOR_EACH_HOST_PAIR_CONNECTION(md->iface->ip_dev->id_address, unset_address, tmp) {

#if 0
		/* REMOTE==%any so d can never be an instance */
		if (tmp->kind == CK_INSTANCE && tmp->spd.that.id.kind == ID_NULL) {
			connection_buf cb;
			dbg("skipping unauthenticated "PRI_CONNECTION" with ID_NULL",
			    pri_connection(tmp, &cb));
			continue;
		}
#endif

		if (tmp->config->prospective_shunt == SHUNT_TRAP) {
			continue;
		}
		if (tmp->kind != CK_INSTANCE) {
			continue;
		}
		ip_address sender = endpoint_address(md->sender);
		if (!address_in_selector_range(sender, tmp->spd.that.client)) {
			continue;
		}
		ldbg(md->md_logger,
		     "passthrough conn %s also matches - check which has longer prefix match", tmp->name);
		if (c->spd.that.client.maskbits >= tmp->spd.that.client.maskbits) {
			continue;
		}
		ldbg(md->md_logger,
		     "passthrough conn was a better match (%d bits versus conn %d bits) - suppressing NO_PROPSAL_CHOSEN reply",
		     tmp->spd.that.client.maskbits,
		     c->spd.that.client.maskbits);
		return NULL;
	}
	return c;
}
