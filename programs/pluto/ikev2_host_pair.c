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

static struct connection *find_next_v2_host_connection(struct connection *c,
						       lset_t req_policy, lset_t policy_exact_mask,
						       const struct id *peer_id)
{
	enum ike_version ike_version = IKEv2;
	policy_buf pb;
	dbg("find_next_host_connection policy=%s",
	    str_policy(req_policy, &pb));

	for (; c != NULL; c = c->hp_next) {
		policy_buf fb;
		dbg("found policy = %s (%s)",
		    str_policy(c->policy, &fb),
		    c->name);

		if (NEVER_NEGOTIATE(c->policy)) {
			/* are we a block or clear connection? */
			lset_t shunt = (c->policy & POLICY_SHUNT_MASK) >> POLICY_SHUNT_SHIFT;
			if (shunt != POLICY_SHUNT_TRAP) {
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
				if ((c->policy & POLICY_OPPORTUNISTIC))
					continue;

				/* shunt match - stop the search for another conn if we are groupinstance*/
				if (c->policy & POLICY_GROUPINSTANCE)
					break;
			}
			continue;
		}

		/*
		 * Success may require exact match of:
		 * (1) XAUTH (POLICY_XAUTH)
		 * (2) kind of IKEV1 (POLICY_AGGRESSIVE)
		 * (3) IKE_VERSION
		 * So if any bits are on in the exclusive OR, we fail.
		 * Each of our callers knows what is known so specifies
		 * the policy_exact_mask.
		 */
		if (c->ike_version != ike_version)
			continue;
		if ((req_policy ^ c->policy) & policy_exact_mask)
			continue;

		if (peer_id != NULL && !same_id(peer_id, &c->spd.that.id) &&
			(c->spd.that.id.kind != ID_FROMCERT && !any_id(&c->spd.that.id))) {
				continue; /* incompatible ID */
		}

		/*
		 * Success if all specified policy bits are in candidate's policy.
		 * It works even when the exact-match bits are included.
		 */
		if ((req_policy & ~c->policy) == LEMPTY)
			break;
	}

	if (DBGP(DBG_BASE)) {
		if (c == NULL) {
			DBG_log("find_next_host_connection returns <empty>");
		} else {
			connection_buf ci;
			DBG_log("find_next_host_connection returns "PRI_CONNECTION"",
				pri_connection(c, &ci));
		}
	}

	return c;
}

/*
 * find_host_connection: find the first satisfactory connection
 *	with this pair of hosts.
 *
 * find_next_host_connection: find the next satisfactory connection
 *	Starts where find_host_connection left off.
 *	NOTE: it will return its argument; if you want to
 *	advance, use c->hp_next.
 *
 * We start with the list that find_host_pair_connections would yield
 * but we narrow the selection.
 *
 * We only yield a connection that can negotiate.
 *
 * The caller can specify policy requirements as
 * req_policy and policy_exact_mask.
 *
 * All policy bits found in req_policy must be in the
 * policy of the connection.
 *
 * For all bits in policy_exact mask, the req_policy
 * and connection's policy must be equal.  Likely candidates:
 * - XAUTH (POLICY_XAUTH)
 * - kind of IKEV1 (POLICY_AGGRESSIVE)
 * These should only be used if the caller actually knows
 * the exact value and has included it in req_policy.
 */

static struct connection *find_v2_host_connection(const ip_address local_address,
						  const ip_address remote_address,
						  lset_t req_policy, lset_t policy_exact_mask,
						  const struct id *peer_id)
{
	enum ike_version ike_version = IKEv2;
	address_buf lb;
	address_buf rb;
	policy_buf pb;
	dbg("find_host_connection %s local=%s remote=%s policy=%s but ignoring ports",
	    enum_name(&ike_version_names, ike_version),
	    str_address(&local_address, &lb),
	    str_address(&remote_address, &rb),
	    str_policy(req_policy, &pb));

	struct host_pair *hp = find_host_pair(local_address, remote_address);
	if (hp == NULL) {
		return NULL;
	}

	/* XXX: don't be fooled by "next", the search includes hp->connections */
	struct connection *c = find_next_v2_host_connection(hp->connections,
							    req_policy, policy_exact_mask, peer_id);
	/*
	 * This could be a shared IKE SA connection, in which case
	 * we prefer to find the connection that has the IKE SA
	 *
	 * XXX: need to advance candidate before calling
	 * find_next_host_connection() as otherwise it returns the
	 * same connection, ARGH!
	 */
	for (struct connection *candidate = c;
	     candidate != NULL;
	     candidate = find_next_v2_host_connection(candidate->hp_next,
						      req_policy, policy_exact_mask, peer_id)) {
		if (candidate->newest_isakmp_sa != SOS_NOBODY)
			return candidate;
	}

	return c;
}

static struct connection *ikev2_find_host_connection(struct msg_digest *md,
						     lset_t policy, bool *send_reject_response)
{
	const ip_endpoint *local_endpoint = &md->iface->local_endpoint;
	const ip_endpoint *remote_endpoint = &md->sender;
        struct id peer_id;
	struct id *ppeer_id = NULL;

	struct payload_digest *const pl_id_peer = md->chain[ISAKMP_NEXT_v2IDi];
	if (pl_id_peer == NULL) {
                dbg("IKEv2 no peer ID received");
	} else {
		enum ike_id_type hik = pl_id_peer->payload.v2id.isai_type; /* Peers Id Kind */
		diag_t d = unpack_peer_id(hik, &peer_id, &pl_id_peer->pbs);
		if (d != NULL) {
			dbg("IKEv2 mode peer ID extraction failed - ignored peer ID for connection lookup");
		} else {
			ppeer_id = &peer_id;
		}
	}

	/* just the adddress */
	ip_address local_address = endpoint_address(*local_endpoint);
	ip_address remote_address = endpoint_address(*remote_endpoint);

	struct connection *c = find_v2_host_connection(local_address,
						       remote_address,
						       policy, LEMPTY, ppeer_id);
	if (c == NULL) {
		/*
		 * See if a wildcarded connection can be found.  We
		 * cannot pick the right connection, so we're making a
		 * guess.  All Road Warrior connections are fair game:
		 * we pick the first we come across (if any).  If we
		 * don't find any, we pick the first opportunistic
		 * with the smallest subnet that includes the peer.
		 * There is, of course, no necessary relationship
		 * between an Initiator's address and that of its
		 * client, but Food Groups kind of assumes one.
		 */
		for (struct connection *d = find_v2_host_connection(local_address,
								    unset_address,
								    policy, LEMPTY, ppeer_id);
		     d != NULL; d = find_next_v2_host_connection(d->hp_next, policy, LEMPTY, ppeer_id)) {
			if (d->kind == CK_GROUP) {
				continue;
			}
			/*
			 * Road Warrior: we have an instant winner.
			 */
			if (d->kind == CK_TEMPLATE && !(d->policy & POLICY_OPPORTUNISTIC)) {
				c = d;
				break;
			}
			/*
			 * Opportunistic or Shunt: keep searching
			 * selecting the tightest match.
			 */
			if (address_in_selector_subnet(remote_address, d->spd.that.client) &&
			    (c == NULL || !selector_in_selector(c->spd.that.client,
								d->spd.that.client))) {

				c = d;
				/* keep looking */
			}
		}

		if (c == NULL) {
			endpoint_buf b;
			policy_buf pb;
			dbgl(md->md_logger,
			     "%s message received on %s but no connection has been authorized with policy %s",
			     enum_name(&ikev2_exchange_names, md->hdr.isa_xchg),
			     str_endpoint(local_endpoint, &b),
			     str_policy(policy, &pb));
			*send_reject_response = true;
			return NULL;
		}

		if (c->kind != CK_TEMPLATE) {
			endpoint_buf b;
			connection_buf cib;
			dbgl(md->md_logger,
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
		    c->ike_version == IKEv2) {
			dbgl(md->md_logger, "oppo_instantiate");
			c = oppo_instantiate(c, &c->spd.that.id,
					     &local_address, &remote_address);
		} else {
			/* regular roadwarrior */
			dbgl(md->md_logger, "rw_instantiate");
			c = rw_instantiate(c, &remote_address, NULL, NULL);
		}
	} else {
		/*
		 * We found a non-wildcard connection.
		 * Double check whether it needs instantiation anyway (eg. vnet=)
		 */
		/* vnet=/vhost= should have set CK_TEMPLATE on connection loading */
		passert(c->spd.this.virt == NULL);

		if (c->kind == CK_TEMPLATE && c->spd.that.virt != NULL) {
			dbgl(md->md_logger,
			     "local endpoint has virt (vnet/vhost) set without wildcards - needs instantiation");
			c = rw_instantiate(c, &remote_address, NULL, NULL);
		} else if ((c->kind == CK_TEMPLATE) &&
				(c->policy & POLICY_IKEV2_ALLOW_NARROWING)) {
			dbgl(md->md_logger,
			     "local endpoint has narrowing=yes - needs instantiation");
			c = rw_instantiate(c, &remote_address, NULL, NULL);
		}
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
	dbgl(md->md_logger,
	     "found connection: "PRI_CONNECTION" with policy %s",
	     pri_connection(c, &ci),
	     str_policy(*policy, &pb));

	/*
	 * Did we overlook a type=passthrough foodgroup?
	 */
	FOR_EACH_HOST_PAIR_CONNECTION(md->iface->ip_dev->id_address, unset_address, tmp) {
		if ((tmp->policy & POLICY_SHUNT_MASK) == POLICY_SHUNT_TRAP) {
			continue;
		}
		if (tmp->kind != CK_INSTANCE) {
			continue;
		}
		ip_address sender = endpoint_address(md->sender);
		if (!address_in_selector_subnet(sender, tmp->spd.that.client)) {
			continue;
		}
		dbgl(md->md_logger,
		     "passthrough conn %s also matches - check which has longer prefix match", tmp->name);
		if (c->spd.that.client.maskbits >= tmp->spd.that.client.maskbits) {
			continue;
		}
		dbgl(md->md_logger,
		     "passthrough conn was a better match (%d bits versus conn %d bits) - suppressing NO_PROPSAL_CHOSEN reply",
		     tmp->spd.that.client.maskbits,
		     c->spd.that.client.maskbits);
		return NULL;
	}
	return c;
}
