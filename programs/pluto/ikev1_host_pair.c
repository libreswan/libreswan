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
#include "ikev1_host_pair.h"
#include "log.h"
#include "connections.h"
#include "demux.h"

struct connection *find_next_v1_host_connection(struct connection *c,
						lset_t req_policy, lset_t policy_exact_mask,
						const struct id *peer_id)
{
	enum ike_version ike_version = IKEv1;
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

struct connection *find_v1_host_connection(const ip_address local_address,
					   const ip_address remote_address,
					   lset_t req_policy, lset_t policy_exact_mask,
					   const struct id *peer_id)
{
	enum ike_version ike_version = IKEv1;
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
	struct connection *c = find_next_v1_host_connection(hp->connections,
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
	     candidate = find_next_v1_host_connection(candidate->hp_next,
						      req_policy, policy_exact_mask, peer_id)) {
		if (candidate->newest_isakmp_sa != SOS_NOBODY)
			return candidate;
	}

	return c;
}
