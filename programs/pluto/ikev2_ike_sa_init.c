/* IKEv2's IKE_SA_INIT exchange, for libreswan
 *
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010-2019 Tuomo Soini <tis@foobar.fi
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012-2018 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017-2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2017-2018 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
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

#include "defs.h"
#include "demux.h"
#include "state.h"
#include "ikev2.h"
#include "log.h"
#include "ikev2_message.h"
#include "ikev2_send.h"
#include "connections.h"
#include "ikev2_redirect.h"
#include "nat_traversal.h"
#include "send.h"
#include "pluto_stats.h"
#include "crypt_dh.h"
#include "pluto_crypt.h"

stf_status process_IKE_SA_INIT_v2N_INVALID_KE_PAYLOAD_response(struct ike_sa *ike,
							       struct child_sa *child,
							       struct msg_digest *md)
{
	struct connection *c = ike->sa.st_connection;

	pexpect(child == NULL);
	if (!pexpect(md->pbs[PBS_v2N_INVALID_KE_PAYLOAD] != NULL)) {
		return STF_INTERNAL_ERROR;
	}
	struct pbs_in invalid_ke_pbs = *md->pbs[PBS_v2N_INVALID_KE_PAYLOAD];

	/* careful of DDOS, only log with debugging on? */
	/* we treat this as a "retransmit" event to rate limit these */
	if (!count_duplicate(&ike->sa, MAXIMUM_INVALID_KE_RETRANS)) {
		dbg("ignoring received INVALID_KE packets - received too many (DoS?)");
		return STF_IGNORE;
	}

	/*
	 * There's at least this notify payload, is there more than
	 * one?
	 */
	if (md->chain[ISAKMP_NEXT_v2N]->next != NULL) {
		dbg("ignoring other notify payloads");
	}

	struct suggested_group sg;
	if (!in_struct(&sg, &suggested_group_desc, &invalid_ke_pbs, NULL)) {
		/* already logged */
		return STF_IGNORE;
	}

	pstats(invalidke_recv_s, sg.sg_group);
	pstats(invalidke_recv_u, ike->sa.st_oakley.ta_dh->group);

	struct ikev2_proposals *ike_proposals =
		get_v2_ike_proposals(c, "IKE SA initiator validating remote's suggested KE");
	if (!ikev2_proposals_include_modp(ike_proposals, sg.sg_group)) {
		struct esb_buf esb;
		log_state(RC_LOG, &ike->sa,
			  "Discarding unauthenticated INVALID_KE_PAYLOAD response to DH %s; suggested DH %s is not acceptable",
			  ike->sa.st_oakley.ta_dh->common.fqn,
			  enum_show_shortb(&oakley_group_names,
					   sg.sg_group, &esb));
		return STF_IGNORE;
	}

	dbg("Suggested modp group is acceptable");
	/*
	 * Since there must be a group object for every local
	 * proposal, and sg.sg_group matches one of the local proposal
	 * groups, a lookup of sg.sg_group must succeed.
	 */
	const struct dh_desc *new_group = ikev2_get_dh_desc(sg.sg_group);
	passert(new_group != NULL);
	log_state(RC_LOG, &ike->sa,
		  "Received unauthenticated INVALID_KE_PAYLOAD response to DH %s; resending with suggested DH %s",
		  ike->sa.st_oakley.ta_dh->common.fqn,
		  new_group->common.fqn);
	ike->sa.st_oakley.ta_dh = new_group;
	/* wipe our mismatched KE */
	free_dh_secret(&ike->sa.st_dh_secret);
	/*
	 * Need to wind the Message ID back to the point where the
	 * send code thinkgs this is the initial request.
	 */
	v2_msgid_init_ike(ike);
	/*
	 * Stop retransmits! ?????
	 */
	clear_retransmits(&ike->sa);
	/*
	 * get a new KE
	 */
	request_ke_and_nonce("rekey outI", &ike->sa,
			     ike->sa.st_oakley.ta_dh,
			     ikev2_parent_outI1_continue);
	return STF_SUSPEND;
}
