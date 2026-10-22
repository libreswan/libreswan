/* demultiplex incoming IKE messages
 *
 * Copyright (C) 1998-2002,2013-2016 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2008 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013,2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2015 Antony Antony <antony@phenome.org>
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
 * Copyright (C) 2022 Paul Wouters <paul.wouters@aiven.io>
 * Copyright (C) 2026 Andrew Cagney
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
 */

#include "pluto_constants.h"
#include "names.h"
#include "ipsecconf/setup.h"

#include "defs.h"

#include "ikev1_demux.h"

#include "demux.h"
#include "log.h"
#include "pluto_stats.h"
#include "ikev1_notification.h"
#include "ikev1.h"

static enum global_ikev1_policy global_ikev1_policy; /* see init_demux() */

void process_ikev1_md(struct msg_digest *md,
		      unsigned vmajor, unsigned vminor)
{
	if (global_ikev1_policy == GLOBAL_IKEv1_DROP) {
		limited_llog_md(md, "ignoring IKEv1 packet as global policy is set to silently drop all IKEv1 packets");
		pstats_ikev1_dropped++;
		return;
	}
	if (global_ikev1_policy == GLOBAL_IKEv1_REJECT) {
		limited_llog_md(md, "rejecting IKEv1 packet as global policy is set to reject all IKEv1 packets");
		send_v1_notification_from_md(md, v1N_INVALID_MAJOR_VERSION);
		pstats_ikev1_dropped++;
		return;
	}

	if (vminor > ISAKMP_MINOR_VERSION) {
		/*
		 * RFC2408 3.1 ISAKMP Header Format:
		 *
		 * Minor Version (4 bits) - indicates the minor
		 * version of the ISAKMP protocol in use.
		 * Implementations based on this version of the ISAKMP
		 * Internet-Draft MUST set the Minor Version to 0.
		 * Implementations based on previous versions of
		 * ISAKMP Internet- Drafts MUST set the Minor Version
		 * to 1.  Implementations SHOULD never accept packets
		 * with a minor version number larger than its own,
		 * given the major version numbers are identical.
		 */
		limited_llog_md(md, "ignoring packet with IKEv1 minor version number %d greater than %d",
				vminor, ISAKMP_MINOR_VERSION);
		send_v1_notification_from_md(md, v1N_INVALID_MINOR_VERSION);
		return;
	}
	name_buf xb;
	ldbg(md->logger,
	     "processing version=%u.%u packet with exchange type=%s (%d)",
	     vmajor, vminor,
	     str_enum_short(&ikev1_exchange_names, md->hdr.isa_xchg, &xb),
	     md->hdr.isa_xchg);
	process_v1_packet(md);
	/* our caller will md_delref(mdp) */
}

void init_ikev1_demux(struct logger *logger UNUSED)
{
	global_ikev1_policy = config_setup_option(KBF_IKEv1_POLICY);
}
