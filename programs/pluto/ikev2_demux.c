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
#include "ipsecconf/setup.h"

#include "defs.h"

#include "ikev2_demux.h"

#include "demux.h"
#include "log.h"
#include "pluto_stats.h"
#include "ikev2_notification.h"
#include "ikev2.h"

void process_ikev2_md(struct msg_digest *md,
		      unsigned vmajor, unsigned vminor)
{
	if (vminor != IKEv2_MINOR_VERSION) {
		/* Unlike IKEv1, for IKEv2 we are supposed to try to
		 * continue on unknown minors
		 */
		limited_llog_md(md, "Ignoring unknown/unsupported IKEv2 minor version number %d",
				vminor);
	}
	name_buf xb;
	ldbg(md->logger,
	     "processing version=%u.%u packet with exchange type=%s (%d)",
	     vmajor, vminor,
	     str_enum_short(&ikev2_exchange_names, md->hdr.isa_xchg, &xb),
	     md->hdr.isa_xchg);
	process_ikev2_packet(md);
}
