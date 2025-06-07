/* Libreswan ISAKMP VendorID Handling
 * Copyright (C) 2002-2003 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2004 Xelerance Corporation
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 *
 * See also https://github.com/royhills/ike-scan/blob/master/ike-vendor-ids
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

#include "vendorid.h"

#include "defs.h"

#include "log.h"

#include "ikev2_vendorid.h"

/*
 * Handle IKEv2 Known VendorID's.
 * We don't know about any real IKEv2 vendor id strings yet
 */

void handle_v2_vendorid(shunk_t vid, struct logger *logger)
{
	enum known_vendorid id = vendorid_by_shunk(vid);

	/* IKEv2 VID processing */
	bool vid_useful = true; /* tentatively TRUE */
	switch (id) {
	case VID_LIBRESWANSELF:
	case VID_LIBRESWAN:
	case VID_LIBRESWAN_OLD:
	case VID_OPPORTUNISTIC:
		/* not really useful, but it changes the msg from "ignored" to "received" */
		break;
	default:
		vid_useful = false;
		break;
	}

	llog_vendorid(logger, id, vid, vid_useful);
}

/*
 * Add an IKEv2 (!)  vendor id payload to the msg
 */

static bool emit_v2V_raw(struct pbs_out *outs, shunk_t vid, const char *descr)
{
	struct ikev2_generic gen = {
		.isag_np = 0,
	};

	struct pbs_out pbs;
	if (!pbs_out_struct(outs, &ikev2_vendor_id_desc, &gen, sizeof(gen), &pbs)) {
		/* already logged */
		return false; /*fatal*/
	}

	if (!pbs_out_hunk(&pbs, vid, descr)) {
		/* already logged */
		return false;
	}
	close_output_pbs(&pbs);
	return true;
}

bool emit_v2V(struct pbs_out *outs, const char * vid)
{
	return emit_v2V_raw(outs, shunk1(vid), vid);
}

bool emit_v2VID(struct pbs_out *outs, enum known_vendorid id)
{
	shunk_t vid = shunk_from_vendorid(id);
	name_buf eb;
	const char *descr = str_vendorid(id, &eb);
	dbg("%s(): sending [%s]", __func__, descr);
	return emit_v2V_raw(outs, vid, descr);
}

/*
 * The VID table or entries are static
 */
bool vid_is_oppo(const char *vid, size_t len)
{
	shunk_t oppo = shunk_from_vendorid(VID_OPPORTUNISTIC);
	if (oppo.len == len && memeq(vid, oppo.ptr, len)) {
		dbg("VID_OPPORTUNISTIC received");
		return true;
	} else {
		return false;
	}
}
