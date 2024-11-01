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
#include "ikev1_vendorid.h"
#include "demux.h"
#include "connections.h"

/*
 * Handle IKEv1 Known VendorID's.  This function parses what the remote peer
 * sends us, and enables/disables features based on it.  As we go along,
 * we set vid_useful to TRUE if we did something based on this VendorID.  This
 * suppresses the 'Ignored VendorID ...' log message.
 *
 * @param md message_digest
 * @param vidstr VendorID String
 * @param len Length of vidstr
 * @param vid VendorID Struct (see vendor.h)
 * @param st State Structure (Hopefully initialized)
 * @return void
 */

void handle_v1_vendorid(struct msg_digest *md,
			shunk_t vid,
			struct logger *logger)
{
	enum known_vendorid id = vendorid_by_shunk(vid);

	bool vid_useful = true; /* tentatively TRUE */

	switch (id) {
	/*
	 * Use most recent supported NAT-Traversal method and ignore
	 * the other ones (implementations will send all supported
	 * methods but only one will be used)
	 *
	 * Note: most recent == higher id in vendor.h
	 */

	case VID_LIBRESWANSELF:
	case VID_LIBRESWAN:
	case VID_LIBRESWAN_OLD:
	case VID_OPPORTUNISTIC:
		/* not really useful, but it changes the msg from "ignored" to "received" */
		break;

	case VID_NATT_IETF_00:
	case VID_NATT_IETF_01:
		vid_useful = false; /* no longer supported */
		break;

	case VID_NATT_IETF_02:
	case VID_NATT_IETF_02_N:
	case VID_NATT_IETF_03:
	case VID_NATT_IETF_04:
	case VID_NATT_IETF_05:
	case VID_NATT_IETF_06:
	case VID_NATT_IETF_07:
	case VID_NATT_IETF_08:
	case VID_NATT_DRAFT_IETF_IPSEC_NAT_T_IKE:
	case VID_NATT_RFC:
		if (md->v1_quirks.qnat_traversal_vid < id) {
			enum_buf idb;
			dbg(" quirks.qnat_traversal_vid set to=%d [%s]", id,
			    str_vendorid(id, &idb));
			md->v1_quirks.qnat_traversal_vid = id;
		} else {
			enum_buf idb;
			dbg("ignoring older NAT-T Vendor ID payload [%s]",
			    str_vendorid(id, &idb));
			vid_useful = false;
		}
		break;

	case VID_MISC_DPD:
	case VID_DPD1_NG:
		/* Remote side would like to do DPD with us on this connection */
		md->dpd = true;
		break;

	case VID_MISC_IKEv2:
		md->ikev2 = true;
		break;

	case VID_SSH_SENTINEL_1_4_1:
		llog(RC_LOG, logger,
			    "SSH Sentinel 1.4.1 found, setting XAUTH_ACK quirk");
		md->v1_quirks.xauth_ack_msgid = true;
		break;

	case VID_CISCO_UNITY:
		md->v1_quirks.modecfg_pull_mode = true;
		break;

	case VID_MISC_XAUTH:
		md->v1_quirks.xauth_vid = true;
		break;

	case VID_IKE_FRAGMENTATION:
		md->fragvid = true;
		break;

	default:
		vid_useful = false;
		break;
	}

	llog_vendorid(logger, id, vid, vid_useful);
}

/**
 * Add an IKEv1 (!)  vendor id payload to the msg
 *
 * @param np
 * @param outs PB stream
 * @param vid Int of VendorID to be sent (see vendor.h for the list)
 * @return bool True if successful
 */

bool out_v1VID(struct pbs_out *outs, unsigned int id)
{
	shunk_t blob = shunk_from_vendorid(id);
	enum_buf eb;
	const char *descr = str_vendorid(id, &eb);
	dbg("%s(): sending [%s]", __func__, descr);
	return ikev1_out_generic_raw(&isakmp_vendor_id_desc, outs,
				     blob.ptr, blob.len, "V_ID");
}

/*
 * out_vid_set: output all Vendor ID payloads for IKEv1.
 *
 * Next Payload has historically been tricky.  We dodge this
 * by a couple of ways
 *
 * We always emit DPD VID.  So the our caller knows that the
 * preceding NP must be ISAKMP_NEXT_VID.  This also means that
 * each VID payload before DPD VID must have NP ISAKMP_NEXT_VID.
 *
 * It happens that VID payloads that are emitted here are the last payloads
 * of the message so the DPD VID payload's NP must be ISAKMP_NEXT_NONE.
 *
 * If any changes make this NP calculation more tricky, we should
 * exploit the NP backpatching logic in out_struct.
 */

bool out_v1VID_set(struct pbs_out *outs, const struct connection *c)
{
	/* cusomizeable Vendor ID */
	if (c->config->send_vendorid) {
		if (!ikev1_out_generic_raw(&isakmp_vendor_id_desc, outs,
					pluto_vendorid, strlen(pluto_vendorid), "Pluto Vendor ID")) {
			return false;
		}
	}

#define MAYBE_VID(q, vid) {  \
	if (q) {  \
		if (!out_v1VID(outs, vid)) {  \
			return false;  \
		}  \
	}  \
}

	MAYBE_VID(c->config->send_vid_cisco_unity, VID_CISCO_UNITY);
	MAYBE_VID(c->config->send_vid_fake_strongswan, VID_STRONGSWAN);
	MAYBE_VID(c->config->ike_frag.allow, VID_IKE_FRAGMENTATION);
	MAYBE_VID(c->local->host.config->xauth.client || c->local->host.config->xauth.server, VID_MISC_XAUTH);

#undef MAYBE_VID

	/*
	 * DPD: last, unconditional, VID.
	 * Note: because this is unconditional AND last
	 * we know that all previous np must be ISAKMP_NEXT_VID.
	 * There might be a successor payload generated by caller;
	 * we count on backpatching to fix our np.
	 */

	if (!out_v1VID(outs, VID_MISC_DPD)) {
		return false;
	}

	return true;
}
