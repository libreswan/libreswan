/*
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2011-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2018 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012,2016-2017 Antony Antony <appu@phenome.org>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2014-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Antony Antony <antony@phenome.org>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
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

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "sysdep.h"
#include "constants.h"

#include "defs.h"
#include "id.h"
#include "x509.h"
#include "pluto_x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "packet.h"
#include "crypto.h"
#include "ike_alg.h"
#include "log.h"
#include "demux.h"      /* needs packet.h */
#include "ikev2.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "timer.h"
#include "whack.h"      /* requires connections.h */
#include "server.h"
#include "host_pair.h"
#include "addresspool.h"
#include "rnd.h"
#include "ip_address.h"
#include "ikev2_send.h"
#include "ikev2_message.h"
#include "ikev2_ts.h"
#include "ip_info.h"
#ifdef USE_XFRM_INTERFACE
# include "kernel_xfrm_interface.h"
#endif
#include "ikev2_cp.h"
#include "ikev2_child.h"
#include "ike_alg_dh.h"
#include "pluto_stats.h"
#include "pending.h"
#include "kernel.h"			/* for get_my_cpi() hack */
#include "ikev2_proposals.h"

static bool emit_v2_child_response_payloads(struct ike_sa *ike,
					    const struct child_sa *child,
					    const struct msg_digest *request_md,
					    struct pbs_out *outpbs);

static bool has_v2_IKE_AUTH_child_sa_payloads(const struct msg_digest *md)
{
	return (md->chain[ISAKMP_NEXT_v2SA] != NULL &&
		md->chain[ISAKMP_NEXT_v2TSi] != NULL &&
		md->chain[ISAKMP_NEXT_v2TSr] != NULL);
}

static bool compute_v2_child_ipcomp_cpi(struct child_sa *larval_child)
{
	const struct connection *cc = larval_child->sa.st_connection;
	pexpect(larval_child->sa.st_ipcomp.inbound.spi == 0);
	/* CPI is stored in network low order end of an ipsec_spi_t */
	ipsec_spi_t n_ipcomp_cpi = get_ipsec_cpi(cc, larval_child->sa.st_logger);
	ipsec_spi_t h_ipcomp_cpi = (uint16_t)ntohl(n_ipcomp_cpi);
	dbg("calculated compression CPI=%d", h_ipcomp_cpi);
	if (h_ipcomp_cpi < IPCOMP_FIRST_NEGOTIATED) {
		/* get_my_cpi() failed */
		llog_sa(RC_LOG_SERIOUS, larval_child,
			"kernel failed to calculate compression CPI (CPI=%d)", h_ipcomp_cpi);
		return false;
	}
	larval_child->sa.st_ipcomp.inbound.spi = n_ipcomp_cpi;
	return true;
}

static bool compute_v2_child_spi(struct child_sa *larval_child)
{
	struct connection *cc = larval_child->sa.st_connection;
	struct ipsec_proto_info *proto_info = ikev2_child_sa_proto_info(larval_child);
	/* XXX: should "avoid" be set to the peer's SPI when known? */
	pexpect(proto_info->inbound.spi == 0);
	proto_info->inbound.spi = get_ipsec_spi(cc,
						proto_info->protocol,
						0 /* avoid this # */,
						larval_child->sa.st_logger);
	return (proto_info->inbound.spi != 0);
}

static bool emit_v2N_ipcomp_supported(const struct child_sa *child, struct pbs_out *s)
{
	dbg("Initiator child policy is compress=yes, sending v2N_IPCOMP_SUPPORTED for DEFLATE");

	ipsec_spi_t h_cpi = (uint16_t)ntohl(child->sa.st_ipcomp.inbound.spi);
	if (!pexpect(h_cpi != 0)) {
		return false;
	}

	struct ikev2_notify_ipcomp_data id = {
		.ikev2_cpi = h_cpi, /* packet code expects host byte order */
		.ikev2_notify_ipcomp_trans = IPCOMP_DEFLATE,
	};

	struct pbs_out d_pbs;
	if (!emit_v2Npl(v2N_IPCOMP_SUPPORTED, s, &d_pbs)) {
		return false;
	}

	if (!pbs_out_struct(&d_pbs, &ikev2notify_ipcomp_data_desc, &id, sizeof(id), NULL)) {
		/* already logged */
		return false; /*fatal */
	}

	close_output_pbs(&d_pbs);
	return true;
}

bool prep_v2_child_for_request(struct child_sa *larval_child)
{
	struct connection *cc = larval_child->sa.st_connection;
	if ((cc->policy & POLICY_COMPRESS) &&
	    !compute_v2_child_ipcomp_cpi(larval_child)) {
		return false;
	}

	/* Generate and save!!! a new SPI. */
	if (!compute_v2_child_spi(larval_child)) {
		return false;
	}

	return true;
}

bool emit_v2_child_request_payloads(const struct ike_sa *ike,
				    const struct child_sa *larval_child,
				    const struct ikev2_proposals *child_proposals,
				    struct pbs_out *pbs)
{
	if (!pexpect(larval_child->sa.st_state->kind == STATE_V2_NEW_CHILD_I0 ||
		     larval_child->sa.st_state->kind == STATE_V2_REKEY_CHILD_I0 ||
		     larval_child->sa.st_state->kind == STATE_V2_IKE_AUTH_CHILD_I0)) {
		return false;
	}

	if (!pexpect(larval_child->sa.st_establishing_sa == IPSEC_SA)) {
		return false;
	}

	/* hack */
	bool ike_auth_exchange = (larval_child->sa.st_state->kind == STATE_V2_IKE_AUTH_CHILD_I0);

	struct connection *cc = larval_child->sa.st_connection;

	/* SA - security association */

	const struct ipsec_proto_info *proto_info = ikev2_child_sa_proto_info(larval_child);
	shunk_t local_spi = THING_AS_SHUNK(proto_info->inbound.spi);
	if (!ikev2_emit_sa_proposals(pbs, child_proposals, local_spi)) {
		return false;
	}

	/* Ni - only for CREATE_CHILD_SA */

	if (!ike_auth_exchange) {
		struct ikev2_generic in = {
			.isag_critical = build_ikev2_critical(false, larval_child->sa.st_logger),
		};
		struct pbs_out pb_nr;
		if (!pbs_out_struct(pbs, &ikev2_nonce_desc, &in, sizeof(in), &pb_nr)) {
			/* already logged */
			return false; /*fatal*/
		}

		if (!pbs_out_hunk(&pb_nr, larval_child->sa.st_ni, "IKEv2 nonce")) {
			/* already logged */
			return false;
		}
		close_output_pbs(&pb_nr);
	}

	/* KEi - only for CREATE_CHILD_SA; and then only sometimes. */

	if (larval_child->sa.st_pfs_group != NULL &&
	    !emit_v2KE(larval_child->sa.st_gi, larval_child->sa.st_pfs_group, pbs)) {
		return false;
	}

	/* CP[CFG_REQUEST) - only IKE_AUTH exchange for now */

	if (!ike_auth_exchange) {
		dbg("skipping CP, not IKE_AUTH request");
	} else if (need_v2CP_request(cc, ike->sa.hidden_variables.st_nat_traversal)) {
		if (!emit_v2CP_request(larval_child, pbs)) {
			return false;
		}
	}

	/* TS[ir] - traffic selectors */

	if (!emit_v2TS_request_payloads(pbs, larval_child)) {
		return false;
	}

	/* IPCOMP based on policy */

	if ((cc->policy & POLICY_COMPRESS) &&
	    !emit_v2N_ipcomp_supported(larval_child, pbs)) {
		return false;
	}

	/* Transport based on policy */

	bool send_use_transport = (cc->policy & POLICY_TUNNEL) == LEMPTY;
	dbg("Initiator child policy is transport mode, sending v2N_USE_TRANSPORT_MODE? %s",
	    bool_str(send_use_transport));
	if (send_use_transport &&
	    !emit_v2N(v2N_USE_TRANSPORT_MODE, pbs)) {
		return false;
	}

	if (cc->config->send_no_esp_tfc &&
	    !emit_v2N(v2N_ESP_TFC_PADDING_NOT_SUPPORTED, pbs)) {
		return false;
	}

	return true;
}

/*
 * Process the CHILD payloads (assumes the SA proposal payloads were
 * handled earlier).
 *
 * Three possible outcomes:
 *
 * - everything works: v2N_NOTHING_WRONG is returned and SK_PBS
 * contains response.
 *
 * - the child is invalid: a non-fatal notification is returned; the
 *   caller deletes the larval child and records the notification as
 *   the response (or part of a bigger response)
 *
 * - something bad: a fatal notification is returned; the caller
 *   deletes the larval child, tears down the IKE SA, and records the
 *   notification as the response
 *
 * XXX: should this code instead handle things like deleting the child
 * and recording non-fatal notifications?  For moment no:
 *
 * - would have one function creating Child with nested function
 *   deleting it
 *
 * - would have caller having to decide if/when to ignore result
 */

v2_notification_t process_v2_child_request_payloads(struct ike_sa *ike,
						    struct child_sa *larval_child,
						    struct msg_digest *request_md,
						    struct pbs_out *sk_pbs)
{
	struct connection *cc = larval_child->sa.st_connection;

	pexpect(larval_child->sa.st_v2_accepted_proposal != NULL);

	/*
	 * Verify if transport / tunnel mode matches; update the
	 * proposal as needed.
	 */

	bool expecting_transport_mode = ((cc->policy & POLICY_TUNNEL) == LEMPTY);
	enum encapsulation_mode encapsulation_mode = ENCAPSULATION_MODE_TUNNEL;
	if (request_md->pd[PD_v2N_USE_TRANSPORT_MODE] != NULL) {
		if (!expecting_transport_mode) {
			/*
			 * RFC allows us to ignore their (wrong)
			 * request for transport mode
			 */
			llog_sa(RC_LOG, larval_child,
				"policy dictates Tunnel Mode, ignoring peer's request for Transport Mode");
		} else {
			dbg("local policy is transport mode and received USE_TRANSPORT_MODE");
			larval_child->sa.st_seen_and_use_transport_mode = true;
			encapsulation_mode = ENCAPSULATION_MODE_TRANSPORT;
			if (larval_child->sa.st_esp.present) {
				larval_child->sa.st_esp.attrs.mode = encapsulation_mode;
			}
			if (larval_child->sa.st_ah.present) {
				larval_child->sa.st_ah.attrs.mode = encapsulation_mode;
			}
		}
	} else if (expecting_transport_mode) {
		/* we should have received transport mode request */
		llog_sa(RC_LOG_SERIOUS, larval_child,
			"policy dictates Transport Mode, but peer requested Tunnel Mode");
		return v2N_NO_PROPOSAL_CHOSEN;
	}

	if (!compute_v2_child_spi(larval_child)) {
		return v2N_INVALID_SYNTAX;/* something fatal */
	}

	bool expecting_compression = (cc->policy & POLICY_COMPRESS);
	if (request_md->pd[PD_v2N_IPCOMP_SUPPORTED] != NULL) {
		if (!expecting_compression) {
			dbg("Ignored IPCOMP request as connection has compress=no");
			larval_child->sa.st_ipcomp.present = false;
		} else {
			dbg("received v2N_IPCOMP_SUPPORTED");

			struct pbs_in pbs = request_md->pd[PD_v2N_IPCOMP_SUPPORTED]->pbs;
			struct ikev2_notify_ipcomp_data n_ipcomp;
			diag_t d = pbs_in_struct(&pbs, &ikev2notify_ipcomp_data_desc,
						 &n_ipcomp, sizeof(n_ipcomp), NULL);
			if (d != NULL) {
				llog_diag(RC_LOG, larval_child->sa.st_logger, &d, "%s", "");
				return v2N_NO_PROPOSAL_CHOSEN;
			}

			if (n_ipcomp.ikev2_notify_ipcomp_trans != IPCOMP_DEFLATE) {
				llog_sa(RC_LOG_SERIOUS, larval_child,
					"unsupported IPCOMP compression algorithm %d",
					n_ipcomp.ikev2_notify_ipcomp_trans); /* enum_name this later */
				return v2N_NO_PROPOSAL_CHOSEN;
			}

			if (n_ipcomp.ikev2_cpi < IPCOMP_FIRST_NEGOTIATED) {
				llog_sa(RC_LOG_SERIOUS, larval_child,
					"illegal IPCOMP CPI %d", n_ipcomp.ikev2_cpi);
				return v2N_NO_PROPOSAL_CHOSEN;
			}

			dbg("received v2N_IPCOMP_SUPPORTED with compression CPI=%d", htonl(n_ipcomp.ikev2_cpi));
			//child->sa.st_ipcomp.outbound.spi = uniquify_peer_cpi((ipsec_spi_t)htonl(n_ipcomp.ikev2_cpi), cst, 0);
			larval_child->sa.st_ipcomp.outbound.spi = htonl((ipsec_spi_t)n_ipcomp.ikev2_cpi);
			larval_child->sa.st_ipcomp.attrs.transattrs.ta_ipcomp = ikev2_get_ipcomp_desc(n_ipcomp.ikev2_notify_ipcomp_trans);
			larval_child->sa.st_ipcomp.attrs.mode = encapsulation_mode;
			larval_child->sa.st_ipcomp.inbound.last_used = monotime_from_threadtime(request_md->md_inception);
			larval_child->sa.st_ipcomp.outbound.last_used = monotime_from_threadtime(request_md->md_inception);

			larval_child->sa.st_ipcomp.present = true;
			/* logic above decided to enable IPCOMP */
			if (!compute_v2_child_ipcomp_cpi(larval_child)) {
				return v2N_INVALID_SYNTAX; /* something fatal */
			}
		}
	} else if (expecting_compression) {
		dbg("policy suggested compression, but peer did not offer support");
	}

	if (request_md->pd[PD_v2N_ESP_TFC_PADDING_NOT_SUPPORTED] != NULL) {
		dbg("received ESP_TFC_PADDING_NOT_SUPPORTED");
		larval_child->sa.st_seen_no_tfc = true;
	}

	ikev2_derive_child_keys(ike, larval_child);

	/*
	 * Check to see if we need to release an old instance
	 * Note that this will call delete on the old
	 * connection we should do this after installing
	 * ipsec_sa, but that will give us a "eroute in use"
	 * error.
	 */
#ifdef USE_XFRM_INTERFACE
	if (cc->xfrmi != NULL && cc->xfrmi->if_id != 0) {
		if (!add_xfrm_interface(cc, larval_child->sa.st_logger)) {
			return v2N_INVALID_SYNTAX; /* fatal */
		}
	}
#endif

	/* install inbound and outbound SPI info */
	if (!install_ipsec_sa(&larval_child->sa, true)) {
		/* already logged */
		return v2N_TS_UNACCEPTABLE;
	}

	/*
	 * Mark that the connection has an established Child SA
	 * associated with it.
	 *
	 * (The IKE SA's connection may not be the same as the Child
	 * SAs connection).
	 */
	pexpect(ike->sa.st_connection->newest_ike_sa == ike->sa.st_serialno);
	set_newest_v2_child_sa(__func__, larval_child); /* process_v2_CREATE_CHILD_SA_request_continue_2() */

	/*
	 * Should this save SK_PBS so that, when the emit fails,
	 * partial output can be discarded?
	 */
	if (!emit_v2_child_response_payloads(ike, larval_child, request_md, sk_pbs)) {
		return v2N_INVALID_SYNTAX; /* something fatal to IKE (but bogus) */
	}

	/*
	 * XXX: fudge a state transition.
	 *
	 * Code extracted and simplified from
	 * success_v2_state_transition(); suspect very similar code
	 * will appear in the initiator.
	 */
	v2_child_sa_established(ike, larval_child);

	return v2N_NOTHING_WRONG;
}

bool emit_v2_child_response_payloads(struct ike_sa *ike,
				     const struct child_sa *larval_child,
				     const struct msg_digest *request_md,
				     struct pbs_out *outpbs)
{
	pexpect(larval_child->sa.st_establishing_sa == IPSEC_SA); /* never grow up */
	enum isakmp_xchg_type isa_xchg = request_md->hdr.isa_xchg;
	struct connection *cc = larval_child->sa.st_connection;

	if (request_md->chain[ISAKMP_NEXT_v2CP] != NULL) {
		if (nr_child_leases(cc->remote) > 0) {
			if (!emit_v2CP_response(larval_child, outpbs)) {
				return false;
			}
		} else {
			dbg("#%lu %s ignoring unexpected v2CP payload",
			    larval_child->sa.st_serialno, larval_child->sa.st_state->name);
		}
	}

	/* start of SA out */
	{
		/* ??? this code won't support AH + ESP */
		const struct ipsec_proto_info *proto_info = ikev2_child_sa_proto_info(larval_child);
		shunk_t local_spi = THING_AS_SHUNK(proto_info->inbound.spi);
		if (!ikev2_emit_sa_proposal(outpbs,
					    larval_child->sa.st_v2_accepted_proposal,
					    local_spi)) {
			dbg("problem emitting accepted proposal");
			return false;
		}
	}

	if (isa_xchg == ISAKMP_v2_CREATE_CHILD_SA) {
		/* send NONCE */
		struct ikev2_generic in = {
			.isag_critical = build_ikev2_critical(false, ike->sa.st_logger),
		};
		pb_stream pb_nr;

		if (!pbs_out_struct(outpbs, &ikev2_nonce_desc, &in, sizeof(in), &pb_nr)) {
			/* already logged */
			return false; /*fatal*/
		}

		if (!pbs_out_hunk(&pb_nr, larval_child->sa.st_nr, "IKEv2 nonce")) {
			/* already logged */
			return false;
		}

		close_output_pbs(&pb_nr);

		/*
		 * XXX: shouldn't this be conditional on the local end
		 * having computed KE and not what the remote sent?
		 */
		if (request_md->chain[ISAKMP_NEXT_v2KE] != NULL &&
		    !emit_v2KE(larval_child->sa.st_gr, larval_child->sa.st_oakley.ta_dh, outpbs)) {
			return false;
		}
	}

	/*
	 * XXX: see above notes on 'role' - this must be the
	 * SA_RESPONDER.
	 */
	if (!emit_v2TS_response_payloads(outpbs, larval_child)) {
		return false;
	}

	if (larval_child->sa.st_seen_and_use_transport_mode &&
	    !emit_v2N(v2N_USE_TRANSPORT_MODE, outpbs)) {
		return false;
	}

	if (cc->config->send_no_esp_tfc &&
	    !emit_v2N(v2N_ESP_TFC_PADDING_NOT_SUPPORTED, outpbs)) {
			return false;
	}

	if (larval_child->sa.st_ipcomp.present &&
	    !emit_v2N_ipcomp_supported(larval_child, outpbs)) {
		return false;
	}

	return true;
}

v2_notification_t process_v2_childs_sa_payload(const char *what,
					       struct ike_sa *ike UNUSED,
					       struct child_sa *child,
					       struct msg_digest *md,
					       const struct ikev2_proposals *child_proposals,
					       bool expect_accepted_proposal)
{
	struct connection *c = child->sa.st_connection;
	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_v2SA];
	enum isakmp_xchg_type isa_xchg = md->hdr.isa_xchg;
	struct ipsec_proto_info *proto_info = ikev2_child_sa_proto_info(child);
	v2_notification_t n;

	n = ikev2_process_sa_payload(what,
				     &sa_pd->pbs,
				     /*expect_ike*/ false,
				     /*expect_spi*/ true,
				     expect_accepted_proposal,
				     LIN(POLICY_OPPORTUNISTIC, c->policy),
				     &child->sa.st_v2_accepted_proposal,
				     child_proposals, child->sa.st_logger);
	if (n != v2N_NOTHING_WRONG) {
		llog_sa(RC_LOG_SERIOUS, child,
			"%s failed, responder SA processing returned %s",
			what, enum_name_short(&v2_notification_names, n));
		return n;
	}

	if (DBGP(DBG_BASE)) {
		DBG_log_ikev2_proposal(what, child->sa.st_v2_accepted_proposal);
	}
	if (!ikev2_proposal_to_proto_info(child->sa.st_v2_accepted_proposal, proto_info,
					  monotime_from_threadtime(md->md_inception),
					  child->sa.st_logger)) {
		llog_sa(RC_LOG_SERIOUS, child,
			"%s proposed/accepted a proposal we don't actually support!", what);
		return v2N_NO_PROPOSAL_CHOSEN; /* lie */
	}

	/*
	 * Update/check the PFS.
	 *
	 * For the responder, go with what ever was negotiated.  For
	 * the initiator, check what was negotiated against what was
	 * sent.
	 *
	 * Because code expects .st_pfs_group to use NULL, and not
	 * &ike_alg_dh_none, to indicate no-DH algorithm, the value
	 * returned by the proposal parser needs to be patched up.
	 */
	const struct dh_desc *accepted_dh =
		proto_info->attrs.transattrs.ta_dh == &ike_alg_dh_none ? NULL
		: proto_info->attrs.transattrs.ta_dh;
	switch (child->sa.st_sa_role) {
	case SA_INITIATOR:
		pexpect(expect_accepted_proposal);
		if (accepted_dh != NULL && accepted_dh != child->sa.st_pfs_group) {
			llog_sa(RC_LOG_SERIOUS, child,
				"expecting %s but remote's accepted proposal includes %s",
				child->sa.st_pfs_group == NULL ? "no DH" : child->sa.st_pfs_group->common.fqn,
				accepted_dh->common.fqn);
			return v2N_NO_PROPOSAL_CHOSEN;
		}
		child->sa.st_pfs_group = accepted_dh;
		break;
	case SA_RESPONDER:
		pexpect(!expect_accepted_proposal);
		pexpect(child->sa.st_sa_role == SA_RESPONDER);
		pexpect(child->sa.st_pfs_group == NULL);
		child->sa.st_pfs_group = accepted_dh;
		break;
	default:
		bad_case(child->sa.st_sa_role);
	}

	/*
	 * Update the state's st_oakley parameters from the proposal,
	 * but retain the previous PRF.  A CHILD_SA always uses the
	 * PRF negotiated when creating initial IKE SA.
	 *
	 * XXX: The mystery is, why is .st_oakley even being updated?
	 * Perhaps it is to prop up code getting the CHILD_SA's PRF
	 * from the child when that code should use the CHILD_SA's IKE
	 * SA; or perhaps it is getting things ready for an IKE SA
	 * re-key?
	 */
	if (isa_xchg == ISAKMP_v2_CREATE_CHILD_SA && child->sa.st_pfs_group != NULL) {
		dbg("updating #%lu's .st_oakley with preserved PRF, but why update?",
			child->sa.st_serialno);
		struct trans_attrs accepted_oakley = proto_info->attrs.transattrs;
		pexpect(accepted_oakley.ta_prf == NULL);
		accepted_oakley.ta_prf = child->sa.st_oakley.ta_prf;
		child->sa.st_oakley = accepted_oakley;
	}

	return v2N_NOTHING_WRONG;
}

static void jam_end_selector(struct jambuf *buf, ip_selector s)
{
	const struct ip_protocol *proto = selector_protocol(s);
	const ip_range r = selector_range(s);
	jam_string(buf, "[");
	jam_range(buf, &r);
	jam_string(buf, ":");
	if (s.hport == 0) {
		jam_string(buf, "0-65535");
	} else {
		jam(buf, "%d-%d", s.hport, s.hport);
	}
	jam(buf, " %d", proto->ipproto);
	jam_string(buf, "]");
}

void llog_v2_child_sa_established(struct ike_sa *ike UNUSED, struct child_sa *child)
{
	struct connection *c = child->sa.st_connection;
	LLOG_JAMBUF(RC_SUCCESS, child->sa.st_logger, buf) {
		switch (child->sa.st_sa_role) {
		case SA_INITIATOR: jam_string(buf, "initiator"); break;
		case SA_RESPONDER: jam_string(buf, "responder"); break;
		}
		if (child->sa.st_v2_rekey_pred == SOS_NOBODY) {
			jam(buf, " established Child SA");
		} else {
			jam(buf, " rekeyed Child SA "PRI_SO"",
			    pri_so(child->sa.st_v2_rekey_pred));
		}
		jam(buf, " using "PRI_SO"; ", pri_so(child->sa.st_clonedfrom));
		/* log Child SA Traffic Selector details for admin's pleasure */
		jam(buf, "IPsec %s", (c->policy & POLICY_TUNNEL ? "tunnel" : "transport"));
		FOR_EACH_ITEM(spd, &c->child.spds) {
			jam_string(buf, " ");
			if (connection_requires_tss(c) == NULL) {
				jam_end_selector(buf, spd->local->client);
				jam_string(buf, " -> ");
				jam_end_selector(buf, spd->remote->client);
			} else {
				jam_string(buf, "[");
				jam_selector_pair(buf, &spd->local->client,
						  &spd->remote->client);
				jam_string(buf, "]");
			}
		}
		jam_string(buf, " ");
		jam_child_sa_details(buf, &child->sa);
	}
}

/*
 * This is called by:
 *
 * - IKE_AUTH responder
 * - IKE_AUTH initiator
 * - CREATE_CHILD_SA responder
 *
 * but NOT by the CREATE_CHILD_SA initiator.
 *
 * Why?
 *
 * Because the CREATE_CHILD_SA initiator still switches from the IKE
 * to Child SA and then lets sucess_v2_state_transition() performs the
 * below.
 *
 * Ulgh.
 */

void v2_child_sa_established(struct ike_sa *ike, struct child_sa *child)
{
	pexpect(child->sa.st_v2_transition->next_state == STATE_V2_ESTABLISHED_CHILD_SA);
	change_v2_state(&child->sa);

	pstat_sa_established(&child->sa);

	llog_v2_child_sa_established(ike, child);

	schedule_v2_replace_event(&child->sa);

	/*
	 * start liveness checks if set, making sure we only schedule
	 * once when moving from I2->I3 or R1->R2
	 */
	if (dpd_active_locally(child->sa.st_connection)) {
		dbg("dpd enabled, scheduling ikev2 liveness checks");
		deltatime_t delay = deltatime_max(child->sa.st_connection->config->dpd.delay,
						  deltatime(MIN_LIVENESS));
		event_schedule(EVENT_v2_LIVENESS, delay, &child->sa);
	}

	connection_buf cb;
	dbg("unpending IKE SA #%lu CHILD SA #%lu connection "PRI_CONNECTION,
	    ike->sa.st_serialno, child->sa.st_serialno,
	    pri_connection(child->sa.st_connection, &cb));
	unpend(ike, child->sa.st_connection);
}

v2_notification_t process_v2_child_response_payloads(struct ike_sa *ike, struct child_sa *child,
						     struct msg_digest *md)
{
	struct connection *c = child->sa.st_connection;

	if (!process_v2TS_response_payloads(child, md)) {
		return v2N_TS_UNACCEPTABLE;
	}

	/*
	 * examine notification payloads for Child SA errors
	 * (presumably any error reaching this point is for the
	 * child?).
	 *
	 * https://tools.ietf.org/html/rfc7296#section-3.10.1
	 *
	 *   Types in the range 0 - 16383 are intended for reporting
	 *   errors.  An implementation receiving a Notify payload
	 *   with one of these types that it does not recognize in a
	 *   response MUST assume that the corresponding request has
	 *   failed entirely.  Unrecognized error types in a request
	 *   and status types in a request or response MUST be
	 *   ignored, and they should be logged.
	 */
	if (md->v2N_error != v2N_NOTHING_WRONG) {
		esb_buf esb;
		llog_sa(RC_LOG_SERIOUS, child, "received ERROR NOTIFY (%d): %s ",
			  md->v2N_error,
			  enum_show(&v2_notification_names, md->v2N_error, &esb));
		return md->v2N_error;
	}

	/* check for Child SA related NOTIFY payloads */
	enum encapsulation_mode encapsulation_mode = ENCAPSULATION_MODE_TUNNEL;
	if (md->pd[PD_v2N_USE_TRANSPORT_MODE] != NULL) {
		if (c->policy & POLICY_TUNNEL) {
			/*
			 * This means we did not send
			 * v2N_USE_TRANSPORT, however responder is
			 * sending it in now, seems incorrect
			 */
			dbg("Initiator policy is tunnel, responder sends v2N_USE_TRANSPORT_MODE notification in inR2, ignoring it");
		} else {
			dbg("Initiator policy is transport, responder sends v2N_USE_TRANSPORT_MODE, setting CHILD SA to transport mode");
			encapsulation_mode = ENCAPSULATION_MODE_TRANSPORT;
			if (child->sa.st_esp.present) {
				child->sa.st_esp.attrs.mode = encapsulation_mode;
			}
			if (child->sa.st_ah.present) {
				child->sa.st_ah.attrs.mode = encapsulation_mode;
			}
		}
	}
	child->sa.st_seen_no_tfc = md->pd[PD_v2N_ESP_TFC_PADDING_NOT_SUPPORTED] != NULL;
	if (md->pd[PD_v2N_IPCOMP_SUPPORTED] != NULL) {
		struct pbs_in pbs = md->pd[PD_v2N_IPCOMP_SUPPORTED]->pbs;
		size_t len = pbs_left(&pbs);
		struct ikev2_notify_ipcomp_data n_ipcomp;

		dbg("received v2N_IPCOMP_SUPPORTED of length %zd", len);
		if ((c->policy & POLICY_COMPRESS) == LEMPTY) {
			llog_sa(RC_LOG_SERIOUS, child,
				  "Unexpected IPCOMP request as our connection policy did not indicate support for it");
			return v2N_NO_PROPOSAL_CHOSEN;
		}

		diag_t d = pbs_in_struct(&pbs, &ikev2notify_ipcomp_data_desc,
					 &n_ipcomp, sizeof(n_ipcomp), NULL);
		if (d != NULL) {
			llog_diag(RC_LOG, child->sa.st_logger, &d, "%s", "");
			return v2N_INVALID_SYNTAX; /* fatal */
		}

		if (n_ipcomp.ikev2_notify_ipcomp_trans != IPCOMP_DEFLATE) {
			llog_sa(RC_LOG_SERIOUS, child,
				  "Unsupported IPCOMP compression method %d",
			       n_ipcomp.ikev2_notify_ipcomp_trans); /* enum_name this later */
			return v2N_INVALID_SYNTAX; /* fatal */
		}

		if (n_ipcomp.ikev2_cpi < IPCOMP_FIRST_NEGOTIATED) {
			llog_sa(RC_LOG_SERIOUS, child,
				  "Illegal IPCOMP CPI %d", n_ipcomp.ikev2_cpi);
			return v2N_INVALID_SYNTAX; /* fatal */
		}
		dbg("Received compression CPI=%d", n_ipcomp.ikev2_cpi);

		//child->sa.st_ipcomp.outbound.spi = uniquify_peer_cpi((ipsec_spi_t)htonl(n_ipcomp.ikev2_cpi), st, 0);
		child->sa.st_ipcomp.outbound.spi = htonl((ipsec_spi_t)n_ipcomp.ikev2_cpi);
		child->sa.st_ipcomp.attrs.transattrs.ta_ipcomp =
			ikev2_get_ipcomp_desc(n_ipcomp.ikev2_notify_ipcomp_trans);
		child->sa.st_ipcomp.attrs.mode = encapsulation_mode;
		child->sa.st_ipcomp.inbound.last_used = monotime_from_threadtime(md->md_inception);
		child->sa.st_ipcomp.outbound.last_used = monotime_from_threadtime(md->md_inception);
		child->sa.st_ipcomp.present = true;
	}

	ikev2_derive_child_keys(ike, child);

#ifdef USE_XFRM_INTERFACE
	/* before calling do_command() */
	if (child->sa.st_state->kind != STATE_V2_REKEY_CHILD_I1)
		if (c->xfrmi != NULL &&
				c->xfrmi->if_id != 0)
			if (!add_xfrm_interface(c, child->sa.st_logger))
				return v2N_INVALID_SYNTAX; /* fatal */
#endif
	/* now install child SAs */
	if (!install_ipsec_sa(&child->sa, true))
		/* This affects/kills the IKE SA? Oops :-( */
		return v2N_INVALID_SYNTAX; /* fatal */

	set_newest_v2_child_sa(__func__, child); /* process_v2_child_response_payloads() */

	if (child->sa.st_state->kind == STATE_V2_REKEY_CHILD_I1)
		ikev2_rekey_expire_predecessor(child, child->sa.st_v2_rekey_pred);

	return v2N_NOTHING_WRONG;
}

/*
 * Try to create child in .wip_sa.  Return NOTHING_WRONG, non-fatal,
 * or fatal notification.  Caller will handle notifies and child
 * cleanup.
 */

static v2_notification_t process_v2_IKE_AUTH_request_child_sa_payloads(struct ike_sa *ike,
								       struct msg_digest *md,
								       struct pbs_out *sk_pbs)
{
	v2_notification_t n;

	if (impair.omit_v2_ike_auth_child) {
		/* only omit when missing */
		if (has_v2_IKE_AUTH_child_sa_payloads(md)) {
			llog_pexpect(ike->sa.st_logger, HERE,
				     "IMPAIR: IKE_AUTH request should have omitted CHILD SA payloads");
			return v2N_INVALID_SYNTAX; /* fatal */
		}
		llog_sa(RC_LOG, ike, "IMPAIR: as expected, IKE_AUTH request omitted CHILD SA payloads");
		return v2N_NOTHING_WRONG;
	}

	if (impair.ignore_v2_ike_auth_child) {
		/* try to ignore the child */
		if (!has_v2_IKE_AUTH_child_sa_payloads(md)) {
			llog_pexpect(ike->sa.st_logger, HERE,
				     "IMPAIR: IKE_AUTH request should have included CHILD_SA payloads");
			return v2N_INVALID_SYNTAX; /* fatal */
		}
		llog_sa(RC_LOG, ike, "IMPAIR: as expected, IKE_AUTH request included CHILD SA payloads; ignoring them");
		return v2N_NOTHING_WRONG;
	}

	/* try to process them */
	if (!has_v2_IKE_AUTH_child_sa_payloads(md)) {
		llog_sa(RC_LOG, ike, "IKE_AUTH request does not propose a Child SA; creating childless SA");
		/* caller will send notification, if needed */
		return v2N_NOTHING_WRONG;
	}

	/*
	 * There's enough to build a Child SA.  Save it in .WIP_SA, if
	 * this function fails call will clean it up.
	 */

	struct child_sa *child =
		ike->sa.st_v2_msgid_windows.responder.wip_sa =
		new_v2_child_sa(ike->sa.st_connection, ike,
				IPSEC_SA, SA_RESPONDER,
				STATE_V2_IKE_AUTH_CHILD_R0,
				null_fd);

	/*
	 * Parse the CP payloads if needed (need child so that rants
	 * can be logged against child).
	 *
	 * 2.19.  Requesting an Internal Address on a Remote Network
	 *
	 * When is CP allowed?
	 *
	 *   A request for such a temporary address can be included in
	 *   any request to create a Child SA (including the implicit
	 *   request in message 3) by including a CP payload.
	 *
	 * i.e., a childless IKE_AUTH exchange must not have CP
	 * payload and, hence, this code comes after above check for
	 * Child SA payloads.
	 *
	 * When is CP required?
	 *
	 *   In the case where the IRAS's [IPsec Remote Access Server]
	 *   configuration requires that CP be used for a given
	 *   identity IDi, but IRAC has failed to send a
	 *   CP(CFG_REQUEST), IRAS MUST fail the request, and
	 *   terminate the Child SA creation with a FAILED_CP_REQUIRED
	 *   error.
	 *
	 * The IKE SA's authenticated so IDi has been confirmed for
	 * the connection.  So lets boldly assume that the IKE's
	 * modecfg.server (also set when peer has an addresspool)
	 * implies IRAS.
	 *
	 * Why is all this ignored?
	 *
	 * OE defines client connections but then expects them to
	 * behave like a server when the peer is the one initiating.
	 */

	pexpect(ike->sa.st_connection == child->sa.st_connection);
	const struct host_end_config *local = ike->sa.st_connection->local->host.config;
	const struct host_end_config *remote = ike->sa.st_connection->remote->host.config;
	const struct ip_info *pool_afi =
		(child->sa.st_connection->pool[IPv4_INDEX] != NULL ? &ipv4_info :
		 child->sa.st_connection->pool[IPv6_INDEX] != NULL ? &ipv6_info :
		 NULL);
	bool oe_server = ((ike->sa.st_connection->policy & POLICY_OPPORTUNISTIC) &&
			  md->chain[ISAKMP_NEXT_v2CP] != NULL && pool_afi != NULL);

	dbg("oe_server=%s; local: %s client=%s, server=%s; remote: %s client=%s, server=%s",
	    bool_str(oe_server),
	    /**/
	    local->leftright, bool_str(local->modecfg.client), bool_str(local->modecfg.server),
	    /**/
	    remote->leftright, bool_str(remote->modecfg.client), bool_str(remote->modecfg.server));

	if (local->modecfg.server) {
		if (md->chain[ISAKMP_NEXT_v2CP] == NULL) {
			llog_sa(RC_LOG, ike,
				"IKE_AUTH request does not include a CP payload required by %smodecfgserver=true; Child SA ignored",
				local->leftright);
			/* just logged; caller, below, cleans up */
			return v2N_FAILED_CP_REQUIRED;
		}
		if (!process_v2_IKE_AUTH_request_v2CP_request_payload(ike, child, md->chain[ISAKMP_NEXT_v2CP])) {
			/* already logged; caller, below, cleans up */
			return v2N_INTERNAL_ADDRESS_FAILURE;
		}
	}

	/*
	 * Process TS (but only when there's no CP); what woh no way!
	 *
	 * The CP payload's result should be checked against the TS
	 * payload except libreswan will change connection based on
	 * the TS content which can cause a connection to steal
	 * another connection's lease.
	 *
	 * Clearly a bug.
	 */
	if (connection_requires_tss(child->sa.st_connection) != NULL ||
	    !local->modecfg.server) {
		/*
		 * Danger! This TS call can change the child's
		 * connection.
		 */
		if (!process_v2TS_request_payloads(child, md)) {
			/* already logged; caller, below, cleans up */
			return v2N_TS_UNACCEPTABLE;
		}
	} else {
		ldbg_sa(child, "skipping TS processing, mainly to stop tests failing but rumored to cause connection flips?!?");
	}

	n = process_v2_childs_sa_payload("IKE_AUTH responder matching remote ESP/AH proposals",
					 ike, child, md,
					 child->sa.st_connection->config->v2_ike_auth_child_proposals,
					 /*expect-accepted-proposal?*/false);
	dbg("process_v2_childs_sa_payload returned %s", enum_name(&v2_notification_names, n));
	if (n != v2N_NOTHING_WRONG) {
		/* already logged; caller, below, cleans up */
		return n;
	}

	n = process_v2_child_request_payloads(ike, child, md, sk_pbs);
	if (n != v2N_NOTHING_WRONG) {
		/* already logged; caller, below, cleans up */
		return n;
	}

	return v2N_NOTHING_WRONG;
}

/*
 * When required, create a Child SA.
 *
 * Returning FALSE means major SNAFU and caller should abort
 * connection; reply, if any, will already be recorded.
 */

bool process_any_v2_IKE_AUTH_request_child_sa_payloads(struct ike_sa *ike,
						       struct msg_digest *md,
						       struct pbs_out *sk_pbs)
{
	pexpect(ike->sa.st_v2_msgid_windows.responder.wip_sa == NULL);
	v2_notification_t cn = process_v2_IKE_AUTH_request_child_sa_payloads(ike, md, sk_pbs);
	if (cn != v2N_NOTHING_WRONG) {
		/* XXX: add delete_any_child_sa()? */
		if (ike->sa.st_v2_msgid_windows.responder.wip_sa != NULL) {
			delete_state(&ike->sa.st_v2_msgid_windows.responder.wip_sa->sa);
			ike->sa.st_v2_msgid_windows.responder.wip_sa = NULL;
		}
		if (v2_notification_fatal(cn)) {
			record_v2N_response(ike->sa.st_logger, ike, md,
					    cn, NULL/*no-data*/,
					    ENCRYPTED_PAYLOAD);
			return false;
		}
		emit_v2N(cn, sk_pbs);
	}
	ike->sa.st_v2_msgid_windows.responder.wip_sa = NULL; /* all done */
	return true;
}

v2_notification_t process_v2_IKE_AUTH_response_child_sa_payloads(struct ike_sa *ike,
								 struct msg_digest *response_md)
{
	v2_notification_t n;

	if (impair.ignore_v2_ike_auth_child) {
		/* Try to ignore the CHILD SA payloads. */
		if (!has_v2_IKE_AUTH_child_sa_payloads(response_md)) {
			llog_pexpect(ike->sa.st_logger, HERE,
				     "IMPAIR: IKE_AUTH response should have included CHILD SA payloads");
			return v2N_INVALID_SYNTAX; /* fatal */
		}
		llog_sa(RC_LOG, ike,
			"IMPAIR: as expected, IKE_AUTH response includes CHILD SA payloads; ignoring them");
		return v2N_NOTHING_WRONG;
	}

	if (impair.omit_v2_ike_auth_child) {
		/* Try to ignore missing CHILD SA payloads. */
		if (has_v2_IKE_AUTH_child_sa_payloads(response_md)) {
			llog_pexpect(ike->sa.st_logger, HERE,
				     "IMPAIR: IKE_AUTH response should have omitted CHILD SA payloads");
			return v2N_INVALID_SYNTAX; /* fatal */
		}
		llog_sa(RC_LOG, ike, "IMPAIR: as expected, IKE_AUTH response omitted CHILD SA payloads");
		return v2N_NOTHING_WRONG;
	}

	struct child_sa *child = ike->sa.st_v2_msgid_windows.initiator.wip_sa;
	if (child == NULL) {
		/*
		 * Did the responder send Child SA payloads this end
		 * didn't ask for?
		 */
		if (has_v2_IKE_AUTH_child_sa_payloads(response_md)) {
			llog_sa(RC_LOG_SERIOUS, ike,
				"IKE_AUTH response contains v2SA, v2TSi or v2TSr: but a CHILD SA was not requested!");
			return v2N_INVALID_SYNTAX; /* fatal */
		}
		dbg("IKE SA #%lu has no and expects no CHILD SA", ike->sa.st_serialno);
		return v2N_NOTHING_WRONG;
	}

	/*
	 * Was there a child error notification?  The RFC says this
	 * list isn't definitive.
	 *
	 * XXX: can this code assume that the response contains only
	 * one notify and that is for the child?  Given notifies are
	 * used to communicate compression I've my doubt.
	 */
	FOR_EACH_THING(pd, PD_v2N_NO_PROPOSAL_CHOSEN, PD_v2N_TS_UNACCEPTABLE,
		       PD_v2N_SINGLE_PAIR_REQUIRED, PD_v2N_INTERNAL_ADDRESS_FAILURE,
		       PD_v2N_FAILED_CP_REQUIRED) {
		if (response_md->pd[pd] != NULL) {
			/* convert PD to N */
			v2_notification_t n = response_md->pd[pd]->payload.v2n.isan_type;
			/*
			 * Log something the testsuite expects for
			 * now.  It provides an anchor when looking at
			 * test changes.
			 */
			enum_buf esb;
			llog_sa(RC_LOG_SERIOUS, child,
				"IKE_AUTH response rejected Child SA with %s",
				str_enum_short(&v2_notification_names, n, &esb));
			connection_buf cb;
			dbg("unpending IKE SA #%lu CHILD SA #%lu connection "PRI_CONNECTION,
			    ike->sa.st_serialno, child->sa.st_serialno,
			    pri_connection(child->sa.st_connection, &cb));
			unpend(ike, child->sa.st_connection);
			delete_state(&child->sa);
			ike->sa.st_v2_msgid_windows.initiator.wip_sa = child = NULL;
			/* handled */
			return v2N_NOTHING_WRONG;
		}
	}

	/*
	 * XXX: remote approved the Child SA; now check that what was
	 * approved is acceptable to this local end.  If it isn't
	 * return a notification.
	 *
	 * Code should be initiating a new exchange that contains the
	 * notification; later.
	 */

	/* Expect CHILD SA payloads. */
	if (!has_v2_IKE_AUTH_child_sa_payloads(response_md)) {
		llog_sa(RC_LOG_SERIOUS, child,
			"IKE_AUTH response missing v2SA, v2TSi or v2TSr: not attempting to setup CHILD SA");
		return v2N_TS_UNACCEPTABLE;
	}

	child->sa.st_ikev2_anon = ike->sa.st_ikev2_anon; /* was set after duplicate_state() (?!?) */
	child->sa.st_seen_no_tfc = response_md->pd[PD_v2N_ESP_TFC_PADDING_NOT_SUPPORTED] != NULL;

	/* AUTH is ok, we can trust the notify payloads */
	if (response_md->pd[PD_v2N_USE_TRANSPORT_MODE] != NULL) {
		/* FIXME: use new RFC logic turning this into a request, not requirement */
		if (LIN(POLICY_TUNNEL, child->sa.st_connection->policy)) {
			llog_sa(RC_LOG_SERIOUS, child,
				  "local policy requires Tunnel Mode but peer requires required Transport Mode");
			return v2N_TS_UNACCEPTABLE;
		}
	} else {
		if (!LIN(POLICY_TUNNEL, child->sa.st_connection->policy)) {
			llog_sa(RC_LOG_SERIOUS, child,
				  "local policy requires Transport Mode but peer requires required Tunnel Mode");
			return v2N_TS_UNACCEPTABLE;
		}
	}

	/* examine and accept SA ESP/AH proposals */

	n = process_v2_childs_sa_payload("IKE_AUTH initiator accepting remote ESP/AH proposal",
					 ike, child, response_md,
					 child->sa.st_connection->config->v2_ike_auth_child_proposals,
					 /*expect-accepted-proposal?*/true);
	if (n != v2N_NOTHING_WRONG) {
		return n;
	}

	/*
	 * IP parameters on rekey MUST be identical, so CP payloads
	 * not needed.
	 */
	if (expect_v2CP_response(child->sa.st_connection, ike->sa.hidden_variables.st_nat_traversal)) {
		if (response_md->chain[ISAKMP_NEXT_v2CP] == NULL) {
			/*
			 * not really anything to here... but it would
			 * be worth unpending again.
			 */
			llog_sa(RC_LOG_SERIOUS, child,
				  "missing v2CP reply, not attempting to setup child SA");
			return v2N_TS_UNACCEPTABLE;
		}
		if (!process_v2CP_response_payload(ike, child, response_md->chain[ISAKMP_NEXT_v2CP])) {
			return v2N_TS_UNACCEPTABLE;
		}
	}

	n = process_v2_child_response_payloads(ike, child, response_md);
	if (n != v2N_NOTHING_WRONG) {
		if (v2_notification_fatal(n)) {
			llog_sa(RC_LOG_SERIOUS, child,
				"CHILD SA encountered fatal error: %s",
				enum_name_short(&v2_notification_names, n));
		} else {
			llog_sa(RC_LOG_SERIOUS, child,
				"CHILD SA failed: %s",
				enum_name_short(&v2_notification_names, n));
		}
		return n;
	}

	/*
	 * XXX: fudge a state transition.
	 *
	 * Code extracted and simplified from
	 * success_v2_state_transition(); suspect very similar code
	 * will appear in the responder.
	 */
	v2_child_sa_established(ike, child);
	/* hack; cover all bases; handled by close any whacks? */
	release_whack(child->sa.st_logger, HERE);

	return v2N_NOTHING_WRONG;
}
