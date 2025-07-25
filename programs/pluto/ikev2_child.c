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
#include "addresspool.h"
#include "rnd.h"
#include "ip_address.h"
#include "ikev2_send.h"
#include "ikev2_message.h"
#include "ikev2_ts.h"
#include "ip_info.h"
#include "ipsec_interface.h"
#include "ikev2_cp.h"
#include "ikev2_child.h"
#include "ike_alg_dh.h"
#include "pluto_stats.h"
#include "pending.h"
#include "kernel.h"			/* for get_my_cpi() hack */
#include "ikev2_proposals.h"
#include "ikev2_parent.h"
#include "ikev2_states.h"
#include "ikev2_notification.h"
#include "iface.h"
#include "nat_traversal.h"

static bool emit_v2_child_response_payloads(struct ike_sa *ike,
					    const struct child_sa *child,
					    const struct msg_digest *request_md,
					    struct pbs_out *outpbs);

/*
 * Drive the larval Child SA's state machine.
 */

void set_larval_v2_transition(struct child_sa *larval,
			      const struct finite_state *to,
			      where_t where)
{
	const struct v2_transition *transition =
		larval->sa.st_state->v2.child_transition;
	PASSERT_WHERE(larval->sa.logger, where, transition != NULL);
	PEXPECT_WHERE(larval->sa.logger, where, larval->sa.st_state != NULL);
	PEXPECT_WHERE(larval->sa.logger, where, larval->sa.st_state->v2.child_transition == transition);
	PEXPECT_WHERE(larval->sa.logger, where, transition->to == to);
	set_v2_transition(&larval->sa, transition, where);
}

/*
 * All payloads required by an IKE_AUTH child?
 */

static bool has_v2_IKE_AUTH_child_payloads(const struct msg_digest *md)
{
	return (md->chain[ISAKMP_NEXT_v2SA] != NULL &&
		md->chain[ISAKMP_NEXT_v2TSi] != NULL &&
		md->chain[ISAKMP_NEXT_v2TSr] != NULL);
}

static bool compute_v2_child_ipcomp_cpi(struct child_sa *larval_child)
{
	struct logger *logger = larval_child->sa.logger;
	const struct connection *cc = larval_child->sa.st_connection;
	PEXPECT(logger, larval_child->sa.st_ipcomp.inbound.spi == 0);
	/* CPI is stored in network low order end of an ipsec_spi_t */
	ipsec_spi_t n_ipcomp_cpi = get_ipsec_cpi(cc, larval_child->sa.logger);
	ipsec_spi_t h_ipcomp_cpi = (uint16_t)ntohl(n_ipcomp_cpi);
	ldbg(logger, "calculated compression CPI=%d", h_ipcomp_cpi);
	if (h_ipcomp_cpi < IPCOMP_FIRST_NEGOTIATED) {
		/* get_my_cpi() failed */
		llog(RC_LOG, logger, "kernel failed to calculate compression CPI (CPI=%d)", h_ipcomp_cpi);
		return false;
	}
	larval_child->sa.st_ipcomp.inbound.spi = n_ipcomp_cpi;
	return true;
}

static bool compute_v2_child_spi(struct child_sa *larval_child)
{
	struct logger *logger = larval_child->sa.logger;
	struct connection *cc = larval_child->sa.st_connection;
	struct ipsec_proto_info *proto_info = ikev2_child_sa_proto_info(larval_child);
	/* hack until esp/ah merged */
	const struct ip_protocol *protocol = NULL;
	if (proto_info == &larval_child->sa.st_esp) {
		protocol = &ip_protocol_esp;
	}
	if (proto_info == &larval_child->sa.st_ah) {
		protocol = &ip_protocol_ah;
	}
	if (PBAD(larval_child->sa.logger, protocol == NULL)) {
		return false;
	}
	/* XXX: should "avoid" be set to the peer's SPI when known? */
	PEXPECT(logger, proto_info->inbound.spi == 0);
	proto_info->inbound.spi = get_ipsec_spi(cc, protocol, 0 /* avoid this # */, logger);
	return (proto_info->inbound.spi != 0);
}

static bool emit_v2N_IPCOMP_SUPPORTED(const struct child_sa *child, struct pbs_out *outs)
{
	struct logger *logger = child->sa.logger;
	ldbg(logger, "initiator child policy is compress=yes, sending v2N_IPCOMP_SUPPORTED for DEFLATE");

	v2_notification_t ntype = v2N_IPCOMP_SUPPORTED;
	if (impair.omit_v2_notification.enabled &&
	    impair.omit_v2_notification.value == ntype) {
		name_buf eb;
		llog(RC_LOG, logger, "IMPAIR: omitting %s notification",
		     str_enum_short(&v2_notification_names, ntype, &eb));
		return true;
	}

	ipsec_spi_t h_cpi = (uint16_t)ntohl(child->sa.st_ipcomp.inbound.spi);
	if (!PEXPECT(logger, h_cpi != 0)) {
		return false;
	}

	struct pbs_out d_pbs;
	if (!open_v2N_output_pbs(outs, ntype, &d_pbs)) {
		return false;
	}

	struct ikev2_notify_ipcomp_data id = {
		.ikev2_cpi = h_cpi, /* packet code expects host byte order */
		.ikev2_notify_ipcomp_trans = IPCOMP_DEFLATE,
	};

	if (!pbs_out_struct(&d_pbs, id, &ikev2notify_ipcomp_data_desc, NULL)) {
		/* already logged */
		return false; /*fatal */
	}

	close_pbs_out(&d_pbs);
	return true;
}

bool prep_v2_child_for_request(struct child_sa *larval_child)
{
	struct connection *cc = larval_child->sa.st_connection;
	if (cc->config->child.ipcomp &&
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
				    bool ike_auth_exchange,
				    struct pbs_out *pbs)
{
	struct logger *logger = larval_child->sa.logger;
	if (!PEXPECT(logger, (larval_child->sa.st_state == &state_v2_NEW_CHILD_I0 ||
			      larval_child->sa.st_state == &state_v2_REKEY_CHILD_I0))) {
		return false;
	}

	if (!PEXPECT(logger, larval_child->sa.st_sa_kind_when_established == CHILD_SA)) {
		return false;
	}

	struct connection *cc = larval_child->sa.st_connection;

	/* SA - security association */

	const struct ipsec_proto_info *proto_info = ikev2_child_sa_proto_info(larval_child);
	shunk_t local_spi = THING_AS_SHUNK(proto_info->inbound.spi);
	if (!emit_v2SA_proposals(pbs, child_proposals, local_spi)) {
		return false;
	}

	/* Ni - only for CREATE_CHILD_SA */

	if (!ike_auth_exchange) {
		struct ikev2_generic in = {
			.isag_critical = build_ikev2_critical(false, logger),
		};
		struct pbs_out pb_nr;
		if (!pbs_out_struct(pbs, in, &ikev2_nonce_desc, &pb_nr)) {
			/* already logged */
			return false; /*fatal*/
		}

		if (!pbs_out_hunk(&pb_nr, larval_child->sa.st_ni, "IKEv2 nonce")) {
			/* already logged */
			return false;
		}
		close_pbs_out(&pb_nr);
	}

	/* KEi - only for CREATE_CHILD_SA; and then only sometimes. */

	if (larval_child->sa.st_pfs_group != NULL &&
	    !emit_v2KE(larval_child->sa.st_gi, larval_child->sa.st_pfs_group, pbs)) {
		return false;
	}

	/* CP[CFG_REQUEST) - only IKE_AUTH exchange for now */

	if (!ike_auth_exchange) {
		ldbg(logger, "skipping CP, not IKE_AUTH request");
	} else if (send_v2CP_request(cc, ike->sa.hidden_variables.st_nated_host)) {
		if (!emit_v2CP_request(larval_child, pbs)) {
			return false;
		}
	}

	/* TS[ir] - traffic selectors */

	if (!emit_v2TS_request_payloads(pbs, larval_child)) {
		return false;
	}

	/* IPCOMP based on policy */

	if (cc->config->child.ipcomp &&
	    !emit_v2N_IPCOMP_SUPPORTED(larval_child, pbs)) {
		return false;
	}

	/* Transport based on policy */

	bool send_use_transport = (cc->config->child.encap_mode == ENCAP_MODE_TRANSPORT);
	ldbg(logger, "initiator child policy is transport mode, sending v2N_USE_TRANSPORT_MODE? %s",
	     bool_str(send_use_transport));
	if (send_use_transport &&
	    !emit_v2N(v2N_USE_TRANSPORT_MODE, pbs)) {
		return false;
	}

	if (!send_use_transport && cc->config->child.iptfs.enabled &&
	    !emit_v2N(v2N_USE_AGGFRAG, pbs)) {
		return false;
	}

	if (cc->config->child.send.esp_tfc_padding_not_supported &&
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
	struct logger *logger = larval_child->sa.logger;
	struct connection *cc = larval_child->sa.st_connection;

	PEXPECT(logger, larval_child->sa.st_v2_accepted_proposal != NULL);

	/*
	 * Verify if transport / tunnel mode matches; update the
	 * proposal as needed.
	 */

	bool transport_mode_accepted =
		accept_v2_notification(v2N_USE_TRANSPORT_MODE, logger, request_md,
				       cc->config->child.encap_mode == ENCAP_MODE_TRANSPORT);

	enum kernel_mode required_mode =
		(cc->config->child.encap_mode == ENCAP_MODE_TRANSPORT ? KERNEL_MODE_TRANSPORT :
		 cc->config->child.encap_mode == ENCAP_MODE_TUNNEL ? KERNEL_MODE_TUNNEL :
		 PEXPECT(logger, 0));
	enum kernel_mode requested_mode =
		(transport_mode_accepted ? KERNEL_MODE_TRANSPORT :
		 KERNEL_MODE_TUNNEL);
	if (required_mode == requested_mode) {
		name_buf mb;
		ldbg_sa(larval_child, "local policy is %s and received matching notify",
			str_enum_long(&kernel_mode_stories, required_mode, &mb));
	} else if (required_mode == KERNEL_MODE_TUNNEL) {
		/*
		 * RFC allows us to ignore their (wrong) request for
		 * transport mode.
		 */
		name_buf dmb, rmb;
		llog_sa(RC_LOG, larval_child,
			"policy dictates %s, ignoring peer's request for %s",
			str_enum_long(&kernel_mode_stories, required_mode, &dmb),
			str_enum_long(&kernel_mode_stories, requested_mode, &rmb));
	} else {
		/* we should have received a matching mode request */
		name_buf dmb, rmb;
		llog_sa(RC_LOG, larval_child,
			"policy dictates %s, but peer requested %s",
			str_enum_long(&kernel_mode_stories, required_mode, &dmb),
			str_enum_long(&kernel_mode_stories, requested_mode, &rmb));
		return v2N_NO_PROPOSAL_CHOSEN;
	}

	larval_child->sa.st_seen_and_use_iptfs =
		accept_v2_notification(v2N_USE_AGGFRAG,
				       larval_child->sa.logger,
				       request_md,
				       cc->config->child.iptfs.enabled);

	larval_child->sa.st_kernel_mode = required_mode;

	if (!compute_v2_child_spi(larval_child)) {
		return v2N_INVALID_SYNTAX;/* something fatal */
	}

	bool expecting_compression = cc->config->child.ipcomp;
	if (request_md->pd[PD_v2N_IPCOMP_SUPPORTED] != NULL) {
		if (!expecting_compression) {
			ldbg(logger, "Ignored IPCOMP request as connection has compress=no");
			PEXPECT(logger, larval_child->sa.st_ipcomp.protocol == NULL);
		} else {
			ldbg(logger, "received v2N_IPCOMP_SUPPORTED");

			struct pbs_in pbs = request_md->pd[PD_v2N_IPCOMP_SUPPORTED]->pbs;
			struct ikev2_notify_ipcomp_data n_ipcomp;
			diag_t d = pbs_in_struct(&pbs, &ikev2notify_ipcomp_data_desc,
						 &n_ipcomp, sizeof(n_ipcomp), NULL);
			if (d != NULL) {
				llog(RC_LOG, larval_child->sa.logger, "%s", str_diag(d));
				pfree_diag(&d);
				return v2N_NO_PROPOSAL_CHOSEN;
			}

			if (n_ipcomp.ikev2_notify_ipcomp_trans != IPCOMP_DEFLATE) {
				llog_sa(RC_LOG, larval_child,
					"unsupported IPCOMP compression algorithm %d",
					n_ipcomp.ikev2_notify_ipcomp_trans); /* enum_name this later */
				return v2N_NO_PROPOSAL_CHOSEN;
			}

			if (n_ipcomp.ikev2_cpi < IPCOMP_FIRST_NEGOTIATED) {
				llog_sa(RC_LOG, larval_child,
					"illegal IPCOMP CPI %d", n_ipcomp.ikev2_cpi);
				return v2N_NO_PROPOSAL_CHOSEN;
			}

			ldbg(logger, "received v2N_IPCOMP_SUPPORTED with compression CPI=%d", htonl(n_ipcomp.ikev2_cpi));
			//child->sa.st_ipcomp.outbound.spi = uniquify_peer_cpi((ipsec_spi_t)htonl(n_ipcomp.ikev2_cpi), cst, 0);
			name_buf ignore;
			larval_child->sa.st_ipcomp.outbound.spi = htonl((ipsec_spi_t)n_ipcomp.ikev2_cpi);
			larval_child->sa.st_ipcomp.trans_attrs.ta_ipcomp =
				ikev2_ipcomp_desc(n_ipcomp.ikev2_notify_ipcomp_trans, &ignore);
			larval_child->sa.st_ipcomp.inbound.last_used =
			larval_child->sa.st_ipcomp.outbound.last_used =
				realnow();

			larval_child->sa.st_ipcomp.protocol = &ip_protocol_ipcomp;
			/* logic above decided to enable IPCOMP */
			if (!compute_v2_child_ipcomp_cpi(larval_child)) {
				return v2N_INVALID_SYNTAX; /* something fatal */
			}
		}
	} else if (expecting_compression) {
		ldbg(logger, "policy suggested compression, but peer did not offer support");
	}

	/* is not not negotiated */
	larval_child->sa.st_seen_esp_tfc_padding_not_supported =
		(request_md->pd[PD_v2N_ESP_TFC_PADDING_NOT_SUPPORTED] != NULL);
	ldbg(larval_child->sa.logger, "received ESP_TFC_PADDING_NOT_SUPPORTED=%s",
	     bool_str(larval_child->sa.st_seen_esp_tfc_padding_not_supported));

	ikev2_derive_child_keys(ike, larval_child);

	/*
	 * Check to see if we need to release an old instance
	 * Note that this will call delete on the old
	 * connection we should do this after installing
	 * ipsec_sa, but that will give us a "eroute in use"
	 * error.
	 */

	/* re-check IKE, child about to be updated */
	PEXPECT(logger, ike->sa.st_connection->established_ike_sa == ike->sa.st_serialno);

	/* install inbound and outbound SPI info */
	if (!connection_establish_child(ike, larval_child, HERE)) {
		/* already logged */
		return v2N_TEMPORARY_FAILURE;
	}

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
	struct logger *logger = larval_child->sa.logger;
	PEXPECT(logger, larval_child->sa.st_sa_kind_when_established == CHILD_SA); /* never grow up */
	enum ikev2_exchange isa_xchg = request_md->hdr.isa_xchg;
	struct connection *cc = larval_child->sa.st_connection;

	if (request_md->chain[ISAKMP_NEXT_v2CP] != NULL) {
		if (nr_child_leases(cc->remote) > 0) {
			if (!emit_v2CP_response(larval_child, outpbs)) {
				return false;
			}
		} else {
			ldbg(larval_child->sa.logger, PRI_SO" %s ignoring unexpected v2CP payload",
			     pri_so(larval_child->sa.st_serialno),
			     larval_child->sa.st_state->name);
		}
	}

	/* start of SA out */
	{
		/* ??? this code won't support AH + ESP */
		const struct ipsec_proto_info *proto_info = ikev2_child_sa_proto_info(larval_child);
		shunk_t local_spi = THING_AS_SHUNK(proto_info->inbound.spi);
		if (!emit_v2SA_proposal(outpbs,
					larval_child->sa.st_v2_accepted_proposal,
					local_spi)) {
			ldbg(logger, "problem emitting accepted proposal");
			return false;
		}
	}

	if (isa_xchg == ISAKMP_v2_CREATE_CHILD_SA) {
		/* send NONCE */
		struct ikev2_generic in = {
			.isag_critical = build_ikev2_critical(false, ike->sa.logger),
		};
		struct pbs_out pb_nr;

		if (!pbs_out_struct(outpbs, in, &ikev2_nonce_desc, &pb_nr)) {
			/* already logged */
			return false; /*fatal*/
		}

		if (!pbs_out_hunk(&pb_nr, larval_child->sa.st_nr, "IKEv2 nonce")) {
			/* already logged */
			return false;
		}

		close_pbs_out(&pb_nr);

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

	if (larval_child->sa.st_kernel_mode == KERNEL_MODE_TRANSPORT &&
	    !emit_v2N(v2N_USE_TRANSPORT_MODE, outpbs)) {
		return false;
	}

	if (larval_child->sa.st_seen_and_use_iptfs &&
	    !emit_v2N(v2N_USE_AGGFRAG, outpbs)) {
		return false;
	}

	if (cc->config->child.send.esp_tfc_padding_not_supported &&
	    !emit_v2N(v2N_ESP_TFC_PADDING_NOT_SUPPORTED, outpbs)) {
		return false;
	}

	if (larval_child->sa.st_ipcomp.protocol == &ip_protocol_ipcomp &&
	    !emit_v2N_IPCOMP_SUPPORTED(larval_child, outpbs)) {
		return false;
	}

	return true;
}

v2_notification_t process_childs_v2SA_payload(const char *what,
					      struct ike_sa *unused_ike UNUSED,
					      struct child_sa *child,
					      struct msg_digest *md,
					      const struct ikev2_proposals *child_proposals,
					      bool expect_accepted_proposal)
{
	struct verbose verbose = VERBOSE(DEBUG_STREAM, child->sa.logger, NULL);

	struct connection *c = child->sa.st_connection;
	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_v2SA];
	enum ikev2_exchange isa_xchg = md->hdr.isa_xchg;
	v2_notification_t n;

	n = process_v2SA_payload(what,
				 &sa_pd->pbs,
				 /*expect_ike*/ false,
				 /*expect_spi*/ true,
				 expect_accepted_proposal,
				 /*limit-logging*/is_opportunistic(c),
				 &child->sa.st_v2_accepted_proposal,
				 child_proposals, verbose);
	if (n != v2N_NOTHING_WRONG) {
		name_buf nb;
		vlog("%s failed, responder SA processing returned %s",
		     what, str_enum_short(&v2_notification_names, n, &nb));
		return n;
	}

	vdbg_ikev2_proposal(verbose, what, child->sa.st_v2_accepted_proposal);

	struct ipsec_proto_info *proto_info = ikev2_child_sa_proto_info(child);
	/* hack until esp/ah merged */
	const struct ip_protocol *protocol = NULL;
	if (proto_info == &child->sa.st_esp) {
		protocol = &ip_protocol_esp;
	}
	if (proto_info == &child->sa.st_ah) {
		protocol = &ip_protocol_ah;
	}
	if (PBAD(child->sa.logger, protocol == NULL)) {
		return v2N_NO_PROPOSAL_CHOSEN; /* lie */
	}
	proto_info->protocol = protocol;
	if (!ikev2_proposal_to_proto_info(child->sa.st_v2_accepted_proposal, proto_info,
					  child->sa.logger)) {
		vlog("%s proposed/accepted a proposal we don't actually support!", what);
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
		proto_info->trans_attrs.ta_dh == &ike_alg_dh_none ? NULL
		: proto_info->trans_attrs.ta_dh;
	switch (child->sa.st_sa_role) {
	case SA_INITIATOR:
		vexpect(expect_accepted_proposal);
		if (accepted_dh != NULL && accepted_dh != child->sa.st_pfs_group) {
			vlog("expecting %s but remote's accepted proposal includes %s",
			     child->sa.st_pfs_group == NULL ? "no DH" : child->sa.st_pfs_group->common.fqn,
			     accepted_dh->common.fqn);
			return v2N_NO_PROPOSAL_CHOSEN;
		}
		child->sa.st_pfs_group = accepted_dh;
		break;
	case SA_RESPONDER:
		vexpect(!expect_accepted_proposal);
		vexpect(child->sa.st_sa_role == SA_RESPONDER);
		vexpect(child->sa.st_pfs_group == NULL);
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
		vdbg("updating "PRI_SO"'s .st_oakley with preserved PRF, but why update?",
		     pri_so(child->sa.st_serialno));
		struct trans_attrs accepted_oakley = proto_info->trans_attrs;
		vexpect(accepted_oakley.ta_prf == NULL);
		accepted_oakley.ta_prf = child->sa.st_oakley.ta_prf;
		child->sa.st_oakley = accepted_oakley;
	}

	return v2N_NOTHING_WRONG;
}

void jam_v2_success_child_sa_request_details(struct jambuf *buf, struct child_sa *larval)
{
	const struct config *config = larval->sa.st_connection->config;
	jam_string(buf, "{");
	/*
	 * While ESP/AH isn't dynamic (from config),
	 * inTCP/inUDP are (determined by the negotiating IKE
	 * SA).  For completeness include both.
	 */
	jam_enum_short(buf, &encap_proto_names, config->child.encap_proto);
	if (larval->sa.st_iface_endpoint->io->protocol == &ip_protocol_tcp) {
		jam_string(buf, "inTCP");
	} else if (nat_traversal_detected(&larval->sa)) {
		jam_string(buf, "inUDP");
	}
#if 0
	/*
	 * Show negotiation parameters?  For moment, no. They
	 * are just a copy/paste from config and can be seen
	 * with connectionstatus.
	 */
	if (config->esn.yes && config->esn.no) {
		jam_string(buf, " ESN?");
	} else if (config->esn.yes) {
		jam_string(buf, " ESN=Y");
	} else if (config->esn.no) {
		jam_string(buf, " ESN=N");
	}
	if (config->child.iptfs.enabled) {
		jam_string(buf, " IPTFS?");
	}
#endif
	/*
	 * This is a must.  It's needed to pair two Child SA
	 * exchanges (expecially when they cross streams)
	 */
	const struct ipsec_proto_info *proto = ikev2_child_sa_proto_info(larval);
	jam(buf, " <0x%08"PRIx32, ntohl(proto->inbound.spi));
	/* optional IPCOMP */
	if (larval->sa.st_ipcomp.inbound.spi != 0) {
		jam(buf, " IPCOMP <0x%04"PRIx32, ntohl(larval->sa.st_ipcomp.inbound.spi));
	}
	/* close */
	jam_string(buf, "}");
}

void llog_v2_child_sa_established(struct ike_sa *ike UNUSED, struct child_sa *child)
{
	struct connection *c = child->sa.st_connection;
	LLOG_JAMBUF(RC_LOG, child->sa.logger, buf) {
		switch (child->sa.st_sa_role) {
		case SA_INITIATOR: jam_string(buf, "initiator"); break;
		case SA_RESPONDER: jam_string(buf, "responder"); break;
		}
		if (child->sa.st_v2_rekey_pred == SOS_NOBODY) {
			jam_string(buf, " established Child SA");
		} else {
			jam_string(buf, " rekeyed Child SA ");
			jam_so(buf, child->sa.st_v2_rekey_pred);
		}
		jam_string(buf, " using ");
		jam_so(buf, child->sa.st_clonedfrom);
		jam_string(buf, "; IPsec ");
		/* log Child SA Traffic Selector details for admin's pleasure */
		jam_enum_human(buf, &kernel_mode_names, child->sa.st_kernel_mode);
		FOR_EACH_ITEM(spd, &c->child.spds) {
			jam_string(buf, " ");
			jam_string(buf, "[");
			jam_selector_pair(buf, &spd->local->client,
					  &spd->remote->client);
			jam_string(buf, "]");
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
	struct logger *logger = child->sa.logger;
	PEXPECT(logger, child->sa.st_v2_transition->to == &state_v2_ESTABLISHED_CHILD_SA);
	change_v2_state(&child->sa);

	pstat_sa_established(&child->sa);

	llog_v2_child_sa_established(ike, child);

	schedule_v2_replace_event(&child->sa);

	/*
	 * start liveness checks if set, making sure we only schedule
	 * once when moving from I2->I3 or R1->R2
	 */
	if (dpd_active_locally(child->sa.st_connection)) {
		ldbg(logger, "dpd enabled, scheduling ikev2 liveness checks");
		deltatime_t delay = deltatime_max(child->sa.st_connection->config->dpd.delay,
						  deltatime(MIN_LIVENESS));
		event_schedule(EVENT_v2_LIVENESS, delay, &child->sa);
	}

	ldbg(child->sa.logger, "unpending IKE SA "PRI_SO" CHILD SA "PRI_SO" connection %s",
	     pri_so(ike->sa.st_serialno),
	     pri_so(child->sa.st_serialno),
	     child->sa.st_connection->name);
	unpend(ike, child->sa.st_connection);
}

v2_notification_t process_v2_child_response_payloads(struct ike_sa *ike, struct child_sa *child,
						     struct msg_digest *md)
{
	struct connection *c = child->sa.st_connection;
	struct logger *logger = child->sa.logger;

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
		name_buf esb;
		llog_sa(RC_LOG, child, "received ERROR NOTIFY (%d): %s ",
			  md->v2N_error,
			  str_enum_long(&v2_notification_names, md->v2N_error, &esb));
		return md->v2N_error;
	}

	/* check for Child SA related NOTIFY payloads */

	bool transport_mode_accepted =
		accept_v2_notification(v2N_USE_TRANSPORT_MODE, child->sa.logger, md,
				       c->config->child.encap_mode == ENCAP_MODE_TRANSPORT);

	enum kernel_mode required_mode =
		(c->config->child.encap_mode == ENCAP_MODE_TRANSPORT ? KERNEL_MODE_TRANSPORT :
		 c->config->child.encap_mode == ENCAP_MODE_TUNNEL ? KERNEL_MODE_TUNNEL :
		 PEXPECT(logger, 0));
	enum kernel_mode accepted_mode =
		(transport_mode_accepted ? KERNEL_MODE_TRANSPORT :
		 KERNEL_MODE_TUNNEL);
	if (required_mode != accepted_mode) {
		/* we should have accepted a matching response */
		name_buf amb, rmb;
		llog_sa(RC_LOG, child,
			"policy dictates %s, but peer requested %s",
			str_enum_long(&kernel_mode_stories, required_mode, &rmb),
			str_enum_long(&kernel_mode_stories, accepted_mode, &amb));
 		return v2N_NO_PROPOSAL_CHOSEN;
 	}

	child->sa.st_seen_and_use_iptfs =
		accept_v2_notification(v2N_USE_AGGFRAG, child->sa.logger, md,
				       c->config->child.iptfs.enabled);

	name_buf rmb;
	ldbg_sa(child, "local policy is %s and received matching notify",
		str_enum_long(&kernel_mode_stories, required_mode, &rmb));
	child->sa.st_kernel_mode = required_mode;

	/* not negotiated */
	child->sa.st_seen_esp_tfc_padding_not_supported =
		(md->pd[PD_v2N_ESP_TFC_PADDING_NOT_SUPPORTED] != NULL);
	ldbg(child->sa.logger, "received ESP_TFC_PADDING_NOT_SUPPORTED=%s",
	     bool_str(child->sa.st_seen_esp_tfc_padding_not_supported));

	if (md->pd[PD_v2N_IPCOMP_SUPPORTED] != NULL) {
		struct pbs_in pbs = md->pd[PD_v2N_IPCOMP_SUPPORTED]->pbs;
		size_t len = pbs_left(&pbs);
		struct ikev2_notify_ipcomp_data n_ipcomp;

		ldbg(logger, "received v2N_IPCOMP_SUPPORTED of length %zd", len);
		if (!c->config->child.ipcomp) {
			llog_sa(RC_LOG, child,
				  "Unexpected IPCOMP request as our connection policy did not indicate support for it");
			return v2N_NO_PROPOSAL_CHOSEN;
		}

		diag_t d = pbs_in_struct(&pbs, &ikev2notify_ipcomp_data_desc,
					 &n_ipcomp, sizeof(n_ipcomp), NULL);
		if (d != NULL) {
			llog(RC_LOG, child->sa.logger, "%s", str_diag(d));
			pfree_diag(&d);
			return v2N_INVALID_SYNTAX; /* fatal */
		}

		if (n_ipcomp.ikev2_notify_ipcomp_trans != IPCOMP_DEFLATE) {
			llog_sa(RC_LOG, child,
				  "Unsupported IPCOMP compression method %d",
			       n_ipcomp.ikev2_notify_ipcomp_trans); /* enum_name this later */
			return v2N_INVALID_SYNTAX; /* fatal */
		}

		if (n_ipcomp.ikev2_cpi < IPCOMP_FIRST_NEGOTIATED) {
			llog_sa(RC_LOG, child,
				  "Illegal IPCOMP CPI %d", n_ipcomp.ikev2_cpi);
			return v2N_INVALID_SYNTAX; /* fatal */
		}
		ldbg(logger, "Received compression CPI=%d", n_ipcomp.ikev2_cpi);

		//child->sa.st_ipcomp.outbound.spi = uniquify_peer_cpi((ipsec_spi_t)htonl(n_ipcomp.ikev2_cpi), st, 0);
		child->sa.st_ipcomp.outbound.spi = htonl((ipsec_spi_t)n_ipcomp.ikev2_cpi);
		name_buf ignore;
		child->sa.st_ipcomp.trans_attrs.ta_ipcomp =
			ikev2_ipcomp_desc(n_ipcomp.ikev2_notify_ipcomp_trans, &ignore);
		child->sa.st_ipcomp.inbound.last_used =
		child->sa.st_ipcomp.outbound.last_used =
			realnow();
		child->sa.st_ipcomp.protocol = &ip_protocol_ipcomp;
	}

	ikev2_derive_child_keys(ike, child);

	/* now install child SAs */
	if (!connection_establish_child(ike, child, HERE)) {
		return v2N_TEMPORARY_FAILURE; /* delete child */
	}

	if (child->sa.st_state == &state_v2_REKEY_CHILD_I1)
		ikev2_rekey_expire_predecessor(child, child->sa.st_v2_rekey_pred);

	return v2N_NOTHING_WRONG;
}

/*
 * Try to create child in .wip_sa.  Return NOTHING_WRONG, non-fatal,
 * or fatal notification.  Caller will handle notifies and child
 * cleanup.
 */

static v2_notification_t process_v2_IKE_AUTH_request_child_sa_payloads(struct ike_sa *ike,
								       struct child_sa *child,
								       struct msg_digest *md,
								       struct pbs_out *sk_pbs)
{
	struct logger *logger = child->sa.logger;
	v2_notification_t n;
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

	PEXPECT(logger, ike->sa.st_connection == child->sa.st_connection);
	const struct host_end_config *local = ike->sa.st_connection->local->host.config;
	const struct ip_info *pool_afi =
		(child->sa.st_connection->pool[IPv4] != NULL ? &ipv4_info :
		 child->sa.st_connection->pool[IPv6] != NULL ? &ipv6_info :
		 NULL);
	bool oe_server = (is_opportunistic(ike->sa.st_connection) &&
			  md->chain[ISAKMP_NEXT_v2CP] != NULL && pool_afi != NULL);

	ldbg_cp(child->sa.logger, child->sa.st_connection,
		"oe_server %s; processing v2CP and leasing addresses: %s",
		bool_str(oe_server), bool_str(local->modecfg.server));

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
	 * Process TS (but only when there's no CP); what woah no way!
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
		if (!process_v2TS_request_payloads(ike, child, md)) {
			/* already logged; caller, below, cleans up */
			return v2N_TS_UNACCEPTABLE;
		}
	} else {
		ldbg_sa(child, "skipping TS processing, mainly to stop tests failing but rumored to cause connection flips?!?");
	}

	n = process_childs_v2SA_payload("IKE_AUTH responder matching remote ESP/AH proposals",
					ike, child, md,
					child->sa.st_connection->config->child.v2_ike_auth_proposals,
					/*expect-accepted-proposal?*/false);
	name_buf nb;
	ldbg(child->sa.logger, "process_v2_childs_sa_payload() returned %s",
	     str_enum_long(&v2_notification_names, n, &nb));
	if (n != v2N_NOTHING_WRONG) {
		/* already logged; caller, below, cleans up */
		return n;
	}

	n = process_v2_child_request_payloads(ike, child, md, sk_pbs);
	ldbg(child->sa.logger, "process_v2_child_request_payloads() returned %s",
	     str_enum_long(&v2_notification_names, n, &nb));
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

bool process_any_v2_IKE_AUTH_request_child_payloads(struct ike_sa *ike,
						    struct msg_digest *md,
						    struct pbs_out *sk_pbs)
{
	if (impair.omit_v2_ike_auth_child) {
		/* only omit when missing */
		if (has_v2_IKE_AUTH_child_payloads(md)) {
			llog(RC_LOG, ike->sa.logger, "IMPAIR: ignoring Child SA payloads");
		} else {
			llog(RC_LOG, ike->sa.logger, "IMPAIR: no Child SA payloads to ignore");
		}
		return true;
	}

	/* try to process them */
	if (!has_v2_IKE_AUTH_child_payloads(md)) {
		llog(RC_LOG, ike->sa.logger, "IKE_AUTH request does not propose a Child SA; creating childless SA");
		return true;
	}

	/*
	 * There's enough to build a Child SA.  Save it in .WIP_SA, if
	 * this function fails call will clean it up.
	 */

	PEXPECT(ike->sa.logger, ike->sa.st_v2_msgid_windows.responder.wip_sa == NULL);
	struct child_sa *child =
		ike->sa.st_v2_msgid_windows.responder.wip_sa =
		new_v2_child_sa(ike->sa.st_connection, ike,
				CHILD_SA, SA_RESPONDER,
				STATE_V2_NEW_CHILD_R0);

	v2_notification_t cn = process_v2_IKE_AUTH_request_child_sa_payloads(ike, child, md, sk_pbs);
	if (cn != v2N_NOTHING_WRONG) {
		connection_teardown_child(&ike->sa.st_v2_msgid_windows.responder.wip_sa, REASON_DELETED, HERE);
		if (v2_notification_fatal(cn)) {
			record_v2N_response(ike->sa.logger, ike, md,
					    cn, empty_shunk/*no-data*/,
					    ENCRYPTED_PAYLOAD);
			return false;
		}
		emit_v2N(cn, sk_pbs);
	}
	ike->sa.st_v2_msgid_windows.responder.wip_sa = NULL; /* all done */
	return true;
}

/*
 * Process the Child SA payloads from an IKE_AUTH response.
 *
 * Return something other than v2N_NOTHING_WRONG when Child SA is
 * rejected.
 *
 * When the peer rejects the Child SA, delete it before returning.
 * Since the peer never created the Child SA, there's nothing to
 * cleanup.
 *
 * When this end rejects the Child SA, leave it standing.  Caller will
 * see this and initiate a cleanup such as Delete Child SA (but
 * sometimes deletes the IKE SA instead).
 */

v2_notification_t process_v2_IKE_AUTH_response_child_payloads(struct ike_sa *ike,
							      struct msg_digest *response_md)
{
	v2_notification_t n;

	if (impair.omit_v2_ike_auth_child) {
		/* Try to ignore missing CHILD SA payloads. */
		if (has_v2_IKE_AUTH_child_payloads(response_md)) {
			llog_pexpect(ike->sa.logger, HERE,
				     "IMPAIR: IKE_AUTH response should have omitted CHILD SA payloads");
			return v2N_INVALID_SYNTAX; /* fatal */
		}
		llog(RC_LOG, ike->sa.logger, "IMPAIR: as expected, IKE_AUTH response omitted CHILD SA payloads");
		return v2N_NOTHING_WRONG;
	}

	struct child_sa *child = ike->sa.st_v2_msgid_windows.initiator.wip_sa;
	if (child == NULL) {
		/*
		 * Did the responder send Child SA payloads this end
		 * didn't ask for?
		 */
		if (has_v2_IKE_AUTH_child_payloads(response_md)) {
			llog_sa(RC_LOG, ike,
				"IKE_AUTH response contains v2SA, v2TSi or v2TSr: but a CHILD SA was not requested!");
			return v2N_INVALID_SYNTAX; /* fatal */
		}
		ldbg(ike->sa.logger, "IKE SA "PRI_SO" has no and expects no CHILD SA",
		     pri_so(ike->sa.st_serialno));
		return v2N_NOTHING_WRONG;
	}

	/*
	 * Drive the larval Child SA's state machine.
	 */
	set_larval_v2_transition(child, &state_v2_ESTABLISHED_CHILD_SA, HERE);

	/*
	 * Was there an error notification for the Child SA in the
	 * response?  The RFC says this list isn't definitive.
	 *
	 * Since the peer rejected the Child SA (i.e., never created
	 * it), there's no need to send a delete.
	 *
	 * XXX: can this code assume that the response contains only
	 * one notify and that is for the child?  Given notifies are
	 * used to communicate compression I've my doubt.
	 */
	FOR_EACH_THING(pd,
		       PD_v2N_NO_PROPOSAL_CHOSEN,
		       PD_v2N_TS_UNACCEPTABLE,
		       PD_v2N_SINGLE_PAIR_REQUIRED,
		       PD_v2N_INTERNAL_ADDRESS_FAILURE,
		       PD_v2N_FAILED_CP_REQUIRED) {
		if (response_md->pd[pd] != NULL) {
			/* convert PD to N */
			v2_notification_t n = response_md->pd[pd]->payload.v2n.isan_type;
			/*
			 * Log something the testsuite expects for
			 * now.  It provides an anchor when looking at
			 * test changes.
			 */
			name_buf esb;
			llog_sa(RC_LOG, child,
				"IKE_AUTH response rejected Child SA with %s",
				str_enum_short(&v2_notification_names, n, &esb));
			/*
			 * Remove the Child SA's connection from the
			 * pending queue.
			 */
			ldbg(child->sa.logger, "unpending IKE SA "PRI_SO" CHILD SA "PRI_SO" connection %s",
			     pri_so(ike->sa.st_serialno),
			     pri_so(child->sa.st_serialno),
			     child->sa.st_connection->name);
			unpend(ike, child->sa.st_connection);
			/*
			 * Clean up the Child SA.
			 *
			 * If the caller sees the Child SA it will
			 * assume that it needs to initiate a delete.
			 */
			connection_teardown_child(&child, REASON_DELETED, HERE);
			ike->sa.st_v2_msgid_windows.initiator.wip_sa = child = NULL;
			/* handled */
			return n;
		}
	}

	/*
	 * Requested a Child SA, since peer didn't reject it (see
	 * above), there should be Child SA payloads in the response.
	 */

	if (!has_v2_IKE_AUTH_child_payloads(response_md)) {
		llog_sa(RC_LOG, child, "IKE_AUTH response missing at least one of the Child SA payloads v2SA, v2TSi and v2TSr");
		return v2N_INVALID_SYNTAX;	/* fatal */
	}

	/* AUTH is ok, we can trust the notify payloads */

	child->sa.st_ikev2_anon = ike->sa.st_ikev2_anon; /* was set after duplicate_state() (?!?) */

	/* examine and accept SA ESP/AH proposals */

	n = process_childs_v2SA_payload("IKE_AUTH initiator accepting remote ESP/AH proposal",
					ike, child, response_md,
					child->sa.st_connection->config->child.v2_ike_auth_proposals,
					/*expect-accepted-proposal?*/true);
	if (n != v2N_NOTHING_WRONG) {
		return n;
	}

	if (need_v2CP_response(child->sa.st_connection,
			       ike->sa.hidden_variables.st_nated_host)) {
		if (response_md->chain[ISAKMP_NEXT_v2CP] == NULL) {
			/*
			 * not really anything to here... but it would
			 * be worth unpending again.
			 */
			llog_sa(RC_LOG, child,
				  "missing v2CP reply, not attempting to setup child SA");
			return v2N_TS_UNACCEPTABLE;
		}
		if (!process_v2CP_response_payload(ike, child, response_md->chain[ISAKMP_NEXT_v2CP])) {
			return v2N_TS_UNACCEPTABLE;
		}
	}

	n = process_v2_child_response_payloads(ike, child, response_md);
	if (n != v2N_NOTHING_WRONG) {
		/* already logged */
		if (v2_notification_fatal(n)) {
			name_buf nb;
			llog_sa(RC_LOG, child,
				"CHILD SA encountered fatal error: %s",
				str_enum_short(&v2_notification_names, n, &nb));
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
	release_whack(child->sa.logger, HERE);

	return v2N_NOTHING_WRONG;
}
