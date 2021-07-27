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
#include "vendor.h"
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
#include "kernel.h"			/* for raw_policy() hack */

static bool has_v2_IKE_AUTH_child_sa_payloads(const struct msg_digest *md)
{
	return (md->chain[ISAKMP_NEXT_v2SA] != NULL &&
		md->chain[ISAKMP_NEXT_v2TSi] != NULL &&
		md->chain[ISAKMP_NEXT_v2TSr] != NULL);
}

stf_status emit_v2_child_sa_response_payloads(struct ike_sa *ike,
					      struct child_sa *child,
					      struct msg_digest *md,
					      struct pbs_out *outpbs)
{
	pexpect(child->sa.st_establishing_sa == IPSEC_SA); /* never grow up */
	enum isakmp_xchg_type isa_xchg = md->hdr.isa_xchg;
	struct connection *c = child->sa.st_connection;

	if (md->chain[ISAKMP_NEXT_v2CP] != NULL) {
		if (c->spd.that.has_lease) {
			if (!emit_v2_child_configuration_payload(child, outpbs)) {
				return STF_INTERNAL_ERROR;
			}
		} else {
			dbg("#%lu %s ignoring unexpected v2CP payload",
			    child->sa.st_serialno, child->sa.st_state->name);
		}
	}

	/* start of SA out */
	{
		/* ??? this code won't support AH + ESP */
		struct ipsec_proto_info *proto_info = ikev2_child_sa_proto_info(child);
		proto_info->our_spi = ikev2_child_sa_spi(&c->spd, c->policy,
							 child->sa.st_logger);
		chunk_t local_spi = THING_AS_CHUNK(proto_info->our_spi);
		if (!ikev2_emit_sa_proposal(outpbs,
					    child->sa.st_accepted_esp_or_ah_proposal,
					    &local_spi)) {
			dbg("problem emitting accepted proposal");
			return STF_INTERNAL_ERROR;
		}
	}

	if (isa_xchg == ISAKMP_v2_CREATE_CHILD_SA) {
		/* send NONCE */
		struct ikev2_generic in = {
			.isag_critical = build_ikev2_critical(false, ike->sa.st_logger),
		};
		pb_stream pb_nr;
		if (!out_struct(&in, &ikev2_nonce_desc, outpbs, &pb_nr) ||
		    !out_hunk(child->sa.st_nr, &pb_nr, "IKEv2 nonce"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&pb_nr);

		/*
		 * XXX: shouldn't this be conditional on the local end
		 * having computed KE and not what the remote sent?
		 */
		if (md->chain[ISAKMP_NEXT_v2KE] != NULL) {
			if (!emit_v2KE(&child->sa.st_gr, child->sa.st_oakley.ta_dh, outpbs))
				return STF_INTERNAL_ERROR;
		}
	}

	if (md->pd[PD_v2N_USE_TRANSPORT_MODE] != NULL) {
		dbg("received USE_TRANSPORT_MODE");
		child->sa.st_seen_use_transport = TRUE;
	}

	if (md->pd[PD_v2N_IPCOMP_SUPPORTED] != NULL) {
		struct pbs_in pbs = md->pd[PD_v2N_IPCOMP_SUPPORTED]->pbs;
		size_t len = pbs_left(&pbs);
		struct ikev2_notify_ipcomp_data n_ipcomp;

		dbg("received v2N_IPCOMP_SUPPORTED of length %zd", len);

		diag_t d = pbs_in_struct(&pbs, &ikev2notify_ipcomp_data_desc,
					 &n_ipcomp, sizeof(n_ipcomp), NULL);
		if (d != NULL) {
			llog_diag(RC_LOG, child->sa.st_logger, &d, "%s", "");
			return STF_FATAL;
		}

		if (n_ipcomp.ikev2_notify_ipcomp_trans != IPCOMP_DEFLATE) {
			log_state(RC_LOG_SERIOUS, &child->sa,
				  "Unsupported IPCOMP compression method %d",
				  n_ipcomp.ikev2_notify_ipcomp_trans); /* enum_name this later */
			return STF_FATAL;
		}
		if (n_ipcomp.ikev2_cpi < IPCOMP_FIRST_NEGOTIATED) {
			log_state(RC_LOG_SERIOUS, &child->sa,
				  "Illegal IPCOMP CPI %d", n_ipcomp.ikev2_cpi);
			return STF_FATAL;
		}
		if ((c->policy & POLICY_COMPRESS) == LEMPTY) {
			dbg("Ignored IPCOMP request as connection has compress=no");
			child->sa.st_ipcomp.present = false;
		} else {
			dbg("Received compression CPI=%d", htonl(n_ipcomp.ikev2_cpi));
			//child->sa.st_ipcomp.attrs.spi = uniquify_peer_cpi((ipsec_spi_t)htonl(n_ipcomp.ikev2_cpi), cst, 0);
			child->sa.st_ipcomp.attrs.spi = htonl((ipsec_spi_t)n_ipcomp.ikev2_cpi);
			child->sa.st_ipcomp.attrs.transattrs.ta_comp = n_ipcomp.ikev2_notify_ipcomp_trans;
			child->sa.st_ipcomp.attrs.mode = ENCAPSULATION_MODE_TUNNEL; /* always? */
			child->sa.st_ipcomp.present = true;
		}
	} else if (c->policy & POLICY_COMPRESS) {
		dbg("policy suggested compression, but peer did not offer support");
	}

	if (md->pd[PD_v2N_ESP_TFC_PADDING_NOT_SUPPORTED] != NULL) {
		dbg("received ESP_TFC_PADDING_NOT_SUPPORTED");
		child->sa.st_seen_no_tfc = true;
	}

	/* verify if transport / tunnel mode is matches */
	if ((c->policy & POLICY_TUNNEL) == LEMPTY) {
		/* we should have received transport mode request - and send one */
		if (!child->sa.st_seen_use_transport) {
			log_state(RC_LOG, &child->sa,
				  "policy dictates Transport Mode, but peer requested Tunnel Mode");
			return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
		}
	} else {
		if (child->sa.st_seen_use_transport) {
			/* RFC allows us to ignore their (wrong) request for transport mode */
			log_state(RC_LOG, &child->sa,
				  "policy dictates Tunnel Mode, ignoring peer's request for Transport Mode");
		}
	}

	/*
	 * XXX: see above notes on 'role' - this must be the
	 * SA_RESPONDER.
	 */
	stf_status ret = emit_v2TS_payloads(outpbs, child);
	if (ret != STF_OK)
		return ret;

	if (child->sa.st_seen_use_transport) {
		if (c->policy & POLICY_TUNNEL) {
			log_state(RC_LOG, &child->sa,
				  "Local policy is tunnel mode - ignoring request for transport mode");
		} else {
			dbg("Local policy is transport mode and received USE_TRANSPORT_MODE");
			if (child->sa.st_esp.present) {
				child->sa.st_esp.attrs.mode =
					ENCAPSULATION_MODE_TRANSPORT;
			}
			if (child->sa.st_ah.present) {
				child->sa.st_ah.attrs.mode =
					ENCAPSULATION_MODE_TRANSPORT;
			}
			/* In v2, for parent, protoid must be 0 and SPI must be empty */
			if (!emit_v2N(v2N_USE_TRANSPORT_MODE, outpbs))
				return STF_INTERNAL_ERROR;
		}
	} else {
		/* the peer wants tunnel mode */
		if ((c->policy & POLICY_TUNNEL) == LEMPTY) {
			log_state(RC_LOG_SERIOUS, &child->sa,
				  "Local policy is transport mode, but peer did not request that");
			return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
		}
	}

	if (c->send_no_esp_tfc) {
		dbg("Sending ESP_TFC_PADDING_NOT_SUPPORTED");
		if (!emit_v2N(v2N_ESP_TFC_PADDING_NOT_SUPPORTED, outpbs))
			return STF_INTERNAL_ERROR;
	}

	if (child->sa.st_ipcomp.present) {
		/* logic above decided to enable IPCOMP */
		if (!emit_v2N_ipcomp_supported(child, outpbs))
			return STF_INTERNAL_ERROR;
	}

	ikev2_derive_child_keys(ike, child);
	return STF_OK;
}

static void ikev2_set_domain(struct pbs_in *cp_a_pbs, struct child_sa *child)
{
	bool responder = (child->sa.st_sa_role == SA_RESPONDER);
	bool ignore = LIN(POLICY_IGNORE_PEER_DNS, child->sa.st_connection->policy);

	if (!responder) {
		char *safestr = cisco_stringify(cp_a_pbs, "INTERNAL_DNS_DOMAIN",
						ignore, child->sa.st_logger);
		if (safestr != NULL) {
			append_st_cfg_domain(&child->sa, safestr);
		}
	} else {
		log_state(RC_LOG, &child->sa,
			  "initiator INTERNAL_DNS_DOMAIN CP ignored");
	}
}

static bool ikev2_set_dns(struct pbs_in *cp_a_pbs, struct child_sa *child,
			  const struct ip_info *af)
{
	struct connection *c = child->sa.st_connection;
	bool ignore = LIN(POLICY_IGNORE_PEER_DNS, c->policy);

	if (c->policy & POLICY_OPPORTUNISTIC) {
		log_state(RC_LOG, &child->sa,
			  "ignored INTERNAL_IP%d_DNS CP payload for Opportunistic IPsec",
			  af->ip_version);
		return true;
	}

	ip_address ip;
	diag_t d = pbs_in_address(cp_a_pbs, &ip, af, "INTERNAL_IP_DNS CP payload");
	if (d != NULL) {
		llog_diag(RC_LOG, child->sa.st_logger, &d, "%s", "");
		return false;
	}

	/* i.e. all zeros */
	if (address_is_any(ip)) {
		address_buf ip_str;
		log_state(RC_LOG, &child->sa,
			  "ERROR INTERNAL_IP%d_DNS %s is invalid",
			  af->ip_version, ipstr(&ip, &ip_str));
		return false;
	}

	bool responder = (child->sa.st_sa_role == SA_RESPONDER);
	if (!responder) {
		address_buf ip_buf;
		const char *ip_str = ipstr(&ip, &ip_buf);

		log_state(RC_LOG, &child->sa,
			  "received %sINTERNAL_IP%d_DNS %s",
			  ignore ? "and ignored " : "",
			  af->ip_version, ip_str);
		if (!ignore)
			append_st_cfg_dns(&child->sa, ip_str);
	} else {
		log_state(RC_LOG, &child->sa,
			  "initiator INTERNAL_IP%d_DNS CP ignored",
			  af->ip_version);
	}

	return true;
}

static bool ikev2_set_internal_address(struct pbs_in *cp_a_pbs, struct child_sa *child,
				       const struct ip_info *af, bool *seen_an_address)
{
	struct connection *c = child->sa.st_connection;

	ip_address ip;
	diag_t d = pbs_in_address(cp_a_pbs, &ip, af, "INTERNAL_IP_ADDRESS");
	if (d != NULL) {
		llog_diag(RC_LOG, child->sa.st_logger, &d, "%s", "");
		return false;
	}

	/*
	 * if (af->af == AF_INET6) pbs_in_address only reads 16 bytes.
	 * There should be one more byte in the pbs, 17th byte is prefix length.
	 */

	if (address_is_any(ip)) {
		ipstr_buf ip_str;
		log_state(RC_LOG, &child->sa,
			  "ERROR INTERNAL_IP%d_ADDRESS %s is invalid",
			  af->ip_version, ipstr(&ip, &ip_str));
		return false;
	}

	ipstr_buf ip_str;
	log_state(RC_LOG, &child->sa,
		  "received INTERNAL_IP%d_ADDRESS %s%s",
		  af->ip_version, ipstr(&ip, &ip_str),
		  *seen_an_address ? "; discarded" : "");

	bool responder = (child->sa.st_sa_role == SA_RESPONDER);
	if (responder) {
		log_state(RC_LOG, &child->sa, "bogus responder CP ignored");
		return true;
	}

	if (*seen_an_address) {
		return true;
	}

	*seen_an_address = true;
	c->spd.this.has_client = true;
	c->spd.this.has_internal_address = true;

	if (c->spd.this.cat) {
		dbg("CAT is set, not setting host source IP address to %s",
		    ipstr(&ip, &ip_str));
		ip_address this_client_prefix = selector_prefix(c->spd.this.client);
		if (address_eq_address(this_client_prefix, ip)) {
			/*
			 * The address we received is same as this
			 * side should we also check the host_srcip.
			 */
			dbg("#%lu %s[%lu] received INTERNAL_IP%d_ADDRESS that is same as this.client.addr %s. Will not add CAT iptable rules",
			    child->sa.st_serialno, c->name, c->instance_serial,
			    af->ip_version, ipstr(&ip, &ip_str));
		} else {
			c->spd.this.client = selector_from_address(ip);
			c->spd.this.has_cat = true; /* create iptable entry */
		}
	} else {
		c->spd.this.client = selector_from_address(ip);
		/* only set sourceip= value if unset in configuration */
		if (address_is_unset(&c->spd.this.host_srcip) ||
		    address_is_any(c->spd.this.host_srcip)) {
			dbg("setting host source IP address to %s",
			    ipstr(&ip, &ip_str));
			c->spd.this.host_srcip = ip;
		}
	}

	return true;
}

bool ikev2_parse_cp_r_body(struct payload_digest *cp_pd, struct child_sa *child)
{
	struct ikev2_cp *cp =  &cp_pd->payload.v2cp;
	struct connection *c = child->sa.st_connection;
	pb_stream *attrs = &cp_pd->pbs;

	dbg("#%lu %s[%lu] parsing ISAKMP_NEXT_v2CP payload",
	    child->sa.st_serialno, c->name, c->instance_serial);

	switch (child->sa.st_sa_role) {
	case SA_INITIATOR:
		if (cp->isacp_type != IKEv2_CP_CFG_REPLY) {
			log_state(RC_LOG_SERIOUS, &child->sa,
				  "ERROR expected IKEv2_CP_CFG_REPLY got a %s",
				  enum_name(&ikev2_cp_type_names, cp->isacp_type));
			return false;
		}
		break;
	case SA_RESPONDER:
		if (cp->isacp_type != IKEv2_CP_CFG_REQUEST) {
			log_state(RC_LOG_SERIOUS, &child->sa,
				  "ERROR expected IKEv2_CP_CFG_REQUEST got a %s",
				  enum_name(&ikev2_cp_type_names, cp->isacp_type));
			return false;
		}
		break;
	default:
		bad_case(child->sa.st_sa_role);
	}

	bool seen_internal_address = false;
	while (pbs_left(attrs) > 0) {
		struct ikev2_cp_attribute cp_a;
		pb_stream cp_a_pbs;

		diag_t d = pbs_in_struct(attrs, &ikev2_cp_attribute_desc,
					 &cp_a, sizeof(cp_a), &cp_a_pbs);
		if (d != NULL) {
			llog_diag(RC_LOG_SERIOUS, child->sa.st_logger, &d,
				 "ERROR malformed CP attribute");
			return false;
		}

		switch (cp_a.type) {
		case IKEv2_INTERNAL_IP4_ADDRESS | ISAKMP_ATTR_AF_TLV:
			if (!ikev2_set_internal_address(&cp_a_pbs, child, &ipv4_info,
							&seen_internal_address)) {
				log_state(RC_LOG_SERIOUS, &child->sa,
					  "ERROR malformed INTERNAL_IP4_ADDRESS attribute");
				return FALSE;
			}
			break;

		case IKEv2_INTERNAL_IP4_DNS | ISAKMP_ATTR_AF_TLV:
			if (!ikev2_set_dns(&cp_a_pbs, child, &ipv4_info)) {
				log_state(RC_LOG_SERIOUS, &child->sa,
					  "ERROR malformed INTERNAL_IP4_DNS attribute");
				return FALSE;
			}
			break;

		case IKEv2_INTERNAL_IP6_ADDRESS | ISAKMP_ATTR_AF_TLV:
			if (!ikev2_set_internal_address(&cp_a_pbs, child, &ipv6_info,
							&seen_internal_address)) {
				log_state(RC_LOG_SERIOUS, &child->sa,
					  "ERROR malformed INTERNAL_IP6_ADDRESS attribute");
				return FALSE;
			}
			break;

		case IKEv2_INTERNAL_IP6_DNS | ISAKMP_ATTR_AF_TLV:
			if (!ikev2_set_dns(&cp_a_pbs, child, &ipv6_info)) {
				log_state(RC_LOG_SERIOUS, &child->sa,
					  "ERROR malformed INTERNAL_IP6_DNS attribute");
				return FALSE;
			}
			break;

		case IKEv2_INTERNAL_DNS_DOMAIN | ISAKMP_ATTR_AF_TLV:
			ikev2_set_domain(&cp_a_pbs, child); /* can't fail */
			break;

		default:
			log_state(RC_LOG, &child->sa,
				  "unknown attribute %s length %u",
				  enum_name(&ikev2_cp_attribute_type_names, cp_a.type),
				  cp_a.len);
			break;
		}
	}
	return TRUE;
}

stf_status process_v2_childs_sa_payload(const char *what,
					struct ike_sa *ike, struct child_sa *child,
					struct msg_digest *md, bool expect_accepted_proposal)
{
	struct connection *c = child->sa.st_connection;
	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_v2SA];
	enum isakmp_xchg_type isa_xchg = md->hdr.isa_xchg;
	struct ipsec_proto_info *proto_info = ikev2_child_sa_proto_info(child);
	stf_status ret;

	struct ikev2_proposals *child_proposals;
	if (isa_xchg == ISAKMP_v2_CREATE_CHILD_SA) {
		const struct dh_desc *default_dh = (c->policy & POLICY_PFS) != LEMPTY
			? ike->sa.st_oakley.ta_dh
			: &ike_alg_dh_none;
		child_proposals = get_v2_create_child_proposals(c, what, default_dh,
								child->sa.st_logger);
	} else {
		child_proposals = get_v2_ike_auth_child_proposals(c, what,
								  child->sa.st_logger);
	}

	ret = ikev2_process_sa_payload(what,
				       &sa_pd->pbs,
				       /*expect_ike*/ FALSE,
				       /*expect_spi*/ TRUE,
				       expect_accepted_proposal,
				       LIN(POLICY_OPPORTUNISTIC, c->policy),
				       &child->sa.st_accepted_esp_or_ah_proposal,
				       child_proposals, child->sa.st_logger);

	if (ret != STF_OK) {
		LLOG_JAMBUF(RC_LOG_SERIOUS, child->sa.st_logger, buf) {
			jam_string(buf, what);
			jam(buf, " failed, responder SA processing returned ");
			jam_v2_stf_status(buf, ret);
		}
		pexpect(ret > STF_FAIL);
		return ret;
	}

	if (DBGP(DBG_BASE)) {
		DBG_log_ikev2_proposal(what, child->sa.st_accepted_esp_or_ah_proposal);
	}
	if (!ikev2_proposal_to_proto_info(child->sa.st_accepted_esp_or_ah_proposal, proto_info,
					  child->sa.st_logger)) {
		log_state(RC_LOG_SERIOUS, &child->sa,
			  "%s proposed/accepted a proposal we don't actually support!", what);
		return STF_FATAL;
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
			log_state(RC_LOG_SERIOUS, &child->sa,
				  "expecting %s but remote's accepted proposal includes %s",
				  child->sa.st_pfs_group == NULL ? "no DH" : child->sa.st_pfs_group->common.fqn,
				  accepted_dh->common.fqn);
			return STF_FATAL;
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

	return STF_OK;
}

void v2_child_sa_established(struct ike_sa *ike, struct child_sa *child)
{
	struct connection *c = child->sa.st_connection;
	change_state(&child->sa, STATE_V2_ESTABLISHED_CHILD_SA);

	pstat_sa_established(&child->sa);
	log_ipsec_sa_established("negotiated connection", &child->sa);

	/*
	 * ULGH, mixing debug and non debug output.
	 */
	lset_t rc_flags =
		(!(c->policy & POLICY_OPPORTUNISTIC) ? ALL_STREAMS|RC_SUCCESS :
		 (c->policy & POLICY_OPPORTUNISTIC) && DBGP(DBG_BASE) ? DEBUG_STREAM :
		 NO_STREAM);
	if (rc_flags != NO_STREAM) {
		LLOG_JAMBUF(rc_flags, child->sa.st_logger, buf) {
			jam(buf, "%s", child->sa.st_state->story);
			/* document SA details for admin's pleasure */
			lswlog_child_sa_established(buf, &child->sa);
		}
	}

	v2_schedule_replace_event(&child->sa);

	/*
	 * start liveness checks if set, making sure we only schedule
	 * once when moving from I2->I3 or R1->R2
	 */
	if (dpd_active_locally(&child->sa)) {
		dbg("dpd enabled, scheduling ikev2 liveness checks");
		deltatime_t delay = deltatime_max(child->sa.st_connection->dpd_delay,
						  deltatime(MIN_LIVENESS));
		event_schedule(EVENT_v2_LIVENESS, delay, &child->sa);
	}

	connection_buf cb;
	dbg("unpending IKE SA #%lu CHILD SA #%lu connection "PRI_CONNECTION,
	    ike->sa.st_serialno, child->sa.st_serialno,
	    pri_connection(child->sa.st_connection, &cb));
	unpend(ike, child->sa.st_connection);
}

/*
 * Deal with either CP or TS.
 *
 * A CREATE_CHILD_SA can, technically, include a CP (Configuration)
 * payload.  However no one does it.  Allow it here so that the code
 * paths are consistent (and it seems that pluto has supported it).
 */

v2_notification_t assign_v2_responders_child_client(struct child_sa *child,
						    struct msg_digest *md)
{
	struct connection *c = child->sa.st_connection;

	if (c->pool != NULL && md->chain[ISAKMP_NEXT_v2CP] != NULL) {
		/*
		 * See ikev2-hostpair-02 where the connection is
		 * constantly clawed back as the SA keeps trying to
		 * establish / replace / rekey.
		 */
		err_t e = lease_that_address(c, &child->sa);
		if (e != NULL) {
			log_state(RC_LOG, &child->sa, "ikev2 lease_an_address failure %s", e);
			return v2N_INTERNAL_ADDRESS_FAILURE;
		}
	} else {
		if (!v2_process_ts_request(child, md)) {
			/* already logged? */
			return v2N_TS_UNACCEPTABLE;
		}
	}
	return v2N_NOTHING_WRONG;
}

v2_notification_t ikev2_process_ts_and_rest(struct ike_sa *ike, struct child_sa *child,
					    struct msg_digest *md)
{
	struct connection *c = child->sa.st_connection;

	if (!v2_process_ts_response(child, md)) {
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
		log_state(RC_LOG_SERIOUS, &child->sa, "received ERROR NOTIFY (%d): %s ",
			  md->v2N_error,
			  enum_show(&ikev2_notify_names, md->v2N_error, &esb));
		return md->v2N_error;
	}

	/* check for Child SA related NOTIFY payloads */
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
			if (child->sa.st_esp.present) {
				child->sa.st_esp.attrs.mode = ENCAPSULATION_MODE_TRANSPORT;
			}
			if (child->sa.st_ah.present) {
				child->sa.st_ah.attrs.mode = ENCAPSULATION_MODE_TRANSPORT;
			}
		}
	}
	child->sa.st_seen_no_tfc = md->pd[PD_v2N_ESP_TFC_PADDING_NOT_SUPPORTED] != NULL;
	if (md->pd[PD_v2N_IPCOMP_SUPPORTED] != NULL) {
		pb_stream pbs = md->pd[PD_v2N_IPCOMP_SUPPORTED]->pbs;
		size_t len = pbs_left(&pbs);
		struct ikev2_notify_ipcomp_data n_ipcomp;

		dbg("received v2N_IPCOMP_SUPPORTED of length %zd", len);
		if ((c->policy & POLICY_COMPRESS) == LEMPTY) {
			log_state(RC_LOG_SERIOUS, &child->sa,
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
			log_state(RC_LOG_SERIOUS, &child->sa,
				  "Unsupported IPCOMP compression method %d",
			       n_ipcomp.ikev2_notify_ipcomp_trans); /* enum_name this later */
			return v2N_INVALID_SYNTAX; /* fatal */
		}

		if (n_ipcomp.ikev2_cpi < IPCOMP_FIRST_NEGOTIATED) {
			log_state(RC_LOG_SERIOUS, &child->sa,
				  "Illegal IPCOMP CPI %d", n_ipcomp.ikev2_cpi);
			return v2N_INVALID_SYNTAX; /* fatal */
		}
		dbg("Received compression CPI=%d", n_ipcomp.ikev2_cpi);

		//child->sa.st_ipcomp.attrs.spi = uniquify_peer_cpi((ipsec_spi_t)htonl(n_ipcomp.ikev2_cpi), st, 0);
		child->sa.st_ipcomp.attrs.spi = htonl((ipsec_spi_t)n_ipcomp.ikev2_cpi);
		child->sa.st_ipcomp.attrs.transattrs.ta_comp = n_ipcomp.ikev2_notify_ipcomp_trans;
		child->sa.st_ipcomp.attrs.mode = ENCAPSULATION_MODE_TUNNEL; /* always? */
		child->sa.st_ipcomp.present = true;
	}

	ikev2_derive_child_keys(ike, child);

#ifdef USE_XFRM_INTERFACE
	/* before calling do_command() */
	if (child->sa.st_state->kind != STATE_V2_REKEY_CHILD_I1)
		if (c->xfrmi != NULL &&
				c->xfrmi->if_id != 0)
			if (add_xfrmi(c, child->sa.st_logger))
				return v2N_INVALID_SYNTAX; /* fatal */
#endif
	/* now install child SAs */
	if (!install_ipsec_sa(&child->sa, TRUE))
		/* This affects/kills the IKE SA? Oops :-( */
		return v2N_INVALID_SYNTAX; /* fatal */

	set_newest_ipsec_sa("inR2", &child->sa);

	if (child->sa.st_state->kind == STATE_V2_REKEY_CHILD_I1)
		ikev2_rekey_expire_predecessor(child, child->sa.st_ipsec_pred);

	return v2N_NOTHING_WRONG;
}

v2_notification_t process_v2_IKE_AUTH_request_child_sa_payloads(struct ike_sa *ike,
								struct msg_digest *md,
								struct pbs_out *sk_pbs)
{
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
		struct connection *ic = ike->sa.st_connection;
		if (ic->spd.this.sec_label.len > 0) {
			pexpect(ic->kind == CK_TEMPLATE);
			llog_sa(RC_LOG, ike,
				"connection has a security label; allowing childless IKE SA");
			return v2N_NOTHING_WRONG;
		}
		/*
		 * XXX: not right, need way to determine if policy
		 * allows childless IKE SAs with this connection (or
		 * just always enable them).
		 */
		llog_sa(RC_LOG, ike, "IKE_AUTH request does not propose a Child SA; rejecting request");
		/* caller will send notification, if needed */
		return v2N_AUTHENTICATION_FAILED; /* fatal */
	}

	/* above confirmed there's enough to build a Child SA */
	struct child_sa *child = new_v2_child_state(ike->sa.st_connection, ike,
						    IPSEC_SA, SA_RESPONDER,
						    STATE_V2_IKE_AUTH_CHILD_R0,
						    null_fd);

	/*
	 * Danger! This call can change the child's connection.
	 */

	v2_notification_t n = assign_v2_responders_child_client(child, md);
	if (n != v2N_NOTHING_WRONG) {
		/* already logged */
		delete_state(&child->sa);
		return n;
	}

	stf_status ret;
	ret = process_v2_childs_sa_payload("IKE_AUTH responder matching remote ESP/AH proposals",
					   ike, child, md,
					   /*expect-accepted-proposal?*/false);
	LSWDBGP(DBG_BASE, buf) {
		jam(buf, "process_v2_childs_sa_payload returned ");
		jam_v2_stf_status(buf, ret);
	}
	if (ret != STF_OK) {
		/* already logged */
		delete_state(&child->sa);
		if (ret <= STF_FAIL) {
			return v2N_INVALID_SYNTAX; /* fatal */
		}
		v2_notification_t n = ret - STF_FAIL;
		return n;
	}

	ret = emit_v2_child_sa_response_payloads(ike, child, md, sk_pbs);
	LSWDBGP(DBG_BASE, buf) {
		jam(buf, "emit_v2_child_sa_response_payloads() returned ");
		jam_v2_stf_status(buf, ret);
	}
	if (ret != STF_OK) {
		/* already logged */
		delete_state(&child->sa);
		if (ret <= STF_FAIL) {
			return v2N_INVALID_SYNTAX; /* fatal */
		}
		v2_notification_t n = ret - STF_FAIL;
		return n;
	}

	/*
	 * Check to see if we need to release an old instance
	 * Note that this will call delete on the old
	 * connection we should do this after installing
	 * ipsec_sa, but that will give us a "eroute in use"
	 * error.
	 */
#ifdef USE_XFRM_INTERFACE
	struct connection *cc = child->sa.st_connection;
	if (cc->xfrmi != NULL && cc->xfrmi->if_id != 0) {
		if (add_xfrmi(cc, child->sa.st_logger)) {
			/* already logged? */
			delete_state(&child->sa);
			return v2N_INVALID_SYNTAX; /* fatal */
		}
	}
#endif

	/* install inbound and outbound SPI info */
	if (!install_ipsec_sa(&child->sa, true)) {
		/* already logged? */
		delete_state(&child->sa);
		return v2N_INVALID_SYNTAX; /* fatal */
	}

	/* mark the connection as now having an IPsec SA associated with it. */
	set_newest_ipsec_sa(enum_name(&ikev2_exchange_names, md->hdr.isa_xchg),
			    &child->sa);

	/*
	 * XXX: fudge a state transition.
	 *
	 * Code extracted and simplified from
	 * success_v2_state_transition(); suspect very similar
	 * code will appear in the initiator.
	 */
	v2_child_sa_established(ike, child);

	return v2N_NOTHING_WRONG;
}

v2_notification_t process_v2_IKE_AUTH_response_child_sa_payloads(struct ike_sa *ike,
								 struct msg_digest *md)
{
	if (impair.ignore_v2_ike_auth_child) {
		/* Try to ignore the CHILD SA payloads. */
		if (!has_v2_IKE_AUTH_child_sa_payloads(md)) {
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
		if (has_v2_IKE_AUTH_child_sa_payloads(md)) {
			llog_pexpect(ike->sa.st_logger, HERE,
				     "IMPAIR: IKE_AUTH response should have omitted CHILD SA payloads");
			return v2N_INVALID_SYNTAX; /* fatal */
		}
		llog_sa(RC_LOG, ike, "IMPAIR: as expected, IKE_AUTH response omitted CHILD SA payloads");
		return v2N_NOTHING_WRONG;
	}

	struct child_sa *child = ike->sa.st_v2_larval_initiator_sa;
	if (child == NULL) {
		/*
		 * Did the responder send Child SA payloads this end
		 * didn't ask for?
		 */
		if (has_v2_IKE_AUTH_child_sa_payloads(md)) {
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
		if (md->pd[pd] != NULL) {
			/* convert PD to N */
			v2_notification_t n = md->pd[pd]->payload.v2n.isan_type;
			/*
			 * Log something the testsuite expects for
			 * now.  It provides an anchor when looking at
			 * test changes.
			 */
			esb_buf esb;
			llog_sa(RC_LOG_SERIOUS, child,
				"IKE_AUTH response contained the Child SA error notification %s",
				enum_show_short(&ikev2_notify_names, n, &esb));
			llog_sa(RC_LOG_SERIOUS, ike,
				"IKE SA established but responder rejected Child SA request");
			connection_buf cb;
			dbg("unpending IKE SA #%lu CHILD SA #%lu connection "PRI_CONNECTION,
			    ike->sa.st_serialno, child->sa.st_serialno,
			    pri_connection(child->sa.st_connection, &cb));
			unpend(ike, child->sa.st_connection);
			delete_state(&child->sa);
			ike->sa.st_v2_larval_initiator_sa = child = NULL;
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
	if (!has_v2_IKE_AUTH_child_sa_payloads(md)) {
		llog_sa(RC_LOG_SERIOUS, child,
			"IKE_AUTH response missing v2SA, v2TSi or v2TSr: not attempting to setup CHILD SA");
		return v2N_TS_UNACCEPTABLE;
	}

	child->sa.st_ikev2_anon = ike->sa.st_ikev2_anon; /* was set after duplicate_state() (?!?) */
	child->sa.st_seen_no_tfc = md->pd[PD_v2N_ESP_TFC_PADDING_NOT_SUPPORTED] != NULL;

	/* AUTH is ok, we can trust the notify payloads */
	if (md->pd[PD_v2N_USE_TRANSPORT_MODE] != NULL) {
		/* FIXME: use new RFC logic turning this into a request, not requirement */
		if (LIN(POLICY_TUNNEL, child->sa.st_connection->policy)) {
			log_state(RC_LOG_SERIOUS, &child->sa,
				  "local policy requires Tunnel Mode but peer requires required Transport Mode");
			return v2N_TS_UNACCEPTABLE;
		}
	} else {
		if (!LIN(POLICY_TUNNEL, child->sa.st_connection->policy)) {
			log_state(RC_LOG_SERIOUS, &child->sa,
				  "local policy requires Transport Mode but peer requires required Tunnel Mode");
			return v2N_TS_UNACCEPTABLE;
		}
	}

	/* examine and accept SA ESP/AH proposals */
	stf_status res;

	res = process_v2_childs_sa_payload("IKE_AUTH initiator accepting remote ESP/AH proposal",
					   ike, child,
					   md, /*expect-accepted-proposal?*/true);
	if (res > STF_FAIL) {
		v2_notification_t n = res - STF_FAIL;
		return n;
	} else if (res != STF_OK) {
		return v2N_INVALID_SYNTAX; /* fatal */
	}

	/*
	 * IP parameters on rekey MUST be identical, so CP payloads
	 * not needed.
	 */
	if (need_v2_configuration_payload(child->sa.st_connection,
					  ike->sa.hidden_variables.st_nat_traversal)) {
		if (md->chain[ISAKMP_NEXT_v2CP] == NULL) {
			/*
			 * not really anything to here... but it would
			 * be worth unpending again.
			 */
			log_state(RC_LOG_SERIOUS, &child->sa,
				  "missing v2CP reply, not attempting to setup child SA");
			return v2N_TS_UNACCEPTABLE;
		}
		if (!ikev2_parse_cp_r_body(md->chain[ISAKMP_NEXT_v2CP], child)) {
			return v2N_TS_UNACCEPTABLE;
		}
	}

	v2_notification_t n = ikev2_process_ts_and_rest(ike, child, md);
	if (n != v2N_NOTHING_WRONG) {
		if (v2_notification_fatal(n)) {
			llog_sa(RC_LOG_SERIOUS, child,
				"CHILD SA encountered fatal error: %s",
				enum_name_short(&ikev2_notify_names, n));
		} else {
			llog_sa(RC_LOG_SERIOUS, child,
				"CHILD SA failed: %s",
				enum_name_short(&ikev2_notify_names, n));
		}
		return n;
	}

	v2_child_sa_established(ike, child);
	/* hack; cover all bases; handled by close any whacks? */
	close_any(&child->sa.st_logger->object_whackfd);
	close_any(&child->sa.st_logger->global_whackfd);

	return v2N_NOTHING_WRONG;
}

struct ipsec_proto_info *ikev2_child_sa_proto_info(struct child_sa *child)
{
	lset_t policy = child->sa.st_connection->policy;
	switch (policy & (POLICY_ENCRYPT | POLICY_AUTHENTICATE)) {
	case POLICY_ENCRYPT:
		return &child->sa.st_esp;
	case POLICY_AUTHENTICATE:
		return &child->sa.st_ah;
	default:
		bad_case(policy);
	}
}
