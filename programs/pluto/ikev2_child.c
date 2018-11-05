/*
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2011-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2018 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012,2016-2017 Antony Antony <appu@phenome.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2014-2015 Andrew cagney <cagney@gnu.org>
 * Copyright (C) 2017 Antony Antony <antony@phenome.org>
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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"

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
#include "pluto_crypt.h"  /* for pluto_crypto_req & pluto_crypto_req_cont */
#include "ikev2.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "timer.h"
#include "whack.h"      /* requires connections.h */
#include "server.h"
#include "vendor.h"
#include "kernel.h"
#include "virtual.h"	/* needs connections.h */
#include "hostpair.h"
#include "addresspool.h"
#include "rnd.h"
#include "ip_address.h"
#include "ikev2_send.h"
#include "ikev2_message.h"
#include "ikev2_ts.h"

static stf_status ikev2_cp_reply_state(const struct msg_digest *md,
	struct state **ret_cst,
	enum isakmp_xchg_types isa_xchg)
{
	ip_address ipv4;
	struct connection *c = md->st->st_connection;

	err_t e = lease_an_address(c, md->st, &ipv4);
	if (e != NULL) {
		libreswan_log("ikev2 lease_an_address failure %s", e);
		return STF_INTERNAL_ERROR;
	}

	struct state *cst;

	if (isa_xchg == ISAKMP_v2_CREATE_CHILD_SA) {
		cst = md->st;
		update_state_connection(cst, c);
	} else {
		cst = ikev2_duplicate_state(pexpect_ike_sa(md->st), IPSEC_SA,
					    v2_msg_role(md) == MESSAGE_REQUEST ? SA_RESPONDER :
					    v2_msg_role(md) == MESSAGE_RESPONSE ? SA_INITIATOR :
					    0);
		cst->st_connection = c;	/* safe: from duplicate_state */
		insert_state(cst); /* needed for delete - we should never have duplicated before we were sure */
	}

	struct spd_route *spd = &md->st->st_connection->spd;
	spd->that.has_lease = TRUE;
	spd->that.client.addr = ipv4;
	spd->that.client.maskbits = 32; /* export it as value */
	spd->that.has_client = TRUE;

	cst->st_ts_this = ikev2_end_to_ts(&spd->this);
	cst->st_ts_that = ikev2_end_to_ts(&spd->that);

	*ret_cst = cst;	/* success! */
	return STF_OK;
}

stf_status ikev2_child_sa_respond(struct msg_digest *md,
				  pb_stream *outpbs,
				  enum isakmp_xchg_types isa_xchg)
{
	struct state *cst = NULL;	/* child state */
	struct connection *c = md->st->st_connection;

	/*
	 * MD->ST could be a parent (AUTH) or pre-created child
	 * (CHILD_SA).
	 */
	struct ike_sa *ike = ike_sa(md->st);

	if (isa_xchg == ISAKMP_v2_CREATE_CHILD_SA &&
	    md->st->st_ipsec_pred != SOS_NOBODY) {
		/* this is Child SA rekey we already have child state object */
		cst = md->st;
	} else if (c->pool != NULL && md->chain[ISAKMP_NEXT_v2CP] != NULL) {
		RETURN_STF_FAILURE_STATUS(ikev2_cp_reply_state(md, &cst,
					isa_xchg));
	} else if (isa_xchg == ISAKMP_v2_CREATE_CHILD_SA) {
		cst = md->st;
	} else {
		/* ??? is this only for AUTH exchange? */
		pexpect(isa_xchg == ISAKMP_v2_AUTH); /* see calls */
		pexpect(md->hdr.isa_xchg == ISAKMP_v2_AUTH); /* redundant */
		/*
		 * While this function is called with MD->ST pointing
		 * at either an IKE SA or CHILD SA, this code path
		 * only works when MD->ST is the IKE SA.
		 *
		 * XXX: this create-state code block should be moved
		 * to the ISAKMP_v2_AUTH caller.
		 */
		passert(cst == NULL);
		pexpect(md->st != NULL);
		pexpect(md->st == &ike->sa); /* passed in parent */
		cst = ikev2_duplicate_state(ike, IPSEC_SA, SA_RESPONDER);
		/* needed for delete */
		insert_state(cst);
		if (!v2_process_ts_request(pexpect_child_sa(cst), md)) {
			/*
			 * XXX: while the CHILD SA failed, the IKE SA
			 * should continue to exist.  This STF_FAIL
			 * will blame MD->ST aka the IKE SA.
			 */
			delete_state(cst);
			return STF_FAIL + v2N_TS_UNACCEPTABLE;
		}
	}

	/* switch to child */
	md->st = cst;
	c = cst->st_connection;

	/*
	 * The notifies have not yet been processed here, so we cannot
	 * look at st_seen_use_transport in either st or pst.  If we
	 * change to comply to RFC style transport mode negotiation,
	 * reading ntfy's will have to be done here.
	 */

	if (c->spd.that.has_lease &&
	    md->chain[ISAKMP_NEXT_v2CP] != NULL &&
	    cst->st_state != STATE_V2_REKEY_IKE_R) {
		ikev2_send_cp(&ike->sa, ISAKMP_NEXT_v2SA, outpbs);
	} else if (md->chain[ISAKMP_NEXT_v2CP] != NULL) {
		DBG(DBG_CONTROL, DBG_log("#%lu %s ignoring unexpected v2CP payload",
					cst->st_serialno,
					enum_name(&state_names, cst->st_state)));
	}

	/* start of SA out */
	{
		/* ??? this code won't support AH + ESP */
		struct ipsec_proto_info *proto_info
			= ikev2_child_sa_proto_info(cst, c->policy);

		if (isa_xchg != ISAKMP_v2_CREATE_CHILD_SA)  {
			RETURN_STF_FAILURE_STATUS(ikev2_process_child_sa_pl(md, FALSE));
		}
		proto_info->our_spi = ikev2_child_sa_spi(&c->spd, c->policy);
		chunk_t local_spi;
		setchunk(local_spi, (uint8_t*)&proto_info->our_spi,
				sizeof(proto_info->our_spi));
		if (!ikev2_emit_sa_proposal(outpbs,
					cst->st_accepted_esp_or_ah_proposal,
					&local_spi)) {
			DBGF(DBG_CONTROL, "problem emitting accepted proposal");
			return STF_INTERNAL_ERROR;
		}
	}

	if (isa_xchg == ISAKMP_v2_CREATE_CHILD_SA) {
		/* send NONCE */
		struct ikev2_generic in = {
			.isag_critical = build_ikev2_critical(false),
		};
		pb_stream pb_nr;
		if (!out_struct(&in, &ikev2_nonce_desc, outpbs, &pb_nr) ||
		    !out_chunk(cst->st_nr, &pb_nr, "IKEv2 nonce"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&pb_nr);

		/*
		 * XXX: shoudn't this be conditional on the local end
		 * having computed KE and not what the remote sent?
		 */
		if (md->chain[ISAKMP_NEXT_v2KE] != NULL)  {
			if (!emit_v2KE(&cst->st_gr, cst->st_oakley.ta_dh, outpbs))
				return STF_INTERNAL_ERROR;
		}
	}

	/*
	 * Paul: This is the second time we are processing NOTIFY's I
	 * suspect we are only interested in those related to the
	 * Child SA and mark those on the child state. But this code
	 * is used in IKE_AUTH as well as CREATE_CHILD_SA, so we end
	 * up double logging bad payloads on the responder.
	 */
	/* Process all NOTIFY payloads */
	for (struct payload_digest *ntfy = md->chain[ISAKMP_NEXT_v2N];
	     ntfy != NULL; ntfy = ntfy->next) {
		switch (ntfy->payload.v2n.isan_type) {
		case v2N_NAT_DETECTION_SOURCE_IP:
		case v2N_NAT_DETECTION_DESTINATION_IP:
		case v2N_IKEV2_FRAGMENTATION_SUPPORTED:
		case v2N_COOKIE:
		case v2N_USE_PPK:
			DBG(DBG_CONTROL, DBG_log("received %s which is not valid for current exchange",
						 enum_name(&ikev2_notify_names,
							   ntfy->payload.v2n.isan_type)));
			break;
		case v2N_USE_TRANSPORT_MODE:
			DBG(DBG_CONTROL, DBG_log("received USE_TRANSPORT_MODE"));
			cst->st_seen_use_transport = TRUE;
			break;
		case v2N_ESP_TFC_PADDING_NOT_SUPPORTED:
			DBG(DBG_CONTROL, DBG_log("received ESP_TFC_PADDING_NOT_SUPPORTED"));
			cst->st_seen_no_tfc = TRUE;
			break;
		case v2N_MOBIKE_SUPPORTED:
			DBG(DBG_CONTROL, DBG_log("received v2N_MOBIKE_SUPPORTED"));
			cst->st_seen_mobike = ike->sa.st_seen_mobike = TRUE;
			break;
		case v2N_INITIAL_CONTACT:
			DBG(DBG_CONTROL, DBG_log("received v2N_INITIAL_CONTACT"));
			cst->st_seen_initialc = ike->sa.st_seen_initialc = TRUE;
			break;
		case v2N_REKEY_SA:
			DBG(DBG_CONTROL, DBG_log("received REKEY_SA already proceesd"));
			break;
		case v2N_PPK_IDENTITY:
			DBG(DBG_CONTROL, DBG_log("received PPK_IDENTITY already processed"));
			break;
		case v2N_NO_PPK_AUTH:
			DBG(DBG_CONTROL, DBG_log("received NO_PPK_AUTH already processed"));
			break;
		default:
			libreswan_log("received unsupported NOTIFY %s ",
				      enum_name(&ikev2_notify_names,
						ntfy->payload.v2n.isan_type));
		}
	}

	{
		/* verify if transport / tunnel mode is matches */
		if ((c->policy & POLICY_TUNNEL) == LEMPTY) {
			/* we should have received transport mode request - and send one */
			if (!cst->st_seen_use_transport) {
				libreswan_log("policy dictates Transport Mode, but peer requested Tunnel Mode");
				return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
			}
		} else {
			if (cst->st_seen_use_transport) {
				/* RFC allows us to ignore their (wrong) request for transport mode */
				libreswan_log("policy dictates Tunnel Mode, ignoring peer's request for Transport Mode");
			}
		}

		/*
		 * XXX: see above notes on 'role' - this must be the
		 * SA_RESPONDER.
		 */
		stf_status ret = v2_emit_ts_payloads(pexpect_child_sa(cst),
						     outpbs, c);

		if (ret != STF_OK)
			return ret;	/* should we delete_state cst? */
	}

	if (cst->st_seen_use_transport) {
		if (c->policy & POLICY_TUNNEL) {
			libreswan_log("Local policy is tunnel mode - ignoring request for transport mode");
		} else {
			DBG(DBG_CONTROL, DBG_log("Local policy is transport mode and received USE_TRANSPORT_MODE"));
			if (cst->st_esp.present) {
				cst->st_esp.attrs.encapsulation =
					ENCAPSULATION_MODE_TRANSPORT;
			}
			if (cst->st_ah.present) {
				cst->st_ah.attrs.encapsulation =
					ENCAPSULATION_MODE_TRANSPORT;
			}
			/* In v2, for parent, protoid must be 0 and SPI must be empty */
			if (!ship_v2Ns(c->send_no_esp_tfc ? ISAKMP_NEXT_v2N : ISAKMP_NEXT_v2NONE,
				       v2N_USE_TRANSPORT_MODE, outpbs))
				return STF_INTERNAL_ERROR;
		}
	} else {
		/* the peer wants tunnel mode */
		if ((c->policy & POLICY_TUNNEL) == LEMPTY) {
			libreswan_log("Local policy is transport mode, but peer did not request that");
			return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
		}
	}

	if (c->send_no_esp_tfc) {
		DBG(DBG_CONTROL, DBG_log("Sending ESP_TFC_PADDING_NOT_SUPPORTED"));
		if (!ship_v2Ns(ISAKMP_NEXT_v2NONE,
			       v2N_ESP_TFC_PADDING_NOT_SUPPORTED, outpbs))
			return STF_INTERNAL_ERROR;
	}

	ikev2_derive_child_keys(pexpect_child_sa(cst));

	/*
	 * Check to see if we need to release an old instance
	 * Note that this will call delete on the old connection
	 * we should do this after installing ipsec_sa, but that will
	 * give us a "eroute in use" error.
	 */
	if (isa_xchg == ISAKMP_v2_CREATE_CHILD_SA) {
		/* skip check for rekey */
		ike->sa.st_connection->newest_isakmp_sa = ike->sa.st_serialno;
	} else {
		ISAKMP_SA_established(&ike->sa);
	}

	/* install inbound and outbound SPI info */
	if (!install_ipsec_sa(cst, TRUE))
		return STF_FATAL;

	/* mark the connection as now having an IPsec SA associated with it. */
	set_newest_ipsec_sa(enum_name(&ikev2_exchange_names, isa_xchg), cst);

	return STF_OK;
}

static void ikev2_set_domain(pb_stream *cp_a_pbs, struct state *st)
{
	bool responder = (st->st_state != STATE_PARENT_I2);

	if (!responder) {
		char *safestr = cisco_stringify(cp_a_pbs, "INTERNAL_DNS_DOMAIN");
		append_st_cfg_domain(st, safestr);
	} else {
		libreswan_log("initiator INTERNAL_DNS_DOMAIN CP ignored");
	}
}

static bool ikev2_set_dns(pb_stream *cp_a_pbs, struct state *st, int af)
{
	ip_address ip;
	char ip_str[ADDRTOT_BUF];
	struct connection *c = st->st_connection;
	err_t ugh = initaddr(cp_a_pbs->cur, pbs_left(cp_a_pbs), af, &ip);
	bool responder = (st->st_state != STATE_PARENT_I2);

	if (c->policy & POLICY_OPPORTUNISTIC) {
		libreswan_log("ignored INTERNAL_IP%s_DNS CP payload for Opportunistic IPsec",
			af == AF_INET ? "4" : "6");
		return TRUE;
	}

	addrtot(&ip, 0, ip_str, sizeof(ip_str));

	if ((ugh != NULL && st->st_state == STATE_PARENT_I2)) {
		libreswan_log("ERROR INTERNAL_IP%s_DNS malformed: %s",
			af == AF_INET ? "4" : "6", ugh);
		return FALSE;
	}

	if (isanyaddr(&ip)) {
		libreswan_log("ERROR INTERNAL_IP%s_DNS %s is invalid",
			af == AF_INET ? "4" : "6",
			ugh == NULL ? ip_str : ugh);
		return FALSE;
	}

	if (!responder) {
		libreswan_log("received INTERNAL_IP%s_DNS %s",
			af == AF_INET ? "4" : "6", ip_str);
		append_st_cfg_dns(st, ip_str);
	} else {
		libreswan_log("initiator INTERNAL_IP%s_DNS CP ignored",
			af == AF_INET ? "4" : "6");
	}

	return TRUE;
}

static bool ikev2_set_ia(pb_stream *cp_a_pbs, struct state *st, int af,
			 bool *seen_an_address)
{
	ip_address ip;
	ipstr_buf ip_str;
	struct connection *c = st->st_connection;
	err_t ugh = initaddr(cp_a_pbs->cur, pbs_left(cp_a_pbs), af, &ip);
	bool responder = st->st_state != STATE_PARENT_I2;

	if ((ugh != NULL && st->st_state == STATE_PARENT_I2) || isanyaddr(&ip)) {
		libreswan_log("ERROR INTERNAL_IP%s_ADDRESS malformed: %s",
			af == AF_INET ? "4" : "6", ugh);
		return FALSE;
	}

	if (isanyaddr(&ip)) {
		libreswan_log("ERROR INTERNAL_IP%s_ADDRESS %s is invalid",
			af == AF_INET ? "4" : "6",
			ipstr(&ip, &ip_str));
		return FALSE;
	}

	libreswan_log("received INTERNAL_IP%s_ADDRESS %s%s",
		      af == AF_INET ? "4" : "6",
		      ipstr(&ip, &ip_str),
		      *seen_an_address ? "; discarded" : "");

	if (responder) {
		libreswan_log("bogus responder CP ignored");
		return TRUE;
	}

	if (*seen_an_address) {
		return true;
	}

	*seen_an_address = true;
	c->spd.this.has_client = TRUE;
	c->spd.this.has_internal_address = TRUE;

	if (c->spd.this.cat) {
		DBG(DBG_CONTROL, DBG_log("CAT is set, not setting host source IP address to %s",
			ipstr(&ip, &ip_str)));
		if (sameaddr(&c->spd.this.client.addr, &ip)) {
			/* The address we received is same as this side
			 * should we also check the host_srcip */
			DBG(DBG_CONTROL, DBG_log("#%lu %s[%lu] received INTERNAL_IP%s_ADDRESS that is same as this.client.addr %s. Will not add CAT iptable rules",
				st->st_serialno, c->name, c->instance_serial,
				af == AF_INET ? "4" : "6",
				ipstr(&ip, &ip_str)));
		} else {
			c->spd.this.client.addr = ip;
			if (af == AF_INET)
				c->spd.this.client.maskbits = 32;
			else
				c->spd.this.client.maskbits = 128;
			st->st_ts_this = ikev2_end_to_ts(&c->spd.this);
			c->spd.this.has_cat = TRUE; /* create iptable entry */
		}
	} else {
		addrtosubnet(&ip, &c->spd.this.client);
		setportof(0, &c->spd.this.client.addr); /* ??? redundant? */
		/* only set sourceip= value if unset in configuration */
		if (addrlenof(&c->spd.this.host_srcip) == 0 ||
			isanyaddr(&c->spd.this.host_srcip)) {
				DBG(DBG_CONTROL, DBG_log("setting host source IP address to %s",
					ipstr(&ip, &ip_str)));
				c->spd.this.host_srcip = ip;
		}
	}

	return TRUE;
}

bool ikev2_parse_cp_r_body(struct payload_digest *cp_pd, struct state *st)
{
	struct ikev2_cp *cp =  &cp_pd->payload.v2cp;
	struct connection *c = st->st_connection;
	pb_stream *attrs = &cp_pd->pbs;

	DBG(DBG_CONTROLMORE, DBG_log("#%lu %s[%lu] parsing ISAKMP_NEXT_v2CP payload",
				st->st_serialno, c->name, c->instance_serial));

	if (st->st_state == STATE_PARENT_I2 && cp->isacp_type !=  IKEv2_CP_CFG_REPLY) {
		loglog(RC_LOG_SERIOUS, "ERROR expected IKEv2_CP_CFG_REPLY got a %s",
			enum_name(&ikev2_cp_type_names, cp->isacp_type));
		return FALSE;
	}

	if (st->st_state == STATE_PARENT_R1 && cp->isacp_type !=  IKEv2_CP_CFG_REQUEST) {
		loglog(RC_LOG_SERIOUS, "ERROR expected IKEv2_CP_CFG_REQUEST got a %s",
			enum_name(&ikev2_cp_type_names, cp->isacp_type));
		return FALSE;
	}

	bool seen_internal_address = false;
	while (pbs_left(attrs) > 0) {
		struct ikev2_cp_attribute cp_a;
		pb_stream cp_a_pbs;

		if (!in_struct(&cp_a, &ikev2_cp_attribute_desc,
					attrs, &cp_a_pbs)) {
			loglog(RC_LOG_SERIOUS, "ERROR malformed CP attribute");
			return FALSE;
		}

		switch (cp_a.type) {
		case IKEv2_INTERNAL_IP4_ADDRESS | ISAKMP_ATTR_AF_TLV:
			if (!ikev2_set_ia(&cp_a_pbs, st, AF_INET,
					  &seen_internal_address)) {
				loglog(RC_LOG_SERIOUS, "ERROR malformed INTERNAL_IP4_ADDRESS attribute");
				return FALSE;
			}
			break;

		case IKEv2_INTERNAL_IP4_DNS | ISAKMP_ATTR_AF_TLV:
			if (!ikev2_set_dns(&cp_a_pbs, st, AF_INET)) {
				loglog(RC_LOG_SERIOUS, "ERROR malformed INTERNAL_IP4_DNS attribute");
				return FALSE;
			}
			break;

		case IKEv2_INTERNAL_IP6_ADDRESS | ISAKMP_ATTR_AF_TLV:
			if (!ikev2_set_ia(&cp_a_pbs, st, AF_INET6,
						 &seen_internal_address)) {
				loglog(RC_LOG_SERIOUS, "ERROR malformed INTERNAL_IP6_ADDRESS attribute");
				return FALSE;
			}
			break;

		case IKEv2_INTERNAL_IP6_DNS | ISAKMP_ATTR_AF_TLV:
			if (!ikev2_set_dns(&cp_a_pbs, st, AF_INET6)) {
				loglog(RC_LOG_SERIOUS, "ERROR malformed INTERNAL_IP6_DNS attribute");
				return FALSE;
			}
			break;

		case IKEv2_INTERNAL_DNS_DOMAIN | ISAKMP_ATTR_AF_TLV:
			ikev2_set_domain(&cp_a_pbs, st); /* can't fail */
			break;

		default:
			libreswan_log("unknown attribute %s length %u",
				enum_name(&ikev2_cp_attribute_type_names,
					cp_a.type),
				cp_a.len);
			break;
		}
	}
	return TRUE;
}
