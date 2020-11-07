/* XAUTH related functions
 *
 * Copyright (C) 2001-2002 Colubris Networks
 * Copyright (C) 2003 Sean Mathews - Nu Tech Software Solutions, inc.
 * Copyright (C) 2003-2004 Xelerance Corporation
 * Copyright (C) 2009 Ken Wilson <Ken_Wilson@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012-2013 Philippe Vouters <philippe.vouters@laposte.net>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
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
 * This code originally written by Colubris Networks, Inc.
 * Extraction of patch and porting to 1.99 codebases by Xelerance Corporation
 * Porting to 2.x by Sean Mathews
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>

#if defined(linux)
/* is supposed to be in unistd.h, but it isn't on linux */
#include <crypt.h>
#endif


#include "lswalloc.h"

#include "sysdep.h"
#include "lswconf.h"
#include "constants.h"

#include "defs.h"
#include "state.h"
#include "ikev1_msgid.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"	/* needs id.h */
#include "packet.h"
#include "demux.h"		/* needs packet.h */
#include "log.h"
#include "timer.h"
#include "server.h"
#include "keys.h"
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "pam_auth.h"
#include "crypto.h"
#include "ike_alg.h"
#include "secrets.h"
#include "ikev1.h"
#include "ikev1_xauth.h"
#include "addresspool.h"
#include "ip_address.h"
#include "send.h"		/* for send without recording */
#include "ikev1_send.h"
#include "ip_info.h"
#include "ikev1_hash.h"
#include "impair.h"
#include "ikev1_message.h"

/* forward declarations */
static stf_status xauth_client_ackstatus(struct state *st,
					 pb_stream *rbody,
					 uint16_t ap_id);

/* CISCO_SPLIT_INC example payload
 *  70 04      00 0e      0a 00 00 00 ff 00 00 00 00 00 00 00 00 00
 *   \/          \/        \ \  /  /   \ \  / /   \  \  \ /  /  /
 *  28676        14        10.0.0.0    255.0.0.0
 *
 *  SPLIT_INC  Length       IP addr      mask     proto?,sport?,dport?,proto?,sport?,dport?
 */

struct CISCO_split_item {
	struct in_addr cs_addr;
	struct in_addr cs_mask;
};

static field_desc CISCO_split_fields[] = {
	{ ft_raw, 4, "IPv4 address", NULL },
	{ ft_raw, 4, "IPv4 mask", NULL },
	{ ft_zig, 6, "protos and ports?", NULL },
	{ ft_end, 0, NULL, NULL }
};

struct_desc CISCO_split_desc = 	{
	.name = "CISCO split item",
	.fields = CISCO_split_fields,
	.size = 14,
};

oakley_auth_t xauth_calcbaseauth(oakley_auth_t baseauth)
{
	switch (baseauth) {
	case HybridInitRSA:
	case HybridRespRSA:
	case XAUTHInitRSA:
	case XAUTHRespRSA:
		baseauth = OAKLEY_RSA_SIG;
		break;

	case XAUTHInitDSS:
	case XAUTHRespDSS:
	case HybridInitDSS:
	case HybridRespDSS:
		baseauth = OAKLEY_DSS_SIG;
		break;

	case XAUTHInitPreShared:
	case XAUTHRespPreShared:
		baseauth = OAKLEY_PRESHARED_KEY;
		break;

	case XAUTHInitRSAEncryption:
	case XAUTHRespRSAEncryption:
		baseauth = OAKLEY_RSA_ENC;
		break;

	/* Not implemented */
	case XAUTHInitRSARevisedEncryption:
	case XAUTHRespRSARevisedEncryption:
		baseauth = OAKLEY_RSA_REVISED_MODE;
		break;
	}

	return baseauth;
}

/**
 * Compute HASH of Mode Config.
 *
 * @param dest
 * @param start
 * @param roof
 * @param st State structure
 * @return size_t Length of the HASH
 */

static bool emit_xauth_hash(const char *what, struct state *st,
			    struct v1_hash_fixup *hash_fixup, pb_stream *out)
{
	return emit_v1_HASH(V1_HASH_1, what,
			    IMPAIR_v1_XAUTH_EXCHANGE,
			    st, hash_fixup, out);
}

static void fixup_xauth_hash(struct state *st,
			     struct v1_hash_fixup *hash_fixup,
			     const uint8_t *roof)
{
	fixup_v1_HASH(st, hash_fixup, st->st_v1_msgid.phase15, roof);
}

/**
 * Add ISAKMP attribute
 *
 * Add a given Mode Config attribute to the reply stream.
 *
 * @param pb_stream strattr the reply stream (stream)
 * @param attr_type int the attribute type
 * @param ia internal_addr the IP information for the connection
 * @param st State structure
 * @return stf_status STF_OK or STF_INTERNAL_ERROR
 */
static stf_status isakmp_add_attr(pb_stream *strattr,
				   const int attr_type,
				   const ip_address *ia,
				   const struct state *st)
{
	bool ok = TRUE;
	struct connection *c = st->st_connection;

	/* ISAKMP attr out */
	const struct isakmp_attribute attr = {
		.isaat_af_type = attr_type | ISAKMP_ATTR_AF_TLV
	};

	pb_stream attrval;
	if (!out_struct(&attr,
			&isakmp_xauth_attribute_desc,
			strattr,
			&attrval))
		return STF_INTERNAL_ERROR;

	switch (attr_type) {
	case INTERNAL_IP4_ADDRESS:
	{
		diag_t d = pbs_out_address(&attrval, ia, "IP_addr");
		if (d != NULL) {
			log_diag(RC_LOG_SERIOUS, attrval.out_logger, &d, "%s", "");
			return STF_INTERNAL_ERROR;
		}
		break;
	}

	case INTERNAL_IP4_SUBNET:
	{
		diag_t d = pbs_out_address(&attrval, &c->spd.this.client.addr, "IP4_subnet");
		if (d != NULL) {
			log_diag(RC_LOG_SERIOUS, attrval.out_logger, &d, "%s", "");
			return STF_INTERNAL_ERROR;
		}
	}
		/* FALL THROUGH */
	case INTERNAL_IP4_NETMASK:
	{
		int m = c->spd.this.client.maskbits;
		uint32_t mask = htonl(~(m == 32 ? (uint32_t)0 : ~(uint32_t)0 >> m));

		ok = out_raw(&mask, sizeof(mask), &attrval, "IP4_submsk");
		break;
	}

	case INTERNAL_IP4_DNS:
	{
		/*
		 * Emit one attribute per DNS IP.
		 * (All other cases emit exactly one attribute.)
		 * The first's emission is started above
		 * and the last's is finished at the end
		 * so our loop structure is odd.
		 */
		char *ipstr = strtok(c->modecfg_dns, ", ");

		while (ipstr != NULL) {
			ip_address dnsip;
			err_t e = ttoaddr_num(ipstr, 0, AF_INET, &dnsip);

			if (e != NULL) {
				loglog(RC_LOG_SERIOUS, "Invalid DNS IPv4 %s:%s", ipstr, e);
				return STF_INTERNAL_ERROR;
			}
			/* emit attribute's value */
			diag_t d = pbs_out_address(&attrval, &dnsip, "IP4_dns");
			if (d != NULL) {
				log_diag(RC_LOG_SERIOUS, attrval.out_logger, &d, "%s", "");
				return STF_INTERNAL_ERROR;
			}

			ipstr = strtok(NULL, ", ");
			if (ipstr != NULL) {
				/* end this attribute */
				close_output_pbs(&attrval);

				/* start the next attribute */
				if (!out_struct(&attr,
						&isakmp_xauth_attribute_desc,
						strattr,
						&attrval))
					return STF_INTERNAL_ERROR;
			}
		}
		break;
	}

	case MODECFG_DOMAIN:
	{
		/*
		 * IKEv2 allows more then one, separated by comma or space
		 * We don't know if existing IKEv1 implementations support
		 * more then one, so we just send the first one configured.
		 */
		char *first = strtok(c->modecfg_domains, ", ");
		if (first != NULL)
			ok = out_raw(first, strlen(first), &attrval, "MODECFG_DOMAIN");
		break;
	}

	case MODECFG_BANNER:
		ok = out_raw(c->modecfg_banner,
			     strlen(c->modecfg_banner),
			     &attrval, "");
		break;

	/* XXX: not sending if our end is 0.0.0.0/0 equals previous previous behaviour */
	case CISCO_SPLIT_INC:
	{
		/* XXX: bitstomask(c->spd.this.client.maskbits), */
		ip_address mask = subnet_mask(&c->spd.this.client);
		ip_address addr = subnet_prefix(&c->spd.this.client);
		struct CISCO_split_item i = {
			.cs_addr = { htonl(ntohl_address(&addr)), },
			.cs_mask = { htonl(ntohl_address(&mask)), },
		};

		ok = out_struct(&i, &CISCO_split_desc, &attrval, NULL);
		break;
	}
	default:
		libreswan_log(
			"attempt to send unsupported mode cfg attribute %s.",
			enum_show(&modecfg_attr_names,
				  attr_type));
		break;
	}

	if (!ok)
		return STF_INTERNAL_ERROR;

	close_output_pbs(&attrval);

	return STF_OK;
}

/**
 * Mode Config Reply
 *
 * Generates a reply stream containing Mode Config information (eg: IP, DNS, WINS)
 *
 * @param st State structure
 * @param resp Type of reply (lset_t)  ??? why singular -- this is a set?
 * @param pb_stream rbody Body of the reply (stream)
 * @param replytype int
 * @param use_modecfg_addr_as_client_addr bool
 *	True means force the IP assigned by Mode Config to be the
 *	spd.that.addr.  Useful when you know the client will change peers IP
 *	to be what was assigned immediately after authentication.
 * @param ap_id ISAMA Identifier
 * @return stf_status STF_OK or STF_INTERNAL_ERROR
 */
static stf_status modecfg_resp(struct state *st,
			lset_t resp,
			pb_stream *rbody,
			uint16_t replytype,
			bool use_modecfg_addr_as_client_addr,
			uint16_t ap_id)
{
	struct v1_hash_fixup hash_fixup;
	if (!emit_xauth_hash("XAUTH: mode config response",
			     st, &hash_fixup, rbody)) {
		return STF_INTERNAL_ERROR;
	}

	/* ATTR out */
	{
		pb_stream strattr;
		int attr_type;
		struct connection *c = st->st_connection;

		{
			struct isakmp_mode_attr attrh = {
				.isama_type = replytype,
				.isama_identifier = ap_id,
			};

			if (!out_struct(&attrh, &isakmp_attr_desc, rbody, &strattr))
				return STF_INTERNAL_ERROR;
		}

		/*
		 * Get an inside IP address, INTERNAL_IP4_ADDRESS and
		 * DNS if any for a connection
		 *
		 * XXX: since the code that follows only saves the
		 * address when USE_MODECFG_ADDR_AS_CLIENT_ADDR, can
		 * this leak?
		 *
		 * XXX: like for ikev2-hostpair-02, could this be
		 * re-assigning the same address?
		 */

		ip_address ia;
		if (use_modecfg_addr_as_client_addr &&
		    c->pool != NULL) {
			err_t e = lease_that_address(c, st);
			if (e != NULL) {
				log_state(RC_LOG, st, "lease_an_address failure %s", e);
				return STF_INTERNAL_ERROR;
			}
			ia = selector_prefix(&c->spd.that.client);
			address_buf iab;
			dbg("a lease %s", str_address(&ia, &iab));
		} else {
			pexpect(subnet_is_specified(&c->spd.that.client));
			ia = selector_prefix(&c->spd.that.client);
			address_buf iab;
			dbg("a client %s", str_address(&ia, &iab));
		}

		/* If we got DNS addresses, answer with those */
		if (c->modecfg_dns != NULL)
			resp |= LELEM(INTERNAL_IP4_DNS);
		else
			resp &= ~LELEM(INTERNAL_IP4_DNS);

		/* Send the attributes requested by the client. */
		attr_type = 0;
		while (resp != LEMPTY) {
			if (resp & 1) {
				stf_status ret = isakmp_add_attr(&strattr, attr_type, &ia, st);
				if (ret != STF_OK)
					return ret;
			}
			attr_type++;
			resp >>= 1;
		}

		/*
		 * Send these even if the client didn't request them. Due
		 * to and unwise use of a bitmask the limited range of lset_t
		 * causes us to loose track of whether the client requested
		 * them. No biggie, the MODECFG draft allows us to send
		 * attributes that the client didn't request and if we set
		 * MODECFG_DOMAIN and MODECFG_BANNER in connection
		 * configuration we probably want the client to see them
		 * anyway.
		 * ??? might we be sending them twice?
		 */
		if (c->modecfg_domains != NULL) {
			dbg("We are sending '%s' as domain", strtok(c->modecfg_domains, ", "));
			isakmp_add_attr(&strattr, MODECFG_DOMAIN, &ia, st);
		} else {
			dbg("we are not sending a domain");
		}

		if (c->modecfg_banner != NULL) {
			dbg("We are sending '%s' as banner", c->modecfg_banner);
			isakmp_add_attr(&strattr, MODECFG_BANNER, &ia, st);
		} else {
			dbg("We are not sending a banner");
		}

		if (isanyaddr(&c->spd.this.client.addr)) {
			dbg("We are 0.0.0.0/0 so not sending CISCO_SPLIT_INC");
		} else {
			dbg("We are sending our subnet as CISCO_SPLIT_INC");
			isakmp_add_attr(&strattr, CISCO_SPLIT_INC, &ia, st);
		}

		if (!ikev1_close_message(&strattr, st))
			return STF_INTERNAL_ERROR;
	}

	fixup_xauth_hash(st, &hash_fixup, rbody->cur);

	if (!ikev1_close_message(rbody, st) ||
	    !ikev1_encrypt_message(rbody, st))
		return STF_INTERNAL_ERROR;

	return STF_OK;
}

/** Set MODE_CONFIG data to client.  Pack IP Addresses, DNS, etc... and ship
 *
 * @param st State Structure
 * @return stf_status
 */
static stf_status modecfg_send_set(struct state *st)
{
	/* set up reply */
	uint8_t buf[256];
	struct pbs_out reply = open_pbs_out("ModecfgR1", buf, sizeof(buf), st->st_logger);

	change_state(st, STATE_MODE_CFG_R1);
	/* HDR out */
	struct pbs_out rbody;
	{
		struct isakmp_hdr hdr = {
			.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
				  ISAKMP_MINOR_VERSION,
			.isa_xchg = ISAKMP_XCHG_MODE_CFG,
			.isa_flags = ISAKMP_FLAGS_v1_ENCRYPTION,
			.isa_msgid = st->st_v1_msgid.phase15,
		};

		if (impair.send_bogus_isakmp_flag) {
			hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
		}

		hdr.isa_ike_initiator_spi = st->st_ike_spis.initiator;
		hdr.isa_ike_responder_spi = st->st_ike_spis.responder;

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply, &rbody))
			return STF_INTERNAL_ERROR;
	}

#ifdef SOFTREMOTE_CLIENT_WORKAROUND
	/* see: http://popoludnica.pl/?id=10100110 */
	/* should become a conn option */
	/* client-side is not yet implemented for this - only works with SoftRemote clients */
	/* SoftRemote takes the IV for XAUTH from phase2, where Libreswan takes it from phase1 */
	init_phase2_iv(st, &st->st_v1_msgid.phase15);
#endif

/* XXX This does not include IPv6 at this point */
#define MODECFG_SET_ITEM (LELEM(INTERNAL_IP4_ADDRESS) | \
			  LELEM(INTERNAL_IP4_SUBNET) | \
			  LELEM(INTERNAL_IP4_DNS))

	stf_status stat = modecfg_resp(st,
		     MODECFG_SET_ITEM,
		     &rbody,
		     ISAKMP_CFG_SET,
		     TRUE,
		     0 /* XXX ID */);

	if (stat != STF_OK)
		return stat;
#undef MODECFG_SET_ITEM

	/* Transmit */
	record_and_send_v1_ike_msg(st, &reply, "ModeCfg set");

	if (state_event(st, EVENT_RETRANSMIT) == NULL) {
		delete_event(st);
		clear_retransmits(st);
		start_retransmits(st);
	}

	return STF_OK;
}

/** Set MODE_CONFIG data to client.  Pack IP Addresses, DNS, etc... and ship
 *
 * @param st State Structure
 * @return stf_status
 */
stf_status modecfg_start_set(struct state *st)
{
	if (st->st_v1_msgid.phase15 == v1_MAINMODE_MSGID) {
		/* pick a new message id */
		st->st_v1_msgid.phase15 = generate_msgid(st);
	}
	st->hidden_variables.st_modecfg_vars_set = TRUE;

	return modecfg_send_set(st);
}

/*
 * Send XAUTH credential request (username + password request)
 * @param st State
 * @return stf_status
 */
stf_status xauth_send_request(struct state *st)
{
	const enum state_kind p_state = st->st_state->kind;

	/* set up reply */
	uint8_t buf[256];
	struct pbs_out reply = open_pbs_out("xauth_buf", buf, sizeof(buf), st->st_logger);

	libreswan_log("XAUTH: Sending Username/Password request (%s->XAUTH_R0)",
		      st->st_state->short_name);

	/* this is the beginning of a new exchange */
	st->st_v1_msgid.phase15 = generate_msgid(st);
	change_state(st, STATE_XAUTH_R0);

	/* HDR out */
	struct pbs_out rbody;
	{
		struct isakmp_hdr hdr = {
			.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
				  ISAKMP_MINOR_VERSION,
			.isa_xchg = ISAKMP_XCHG_MODE_CFG,
			.isa_flags = ISAKMP_FLAGS_v1_ENCRYPTION,
			.isa_msgid = st->st_v1_msgid.phase15,
		};

		if (impair.send_bogus_isakmp_flag) {
			hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
		}
		hdr.isa_ike_initiator_spi = st->st_ike_spis.initiator;
		hdr.isa_ike_responder_spi = st->st_ike_spis.responder;

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply, &rbody))
			return STF_INTERNAL_ERROR;
	}

	struct v1_hash_fixup hash_fixup;
	if (!emit_xauth_hash("XAUTH: send request",
			     st, &hash_fixup, &rbody)) {
		return STF_INTERNAL_ERROR;
	}

	/* ATTR out */
	{
		struct isakmp_mode_attr attrh = {
			.isama_type = ISAKMP_CFG_REQUEST,
			.isama_identifier = 0,
		};
		pb_stream strattr;

		/* Empty name attribute */
		struct isakmp_attribute nm = {
			.isaat_af_type = XAUTH_USER_NAME,
		};

		/* Empty password attribute */
		struct isakmp_attribute pw = {
			.isaat_af_type = XAUTH_USER_PASSWORD,
		};

		if (!out_struct(&attrh, &isakmp_attr_desc, &rbody, &strattr) ||
		    !out_struct(&nm, &isakmp_xauth_attribute_desc, &strattr,
				NULL) ||
		    !out_struct(&pw, &isakmp_xauth_attribute_desc, &strattr,
				NULL) ||
		    !ikev1_close_message(&strattr, st))
			return STF_INTERNAL_ERROR;
	}

	fixup_xauth_hash(st, &hash_fixup, rbody.cur);

	if (!ikev1_close_message(&rbody, st))
			return STF_INTERNAL_ERROR;

	close_output_pbs(&reply);

	init_phase2_iv(st, &st->st_v1_msgid.phase15);

	if (!ikev1_encrypt_message(&rbody, st))
		return STF_INTERNAL_ERROR;

	/* Transmit */
	if (!impair.send_no_xauth_r0) {
		if (p_state == STATE_AGGR_R2) {
			record_and_send_v1_ike_msg(st, &reply, "XAUTH: req");
		} else {
			/*
			 * Main Mode responder: do not record XAUTH_R0 message.
			 * If retransmit timer goes off, retransmit the last
			 * Main Mode message and send/create a new XAUTH_R0
			 * message.
			 */
			send_ike_msg_without_recording(st, &reply,
					"XAUTH: req");
		}
	} else {
		libreswan_log("IMPAIR: Skipped sending XAUTH user/pass packet");
		if (p_state == STATE_AGGR_R2) {
			/* record-only so we properly emulate packet drop */
			record_outbound_v1_ike_msg(st, &reply, "XAUTH: req");
		}
	}

	if (state_event(st, EVENT_RETRANSMIT) == NULL) {
		delete_event(st);
		clear_retransmits(st);
		start_retransmits(st);
	}

	return STF_OK;
}

/** Send modecfg IP address request (IP4 address)
 * @param st State
 * @return stf_status
 */
stf_status modecfg_send_request(struct state *st)
{
	/* set up reply */
	uint8_t buf[256];
	struct pbs_out reply = open_pbs_out("xauth_buf", buf, sizeof(buf), st->st_logger);

	libreswan_log("modecfg: Sending IP request (MODECFG_I1)");

	/* this is the beginning of a new exchange */
	st->st_v1_msgid.phase15 = generate_msgid(st);
	change_state(st, STATE_MODE_CFG_I1);

	/* HDR out */
	struct pbs_out rbody;
	{
		struct isakmp_hdr hdr = {
			.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
				  ISAKMP_MINOR_VERSION,
			.isa_xchg = ISAKMP_XCHG_MODE_CFG,
			.isa_flags = ISAKMP_FLAGS_v1_ENCRYPTION,
			.isa_msgid = st->st_v1_msgid.phase15,
		};

		if (impair.send_bogus_isakmp_flag) {
			hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
		}

		hdr.isa_ike_initiator_spi = st->st_ike_spis.initiator;
		hdr.isa_ike_responder_spi = st->st_ike_spis.responder;

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply, &rbody))
			return STF_INTERNAL_ERROR;
	}

	struct v1_hash_fixup hash_fixup;
	if (!emit_xauth_hash("XAUTH: mode config request",
			     st, &hash_fixup, &rbody)) {
		return STF_INTERNAL_ERROR;
	}

	/* ATTR out */
	{
		struct isakmp_mode_attr attrh = {
			.isama_type = ISAKMP_CFG_REQUEST,
			.isama_identifier = 0,
		};
		pb_stream strattr;

		if (!out_struct(&attrh, &isakmp_attr_desc, &rbody, &strattr))
			return STF_INTERNAL_ERROR;

		/* generate LOT of empty attributes */
		static const uint16_t at[] = {
			INTERNAL_IP4_ADDRESS, INTERNAL_IP4_NETMASK,
			INTERNAL_IP4_DNS, MODECFG_BANNER, MODECFG_DOMAIN,
			CISCO_SPLIT_INC, 0  };

		for (const uint16_t *p = at; *p != 0; p++) {
			struct isakmp_attribute attr = {
				.isaat_af_type = *p,
			};
			if (!out_struct(&attr, &isakmp_xauth_attribute_desc,
					&strattr, NULL))
				return STF_INTERNAL_ERROR;
		}

		if (!ikev1_close_message(&strattr, st))
			return STF_INTERNAL_ERROR;
	}

	fixup_xauth_hash(st, &hash_fixup, rbody.cur);

	if (!ikev1_close_message(&rbody, st))
		return STF_INTERNAL_ERROR;

	close_output_pbs(&reply);

	init_phase2_iv(st, &st->st_v1_msgid.phase15);

	if (!ikev1_encrypt_message(&rbody, st))
		return STF_INTERNAL_ERROR;

	/* Transmit */
	record_and_send_v1_ike_msg(st, &reply, "modecfg: req");

	if (state_event(st, EVENT_RETRANSMIT) == NULL) {
		delete_event(st);
		clear_retransmits(st);
		start_retransmits(st);
	}
	st->hidden_variables.st_modecfg_started = TRUE;

	return STF_OK;
}

/** Send XAUTH status to client
 *
 * @param st State
 * @param status Status code
 * @return stf_status
 */
/* IN AN AUTH THREAD */
static stf_status xauth_send_status(struct state *st, int status)
{
	/* set up reply */
	uint8_t buf[256];
	struct pbs_out reply = open_pbs_out("xauth_buf", buf, sizeof(buf), st->st_logger);

	/* pick a new message id */
	st->st_v1_msgid.phase15 = generate_msgid(st);

	/* HDR out */
	struct pbs_out rbody;
	{
		struct isakmp_hdr hdr = {
			.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
				  ISAKMP_MINOR_VERSION,
			.isa_xchg = ISAKMP_XCHG_MODE_CFG,
			.isa_flags = ISAKMP_FLAGS_v1_ENCRYPTION,
			.isa_msgid = st->st_v1_msgid.phase15,
		};

		if (impair.send_bogus_isakmp_flag) {
			hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
		}
		hdr.isa_ike_initiator_spi = st->st_ike_spis.initiator;
		hdr.isa_ike_responder_spi = st->st_ike_spis.responder;

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply, &rbody))
			return STF_INTERNAL_ERROR;
	}

	struct v1_hash_fixup hash_fixup;
	if (!emit_xauth_hash("XAUTH: status", st, &hash_fixup, &rbody)) {
		return STF_INTERNAL_ERROR;
	}

	/* ATTR out */
	{
		struct isakmp_mode_attr attrh = {
			.isama_type = ISAKMP_CFG_SET,
			.isama_identifier = 0,
		};
		pb_stream strattr;
		/* ISAKMP attr out (status) */
		struct isakmp_attribute attr = {
			.isaat_af_type = XAUTH_STATUS | ISAKMP_ATTR_AF_TV,
			.isaat_lv = status,
		};

		if (!out_struct(&attrh, &isakmp_attr_desc, &rbody, &strattr) ||
		    !out_struct(&attr, &isakmp_xauth_attribute_desc, &strattr,
				NULL) ||
		    !ikev1_close_message(&strattr, st))
			return STF_INTERNAL_ERROR;
	}

	fixup_xauth_hash(st, &hash_fixup, rbody.cur);

	if (!ikev1_close_message(&rbody, st))
		return STF_INTERNAL_ERROR;

	close_output_pbs(&reply);

	init_phase2_iv(st, &st->st_v1_msgid.phase15);

	if (!ikev1_encrypt_message(&rbody, st))
		return STF_INTERNAL_ERROR;

	/* Set up a retransmission event, half a minute hence */
	/* Schedule retransmit before sending, to avoid race with main thread */
	delete_event(st);
	clear_retransmits(st);
	start_retransmits(st);

	/* Transmit */
	record_and_send_v1_ike_msg(st, &reply, "XAUTH: status");

	if (status != 0)
		change_state(st, STATE_XAUTH_R1);

	return STF_OK;
}

static bool add_xauth_addresspool(struct connection *c,
				  const char *userid,
				  const char *addresspool)
{
	/* set user defined ip address or pool */
	bool ret = FALSE;
	err_t er;
	ip_range pool_range;

	if (strchr(addresspool, '-') == NULL) {
		/* convert single ip address to addresspool */
		char single_addresspool[128];

		snprintf(single_addresspool, sizeof(single_addresspool),
			"%s-%s",
			addresspool, addresspool);
		dbg("XAUTH: adding single ip addresspool entry %s for the conn %s user=%s",
		    single_addresspool, c->name, userid);
		er = ttorange(single_addresspool, &ipv4_info, &pool_range);
	} else {
		dbg("XAUTH: adding addresspool entry %s for the conn %s user %s",
		    addresspool, c->name, userid);
		er = ttorange(addresspool, &ipv4_info, &pool_range);
	}
	if (er != NULL) {
		libreswan_log("XAUTH IP address %s is not valid %s user=%s",
			addresspool, er, userid);
	} else {
		/* install new addresspool */

		/* delete existing pool if it exists */
		if (c->pool != NULL) {
			free_that_address_lease(c);
			unreference_addresspool(c);
		}

		c->pool = install_addresspool(&pool_range);
		if (c->pool != NULL) {
			reference_addresspool(c);
			ret = TRUE;
		}
	}

	return ret;
}

/** Do authentication via /etc/ipsec.d/passwd file using MD5 passwords
 *
 * Structure is one entry per line.
 * Each line has fields separated by colons.
 * Empty lines and lines starting with # are ignored.
 * Whitespace is NOT ignored.
 *
 * Syntax of an entry:
 *	username:passwdhash[:connectioname[:addresspool]]
 *
 * If connectionname is present and not empty,
 * the entry only applies to connections with that name.
 * Otherwise the entry applies to all connections.
 *
 * Example creation of file with two entries (without connectionname):
 *	htpasswd -c -b /etc/ipsec.d/passwd road roadpass
 *	htpasswd -b /etc/ipsec.d/passwd home homepass
 *
 * NOTE: htpasswd on your system may create a crypt() incompatible hash
 * by default (i.e. a type id of $apr1$). To create a crypt() compatible
 * hash with htpasswd use the -d option.
 *
 * @return bool success
 */

static bool do_file_authentication(struct state *st, const char *name,
				   const char *password, const char *connname)
{
	char pswdpath[PATH_MAX];
	char line[1024]; /* we hope that this is more than enough */
	int lineno = 0;
	bool win = FALSE;

	snprintf(pswdpath, sizeof(pswdpath), "%s/passwd", lsw_init_options()->confddir);

	FILE *fp = fopen(pswdpath, "r");
	if (fp == NULL) {
		/* unable to open the password file */
		libreswan_log(
			"XAUTH: unable to open password file (%s) for verification",
			pswdpath);
		return FALSE;
	}

	libreswan_log("XAUTH: password file (%s) open.", pswdpath);

	/** simple stuff read in a line then go through positioning
	 * userid, passwd and conniectionname at the beginning of each of the
	 * memory locations of our real data and replace the ':' with '\0'
	 */

	while (fgets(line, sizeof(line), fp) != NULL) {
		char *p;	/* current position */
		char *userid;
		char *passwdhash;
		char *connectionname = NULL;
		char *addresspool = NULL;
		struct connection *c = st->st_connection;

		lineno++;

		/* strip final \n (optional: we accept a partial last line) */
		p = strchr(line, '\n');
		if (p != NULL)
			*p = '\0';

		/* ignore empty or comment line */
		if (*line == '\0' || *line == '#')
			continue;

		/* get userid */
		userid = line;
		p = strchr(userid, ':');	/* find end */
		if (p == NULL) {
			/* no end: skip line */
			libreswan_log("XAUTH: %s:%d missing password hash field", pswdpath, lineno);
			continue;
		}

		*p++ ='\0'; /* terminate string by overwriting : */

		/* get password hash */
		passwdhash = p;
		p = strchr(passwdhash, ':'); /* find end */
		if (p != NULL) {
			/* optional connectionname */
			*p++='\0';     /* terminate string by overwriting : */
			connectionname = p;
			p = strchr(connectionname, ':'); /* find end */
			/* ??? any whitespace is included */
		}

		if (p != NULL) {
			/* optional addresspool */
			*p++ ='\0'; /* terminate connectionname string by overwriting : */
			addresspool = p;
		}

		/* now connnectionname is terminated; set to NULL if empty */
		if (connectionname != NULL && connectionname[0] == '\0')
			connectionname = NULL;

		dbg("XAUTH: found user(%s/%s) pass(%s) connid(%s/%s) addresspool(%s)",
		    userid, name, passwdhash,
		    connectionname == NULL ? "" : connectionname,
		    connname,
		    addresspool == NULL ? "" : addresspool);

		/* If connectionname is null, it applies to all connections */
		if (streq(userid, name) &&
		    (connectionname == NULL || streq(connectionname, connname)))
		{
			const char *cp;
			/*
			 * keep the passwords using whatever utilities
			 * we have NOTE: crypt() may not be
			 * thread-safe
			 */
			cp = crypt(password, passwdhash);
			win = cp != NULL && streq(cp, passwdhash);

			DBGF(DBG_CRYPT, "XAUTH: %s user(%s:%s) pass %s vs %s",
			     win ? "success" : "failure",
			     userid, connectionname, cp, passwdhash);

			libreswan_log("XAUTH: %s user(%s:%s) ",
				win ? "success" : "failure",
				userid, connectionname);

			if (win) {
				if (addresspool != NULL && addresspool[0] != '\0') {
					/* ??? failure to add addresspool seems like a funny failure */
					/* ??? should we then keep trying other entries? */
					if (!add_xauth_addresspool(c, userid,
								   addresspool)) {
						win = FALSE;
						continue;	/* try other entries */
					}
				}
				break;	/* we have a winner */
			}
		}
	}

	fclose(fp);
	return win;
}

/*
 * Main authentication routine will then call the actual compiled-in
 * method to verify the user/password
 */

static pamauth_callback_t ikev1_xauth_callback;	/* type assertion */

static void ikev1_xauth_callback(struct state *st,
				 struct msg_digest *md UNUSED,
				 const char *name, bool results)
{
	/*
	 * If XAUTH authentication failed, should we soft fail or hard fail?
	 * The soft fail mode is used to bring up the SA in a walled garden.
	 * This can be detected in the updown script by the env variable XAUTH_FAILED=1
	 */
	if (!results && st->st_connection->xauthfail == XAUTHFAIL_SOFT) {
		libreswan_log("XAUTH: authentication for %s failed, but policy is set to soft fail",
			      name);
		st->st_xauth_soft = TRUE; /* passed to updown for notification */
		results = TRUE;
	}

	if (results) {
		libreswan_log("XAUTH: User %s: Authentication Successful",
			      name);
		/* ??? result of xauth_send_status is ignored */
		xauth_send_status(st, XAUTH_STATUS_OK);

		if (st->quirks.xauth_ack_msgid)
			st->st_v1_msgid.phase15 = v1_MAINMODE_MSGID;

		jam_str(st->st_xauth_username, sizeof(st->st_xauth_username), name);
	} else {
		/*
		 * Login attempt failed, display error, send XAUTH status to client
		 * and reset state to XAUTH_R0
		 */
		libreswan_log("XAUTH: User %s: Authentication Failed: Incorrect Username or Password",
			      name);
		/* ??? result of xauth_send_status is ignored */
		xauth_send_status(st, XAUTH_STATUS_FAIL);
	}
}

/*
 * Schedule the XAUTH callback for NOW so it is (we hope) run next.
 *
 * This way all xauth mechanisms use the same code paths - suspend
 * state and then finish things in ikev1_xauth_callback().
 */

struct xauth_immediate_context {
	bool success;
	so_serial_t serialno;
	char *name;
};

static resume_cb xauth_immediate_callback;
static stf_status xauth_immediate_callback(struct state *st,
					   struct msg_digest *md,
					   void *arg)
{
	struct xauth_immediate_context *xic = (struct xauth_immediate_context *)arg;
	if (st == NULL) {
		libreswan_log("XAUTH: #%lu: state destroyed for user '%s'",
			      xic->serialno, xic->name);
	} else {
		/* ikev1_xauth_callback() will log result */
		ikev1_xauth_callback(st, md, xic->name, xic->success);
	}
	pfree(xic->name);
	pfree(xic);
	return STF_SKIP_COMPLETE_STATE_TRANSITION;
}

static void xauth_immediate(const char *name, const struct state *st, bool success)
{
	struct xauth_immediate_context *xic = alloc_thing(struct xauth_immediate_context, "xauth next");
	xic->success = success;
	xic->serialno = st->st_serialno;
	xic->name = clone_str(name, "xauth next name");
	schedule_resume("xauth immediate", st->st_serialno,
			xauth_immediate_callback, xic);
}

/** Launch an authentication prompt
 *
 * @param st State Structure
 * @param name Username
 * @param password Password
 */
static void xauth_launch_authent(struct state *st,
				chunk_t *name,
				chunk_t *password)
{
	/*
	 * XAUTH somehow already in progress?
	 */
#ifdef AUTH_HAVE_PAM
	if (st->st_pamauth != NULL)
		return;
#endif

	char *arg_name = clone_hunk_as_string(*name, "NUL-terminated XAUTH name");
	char *arg_password = clone_hunk_as_string(*password, "NUL-terminated XAUTH password");

	/*
	 * For XAUTH, we're flipping between retransmitting the packet
	 * in the retransmit slot, and the XAUTH packet.
	 * Two alternative events can be outstanding. Cancel both.
	 */
	delete_event(st);
	clear_retransmits(st);
	event_delete(EVENT_v1_SEND_XAUTH, st);

	switch (st->st_connection->xauthby) {
#ifdef AUTH_HAVE_PAM
	case XAUTHBY_PAM:
		libreswan_log("XAUTH: PAM authentication method requested to authenticate user '%s'",
			      arg_name);
		auth_fork_pam_process(st,
				       arg_name, arg_password,
				       "XAUTH",
				       ikev1_xauth_callback);
		event_schedule(EVENT_PAM_TIMEOUT, EVENT_PAM_TIMEOUT_DELAY, st);
		break;
#endif

	case XAUTHBY_FILE:
		libreswan_log("XAUTH: password file authentication method requested to authenticate user '%s'",
			      arg_name);
		bool success = do_file_authentication(st, arg_name, arg_password, st->st_connection->name);
		xauth_immediate(arg_name, st, success);
		break;

	case XAUTHBY_ALWAYSOK:
		libreswan_log("XAUTH: authentication method 'always ok' requested to authenticate user '%s'",
			      arg_name);
		xauth_immediate(arg_name, st, true);
		break;

	default:
		libreswan_log("XAUTH: unknown authentication method requested to authenticate user '%s'",
			      arg_name);
		bad_case(st->st_connection->xauthby);
	}

	pfreeany(arg_name);
	pfreeany(arg_password);
}

/* log a nice description of an unsupported attribute */
static void log_bad_attr(const char *kind, enum_names *ed, unsigned val)
{
	dbg("Unsupported %s %s attribute %s received.",
	    kind,
	    (val & ISAKMP_ATTR_AF_MASK) == ISAKMP_ATTR_AF_TV ? "basic" : "long",
	    enum_show(ed, val & ISAKMP_ATTR_RTYPE_MASK));
}

/*
 * STATE_XAUTH_R0:
 * First REQUEST sent, expect for REPLY
 * HDR*, HASH, ATTR(REPLY,PASSWORD) --> HDR*, HASH, ATTR(STATUS)
 *
 * @param md Message Digest
 * @return stf_status
 */
stf_status xauth_inR0(struct state *st, struct msg_digest *md)
{
	pb_stream *attrs = &md->chain[ISAKMP_NEXT_MCFG_ATTR]->pbs;

	/*
	 * There are many ways out of this routine
	 * so we don't want an obligation to free anything.
	 * We manage this by making these chunks just
	 * references to parts of the input packet.
	 */
	static unsigned char unknown[] = "<unknown>";	/* never written to */
	chunk_t name;
	chunk_t password = EMPTY_CHUNK;
	bool gotname = FALSE,
		gotpassword = FALSE;

	name = chunk2(unknown, sizeof(unknown) - 1);	/* to make diagnostics easier */

	/* XXX This needs checking with the proper RFC's - ISAKMP_CFG_ACK got added for Cisco interop */
	switch (md->chain[ISAKMP_NEXT_MCFG_ATTR]->payload.mode_attribute.isama_type) {
	case ISAKMP_CFG_REPLY:
	case ISAKMP_CFG_ACK:
		break;	/* OK */
	default:
		libreswan_log(
			"Expecting MODE_CFG_REPLY; got %s instead.",
			enum_name(&attr_msg_type_names,
				  md->chain[ISAKMP_NEXT_MCFG_ATTR]->payload.
				  mode_attribute.isama_type));
		return STF_IGNORE;
	}

	while (pbs_left(attrs) >= isakmp_xauth_attribute_desc.size) {
		struct isakmp_attribute attr;
		pb_stream strattr;
		size_t sz;

		if (!in_struct(&attr, &isakmp_xauth_attribute_desc,
			       attrs, &strattr)) {
			/* fail if malformed */
			return STF_FAIL;
		}

		switch (attr.isaat_af_type) {
		case XAUTH_TYPE | ISAKMP_ATTR_AF_TV:
			/* since we only accept XAUTH_TYPE_GENERIC we don't need to record this attribute */
			if (attr.isaat_lv != XAUTH_TYPE_GENERIC) {
				dbg("unsupported XAUTH_TYPE value %s received",
				    enum_show(&xauth_type_names, attr.isaat_lv));
				return STF_FAIL + NO_PROPOSAL_CHOSEN;
			}
			break;

		case XAUTH_USER_NAME | ISAKMP_ATTR_AF_TLV:
			if (gotname) {
				dbg("XAUTH: two User Names!  Rejected");
				return STF_FAIL + NO_PROPOSAL_CHOSEN;
			}
			sz = pbs_left(&strattr);
			if (strnlen((const char *)strattr.cur, sz) != sz) {
				libreswan_log(
					"XAUTH User Name contains NUL character: rejected");
				return STF_FAIL + NO_PROPOSAL_CHOSEN;
			}
			name = chunk2(strattr.cur, sz);
			gotname = TRUE;
			break;

		case XAUTH_USER_PASSWORD | ISAKMP_ATTR_AF_TLV:
			if (gotpassword) {
				libreswan_log(
					"XAUTH: two User Passwords!  Rejected");
				return STF_FAIL + NO_PROPOSAL_CHOSEN;
			}
			sz = pbs_left(&strattr);
			if (sz > 0 && strattr.cur[sz-1] == '\0') {
				libreswan_log(
					"Ignoring NUL at end of XAUTH User Password (Android Issue 36879?)");
				sz--;
			}
			if (strnlen((const char *)strattr.cur, sz) != sz) {
				libreswan_log(
					"XAUTH User Password contains NUL character: rejected");
				return STF_FAIL + NO_PROPOSAL_CHOSEN;
			}
			password = chunk2(strattr.cur, sz);
			gotpassword = TRUE;
			break;

		default:
			log_bad_attr("XAUTH (inR0)", &xauth_attr_names, attr.isaat_af_type);
			break;
		}
	}

	/** we must get a username and a password value */
	if (!gotname || !gotpassword) {
		libreswan_log(
			"Expected MODE_CFG_REPLY is missing %s%s%s attribute",
			!gotname ? "username" : "",
			!gotname && !gotpassword ? " and " : "",
			!gotpassword ? "password" : "");
		if (st->hidden_variables.st_xauth_client_attempt++ <
		    XAUTH_PROMPT_TRIES) {
			stf_status stat = xauth_send_request(st);

			libreswan_log(
				"XAUTH: User %.*s: Authentication Failed (retry %d)",
				(int)name.len, name.ptr,
				st->hidden_variables.st_xauth_client_attempt);
			/**
			 * STF_OK means that we transmitted again okay, but actually
			 * the state transition failed, as we are prompting again.
			 */
			return stat == STF_OK ? STF_IGNORE : stat;
		} else {
			stf_status stat = xauth_send_status(st, XAUTH_STATUS_FAIL);

			libreswan_log(
				"XAUTH: User %.*s: Authentication Failed (Retried %d times)",
				(int)name.len, name.ptr,
				st->hidden_variables.st_xauth_client_attempt);

			return stat == STF_OK ? STF_FAIL : stat;
		}
	} else {
		xauth_launch_authent(st, &name, &password);
		return STF_SUSPEND;
	}
}

/*
 * STATE_XAUTH_R1:
 * STATUS sent, expect for ACK
 * HDR*, ATTR(STATUS), HASH --> Done
 *
 * @param md Message Digest
 * @return stf_status
 */
stf_status xauth_inR1(struct state *st, struct msg_digest *md UNUSED)
{
	libreswan_log("XAUTH: xauth_inR1(STF_OK)");
	/* Back to where we were */
	st->st_oakley.doing_xauth = FALSE;

	if (!st->st_connection->spd.this.modecfg_server) {
		dbg("not server, starting new exchange");
		st->st_v1_msgid.phase15 = v1_MAINMODE_MSGID;
	}

	if (st->st_connection->spd.this.modecfg_server &&
	    st->hidden_variables.st_modecfg_vars_set) {
		dbg("modecfg server, vars are set. Starting new exchange.");
		st->st_v1_msgid.phase15 = v1_MAINMODE_MSGID;
	}

	if (st->st_connection->spd.this.modecfg_server &&
	    st->st_connection->policy & POLICY_MODECFG_PULL) {
		dbg("modecfg server, pull mode. Starting new exchange.");
		st->st_v1_msgid.phase15 = v1_MAINMODE_MSGID;
	}
	return STF_OK;
}

/*
 * STATE_MODE_CFG_R0:
 * HDR*, HASH, ATTR(REQ=IP) --> HDR*, HASH, ATTR(REPLY=IP)
 *
 * This state occurs both in the responder and in the initiator.
 *
 * In the responding server, it occurs when the client *asks* for an IP
 * address or other information.
 *
 * Otherwise, it occurs in the initiator when the server sends a challenge
 * a set, or has a reply to our request.
 *
 * @param md Message Digest
 * @return stf_status
 */
stf_status modecfg_inR0(struct state *st, struct msg_digest *md)
{
	struct pbs_out rbody;
	ikev1_init_pbs_out_from_md_hdr(md, TRUE,
				       &reply_stream, reply_buffer, sizeof(reply_buffer),
				       &rbody, st->st_logger);

	struct isakmp_mode_attr *ma = &md->chain[ISAKMP_NEXT_MCFG_ATTR]->payload.mode_attribute;
	pb_stream *attrs = &md->chain[ISAKMP_NEXT_MCFG_ATTR]->pbs;
	lset_t resp = LEMPTY;

	dbg("arrived in modecfg_inR0");

	st->st_v1_msgid.phase15 = md->hdr.isa_msgid;

	switch (ma->isama_type) {
	default:
		libreswan_log(
			"Expecting ISAKMP_CFG_REQUEST, got %s instead (ignored).",
			enum_name(&attr_msg_type_names,
				  ma->isama_type));
		/* ??? what should we do here?  Pretend all is well? */
		break;

	case ISAKMP_CFG_REQUEST:
		while (pbs_left(attrs) >= isakmp_xauth_attribute_desc.size) {
			/* ??? this looks kind of fishy:
			 * - what happens if attributes are repeated (resp cannot record that)?
			 * - who actually parses the subattributes to see if they are OK?
			 */
			struct isakmp_attribute attr;
			pb_stream strattr;

			if (!in_struct(&attr,
				       &isakmp_xauth_attribute_desc,
				       attrs,
				       &strattr)) {
				/* reject malformed */
				return STF_FAIL;
			}
			switch (attr.isaat_af_type) {
			case INTERNAL_IP4_ADDRESS | ISAKMP_ATTR_AF_TLV:
			case INTERNAL_IP4_NETMASK | ISAKMP_ATTR_AF_TLV:
			case INTERNAL_IP4_DNS | ISAKMP_ATTR_AF_TLV:
			case INTERNAL_IP4_SUBNET | ISAKMP_ATTR_AF_TLV:
				resp |= LELEM(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);
				break;
			case INTERNAL_IP4_NBNS | ISAKMP_ATTR_AF_TLV:
				/* ignore */
				break;

			default:
				log_bad_attr("modecfg (CFG_REQUEST)", &modecfg_attr_names, attr.isaat_af_type);
				break;
			}
		}

		{
			stf_status stat = modecfg_resp(st, resp,
						       &rbody,
						       ISAKMP_CFG_REPLY,
						       TRUE,
						       ma->isama_identifier);

			if (stat != STF_OK) {
				/* notification payload - not exactly the right choice, but okay */
				md->v1_note = CERTIFICATE_UNAVAILABLE;
				return stat;
			}
		}

		/* they asked us, we reponded, msgid is done */
		st->st_v1_msgid.phase15 = v1_MAINMODE_MSGID;
	}

	libreswan_log("modecfg_inR0(STF_OK)");
	return STF_OK;
}

/*
 * STATE_MODE_CFG_R2:
 * HDR*, HASH, ATTR(SET=IP) --> HDR*, HASH, ATTR(ACK,OK)
 *
 * used in server push mode, on the client (initiator).
 *
 * @param md Message Digest
 * @return stf_status
 */
static stf_status modecfg_inI2(struct msg_digest *md, pb_stream *rbody)
{
	struct state *const st = md->st;
	struct isakmp_mode_attr *ma = &md->chain[ISAKMP_NEXT_MCFG_ATTR]->payload.mode_attribute;
	pb_stream *attrs = &md->chain[ISAKMP_NEXT_MCFG_ATTR]->pbs;
	uint16_t isama_id = ma->isama_identifier;
	lset_t resp = LEMPTY;

	dbg("modecfg_inI2");

	st->st_v1_msgid.phase15 = md->hdr.isa_msgid;

	/* CHECK that SET has been received. */

	if (ma->isama_type != ISAKMP_CFG_SET) {
		libreswan_log(
			"Expecting MODE_CFG_SET, got %x instead.",
			ma->isama_type);
		return STF_IGNORE;
	}

	while (pbs_left(attrs) >= isakmp_xauth_attribute_desc.size) {
		struct isakmp_attribute attr;
		pb_stream strattr;

		if (!in_struct(&attr, &isakmp_xauth_attribute_desc,
			       attrs, &strattr)) {
			/* reject malformed */
			return STF_FAIL;
		}

		switch (attr.isaat_af_type) {
		case INTERNAL_IP4_ADDRESS | ISAKMP_ATTR_AF_TLV:
		{
			struct connection *c = st->st_connection;

			ip_address a;
			if (!pbs_in_address(&a, &ipv4_info, &strattr, "addr")) {
				return STF_FATAL;
			}
			endtosubnet(&a, &c->spd.this.client, HERE);

			c->spd.this.has_client = TRUE;
			subnet_buf caddr;
			str_subnet(&c->spd.this.client, &caddr);
			loglog(RC_LOG, "Received IP address %s", caddr.buf);

			if (!address_is_specified(&c->spd.this.host_srcip)) {
				libreswan_log("setting ip source address to %s",
					      caddr.buf);
				c->spd.this.host_srcip = a;
			}
			resp |= LELEM(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);
			break;
		}

		case INTERNAL_IP4_NETMASK | ISAKMP_ATTR_AF_TLV:
		case INTERNAL_IP4_DNS | ISAKMP_ATTR_AF_TLV:
		case INTERNAL_IP4_SUBNET | ISAKMP_ATTR_AF_TLV:
			resp |= LELEM(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);
			break;
		case INTERNAL_IP4_NBNS | ISAKMP_ATTR_AF_TLV:
			/* ignore */
			break;
		case MODECFG_DOMAIN | ISAKMP_ATTR_AF_TLV:
		case MODECFG_BANNER | ISAKMP_ATTR_AF_TLV:
		case CISCO_SPLIT_INC | ISAKMP_ATTR_AF_TLV:
			/* ignore - we will always send/receive these */
			break;

		default:
			log_bad_attr("modecfg (inR2)", &modecfg_attr_names, attr.isaat_af_type);
			break;
		}
	}
	/* loglog(LOG_DEBUG, "ModeCfg ACK: 0x%" PRIxLSET, resp); */

	/* ack things */
	{
		stf_status stat = modecfg_resp(st, resp,
					       rbody,
					       ISAKMP_CFG_ACK,
					       FALSE,
					       isama_id);

		if (stat != STF_OK) {
			/* notification payload - not exactly the right choice, but okay */
			md->v1_note = CERTIFICATE_UNAVAILABLE;
			return stat;
		}
	}

	/*
	 * we are done with this exchange, clear things so
	 * that we can start phase 2 properly
	 */
	st->st_v1_msgid.phase15 = v1_MAINMODE_MSGID;
	if (resp != LEMPTY)
		st->hidden_variables.st_modecfg_vars_set = TRUE;

	dbg("modecfg_inI2(STF_OK)");
	return STF_OK;
}

/*
 * STATE_MODE_CFG_R1:
 * HDR*, HASH, ATTR(SET=IP) --> HDR*, HASH, ATTR(ACK,OK)
 *
 * @param md Message Digest
 * @return stf_status
 */
stf_status modecfg_inR1(struct state *st, struct msg_digest *md)
{
	struct pbs_out rbody;
	ikev1_init_pbs_out_from_md_hdr(md, TRUE,
				       &reply_stream, reply_buffer, sizeof(reply_buffer),
				       &rbody, st->st_logger);

	struct connection *c = st->st_connection;

	struct isakmp_mode_attr *ma = &md->chain[ISAKMP_NEXT_MCFG_ATTR]->payload.mode_attribute;
	pb_stream *attrs = &md->chain[ISAKMP_NEXT_MCFG_ATTR]->pbs;
	lset_t resp = LEMPTY;

	dbg("modecfg_inR1: received mode cfg reply");

	st->st_v1_msgid.phase15 = md->hdr.isa_msgid;

	switch (ma->isama_type) {
	default:
	{
		libreswan_log(
			"Expecting ISAKMP_CFG_ACK or ISAKMP_CFG_REPLY, got %x instead.",
			ma->isama_type);
		return STF_IGNORE;
		break;
	}

	case ISAKMP_CFG_ACK:
		/* CHECK that ACK has been received. */
		while (pbs_left(attrs) >= isakmp_xauth_attribute_desc.size) {
			struct isakmp_attribute attr;

			if (!in_struct(&attr,
				       &isakmp_xauth_attribute_desc,
				       attrs, NULL)) {
				/* reject malformed */
				return STF_FAIL;
			}

			switch (attr.isaat_af_type) {
			case INTERNAL_IP4_ADDRESS | ISAKMP_ATTR_AF_TLV:
			case INTERNAL_IP4_NETMASK | ISAKMP_ATTR_AF_TLV:
			case INTERNAL_IP4_DNS | ISAKMP_ATTR_AF_TLV:
			case INTERNAL_IP4_SUBNET | ISAKMP_ATTR_AF_TLV:
				resp |= LELEM(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);
				break;

			case INTERNAL_IP4_NBNS | ISAKMP_ATTR_AF_TLV:
				/* ignore */
				break;
			case MODECFG_DOMAIN | ISAKMP_ATTR_AF_TLV:
			case MODECFG_BANNER | ISAKMP_ATTR_AF_TLV:
			case CISCO_SPLIT_INC | ISAKMP_ATTR_AF_TLV:
				/* ignore - we will always send/receive these */
				break;

			default:
				log_bad_attr("modecfg (CFG_ACK)", &modecfg_attr_names, attr.isaat_af_type);
				break;
			}
		}
		break;

	case ISAKMP_CFG_REPLY:
		while (pbs_left(attrs) >= isakmp_xauth_attribute_desc.size) {
			struct isakmp_attribute attr;
			pb_stream strattr;

			if (!in_struct(&attr,
				       &isakmp_xauth_attribute_desc,
				       attrs, &strattr)) {
				/* reject malformed */
				return STF_FAIL;
			}

			switch (attr.isaat_af_type) {
			case INTERNAL_IP4_ADDRESS | ISAKMP_ATTR_AF_TLV:
			{
				struct connection *c = st->st_connection;

				ip_address a;
				if (!pbs_in_address(&a, &ipv4_info, &strattr, "addr")) {
					return STF_FATAL;
				}
				endtosubnet(&a, &c->spd.this.client, HERE);

				c->spd.this.has_client = TRUE;
				subnet_buf caddr;
				str_subnet(&c->spd.this.client, &caddr);
				loglog(RC_INFORMATIONAL,
					"Received IPv4 address: %s",
					caddr.buf);

				if (!address_is_specified(&c->spd.this.host_srcip)) {
					dbg("setting ip source address to %s",
					    caddr.buf);
					c->spd.this.host_srcip = a;
				}
				resp |= LELEM(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);
				break;
			}

			case INTERNAL_IP4_NETMASK | ISAKMP_ATTR_AF_TLV:
			{
				ip_address a;
				if (!pbs_in_address(&a, &ipv4_info, &strattr, "addr")) {
					return STF_FATAL;
				}

				address_buf b;
				dbg("Received IP4 NETMASK %s", str_address(&a, &b));
				resp |= LELEM(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);
				break;
			}

			case INTERNAL_IP4_DNS | ISAKMP_ATTR_AF_TLV:
			{
				ip_address a;
				if (!pbs_in_address(&a, &ipv4_info, &strattr, "addr")) {
					return STF_FATAL;
				}

				address_buf a_buf;
				const char *a_str = ipstr(&a, &a_buf);
				bool ignore = LIN(POLICY_IGNORE_PEER_DNS, c->policy);
				loglog(RC_INFORMATIONAL, "Received %sDNS server %s",
					ignore ? "and ignored " : "",
					a_str);

				append_st_cfg_dns(st, a_str);

				resp |= LELEM(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);
				break;
			}

			case MODECFG_DOMAIN | ISAKMP_ATTR_AF_TLV:
			{
				append_st_cfg_domain(st, cisco_stringify(&strattr, "Domain", c->policy));
				break;
			}

			case MODECFG_BANNER | ISAKMP_ATTR_AF_TLV:
			{
				st->st_seen_cfg_banner = cisco_stringify(&strattr, "Banner", c->policy);
				break;
			}

			case CISCO_SPLIT_INC | ISAKMP_ATTR_AF_TLV:
			{
				struct connection *c = st->st_connection;

				/* make sure that other side isn't an endpoint */
				if (!c->spd.that.has_client) {
					passert(c->spd.spd_next == NULL);
					c->spd.that.has_client = TRUE;
					c->spd.that.client = ipv4_info.all_addresses;
				}

				while (pbs_left(&strattr) > 0) {
					struct CISCO_split_item i;

					if (!in_struct(&i, &CISCO_split_desc, &strattr, NULL)) {
						loglog(RC_INFORMATIONAL,
						    "ignoring malformed CISCO_SPLIT_INC payload");
						break;
					}

					ip_address base = address_from_in_addr(&i.cs_addr);
					ip_address mask = address_from_in_addr(&i.cs_mask);
					ip_subnet subnet;
					err_t ugh = address_mask_to_subnet(&base, &mask, &subnet);
					if (ugh != NULL) {
						loglog(RC_INFORMATIONAL,
							"ignoring malformed CISCO_SPLIT_INC subnet: %s",
							ugh);
						break;
					}

					subnet_buf pretty_subnet;
					str_subnet(&subnet, &pretty_subnet);

					loglog(RC_INFORMATIONAL,
						"Received subnet %s",
						pretty_subnet.buf);

					struct spd_route *sr;
					for (sr = &c->spd; ; sr = sr->spd_next) {
						if (samesubnet(&subnet, &sr->that.client)) {
							/* duplicate entry: ignore */
							loglog(RC_INFORMATIONAL,
								"Subnet %s already has an spd_route - ignoring",
								pretty_subnet.buf);
							break;
						} else if (sr->spd_next == NULL) {
							/* new entry: add at end*/
							sr = sr->spd_next = clone_thing(c->spd,
								"remote subnets policies");
							sr->spd_next = NULL;

							sr->this.id.name = EMPTY_CHUNK;
							sr->that.id.name = EMPTY_CHUNK;

							sr->this.host_addr_name = NULL;
							sr->that.client = subnet;
							sr->this.cert.ty = CERT_NONE;
							sr->that.cert.ty = CERT_NONE;

							sr->this.ca = EMPTY_CHUNK;
							sr->that.ca = EMPTY_CHUNK;

							/* unshare pointers */
							sr->this.virt = NULL;
							sr->that.virt = NULL;

							unshare_connection_end(&sr->this);
							unshare_connection_end(&sr->that);
							break;
						}
					}
				}

				/*
				 * ??? this won't work because CISCO_SPLIT_INC is way bigger than LELEM_ROOF
				 * resp |= LELEM(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);
				 */
				break;
			}

			case INTERNAL_IP4_NBNS | ISAKMP_ATTR_AF_TLV:
			case INTERNAL_IP6_NBNS | ISAKMP_ATTR_AF_TLV:
			{
				libreswan_log("Received and ignored obsoleted Cisco NetBEUI NS info");
				break;
			}

			default:
			{
				log_bad_attr("modecfg (CISCO_SPLIT_INC)", &modecfg_attr_names, attr.isaat_af_type);
				break;
			}

			}
		}
		break;
	}

	/* we are done with this exchange, clear things so that we can start phase 2 properly */
	st->st_v1_msgid.phase15 = v1_MAINMODE_MSGID;
	if (resp != LEMPTY)
		st->hidden_variables.st_modecfg_vars_set = TRUE;

	dbg("modecfg_inR1(STF_OK)");
	return STF_OK;
}

/** XAUTH client code - response to challenge.  May open filehandle to console
 * in order to prompt user for password
 *
 * @param st State
 * @param xauth_resp XAUTH Response
 * @param rbody Reply Body
 * @param ap_id
 * @return stf_status
 */
static stf_status xauth_client_resp(struct state *st,
			     lset_t xauth_resp,
			     pb_stream *rbody,
			     uint16_t ap_id)
{
	char xauth_username[MAX_XAUTH_USERNAME_LEN];

	struct v1_hash_fixup hash_fixup;
	if (!emit_xauth_hash("XAUTH: client response", st, &hash_fixup, rbody)) {
		return STF_INTERNAL_ERROR;
	}

	/* MCFG_ATTR out */
	{
		pb_stream strattr;

		{
			struct isakmp_mode_attr attrh = {
				.isama_type = ISAKMP_CFG_REPLY,
				.isama_identifier = ap_id,
			};

			if (!out_struct(&attrh, &isakmp_attr_desc, rbody, &strattr))
				return STF_INTERNAL_ERROR;
		}

		/* lset_t xauth_resp is used as a secondary index variable */

		for (int attr_type = XAUTH_TYPE; xauth_resp != LEMPTY; attr_type++) {
			if (xauth_resp & 1) {
				/* ISAKMP attr out */
				struct isakmp_attribute attr;
				pb_stream attrval;

				switch (attr_type) {
				case XAUTH_TYPE:
					attr.isaat_af_type = attr_type |
							     ISAKMP_ATTR_AF_TV;
					attr.isaat_lv = XAUTH_TYPE_GENERIC;
					if (!out_struct(&attr,
							&isakmp_xauth_attribute_desc,
							&strattr,
							NULL))
						return STF_INTERNAL_ERROR;
					break;

				case XAUTH_USER_NAME:
					attr.isaat_af_type = attr_type |
							     ISAKMP_ATTR_AF_TLV;
					if (!out_struct(&attr,
							&
							isakmp_xauth_attribute_desc,
							&strattr,
							&attrval))
						return STF_INTERNAL_ERROR;

					if (st->st_xauth_username[0] == '\0') {
						if (!fd_p(st->st_whack_sock)) {
							loglog(RC_LOG_SERIOUS,
							       "XAUTH username requested, but no file descriptor available for prompt");
							return STF_FATAL;
						}

						if (!whack_prompt_for(st,
							"Username",
							TRUE,
							xauth_username,
							sizeof(xauth_username)))
						{
							loglog(RC_LOG_SERIOUS,
							       "XAUTH username prompt failed.");
							return STF_FATAL;
						}
						/* replace the first newline character with a string-terminating \0. */
						char *cptr = memchr(
							xauth_username,
							'\n',
							sizeof(xauth_username));
						if (cptr != NULL)
							*cptr = '\0';

						jam_str(st->st_xauth_username,
							sizeof(st->st_xauth_username),
							xauth_username);
					}

					if (!out_raw(st->st_xauth_username,
						     strlen(st->
							    st_xauth_username),
						     &attrval,
						     "XAUTH username"))
						return STF_INTERNAL_ERROR;

					close_output_pbs(&attrval);

					break;

				case XAUTH_USER_PASSWORD:
					attr.isaat_af_type = attr_type |
							     ISAKMP_ATTR_AF_TLV;
					if (!out_struct(&attr,
						&isakmp_xauth_attribute_desc,
						&strattr, &attrval))
					{
						return STF_INTERNAL_ERROR;
					}

					if (st->st_xauth_password.ptr == NULL)
					{
						struct secret *s =
							lsw_get_xauthsecret(
								st->st_xauth_username);

						dbg("looked up username=%s, got=%p",
						    st->st_xauth_username,
						    s);
						if (s != NULL) {
							struct private_key_stuff
								*pks = lsw_get_pks(s);

							st->st_xauth_password = clone_hunk(pks->u.preshared_secret,
											   "saved xauth password");
						}
					}

					/*
					 * If we don't already have a password,
					 * try to ask for one through whack.
					 * We'll discard this password after use.
					 */
					bool discard_pw = FALSE;

					if (st->st_xauth_password.ptr == NULL) {
						char xauth_password[XAUTH_MAX_PASS_LENGTH];

						if (!fd_p(st->st_whack_sock)) {
							loglog(RC_LOG_SERIOUS,
							       "XAUTH password requested, but no file descriptor available for prompt");
							return STF_FATAL;
						}

						if (!whack_prompt_for(st,
								      "Password",
								      FALSE,
								      xauth_password,
								      sizeof(xauth_password)))
						{
							loglog(RC_LOG_SERIOUS,
							       "XAUTH password prompt failed.");
							return STF_FATAL;
						}

						/* replace the first newline character with a string-terminating \0. */
						{
							char *cptr = memchr(xauth_password,
								'\n',
								sizeof(xauth_password));
							if (cptr != NULL)
								*cptr = '\0';
						}
						/* see above */
						pexpect(st->st_xauth_password.ptr == NULL);
						st->st_xauth_password = clone_bytes_as_chunk(xauth_password,
											     strlen(xauth_password),
											     "XAUTH password");
						discard_pw = TRUE;
					}

					if (!pbs_out_hunk(st->st_xauth_password,
							  &attrval,
							  "XAUTH password")) {
						if (discard_pw) {
							free_chunk_content(&
								st->st_xauth_password);
						}
						return STF_INTERNAL_ERROR;
					}

					if (discard_pw) {
						free_chunk_content(&
							st->st_xauth_password);
					}
					close_output_pbs(&attrval);
					break;

				default:
					libreswan_log(
						"trying to send XAUTH reply, sending %s instead.",
						enum_show(&modecfg_attr_names,
							  attr_type));
					break;
				}
			}

			xauth_resp >>= 1;
		}

		/* do not PAD here, */
		close_output_pbs(&strattr);
	}

	libreswan_log("XAUTH: Answering XAUTH challenge with user='%s'",
		      st->st_xauth_username);

	fixup_xauth_hash(st, &hash_fixup, rbody->cur);

	if (!ikev1_close_message(rbody, st) ||
	    !ikev1_encrypt_message(rbody, st))
		return STF_INTERNAL_ERROR;

	return STF_OK;
}

#define XAUTHLELEM(x) (LELEM((x & ISAKMP_ATTR_RTYPE_MASK) - XAUTH_TYPE))

/*
 * STATE_XAUTH_I0:
 * HDR*, HASH, ATTR(REQ=IP) --> HDR*, HASH, ATTR(REPLY=IP)
 *
 * This state occurs in initiator.
 *
 * In the initating client, it occurs in XAUTH, when the responding server
 * demands a password, and we have to supply it.
 *
 * @param md Message Digest
 * @return stf_status
 */
stf_status xauth_inI0(struct state *st, struct msg_digest *md)
{
	struct pbs_out rbody;
	ikev1_init_pbs_out_from_md_hdr(md, TRUE,
				       &reply_stream, reply_buffer, sizeof(reply_buffer),
				       &rbody, st->st_logger);

	struct isakmp_mode_attr *ma = &md->chain[ISAKMP_NEXT_MCFG_ATTR]->payload.mode_attribute;
	pb_stream *attrs = &md->chain[ISAKMP_NEXT_MCFG_ATTR]->pbs;
	lset_t xauth_resp = LEMPTY;

	int status = 0;
	stf_status stat = STF_FAIL;
	bool gotrequest = FALSE;
	bool gotset = FALSE;
	bool got_status = FALSE;

	if (st->hidden_variables.st_xauth_client_done)
		return modecfg_inI2(md, &rbody);

	dbg("arrived in xauth_inI0");

	if (impair.drop_xauth_r0) {
		libreswan_log("IMPAIR: drop XAUTH R0 message ");
		return STF_FAIL;
	}

	st->st_v1_msgid.phase15 = md->hdr.isa_msgid;

	switch (ma->isama_type) {
	default:
		libreswan_log(
			"Expecting ISAKMP_CFG_REQUEST or ISAKMP_CFG_SET, got %s instead (ignored).",
			enum_name(&attr_msg_type_names,
				  ma->isama_type));
		/* ??? what are we supposed to do here?  Original code fell through to next case! */
		return STF_FAIL;

	case ISAKMP_CFG_SET:
		gotset = TRUE;
		break;

	case ISAKMP_CFG_REQUEST:
		gotrequest = TRUE;
		break;
	}

	while (pbs_left(attrs) >= isakmp_xauth_attribute_desc.size) {
		struct isakmp_attribute attr;
		pb_stream strattr;

		if (!in_struct(&attr, &isakmp_xauth_attribute_desc,
			       attrs, &strattr)) {
			/* reject malformed */
			return STF_FAIL;
		}

		switch (attr.isaat_af_type) {
		case XAUTH_STATUS | ISAKMP_ATTR_AF_TV:
			got_status = TRUE;
			switch (attr.isaat_lv) {
			case XAUTH_STATUS_FAIL:
				libreswan_log("Received Cisco XAUTH status: FAIL");
				status = attr.isaat_lv;
				break;
			case XAUTH_STATUS_OK:
				dbg("received Cisco XAUTH status: OK");
				status = attr.isaat_lv;
				break;
			default:
				/* ??? treat as fail?  Should we abort negotiation? */
				libreswan_log("invalid XAUTH_STATUS value %u", attr.isaat_lv);
				status = XAUTH_STATUS_FAIL;
				break;
			}
			break;

		case XAUTH_MESSAGE | ISAKMP_ATTR_AF_TLV:
		{
			/* ??? should the message be sanitized before logging? */
			/* XXX check RFC for max length? */
			size_t len = attr.isaat_lv;
			char msgbuf[81];

			dbg("received Cisco XAUTH message");
			if (len >= sizeof(msgbuf) )
				len = sizeof(msgbuf) - 1;
			memcpy(msgbuf, strattr.cur, len);
			msgbuf[len] = '\0';
			loglog(RC_LOG_SERIOUS,
			       "XAUTH Message: %s", msgbuf);
			break;
		}

		case XAUTH_TYPE | ISAKMP_ATTR_AF_TV:
			if (attr.isaat_lv != XAUTH_TYPE_GENERIC) {
				libreswan_log(
					"XAUTH: Unsupported type: %d",
					attr.isaat_lv);
				return STF_IGNORE;
			}
			dbg("received Cisco XAUTH type: Generic");
			xauth_resp |= XAUTHLELEM(XAUTH_TYPE);
			break;

		case XAUTH_USER_NAME | ISAKMP_ATTR_AF_TLV:
			dbg("received Cisco XAUTH username");
			xauth_resp |= XAUTHLELEM(XAUTH_USER_NAME);
			break;

		case XAUTH_USER_PASSWORD | ISAKMP_ATTR_AF_TLV:
			dbg("received Cisco XAUTH password");
			xauth_resp |= XAUTHLELEM(XAUTH_USER_PASSWORD);
			break;

		case INTERNAL_IP4_ADDRESS | ISAKMP_ATTR_AF_TLV:
			dbg("received Cisco Internal IPv4 address");
			break;

		case INTERNAL_IP4_NETMASK | ISAKMP_ATTR_AF_TLV:
			dbg("received Cisco Internal IPv4 netmask");
			break;

		case INTERNAL_IP4_DNS | ISAKMP_ATTR_AF_TLV:
			dbg("received Cisco IPv4 DNS info");
			break;

		case INTERNAL_IP4_SUBNET | ISAKMP_ATTR_AF_TV:
			dbg("received Cisco IPv4 Subnet info");
			break;

		case INTERNAL_IP4_NBNS | ISAKMP_ATTR_AF_TV:
			dbg("received Cisco NetBEUI NS info");
			break;

		default:
			log_bad_attr("XAUTH (inI0)", &modecfg_attr_names, attr.isaat_af_type);
			break;
		}
	}

	if (gotset && got_status) {
		/* ACK whatever it was that we got */
		stat = xauth_client_ackstatus(st, &rbody,
					      md->chain[
						      ISAKMP_NEXT_MCFG_ATTR]->payload.mode_attribute.isama_identifier);

		/* must have gotten a status */
		if (status != XAUTH_STATUS_FAIL && stat == STF_OK) {
			st->hidden_variables.st_xauth_client_done =
				TRUE;
			loglog(RC_LOG, "XAUTH: Successfully Authenticated");
			st->st_oakley.doing_xauth = FALSE;

			return STF_OK;
		} else {
			libreswan_log("xauth: xauth_client_ackstatus() returned %s",
				      enum_name(&stf_status_names, stat));
			libreswan_log("XAUTH: aborting entire IKE Exchange");
			return STF_FATAL;
		}
	}

	if (gotrequest) {
		if (DBGP(DBG_BASE)) {
			if (xauth_resp &
			    (XAUTHLELEM(XAUTH_USER_NAME) |
			     XAUTHLELEM(XAUTH_USER_PASSWORD)))
				DBG_log("XAUTH: Username or password request received");
		}

		/* sanitize what we were asked to reply to */
		if (LDISJOINT(xauth_resp,
			XAUTHLELEM(XAUTH_USER_NAME) |
			XAUTHLELEM(XAUTH_USER_PASSWORD)))
		{
			if (st->st_connection->spd.this.xauth_client) {
				libreswan_log(
					"XAUTH: No username or password request was received.");
				return STF_IGNORE;
			}
		} else {
			if (!st->st_connection->spd.this.xauth_client) {
				libreswan_log(
					"XAUTH: Username or password request was received, but XAUTH client mode not enabled.");
				return STF_IGNORE;
			}
		}

		stat = xauth_client_resp(st, xauth_resp,
					 &rbody,
					 md->chain[ISAKMP_NEXT_MCFG_ATTR]->payload.mode_attribute.isama_identifier);
	}

	if (stat != STF_OK) {
		/* notification payload - not exactly the right choice, but okay */
		md->v1_note = CERTIFICATE_UNAVAILABLE;
		return stat;
	}

	/* reset the message ID */
	st->st_v1_msgid.phase15 = v1_MAINMODE_MSGID;

	dbg("xauth_inI0(STF_OK)");
	return STF_OK;
}

/** XAUTH client code - Acknowledge status
 *
 * @param st State
 * @param rbody Response Body
 * @param ap_id
 * @return stf_status
 */
static stf_status xauth_client_ackstatus(struct state *st,
					 pb_stream *rbody,
					 uint16_t ap_id)
{
	struct v1_hash_fixup hash_fixup;
	if (!emit_xauth_hash("XAUTH: ack status", st, &hash_fixup, rbody)) {
		return STF_INTERNAL_ERROR;
	}

	/* ATTR out */
	{
		struct isakmp_mode_attr attrh = {
			.isama_type = ISAKMP_CFG_ACK,
			.isama_identifier = ap_id,
		};
		pb_stream strattr;
		struct isakmp_attribute attr = {
			.isaat_af_type = XAUTH_STATUS | ISAKMP_ATTR_AF_TV,
			.isaat_lv = XAUTH_STATUS_OK,
		};

		if (!out_struct(&attrh, &isakmp_attr_desc, rbody, &strattr) ||
		    !out_struct(&attr, &isakmp_xauth_attribute_desc, &strattr,
				NULL) ||
		    !ikev1_close_message(&strattr, st))
			return STF_INTERNAL_ERROR;
	}

	fixup_xauth_hash(st, &hash_fixup, rbody->cur);

	if (!ikev1_close_message(rbody, st) ||
	    !ikev1_encrypt_message(rbody, st))
		return STF_INTERNAL_ERROR;

	return STF_OK;
}

/*
 * STATE_XAUTH_I1:
 * HDR*, HASH, ATTR(SET=IP) --> HDR*, HASH, ATTR(ACK,OK)
 *
 * @param md Message Digest
 * @return stf_status
 */
stf_status xauth_inI1(struct state *st, struct msg_digest *md)
{
	struct pbs_out rbody;
	ikev1_init_pbs_out_from_md_hdr(md, TRUE,
				       &reply_stream, reply_buffer, sizeof(reply_buffer),
				       &rbody, st->st_logger);

	struct isakmp_mode_attr *ma = &md->chain[ISAKMP_NEXT_MCFG_ATTR]->payload.mode_attribute;
	pb_stream *attrs = &md->chain[ISAKMP_NEXT_MCFG_ATTR]->pbs;
	bool got_status = FALSE;
	unsigned int status = XAUTH_STATUS_FAIL;
	stf_status stat;
	lset_t xauth_resp = LEMPTY;	/* ??? value never used */

	dbg("xauth_inI1");

	if (st->hidden_variables.st_xauth_client_done) {
		dbg("st_xauth_client_done, moving into modecfg_inI2");
		return modecfg_inI2(md, &rbody);
	}
	dbg("Continuing with xauth_inI1");

	st->st_v1_msgid.phase15 = md->hdr.isa_msgid;

	switch (ma->isama_type) {
	default:
		libreswan_log(
			"Expecting MODE_CFG_SET, got %x instead.",
			ma->isama_type);
		return STF_IGNORE;

	case ISAKMP_CFG_SET:
		/* CHECK that SET has been received. */
		while (pbs_left(attrs) >= isakmp_xauth_attribute_desc.size) {
			struct isakmp_attribute attr;
			pb_stream strattr;

			if (!in_struct(&attr,
				       &isakmp_xauth_attribute_desc,
				       attrs, &strattr)) {
				/* reject malformed */
				return STF_FAIL;
			}

			switch (attr.isaat_af_type) {
			case XAUTH_STATUS | ISAKMP_ATTR_AF_TV:
				xauth_resp |= XAUTHLELEM(XAUTH_STATUS);
				got_status = TRUE;
				switch (attr.isaat_lv) {
				case XAUTH_STATUS_FAIL:
				case XAUTH_STATUS_OK:
					status = attr.isaat_lv;
					break;
				default:
					/* ??? treat as fail?  Should we abort negotiation? */
					libreswan_log("invalid XAUTH_STATUS value %u", attr.isaat_lv);
					status = XAUTH_STATUS_FAIL;
					break;
				}
				break;

			default:
				libreswan_log(
					"while waiting for XAUTH_STATUS, got %s %s instead.",
					(attr.isaat_af_type & ISAKMP_ATTR_AF_MASK) == ISAKMP_ATTR_AF_TV ? "basic" : "long",
					enum_show(&modecfg_attr_names,
						  attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK));
				break;
			}
		}
		break;
	}

	/* first check if we might be done! */
	if (!got_status || status == XAUTH_STATUS_FAIL) {
		/* oops, something seriously wrong */
		libreswan_log(
			"did not get status attribute in xauth_inI1, looking for new challenge.");
		change_state(st, STATE_XAUTH_I0);
		return xauth_inI0(st, md);
	}

	/* ACK whatever it was that we got */
	stat = xauth_client_ackstatus(st, &rbody,
				      md->chain[ISAKMP_NEXT_MCFG_ATTR]->payload.mode_attribute.isama_identifier);

	/* must have gotten a status */
	if (status && stat == STF_OK) {
		st->hidden_variables.st_xauth_client_done = TRUE;
		libreswan_log("successfully logged in");
		st->st_oakley.doing_xauth = FALSE;

		return STF_OK;
	}

	/* what? */
	return stat;
}
