/*
 * IKEv2 Redirect Mechanism (RFC 5685) related functions
 *
 * Copyright (C) 2018 - 2020 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2020 Paul Wouters <pwouters@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <unistd.h>


#include "lswlog.h"
#include "constants.h"
#include "defs.h"

#include "id.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "packet.h"
#include "demux.h"
#include "ip_address.h"
#include "ipsec_doi.h"
#include "ikev2.h"
#include "ikev2_send.h"
#include "kernel.h"		/* needed for del_spi */
#include "ip_info.h"
#include "ikev2_redirect.h"
#include "initiate.h"
#include "log.h"

enum allow_global_redirect global_redirect;
char *global_redirect_to;

/*
 * Structure of REDIRECT Notify payload from RFC 5685.
 * The second part (Notification data) is interesting to us.
 * GW Ident Type: Type of Identity of new gateway
 * GW Ident Len:  Length of the New Responder GW Identity field
 *
 * Nonce Data is sent only if Redirect is happening during
 * IKE_SA_INIT exchange.
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Next Payload  |C|  RESERVED   |         Payload Length        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Protocol ID(=0)| SPI Size (=0) |      Notify Message Type      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | GW Ident Type |  GW Ident Len |                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               ~
 * ~                   New Responder GW Identity                   ~
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * ~                        Nonce Data                             ~
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/*
 * Build a notification data for REDIRECT (or REDIRECTED_FROM)
 * payload from the given string or ip.
 *
 * NOTE: destination string can also contain an 'unparsed'
 * IP address.
 * In ip we will always have already 'parsed' IP address,
 * obviously. ip will not be NULL only in cases
 * where we use this function for constructing data
 * for REDIRECTED_FROM notification.
 */
static chunk_t build_redirect_notification_data(const char *dest_str, /* optional */
						const ip_address *dest_ip, /* optional */
						const shunk_t *nonce) /* optional */
{
	passert((dest_str == NULL) != (dest_ip == NULL));

	ip_address ip_addr;
	bool send_ip;
	err_t ugh;

	if (dest_str != NULL) {
		ugh = ttoaddr_num(dest_str, 0, AF_UNSPEC, &ip_addr);
		if (ugh != NULL)
			/*
			* ttoaddr_num failed: just ship dest_str as a FQDN
			* ??? it may be a bogus string
			*/
			send_ip = false;
		else
			send_ip = true;
	} else {
		send_ip = true;
		ip_addr = *dest_ip;
	}

	struct ikev2_redirect_part gwi;
	shunk_t id;

	if (!send_ip) {
		id = shunk1(dest_str);
		gwi.gw_identity_type = GW_FQDN;
	} else {
		switch (addrtypeof(&ip_addr)) {
		case AF_INET:
			gwi.gw_identity_type = GW_IPV4;
			break;
		case AF_INET6:
			gwi.gw_identity_type = GW_IPV6;
			break;
		default:
			bad_case(addrtypeof(&ip_addr));
		}
		id = address_as_shunk(&ip_addr);
	}

	if (id.len > 0xFF) {
		loglog(RC_LOG_SERIOUS, "redirect destination longer than 255 octets; ignoring");
		return empty_chunk;
	}
	gwi.gw_identity_len = id.len;

	/*
	 * Dummy pbs we need for more elegant notification
	 * data construction (using out_struct and et. al.)
	 */
	uint8_t buf[MIN_OUTPUT_UDP_SIZE];
	pb_stream gwid_pbs = open_out_pbs("gwid_pbs",
				       buf, sizeof(buf));
	if (out_struct(&gwi, &ikev2_redirect_desc, &gwid_pbs, NULL) &&
			out_raw(id.ptr, id.len , &gwid_pbs, "redirect ID") &&
			(nonce == NULL || pbs_out_hunk(*nonce, &gwid_pbs, "nonce in redirect notify")) &&
			(close_output_pbs(&gwid_pbs), true))
		/* please make sure callee frees this chunk */
		return clone_out_pbs_as_chunk(&gwid_pbs, "redirect notify data");

	return empty_chunk;
}

bool redirect_global(struct msg_digest *md)
{
	/* if we don't support global redirection, no need to continue */
	if (global_redirect == GLOBAL_REDIRECT_NO)
		return false;
	else if (global_redirect == GLOBAL_REDIRECT_AUTO && !require_ddos_cookies())
		return false;

	/*
	 * From this point on we know that redirection is a must, and return
	 * value will be true. The only thing that we need to note is whether
	 * we redirect or not, and that difference will be marked with a
	 * log message.
	 */

	if (global_redirect_to == NULL) {
		log_md(RC_LOG_SERIOUS, md,
		       "global redirect destination is not specified");
		return true;
	}

	if (md->chain[ISAKMP_NEXT_v2Ni] == NULL) {
		/* Ni is used as cookie to protect REDIRECT in IKE_SA_INIT */
		dbg("Ni payload required for REDIRECT is missing");
		return true;
	}

	bool peer_redirect_support =
		(md->pbs[PBS_v2N_REDIRECTED_FROM] != NULL ||
		 md->pbs[PBS_v2N_REDIRECT_SUPPORTED] != NULL);

	if (!peer_redirect_support) {
		dbg("peer didn't indicate support for redirection");
		return true;
	}

	shunk_t Ni = pbs_in_left_as_shunk(&md->chain[ISAKMP_NEXT_v2Ni]->pbs);
	if (Ni.len == 0) {
		dbg("Initiator nonce should not be zero length");
		return true;
	}

	chunk_t data = build_redirect_notification_data(global_redirect_to, NULL, &Ni);

	if (data.len == 0) {
		log_md(RC_LOG_SERIOUS, md,
		       "failed to construct REDIRECT notification data");
		return true;
	}

	send_v2N_response_from_md(md, v2N_REDIRECT, &data);
	free_chunk_content(&data);
	return true;
}

bool emit_redirect_notification(const char *dest_str, pb_stream *pbs)
{
	chunk_t data = build_redirect_notification_data(dest_str, NULL, NULL);

	if (data.len == 0)
		return false;

	bool ret = emit_v2N_bytes(v2N_REDIRECT, data.ptr, data.len, pbs);
	free_chunk_content(&data);

	return ret;
}

bool emit_redirected_from_notification(const ip_address *ip_addr, pb_stream *pbs)
{
	chunk_t data = build_redirect_notification_data(NULL, ip_addr, NULL);

	if (data.len == 0)
		return false;

	bool ret = emit_v2N_bytes(v2N_REDIRECTED_FROM, data.ptr, data.len, pbs);
	free_chunk_content(&data);

	return ret;
}

/*
 * Iterate through the allowed_targets_list, and if none of the
 * specified addresses matches the one from REDIRECT
 * payload, return FALSE
 */
static bool allow_to_be_redirected(const char *allowed_targets_list, ip_address *dest_ip)
{
	if (allowed_targets_list == NULL || streq(allowed_targets_list, "%any"))
		return true;

	ip_address ip_addr;

	for (const char *t = allowed_targets_list;; ) {
		t += strspn(t, ", ");	/* skip leading separator */
		int len = strcspn(t, ", ");	/* length of name */
		if (len == 0)
			break;	/* no more */

		err_t ugh = ttoaddr_num(t, len, AF_UNSPEC, &ip_addr);

		if (ugh != NULL) {
			dbg("address %.*s isn't a valid address", len, t);
		} else if (sameaddr(dest_ip, &ip_addr)) {
			dbg("address %.*s is a match to received GW identity", len, t);
			return TRUE;
		} else {
			dbg("address %.*s is not a match to received GW identity", len, t);
		}
		t += len;	/* skip name */
	}
	dbg("we did not find suitable address in the list specified by accept-redirect-to option");
	return false;
}

err_t parse_redirect_payload(const struct pbs_in *notify_pbs,
			     const char *allowed_targets_list,
			     const chunk_t *nonce,
			     ip_address *redirect_ip /* result */,
			     struct logger *logger)
{
	struct pbs_in input_pbs = *notify_pbs;
	struct ikev2_redirect_part gw_info;

	if (!pbs_in_struct(&input_pbs, &gw_info, sizeof(gw_info),
			   &ikev2_redirect_desc, NULL, logger)) {
		return "received malformed REDIRECT payload";
	}

	const struct ip_info *af;

	switch (gw_info.gw_identity_type) {
	case GW_IPV4:
		af = &ipv4_info;
		break;
	case GW_IPV6:
		af = &ipv6_info;
		break;
	case GW_FQDN:
		af  = NULL;
		break;
	default:
		return "bad GW Ident Type";
	}

	/* pbs_in_raw() actual GW Identity */
	if (af == NULL) {
		/*
		 * The FQDN string isn't NUL-terminated.
		 *
		 * The length is stored in a byte so it cannot be
		 * larger than 0xFF.
		 * Some helpful compilers moan about this test being always true
		 * so I eliminated it:
		 *	passert(gw_info.gw_identity_len <= 0xFF);
		 */
		unsigned char gw_str[0xFF];

		if (!pbs_in_raw(&input_pbs, &gw_str, gw_info.gw_identity_len,
				"GW Identity", logger))
			return "error while extracting GW Identity from variable part of IKEv2_REDIRECT Notify payload";

		err_t ugh = ttoaddr((char *) gw_str, gw_info.gw_identity_len,
					AF_UNSPEC, redirect_ip);
		if (ugh != NULL) {
			return ugh;
		}
	} else {
		if (gw_info.gw_identity_len < af->ip_size) {
			return "transferred GW Identity Length is too small for an IP address";
		}
		if (!pbs_in_address(redirect_ip, af, &input_pbs, "REDIRECT address")) {
			return "variable part of payload does not match transferred GW Identity Length";
		}
		address_buf b;
		dbg("   GW Identity IP: %s", ipstr(redirect_ip, &b));
	}

	/*
	 * now check the list of allowed targets to
	 * see if parsed address matches any in the list
	 */
	if (!allow_to_be_redirected(allowed_targets_list, redirect_ip))
		return "received GW Identity is not listed in accept-redirect-to conn option";

	size_t len = pbs_left(&input_pbs);

	if (nonce == NULL) {
		if (len > 0)
			return "unexpected extra bytes in Notify data after GW data - nonce should have been omitted";
		else
			return NULL;
	}

	if (nonce->len != len || !memeq(nonce->ptr, input_pbs.cur, len)) {
		if (DBGP(DBG_BASE)) {
			DBG_dump_hunk("expected nonce", *nonce);
			DBG_dump("received nonce", input_pbs.cur, len);
		}
		return "received nonce does not match our expected nonce Ni (spoofed packet?)";
	}

	return NULL;
}

/*
 * if we were redirected in AUTH, we must delete one XFRM
 * state entry manually (to the old gateway), because
 * teardown_half_ipsec_sa() in kernel.c, that is called eventually
 * following the above EVENT_SA_EXPIRE, does not delete
 * it. It does not delete it (via del_spi) because
 * st->st_esp.present was not still at that point set to
 * TRUE. (see the method teardown_half_ipsec_sa for more details)
 *
 * note: the IPsec SA is not truly and fully established when
 * we are doing redirect in IKE_AUTH, and because of that
 * we may delete XFRM state entry without any worries.
 */
static void del_spi_trick(struct state *st)
{
	if (del_spi(st->st_esp.our_spi, &ip_protocol_esp,
		    &st->st_connection->temp_vars.old_gw_address,
		    &st->st_connection->spd.this.host_addr)) {
		dbg("redirect: successfully deleted lingering SPI entry");
	} else {
		dbg("redirect: failed to delete lingering SPI entry");
	}
}

void initiate_redirect(struct state *st)
{
	ipstr_buf b;
	struct state *right_state = &ike_sa(st, HERE)->sa;
	struct connection *c = right_state->st_connection;
	ip_address redirect_ip = c->temp_vars.redirect_ip;

	/* stuff for loop detection */
	if (c->temp_vars.num_redirects == 0)
		c->temp_vars.first_redirect_time = realnow();
	c->temp_vars.num_redirects++;

	if (c->temp_vars.num_redirects > MAX_REDIRECTS) {
		/* XXX: is this correct? */
		if (deltatime_cmp(deltatime(REDIRECT_LOOP_DETECT_PERIOD), !=,
				  realtimediff(c->temp_vars.first_redirect_time, realnow()))) {
			loglog(RC_LOG_SERIOUS, "redirect loop, stop initiating IKEv2 exchanges");
			event_force(EVENT_SA_EXPIRE, right_state);

			if (st->st_redirected_in_auth)
				del_spi_trick(st);

			return;
		} else {
			c->temp_vars.num_redirects = 0;
		}
	}

	/* save old address for REDIRECTED_FROM notify */
	c->temp_vars.old_gw_address = c->spd.that.host_addr;
	/* update host_addr of other end, port stays the same */
	c->spd.that.host_addr = redirect_ip;

	libreswan_log("initiating a redirect to new gateway (address: %s)",
			sensitive_ipstr(&redirect_ip, &b));

	initiate_connections_by_name(c->name, NULL,
				     st->st_whack_sock,
				     st->st_whack_sock == NULL/*background*/);

	event_force(EVENT_SA_EXPIRE, right_state);
	/*
	 * if we were redirected in AUTH, we must delete one XFRM
	 * state entry manually (to the old gateway), because
	 * teardown_half_ipsec_sa() in kernel.c, that is called eventually
	 * following the above EVENT_SA_EXPIRE, does not delete
	 * it. It does not delete it (via del_spi) because
	 * st->st_esp.present was not set to TRUE. (see the method
	 * teardown_half_ipsec_sa for more details)
	 *
	 * note: the IPsec SA is not truly and fully established when
	 * we are doing redirect in IKE_AUTH, and because of that
	 * we may delete XFRM state entry without any worries.
	 */
	if (st->st_redirected_in_auth)
		del_spi_trick(st);
}

/* helper function for send_v2_informational_request() */
static payload_emitter_fn add_redirect_payload;
static bool add_redirect_payload(struct state *st, pb_stream *pbs)
{
	return emit_redirect_notification(st->st_active_redirect_gw, pbs);
}

void send_active_redirect_in_informational(struct state *st)
{
	struct ike_sa *ike = ike_sa(st, HERE);
	stf_status e = record_v2_informational_request("active REDIRECT informational request",
						       ike, st, add_redirect_payload);
	if (e == STF_OK) {
		send_recorded_v2_message(ike, "active REDIRECT informational request",
					 MESSAGE_REQUEST);
		/*
		 * XXX: record 'n' send violates the RFC.  This code
		 * should instead let success_v2_state_transition()
		 * deal with things.
		 */
		dbg_v2_msgid(ike, st, "XXX: in %s hacking around record'n'send bypassing send queue",
			     __func__);
		v2_msgid_update_sent(ike, &ike->sa, NULL /* new exchange */, MESSAGE_REQUEST);
		ipstr_buf b;
		libreswan_log("redirecting of peer %s successful",
				sensitive_ipstr(&st->st_remote_endpoint, &b));
	} else {
		libreswan_log("redirect not successful");
	}
}

stf_status process_IKE_SA_INIT_v2N_REDIRECT_response(struct ike_sa *ike,
						     struct child_sa *child,
						     struct msg_digest *md)
{
	struct connection *c = ike->sa.st_connection;
	pexpect(child == NULL);
	if (!pexpect(md->pbs[PBS_v2N_REDIRECT] != NULL)) {
		return STF_INTERNAL_ERROR;
	}
	struct pbs_in redirect_pbs = *md->pbs[PBS_v2N_REDIRECT];

	if (!LIN(POLICY_ACCEPT_REDIRECT_YES, ike->sa.st_connection->policy)) {
		log_state(RC_LOG, &ike->sa,
			  "ignoring v2N_REDIRECT, we don't accept being redirected");
		return STF_IGNORE;
	}

	ip_address redirect_ip;
	err_t err = parse_redirect_payload(&redirect_pbs,
					   c->accept_redirect_to,
					   &ike->sa.st_ni,
					   &redirect_ip,
					   ike->sa.st_logger);
	if (err != NULL) {
		log_state(RC_LOG_SERIOUS, &ike->sa,
			  "warning: parsing of v2N_REDIRECT payload failed: %s", err);
		return STF_IGNORE;
	}

	/*
	 * MAGIC: the redirect event will delete the IKE SA and start
	 * a new one with the new IP.
	 *
	 * XXX: could this, like COOKIE and INVALID_KE_PAYLOAD, just
	 * continue with the current state.
	 */
	ike->sa.st_connection->temp_vars.redirect_ip = redirect_ip;
	return STF_OK;
}
