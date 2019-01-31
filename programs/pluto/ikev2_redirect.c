/*
 * IKEv2 Redirect Mechanism (RFC 5685) related functions
 *
 * Copyright (C) 2018 Vukasin Karadzic <vukasin.karadzic@gmail.com>
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

#include <libreswan.h>

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

#include "ikev2_redirect.h"

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

bool emit_redirect_notification(
		const char *destination,
		const chunk_t *nonce, /* optional */
		pb_stream *pbs)
{
	ip_address ip_addr;
	err_t ugh = ttoaddr_num(destination, 0, AF_UNSPEC, &ip_addr);

	if (ugh != NULL) {
		/*
		 * ttoaddr_num failed: just ship destination as a FQDN
		 * ??? it may be a bogus string
		 */
		return emit_redirect_notification_decoded_dest(v2N_REDIRECT,
			NULL, destination, nonce, pbs);
	} else {
		return emit_redirect_notification_decoded_dest(v2N_REDIRECT,
			&ip_addr, NULL, nonce, pbs);
	}
}

bool emit_redirect_notification_decoded_dest(
		v2_notification_t ntype,
		const ip_address *dest_ip,
		const char *dest_str,
		const chunk_t *nonce, /* optional */
		pb_stream *pbs)
{
	struct ikev2_redirect_part gwi;
	size_t id_len;
	const unsigned char *id_bytes;

	if (dest_ip == NULL) {
		id_len = strlen(dest_str);
		id_bytes = (const unsigned char *)dest_str;
	} else {
		passert(dest_str == NULL);

		switch (addrtypeof(dest_ip)) {
		case AF_INET:
			gwi.gw_identity_type = GW_IPV4;
			break;
		case AF_INET6:
			gwi.gw_identity_type = GW_IPV6;
			break;
		default:
			bad_case(addrtypeof(dest_ip));
		}
		id_len = addrbytesptr_read(dest_ip, &id_bytes);
	}

	if (id_len > 0xFF) {
		/* ??? what should we do? */
		loglog(RC_LOG_SERIOUS, "redirect destination longer than 255 octets; ignoring");
		return false;
	}
	gwi.gw_identity_len = id_len;

	passert(nonce == NULL ||
		(nonce->len >= IKEv2_MINIMUM_NONCE_SIZE &&
		 nonce->len <= IKEv2_MAXIMUM_NONCE_SIZE));

	pb_stream gwid_pbs;
	return
-		emit_v2Npl(ntype, pbs, &gwid_pbs) &&
		out_struct(&gwi, &ikev2_redirect_desc, &gwid_pbs, NULL) &&
		out_raw(id_bytes, id_len , &gwid_pbs, "redirect ID") &&
		(nonce == NULL || out_chunk(*nonce, &gwid_pbs, "redirect ID len")) &&
		(close_output_pbs(&gwid_pbs), true);
}

/*
 * Iterate through the allowed_targets_list, and if none of the
 * specified addresses matches the one from REDIRECT
 * payload, return FALSE
 */
static bool allow_to_be_redirected(const char *allowed_targets_list, ip_address *dest_ip)
{
	if (allowed_targets_list == NULL || streq(allowed_targets_list, "%any"))
		return TRUE;

	ip_address ip_addr;

	for (const char *t = allowed_targets_list;; ) {
		t += strspn(t, ", ");	/* skip leading separator */
		int len = strcspn(t, ", ");	/* length of name */
		if (len == 0)
			break;	/* no more */

		err_t ugh = ttoaddr_num(t, len, AF_UNSPEC, &ip_addr);

		if (ugh != NULL) {
			DBGF(DBG_CONTROLMORE, "address %.*s isn't a valid address", len, t);
		} else if (sameaddr(dest_ip, &ip_addr)) {
			DBGF(DBG_CONTROLMORE,
				"address %.*s is a match to received GW identity", len, t);
			return TRUE;
		} else {
			DBGF(DBG_CONTROLMORE,
				"address %.*s is not a match to received GW identity", len, t);
		}
		t += len;	/* skip name */
	}
	DBGF(DBG_CONTROLMORE,
		"we did not find suitable address in the list specified by accept-redirect-to option");
	return FALSE;
}

err_t parse_redirect_payload(pb_stream *input_pbs,
			     const char *allowed_targets_list,
			     const chunk_t *nonce,
			     ip_address *redirect_ip /* result */)
{
	struct ikev2_redirect_part gw_info;

	if (!in_struct(&gw_info, &ikev2_redirect_desc, input_pbs, NULL))
		return "received deformed REDIRECT payload";

	int af;

	switch (gw_info.gw_identity_type) {
	case GW_IPV4:
		af = AF_INET;
		break;
	case GW_IPV6:
		af = AF_INET6;
		break;
	case GW_FQDN:
		af  = AF_UNSPEC;
		break;
	default:
		return "bad GW Ident Type";
	}

	/* in_raw() actual GW Identity */
	switch (af) {
	case AF_UNSPEC:
	{
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

		if (!in_raw(&gw_str, gw_info.gw_identity_len, input_pbs, "GW Identity"))
			return "error while extracting GW Identity from variable part of IKEv2_REDIRECT Notify payload";

		err_t ugh = ttoaddr((char *) gw_str, gw_info.gw_identity_len,
					AF_UNSPEC, redirect_ip);
		if (ugh != NULL)
			return ugh;
		break;
	}
	case AF_INET:
	case AF_INET6:
	{
		if (pbs_left(input_pbs) < gw_info.gw_identity_len)
			return "variable part of payload is smaller than transfered GW Identity Length";

		/* parse address directly to redirect_ip */
		err_t ugh = initaddr(input_pbs->cur, gw_info.gw_identity_len, af, redirect_ip);
		if (ugh != NULL)
			return ugh;

		DBG(DBG_PARSING, {
			ip_address_buf b;
			DBG_log("   GW Identity IP: %s", ipstr(redirect_ip, &b));
		});
		input_pbs->cur += gw_info.gw_identity_len;
		break;
	}
	}

	/*
	 * now check the list of allowed targets to
	 * see if parsed address matches any in the list
	 */
	if (!allow_to_be_redirected(allowed_targets_list, redirect_ip))
		return "received GW Identity is not listed in accept-redirect-to conn option";

	size_t len = pbs_left(input_pbs);

	if (nonce == NULL) {
		if (len > 0)
			return "unexpected extra bytes in Notify data";
	} else {
		if (len < IKEv2_MINIMUM_NONCE_SIZE)
			return "expected nonce is smaller than IKEv2 minimum nonce size";
		else if (len > IKEv2_MAXIMUM_NONCE_SIZE)
			return "expected nonce is bigger than IKEv2 maximum nonce size";

		if (nonce->len != len ||
		    !memeq(nonce->ptr, input_pbs->cur, len)) {
			DBG(DBG_CONTROL, {
				DBG_dump_chunk("expected nonce", *nonce);
				DBG_dump("received nonce", input_pbs->cur, len);
			});
			return "received nonce is not the same as Ni";
		}
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
	if (del_spi(st->st_esp.our_spi, SA_ESP,
		    &st->st_connection->temp_vars.old_gw_address,
		    &st->st_connection->spd.this.host_addr)) {
		DBG(DBG_CONTROL, DBG_log("redirect: successfully deleted lingering SPI entry"));
	} else {
		DBG(DBG_CONTROL, DBG_log("redirect: failed to delete lingering SPI entry"));
	}
}

void initiate_redirect(struct state *st)
{
	ipstr_buf b;
	struct state *right_state;

	if (IS_PARENT_SA(st))
		right_state = st;
	else
		right_state = state_with_serialno(st->st_clonedfrom);

	struct connection *c = right_state->st_connection;
	ip_address redirect_ip = c->temp_vars.redirect_ip;

	/* stuff for loop detection */
	if (c->temp_vars.num_redirects == 0)
		c->temp_vars.first_redirect_time = realnow();
	c->temp_vars.num_redirects++;

	if (c->temp_vars.num_redirects > MAX_REDIRECTS) {
		if (deltatime_cmp(deltatime(REDIRECT_LOOP_DETECT_PERIOD),
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

	initiate_connection(c->name, dup_any(st->st_whack_sock),
				empty_lmod, empty_lmod,
				NULL);

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
static payload_master_t add_redirect_payload;
static bool add_redirect_payload(struct state *st, pb_stream *pbs)
{
	return emit_redirect_notification(st->st_active_redirect_gw, NULL, pbs);
}

void send_active_redirect_in_informational(struct state *st)
{
	stf_status e = record_v2_informational_request("active REDIRECT informational request",
						       ike_sa(st), st, add_redirect_payload);
	if (e == STF_OK) {
		send_recorded_v2_ike_msg(st, "active REDIRECT informational request");
		ipstr_buf b;
		libreswan_log("redirecting of peer %s successful",
				sensitive_ipstr(&st->st_remoteaddr, &b));
	} else {
		libreswan_log("redirect not successful");
	}
}
