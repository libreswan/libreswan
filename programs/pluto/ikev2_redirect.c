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

/* two bytes for GW Ident Type and GW Ident Len */
#define GW_PAYLOAD_INFO_SIZE 2

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

err_t build_redirect_notify_data(char *destination,
				 bool global_red,
				 chunk_t *nonce,
				 chunk_t *data)
{
	ip_address ip_addr;
	uint8_t redir_gw_type = 0, gw_identity_len = 0;	/* exactly one byte as per RFC */
	size_t data_len = 0;
	unsigned char *tmp = NULL;
	err_t ugh = NULL;

	passert(destination != NULL);

	/*
	 * try ttoaddr_num, if it fails just
	 * ship destination (as a FQDN, although
	 * it may be a bogus string)
	 */
	ugh = ttoaddr_num(destination, 0, AF_UNSPEC, &ip_addr);
	if (ugh != NULL) {
		DBG(DBG_CONTROL, DBG_log("REDIRECT destination is not IPv4/IPv6 address, we are going to send it as FQDN"));
		redir_gw_type = GW_FQDN;
		gw_identity_len = strlen(destination);
	} else {
		switch (addrtypeof(&ip_addr)) {
		case AF_INET:
			redir_gw_type = GW_IPV4;
			gw_identity_len = 4;
			break;
		case AF_INET6:
			redir_gw_type = GW_IPV6;
			gw_identity_len = 16;
			break;
		default:
			break;
		}
	}

	data_len = GW_PAYLOAD_INFO_SIZE + gw_identity_len + (global_red == TRUE ? nonce->len : 0);
	*data = alloc_chunk(data_len, "data for REDIRECT Notify payload");	/* we free this in calling function
										   or here (when len != gw_identity_len) */
	tmp = data->ptr;
	*tmp++ = redir_gw_type;
	*tmp++ = gw_identity_len;

	if (redir_gw_type == GW_FQDN) {
		/* write string - FQDN - to tmp (chunk_t data) */
		memcpy(tmp, destination, gw_identity_len);
		tmp += gw_identity_len;
	} else {
		/* write values of IPv4/IPv6 address */
		unsigned char *addr_bytes;
		size_t len = addrbytesptr_write(&ip_addr, &addr_bytes);
		if (len != gw_identity_len) {
			freeanychunk(*data);
			return "GW identity length doesn't match address bytes length";
		}
		/* write ip_address bytes to tmp (chunk_t data) */
		memcpy(tmp, addr_bytes, len);
		tmp += len;
	}

	if (global_red) {
		memcpy(tmp, nonce->ptr, nonce->len);
		tmp += nonce->len;
	}

	return NULL;
}

/*
 * Itterate through the allowed_targets_list, and if none of the
 * specified addresses matches the one from REDIRECT
 * payload, return FALSE
 */
static bool allow_to_be_redirected(char *allowed_targets_list, ip_address *dest_ip)
{
	if (allowed_targets_list == NULL || streq(allowed_targets_list, "%any"))
		return TRUE;

	char *tok;
	ip_address ip_addr;
	err_t ugh;

	tok = strtok(allowed_targets_list, ", ");
	while (tok != NULL) {
		if (strchr(tok, ':') != NULL)
			ugh = ttoaddr_num(tok, 0, AF_INET6, &ip_addr);
		else
			/* IPv4 and FQDN are left as possible options,
			 * try with AF_UNSPECIFIED, ttoaddr should do the rest */
			ugh = ttoaddr(tok, 0, AF_UNSPEC, &ip_addr);

		if (ugh != NULL) {
			DBG(DBG_CONTROLMORE, DBG_log("address %s isn't a valid address", tok));
		} else {
			if (sameaddr(dest_ip, &ip_addr)) {
				DBG(DBG_CONTROLMORE,
				    DBG_log("address %s is a match to received GW identity", tok));
				return TRUE;
			} else {
				DBG(DBG_CONTROLMORE,
				    DBG_log("address %s is not a match to received GW identity", tok));
			}
		}
		tok = strtok(NULL, ", ");
	}
	DBG(DBG_CONTROLMORE,
	    DBG_log("we did not find suitable address in the list specified by accept-redirect-to option"));
	return FALSE;
}

err_t parse_redirect_payload(pb_stream *input_pbs,
			     char *allowed_targets_list,
			     bool global_red,
			     chunk_t *nonce,
			     ip_address *redirect_ip)
{
	struct ikev2_redirect_part gw_info;
	chunk_t gw_identity;
	int af = AF_UNSPEC;
	err_t ugh = NULL;

	if (!in_struct(&gw_info, &ikev2_redirect_desc, input_pbs, NULL))
		return "received deformed REDIRECT payload";

	switch (gw_info.gw_identity_type) {
	case GW_IPV4:
		af = AF_INET;
		break;
	case GW_IPV6:
		af = AF_INET6;
		break;
	case GW_FQDN:
		break;
	default:
		return "bad GW Ident Type";
	}

	/* in_raw() actual GW Identity */
	if (af != AF_INET && af != AF_INET6) {
		if (!in_raw(&gw_identity.ptr, gw_info.gw_identity_len, input_pbs, "GW Identity"))
			return "error while extracting GW Identity from variable part of IKEv2_REDIRECT Notify payload";

		ugh = ttoaddr((char *) gw_identity.ptr, 0, AF_UNSPEC, redirect_ip);
		if (ugh != NULL) {
			return ugh;
		}
	} else {
		/* GW is either IPv4 or IPv6 */
		if (pbs_left(input_pbs) < gw_info.gw_identity_len)
			return "variable part of payload is smaller than transfered GW Identity Length";

		/* parse address directly to redirect_ip */
		ugh = initaddr(input_pbs->cur, gw_info.gw_identity_len, af, redirect_ip);
		if (ugh != NULL)
			return ugh;

		input_pbs->cur += gw_info.gw_identity_len;
	}

	/* now check the list of allowed targets to
	 * see if parsed address matches any in the list */
	if (!allow_to_be_redirected(allowed_targets_list, redirect_ip))
		return "received GW Identity is not listed in accept-redirect-to conn option";

	size_t len = pbs_left(input_pbs);

	DBG(DBG_CONTROLMORE,
	    DBG_log("there are %zu bytes left to parse, and we do%s need to parse nonce",
		     len, global_red ? "" : " NOT"));

	if (global_red) {
		if (len < IKEv2_MINIMUM_NONCE_SIZE)
			return "expected nonce is smaller than IKEv2 minimum nonce size";
		else if (len > IKEv2_MAXIMUM_NONCE_SIZE)
			return "expected nonce is bigger than IKEv2 maximum nonce size";

		if (!memeq(nonce->ptr, input_pbs->cur, len)) {
			chunk_t dump_nonce;

			setchunk(dump_nonce, input_pbs->cur, len);
			DBG(DBG_CONTROL, DBG_dump_chunk("received nonce", dump_nonce));
			return "received nonce is not the same as Ni";
		}
	} else {
		if (len > 0)
			return "there exists extra (unexpected) bytes in Notify data";
	}

	return NULL;
}

err_t build_redirected_from_notify_data(ip_address old_gw_address, chunk_t *data)
{
	int gw_identity_type = 0;
	size_t gw_identity_len = 0, data_len = 0;
	char *tmp = NULL;

	switch (addrtypeof(&old_gw_address)) {
	case AF_INET:
		gw_identity_type = GW_IPV4;
		gw_identity_len = 4;
		break;
	case AF_INET6:
		gw_identity_type = GW_IPV6;
		gw_identity_len = 16;
		break;
	default:
		return "address of the gateway that redirected us is deformed";
	}

	data_len = GW_PAYLOAD_INFO_SIZE + gw_identity_len;
	/*
	 * we free this data in calling function or here
	 * (when len != gw_identity_len)
	 */
	*data = alloc_chunk(data_len, "data for REDIRECTED_FROM Notify payload");

	tmp = (char *) data->ptr;
	*tmp++ = gw_identity_type;
	*tmp++ = gw_identity_len;

	/* write values of IPv4/IPv6 address */
	unsigned char *addr_bytes;
	size_t len = addrbytesptr_write(&old_gw_address, &addr_bytes);

	if (len != gw_identity_len) {
		freeanychunk(*data);
		return "old GW identity length doesn't match address bytes length";
	}

	/* write ip_address bytes to tmp (chunk_t data) */
	memcpy(tmp, addr_bytes, len);

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

	return;
}

/* helper function for send_v2_informational_request() */
static stf_status add_redirect_payload(struct state *st, pb_stream *pbs)
{
	chunk_t notify_data;

	err_t e = build_redirect_notify_data(st->st_active_redirect_gw, FALSE,
						NULL, &notify_data);
	if (e != NULL) {
		loglog(RC_LOG_SERIOUS, "build of REDIRECT Payload failed: %s", e);
		return STF_INTERNAL_ERROR;
	} else {
		if (!ship_v2Nsp(ISAKMP_NEXT_v2NONE, v2N_REDIRECT, &notify_data, pbs))
			return STF_INTERNAL_ERROR;
		freeanychunk(notify_data);
	}

	return STF_OK;
}

void send_active_redirect_in_informational(struct state *st)
{
	ipstr_buf b;
	stf_status e = send_v2_informational_request("active REDIRECT informational request",
					st, ike_sa(st), add_redirect_payload);
	if (e == STF_OK)
		libreswan_log("redirecting of peer %s successful",
				sensitive_ipstr(&st->st_remoteaddr, &b));
	else
		libreswan_log("redirect not successful");
}
