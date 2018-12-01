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

#ifndef _IKEV2_REDIRECT_H
#define _IKEV2_REDIRECT_H

#include "packet.h"

int global_redirect;
char *global_redirect_to;

/*
 * Build Notify data for IKEv2 Notify Redirect notification.
 * We don't use out_struct, because we pass chunk_t to
 * ship_v2N method, and not a pb_stream. Luckily, only
 * two bytes (GW Ident Type, GW Ident Len) are static
 * fields in Notify Data of REDIRECT payload.
 *
 * @param destination string of IPv4/IPv6/FQDN address.
 * @param global_red bool that indicates whether payload
 * 	  will be sent in IKE_SA_INIT
 * @param nonce data containing nonce, only being sent if
 * 	  global_red is true
 * @param data Notify data we built.
 * @return err_t NULL if everything went right,
 * 		 otherwise (not-NULL) what went wrong
 */
extern err_t build_redirect_notify_data(char *destination,
					bool global_red,
					chunk_t *nonce,
					chunk_t *data);

/*
 * Extract needed information from IKEv2 Notify Redirect
 * notification.
 *
 * @param data that was transferred in v2_REDIRECT Notify
 * @param char* list of addresses we allow to be redirected
 * 	  to, specified with conn option accept-redirect-to
 * @param global_red bool that indicates whether
 * 	  payload was sent in IKE_SA_INIT response
 * @param nonce that was send in IKE_SA_INIT request,
 * 	  we need to compare it with nonce data sent
 * 	  in Notify data. We do all that only if
 * 	  global_red is true
 * @param redirect_ip ip address we need to redirect to
 * @return err_t NULL if everything went right,
 * 		 otherwise (non-NULL)  what went wrong
 */
extern err_t parse_redirect_payload(pb_stream *input,
				    char *allowed_targets_list,
				    bool in_ike_sa_init,
				    chunk_t *nonce,
				    ip_address *redirect_ip);

/*
 * Build Notify data for IKEv2 Notify REDIRECTED_FROM payload.
 *
 * REDIRECTED_FROM has the same structure as REDIRECT payload,
 * except there is no nonce sending in any case, and GW_FQDN
 * is not valid as GW_Ident_Type.
 *
 * @param old_gw_address ip_address of the gateway that sent us here
 * @param data Notify data we built
 */
extern err_t build_redirected_from_notify_data(ip_address old_gw_address,
					   chunk_t *data);

/*
 * Initiate via initiate_connection new IKE_SA_INIT exchange
 */
extern void initiate_redirect(struct state *st);

/*
 * Send IKEv2 INFORMATIONAL exchange with REDIRECT payload.
 * This is the case of redirection during the active tunnel.
 */
extern void send_active_redirect_in_informational(struct state *st);

#endif
