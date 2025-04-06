/* IKEv2 Redirect Mechanism (RFC 5685) related functions, for libreswan
 *
 * Copyright (C) 2018 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2019 D. Hugh Redelmeier <hugh@mimosa.com>
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

extern enum global_redirect global_redirect;

extern const char *global_redirect_to(void);

extern void free_global_redirect_dests(void);

/*
 * Initialize the static struct redirect_dests variable.
 *
 * @param grd_str comma-separated string containing the destinations
 *  (a copy will be made so caller need not preserve the string).
 *  If it is not specified in conf file, gdr_str will be NULL.
 */
extern void set_global_redirect_dests(const char *gdr_str);

/*
 * Check whether we received v2N_REDIRECT_SUPPORTED (in IKE_SA_INIT request),
 * and if we did, send a response with REDIRECT payload (without creating state -
 * just as in COOKIE case).
 *
 * @param md message digest of IKE_SA_INIT request.
 * @return bool TRUE if redirection is a MUST, FALSE otherwise.
 */
extern bool redirect_global(struct msg_digest *md);

/*
 * Emit IKEv2 Notify REDIRECTED_FROM payload.
 *
 * @param ip_addr IP Address of the previous gateway.
 * @param pbs output stream
 */

bool emit_v2N_REDIRECTED_FROM(const ip_address *old_gateway,
			      struct pbs_out *outs);

/*
 * Emit IKEv2 Notify REDIRECT payload.
 *
 * @param destination string of IPv4/IPv6/FQDN address.
 * @param pbs output stream
 */
bool emit_v2N_REDIRECT(const char *destination, struct pbs_out *pbs);

bool redirect_ike_auth(struct ike_sa *ike, struct msg_digest *md, stf_status *status);

/*
 * Used for active redirect mechanism (RFC 5685)
 *
 * @param conn_name name of the connection whose peers should be
 * 	  redirected. If it's NULL, that means redirect ALL active
 * 	  peers on the machine.
 * @param ard_str comma-separated string containing the destinations.
 */
extern void find_and_active_redirect_states(const char *conn_name,
					    const char *active_redirect_dests,
					    struct logger *logger);

extern stf_status process_v2_IKE_SA_INIT_response_v2N_REDIRECT(struct ike_sa *ike,
							       struct child_sa *child,
							       struct msg_digest *md);

/* redirect by established IKE SA */

extern const struct v2_exchange v2_INFORMATIONAL_v2N_REDIRECT_exchange;

#endif
