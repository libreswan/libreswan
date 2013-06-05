/*
 * Copyright (C) 2001-2002 Colubris Networks
 * Copyright (C) 2003-2004 Xelerance Corporation
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

#ifndef _XAUTH_H
#define _XAUTH_H

#define POOL_ADDRESS_FREE 0
#define POOL_ADDRESS_USED 1
struct state;

/**
 * Addresses assigned (usually via MODE_CONFIG) to the Initiator
 * */
struct internal_addr {
	ip_address ipaddr;
	ip_address dns[2];
};

stf_status modecfg_resp(struct state *st, unsigned int resp,
			pb_stream *s, u_int16_t cmd,
			bool use_modecfg_addr_as_client_addr, u_int16_t id);

stf_status xauth_client_resp(struct state *st,
			     unsigned int xauth,
			     pb_stream *rbody,
			     u_int16_t ap_id);

stf_status xauth_client_ackstatus(struct state *st,
				  pb_stream *rbody,
				  u_int16_t ap_id);

stf_status modecfg_send_set(struct state *st);

size_t xauth_mode_cfg_hash(u_char *dest,
			   const u_char *start,
			   const u_char *roof,
			   const struct state *st);

stf_status xauth_send_request(struct state *st);

stf_status xauth_send_status(struct state *st, int status);

int xauth_launch_authent(struct state *st, chunk_t name,
			 chunk_t password, chunk_t connname);

extern stf_status modecfg_start_set(struct state *st);

/* XAUTH States */
extern stf_status xauth_inR0(struct msg_digest *md);
extern stf_status xauth_inR1(struct msg_digest *md);
extern stf_status modecfg_inR0(struct msg_digest *md);
extern stf_status modecfg_inR1(struct msg_digest *md);
extern stf_status xauth_inI0(struct msg_digest *md);
extern stf_status xauth_inI1(struct msg_digest *md);
extern oakley_auth_t xauth_calcbaseauth(oakley_auth_t baseauth);
extern stf_status modecfg_send_request(struct state *st);
int rel_addr_pool(struct connection *c);
#endif  /*#ifndef _XAUTH_Ha */
