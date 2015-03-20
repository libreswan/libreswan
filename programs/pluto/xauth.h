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

#ifndef XAUTH_H
#define XAUTH_H

struct state;	/* so state.h is not a prerequisite */
struct msg_digest;	/* so demux.h is not a prerequisite */

/**
 * Addresses assigned (usually via MODE_CONFIG) to the Initiator
 */
struct internal_addr {
	ip_address ipaddr;
	ip_address dns[2];
};

extern stf_status xauth_send_request(struct state *st);

extern stf_status modecfg_start_set(struct state *st);

/* XAUTH state transitions */
extern stf_status xauth_inR0(struct msg_digest *md);
extern stf_status xauth_inR1(struct msg_digest *md);
extern stf_status modecfg_inR0(struct msg_digest *md);
extern stf_status modecfg_inR1(struct msg_digest *md);
extern stf_status xauth_inI0(struct msg_digest *md);
extern stf_status xauth_inI1(struct msg_digest *md);
extern oakley_auth_t xauth_calcbaseauth(oakley_auth_t baseauth);
extern stf_status modecfg_send_request(struct state *st);

extern void state_deletion_xauth_cleanup(struct state *st);

#endif  /* XAUTH_H */
