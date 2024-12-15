/* show connection status, for libreswan
 *
 * Copyright (C) 2023 Andrew Cagney
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
 */

#ifndef WHACK_CONNECTIONSTATUS_H
#define WHACK_CONNECTIONSTATUS_H

#include "ip_selector.h"

struct whack_message;
struct show;
enum left_right;
struct jambuf;
struct spd_end;
struct connection;
struct host_end;

void whack_connectionstatus(const struct whack_message *m, struct show *s);
void show_connection_statuses(struct show *s);

/* Shared with <<ipsec briefconnectionstatus>> */
void jam_end_host(struct jambuf *buf,
		  const struct connection *c,
		  const struct host_end *end);

void jam_end_spd(struct jambuf *buf,
		 const struct connection *c,
		 const struct spd_end *this,
		 enum left_right left_right,
		 const char *separator);

/*
 * Format the topology of a connection end, leaving out defaults.
 * Largest left end looks like: client === host : port [ host_id ] ---
 * hop Note: if that==NULL, skip nexthop
 */
void jam_spd_ends(struct jambuf *buf, const struct connection *c,
		  const struct spd_end *this,
		  const char *sep, /* probably ... */
		  const struct spd_end *that);

struct connection_client {
	const struct host_end *host;
	const struct child_end *child;
	const ip_selector client;
	const ip_address sourceip;
	const struct virtual_ip *virt;
};

void show_connection_clients(struct show *s, const struct connection *c,
			     void (*show_client)(struct show *s,
						 const struct connection *c,
						 const struct connection_client *this,
						 const struct connection_client *that));

#endif
