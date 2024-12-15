/* Libreswan Virtual IP Management
 * Copyright (C) 2002 Mathieu Lafon - Arkoon Network Security
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

#ifndef VIRTUAL_IP_H
#define VIRTUAL_IP_H

#include "err.h"
#include "ip_address.h"
#include "ip_subnet.h"
#include "verbose.h"

struct connection;
struct spd;
struct spd_end;
struct show;

extern void show_virtual_private(struct show *s);

extern void init_virtual_ip(const char *private_list, struct logger *logger);
extern void free_virtual_ip(void);

diag_t create_virtual(const char *leftright, const char *string, struct virtual_ip **);
struct virtual_ip *virtual_ip_addref_where(struct virtual_ip *vip, where_t where);
#define virtual_ip_addref(VIP) virtual_ip_addref_where(VIP, HERE)
void virtual_ip_delref_where(struct virtual_ip **vip, where_t where);
#define virtual_ip_delref(IP) virtual_ip_delref_where(IP, HERE)

bool is_virtual_spd_end(const struct spd_end *that, struct verbose verbose);
bool is_virtual_remote(const struct connection *c, struct verbose verbose);

bool is_virtual_host(const struct virtual_ip *that);
bool is_virtual_net(const struct virtual_ip *that);

/*
 * With virtual addressing, we must not allow someone to use an
 * already used (by another id) addr/net.
 */

err_t is_virtual_net_allowed(const struct connection *d,
			     const ip_selector remote_client,
			     struct verbose verbose);

#endif /* VIRTUAL_IP_H */
