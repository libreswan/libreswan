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

struct connection;
struct spd_route;
struct end;
struct show;

extern void show_virtual_private(struct show *s);

extern void init_virtual_ip(const char *private_list, struct logger *logger);
extern void free_virtual_ip(void);

struct virtual_ip *create_virtual(const char *string, struct logger *logger);
struct virtual_ip *virtual_ip_addref(struct virtual_ip *vip, where_t where);
void virtual_ip_delref(struct virtual_ip **vip, where_t where);

extern bool is_virtual_end(const struct end *that);
extern bool is_virtual_connection(const struct connection *c);
extern bool is_virtual_sr(const struct spd_route *sr);
extern bool is_virtual_vhost(const struct end *that);
extern err_t check_virtual_net_allowed(const struct connection *c,
				       const ip_subnet *peer_net,
				       const ip_address *peers_addr);

#endif /* VIRTUAL_IP_H */

