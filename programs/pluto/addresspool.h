/*
 * addresspool management functions used with left/rightaddresspool= option.
 * Currently used for IKEv1 XAUTH/ModeConfig options if we are an XAUTH server.
 *
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
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

#ifndef _ADDRESSPOOL_H
#define _ADDRESSPOOL_H

#include "err.h"

struct ip_range;
struct ip_pool;        /* forward declaration; definition is local to addresspool.c */

extern struct ip_pool *install_addresspool(const ip_range *pool_range);
extern err_t find_addresspool(const ip_range *pool_range, struct ip_pool **pool);
extern bool pool_size(ip_range *r, uint32_t *size);

extern void unreference_addresspool(struct connection *c);
extern void reference_addresspool(struct connection *c);

extern err_t lease_that_address(struct connection *c, const struct state *st);
extern void free_that_address_lease(struct connection *c);

extern void show_addresspool_status(struct show *s);

#endif /* _ADDRESSPOOL_H */
