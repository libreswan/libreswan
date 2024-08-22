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

#ifndef ADDRESSPOOL_H
#define ADDRESSPOOL_H

#include "err.h"
#include "ip_range.h"

struct addresspool;        /* abstract object */

diag_t find_addresspool(const ip_range pool_range, struct addresspool **pool) MUST_USE_RESULT;

diag_t install_addresspool(const ip_range pool_range, struct connection *c,
			   struct logger *logger) MUST_USE_RESULT;
void addresspool_delref(struct addresspool **pool, struct logger *logger);
struct addresspool *addresspool_addref(struct addresspool *pool);

extern err_t lease_that_selector(struct connection *c,
				 const char *xauth_username/*possibly-NULL|NUL*/,
				 const ip_selector *selector,
				 struct logger *logger);

extern err_t lease_that_address(struct connection *c, const char *xauth_username/*possibly-NULL|NUL*/,
				const struct ip_info *afi, struct logger *logger);
extern void free_that_address_lease(struct connection *c, const struct ip_info *afi,
				    struct logger *logger);

extern void show_addresspool_status(struct show *s);

#endif /* _ADDRESSPOOL_H */
