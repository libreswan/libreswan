/*
 * xfrmi declarations, linux kernel IPsec interface/device
 *
 * Copyright (C) 2018-2020 Antony Antony <antony@phenome.org>
 * Copyright (C) 2023 Brady Johnson <bradyallenjohnson@gmail.com>
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

#ifndef KERNEL_XFRM_INTERFACE_H
#define KERNEL_XFRM_INTERFACE_H

#include "ip_endpoint.h"

struct connection;

void set_ike_mark_out(const struct connection *c,
		      ip_endpoint *ike_remote,
		      struct logger *logger);

#endif
