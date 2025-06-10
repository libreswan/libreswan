/* AF Information, for libreswan
 *
 * Copyright (C) 2025 Andrew Cagney
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

#include "ip_index.h"

#include "ip_info.h"
#include "passert.h"
#include "sparse_names.h"
#include "lswlog.h"		/* for bad_case() */

const struct ip_info *ip_index_info(enum ip_index index)
{
	switch (index) {
	case IPv4_INDEX: return &ipv4_info;
	case IPv6_INDEX: return &ipv6_info;
	}
	bad_case(index);
}

const struct sparse_names ip_index_names = {
	.list = {
		SPARSE("IPv4", IPv4_INDEX),
		SPARSE("IPv6", IPv6_INDEX),
		SPARSE_NULL,
	},
};
