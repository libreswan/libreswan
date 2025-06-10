/* ip address type index, for libreswan
 *
 * Copyright (C) 2022 Andrew Cagney
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/lgpl-2.1.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 *
 */

#ifndef IP_INDEX_H
#define IP_INDEX_H

enum ip_index {
#define IP_INDEX_FLOOR IPv4_INDEX
	IPv4_INDEX = 1,
	IPv6_INDEX,
#define IP_INDEX_ROOF (IPv6_INDEX+1)
};

extern const struct ip_info *ip_index_info(enum ip_index);
extern const struct sparse_names ip_index_names;

#endif
