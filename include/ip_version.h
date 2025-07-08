/* ip address type, for libreswan
 *
 * Copyright (C) 2021 Andrew Cagney
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

#ifndef IP_VERSION_H
#define IP_VERSION_H

/*
 * A compact enum for all supported IP versions.
 */

enum ip_version {
	/* 0 is reserved!! */
#define IP_VERSION_FLOOR IPv4
	IPv4 = 1,
	IPv6,
#define IP_VERSION_ROOF (IPv6+1)
};

#endif
