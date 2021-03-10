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

#ifndef IP_BYTES_H
#define IP_BYTES_H

#include <stdint.h>		/* for uint8_t */

/*
 * We need something that makes static IPv4 initializers possible
 * (struct in_addr requires htonl() which is run-time only).
 */

struct ip_bytes {
	uint8_t byte[16];
};

#define PRI_BYTES "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
#define pri_bytes(B)							\
	(B).byte[0],							\
		(B).byte[1],						\
		(B).byte[2],						\
		(B).byte[3],						\
		(B).byte[4],						\
		(B).byte[5],						\
		(B).byte[6],						\
		(B).byte[7],						\
		(B).byte[8],						\
		(B).byte[9],						\
		(B).byte[10],						\
		(B).byte[11],						\
		(B).byte[12],						\
		(B).byte[13],						\
		(B).byte[14],						\
		(B).byte[15]

#endif
