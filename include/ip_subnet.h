/* ip subnet, for libreswan
 *
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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
#ifndef IP_SUBNET_H
#define IP_SUBNET_H

#include "ip_address.h"

struct lswlog;

/* then the main types */
typedef struct {
	ip_address addr;
	int maskbits;
} ip_subnet;

/* [floor..ceiling] vs [floor..roof) */
ip_address ip_subnet_floor(const ip_subnet *subnet);
ip_address ip_subnet_ceiling(const ip_subnet *subnet);

typedef struct {
	char buf[sizeof(ip_address_buf) + 4/*/NNN*/];
} ip_subnet_buf;
const char *str_subnet(const ip_subnet *subnet, ip_subnet_buf *out);
void fmt_subnet(struct lswlog *buf, const ip_subnet *subnet);

/*
 * old
 */
#include "err.h"

extern err_t ttosubnet(const char *src, size_t srclen, int af, ip_subnet *dst);
extern void subnettot(const ip_subnet *src, int format, char *buf, size_t buflen);
#define SUBNETTOT_BUF   sizeof(ip_subnet_buf)
extern err_t initsubnet(const ip_address *addr, int maskbits, int clash,
		 ip_subnet *dst);
extern err_t addrtosubnet(const ip_address *addr, ip_subnet *dst);

/* misc. conversions and related */
extern err_t rangetosubnet(const ip_address *from, const ip_address *to,
		    ip_subnet *dst);
extern int subnettypeof(const ip_subnet *src);
extern void networkof(const ip_subnet *src, ip_address *dst);
extern void maskof(const ip_subnet *src, ip_address *dst);

/* tests */
extern bool samesubnet(const ip_subnet *a, const ip_subnet *b);
extern bool addrinsubnet(const ip_address *a, const ip_subnet *s);
extern bool subnetinsubnet(const ip_subnet *a, const ip_subnet *b);
extern bool subnetishost(const ip_subnet *s);
extern bool samesubnettype(const ip_subnet *a, const ip_subnet *b);
#define subnetisaddr(sn, a) (subnetishost(sn) && addrinsubnet((a), (sn)))
extern bool subnetisnone(const ip_subnet *sn);

#endif
