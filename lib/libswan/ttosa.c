/*
 * convert from text form of SA ID to binary
 *
 * Copyright (C) 2000, 2001  Henry Spencer.
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
 */

#include <string.h>

#include "ip_said.h"
#include "ip_info.h"

static struct magic {
	char *name;
	char *really;
} magic[] = {
	{ PASSTHROUGHNAME, PASSTHROUGH4IS },
	{ PASSTHROUGH4NAME, PASSTHROUGH4IS },
	{ PASSTHROUGH6NAME, PASSTHROUGH6IS },
	{ "%pass", "int256@0.0.0.0" },
	{ "%drop", "int257@0.0.0.0" },
	{ "%reject", "int258@0.0.0.0" },
	{ "%hold", "int259@0.0.0.0" },
	{ "%trap", "int260@0.0.0.0" },
	{ "%trapsubnet", "int261@0.0.0.0" },
	{ NULL, NULL }
};

/*
 * ttosa - convert text "ah507@10.0.0.1" to SA identifier
 */
err_t	/* NULL for success, else string literal */
ttosa(src, srclen, sa)
const char *src;
size_t srclen;	/* 0 means "apply strlen" */
ip_said *sa;
{
	const char *at;
	const char *addr;
	size_t alen;
	const char *spi = NULL;
	unsigned long ul;
	const char *oops;
	struct magic *mp;
	size_t nlen;
#       define  MINLEN  5	/* ah0@0 is as short as it can get */
	int base;

	if (srclen == 0)
		srclen = strlen(src);
	if (srclen == 0)
		return "empty string";

	if (srclen < MINLEN)
		return "string too short to be SA identifier";

	if (*src == '%') {
		for (mp = magic; mp->name != NULL; mp++) {
			nlen = strlen(mp->name);
			if (srclen == nlen && memcmp(src, mp->name, nlen) == 0)
				break;
		}
		if (mp->name == NULL)
			return "unknown % keyword";

		src = mp->really;
		srclen = strlen(src);
	}

	at = memchr(src, '@', srclen);
	if (at == NULL)
		return "no @ in SA specifier";

	const struct ip_protocol *sat = protocol_by_prefix(src);
	if (sat == NULL)
		return "SA specifier lacks valid protocol prefix";
	sa->proto = sat;
	spi = src + strlen(sat->prefix);

	if (spi >= at)
		return "no SPI in SA specifier";

	const struct ip_info *afi;
	switch (*spi) {
	case '.':
		afi = &ipv4_info;
		spi++;
		base = 16;
		break;
	case ':':
		afi = &ipv6_info;
		spi++;
		base = 16;
		break;
	default:
		afi = NULL;	/* not known yet */
		base = 0;
		break;
	}
	if (spi >= at)
		return "no SPI found in SA specifier";

	oops = ttoul(spi, at - spi, base, &ul);
	if (oops != NULL)
		return oops;

	sa->spi = htonl(ul);

	addr = at + 1;
	alen = srclen - (addr - src);
	oops = ttoaddress_num(shunk2(addr, alen), afi, &sa->dst);
	if (oops != NULL)
		return oops;

	return NULL;
}
