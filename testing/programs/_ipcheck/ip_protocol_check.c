/*
 * conversion from protocol/port string to protocol and port
 *
 * Copyright (C) 2002 Mario Strasser <mast@gmx.net>,
 *                    Zuercher Hochschule Winterthur,
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

#include "ip_protocol.h"

#include "ipcheck.h"

void ip_protocol_check(void)
{
	FOR_EACH_ELEMENT(p, ip_protocols) {
		/* fudge up something to keep print happy */
		size_t ti = p - ip_protocols;
		struct { unsigned line; } t[] = { { .line = LN, }, };
		size_t size = strlen(p->name) + 1/*NUL*/;
		PRINT("%s sizeof=%zu", p->name, size);
		if (size > sizeof(protocol_buf)) {
			FAIL("sizeof(%s) = %zu > sizeof(protocol_buf)",
			     p->name, size);
		}
		if (p->ipproto != ti) {
			FAIL("%s.ipproto != %zu", p->name, ti);
		}
	}
}
