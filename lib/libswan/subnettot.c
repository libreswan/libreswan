/*
 * convert binary form of subnet description to text
 *
 * Copyright (C) 2000  Henry Spencer.
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

#include "lswlog.h"
#include "ip_subnet.h"

/*
 * subnettot - convert subnet to text "addr/bitcount".
 *
 * This is to prop up old code.  New code can call str_subnet()
 * et.al. directly.
 */
void subnettot(const ip_subnet *sub, int format,
	       char *dst, size_t dstlen)
{
	passert(format == 0);
	passert(dst != NULL);
	fmtbuf_t buf = array_as_fmtbuf(dst, dstlen);
	fmt_subnet(&buf, sub);
}
