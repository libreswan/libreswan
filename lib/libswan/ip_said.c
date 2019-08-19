/* SA ID, for libreswan
 *
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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

#include "ip_said.h"

void jam_said(jambuf_t *buf, const ip_said *said, int format)
{
	char t[SATOT_BUF];
	satot(said, format, t, sizeof(t));
	jam_string(buf, t);
}

const char *str_said(const ip_said *said, int format, said_buf *buf)
{
	jambuf_t b = ARRAY_AS_JAMBUF(buf->buf);
	jam_said(&b, said, format);
	return buf->buf;
}
