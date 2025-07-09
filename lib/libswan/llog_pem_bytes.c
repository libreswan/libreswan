/* Output raw bytes, for libreswan
 *
 * Copyright (C) 2022 Andrew Cagney
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

#include "lswlog.h"

void llog_pem_bytes(enum stream stream,
		    const struct logger *logger,
		    const char *name,
		    const void *ptr, size_t size)
{
	llog(stream, logger, "-----BEGIN %s-----", name);
	llog_base64_bytes(stream, logger, ptr, size);
	llog(stream, logger, "-----END %s-----", name);
}
