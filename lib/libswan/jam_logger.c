/* logging, for libreswan
 *
 * Copyright (C) 2023 Andrew Cagney
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
 *
 */

#include <stdlib.h>		/* for abort() */

#include "lswlog.h"

size_t jam_prefix(struct jambuf *buf, const struct logger *logger)
{
	return logger->object_vec->jam_object_prefix(buf, logger->object);
}

size_t jam_logger_prefix(struct jambuf *buf, const struct logger *logger)
{
	size_t s = jam_prefix(buf, logger);
	if (s > 0) {
		s += jam_string(buf, ": ");
	}
	return s;
}
