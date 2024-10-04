/* logging declarations
 *
 * Copyright (C) 2021 Andrew Cagney
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

#include "lswlog.h"

size_t jam_object_prefix_none(struct jambuf *buf UNUSED, const void *object UNUSED)
{
	return 0;
}

static const struct logger_object_vec logger_global_vec = {
	.name = "global",
	.jam_object_prefix = jam_object_prefix_none,
	.free_object = false,
};

const struct where global_where = {
	.line = 0, .file = "<global>", .func = "<global>",
};

/*const*/struct logger global_logger = {
	.where = &global_where,
	.object = NULL,
	.object_vec = &logger_global_vec,
};
