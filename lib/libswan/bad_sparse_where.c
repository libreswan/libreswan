/* bad_sparse() wrapper, for libreswan
 *
 * Copyright (C) 2013 Andrew Cagney
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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "lswlog.h"
#include "sparse_names.h"

void bad_sparse_where(const struct logger *logger,
		      const struct sparse_names *sn,
		      unsigned long value, where_t where)
{
	name_buf sb;
	llog_passert(logger, where,
		     "sparse %s (%ld) unexpected",
		     str_sparse_long(sn, value, &sb), value);
}
