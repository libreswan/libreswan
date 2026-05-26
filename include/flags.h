/* Flags primitive, for libreswan
 *
 * Copyright (C) 2026 Andrew Cagney
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

#ifndef FLAGS_H
#define FLAGS_H

#include <stdlib.h>
#include <stdbool.h>

#include "lswcdefs.h"
#include "diag.h"

struct enum_names;
struct jambuf;

struct ro_flags {
	unsigned len;
	const bool *flag COUNTED_BY_PTR(len);
};

#define RO_FLAGS(FLAGS) (struct ro_flags) { ARRAY_PTR(FLAGS), }

struct rw_flags {
	unsigned len;
	bool *flag COUNTED_BY_PTR(len);
};

#define RW_FLAGS(FLAGS) (struct rw_flags) { ARRAY_PTR(FLAGS), }

#define ttoflags(VALUE, FLAGS, NAMES)			\
	ttoflags_raw(VALUE, RW_FLAGS(FLAGS), NAMES)

diag_t ttoflags_raw(const char *value,
		    struct rw_flags flags,
		    const struct enum_names *names);

#define jam_flags(BUF, FLAGS, NAMES)				\
	jam_raw_flags(BUF, RO_FLAGS(FLAGS), NAMES)

void jam_raw_flags(struct jambuf *buf,
		   struct ro_flags flags,
		   const struct enum_names *names);

#define jam_flags_human(BUF, FLAGS, NAMES)				\
	jam_raw_flags_human(BUF, RO_FLAGS(FLAGS), NAMES)

void jam_raw_flags_human(struct jambuf *buf,
			 struct ro_flags flags,
			 const struct enum_names *names);

#endif
