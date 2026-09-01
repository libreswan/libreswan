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

struct names;
struct jambuf;

#define FLAGS(FLAG) { ARRAY_PTR(FLAG), }

struct ro_flags {
	unsigned len;
	const bool *flag COUNTED_BY_PTR(len);
};

#define RO_FLAGS(FLAGS)			\
	(struct ro_flags) {		\
		.len = (FLAGS).len,	\
		.flag = (FLAGS).flag,	\
	}

struct rw_flags {
	unsigned len;
	bool *flag COUNTED_BY_PTR(len);
};

#define RW_FLAGS(FLAGS)			\
	(struct rw_flags) {		\
		.len = (FLAGS).len,	\
		.flag = (FLAGS).flag,	\
	}

diag_t tto_rw_flags(const char *value,
		    struct rw_flags flags,
		    const struct names *names);
#define ttoflags(VALUE, FLAG, NAMES)			\
	tto_rw_flags(VALUE, (struct rw_flags) FLAGS(FLAG), NAMES)

void jam_ro_flags(struct jambuf *buf,
		  struct ro_flags flags,
		  const struct names *names);
#define jam_flags(BUF, FLAG, NAMES)				\
	jam_ro_flags(BUF, (struct ro_flags) FLAGS(FLAG), NAMES)

void jam_ro_flags_human(struct jambuf *buf,
			struct ro_flags flags,
			const struct names *names);
#define jam_flags_human(BUF, FLAG, NAMES)				\
	jam_ro_flags_human(BUF, (struct ro_flags) FLAGS(FLAG), NAMES)

#endif
