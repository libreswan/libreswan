/* enums as names, for libreswan
 *
 * Copyright (C) 2025 Andrew Cagney
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

#include <stdio.h>
#include <string.h>

#include "names.h"
#include "jambuf.h"
#include "passert.h"

void bad_name(unsigned long val, name_buf *b)
{
	snprintf(b->tmp, sizeof(b->tmp), "%lu", val);
	b->buf = b->tmp;
}

size_t jam_bad(struct jambuf *buf, const char *prefix, unsigned long val)
{
	size_t s = 0;
	if (prefix != NULL) {
		s += jam_string(buf, prefix);
		const char c = prefix[strlen(prefix)-1];
		/*
		 * Typically .prefix has a trailing "_", but when it
		 * doesn't add one.
		 */
		if (c != '_' && c != '.') {
			s += jam_string(buf, ".");
		}
	}
	s += jam(buf, "%lu", val);
	return s;
}

size_t jam_name_long(struct jambuf *buf, const struct names *en, unsigned long val)
{
	if (en->sparse_names != NULL) {
		return jam_sparse_long(buf, en->sparse_names, val);
	}
	if (en->enum_names != NULL) {
		return jam_enum_long(buf, en->enum_names, val);
	}
	llog_passert(&global_logger, HERE, "barf");
}

size_t jam_name_short(struct jambuf *buf, const struct names *en, unsigned long val)
{
	if (en->sparse_names != NULL) {
		return jam_sparse_short(buf, en->sparse_names, val);
	}
	if (en->enum_names != NULL) {
		return jam_enum_short(buf, en->enum_names, val);
	}
	llog_passert(&global_logger, HERE, "barf");
}

const char *str_name_long(const struct names *en, unsigned long val, name_buf *buf)
{
	if (en->sparse_names != NULL) {
		return str_sparse_long(en->sparse_names, val, buf);
	}
	if (en->enum_names != NULL) {
		return str_enum_long(en->enum_names, val, buf);
	}
	llog_passert(&global_logger, HERE, "barf");
}

const char *str_name_short(const struct names *en, unsigned long val, name_buf *buf)
{
	if (en->sparse_names != NULL) {
		return str_sparse_short(en->sparse_names, val, buf);
	}
	if (en->enum_names != NULL) {
		return str_enum_short(en->enum_names, val, buf);
	}
	llog_passert(&global_logger, HERE, "barf");
}

bool name_long(const struct names *en, unsigned long val, name_buf *b)
{
	if (en->sparse_names != NULL) {
		return sparse_long(en->sparse_names, val, b);
	}
	if (en->enum_names != NULL) {
		return enum_long(en->enum_names, val, b);
	}
	llog_passert(&global_logger, HERE, "barf");
}

bool name_short(const struct names *en, unsigned long val, name_buf *b)
{
	if (en->sparse_names != NULL) {
		return sparse_short(en->sparse_names, val, b);
	}
	if (en->enum_names != NULL) {
		return enum_short(en->enum_names, val, b);
	}
	llog_passert(&global_logger, HERE, "barf");
}

long next_name(const struct names *en, long last)
{
	if (en->sparse_names != NULL) {
		return next_sparse(en->sparse_names, last);
	}
	if (en->enum_names != NULL) {
		return next_enum(en->enum_names, last);
	}
	llog_passert(&global_logger, HERE, "barf");
}

size_t jam_names_quoted(struct jambuf *buf, const struct names *en)
{
	if (en->sparse_names != NULL) {
		return jam_sparse_names_quoted(buf, en->sparse_names);
	}
	if (en->enum_names != NULL) {
		return jam_enum_names_quoted(buf, en->enum_names);
	}
	llog_passert(&global_logger, HERE, "barf");
}

size_t jam_name_human(struct jambuf *buf, const struct names *en, unsigned long val)
{
	if (en->sparse_names != NULL) {
		return jam_sparse_human(buf, en->sparse_names, val);
	}
	if (en->enum_names != NULL) {
		return jam_enum_human(buf, en->enum_names, val);
	}
	llog_passert(&global_logger, HERE, "barf");
}

int index_byname(const struct names *en, shunk_t string)
{
	if (en->sparse_names != NULL) {
		return sparse_byname(en->sparse_names, string);
	}
	if (en->enum_names != NULL) {
		return enum_byname(en->enum_names, string);
	}
	llog_passert(&global_logger, HERE, "barf");
}
