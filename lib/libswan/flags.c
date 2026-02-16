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

#include "flags.h"

#include "jambuf.h"
#include "shunk.h"
#include "names.h"

diag_t ttoflags_raw(const char *value,
		    bool *flag, size_t len,
		    const struct enum_names *names)
{
	shunk_t cursor = shunk1(value);
	while (true) {
		shunk_t elem = shunk_token(&cursor, NULL/*delim*/, "+, \t");
		if (elem.ptr == NULL) {
			break;
		}
		if (elem.len == 0) {
			/* ignore empty */
			continue;
		}
		/* non-empty */
		shunk_t arg = elem;
		/* excludes --no-... no-... */
		bool no = (hunk_streat(&arg, "no-") || hunk_streat(&arg, "no"));
		int ix = enum_byname(names, arg);
		if (ix < 0) {
			return diag("\""PRI_SHUNK"\" unrecognized", pri_shunk(arg));
		}
		if (ix >= (int)len) {
			return diag("\""PRI_SHUNK"\" to big", pri_shunk(arg));
		}
		flag[ix] = !no;
	}
	return NULL;
}

void jam_raw_flags(struct jambuf *buf,
		   const bool *flag, size_t len,
		   const struct enum_names *names)
{
	const char *sep = "";
	for (unsigned u = 0; u < len; u++) {
		if (flag[u]) {
			jam_string(buf, sep); sep = ",";
			jam_enum_short(buf, names, u);
		}
	}
}

void jam_raw_flags_human(struct jambuf *buf,
			 const bool *flag, size_t len,
			 const struct enum_names *names)
{
	const char *sep = "";
	for (unsigned u = 0; u < len; u++) {
		jam_string(buf, sep); sep = ",";
		if (!flag[u]) {
			jam_string(buf, "no");
		}
		jam_enum_human(buf, names, u);
	}
}
