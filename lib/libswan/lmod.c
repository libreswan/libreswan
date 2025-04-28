/* lset modifiers, for libreswan
 *
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
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
#include <stdarg.h>

#include "constants.h"
#include "lmod.h"
#include "lswlog.h"
#include "lswalloc.h"

const lmod_t empty_lmod = {
	LEMPTY,
	LEMPTY,
};

bool lmod_empty(lmod_t mod)
{
	return mod.set == LEMPTY && mod.clr == LEMPTY;
}

void lmod_merge(lmod_t *lhs, lmod_t rhs)
{
	lhs->set = (lhs->set & ~rhs.clr) | rhs.set;
	lhs->clr = (lhs->clr & ~rhs.set) | rhs.clr;
}

lset_t lmod(lset_t set, lmod_t mod)
{
	return (set & ~mod.clr ) | mod.set;
}

lmod_t lmod_set(lmod_t mod, lset_t set)
{
	mod.set |= set;
	mod.clr &= ~set;
	return mod;
}

lmod_t lmod_clr(lmod_t mod, lset_t clr)
{
	mod.clr |= clr;
	mod.set &= ~clr;
	return mod;
}

bool lmod_is_set(lmod_t mod, lset_t set)
{
	return LIN(set, mod.set);
}

bool lmod_is_clr(lmod_t mod, lset_t clr)
{
	return LIN(clr, mod.clr);
}

bool lmod_arg(lmod_t *mod, const struct lmod_info *info,
	      shunk_t args, bool enable)
{
	bool ok = true;
	shunk_t cursor = args;
	while (true) {
		shunk_t elem = shunk_token(&cursor, NULL/*delim*/, "+, \t");
		if (elem.ptr == NULL) {
			break;
		}
		if (elem.len == 0) {
			/* ignore empty */
			continue;
		}
		if (enable && hunk_streq(elem, "none")) {
			/* excludes --no-... none */
			mod->clr = info->mask;
			mod->set = LEMPTY;
		} else {
			/* non-empty */
			shunk_t arg = elem;
			/* excludes --no-... no-... */
			bool no = enable ? hunk_streat(&arg, "no-") : true;
			lset_t bits = LEMPTY;
			/* try aliases first */
			if (info->aliases != NULL) {
				for (struct lmod_alias *c = info->aliases;
				     c->name != NULL; c++) {
					if (hunk_streq(arg, c->name)) {
						bits = c->bits;
						break;
					}
				}
			}
			/* try bit mask second */
			if (bits == LEMPTY) {
				int ix = enum_match(info->names, arg);
				if (ix >= 0) {
					bits = LELEM(ix);
				}
			}
			/* some sort of success */
			if (bits == LEMPTY) {
				ok = false;
				break;
			}
			/* update masks */
			if (no) {
				mod->clr |= bits;
				mod->set &= ~bits;
			} else {
				mod->set |= bits;
				mod->clr &= ~bits;
			}
		}
	}
	return ok;
}

size_t jam_lmod(struct jambuf *buf, enum_names *names, lmod_t mod)
{
	size_t s = 0;
	static const char separator[] = "+";
	s += jam_lset_short(buf, names, separator, mod.set);
	if (mod.clr != LEMPTY) {
		s += jam(buf, " - ");
		s += jam_lset_short(buf, names, separator, mod.clr);
	}
	return s;
}

const char *str_lmod(const struct enum_names *sd, lmod_t val, lmod_buf *out)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(out->buf);
	jam_lmod(&buf, sd, val);
	return out->buf;
}
