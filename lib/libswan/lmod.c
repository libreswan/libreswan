/* lset modifiers, for libreswan
 *
 * Copyright (C) 2017 Andrew Cagney
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
	      const char *args)
{
	char *list = clone_str(args, "list"); /* must free */
	bool ok = true;
	const char *delim = "+, \t";
	for (char *tmp = list, *elem = strsep(&tmp, delim);
	     elem != NULL; elem = strsep(&tmp, delim)) {
		if (streq(elem, "all")) {
			mod->clr = LEMPTY;
			mod->set = info->all;
		} else if (streq(elem, "none")) {
			mod->clr = info->mask;
			mod->set = LEMPTY;
		} else if (*elem != '\0') {
			/* non-empty */
			const char *arg = elem;
			bool no = eat(arg, "no-");
			int ix = enum_match(info->names, shunk1(arg));
			lset_t bit = LEMPTY;
			if (ix >= 0) {
				bit = LELEM(ix);
			} else if (info->compat != NULL) {
				for (struct lmod_compat *c = info->compat;
				     c->name != NULL; c++) {
					if (streq(c->name, arg)) {
						bit = c->bit;
						break;
					}
				}
			}
			if (bit == LEMPTY) {
				ok = false;
				break;
			}
			if (no) {
				mod->clr |= bit;
				mod->set &= ~bit;
			} else {
				mod->set |= bit;
				mod->clr &= ~bit;
			}
		} /* else ignore empty ... */
	}
	pfree(list);
	return ok;
}

void lswlog_lmod(struct lswlog *buf, enum_names *names,
		 const char *separator, lmod_t mod)
{
	lswlog_enum_lset_short(buf, names, separator, mod.set);
	if (mod.clr != LEMPTY) {
		lswlogs(buf, " - ");
		lswlog_enum_lset_short(buf, names, separator, mod.clr);
	}
}
