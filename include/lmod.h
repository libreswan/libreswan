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
 */

#ifndef _LMOD_H_
#define _LMOD_H_

#include "lset.h"
#include "shunk.h"

struct jambuf;

/*
 * lmod_t is for modifying an lset_t.
 *
 * It needs a better name.
 */

typedef struct {
	lset_t set;
	lset_t clr;
} lmod_t;

extern const lmod_t empty_lmod;

lset_t lmod(lset_t set, lmod_t mod);
lmod_t lmod_set(lmod_t lhs, lset_t set);
lmod_t lmod_clr(lmod_t lhs, lset_t set);

bool lmod_is_set(lmod_t lhs, lset_t set);
bool lmod_is_clr(lmod_t lhs, lset_t set);
bool lmod_empty(lmod_t mod);
void lmod_merge(lmod_t *lhs, lmod_t rhs);

struct lmod_alias {
	const char *name;
	lset_t bits;
};

struct lmod_info {
	const struct enum_names *names;
	lset_t mask;
	struct lmod_alias *aliases;
};

bool ttolmod(shunk_t t, lmod_t *mod,
	     const struct lmod_info *info,
	     bool enable);

typedef struct {
	char buf[512]; /* arbitrary */
} lmod_buf;

size_t jam_lmod(struct jambuf *buf, const struct enum_names *names,
		lmod_t mod);
const char *str_lmod(const struct enum_names *sd,
		     lmod_t val, lmod_buf *buf);

#endif
