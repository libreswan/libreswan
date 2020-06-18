/* debug set constants, for libreswan
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

#include <stddef.h>

#include "constants.h"
#include "enum_names.h"
#include "lmod.h"
#include "lswcdefs.h"		/* for ARRAY_REF() */

/*
 * Initialize both the .name and .help arrays.
 *
 * See plutomain.c why the name has an extra "\0" appended (hint it is
 * a hack for encoding what to do with flags).
 *
 * XXX: since only the --debug ... form is supported, has this all
 * become redundant.
 *
 * So that grepping for DBG.<name> finds this file, the N parameter is
 * the full enum name (DBG_...) and not just the truncated suffix.
 */

struct double_double {
	const char *name[DBG_roof_IX - DBG_floor_IX];
	const char *help[DBG_roof_IX - DBG_floor_IX];
};

static struct double_double debug = {

#define D(N,A,H)			       \
	.name[N##_IX - DBG_floor_IX] = A "\0", \
	.help[N##_IX - DBG_floor_IX] = H

	D(DBG_BASE, "debug-base", "enable detailed debug logging"),
	D(DBG_CPU_USAGE, "debug-cpu-usage", "estimate cpu used"),
	D(DBG_CRYPT, "debug-crypt", "encryption/decryption of messages: DANGER!"),
	D(DBG_PRIVATE, "debug-private", "displays private information: DANGER!"),
	D(DBG_WHACKWATCH, "debug-whackwatch", "never let WHACK go"),
	D(DBG_ADD_PREFIX, "debug-add-prefix", "add the log+state prefix to debug lines"),
	D(DBG_TMI, "debug-tmi", "far too much information"),
#undef D
};

const enum_names debug_names = {
	DBG_floor_IX, DBG_roof_IX - 1,
	ARRAY_REF(debug.name),
	"debug-",
	NULL,
};

struct lmod_compat debug_compat[] = {
	{ "klips", DBG_BASE },
	{ "netkey", DBG_BASE },
	{ "control", DBG_BASE, },
	{ "controlmore", DBG_BASE, },
	{ "dns", DBG_BASE, },
	{ "dpd", DBG_BASE, },
	{ "emitting", DBG_BASE, },
	{ "kernel", DBG_BASE, },
	{ "lifecycle", DBG_BASE, },
	{ "nattraversal", DBG_BASE, },
	{ "oppo", DBG_BASE, },
	{ "oppoinfo", DBG_BASE, },
	{ "parsing", DBG_BASE, },
	{ "proposal-parser", DBG_BASE, },
	{ "raw", DBG_BASE, },
	{ "retransmits", DBG_BASE, },
	{ "x509", DBG_BASE, },
	{ "xauth", DBG_BASE, },

	{ "crypt-low", DBG_CRYPT, },

	{ NULL, LEMPTY, },
};

const struct lmod_info debug_lmod_info = {
	.names = &debug_names,
	.all = DBG_ALL,
	.mask = DBG_MASK,
	.compat = debug_compat,
};

const struct enum_names debug_help = {
	DBG_floor_IX, DBG_roof_IX - 1,
	ARRAY_REF(debug.help),
	NULL, NULL,
};
