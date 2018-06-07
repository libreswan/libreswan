/* debug set constants, for libreswan
 *
 * Copyright (C) 2017 Andrew Cagney
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
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

/*
 * See plutomain.c for what the extra "\0" is all about (hint it is a
 * hack for encoding what to do with flags).
 */

#define D(N,A) [N##_IX] = LELEM(N##_IX) == N ? A "\0" : NULL

static const char *debug_strings[] = {
	D(DBG_RAW, "debug-raw"),
	D(DBG_CRYPT, "debug-crypt"),
	D(DBG_CRYPT_LOW, "debug-crypt-low"),
	D(DBG_PARSING, "debug-parsing"),
	D(DBG_EMITTING, "debug-emitting"),
	D(DBG_CONTROL, "debug-control"),
	D(DBG_LIFECYCLE, "debug-lifecycle"),
	D(DBG_KERNEL, "debug-kernel"),
	D(DBG_DNS, "debug-dns"),
	D(DBG_OPPO, "debug-oppo"),
	D(DBG_CONTROLMORE, "debug-controlmore"),
	D(DBG_PFKEY, "debug-pfkey"),
	D(DBG_NATT, "debug-nattraversal"),
	D(DBG_X509, "debug-x509"),
	D(DBG_DPD, "debug-dpd"),
	D(DBG_XAUTH, "debug-xauth"),
	D(DBG_RETRANSMITS, "debug-retransmits"),
	D(DBG_OPPOINFO, "debug-oppoinfo"),
	D(DBG_WHACKWATCH, "debug-whackwatch"),
	D(DBG_PRIVATE, "debug-private"),
	D(DBG_ADD_PREFIX, "debug-add-prefix"),
	D(DBG_PROPOSAL_PARSER, "debug-proposal-parser"),
};

const enum_names debug_names = {
	DBG_floor_IX, DBG_roof_IX - 1,
	ARRAY_REF(debug_strings),
	"debug-",
	NULL,
};

struct lmod_compat debug_compat[] = {
	{ "klips",    DBG_KERNEL },
	{ "netkey",    DBG_KERNEL },
	{ NULL, LEMPTY, },
};

const struct lmod_info debug_lmod_info = {
	.names = &debug_names,
	.all = DBG_ALL,
	.mask = DBG_MASK,
	.compat = debug_compat,
};
