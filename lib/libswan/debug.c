/* debug set constants, for libreswan
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
 */

#include <stddef.h>

#include "constants.h"
#include "enum_names.h"
#include "lmod.h"

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

	D(DBG_ADD_PREFIX, "debug-add-prefix", "add the log+state prefix to debug lines"),
	D(DBG_CONTROL, "debug-control", "control flow within Pluto"),
	D(DBG_CONTROLMORE, "debug-controlmore", "more detailed debugging"),
	D(DBG_CRYPT, "debug-crypt", "high-level encryption/decryption of messages"),
	D(DBG_CRYPT_LOW, "debug-crypt-low", "low-level encryption/decryption implementation details"),
	D(DBG_DNS, "debug-dns", "DNS activity"),
	D(DBG_DPD, "debug-dpd", "DPD items"),
	D(DBG_EMITTING, "debug-emitting", "show encoding of messages"),
	D(DBG_KERNEL, "debug-kernel", "messages with the kernel"),
	D(DBG_LIFECYCLE, "debug-lifecycle", "SA lifecycle"),
	D(DBG_NATT, "debug-nattraversal", "debugging of NAT-traversal"),
	D(DBG_OPPO, "debug-oppo", "opportunism"),
	D(DBG_OPPOINFO, "debug-oppoinfo", "log various informational things about oppo/%trap-keying"),
	D(DBG_PARSING, "debug-parsing", "show decoding of messages"),
	D(DBG_PRIVATE, "debug-private", "displays private information: DANGER!"),
	D(DBG_PROPOSAL_PARSER, "debug-proposal-parser", "parsing ike=... et.al."),
	D(DBG_RAW, "debug-raw", "raw packet I/O"),
	D(DBG_RETRANSMITS, "debug-retransmits", "Retransmitting packets"),
	D(DBG_WHACKWATCH, "debug-whackwatch", "never let WHACK go"),
	D(DBG_X509, "debug-x509", "X.509/pkix verify, cert retrival"),
	D(DBG_XAUTH, "debug-xauth", "XAUTH aka PAM"),
};

const enum_names debug_names = {
	DBG_floor_IX, DBG_roof_IX - 1,
	ARRAY_REF(debug.name),
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

const struct enum_names debug_help = {
	DBG_floor_IX, DBG_roof_IX - 1,
	ARRAY_REF(debug.help),
	NULL, NULL,
};
