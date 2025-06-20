/* updown names, for libreswan
 *
 * Copyright (C) 2025  Andrew Cagney
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

#include "updown.h"
#include "lswcdefs.h"		/* for ARRAY_REF() */
#include "enum_names.h"

static const char *updown_story[] = {
#define C(E,V) [E-UPDOWN_FLOOR] = V
	C(UPDOWN_PREPARE, "prepare"),
	C(UPDOWN_ROUTE, "route"),
	C(UPDOWN_UNROUTE, "unroute"),
	C(UPDOWN_UP, "up"),
	C(UPDOWN_DOWN, "down"),
	C(UPDOWN_DISCONNECT_NM, "disconnectNM"), /*legacy; do not change*/
#undef C
};

const struct enum_names updown_stories = {
	UPDOWN_FLOOR, UPDOWN_ROOF-1,
	ARRAY_REF(updown_story),
	NULL, NULL,
};

static const char *updown_name[] = {
#define C(E) [E-UPDOWN_FLOOR] = #E
	C(UPDOWN_PREPARE),
	C(UPDOWN_ROUTE),
	C(UPDOWN_UNROUTE),
	C(UPDOWN_UP),
	C(UPDOWN_DOWN),
	C(UPDOWN_DISCONNECT_NM),
#undef C
};

const struct enum_names updown_names = {
	UPDOWN_FLOOR, UPDOWN_ROOF-1,
	ARRAY_REF(updown_name),
	"UPDOWN_", NULL,
};
