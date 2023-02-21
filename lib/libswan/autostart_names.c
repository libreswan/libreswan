/* tables of names for values defined in constants.h
 *
 * Copyright (C) 2023 Andrew Cagney
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

#include "lswcdefs.h"		/* for ARRAY_REF() */
#include "enum_names.h"
#include "constants.h"		/* for enum autostart */

static const char *autostart_name[] = {
#define S(E) [E] = #E
	S(AUTOSTART_IGNORE),
	S(AUTOSTART_ADD),
	S(AUTOSTART_ONDEMAND),
	S(AUTOSTART_START),
	S(AUTOSTART_KEEP),
#undef S
};

const struct enum_names autostart_names = {
	AUTOSTART_IGNORE,
	AUTOSTART_KEEP,
	ARRAY_REF(autostart_name),
	"AUTOSTART_", NULL,
};
