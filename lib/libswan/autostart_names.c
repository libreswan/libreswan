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
#include "sparse_names.h"
#include "constants.h"		/* for enum autostart */

const struct sparse_name autostart_names[] = {
	{ "ignore", AUTOSTART_IGNORE },
	{ "add",    AUTOSTART_ADD },
	{ "ondemand",  AUTOSTART_ONDEMAND },
	{ "route",  AUTOSTART_ONDEMAND }, /* backwards compatibility alias */
	{ "up",     AUTOSTART_UP },
	{ "start",  AUTOSTART_UP }, /* alias */
	{ "keep",   AUTOSTART_KEEP }, /* add plus once up, keep up */
	SPARSE_NULL
};
