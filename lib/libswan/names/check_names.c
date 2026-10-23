/* check name constants
 *
 * Copyright (C) 2026  Andrew Cagney
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

#include "names.h"

void check_names(const struct names_checklist *checklist)
{
	/* check that names are well-formed */
	DATA_FOR_EACH(c, checklist) {
		/*
		 * enum_name will check all linked names if given
		 * a value that isn't covered.  -42 is probably not
		 * covered.
		 */
		name_buf b;
		name_long(c->names, -42UL, &b);
	}
}
