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
#include "enum_names.h"

void init_names(void)
{
	check_names(&names_checklist);
	check_enum_names(&enum_names_checklist);
	check_enum_enum_names(&enum_enum_names_checklist);
}
